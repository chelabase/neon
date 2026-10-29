use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwapOption;
use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use clashmap::ClashMap;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey};
use reqwest::{Client, redirect};
use reqwest_retry::RetryTransientMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use thiserror::Error;
use tokio::time::Instant;

use crate::auth::backend::ComputeCredentialKeys;
use crate::context::RequestContext;
use crate::control_plane::errors::GetEndpointJwksError;
use crate::http::read_body_with_limit;
use crate::intern::RoleNameInt;
use crate::types::{EndpointId, RoleName};

// TODO(conrad): make these configurable.
const CLOCK_SKEW_LEEWAY: Duration = Duration::from_secs(30);
const MIN_RENEW: Duration = Duration::from_secs(30);
const AUTO_RENEW: Duration = Duration::from_secs(300);
const MAX_RENEW: Duration = Duration::from_secs(3600);
const MAX_JWK_BODY_SIZE: usize = 64 * 1024;
const JWKS_USER_AGENT: &str = "neon-proxy";

const JWKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const JWKS_FETCH_RETRIES: u32 = 3;

/// How to get the JWT auth rules
pub(crate) trait FetchAuthRules: Clone + Send + Sync + 'static {
    fn fetch_auth_rules(
        &self,
        ctx: &RequestContext,
        endpoint: EndpointId,
    ) -> impl Future<Output = Result<Vec<AuthRule>, FetchAuthRulesError>> + Send;
}

#[derive(Error, Debug)]
pub(crate) enum FetchAuthRulesError {
    #[error(transparent)]
    GetEndpointJwks(#[from] GetEndpointJwksError),

    #[error("JWKs settings for this role were not configured")]
    RoleJwksNotConfigured,
}

#[derive(Clone)]
pub(crate) struct AuthRule {
    pub(crate) id: String,
    pub(crate) jwks_url: url::Url,
    pub(crate) audience: Option<String>,
    pub(crate) role_names: Vec<RoleNameInt>,
}

pub struct JwkCache {
    client: reqwest_middleware::ClientWithMiddleware,

    map: ClashMap<(EndpointId, RoleName), Arc<JwkCacheEntryLock>>,
}

pub(crate) struct JwkCacheEntry {
    /// Should refetch at least every hour to verify when old keys have been removed.
    /// Should refetch when new key IDs are seen only every 5 minutes or so
    last_retrieved: Instant,

    /// cplane will return multiple JWKs urls that we need to scrape.
    key_sets: ahash::HashMap<String, KeySet>,
}

impl JwkCacheEntry {
    fn find_jwk_and_audience(
        &self,
        key_id: &str,
        role_name: &RoleName,
    ) -> Option<(&Jwk, Option<&str>)> {
        self.key_sets
            .values()
            // make sure our requested role has access to the key set
            .filter(|key_set| key_set.role_names.iter().any(|role| **role == **role_name))
            // try and find the requested key-id in the key set
            .find_map(|key_set| {
                key_set
                    .find_key(key_id)
                    .map(|jwk| (jwk, key_set.audience.as_deref()))
            })
    }
}

struct KeySet {
    jwks: jsonwebtoken::jwk::JwkSet,
    audience: Option<String>,
    role_names: Vec<RoleNameInt>,
}

impl KeySet {
    fn find_key(&self, key_id: &str) -> Option<&Jwk> {
        self.jwks
            .keys
            .iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(key_id))
    }
}

pub(crate) struct JwkCacheEntryLock {
    cached: ArcSwapOption<JwkCacheEntry>,
    lookup: tokio::sync::Semaphore,
}

impl Default for JwkCacheEntryLock {
    fn default() -> Self {
        JwkCacheEntryLock {
            cached: ArcSwapOption::empty(),
            lookup: tokio::sync::Semaphore::new(1),
        }
    }
}

#[derive(Deserialize)]
struct JwkSet<'a> {
    /// we parse into raw-value because not all keys in a JWKS are ones
    /// we can parse directly, so we parse them lazily.
    #[serde(borrow)]
    keys: Vec<&'a RawValue>,
}

/// Given a jwks_url, fetch the JWKS and parse out all the signing JWKs.
/// Returns `None` and log a warning if there are any errors.
async fn fetch_jwks(
    client: &reqwest_middleware::ClientWithMiddleware,
    jwks_url: url::Url,
) -> Option<jsonwebtoken::jwk::JwkSet> {
    let req = client.get(jwks_url.clone());
    // TODO(conrad): We need to filter out URLs that point to local resources. Public internet only.
    let resp = req.send().await.and_then(|r| {
        r.error_for_status()
            .map_err(reqwest_middleware::Error::Reqwest)
    });

    let resp = match resp {
        Ok(r) => r,
        // TODO: should we re-insert JWKs if we want to keep this JWKs URL?
        // I expect these failures would be quite sparse.
        Err(e) => {
            tracing::warn!(url=?jwks_url, error=?e, "could not fetch JWKs");
            return None;
        }
    };

    let resp: http::Response<reqwest::Body> = resp.into();

    let bytes = match read_body_with_limit(resp.into_body(), MAX_JWK_BODY_SIZE).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(url=?jwks_url, error=?e, "could not decode JWKs");
            return None;
        }
    };

    let jwks = match serde_json::from_slice::<JwkSet>(&bytes) {
        Ok(jwks) => jwks,
        Err(e) => {
            tracing::warn!(url=?jwks_url, error=?e, "could not decode JWKs");
            return None;
        }
    };

    // `Jwk` is quite large (over 300 bytes). Let's not pre-allocate for what we don't need.
    //
    // Even though we limit our responses to 64KiB, we could still receive a payload like
    // `{"keys":[` + repeat(`0`).take(30000).join(`,`) + `]}`. Parsing this as `RawValue` uses 468KiB.
    // Pre-allocating the corresponding `Vec::<Jwk>::with_capacity(30000)` would use over 9MiB.
    let mut keys = vec![];

    let mut failed = 0;
    for key in jwks.keys {
        let key = match serde_json::from_str::<Jwk>(key.get()) {
            // An unknown `kty`, or a key missing its key material, parses as `Other`.
            Ok(Jwk {
                algorithm: AlgorithmParameters::Other(_),
                ..
            }) => {
                tracing::debug!(url=?jwks_url, "could not decode JWK: unsupported key type");
                failed += 1;
                continue;
            }
            // Key material that isn't base64url.
            Ok(key) if DecodingKey::from_jwk(&key).is_err() => {
                tracing::debug!(url=?jwks_url, "could not decode JWK: invalid key material");
                failed += 1;
                continue;
            }
            Ok(key) => key,
            Err(e) => {
                tracing::debug!(url=?jwks_url, failed=?e, "could not decode JWK");
                failed += 1;
                continue;
            }
        };

        // if `use` is specified to be something other than signing, we can skip storing it.
        if key
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|u| *u != PublicKeyUse::Signature)
        {
            continue;
        }

        keys.push(key);
    }

    keys.shrink_to_fit();

    if failed > 0 {
        tracing::warn!(url=?jwks_url, failed, "could not decode JWKs");
    }

    if keys.is_empty() {
        tracing::warn!(url=?jwks_url, "no valid JWKs found inside the response body");
        return None;
    }

    Some(jsonwebtoken::jwk::JwkSet { keys })
}

impl JwkCacheEntryLock {
    async fn acquire_permit(self: &Arc<Self>) -> JwkRenewalPermit<'_> {
        JwkRenewalPermit::acquire_permit(self).await
    }

    fn try_acquire_permit(self: &Arc<Self>) -> Option<JwkRenewalPermit<'_>> {
        JwkRenewalPermit::try_acquire_permit(self)
    }

    async fn renew_jwks<F: FetchAuthRules>(
        &self,
        _permit: JwkRenewalPermit<'_>,
        ctx: &RequestContext,
        client: &reqwest_middleware::ClientWithMiddleware,
        endpoint: EndpointId,
        auth_rules: &F,
    ) -> Result<Arc<JwkCacheEntry>, JwtError> {
        // double check that no one beat us to updating the cache.
        let now = Instant::now();
        let guard = self.cached.load_full();
        if let Some(cached) = guard {
            let last_update = now.duration_since(cached.last_retrieved);
            if last_update < Duration::from_secs(300) {
                return Ok(cached);
            }
        }

        let rules = auth_rules.fetch_auth_rules(ctx, endpoint).await?;
        let mut key_sets =
            ahash::HashMap::with_capacity_and_hasher(rules.len(), ahash::RandomState::new());

        // TODO(conrad): run concurrently
        // TODO(conrad): strip the JWKs urls (should be checked by cplane as well - cloud#16284)
        for rule in rules {
            if let Some(jwks) = fetch_jwks(client, rule.jwks_url).await {
                key_sets.insert(
                    rule.id,
                    KeySet {
                        jwks,
                        audience: rule.audience,
                        role_names: rule.role_names,
                    },
                );
            }
        }

        let entry = Arc::new(JwkCacheEntry {
            last_retrieved: now,
            key_sets,
        });
        self.cached.swap(Some(Arc::clone(&entry)));

        Ok(entry)
    }

    async fn get_or_update_jwk_cache<F: FetchAuthRules>(
        self: &Arc<Self>,
        ctx: &RequestContext,
        client: &reqwest_middleware::ClientWithMiddleware,
        endpoint: EndpointId,
        fetch: &F,
    ) -> Result<Arc<JwkCacheEntry>, JwtError> {
        let now = Instant::now();
        let guard = self.cached.load_full();

        // if we have no cached JWKs, try and get some
        let Some(cached) = guard else {
            let _paused = ctx.latency_timer_pause(crate::metrics::Waiting::Compute);
            let permit = self.acquire_permit().await;
            return self.renew_jwks(permit, ctx, client, endpoint, fetch).await;
        };

        let last_update = now.duration_since(cached.last_retrieved);

        // check if the cached JWKs need updating.
        if last_update > MAX_RENEW {
            let _paused = ctx.latency_timer_pause(crate::metrics::Waiting::Compute);
            let permit = self.acquire_permit().await;

            // it's been too long since we checked the keys. wait for them to update.
            return self.renew_jwks(permit, ctx, client, endpoint, fetch).await;
        }

        // every 5 minutes we should spawn a job to eagerly update the token.
        if last_update > AUTO_RENEW {
            if let Some(permit) = self.try_acquire_permit() {
                tracing::debug!("JWKs should be renewed. Renewal permit acquired");
                let permit = permit.into_owned();
                let entry = self.clone();
                let client = client.clone();
                let fetch = fetch.clone();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = entry
                        .renew_jwks(permit, &ctx, &client, endpoint, &fetch)
                        .await
                    {
                        tracing::warn!(error=?e, "could not fetch JWKs in background job");
                    }
                });
            } else {
                tracing::debug!("JWKs should be renewed. Renewal permit already taken, skipping");
            }
        }

        Ok(cached)
    }

    async fn check_jwt<F: FetchAuthRules>(
        self: &Arc<Self>,
        ctx: &RequestContext,
        jwt: &str,
        client: &reqwest_middleware::ClientWithMiddleware,
        endpoint: EndpointId,
        role_name: &RoleName,
        fetch: &F,
    ) -> Result<ComputeCredentialKeys, JwtError> {
        // JWT compact form is defined to be
        // <B64(Header)> || . || <B64(Payload)> || . || <B64(Signature)>
        // where Signature = alg(<B64(Header)> || . || <B64(Payload)>);

        let (header_payload, signature) = jwt
            .rsplit_once('.')
            .ok_or(JwtEncodingError::InvalidCompactForm)?;
        let (header, payload) = header_payload
            .split_once('.')
            .ok_or(JwtEncodingError::InvalidCompactForm)?;

        let header = BASE64_URL_SAFE_NO_PAD.decode(header)?;
        let header = serde_json::from_slice::<JwtHeader<'_>>(&header)?;

        let payloadb = BASE64_URL_SAFE_NO_PAD.decode(payload)?;
        let payload = serde_json::from_slice::<JwtPayload<'_>>(&payloadb)?;

        if let Some(iss) = &payload.issuer {
            ctx.set_jwt_issuer(iss.as_ref().to_owned());
        }

        // Refuse a signature that isn't base64url before looking for the key.
        BASE64_URL_SAFE_NO_PAD.decode(signature)?;

        let kid = header.key_id.ok_or(JwtError::MissingKeyId)?;

        let mut guard = self
            .get_or_update_jwk_cache(ctx, client, endpoint.clone(), fetch)
            .await?;

        // get the key from the JWKs if possible. If not, wait for the keys to update.
        let (jwk, expected_audience) = loop {
            match guard.find_jwk_and_audience(&kid, role_name) {
                Some(jwk) => break jwk,
                None if guard.last_retrieved.elapsed() > MIN_RENEW => {
                    let _paused = ctx.latency_timer_pause(crate::metrics::Waiting::Compute);

                    let permit = self.acquire_permit().await;
                    guard = self
                        .renew_jwks(permit, ctx, client, endpoint.clone(), fetch)
                        .await?;
                }
                _ => return Err(JwtError::JwkNotFound),
            }
        };

        if !is_supported(jwk, header.algorithm) {
            return Err(JwtError::SignatureAlgorithmNotSupported);
        }

        match &jwk.algorithm {
            AlgorithmParameters::EllipticCurve(key) => {
                verify_ec_signature(header_payload.as_bytes(), signature, jwk, &key.curve)?;
            }
            AlgorithmParameters::RSA(_) => {
                verify_rsa_signature(header_payload.as_bytes(), signature, jwk, header.algorithm)?;
            }
            key => return Err(JwtError::UnsupportedKeyType(key.into())),
        }

        tracing::debug!(?payload, "JWT signature valid with claims");

        if let Some(aud) = expected_audience
            && payload.audience.0.iter().all(|s| s != aud)
        {
            return Err(JwtError::InvalidClaims(
                JwtClaimsError::InvalidJwtTokenAudience,
            ));
        }

        let now = SystemTime::now();

        if let Some(exp) = payload.expiration
            && now >= exp + CLOCK_SKEW_LEEWAY
        {
            return Err(JwtError::InvalidClaims(JwtClaimsError::JwtTokenHasExpired(
                exp.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )));
        }

        if let Some(nbf) = payload.not_before
            && nbf >= now + CLOCK_SKEW_LEEWAY
        {
            return Err(JwtError::InvalidClaims(
                JwtClaimsError::JwtTokenNotYetReadyToUse(
                    nbf.duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
            ));
        }

        Ok(ComputeCredentialKeys::JwtPayload(payloadb))
    }
}

impl JwkCache {
    pub(crate) async fn check_jwt<F: FetchAuthRules>(
        &self,
        ctx: &RequestContext,
        endpoint: EndpointId,
        role_name: &RoleName,
        fetch: &F,
        jwt: &str,
    ) -> Result<ComputeCredentialKeys, JwtError> {
        // try with just a read lock first
        let key = (endpoint.clone(), role_name.clone());
        let entry = self.map.get(&key).as_deref().map(Arc::clone);
        let entry = entry.unwrap_or_else(|| {
            // acquire a write lock after to insert.
            let entry = self.map.entry(key).or_default();
            Arc::clone(&*entry)
        });

        entry
            .check_jwt(ctx, jwt, &self.client, endpoint, role_name, fetch)
            .await
    }
}

impl Default for JwkCache {
    fn default() -> Self {
        let client = Client::builder()
            .user_agent(JWKS_USER_AGENT)
            .redirect(redirect::Policy::none())
            .tls_built_in_native_certs(true)
            .connect_timeout(JWKS_CONNECT_TIMEOUT)
            .timeout(JWKS_FETCH_TIMEOUT)
            .build()
            .expect("client config should be valid");

        // Retry up to 3 times with increasing intervals between attempts.
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(JWKS_FETCH_RETRIES);

        let client = reqwest_middleware::ClientBuilder::new(client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        JwkCache {
            client,
            map: ClashMap::default(),
        }
    }
}

/// RSA keys over this many bits are refused, as `rsa` 0.9 refused them.
const MAX_RSA_BITS: usize = 4096;

/// Whether `jwk` may verify a token signed with `alg`: the algorithm matches the key's
/// type and curve (and, for RSA, its size), and the JWK's own `alg`, when it has one.
fn is_supported(jwk: &Jwk, alg: Algorithm) -> bool {
    use Algorithm::{
        ES256, ES384, EdDSA, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384, RS512,
    };

    let by_key = match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => matches!(
            (&ec.curve, alg),
            (EllipticCurve::P256, ES256) | (EllipticCurve::P384, ES384)
        ),
        AlgorithmParameters::RSA(rsa) => {
            // The modulus length in bytes, as sent, over 16: 2048 bits for RS256/PS256
            // (RFC 7518 3.3), more for the longer hashes.
            let strength = BASE64_URL_SAFE_NO_PAD
                .decode(&rsa.n)
                .map_or(0, |n| n.len() / 16);
            match alg {
                RS256 | PS256 => strength >= 16,
                RS384 | PS384 => strength >= 24,
                RS512 | PS512 => strength >= 32,
                _ => false,
            }
        }
        AlgorithmParameters::OctetKey(oct) => {
            let len = BASE64_URL_SAFE_NO_PAD
                .decode(&oct.value)
                .map_or(0, |k| k.len());
            matches!((alg, len), (HS256, 16..) | (HS384, 24..) | (HS512, 32..))
        }
        AlgorithmParameters::OctetKeyPair(_) => alg == EdDSA,
        // `Other` (an unknown `kty`) is skipped when the JWKS is fetched.
        _ => false,
    };
    by_key
        && jwk
            .common
            .key_algorithm
            .is_none_or(|a| a == KeyAlgorithm::from(alg))
}

/// Verify `signature` (base64url) over `data` as `alg` with `key`.
fn verify(data: &[u8], signature: &str, key: &DecodingKey, alg: Algorithm) -> Result<(), JwtError> {
    match jsonwebtoken::crypto::verify(signature, data, key, alg) {
        Ok(true) => Ok(()),
        Ok(false) => Err(JwtError::Signature(signature::Error::new())),
        Err(e) => Err(JwtError::Signature(signature::Error::from_source(e))),
    }
}

fn verify_ec_signature(
    data: &[u8],
    signature: &str,
    jwk: &Jwk,
    curve: &EllipticCurve,
) -> Result<(), JwtError> {
    match curve {
        // aws-lc refuses a point that isn't on the curve when it verifies.
        EllipticCurve::P256 => {
            let key = DecodingKey::from_jwk(jwk).map_err(JwtError::InvalidP256Key)?;
            verify(data, signature, &key, Algorithm::ES256)
        }
        curve => Err(JwtError::UnsupportedEcKeyType(curve.clone())),
    }
}

fn verify_rsa_signature(
    data: &[u8],
    signature: &str,
    jwk: &Jwk,
    alg: Algorithm,
) -> Result<(), JwtError> {
    let key = DecodingKey::from_jwk(jwk).map_err(JwtError::InvalidRsaKey)?;
    if let AlgorithmParameters::RSA(rsa) = &jwk.algorithm {
        let n = BASE64_URL_SAFE_NO_PAD.decode(&rsa.n)?;
        let n = &n[n.iter().take_while(|&&b| b == 0).count()..];
        let bits = n
            .first()
            .map_or(0, |top| n.len() * 8 - top.leading_zeros() as usize);
        if bits > MAX_RSA_BITS {
            return Err(JwtError::RsaKeyTooLarge(bits));
        }
    }

    match alg {
        Algorithm::RS256 => verify(data, signature, &key, Algorithm::RS256),
        _ => Err(JwtError::InvalidRsaSigningAlgorithm),
    }
}

/// <https://datatracker.ietf.org/doc/html/rfc7515#section-4.1>
#[derive(serde::Deserialize, serde::Serialize)]
struct JwtHeader<'a> {
    /// must be a supported alg
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    /// key id, must be provided for our usecase
    #[serde(rename = "kid", borrow)]
    key_id: Option<Cow<'a, str>>,
}

/// <https://datatracker.ietf.org/doc/html/rfc7519#section-4.1>
#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct JwtPayload<'a> {
    /// Audience - Recipient for which the JWT is intended
    #[serde(rename = "aud", default)]
    audience: OneOrMany,
    /// Expiration - Time after which the JWT expires
    #[serde(rename = "exp", deserialize_with = "numeric_date_opt", default)]
    expiration: Option<SystemTime>,
    /// Not before - Time before which the JWT is not valid
    #[serde(rename = "nbf", deserialize_with = "numeric_date_opt", default)]
    not_before: Option<SystemTime>,

    // the following entries are only extracted for the sake of debug logging.
    /// Issuer of the JWT
    #[serde(rename = "iss", borrow)]
    issuer: Option<Cow<'a, str>>,
    /// Subject of the JWT (the user)
    #[serde(rename = "sub", borrow)]
    subject: Option<Cow<'a, str>>,
    /// Unique token identifier
    #[serde(rename = "jti", borrow)]
    jwt_id: Option<Cow<'a, str>>,
    /// Unique session identifier
    #[serde(rename = "sid", borrow)]
    session_id: Option<Cow<'a, str>>,
}

/// `OneOrMany` supports parsing either a single item or an array of items.
///
/// Needed for <https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3>
///
/// > The "aud" (audience) claim identifies the recipients that the JWT is
/// > intended for.  Each principal intended to process the JWT MUST
/// > identify itself with a value in the audience claim.  If the principal
/// > processing the claim does not identify itself with a value in the
/// > "aud" claim when this claim is present, then the JWT MUST be
/// > rejected.  In the general case, the "aud" value is **an array of case-
/// > sensitive strings**, each containing a StringOrURI value.  In the
/// > special case when the JWT has one audience, the "aud" value MAY be a
/// > **single case-sensitive string** containing a StringOrURI value.  The
/// > interpretation of audience values is generally application specific.
/// > Use of this claim is OPTIONAL.
#[derive(Default, Debug)]
struct OneOrMany(Vec<String>);

impl<'de> Deserialize<'de> for OneOrMany {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OneOrManyVisitor;
        impl<'de> Visitor<'de> for OneOrManyVisitor {
            type Value = OneOrMany;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a single string or an array of strings")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OneOrMany(vec![v.to_owned()]))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut v = vec![];
                while let Some(s) = seq.next_element()? {
                    v.push(s);
                }
                Ok(OneOrMany(v))
            }
        }
        deserializer.deserialize_any(OneOrManyVisitor)
    }
}

fn numeric_date_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SystemTime>, D::Error> {
    <Option<u64>>::deserialize(d)?
        .map(|t| {
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(t))
                .ok_or_else(|| {
                    serde::de::Error::custom(format_args!("timestamp out of bounds: {t}"))
                })
        })
        .transpose()
}

struct JwkRenewalPermit<'a> {
    inner: Option<JwkRenewalPermitInner<'a>>,
}

enum JwkRenewalPermitInner<'a> {
    Owned(Arc<JwkCacheEntryLock>),
    Borrowed(&'a Arc<JwkCacheEntryLock>),
}

impl JwkRenewalPermit<'_> {
    fn into_owned(mut self) -> JwkRenewalPermit<'static> {
        JwkRenewalPermit {
            inner: self.inner.take().map(JwkRenewalPermitInner::into_owned),
        }
    }

    async fn acquire_permit(from: &Arc<JwkCacheEntryLock>) -> JwkRenewalPermit<'_> {
        match from.lookup.acquire().await {
            Ok(permit) => {
                permit.forget();
                JwkRenewalPermit {
                    inner: Some(JwkRenewalPermitInner::Borrowed(from)),
                }
            }
            Err(_) => panic!("semaphore should not be closed"),
        }
    }

    fn try_acquire_permit(from: &Arc<JwkCacheEntryLock>) -> Option<JwkRenewalPermit<'_>> {
        match from.lookup.try_acquire() {
            Ok(permit) => {
                permit.forget();
                Some(JwkRenewalPermit {
                    inner: Some(JwkRenewalPermitInner::Borrowed(from)),
                })
            }
            Err(tokio::sync::TryAcquireError::NoPermits) => None,
            Err(tokio::sync::TryAcquireError::Closed) => panic!("semaphore should not be closed"),
        }
    }
}

impl JwkRenewalPermitInner<'_> {
    fn into_owned(self) -> JwkRenewalPermitInner<'static> {
        match self {
            JwkRenewalPermitInner::Owned(p) => JwkRenewalPermitInner::Owned(p),
            JwkRenewalPermitInner::Borrowed(p) => JwkRenewalPermitInner::Owned(Arc::clone(p)),
        }
    }
}

impl Drop for JwkRenewalPermit<'_> {
    fn drop(&mut self) {
        let entry = match &self.inner {
            None => return,
            Some(JwkRenewalPermitInner::Owned(p)) => p,
            Some(JwkRenewalPermitInner::Borrowed(p)) => *p,
        };
        entry.lookup.add_permits(1);
    }
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub(crate) enum JwtError {
    #[error("jwk not found")]
    JwkNotFound,

    #[error("missing key id")]
    MissingKeyId,

    #[error("Provided authentication token is not a valid JWT encoding")]
    JwtEncoding(#[from] JwtEncodingError),

    #[error(transparent)]
    InvalidClaims(#[from] JwtClaimsError),

    #[error("invalid P256 key")]
    InvalidP256Key(jsonwebtoken::errors::Error),

    #[error("invalid RSA key")]
    InvalidRsaKey(jsonwebtoken::errors::Error),

    #[error("RSA key too large ({0} bits)")]
    RsaKeyTooLarge(usize),

    #[error("invalid RSA signing algorithm")]
    InvalidRsaSigningAlgorithm,

    #[error("unsupported EC key type {0:?}")]
    UnsupportedEcKeyType(EllipticCurve),

    #[error("unsupported key type {0:?}")]
    UnsupportedKeyType(KeyType),

    #[error("signature algorithm not supported")]
    SignatureAlgorithmNotSupported,

    #[error("signature error: {0}")]
    Signature(#[from] signature::Error),

    #[error("failed to fetch auth rules: {0}")]
    FetchAuthRules(#[from] FetchAuthRulesError),
}

impl From<base64::DecodeError> for JwtError {
    fn from(err: base64::DecodeError) -> Self {
        JwtEncodingError::Base64Decode(err).into()
    }
}

impl From<serde_json::Error> for JwtError {
    fn from(err: serde_json::Error) -> Self {
        JwtEncodingError::SerdeJson(err).into()
    }
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum JwtEncodingError {
    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    #[error("invalid compact form")]
    InvalidCompactForm,
}

#[derive(Error, Debug, PartialEq)]
#[non_exhaustive]
pub enum JwtClaimsError {
    #[error("invalid JWT token audience")]
    InvalidJwtTokenAudience,

    #[error("JWT token has expired (exp={0})")]
    JwtTokenHasExpired(u64),

    #[error("JWT token is not yet ready to use (nbf={0})")]
    JwtTokenNotYetReadyToUse(u64),
}

#[allow(dead_code, reason = "Debug use only")]
#[derive(Debug)]
pub(crate) enum KeyType {
    Oct,
    Okp(EllipticCurve),
    Unknown,
}

impl From<&AlgorithmParameters> for KeyType {
    fn from(key: &AlgorithmParameters) -> Self {
        match key {
            AlgorithmParameters::OctetKey(_) => Self::Oct,
            AlgorithmParameters::OctetKeyPair(okp) => Self::Okp(okp.curve.clone()),
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::IntoFuture;
    use std::net::SocketAddr;
    use std::time::SystemTime;

    use bytes::Bytes;
    use http::Response;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use serde::Serialize;
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;
    use crate::types::RoleName;

    fn new_ec_jwk(kid: String) -> (TestKey, Jwk) {
        let key = TestKey::p256();
        let jwk = with(key.jwk(&kid), |k| {
            k.insert("alg".into(), "ES256".into());
        });
        (key, serde_json::from_value(jwk).unwrap())
    }

    fn new_rsa_jwk(pem: &str, kid: String) -> (TestKey, Jwk) {
        let key = TestKey::rsa_pem(pem);
        let jwk = with(key.jwk(&kid), |k| {
            k.insert("alg".into(), "RS256".into());
        });
        (key, serde_json::from_value(jwk).unwrap())
    }

    fn jwk_set(keys: Vec<Jwk>) -> jsonwebtoken::jwk::JwkSet {
        jsonwebtoken::jwk::JwkSet { keys }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn jwt_body() -> serde_json::Value {
        let now = now();
        json!({
            "exp": now + 3600,
            "nbf": now,
            "aud": ["audience1", "neon", "audience2"],
            "sub": "user1",
            "sid": "session1",
            "jti": "token1",
            "iss": "neon-testing",
        })
    }

    fn new_ec_jwt(kid: String, key: &TestKey) -> String {
        token(key, &header("ES256", &kid), &jwt_body())
    }

    fn new_custom_ec_jwt(kid: String, key: &TestKey, body: impl Serialize) -> String {
        token(
            key,
            &header("ES256", &kid),
            &serde_json::to_value(body).unwrap(),
        )
    }

    fn new_rsa_jwt(kid: String, key: TestKey) -> String {
        token(&key, &header("RS256", &kid), &jwt_body())
    }

    // RSA key gen is slow....
    const RS1: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDNuWBIWTlo+54Y
aifpGInIrpv6LlsbI/2/2CC81Arlx4RsABORklgA9XSGwaCbHTshHsfd1S916JwA
SpjyPQYWfqo6iAV8a4MhjIeJIkRr74prDCSzOGZvIc6VaGeCIb9clf3HSrPHm3hA
cfLMB8/p5MgoxERPDOIn3XYoS9SEEuP7l0LkmEZMerg6W6lDjQRDny0Lb50Jky9X
mDqnYXBhs99ranbwL5vjy0ba6OIeCWFJme5u+rv5C/P0BOYrJfGxIcEoKa8Ukw5s
PlM+qrz9ope1eOuXMNNdyFDReNBUyaM1AwBAayU5rz57crer7K/UIofaJ42T4cMM
nx/SWfBNAgMBAAECggEACqdpBxYn1PoC6/zDaFzu9celKEWyTiuE/qRwvZa1ocS9
ZOJ0IPvVNud/S2NHsADJiSOQ8joSJScQvSsf1Ju4bv3MTw+wSQtAVUJz2nQ92uEi
5/xPAkEPfP3hNvebNLAOuvrBk8qYmOPCTIQaMNrOt6wzeXkAmJ9wLuRXNCsJLHW+
KLpf2WdgTYxqK06ZiJERFgJ2r1MsC2IgTydzjOAdEIrtMarerTLqqCpwFrk/l0cz
1O2OAb17ZxmhuzMhjNMin81c8F2fZAGMeOjn92Jl5kUsYw/pG+0S8QKlbveR/fdP
We2tJsgXw2zD0q7OJpp8NXS2yddrZGyysYsof983wQKBgQD2McqNJqo+eWL5zony
UbL19loYw0M15EjhzIuzW1Jk0rPj65yQyzpJ6pqicRuWr34MvzCx+ZHM2b3jSiNu
GES2fnC7xLIKyeRxfqsXF71xz+6UStEGRQX27r1YWEtyQVuBhvlqB+AGWP3PYAC+
HecZecnZ+vcihJ2K3+l5O3paVQKBgQDV6vKH5h2SY9vgO8obx0P7XSS+djHhmPuU
f8C/Fq6AuRbIA1g04pzuLU2WS9T26eIjgM173uVNg2TuqJveWzz+CAAp6nCR6l24
DBg49lMGCWrMo4FqPG46QkUqvK8uSj42GkX/e5Rut1Gyu0209emeM6h2d2K15SvY
9563tYSmGQKBgQDwcH5WTi20KA7e07TroJi8GKWzS3gneNUpGQBS4VxdtV4UuXXF
/4TkzafJ/9cm2iurvUmMd6XKP9lw0mY5zp/E70WgTCBp4vUlVsU3H2tYbO+filYL
3ntNx6nKTykX4/a/UJfj0t8as+zli+gNxNx/h+734V9dKdFG4Rl+2fTLpQKBgQCE
qJkTEe+Q0wCOBEYICADupwqcWqwAXWDW7IrZdfVtulqYWwqecVIkmk+dPxWosc4d
ekjz4nyNH0i+gC15LVebqdaAJ/T7aD4KXuW+nXNLMRfcJCGjgipRUruWD0EMEdqW
rqBuGXMpXeH6VxGPgVkJVLvKC6tZZe9VM+pnvteuMQKBgQC8GaL+Lz+al4biyZBf
JE8ekWrIotq/gfUBLP7x70+PB9bNtXtlgmTvjgYg4jiu3KR/ZIYYQ8vfVgkb6tDI
rWGZw86Pzuoi1ppg/pYhKk9qrmCIT4HPEXbHl7ATahu2BOCIU3hybjTh2lB6LbX9
8LMFlz1QPqSZYN/A/kOcLBfa3A==
-----END PRIVATE KEY-----
";
    const RS2: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDipm6FIKSRab3J
HwmK18t7hp+pohllxIDUSPi7S5mIhN/JG2Plq2Lp746E/fuT8dcBF2R4sJlG2L0J
zmxOvBU/i/sQF9s1i4CEfg05k2//gKENIEsF3pMMmrH+mcZi0TTD6rezHpdVxPHk
qWxSyOCtIJV29X+wxPwAB59kQFHzy2ooPB1isZcpE8tO0KthAM+oZ3KuCwE0++cO
IWLeq9aPwyKhtip/xjTMxd1kzdKh592mGSyzr9D0QSWOYFGvgJXANDdiPdhSSOLt
ECWPNPlm2FQvGGvYYBafUqz7VumKHE6x8J6lKdYa2J0ZdDzCIo2IHzlxe+RZNgwy
uAD2jhVxAgMBAAECggEAbsZHWBu3MzcKQiVARbLoygvnN0J5xUqAaMDtiKUPejDv
K1yOu67DXnDuKEP2VL2rhuYG/hHaKE1AP227c9PrUq6424m9YvM2sgrlrdFIuQkG
LeMtp8W7+zoUasp/ssZrUqICfLIj5xCl5UuFHQT/Ar7dLlIYwa3VOLKBDb9+Dnfe
QH5/So4uMXG6vw34JN9jf+eAc8Yt0PeIz62ycvRwdpTJQ0MxZN9ZKpCAQp+VTuXT
zlzNvDMilabEdqUvAyGyz8lBLNl0wdaVrqPqAEWM5U45QXsdFZknWammP7/tijeX
0z+Bi0J0uSEU5X502zm7GArj/NNIiWMcjmDjwUUhwQKBgQD9C2GoqxOxuVPYqwYR
+Jz7f2qMjlSP8adA5Lzuh8UKXDp8JCEQC8ryweLzaOKS9C5MAw+W4W2wd4nJoQI1
P1dgGvBlfvEeRHMgqWtq7FuTsjSe7e0uSEkC4ngDb4sc0QOpv15cMuEz+4+aFLPL
x29EcHWAaBX+rkid3zpQHFU4eQKBgQDlTCEqRuXwwa3V+Sq+mNWzD9QIGtD87TH/
FPO/Ij/cK2+GISgFDqhetiGTH4qrvPL0psPT+iH5zGFYcoFmTtwLdWQJdxhxz0bg
iX/AceyX5e1Bm+ThT36sU83NrxKPkrdk6jNmr2iUF1OTzTwUKOYdHOPZqdMPfF4M
4XAaWVT2uQKBgQD4nKcNdU+7LE9Rr+4d1/o8Klp/0BMK/ayK2HE7lc8kt6qKb2DA
iCWUTqPw7Fq3cQrPia5WWhNP7pJEtFkcAaiR9sW7onW5fBz0uR+dhK0QtmR2xWJj
N4fsOp8ZGQ0/eae0rh1CTobucLkM9EwV6VLLlgYL67e4anlUCo8bSEr+WQKBgQCB
uf6RgqcY/RqyklPCnYlZ0zyskS9nyXKd1GbK3j+u+swP4LZZlh9f5j88k33LCA2U
qLzmMwAB6cWxWqcnELqhqPq9+ClWSmTZKDGk2U936NfAZMirSGRsbsVi9wfTPriP
WYlXMSpDjqb0WgsBhNob4npubQxCGKTFOM5Jufy90QKBgB0Lte1jX144uaXx6dtB
rjXNuWNir0Jy31wHnQuCA+XnfUgPcrKmRLm8taMbXgZwxkNvgFkpUWU8aPEK08Ne
X0n5X2/pBLJzxZc62ccvZYVnctBiFs6HbSnxpuMQCfkt/BcR/ttIepBQQIW86wHL
5JiconnI5aLek0QVPoFaVXFa
-----END PRIVATE KEY-----
";

    #[derive(Clone)]
    struct Fetch(Vec<AuthRule>);

    impl FetchAuthRules for Fetch {
        async fn fetch_auth_rules(
            &self,
            _ctx: &RequestContext,
            _endpoint: EndpointId,
        ) -> Result<Vec<AuthRule>, FetchAuthRulesError> {
            Ok(self.0.clone())
        }
    }

    async fn jwks_server(
        router: impl for<'a> Fn(&'a str) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> SocketAddr {
        let router = Arc::new(router);
        let service = service_fn(move |req| {
            let router = Arc::clone(&router);
            async move {
                match router(req.uri().path()) {
                    Some(body) => Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from(body))),
                    None => Response::builder()
                        .status(404)
                        .body(Full::new(Bytes::new())),
                }
            }
        });

        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let server = hyper::server::conn::http1::Builder::new();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let serve = server.serve_connection(TokioIo::new(s), service.clone());
                tokio::spawn(serve.into_future());
            }
        });

        addr
    }

    #[tokio::test]
    async fn check_jwt_happy_path() {
        let (rs1, jwk1) = new_rsa_jwk(RS1, "rs1".into());
        let (rs2, jwk2) = new_rsa_jwk(RS2, "rs2".into());
        let (ec1, jwk3) = new_ec_jwk("ec1".into());
        let (ec2, jwk4) = new_ec_jwk("ec2".into());

        let foo_jwks = jwk_set(vec![jwk1, jwk3]);
        let bar_jwks = jwk_set(vec![jwk2, jwk4]);

        let jwks_addr = jwks_server(move |path| match path {
            "/foo" => Some(serde_json::to_vec(&foo_jwks).unwrap()),
            "/bar" => Some(serde_json::to_vec(&bar_jwks).unwrap()),
            _ => None,
        })
        .await;

        let role_name1 = RoleName::from("anonymous");
        let role_name2 = RoleName::from("authenticated");

        let roles = vec![
            RoleNameInt::from(&role_name1),
            RoleNameInt::from(&role_name2),
        ];
        let rules = vec![
            AuthRule {
                id: "foo".to_owned(),
                jwks_url: format!("http://{jwks_addr}/foo").parse().unwrap(),
                audience: None,
                role_names: roles.clone(),
            },
            AuthRule {
                id: "bar".to_owned(),
                jwks_url: format!("http://{jwks_addr}/bar").parse().unwrap(),
                audience: None,
                role_names: roles.clone(),
            },
        ];

        let fetch = Fetch(rules);
        let jwk_cache = JwkCache::default();

        let endpoint = EndpointId::from("ep");

        let jwt1 = new_rsa_jwt("rs1".into(), rs1);
        let jwt2 = new_rsa_jwt("rs2".into(), rs2);
        let jwt3 = new_ec_jwt("ec1".into(), &ec1);
        let jwt4 = new_ec_jwt("ec2".into(), &ec2);

        let tokens = [jwt1, jwt2, jwt3, jwt4];
        let role_names = [role_name1, role_name2];
        for role in &role_names {
            for token in &tokens {
                jwk_cache
                    .check_jwt(
                        &RequestContext::test(),
                        endpoint.clone(),
                        role,
                        &fetch,
                        token,
                    )
                    .await
                    .unwrap();
            }
        }
    }

    /// AWS Cognito escapes the `/` in the URL.
    #[tokio::test]
    async fn check_jwt_regression_cognito_issuer() {
        let (key, jwk) = new_ec_jwk("key".into());

        let now = now();
        let token = new_custom_ec_jwt(
            "key".into(),
            &key,
            typed_json::json! {{
                "sub": "dd9a73fd-e785-4a13-aae1-e691ce43e89d",
                // cognito uses `\/`. I cannot replicated that easily here as serde_json will refuse
                // to write that escape character. instead I will make a bogus URL using `\` instead.
                "iss": "https:\\\\cognito-idp.us-west-2.amazonaws.com\\us-west-2_abcdefgh",
                "client_id": "abcdefghijklmnopqrstuvwxyz",
                "origin_jti": "6759d132-3fe7-446e-9e90-2fe7e8017893",
                "event_id": "ec9c36ab-b01d-46a0-94e4-87fde6767065",
                "token_use": "access",
                "scope": "aws.cognito.signin.user.admin",
                "auth_time":now,
                "exp":now + 60,
                "iat":now,
                "jti": "b241614b-0b93-4bdc-96db-0a3c7061d9c0",
                "username": "dd9a73fd-e785-4a13-aae1-e691ce43e89d",
            }},
        );

        let jwks = jwk_set(vec![jwk]);

        let jwks_addr = jwks_server(move |_path| Some(serde_json::to_vec(&jwks).unwrap())).await;

        let role_name = RoleName::from("anonymous");
        let rules = vec![AuthRule {
            id: "aws-cognito".to_owned(),
            jwks_url: format!("http://{jwks_addr}/").parse().unwrap(),
            audience: None,
            role_names: vec![RoleNameInt::from(&role_name)],
        }];

        let fetch = Fetch(rules);
        let jwk_cache = JwkCache::default();

        let endpoint = EndpointId::from("ep");

        jwk_cache
            .check_jwt(
                &RequestContext::test(),
                endpoint.clone(),
                &role_name,
                &fetch,
                &token,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn check_jwt_invalid_signature() {
        let (_, jwk) = new_ec_jwk("1".into());
        let (key, _) = new_ec_jwk("1".into());

        // has a matching kid, but signed by the wrong key
        let bad_jwt = new_ec_jwt("1".into(), &key);

        let jwks = jwk_set(vec![jwk]);
        let jwks_addr = jwks_server(move |path| match path {
            "/" => Some(serde_json::to_vec(&jwks).unwrap()),
            _ => None,
        })
        .await;

        let role = RoleName::from("authenticated");

        let rules = vec![AuthRule {
            id: String::new(),
            jwks_url: format!("http://{jwks_addr}/").parse().unwrap(),
            audience: None,
            role_names: vec![RoleNameInt::from(&role)],
        }];

        let fetch = Fetch(rules);
        let jwk_cache = JwkCache::default();

        let ep = EndpointId::from("ep");

        let ctx = RequestContext::test();
        let err = jwk_cache
            .check_jwt(&ctx, ep, &role, &fetch, &bad_jwt)
            .await
            .unwrap_err();
        assert!(
            matches!(err, JwtError::Signature(_)),
            "expected \"signature error\", got {err:?}"
        );
    }

    #[tokio::test]
    async fn check_jwt_unknown_role() {
        let (key, jwk) = new_rsa_jwk(RS1, "1".into());
        let jwt = new_rsa_jwt("1".into(), key);

        let jwks = jwk_set(vec![jwk]);
        let jwks_addr = jwks_server(move |path| match path {
            "/" => Some(serde_json::to_vec(&jwks).unwrap()),
            _ => None,
        })
        .await;

        let role = RoleName::from("authenticated");
        let rules = vec![AuthRule {
            id: String::new(),
            jwks_url: format!("http://{jwks_addr}/").parse().unwrap(),
            audience: None,
            role_names: vec![RoleNameInt::from(&role)],
        }];

        let fetch = Fetch(rules);
        let jwk_cache = JwkCache::default();

        let ep = EndpointId::from("ep");

        // this role_name is not accepted
        let bad_role_name = RoleName::from("cloud_admin");

        let ctx = RequestContext::test();
        let err = jwk_cache
            .check_jwt(&ctx, ep, &bad_role_name, &fetch, &jwt)
            .await
            .unwrap_err();

        assert!(
            matches!(err, JwtError::JwkNotFound),
            "expected \"jwk not found\", got {err:?}"
        );
    }

    #[tokio::test]
    async fn check_jwt_invalid_claims() {
        let (key, jwk) = new_ec_jwk("1".into());

        let jwks = jwk_set(vec![jwk]);
        let jwks_addr = jwks_server(move |path| match path {
            "/" => Some(serde_json::to_vec(&jwks).unwrap()),
            _ => None,
        })
        .await;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        struct Test {
            body: serde_json::Value,
            error: JwtClaimsError,
        }

        let table = vec![
            Test {
                body: json! {{
                    "nbf": now + 60,
                    "aud": "neon",
                }},
                error: JwtClaimsError::JwtTokenNotYetReadyToUse(now + 60),
            },
            Test {
                body: json! {{
                    "exp": now - 60,
                    "aud": ["neon"],
                }},
                error: JwtClaimsError::JwtTokenHasExpired(now - 60),
            },
            Test {
                body: json! {{
                }},
                error: JwtClaimsError::InvalidJwtTokenAudience,
            },
            Test {
                body: json! {{
                    "aud": [],
                }},
                error: JwtClaimsError::InvalidJwtTokenAudience,
            },
            Test {
                body: json! {{
                    "aud": "foo",
                }},
                error: JwtClaimsError::InvalidJwtTokenAudience,
            },
            Test {
                body: json! {{
                    "aud": ["foo"],
                }},
                error: JwtClaimsError::InvalidJwtTokenAudience,
            },
            Test {
                body: json! {{
                    "aud": ["foo", "bar"],
                }},
                error: JwtClaimsError::InvalidJwtTokenAudience,
            },
        ];

        let role = RoleName::from("authenticated");

        let rules = vec![AuthRule {
            id: String::new(),
            jwks_url: format!("http://{jwks_addr}/").parse().unwrap(),
            audience: Some("neon".to_string()),
            role_names: vec![RoleNameInt::from(&role)],
        }];

        let fetch = Fetch(rules);
        let jwk_cache = JwkCache::default();

        let ep = EndpointId::from("ep");

        let ctx = RequestContext::test();
        for test in table {
            let jwt = new_custom_ec_jwt("1".into(), &key, test.body);

            match jwk_cache
                .check_jwt(&ctx, ep.clone(), &role, &fetch, &jwt)
                .await
            {
                Err(JwtError::InvalidClaims(error)) if error == test.error => {}
                Err(err) => {
                    panic!("expected {:?}, got {err:?}", test.error)
                }
                Ok(_payload) => {
                    panic!("expected {:?}, got ok", test.error)
                }
            }
        }
    }

    #[tokio::test]
    async fn check_jwk_keycloak_regression() {
        let (rs, valid_jwk) = new_rsa_jwk(RS1, "rs1".into());
        let valid_jwk = serde_json::to_value(valid_jwk).unwrap();

        // This is valid, but we cannot parse it as we have no support for encryption JWKs, only signature based ones.
        // This is taken directly from keycloak.
        let invalid_jwk = serde_json::json! {
            {
                "kid": "U-Jc9xRli84eNqRpYQoIPF-GNuRWV3ZvAIhziRW2sbQ",
                "kty": "RSA",
                "alg": "RSA-OAEP",
                "use": "enc",
                "n": "yypYWsEKmM_wWdcPnSGLSm5ytw1WG7P7EVkKSulcDRlrM6HWj3PR68YS8LySYM2D9Z-79oAdZGKhIfzutqL8rK1vS14zDuPpAM-RWY3JuQfm1O_-1DZM8-07PmVRegP5KPxsKblLf_My8ByH6sUOIa1p2rbe2q_b0dSTXYu1t0dW-cGL5VShc400YymvTwpc-5uYNsaVxZajnB7JP1OunOiuCJ48AuVp3PqsLzgoXqlXEB1ZZdch3xT3bxaTtNruGvG4xmLZY68O_T3yrwTCNH2h_jFdGPyXdyZToCMSMK2qSbytlfwfN55pT9Vv42Lz1YmoB7XRjI9aExKPc5AxFw",
                "e": "AQAB",
                "x5c": [
                    "MIICmzCCAYMCBgGS41E6azANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQxMDMxMTYwMTQ0WhcNMzQxMDMxMTYwMzI0WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLKlhawQqYz/BZ1w+dIYtKbnK3DVYbs/sRWQpK6VwNGWszodaPc9HrxhLwvJJgzYP1n7v2gB1kYqEh/O62ovysrW9LXjMO4+kAz5FZjcm5B+bU7/7UNkzz7Ts+ZVF6A/ko/GwpuUt/8zLwHIfqxQ4hrWnatt7ar9vR1JNdi7W3R1b5wYvlVKFzjTRjKa9PClz7m5g2xpXFlqOcHsk/U66c6K4InjwC5Wnc+qwvOCheqVcQHVll1yHfFPdvFpO02u4a8bjGYtljrw79PfKvBMI0faH+MV0Y/Jd3JlOgIxIwrapJvK2V/B83nmlP1W/jYvPViagHtdGMj1oTEo9zkDEXAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAECYX59+Q9v6c9sb6Q0/C6IgLWG2nVCgVE1YWwIzz+68WrhlmNCRuPjY94roB+tc2tdHbj+Nh3LMzJk7L1KCQoW1+LPK6A6E8W9ad0YPcuw8csV2pUA3+H56exQMH0fUAPQAU7tXWvnQ7otcpV1XA8afn/NTMTsnxi9mSkor8MLMYQ3aeRyh1+LAchHBthWiltqsSUqXrbJF59u5p0ghquuKcWR3TXsA7klGYBgGU5KAJifr9XT87rN0bOkGvbeWAgKvnQnjZwxdnLqTfp/pRY/PiJJHhgIBYPIA7STGnMPjmJ995i34zhnbnd8WHXJA3LxrIMqLW/l8eIdvtM1w8KI="
                ],
                "x5t": "QhfzMMnuAfkReTgZ1HtrfyOeeZs",
                "x5t#S256": "cmHDUdKgLiRCEN28D5FBy9IJLFmR7QWfm77SLhGTCTU"
            }
        };

        let jwks = serde_json::json! {{ "keys": [invalid_jwk, valid_jwk ] }};
        let jwks_addr = jwks_server(move |path| match path {
            "/" => Some(serde_json::to_vec(&jwks).unwrap()),
            _ => None,
        })
        .await;

        let role_name = RoleName::from("anonymous");
        let role = RoleNameInt::from(&role_name);

        let rules = vec![AuthRule {
            id: "foo".to_owned(),
            jwks_url: format!("http://{jwks_addr}/").parse().unwrap(),
            audience: None,
            role_names: vec![role],
        }];

        let fetch = Fetch(rules);
        let jwk_cache = JwkCache::default();

        let endpoint = EndpointId::from("ep");

        let token = new_rsa_jwt("rs1".into(), rs);

        jwk_cache
            .check_jwt(
                &RequestContext::test(),
                endpoint.clone(),
                &role_name,
                &fetch,
                &token,
            )
            .await
            .unwrap();
    }

    // ---- Parity cases. Each was run against the `jose-jwk` verifier first; the class
    // in each case is what it gave then ("ok" for accepted). On jsonwebtoken a case
    // jose-jwk accepted must still be accepted and every other case must be refused;
    // the refusal's `JwtError` class may differ. The JWKS documents are raw JSON and
    // the tokens are signed with aws-lc-rs, so nothing here depends on the JWK library
    // under test.

    mod parity {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::rsa::KeySize;
        use aws_lc_rs::signature::{
            ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
            KeyPair, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256,
            RsaEncoding, RsaKeyPair,
        };
        use base64::prelude::BASE64_STANDARD;
        use serde_json::{Value, json};

        use super::*;

        pub(super) const AUD: &str = "neon";

        pub(super) fn b64(bytes: impl AsRef<[u8]>) -> String {
            BASE64_URL_SAFE_NO_PAD.encode(bytes)
        }

        pub(super) fn now() -> u64 {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }

        /// A key that signs, and the JWK fields (`kty`, `crv`, `x`, `y` / `n`, `e`) of its
        /// public half.
        pub(super) enum TestKey {
            Ec(EcdsaKeyPair),
            Rsa(RsaKeyPair),
        }

        impl TestKey {
            pub(super) fn p256() -> Self {
                Self::Ec(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap())
            }
            pub(super) fn p384() -> Self {
                Self::Ec(EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap())
            }
            pub(super) fn rsa_pem(pem: &str) -> Self {
                let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
                let der = BASE64_STANDARD.decode(body).unwrap();
                Self::Rsa(RsaKeyPair::from_pkcs8(&der).unwrap())
            }
            pub(super) fn rsa(size: KeySize) -> Self {
                Self::Rsa(RsaKeyPair::generate(size).unwrap())
            }

            /// The public key's JWK members.
            pub(super) fn jwk(&self, kid: &str) -> Value {
                match self {
                    Self::Ec(kp) => {
                        let point = kp.public_key().as_ref();
                        let len = (point.len() - 1) / 2;
                        let crv = if len == 32 { "P-256" } else { "P-384" };
                        json!({
                            "kty": "EC",
                            "crv": crv,
                            "kid": kid,
                            "x": b64(&point[1..=len]),
                            "y": b64(&point[1 + len..]),
                        })
                    }
                    Self::Rsa(kp) => {
                        let pk = kp.public_key();
                        json!({
                            "kty": "RSA",
                            "kid": kid,
                            "n": b64(pk.modulus().big_endian_without_leading_zero()),
                            "e": b64(pk.exponent().big_endian_without_leading_zero()),
                        })
                    }
                }
            }

            /// The signature of `input` under `alg` (an ECDSA key signs with its own curve).
            pub(super) fn sign(&self, alg: &str, input: &[u8]) -> Vec<u8> {
                let rng = SystemRandom::new();
                match self {
                    Self::Ec(kp) => kp.sign(&rng, input).unwrap().as_ref().to_vec(),
                    Self::Rsa(kp) => {
                        let padding: &'static dyn RsaEncoding = match alg {
                            "RS384" => &RSA_PKCS1_SHA384,
                            "RS512" => &RSA_PKCS1_SHA512,
                            "PS256" => &RSA_PSS_SHA256,
                            _ => &RSA_PKCS1_SHA256,
                        };
                        let mut sig = vec![0; kp.public_modulus_len()];
                        kp.sign(padding, &rng, input, &mut sig).unwrap();
                        sig
                    }
                }
            }
        }

        pub(super) fn claims() -> Value {
            let now = now();
            json!({ "exp": now + 3600, "nbf": now, "aud": [AUD], "sub": "user1" })
        }

        /// `header.payload.signature`, signed by `signer` under the header's `alg`.
        pub(super) fn token(signer: &TestKey, header: &Value, payload: &Value) -> String {
            let input = format!(
                "{}.{}",
                b64(serde_json::to_vec(header).unwrap()),
                b64(serde_json::to_vec(payload).unwrap())
            );
            let alg = header["alg"].as_str().unwrap_or("");
            let sig = signer.sign(alg, input.as_bytes());
            format!("{input}.{}", b64(sig))
        }

        pub(super) fn header(alg: &str, kid: &str) -> Value {
            json!({ "alg": alg, "kid": kid, "typ": "JWT" })
        }

        /// Serve `jwks` and verify `token` against it, for a role the rule allows, with
        /// the rule's audience `AUD`.
        pub(super) async fn check(jwks: &Value, token: &str) -> Result<(), JwtError> {
            let body = serde_json::to_vec(jwks).unwrap();
            let addr = jwks_server(move |_| Some(body.clone())).await;
            let role = RoleName::from("authenticated");
            let fetch = Fetch(vec![AuthRule {
                id: "rule".to_owned(),
                jwks_url: format!("http://{addr}/").parse().unwrap(),
                audience: Some(AUD.to_owned()),
                role_names: vec![RoleNameInt::from(&role)],
            }]);
            JwkCache::default()
                .check_jwt(
                    &RequestContext::test(),
                    EndpointId::from("ep"),
                    &role,
                    &fetch,
                    token,
                )
                .await
                .map(|_| ())
        }

        /// The `JwtError` variant's name ("Signature", "JwkNotFound", ...), or "ok".
        pub(super) fn class(res: &Result<(), JwtError>) -> String {
            match res {
                Ok(()) => "ok".to_owned(),
                Err(e) => {
                    let debug = format!("{e:?}");
                    debug
                        .split(|c: char| !c.is_alphanumeric())
                        .next()
                        .unwrap()
                        .to_owned()
                }
            }
        }

        /// Run every `(name, jwks, token, jose-jwk class)` case and print what each
        /// gave. Fail, listing them, on every case jose-jwk accepted ("ok") that is now
        /// refused, or that it refused and is now accepted.
        pub(super) async fn run(cases: Vec<(&str, Value, String, &str)>) {
            let mut wrong = vec![];
            for (name, jwks, token, before) in cases {
                let res = check(&jwks, &token).await;
                let got = class(&res);
                println!("{name}: {got} (jose-jwk: {before}) ({res:?})");
                if (got == "ok") != (before == "ok") {
                    wrong.push(format!("{name}: jose-jwk {before}, now {got} ({res:?})"));
                }
            }
            assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        }

        /// `jwk` with `edit` applied to its members.
        pub(super) fn with(
            mut jwk: Value,
            edit: impl FnOnce(&mut serde_json::Map<String, Value>),
        ) -> Value {
            edit(jwk.as_object_mut().unwrap());
            jwk
        }

        pub(super) fn set(keys: &[Value]) -> Value {
            json!({ "keys": keys })
        }

        /// Flip one bit of the signature's first byte.
        pub(super) fn tamper(token: &str) -> String {
            let (input, sig) = token.rsplit_once('.').unwrap();
            let mut sig = BASE64_URL_SAFE_NO_PAD.decode(sig).unwrap();
            sig[0] ^= 1;
            format!("{input}.{}", b64(sig))
        }

        /// The token with its signature replaced by `sig` (base64url text).
        pub(super) fn resig(token: &str, sig: &str) -> String {
            let (input, _) = token.rsplit_once('.').unwrap();
            format!("{input}.{sig}")
        }

        pub(super) fn rsa3072() -> TestKey {
            TestKey::rsa(KeySize::Rsa3072)
        }
    }

    use parity::{AUD, TestKey, b64, check, class, header, run, set, token, with};
    use serde_json::Value;

    /// AC 3: a JWKS with P-256, P-384 and RSA keys. ES256 on P-256 and RS256 on RSA are
    /// the algorithms the verifier accepts; the P-384 key and the other RSA algorithms
    /// are refused (they always were: only ES256 and RS256 have a verifier).
    #[tokio::test]
    async fn parity_accepted_algorithms() {
        let (ec, p384, rsa) = (TestKey::p256(), TestKey::p384(), TestKey::rsa_pem(RS1));
        let rsa3k = parity::rsa3072();
        let jwks = set(&[
            ec.jwk("ec"),
            p384.jwk("p384"),
            rsa.jwk("rsa"),
            rsa3k.jwk("rsa3k"),
            with(ec.jwk("ec-alg"), |k| {
                k.insert("alg".into(), "ES256".into());
                k.insert("use".into(), "sig".into());
                k.insert("key_ops".into(), json!(["verify"]));
            }),
            with(rsa.jwk("rsa-alg"), |k| {
                k.insert("alg".into(), "RS256".into());
            }),
        ]);
        let c = parity::claims();
        run(vec![
            (
                "ES256 / P-256",
                jwks.clone(),
                token(&ec, &header("ES256", "ec"), &c),
                "ok",
            ),
            (
                "ES256 / P-256 alg ES256",
                jwks.clone(),
                token(&ec, &header("ES256", "ec-alg"), &c),
                "ok",
            ),
            (
                "RS256 / RSA-2048",
                jwks.clone(),
                token(&rsa, &header("RS256", "rsa"), &c),
                "ok",
            ),
            (
                "RS256 / RSA-2048 alg RS256",
                jwks.clone(),
                token(&rsa, &header("RS256", "rsa-alg"), &c),
                "ok",
            ),
            (
                "RS256 / RSA-3072",
                jwks.clone(),
                token(&rsa3k, &header("RS256", "rsa3k"), &c),
                "ok",
            ),
            (
                "ES384 / P-384",
                jwks.clone(),
                token(&p384, &header("ES384", "p384"), &c),
                "UnsupportedEcKeyType",
            ),
            (
                "RS384 / RSA-2048",
                jwks.clone(),
                token(&rsa, &header("RS384", "rsa"), &c),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "RS384 / RSA-3072",
                jwks.clone(),
                token(&rsa3k, &header("RS384", "rsa3k"), &c),
                "InvalidRsaSigningAlgorithm",
            ),
            (
                "RS512 / RSA-3072",
                jwks.clone(),
                token(&rsa3k, &header("RS512", "rsa3k"), &c),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "PS256 / RSA-2048",
                jwks.clone(),
                token(&rsa, &header("PS256", "rsa"), &c),
                "InvalidRsaSigningAlgorithm",
            ),
            (
                "PS256 / RSA-3072",
                jwks.clone(),
                token(&rsa3k, &header("PS256", "rsa3k"), &c),
                "InvalidRsaSigningAlgorithm",
            ),
        ])
        .await;
    }

    /// AC 4: each refusal keeps its `JwtError` class.
    #[tokio::test]
    async fn parity_key_lookup_signature_and_alg() {
        let (ec, rsa, other) = (TestKey::p256(), TestKey::rsa_pem(RS1), TestKey::p256());
        let jwks = set(&[
            ec.jwk("ec"),
            rsa.jwk("rsa"),
            with(ec.jwk("ec-rs256"), |k| {
                k.insert("alg".into(), "RS256".into());
            }),
            with(rsa.jwk("rsa-ps256"), |k| {
                k.insert("alg".into(), "PS256".into());
            }),
            json!({ "kty": "oct", "kid": "oct", "k": b64([7u8; 32]) }),
            json!({ "kty": "OKP", "crv": "Ed25519", "kid": "okp", "x": b64([9u8; 32]) }),
        ]);
        let c = parity::claims();
        let es = token(&ec, &header("ES256", "ec"), &c);
        let rs = token(&rsa, &header("RS256", "rsa"), &c);
        let input = |t: &str| t.rsplit_once('.').unwrap().0.to_owned();
        let unsigned = |alg: &str, kid: &str| {
            format!(
                "{}.{}.",
                b64(serde_json::to_vec(&header(alg, kid)).unwrap()),
                b64(serde_json::to_vec(&c).unwrap())
            )
        };
        let no_kid = format!(
            "{}.{}",
            b64(serde_json::to_vec(&json!({ "alg": "ES256" })).unwrap()),
            b64(serde_json::to_vec(&c).unwrap())
        );
        let no_kid = format!("{no_kid}.{}", b64(ec.sign("ES256", no_kid.as_bytes())));
        run(vec![
            // key not found
            (
                "kid not in the JWKS",
                jwks.clone(),
                token(&ec, &header("ES256", "nope"), &c),
                "JwkNotFound",
            ),
            ("no kid", jwks.clone(), no_kid, "MissingKeyId"),
            // signature
            (
                "ES256 signed by another key",
                jwks.clone(),
                token(&other, &header("ES256", "ec"), &c),
                "Signature",
            ),
            (
                "ES256 tampered",
                jwks.clone(),
                parity::tamper(&es),
                "Signature",
            ),
            (
                "ES256 empty signature",
                jwks.clone(),
                parity::resig(&es, ""),
                "Signature",
            ),
            (
                "ES256 63-byte signature",
                jwks.clone(),
                parity::resig(&es, &b64([1u8; 63])),
                "Signature",
            ),
            (
                "ES256 zero signature",
                jwks.clone(),
                parity::resig(&es, &b64([0u8; 64])),
                "Signature",
            ),
            (
                "ES256 padded signature",
                jwks.clone(),
                format!("{es}="),
                "JwtEncoding",
            ),
            (
                "RS256 tampered",
                jwks.clone(),
                parity::tamper(&rs),
                "Signature",
            ),
            (
                "RS256 short signature",
                jwks.clone(),
                parity::resig(&rs, &b64([1u8; 255])),
                "Signature",
            ),
            (
                "RS256 signed by another key",
                jwks.clone(),
                token(&TestKey::rsa_pem(RS2), &header("RS256", "rsa"), &c),
                "Signature",
            ),
            (
                "alg none, no signature",
                jwks.clone(),
                unsigned("none", "ec"),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "alg none, ES256 signature",
                jwks.clone(),
                format!(
                    "{}.{}",
                    unsigned("none", "ec").trim_end_matches('.'),
                    b64(ec.sign("ES256", input(&unsigned("none", "ec")).as_bytes()))
                ),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "alg None",
                jwks.clone(),
                unsigned("None", "ec"),
                "JwtEncoding",
            ),
            (
                "alg es256 (lower case)",
                jwks.clone(),
                token(&ec, &header("es256", "ec"), &c),
                "JwtEncoding",
            ),
            (
                "alg FOO",
                jwks.clone(),
                token(&ec, &header("FOO", "ec"), &c),
                "JwtEncoding",
            ),
            // unsupported algorithm
            (
                "HS256 against an EC key",
                jwks.clone(),
                unsigned("HS256", "ec"),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "HS256 against an RSA key",
                jwks.clone(),
                unsigned("HS256", "rsa"),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "ES256 against an RSA key",
                jwks.clone(),
                token(&ec, &header("ES256", "rsa"), &c),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "RS256 against an EC key",
                jwks.clone(),
                token(&rsa, &header("RS256", "ec"), &c),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "ES384 against a P-256 key",
                jwks.clone(),
                token(&ec, &header("ES384", "ec"), &c),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "ES256K against a P-256 key",
                jwks.clone(),
                token(&ec, &header("ES256K", "ec"), &c),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "EdDSA against a P-256 key",
                jwks.clone(),
                token(&ec, &header("EdDSA", "ec"), &c),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "ES256 against an EC key with alg RS256",
                jwks.clone(),
                token(&ec, &header("ES256", "ec-rs256"), &c),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "RS256 against an RSA key with alg PS256",
                jwks.clone(),
                token(&rsa, &header("RS256", "rsa-ps256"), &c),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "PS256 against an RSA key with alg PS256",
                jwks.clone(),
                token(&rsa, &header("PS256", "rsa-ps256"), &c),
                "InvalidRsaSigningAlgorithm",
            ),
            (
                "HS256 against an oct key",
                jwks.clone(),
                unsigned("HS256", "oct"),
                "UnsupportedKeyType",
            ),
            (
                "ES256 against an oct key",
                jwks.clone(),
                unsigned("ES256", "oct"),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "EdDSA against an OKP key",
                jwks.clone(),
                unsigned("EdDSA", "okp"),
                "UnsupportedKeyType",
            ),
        ])
        .await;
    }

    /// AC 4: curve confusion, bad points and incomplete JWKs.
    #[tokio::test]
    async fn parity_bad_keys() {
        let (ec, p384, rsa) = (TestKey::p256(), TestKey::p384(), TestKey::rsa_pem(RS1));
        let ec_jwk = ec.jwk("k");
        let get = |jwk: &Value, m: &str| {
            BASE64_URL_SAFE_NO_PAD
                .decode(jwk[m].as_str().unwrap())
                .unwrap()
        };
        let (ec_x, ec_y) = (get(&ec_jwk, "x"), get(&ec_jwk, "y"));
        let mut y1 = ec_y.clone();
        *y1.last_mut().unwrap() ^= 1;
        let p256_p: Vec<u8> = (0..32).map(|_| 0xffu8).collect();
        let rsa_jwk = rsa.jwk("k");
        let rsa_n = get(&rsa_jwk, "n");
        let mut n0 = vec![0u8];
        n0.extend_from_slice(&rsa_n);
        // A 8192-bit modulus (odd, top bit set). Nothing can sign for it; the key must be
        // refused before any signature check.
        let mut n8k = vec![0xc5u8; 1024];
        n8k[1023] |= 1;
        let claims = parity::claims();
        let es = token(&ec, &header("ES256", "k"), &claims);
        let es384 = token(&p384, &header("ES384", "k"), &claims);
        let p384_as_p256 = with(p384.jwk("k"), |k| {
            k.insert("crv".into(), "P-256".into());
        });
        let rs = token(&rsa, &header("RS256", "k"), &claims);
        let one = |jwk: Value| set(&[jwk]);
        let ec_with = |edit: &dyn Fn(&mut serde_json::Map<String, Value>)| {
            one(with(ec_jwk.clone(), |k| edit(k)))
        };
        let rsa_with = |edit: &dyn Fn(&mut serde_json::Map<String, Value>)| {
            one(with(rsa_jwk.clone(), |k| edit(k)))
        };
        run(vec![
            (
                "P-384 key labelled P-256, ES256",
                one(p384_as_p256.clone()),
                resign(&p384, &header("ES256", "k"), &claims),
                "InvalidP256Key",
            ),
            (
                "P-384 key labelled P-256, ES384",
                one(p384_as_p256.clone()),
                es384.clone(),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "P-256 key labelled P-384, ES384",
                ec_with(&|k| {
                    k.insert("crv".into(), "P-384".into());
                }),
                resign(&ec, &header("ES384", "k"), &claims),
                "UnsupportedEcKeyType",
            ),
            (
                "P-256 key labelled P-384, ES256",
                ec_with(&|k| {
                    k.insert("crv".into(), "P-384".into());
                }),
                es.clone(),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "P-256 key labelled P-521, ES512",
                ec_with(&|k| {
                    k.insert("crv".into(), "P-521".into());
                }),
                resign(&ec, &header("ES512", "k"), &claims),
                "UnsupportedEcKeyType",
            ),
            (
                "P-256 key labelled secp256k1, ES256K",
                ec_with(&|k| {
                    k.insert("crv".into(), "secp256k1".into());
                }),
                resign(&ec, &header("ES256K", "k"), &claims),
                "UnsupportedEcKeyType",
            ),
            (
                "P-256 key with crv Ed25519",
                ec_with(&|k| {
                    k.insert("crv".into(), "Ed25519".into());
                }),
                es.clone(),
                "JwkNotFound",
            ),
            (
                "P-256 key with no crv",
                ec_with(&|k| {
                    k.remove("crv");
                }),
                es.clone(),
                "JwkNotFound",
            ),
            (
                "off-curve point",
                ec_with(&|k| {
                    k.insert("y".into(), b64(&y1).into());
                }),
                es.clone(),
                "InvalidP256Key",
            ),
            (
                "x = p (not a field element)",
                ec_with(&|k| {
                    k.insert("x".into(), b64(&p256_p).into());
                }),
                es.clone(),
                "InvalidP256Key",
            ),
            (
                "31-byte x",
                ec_with(&|k| {
                    k.insert("x".into(), b64(&ec_x[1..]).into());
                }),
                es.clone(),
                "InvalidP256Key",
            ),
            (
                "33-byte x (leading zero)",
                ec_with(&|k| {
                    let mut v0 = vec![0];
                    v0.extend_from_slice(&ec_x);
                    k.insert("x".into(), b64(v0).into());
                }),
                es.clone(),
                "InvalidP256Key",
            ),
            (
                "x and y swapped",
                ec_with(&|k| {
                    k.insert("x".into(), b64(&ec_y).into());
                    k.insert("y".into(), b64(&ec_x).into());
                }),
                es.clone(),
                "InvalidP256Key",
            ),
            (
                "EC JWK missing x",
                ec_with(&|k| {
                    k.remove("x");
                }),
                es.clone(),
                "JwkNotFound",
            ),
            (
                "EC JWK missing y",
                ec_with(&|k| {
                    k.remove("y");
                }),
                es.clone(),
                "JwkNotFound",
            ),
            (
                "EC JWK with padded x",
                ec_with(&|k| {
                    let v = format!("{}=", k["x"].as_str().unwrap());
                    k.insert("x".into(), v.into());
                }),
                es.clone(),
                "JwkNotFound",
            ),
            (
                "EC JWK with standard-alphabet x",
                ec_with(&|k| {
                    let v = format!("+{}", &k["x"].as_str().unwrap()[1..]);
                    k.insert("x".into(), v.into());
                }),
                es.clone(),
                "JwkNotFound",
            ),
            (
                "EC JWK with x as a number",
                ec_with(&|k| {
                    k.insert("x".into(), 5.into());
                }),
                es.clone(),
                "JwkNotFound",
            ),
            (
                "EC JWK with non-canonical x",
                ec_with(&|k| {
                    k.insert("x".into(), non_canonical(k["x"].as_str().unwrap()).into());
                }),
                es.clone(),
                "JwkNotFound",
            ),
            (
                "EC JWK with d",
                ec_with(&|k| {
                    k.insert("d".into(), b64([5u8; 32]).into());
                }),
                es.clone(),
                "ok",
            ),
            (
                "ES256 high-S signature",
                one(ec_jwk.clone()),
                high_s(&es),
                "ok",
            ),
            (
                "OKP JWK with crv P-256",
                one(json!({ "kty": "OKP", "crv": "P-256", "kid": "k", "x": b64([3u8; 32]) })),
                resign(&ec, &header("EdDSA", "k"), &claims),
                "JwkNotFound",
            ),
            (
                "OKP JWK with no x",
                one(json!({ "kty": "OKP", "crv": "Ed25519", "kid": "k" })),
                resign(&ec, &header("EdDSA", "k"), &claims),
                "JwkNotFound",
            ),
            (
                "oct JWK with padded k",
                one(json!({ "kty": "oct", "kid": "k", "k": "AAAA=" })),
                resign(&ec, &header("HS256", "k"), &claims),
                "JwkNotFound",
            ),
            (
                "oct JWK with an 8-byte k",
                one(json!({ "kty": "oct", "kid": "k", "k": b64([1u8; 8]) })),
                resign(&ec, &header("HS256", "k"), &claims),
                "SignatureAlgorithmNotSupported",
            ),
            (
                "RSA JWK with d",
                rsa_with(&|k| {
                    k.insert("d".into(), b64([5u8; 256]).into());
                }),
                rs.clone(),
                "ok",
            ),
            (
                "RSA JWK missing n",
                rsa_with(&|k| {
                    k.remove("n");
                }),
                rs.clone(),
                "JwkNotFound",
            ),
            (
                "RSA JWK missing e",
                rsa_with(&|k| {
                    k.remove("e");
                }),
                rs.clone(),
                "JwkNotFound",
            ),
            (
                "RSA JWK with kty EC",
                rsa_with(&|k| {
                    k.insert("kty".into(), "EC".into());
                }),
                rs.clone(),
                "JwkNotFound",
            ),
            (
                "RSA n with a leading zero byte",
                rsa_with(&|k| {
                    k.insert("n".into(), b64(&n0).into());
                }),
                rs.clone(),
                // jose-jwk: ok. aws-lc refuses a modulus with a leading zero byte (RFC 7518 6.3.1.1 forbids it).
                "refused",
            ),
            (
                "RSA e = 1",
                rsa_with(&|k| {
                    k.insert("e".into(), b64([1u8]).into());
                }),
                rs.clone(),
                "InvalidRsaKey",
            ),
            (
                "RSA e = 0",
                rsa_with(&|k| {
                    k.insert("e".into(), "".into());
                }),
                rs.clone(),
                "InvalidRsaKey",
            ),
            (
                "RSA e = 2^33",
                rsa_with(&|k| {
                    k.insert("e".into(), b64([2u8, 0, 0, 0, 0]).into());
                }),
                rs.clone(),
                "InvalidRsaKey",
            ),
            (
                "RSA 8192-bit n",
                rsa_with(&|k| {
                    k.insert("n".into(), b64(&n8k).into());
                }),
                rs.clone(),
                "InvalidRsaKey",
            ),
            (
                "RSA 1024-bit n",
                rsa_with(&|k| {
                    k.insert("n".into(), b64(&rsa_n[..128]).into());
                }),
                rs.clone(),
                "SignatureAlgorithmNotSupported",
            ),
        ])
        .await;
    }

    /// `value` (base64url, a length that leaves spare bits in its last character) with
    /// those spare bits set.
    fn non_canonical(value: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut bytes = value.as_bytes().to_vec();
        let last = bytes.last_mut().unwrap();
        let idx = ALPHABET.iter().position(|c| c == last).unwrap();
        *last = ALPHABET[idx | 1];
        String::from_utf8(bytes).unwrap()
    }

    /// The token with its ES256 signature (r, s) replaced by (r, n - s).
    fn high_s(token: &str) -> String {
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let (input, sig) = token.rsplit_once('.').unwrap();
        let mut sig = BASE64_URL_SAFE_NO_PAD.decode(sig).unwrap();
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(N[i]) - i16::from(sig[32 + i]) - borrow;
            borrow = i16::from(d < 0);
            sig[32 + i] = (d + 256 * borrow) as u8;
        }
        format!("{input}.{}", b64(sig))
    }

    /// Sign with `signer`, whatever the header's `alg` says.
    fn resign(signer: &TestKey, header: &serde_json::Value, payload: &serde_json::Value) -> String {
        let input = format!(
            "{}.{}",
            b64(serde_json::to_vec(header).unwrap()),
            b64(serde_json::to_vec(payload).unwrap())
        );
        format!("{input}.{}", b64(signer.sign("", input.as_bytes())))
    }

    /// AC 4: `use` filtering and the claim checks (audience, `exp`/`nbf` with the 30 s
    /// leeway).
    #[tokio::test]
    async fn parity_use_and_claims() {
        let ec = TestKey::p256();
        let jwks = set(&[
            ec.jwk("k"),
            with(ec.jwk("enc"), |k| {
                k.insert("use".into(), "enc".into());
            }),
            with(ec.jwk("use-foo"), |k| {
                k.insert("use".into(), "foo".into());
            }),
            with(ec.jwk("ops-foo"), |k| {
                k.insert("key_ops".into(), json!(["verify", "foo"]));
            }),
            with(ec.jwk("ops-sign"), |k| {
                k.insert("key_ops".into(), json!(["sign"]));
            }),
            with(ec.jwk("alg-oaep"), |k| {
                k.insert("alg".into(), "RSA-OAEP".into());
            }),
            with(ec.jwk("x5t-short"), |k| {
                k.insert("x5t".into(), b64([1u8; 19]).into());
            }),
            with(ec.jwk("x5t"), |k| {
                k.insert("x5t".into(), b64([1u8; 20]).into());
                k.insert("x5t#S256".into(), b64([1u8; 32]).into());
                k.insert("x5c".into(), json!(["AAEC"]));
                k.insert("x5u".into(), "not a url".into());
            }),
            with(ec.jwk("x5c-url"), |k| {
                k.insert("x5c".into(), json!(["AA-_"]));
            }),
        ]);
        let now = parity::now();
        let tok = |kid: &str, claims: serde_json::Value| token(&ec, &header("ES256", kid), &claims);
        run(vec![
            (
                "use: enc",
                jwks.clone(),
                tok("enc", parity::claims()),
                "JwkNotFound",
            ),
            (
                "use: foo",
                jwks.clone(),
                tok("use-foo", parity::claims()),
                "JwkNotFound",
            ),
            (
                "key_ops with an unknown op",
                jwks.clone(),
                tok("ops-foo", parity::claims()),
                // jose-jwk: JwkNotFound (it parsed this member strictly). Harmless: proxy never reads it.
                "ok",
            ),
            (
                "key_ops: sign only",
                jwks.clone(),
                tok("ops-sign", parity::claims()),
                "ok",
            ),
            (
                "alg: RSA-OAEP",
                jwks.clone(),
                tok("alg-oaep", parity::claims()),
                "JwkNotFound",
            ),
            (
                "19-byte x5t",
                jwks.clone(),
                tok("x5t-short", parity::claims()),
                // jose-jwk: JwkNotFound (it parsed this member strictly). Harmless: proxy never reads it.
                "ok",
            ),
            (
                "x5t, x5t#S256, x5c, x5u",
                jwks.clone(),
                tok("x5t", parity::claims()),
                "ok",
            ),
            (
                "x5c in base64url",
                jwks.clone(),
                tok("x5c-url", parity::claims()),
                // jose-jwk: JwkNotFound (it parsed this member strictly). Harmless: proxy never reads it.
                "ok",
            ),
            (
                "audience matches",
                jwks.clone(),
                tok("k", json!({ "aud": "neon" })),
                "ok",
            ),
            (
                "audience in a list",
                jwks.clone(),
                tok("k", json!({ "aud": ["x", "neon"] })),
                "ok",
            ),
            (
                "wrong audience",
                jwks.clone(),
                tok("k", json!({ "aud": "neon2" })),
                "InvalidClaims",
            ),
            (
                "audience of other case",
                jwks.clone(),
                tok("k", json!({ "aud": "Neon" })),
                "InvalidClaims",
            ),
            (
                "no audience",
                jwks.clone(),
                tok("k", json!({})),
                "InvalidClaims",
            ),
            (
                "audience a number",
                jwks.clone(),
                tok("k", json!({ "aud": 1 })),
                "JwtEncoding",
            ),
            (
                "expired inside the leeway",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "exp": now - 20 })),
                "ok",
            ),
            (
                "expired outside the leeway",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "exp": now - 40 })),
                "InvalidClaims",
            ),
            (
                "exp 0",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "exp": 0 })),
                "InvalidClaims",
            ),
            (
                "exp a string",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "exp": (now + 60).to_string() })),
                "JwtEncoding",
            ),
            (
                "exp negative",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "exp": -1 })),
                "JwtEncoding",
            ),
            (
                "exp a float",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "exp": (now + 60) as f64 + 0.5 })),
                "JwtEncoding",
            ),
            (
                "exp null",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "exp": null })),
                "ok",
            ),
            (
                "not yet valid inside the leeway",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "nbf": now + 20 })),
                "ok",
            ),
            (
                "not yet valid outside the leeway",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "nbf": now + 40 })),
                "InvalidClaims",
            ),
            (
                "nbf u64::MAX",
                jwks.clone(),
                tok("k", json!({ "aud": AUD, "nbf": u64::MAX })),
                "JwtEncoding",
            ),
        ])
        .await;
    }

    /// AC 5: a JWKS with entries of an unknown `kty`, unknown members and keys of other
    /// types: the bad entries are skipped and the good keys still verify.
    #[tokio::test]
    async fn jwks_skips_unknown_entries() {
        let (ec, rsa) = (TestKey::p256(), TestKey::rsa_pem(RS1));
        let jwks = json!({ "keys": [
            { "kty": "foo", "kid": "ec", "x": "y" },
            { "kid": "ec" },
            0,
            "a string",
            { "kty": "OKP", "crv": "X25519", "kid": "x25519", "x": b64([3u8; 32]) },
            { "kty": "OKP", "crv": "Ed448", "kid": "ed448", "x": b64([3u8; 57]) },
            { "kty": "EC", "crv": "P-256", "kid": "ec", "x": "not base64!" , "y": "AA" },
            with(ec.jwk("ec"), |k| {
                k.insert("extra".into(), json!({ "nested": [1, 2, 3] }));
                k.insert("ext".into(), true.into());
            }),
            with(rsa.jwk("rsa"), |k| {
                k.insert("x5c".into(), json!([]));
                k.insert("qi".into(), "unused".into());
            }),
        ], "extra": "member" });
        let c = parity::claims();
        run(vec![
            (
                "P-256 key after bad entries with its kid",
                jwks.clone(),
                token(&ec, &header("ES256", "ec"), &c),
                "ok",
            ),
            (
                "RSA key with extra members",
                jwks.clone(),
                token(&rsa, &header("RS256", "rsa"), &c),
                "ok",
            ),
            (
                "X25519 key",
                jwks.clone(),
                resign(&ec, &header("EdDSA", "x25519"), &c),
                "UnsupportedKeyType",
            ),
            (
                "Ed448 key",
                jwks.clone(),
                resign(&ec, &header("EdDSA", "ed448"), &c),
                "UnsupportedKeyType",
            ),
        ])
        .await;
        // Only unusable entries: the JWKS gives no key at all.
        let only_bad = json!({ "keys": [{ "kty": "foo", "kid": "ec" }] });
        assert_eq!(
            class(&check(&only_bad, &token(&ec, &header("ES256", "ec"), &c)).await),
            "JwkNotFound"
        );
    }
}
