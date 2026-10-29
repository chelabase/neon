// For details about authentication see docs/authentication.md

use std::borrow::Cow;
use std::fmt::Display;
use std::fs;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use camino::Utf8Path;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
    errors::ErrorKind,
};
use pem::Pem;
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::id::TenantId;

/// Algorithm to use. We require EdDSA.
const STORAGE_TOKEN_ALGORITHM: Algorithm = Algorithm::EdDSA;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Provides access to all data for a specific tenant (specified in `struct Claims` below)
    // TODO: join these two?
    Tenant,
    /// Provides access to all data for a specific tenant, but based on endpoint ID. This token scope
    /// is only used by compute to fetch the spec for a specific endpoint. The spec contains a Tenant-scoped
    /// token authorizing access to all data of a tenant, so the spec-fetch API requires a TenantEndpoint
    /// scope token to ensure that untrusted compute nodes can't fetch spec for arbitrary endpoints.
    TenantEndpoint,
    /// Provides blanket access to all tenants on the pageserver plus pageserver-wide APIs.
    /// Should only be used e.g. for status check/tenant creation/list.
    PageServerApi,
    /// Provides blanket access to all data on the safekeeper plus safekeeper-wide APIs.
    /// Should only be used e.g. for status check.
    /// Currently also used for connection from any pageserver to any safekeeper.
    SafekeeperData,
    /// The scope used by pageservers in upcalls to storage controller and cloud control plane
    #[serde(rename = "generations_api")]
    GenerationsApi,
    /// Allows access to control plane managment API and all storage controller endpoints.
    Admin,

    /// Allows access to control plane & storage controller endpoints used in infrastructure automation (e.g. node registration)
    Infra,

    /// Allows access to storage controller APIs used by the scrubber, to interrogate the state
    /// of a tenant & post scrub results.
    Scrubber,

    /// This scope is used for communication with other storage controller instances.
    /// At the time of writing, this is only used for the step down request.
    #[serde(rename = "controller_peer")]
    ControllerPeer,

    /// Read-only access to `/metrics` on the pageserver, the safekeeper and the storage
    /// controller (and compute_ctl's metrics routes). It opens no other route, libpq
    /// included. A metrics token carries `scope` and `iat`, and no `tenant_id`.
    Metrics,
}

fn deserialize_empty_string_as_none_uuid<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt.as_deref() {
        Some("") => Ok(None),
        Some(s) => Uuid::parse_str(s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

/// JWT payload. See docs/authentication.md for the format
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Claims {
    #[serde(default)]
    pub tenant_id: Option<TenantId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        // Neon control plane includes this field as empty in the claims.
        // Consider it None in those cases.
        deserialize_with = "deserialize_empty_string_as_none_uuid"
    )]
    pub endpoint_id: Option<Uuid>,
    pub scope: Scope,
}

impl Claims {
    pub fn new(tenant_id: Option<TenantId>, scope: Scope) -> Self {
        Self {
            tenant_id,
            scope,
            endpoint_id: None,
        }
    }
}

pub struct SwappableJwtAuth(ArcSwap<JwtAuth>);

impl SwappableJwtAuth {
    pub fn new(jwt_auth: JwtAuth) -> Self {
        SwappableJwtAuth(ArcSwap::new(Arc::new(jwt_auth)))
    }
    pub fn swap(&self, jwt_auth: JwtAuth) {
        self.0.swap(Arc::new(jwt_auth));
    }
    pub fn decode<D: DeserializeOwned>(
        &self,
        token: &str,
    ) -> std::result::Result<TokenData<D>, AuthError> {
        self.0.load().decode(token)
    }
}

impl std::fmt::Debug for SwappableJwtAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Swappable({:?})", self.0.load())
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AuthError(pub Cow<'static, str>);

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct JwtAuth {
    decoding_keys: Vec<DecodingKey>,
    validation: Validation,
}

impl JwtAuth {
    pub fn new(decoding_keys: Vec<DecodingKey>) -> Self {
        // Every field is spelled out (no `..Default::default()`), so a library upgrade
        // can't change one silently and a new field fails to compile here.
        let validation = Validation {
            algorithms: vec![STORAGE_TOKEN_ALGORITHM],
            // The default 'required_spec_claims' is 'exp'. But we don't want to require
            // expiration.
            required_spec_claims: [].into(),
            // An `exp` or `nbf` a token carries is still checked (with a 60 s leeway): a
            // token isn't valid after `exp` nor before `nbf`.
            validate_exp: true,
            validate_nbf: true,
            leeway: 60,
            reject_tokens_expiring_in_less_than: 0,
            // No audience is expected, so a token that carries `aud` is refused.
            validate_aud: true,
            aud: None,
            iss: None,
            sub: None,
        };
        Self {
            decoding_keys,
            validation,
        }
    }

    pub fn from_key_path(key_path: &Utf8Path) -> Result<Self> {
        let metadata = key_path.metadata()?;
        let decoding_keys = if metadata.is_dir() {
            let mut keys = Vec::new();
            for entry in fs::read_dir(key_path)? {
                let path = entry?.path();
                if !path.is_file() {
                    // Ignore directories (don't recurse)
                    continue;
                }
                let public_key = fs::read(path)?;
                keys.push(DecodingKey::from_ed_pem(&public_key)?);
            }
            keys
        } else if metadata.is_file() {
            let public_key = fs::read(key_path)?;
            vec![DecodingKey::from_ed_pem(&public_key)?]
        } else {
            anyhow::bail!("path is neither a directory or a file")
        };
        if decoding_keys.is_empty() {
            anyhow::bail!(
                "Configured for JWT auth with zero decoding keys. All JWT gated requests would be rejected."
            );
        }
        Ok(Self::new(decoding_keys))
    }

    pub fn from_key(key: String) -> Result<Self> {
        Ok(Self::new(vec![DecodingKey::from_ed_pem(key.as_bytes())?]))
    }

    /// Attempt to decode the token with the internal decoding keys.
    ///
    /// The function tries the stored decoding keys in succession,
    /// and returns the first yielding a successful result.
    /// If there is no working decoding key, it returns the last error.
    ///
    /// A token whose `exp` or `nbf` is present but not an integer NumericDate is
    /// refused: the validation would skip such a claim, and the token would never expire.
    pub fn decode<D: DeserializeOwned>(
        &self,
        token: &str,
    ) -> std::result::Result<TokenData<D>, AuthError> {
        let mut res = None;
        for decoding_key in &self.decoding_keys {
            let attempt = decode::<serde_json::Value>(token, decoding_key, &self.validation);
            // jsonwebtoken (since 10.3) refuses a malformed `exp`/`nbf` itself, after the
            // signature check: this key verified the token, as an `Ok` would say.
            let verified = match &attempt {
                Ok(_) => true,
                Err(e) => matches!(e.kind(), ErrorKind::InvalidClaimFormat(_)),
            };
            res = Some(attempt);
            if verified {
                break;
            }
        }
        let data = match res {
            Some(Ok(data)) => data,
            Some(Err(e)) => {
                // The error this function gave before for such a claim (see below).
                if let ErrorKind::InvalidClaimFormat(name) = e.kind() {
                    return Err(AuthError(Cow::Owned(format!(
                        "JWT claim `{name}` is not a NumericDate"
                    ))));
                }
                return Err(AuthError(Cow::Owned(e.to_string())));
            }
            None => return Err(AuthError(Cow::Borrowed("no JWT decoding keys configured"))),
        };
        for name in ["exp", "nbf"] {
            if data.claims.get(name).is_some_and(|value| !value.is_u64()) {
                return Err(AuthError(Cow::Owned(format!(
                    "JWT claim `{name}` is not a NumericDate"
                ))));
            }
        }
        let claims = serde_json::from_value::<D>(data.claims)
            .map_err(|e| AuthError(Cow::Owned(format!("JSON error: {e}"))))?;
        Ok(TokenData {
            header: data.header,
            claims,
        })
    }
}

impl std::fmt::Debug for JwtAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuth")
            .field("validation", &self.validation)
            .finish()
    }
}

// this function is used only for testing purposes in CLI e g generate tokens during init
pub fn encode_from_key_file<S: Serialize>(claims: &S, pem: &Pem) -> Result<String> {
    let key = EncodingKey::from_ed_der(pem.contents());
    Ok(encode(&Header::new(STORAGE_TOKEN_ALGORITHM), claims, &key)?)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    // Generated with:
    //
    // openssl genpkey -algorithm ed25519 -out ed25519-priv.pem
    // openssl pkey -in ed25519-priv.pem -pubout -out ed25519-pub.pem
    const TEST_PUB_KEY_ED25519: &str = r#"
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARYwaNBayR+eGI0iXB4s3QxE3Nl2g1iWbr6KtLWeVD/w=
-----END PUBLIC KEY-----
"#;

    const TEST_PRIV_KEY_ED25519: &str = r#"
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID/Drmc1AA6U/znNRWpF3zEGegOATQxfkdWxitcOMsIH
-----END PRIVATE KEY-----
"#;

    #[test]
    fn test_decode() {
        let expected_claims = Claims {
            tenant_id: Some(TenantId::from_str("3d1f7595b468230304e0b73cecbcb081").unwrap()),
            scope: Scope::Tenant,
            endpoint_id: None,
        };

        // A test token containing the following payload, signed using TEST_PRIV_KEY_ED25519:
        //
        // ```
        // {
        //   "scope": "tenant",
        //   "tenant_id": "3d1f7595b468230304e0b73cecbcb081",
        //   "iss": "neon.controlplane",
        //   "iat": 1678442479
        // }
        // ```
        //
        let encoded_eddsa = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6InRlbmFudCIsInRlbmFudF9pZCI6IjNkMWY3NTk1YjQ2ODIzMDMwNGUwYjczY2VjYmNiMDgxIiwiaXNzIjoibmVvbi5jb250cm9scGxhbmUiLCJpYXQiOjE2Nzg0NDI0Nzl9.rNheBnluMJNgXzSTTJoTNIGy4P_qe0JUHl_nVEGuDCTgHOThPVr552EnmKccrCKquPeW3c2YUk0Y9Oh4KyASAw";

        // Check it can be validated with the public key
        let auth = JwtAuth::new(vec![
            DecodingKey::from_ed_pem(TEST_PUB_KEY_ED25519.as_bytes()).unwrap(),
        ]);
        let claims_from_token: Claims = auth.decode(encoded_eddsa).unwrap().claims;
        assert_eq!(claims_from_token, expected_claims);
    }

    #[test]
    fn test_encode() {
        let claims = Claims {
            tenant_id: Some(TenantId::from_str("3d1f7595b468230304e0b73cecbcb081").unwrap()),
            scope: Scope::Tenant,
            endpoint_id: None,
        };

        let pem = pem::parse(TEST_PRIV_KEY_ED25519).unwrap();
        let encoded = encode_from_key_file(&claims, &pem).unwrap();

        // decode it back
        let auth = JwtAuth::new(vec![
            DecodingKey::from_ed_pem(TEST_PUB_KEY_ED25519.as_bytes()).unwrap(),
        ]);
        let decoded: TokenData<Claims> = auth.decode(&encoded).unwrap();

        assert_eq!(decoded.claims, claims);
    }

    /// The wire names of every scope; `metrics` is the read-only scope of `/metrics`.
    const SCOPE_NAMES: [&str; 10] = [
        "tenant",
        "tenantendpoint",
        "pageserverapi",
        "safekeeperdata",
        "generations_api",
        "admin",
        "infra",
        "scrubber",
        "controller_peer",
        "metrics",
    ];

    // The scope is spelled by its wire name here: the name is the interface Chelabase
    // and the fixtures mint against.
    #[test]
    fn metrics_scope_round_trips_as_metrics() {
        let metrics: Scope = serde_json::from_str("\"metrics\"")
            .expect("`metrics` deserializes as a storage auth scope");
        assert_eq!(serde_json::to_string(&metrics).unwrap(), "\"metrics\"");
        for name in SCOPE_NAMES {
            let scope: Scope = serde_json::from_str(&format!("\"{name}\""))
                .unwrap_or_else(|e| panic!("scope `{name}` doesn't deserialize: {e}"));
            assert_eq!(
                serde_json::to_string(&scope).unwrap(),
                format!("\"{name}\"")
            );
            assert_eq!(scope == metrics, name == "metrics", "scope `{name}`");
        }
    }

    /// A metrics token carries `scope` and `iat` and no `tenant_id` or `exp` (U2); it
    /// decodes, with no tenant.
    #[test]
    fn metrics_token_decodes_without_tenant_or_exp() {
        let pem = pem::parse(TEST_PRIV_KEY_ED25519).unwrap();
        let token = encode_from_key_file(
            &serde_json::json!({"scope": "metrics", "iat": 1_760_000_000u64}),
            &pem,
        )
        .unwrap();
        let auth = JwtAuth::new(vec![
            DecodingKey::from_ed_pem(TEST_PUB_KEY_ED25519.as_bytes()).unwrap(),
        ]);
        let claims: Claims = auth.decode(&token).expect("a metrics token decodes").claims;
        assert_eq!(claims.tenant_id, None);
        assert_eq!(claims.endpoint_id, None);
        assert_eq!(serde_json::to_string(&claims.scope).unwrap(), "\"metrics\"");
    }
}
