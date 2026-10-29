//! The external server's authentication: every route needs a JWT signed by a
//! key of the compute's JWKS, as `Authorization: Bearer <jwt>`.
//!
//! - A missing, malformed or non-Bearer header, a bad signature, an expired
//!   token or an admin token without the compute audience is `401` with
//!   `WWW-Authenticate: Bearer`; the body never echoes what was presented.
//! - `compute_ctl:admin` (with `aud: ["compute"]`) opens every route; a token
//!   without a scope opens every route only for this compute's `compute_id`
//!   (`403` otherwise).
//! - `metrics` opens only `GET /metrics` and `GET /autoscaling_metrics`,
//!   whatever `compute_id` it carries (or none), and is `403` everywhere else.
//!   The decision is by the request's path, never a prefix or the query.
//! - Nothing bypasses the check (an `INSTANCE_ID` changes nothing), and the
//!   token is never logged.

use anyhow::{Result, anyhow};
use axum::body::Body;
use compute_api::requests::{COMPUTE_AUDIENCE, ComputeClaims, ComputeClaimsScope};
use futures::future::BoxFuture;
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, jwk::JwkSet};
use tower_http::auth::AsyncAuthorizeRequest;
use tracing::warn;

use crate::http::JsonResponse;

/// The routes a `metrics` token opens (with `GET`, or `HEAD`).
const METRICS_ROUTES: [&str; 2] = ["/metrics", "/autoscaling_metrics"];

#[derive(Clone, Debug)]
pub(in crate::http) struct Authorize {
    compute_id: String,
    jwks: JwkSet,
    validation: Validation,
}

impl Authorize {
    pub fn new(compute_id: String, jwks: JwkSet) -> Self {
        // BEGIN HADRON
        let use_rsa = jwks.keys.iter().any(|jwk| {
            jwk.common
                .key_algorithm
                .is_some_and(|alg| alg == jsonwebtoken::jwk::KeyAlgorithm::RS256)
        });
        let algorithm = if use_rsa {
            Algorithm::RS256
        } else {
            Algorithm::EdDSA
        };
        // END HADRON

        // Every field is spelled out (no `..Default::default()`), so a library upgrade
        // can't change one silently and a new field fails to compile here.
        let validation = Validation {
            algorithms: vec![algorithm],
            validate_exp: true,
            leeway: 60,
            reject_tokens_expiring_in_less_than: 0,
            // Unused by the control plane
            validate_nbf: false,
            // Unused by the control plane; `authorize_claims` checks an admin token's
            // audience itself.
            validate_aud: false,
            aud: Some([COMPUTE_AUDIENCE.to_owned()].into()),
            iss: None,
            sub: None,
            // Nothing is currently required
            required_spec_claims: [].into(),
        };

        Self {
            compute_id,
            jwks,
            validation,
        }
    }
}

/// A `401` with the Bearer challenge.
fn unauthorized(message: &str) -> Response<Body> {
    let mut response = JsonResponse::error(StatusCode::UNAUTHORIZED, message);
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn forbidden(message: &str) -> Response<Body> {
    JsonResponse::error(StatusCode::FORBIDDEN, message)
}

/// The token of the request's one `Authorization: Bearer <token>` header (the
/// scheme in any case, then one or more spaces, then a token without
/// whitespace; whitespace around the value is ignored). Anything else (no
/// header, two headers, another scheme, no or an empty token, a token with
/// whitespace in it, bytes that aren't visible ASCII) is `None`.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let value = value.to_str().ok()?.trim_matches(|c| c == ' ' || c == '\t');
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim_start_matches(' ');
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    Some(token)
}

/// Whether a `metrics` token opens this request: `GET` (or `HEAD`) on one of
/// [`METRICS_ROUTES`], by exact path.
fn metrics_route(method: &Method, path: &str) -> bool {
    (method == Method::GET || method == Method::HEAD) && METRICS_ROUTES.contains(&path)
}

/// The decision for verified claims on `method` `path`: `Ok` lets the request
/// through.
#[allow(clippy::result_large_err)]
fn authorize_claims(
    claims: &ComputeClaims,
    compute_id: &str,
    method: &Method,
    path: &str,
) -> Result<(), Response<Body>> {
    match claims.scope {
        // TODO: We should validate audience for every token, but
        // instead of this ad-hoc validation, we should turn
        // [`Validation::validate_aud`] on. This is merely a stopgap
        // while we roll out `aud` deployment. We return a 401
        // Unauthorized because when we eventually do use
        // [`Validation`], we will hit the verification error arm which
        // returns 401 Unauthorized.
        Some(ComputeClaimsScope::Admin) => {
            let Some(ref audience) = claims.audience else {
                return Err(unauthorized(
                    "missing audience in authorization token claims",
                ));
            };
            if !audience.iter().any(|a| a == COMPUTE_AUDIENCE) {
                return Err(unauthorized(
                    "invalid audience in authorization token claims",
                ));
            }
            Ok(())
        }

        // RT4-9: by route only, whatever `compute_id` the token carries.
        Some(ComputeClaimsScope::Metrics) => {
            if metrics_route(method, path) {
                Ok(())
            } else {
                Err(forbidden("a metrics token only opens the metrics routes"))
            }
        }

        // Without a scope, the token must be for this compute.
        None => {
            let Some(ref claimed_compute_id) = claims.compute_id else {
                return Err(forbidden(
                    "missing compute_id in authorization token claims",
                ));
            };
            if claimed_compute_id != compute_id {
                return Err(forbidden(
                    "invalid compute ID in authorization token claims",
                ));
            }
            Ok(())
        }
    }
}

impl AsyncAuthorizeRequest<Body> for Authorize {
    type RequestBody = Body;
    type ResponseBody = Body;
    type Future = BoxFuture<'static, Result<Request<Body>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, mut request: Request<Body>) -> Self::Future {
        let compute_id = self.compute_id.clone();
        let jwks = self.jwks.clone();
        let validation = self.validation.clone();

        Box::pin(async move {
            let Some(token) = bearer_token(request.headers()) else {
                return Err(unauthorized(
                    "a Bearer token is required in the Authorization header",
                ));
            };

            let data = match Self::verify(&jwks, token, &validation) {
                Ok(data) => data,
                Err(e) => return Err(unauthorized(&e.to_string())),
            };

            authorize_claims(
                &data.claims,
                &compute_id,
                request.method(),
                request.uri().path(),
            )?;

            // Make claims available to any subsequent middleware or request
            // handlers
            request.extensions_mut().insert(data.claims);

            Ok(request)
        })
    }
}

impl Authorize {
    /// Verify the token using the JSON Web Key set and return the token data.
    /// Neither the token nor its claims are logged; a key without `kid` is
    /// named `<no kid>`. A refused token logs one WARN line, naming each key's
    /// error, however many keys the set holds.
    fn verify(
        jwks: &JwkSet,
        token: &str,
        validation: &Validation,
    ) -> Result<TokenData<ComputeClaims>> {
        let mut failures: Vec<String> = Vec::new();
        for jwk in jwks.keys.iter() {
            let kid = jwk.common.key_id.as_deref().unwrap_or("<no kid>");
            let decoding_key = match DecodingKey::from_jwk(jwk) {
                Ok(key) => key,
                Err(e) => {
                    failures.push(format!("{kid}: no decoding key: {e}"));
                    continue;
                }
            };

            match jsonwebtoken::decode::<ComputeClaims>(token, &decoding_key, validation) {
                Ok(data) => return Ok(data),
                Err(e) => failures.push(format!("{kid}: {e}")),
            }
        }

        if failures.is_empty() {
            warn!("failed to verify an authorization token: the JWKS holds no key");
        } else {
            warn!(
                "failed to verify an authorization token with any of {} keys: {}",
                failures.len(),
                failures.join("; ")
            );
        }
        Err(anyhow!("failed to verify authorization token"))
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method};

    use super::{bearer_token, metrics_route};

    fn headers(values: &[&[u8]]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for v in values {
            map.append("authorization", HeaderValue::from_bytes(v).unwrap());
        }
        map
    }

    #[test]
    fn bearer_token_takes_one_well_formed_header() {
        for (value, want) in [
            (&b"Bearer a.b.c"[..], "a.b.c"),
            (b"bearer a.b.c", "a.b.c"),
            (b"BEARER a.b.c", "a.b.c"),
            (b"bEaReR a.b.c", "a.b.c"),
            (b"Bearer   a.b.c", "a.b.c"),
            (b" Bearer a.b.c ", "a.b.c"),
            (b"\tBearer a.b.c\t", "a.b.c"),
        ] {
            assert_eq!(
                bearer_token(&headers(&[value])),
                Some(want),
                "{:?}",
                String::from_utf8_lossy(value)
            );
        }
        for value in [
            &b""[..],
            b"Bearer",
            b"Bearer ",
            b"Bearer    ",
            b"Bearer\ta.b.c",
            b"Bearer a.b.c d",
            b"Bearer a.b\tc",
            b"Basic Zm9vOmJhcg==",
            b"Token a.b.c",
            b"a.b.c",
            b"Bearera.b.c",
            b"Bearer a.b.\xffc",
        ] {
            assert_eq!(
                bearer_token(&headers(&[value])),
                None,
                "{:?}",
                String::from_utf8_lossy(value)
            );
        }
        assert_eq!(bearer_token(&HeaderMap::new()), None, "no header");
        assert_eq!(
            bearer_token(&headers(&[b"Bearer a.b.c", b"Bearer a.b.c"])),
            None,
            "two headers"
        );
    }

    #[test]
    fn metrics_route_is_exact() {
        for path in ["/metrics", "/autoscaling_metrics"] {
            assert!(metrics_route(&Method::GET, path), "{path}");
            assert!(metrics_route(&Method::HEAD, path), "{path}");
            for m in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
                assert!(!metrics_route(&m, path), "{m} {path}");
            }
        }
        for path in [
            "/metrics/",
            "/metrics.json",
            "/metricsx",
            "/Metrics",
            "/autoscaling_metrics/x",
            "//metrics",
            "/status",
            "",
            "/",
        ] {
            assert!(!metrics_route(&Method::GET, path), "{path}");
        }
    }
}
