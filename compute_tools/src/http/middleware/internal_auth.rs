//! The internal server's authentication (D2, RT4-10): every internal route
//! needs `Authorization: Bearer <secret>`, the per-start secret compute_ctl
//! writes to its internal API token file. There is no bypass (an `INSTANCE_ID`
//! changes nothing), and neither the secret nor a presented header is ever
//! logged or echoed.
//!
//! The check is an extractor rather than a router layer because the secret
//! lives in the router's state (`ComputeNode`), which a layer can't reach:
//! every internal handler takes [`InternalAuth`] as its first argument, so it
//! runs before any other extractor (path, query, body) and the handler itself.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::request::Parts;
use http::{HeaderValue, StatusCode};

use crate::compute::ComputeNode;
use crate::http::JsonResponse;
use crate::token_file::secrets_match;

/// Proof that the request carried the internal API secret.
pub(in crate::http) struct InternalAuth;

/// The `401` every refusal gets: the same body whatever was presented.
fn unauthorized() -> Response {
    let mut response = JsonResponse::error(
        StatusCode::UNAUTHORIZED,
        "the internal API needs the bearer from compute_ctl's internal API token file",
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// Whether `header` is `Bearer <secret>` (the scheme in any case, one space,
/// nothing else).
fn presents(header: &[u8], secret: &str) -> bool {
    const SCHEME: &[u8] = b"bearer ";
    if header.len() <= SCHEME.len() || !header[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        return false;
    }
    secrets_match(&header[SCHEME.len()..], secret.as_bytes())
}

impl FromRequestParts<Arc<ComputeNode>> for InternalAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        compute: &Arc<ComputeNode>,
    ) -> Result<Self, Self::Rejection> {
        let mut values = parts.headers.get_all(AUTHORIZATION).iter();
        match (values.next(), values.next()) {
            (Some(value), None) if presents(value.as_bytes(), compute.internal_api_secret()) => {
                Ok(InternalAuth)
            }
            _ => Err(unauthorized().into_response()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::presents;

    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn only_the_exact_bearer_is_accepted() {
        assert!(presents(format!("Bearer {SECRET}").as_bytes(), SECRET));
        assert!(presents(format!("bearer {SECRET}").as_bytes(), SECRET));
        assert!(presents(format!("BEARER {SECRET}").as_bytes(), SECRET));
        for bad in [
            String::new(),
            "Bearer".into(),
            "Bearer ".into(),
            format!("Bearer  {SECRET}"),
            format!("Bearer {SECRET} "),
            format!(" Bearer {SECRET}"),
            format!("Bearer\t{SECRET}"),
            format!("Bearer {}", &SECRET[1..]),
            format!("Bearer {SECRET}0"),
            format!("Bearer {}", SECRET.to_uppercase()),
            format!("Basic {SECRET}"),
            SECRET.to_string(),
        ] {
            assert!(!presents(bad.as_bytes(), SECRET), "{bad:?}");
        }
        // Non-UTF-8 bytes never match.
        let mut raw = b"Bearer ".to_vec();
        raw.extend_from_slice(&[0xff; 64]);
        assert!(!presents(&raw, SECRET));
    }
}
