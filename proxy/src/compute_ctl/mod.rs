use camino::{Utf8Path, Utf8PathBuf};
use compute_api::responses::GenericAPIError;
use hyper::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncReadExt;

use crate::http;
use crate::types::{DbName, RoleName};
use crate::url::ApiUrl;

#[cfg(test)]
mod tests;

pub struct ComputeCtlApi {
    pub(crate) api: http::Endpoint,
    /// Where compute_ctl publishes its internal API bearer secret. Read before
    /// every call (never cached): compute_ctl draws a new secret on restart.
    pub(crate) token_file: Option<Utf8PathBuf>,
}

/// Longest token the shared token-file format allows.
const MAX_TOKEN_LEN: usize = 8191;
/// The whole token file: the token plus its newline.
const MAX_TOKEN_FILE_LEN: u64 = MAX_TOKEN_LEN as u64 + 1;

/// Reader alphabet of the shared token-file format: `[A-Za-z0-9._~+/=-]`.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

/// Validate the contents of a token file: one line, one optional trailing
/// `\n`, 1..=8191 bytes of the token alphabet, the whole file at most 8 KiB.
fn parse_token_file(bytes: &[u8]) -> Option<&str> {
    if bytes.len() as u64 > MAX_TOKEN_FILE_LEN {
        return None;
    }
    let token = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if token.is_empty() || token.len() > MAX_TOKEN_LEN || !token.iter().copied().all(is_token_byte)
    {
        return None;
    }
    std::str::from_utf8(token).ok()
}

#[cfg(test)]
mod parse_tests {
    use super::parse_token_file;

    #[test]
    fn size_limits_are_exact() {
        let max = "a".repeat(8191);
        assert_eq!(parse_token_file(max.as_bytes()), Some(max.as_str()));
        assert_eq!(
            parse_token_file(format!("{max}\n").as_bytes()),
            Some(max.as_str())
        );
        let over = "a".repeat(8192);
        assert_eq!(parse_token_file(over.as_bytes()), None);
        assert_eq!(parse_token_file(format!("{over}\n").as_bytes()), None);
        assert_eq!(parse_token_file("a".repeat(8194).as_bytes()), None);
    }

    #[test]
    fn empty_and_multiline_are_refused() {
        for bad in [&b""[..], b"\n", b"\n\n", b"a\n\n", b"a\nb", b"a\0", b"a b"] {
            assert_eq!(parse_token_file(bad), None, "{bad:?}");
        }
        assert_eq!(parse_token_file(b"a"), Some("a"));
    }
}

#[derive(Serialize, Debug)]
pub struct ExtensionInstallRequest {
    pub extension: &'static str,
    pub database: DbName,
    pub version: &'static str,
}

#[derive(Serialize, Debug)]
pub struct SetRoleGrantsRequest {
    pub database: DbName,
    pub schema: &'static str,
    pub privileges: Vec<Privilege>,
    pub role: RoleName,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExtensionInstallResponse {}

#[derive(Clone, Debug, Deserialize)]
pub struct SetRoleGrantsResponse {}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum Privilege {
    Usage,
}

#[derive(Error, Debug)]
pub enum ComputeCtlError {
    #[error("connection error: {0}")]
    Connection(#[source] reqwest_middleware::Error),
    #[error("request error [{status}]: {body:?}")]
    Request {
        status: StatusCode,
        body: Option<GenericAPIError>,
    },
    #[error("response parsing error: {0}")]
    Response(#[source] reqwest::Error),
}

impl ComputeCtlApi {
    pub fn token_file(&self) -> Option<&Utf8Path> {
        self.token_file.as_deref()
    }

    /// The current bearer token, or `None` when no file is configured or the
    /// file is missing or invalid (the call then goes out without a header).
    async fn read_token(&self) -> Option<String> {
        let path = self.token_file()?;
        let file = tokio::fs::File::open(path).await.ok()?;
        // One byte over the limit is enough to tell the file is too big.
        let mut bytes = Vec::new();
        file.take(MAX_TOKEN_FILE_LEN + 1)
            .read_to_end(&mut bytes)
            .await
            .ok()?;
        parse_token_file(&bytes).map(str::to_owned)
    }

    pub async fn install_extension(
        &self,
        req: &ExtensionInstallRequest,
    ) -> Result<ExtensionInstallResponse, ComputeCtlError> {
        self.generic_request(req, Method::POST, |url| {
            url.path_segments_mut().push("extensions");
        })
        .await
    }

    pub async fn grant_role(
        &self,
        req: &SetRoleGrantsRequest,
    ) -> Result<SetRoleGrantsResponse, ComputeCtlError> {
        self.generic_request(req, Method::POST, |url| {
            url.path_segments_mut().push("grants");
        })
        .await
    }

    async fn generic_request<Req, Resp>(
        &self,
        req: &Req,
        method: Method,
        url: impl for<'a> FnOnce(&'a mut ApiUrl),
    ) -> Result<Resp, ComputeCtlError>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let mut request = self.api.request_with_url(method, url).json(req);
        if let Some(token) = self.read_token().await {
            // `bearer_auth` marks the header value sensitive (redacted in Debug).
            request = request.bearer_auth(token);
        }
        let resp = request.send().await.map_err(ComputeCtlError::Connection)?;

        let status = resp.status();
        if status.is_client_error() || status.is_server_error() {
            let body = resp.json().await.ok();
            return Err(ComputeCtlError::Request { status, body });
        }

        resp.json().await.map_err(ComputeCtlError::Response)
    }
}
