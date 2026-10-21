use std::sync::Arc;

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::{IntoResponse, Response};
use compute_api::requests::StorageTokenRequest;
use http::StatusCode;

use crate::compute::{ComputeNode, StorageTokenRefusal};
use crate::http::JsonResponse;

/// `POST /storage_token` (RT4-3): a new tenant storage token, written to the
/// storage token file and held in memory; nothing else changes (no status
/// change, no reload), so a refresh can never fail a running compute.
///
/// `204` written; `400` any body rejection, an invalid token, or a compute that
/// started without storage auth; `412` outside `running` and
/// `configuration_pending`; `500` the file couldn't be written (old file kept).
/// No answer or log line carries the token.
pub(in crate::http) async fn refresh_storage_token(
    State(compute): State<Arc<ComputeNode>>,
    body: Result<axum::Json<serde_json::Value>, JsonRejection>,
) -> Response {
    // Every rejection is a 400 with a fixed text: serde's own messages can
    // quote the body. Only a JSON object is a request (serde would also take
    // the struct from an array).
    let parsed = body.map(|axum::Json(value)| {
        value
            .is_object()
            .then(|| serde_json::from_value::<StorageTokenRequest>(value).ok())
            .flatten()
    });
    let request = match parsed {
        Ok(Some(request)) => request,
        Ok(None) => {
            return JsonResponse::error(
                StatusCode::BAD_REQUEST,
                "expected a body of the form {\"token\": \"<storage token>\"}",
            );
        }
        Err(JsonRejection::MissingJsonContentType(_)) => {
            return JsonResponse::error(
                StatusCode::BAD_REQUEST,
                "expected a request with Content-Type: application/json",
            );
        }
        Err(_) => {
            return JsonResponse::error(
                StatusCode::BAD_REQUEST,
                "expected a body of the form {\"token\": \"<storage token>\"}",
            );
        }
    };

    let refreshed =
        tokio::task::spawn_blocking(move || compute.refresh_storage_token(request.token)).await;
    match refreshed {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(StorageTokenRefusal::InvalidToken)) => JsonResponse::error(
            StatusCode::BAD_REQUEST,
            "not a valid storage token (one line of [A-Za-z0-9._~+/=-], 1-8191 bytes)",
        ),
        Ok(Err(StorageTokenRefusal::InvalidStatus(status))) => JsonResponse::invalid_status(status),
        Ok(Err(StorageTokenRefusal::StartedWithoutStorageAuth)) => JsonResponse::error(
            StatusCode::BAD_REQUEST,
            "compute started without storage auth; restart to enable it",
        ),
        Ok(Err(StorageTokenRefusal::WriteFailed(e))) => JsonResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not write the storage token file: {e:#}"),
        ),
        Err(e) => JsonResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the storage token refresh task failed: {e}"),
        ),
    }
}
