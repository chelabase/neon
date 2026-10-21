use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use compute_api::requests::ExtensionInstallRequest;
use compute_api::responses::{ComputeStatus, ExtensionInstallResponse};
use http::StatusCode;

use crate::compute::{ComputeNode, RequestRefused};
use crate::http::JsonResponse;
use crate::http::extract::Json;
use crate::http::middleware::internal_auth::InternalAuth;

/// Install a extension.
///
/// RT4-6: only an extension version whose control file is `trusted` (what the
/// database owner could install itself); anything else is `403`, nothing run.
pub(in crate::http) async fn install_extension(
    _auth: InternalAuth,
    State(compute): State<Arc<ComputeNode>>,
    request: Json<ExtensionInstallRequest>,
) -> Response {
    let status = compute.get_status();
    if status != ComputeStatus::Running {
        return JsonResponse::invalid_status(status);
    }

    match compute
        .install_extension(
            &request.extension,
            &request.database,
            request.version.to_string(),
        )
        .await
    {
        Ok(version) => JsonResponse::success(
            StatusCode::CREATED,
            Some(ExtensionInstallResponse {
                extension: request.extension.clone(),
                version,
            }),
        ),
        Err(e) if e.downcast_ref::<RequestRefused>().is_some() => {
            JsonResponse::error(StatusCode::FORBIDDEN, e)
        }
        Err(e) => JsonResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to install extension: {e}"),
        ),
    }
}
