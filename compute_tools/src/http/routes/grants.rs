use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use compute_api::requests::SetRoleGrantsRequest;
use compute_api::responses::{ComputeStatus, SetRoleGrantsResponse};
use http::StatusCode;

use crate::compute::{ComputeNode, RequestRefused, grant_refusal};
use crate::http::JsonResponse;
use crate::http::extract::Json;
use crate::http::middleware::internal_auth::InternalAuth;

/// Add grants for a role.
///
/// RT4-6: the internal secret is `cloud_admin`-grade, so only what the callers
/// need is allowed: `USAGE`/`CREATE` on a schema a non-superuser owns, for an
/// existing ordinary grantee. The name rules are checked here; the catalog
/// rules by [`ComputeNode::set_role_grants`]. A refusal is `403`, nothing run.
pub(in crate::http) async fn add_grant(
    _auth: InternalAuth,
    State(compute): State<Arc<ComputeNode>>,
    request: Json<SetRoleGrantsRequest>,
) -> Response {
    let status = compute.get_status();
    if status != ComputeStatus::Running {
        return JsonResponse::invalid_status(status);
    }

    if let Some(reason) = grant_refusal(
        &request.schema,
        &request.role,
        &request.privileges,
        &compute.params.privileged_role_name,
    ) {
        return JsonResponse::error(StatusCode::FORBIDDEN, reason);
    }

    match compute
        .set_role_grants(
            &request.database,
            &request.schema,
            &request.privileges,
            &request.role,
        )
        .await
    {
        Ok(()) => JsonResponse::success(
            StatusCode::CREATED,
            Some(SetRoleGrantsResponse {
                database: request.database.clone(),
                schema: request.schema.clone(),
                role: request.role.clone(),
                privileges: request.privileges.clone(),
            }),
        ),
        Err(e) if e.downcast_ref::<RequestRefused>().is_some() => {
            JsonResponse::error(StatusCode::FORBIDDEN, e)
        }
        Err(e) => JsonResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to grant role privileges to the schema: {e}"),
        ),
    }
}
