use utils::auth::{AuthError, Claims, Scope};
use uuid::Uuid;

pub fn check_permission(claims: &Claims, required_scope: Scope) -> Result<(), AuthError> {
    if claims.scope != required_scope {
        return Err(AuthError("Scope mismatch. Permission denied".into()));
    }

    Ok(())
}

#[allow(dead_code)]
pub fn check_endpoint_permission(claims: &Claims, endpoint_id: Uuid) -> Result<(), AuthError> {
    if claims.scope != Scope::TenantEndpoint {
        return Err(AuthError("Scope mismatch. Permission denied".into()));
    }
    if claims.endpoint_id != Some(endpoint_id) {
        return Err(AuthError("Endpoint id mismatch. Permission denied".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use utils::id::TenantId;

    use super::*;

    /// Every storage auth scope. The `match` stops compiling when a variant is added,
    /// so the tables below stay exhaustive.
    fn all_scopes() -> Vec<Scope> {
        let all = vec![
            Scope::Tenant,
            Scope::TenantEndpoint,
            Scope::PageServerApi,
            Scope::SafekeeperData,
            Scope::GenerationsApi,
            Scope::Admin,
            Scope::Infra,
            Scope::Scrubber,
            Scope::ControllerPeer,
            Scope::Metrics,
        ];
        for scope in &all {
            match scope {
                Scope::Tenant
                | Scope::TenantEndpoint
                | Scope::PageServerApi
                | Scope::SafekeeperData
                | Scope::GenerationsApi
                | Scope::Admin
                | Scope::Infra
                | Scope::Scrubber
                | Scope::ControllerPeer
                | Scope::Metrics => {}
            }
        }
        all
    }

    fn claims(scope: Scope, tenant_id: Option<TenantId>) -> Claims {
        Claims::new(tenant_id, scope)
    }

    /// Invariant: `check_permission` is total and allows exactly the required scope,
    /// whatever `tenant_id` the token carries.
    #[test]
    fn check_permission_is_total_and_exact_over_every_scope() {
        for token_scope in all_scopes() {
            for required in all_scopes() {
                for token_tenant in [None, Some(TenantId::generate())] {
                    let token = claims(token_scope, token_tenant);
                    let case = format!(
                        "token scope {token_scope:?}, required {required:?}, token tenant {token_tenant:?}"
                    );
                    let result = catch_unwind(|| check_permission(&token, required))
                        .unwrap_or_else(|_| panic!("check_permission panicked: {case}"));
                    assert_eq!(
                        result.is_ok(),
                        token_scope == required,
                        "{case}: {result:?}"
                    );
                }
            }
        }
    }

    /// The HTTP routes ask for one scope and also take `Admin` (`http::check_permissions`);
    /// a `Metrics` token passes neither check for any scope a route requires (RT4-5).
    #[test]
    fn metrics_is_refused_for_every_route_scope() {
        let metrics = claims(Scope::Metrics, None);
        assert!(check_permission(&metrics, Scope::Admin).is_err());
        for required in all_scopes() {
            if required == Scope::Metrics {
                continue;
            }
            assert!(
                check_permission(&metrics, required).is_err(),
                "a metrics token passed a route requiring {required:?}"
            );
        }
    }

    /// `/metrics` accepts `{Metrics, Admin}` (RT4-5: set membership, not equality).
    #[test]
    fn metrics_route_accepts_metrics_and_admin_only() {
        for scope in all_scopes() {
            for token_tenant in [None, Some(TenantId::generate())] {
                let result = check_metrics_permission(&claims(scope, token_tenant));
                let allowed = matches!(scope, Scope::Metrics | Scope::Admin);
                assert_eq!(
                    result.is_ok(),
                    allowed,
                    "scope {scope:?}, token tenant {token_tenant:?}: {result:?}"
                );
            }
        }
    }

    /// `/profile/cpu` and `/profile/heap` accept `{Admin}` (S8).
    #[test]
    fn profile_routes_accept_admin_only() {
        for scope in all_scopes() {
            for token_tenant in [None, Some(TenantId::generate())] {
                let result = check_profile_permission(&claims(scope, token_tenant));
                assert_eq!(
                    result.is_ok(),
                    scope == Scope::Admin,
                    "scope {scope:?}, token tenant {token_tenant:?}: {result:?}"
                );
            }
        }
    }

    /// The routes the auth middleware lets through without a token: health only.
    #[test]
    fn public_routes_are_health_only() {
        let mut public = crate::http::PUBLIC_ROUTES.to_vec();
        public.sort_unstable();
        assert_eq!(public, ["/live", "/ready", "/status"]);
    }
}
