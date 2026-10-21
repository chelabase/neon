use utils::auth::{AuthError, Claims, Scope};
use uuid::Uuid;

pub fn check_permission(claims: &Claims, required_scope: Scope) -> Result<(), AuthError> {
    if claims.scope != required_scope {
        return Err(AuthError("Scope mismatch. Permission denied".into()));
    }

    Ok(())
}

/// `/metrics` takes `Metrics` and `Admin` (the storage controller's own global scope).
pub fn check_metrics_permission(claims: &Claims) -> Result<(), AuthError> {
    match claims.scope {
        Scope::Metrics | Scope::Admin => Ok(()),
        Scope::Tenant
        | Scope::TenantEndpoint
        | Scope::PageServerApi
        | Scope::SafekeeperData
        | Scope::GenerationsApi
        | Scope::Infra
        | Scope::Scrubber
        | Scope::ControllerPeer => Err(AuthError("Scope mismatch. Permission denied".into())),
    }
}

/// A token whose scope no storage controller route takes is refused before routing
/// (`http::route_scope_middleware`): tenant and compute tokens (`Tenant`,
/// `TenantEndpoint`) and the safekeepers' `SafekeeperData`. Every other scope is left to
/// the route's own check (and `Metrics` to the auth middleware, which keeps it on
/// `/metrics`).
pub fn check_route_scope(claims: &Claims) -> Result<(), AuthError> {
    match claims.scope {
        Scope::Admin
        | Scope::PageServerApi
        | Scope::GenerationsApi
        | Scope::Infra
        | Scope::Scrubber
        | Scope::ControllerPeer
        | Scope::Metrics => Ok(()),
        Scope::Tenant | Scope::TenantEndpoint | Scope::SafekeeperData => Err(AuthError(
            format!(
                "no storage controller route takes scope '{:?}'",
                claims.scope
            )
            .into(),
        )),
    }
}

/// `/profile/cpu` and `/profile/heap` take `Admin` only.
pub fn check_profile_permission(claims: &Claims) -> Result<(), AuthError> {
    check_permission(claims, Scope::Admin)
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

    /// The scope guard in front of every route refuses exactly the scopes no route
    /// takes (tenant and compute tokens, `SafekeeperData`), whatever tenant they carry,
    /// and never panics.
    #[test]
    fn route_scope_guard_refuses_scopes_no_route_takes() {
        for scope in all_scopes() {
            for token_tenant in [None, Some(TenantId::generate())] {
                let token = claims(scope, token_tenant);
                let result = catch_unwind(|| check_route_scope(&token))
                    .unwrap_or_else(|_| panic!("check_route_scope panicked: {scope:?}"));
                let refused = matches!(
                    scope,
                    Scope::Tenant | Scope::TenantEndpoint | Scope::SafekeeperData
                );
                assert_eq!(
                    result.is_err(),
                    refused,
                    "scope {scope:?}, token tenant {token_tenant:?}: {result:?}"
                );
            }
        }
    }

    /// The guard refuses no scope a route asks for: every `check_permissions(_, Scope::X)`
    /// in the router's handlers names a scope the guard lets through.
    #[test]
    fn route_scope_guard_lets_through_every_scope_a_route_asks_for() {
        let src = include_str!("http.rs");
        let calls = src.matches("check_permissions(&").count();
        let mut matched = 0;
        for scope in all_scopes() {
            let n = src
                .matches(&format!("check_permissions(&req, Scope::{scope:?})"))
                .count()
                + src
                    .matches(&format!("check_permissions(&r, Scope::{scope:?})"))
                    .count();
            if n > 0 {
                assert!(
                    check_route_scope(&claims(scope, None)).is_ok(),
                    "a route asks for {scope:?}, which the guard refuses"
                );
            }
            matched += n;
        }
        assert!(matched > 50, "only {matched} route checks found");
        assert_eq!(
            matched, calls,
            "a check_permissions call the test can't read"
        );
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
