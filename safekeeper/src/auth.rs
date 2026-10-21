use utils::auth::{AuthError, Claims, Scope};
use utils::id::TenantId;

/// If tenant_id is provided, allow if token (claims) is for this tenant or
/// whole safekeeper scope (SafekeeperData). Else, allow only if token is
/// SafekeeperData.
pub fn check_permission(claims: &Claims, tenant_id: Option<TenantId>) -> Result<(), AuthError> {
    match (&claims.scope, tenant_id) {
        (Scope::Tenant, None) => Err(AuthError(
            "Attempt to access management api with tenant scope. Permission denied".into(),
        )),
        (Scope::Tenant, Some(tenant_id)) => {
            if claims.tenant_id.unwrap() != tenant_id {
                return Err(AuthError("Tenant id mismatch. Permission denied".into()));
            }
            Ok(())
        }
        (
            Scope::Admin
            | Scope::PageServerApi
            | Scope::GenerationsApi
            | Scope::Infra
            | Scope::Scrubber
            | Scope::ControllerPeer
            | Scope::TenantEndpoint,
            _,
        ) => Err(AuthError(
            format!(
                "JWT scope '{:?}' is ineligible for Safekeeper auth",
                claims.scope
            )
            .into(),
        )),
        (Scope::SafekeeperData, _) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

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

    /// Invariant: `check_permission` is total (it never panics), and it allows exactly
    /// `SafekeeperData` everywhere and `Tenant` on its own tenant's routes. The HTTP
    /// routes, the libpq handler and the WAL service all go through it.
    #[test]
    fn check_permission_is_total_over_every_scope_and_tenant() {
        let own = TenantId::generate();
        let other = TenantId::generate();
        for scope in all_scopes() {
            for token_tenant in [None, Some(own)] {
                for route_tenant in [None, Some(own), Some(other)] {
                    let token = claims(scope, token_tenant);
                    let case = format!(
                        "scope {scope:?}, token tenant {token_tenant:?}, route tenant {route_tenant:?}"
                    );
                    let result = catch_unwind(|| check_permission(&token, route_tenant))
                        .unwrap_or_else(|_| panic!("check_permission panicked: {case}"));
                    let allowed = match scope {
                        Scope::SafekeeperData => true,
                        Scope::Tenant => {
                            token_tenant.is_some()
                                && route_tenant.is_some()
                                && token_tenant == route_tenant
                        }
                        _ => false,
                    };
                    assert_eq!(result.is_ok(), allowed, "{case}: {result:?}");
                    if scope == Scope::Tenant && token_tenant.is_none() && route_tenant.is_some() {
                        assert_eq!(
                            result,
                            Err(AuthError("tenant scope without a tenant id".into())),
                            "{case}"
                        );
                    }
                }
            }
        }
    }

    /// `/metrics` accepts `{Metrics, Admin, SafekeeperData}` (RT4-5: set membership).
    #[test]
    fn metrics_route_accepts_metrics_admin_and_safekeeperdata_only() {
        for scope in all_scopes() {
            for token_tenant in [None, Some(TenantId::generate())] {
                let result = check_metrics_permission(&claims(scope, token_tenant));
                let allowed =
                    matches!(scope, Scope::Metrics | Scope::Admin | Scope::SafekeeperData);
                assert_eq!(
                    result.is_ok(),
                    allowed,
                    "scope {scope:?}, token tenant {token_tenant:?}: {result:?}"
                );
            }
        }
    }

    /// `/profile/cpu` and `/profile/heap` accept `{Admin, SafekeeperData}` (S8).
    #[test]
    fn profile_routes_accept_admin_and_safekeeperdata_only() {
        for scope in all_scopes() {
            for token_tenant in [None, Some(TenantId::generate())] {
                let result = check_profile_permission(&claims(scope, token_tenant));
                let allowed = matches!(scope, Scope::Admin | Scope::SafekeeperData);
                assert_eq!(
                    result.is_ok(),
                    allowed,
                    "scope {scope:?}, token tenant {token_tenant:?}: {result:?}"
                );
            }
        }
    }

    /// `Metrics` and `Admin` open nothing but the routes above.
    #[test]
    fn metrics_and_admin_are_refused_on_every_other_route() {
        for scope in [Scope::Metrics, Scope::Admin] {
            for token_tenant in [None, Some(TenantId::generate())] {
                for route_tenant in [None, token_tenant, Some(TenantId::generate())] {
                    let result = check_permission(&claims(scope, token_tenant), route_tenant);
                    assert!(
                        result.is_err(),
                        "scope {scope:?}, token tenant {token_tenant:?}, route tenant {route_tenant:?}"
                    );
                }
            }
        }
    }

    /// The routes the auth middleware lets through without a token: status only.
    #[test]
    fn public_routes_are_status_only() {
        assert_eq!(crate::http::routes::PUBLIC_ROUTES, ["/v1/status"]);
    }
}
