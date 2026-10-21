"""
Edges of the storage servers' token checks beyond `test_auth.py`: `exp` on the metrics
route, and claims the token validation would otherwise skip.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import jwt
import requests
from fixtures.auth_tokens import TokenScope

if TYPE_CHECKING:
    from fixtures.neon_fixtures import NeonEnvBuilder


def status(url: str, token: str) -> int:
    return requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=60).status_code


def test_metrics_token_exp_and_malformed_dates(neon_env_builder: NeonEnvBuilder):
    """
    On `/metrics` of all three servers: a metrics token past its `exp` (beyond the 60 s
    leeway) is refused, one before it accepted; a token whose `exp` or `nbf` isn't an
    integer is refused (the validation would skip it, and the token would never expire).
    A `metrics` token carrying a `tenant_id` still opens no tenant route.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(
        [
            ".*Authentication error: ExpiredSignature.*",
            ".*Authentication error: JWT claim `(exp|nbf)` is not a NumericDate.*",
        ]
    )
    env.storage_controller.allowed_errors.extend([".*Forbidden.*", ".*Authentication error.*"])

    keys = env.auth_keys
    now = int(time.time())
    urls = [
        f"http://localhost:{env.pageserver.service_port.http}/metrics",
        f"http://localhost:{env.safekeepers[0].port.http}/metrics",
        f"{env.storage_controller_api}/metrics",
    ]

    def raw(claims: dict[str, object]) -> str:
        return jwt.encode(claims, keys.priv, algorithm="EdDSA")

    for url in urls:
        expired = keys.generate_token(scope=TokenScope.METRICS, exp=now - 120, iat=now - 3600)
        assert status(url, expired) == 403, url
        valid = keys.generate_token(scope=TokenScope.METRICS, exp=now + 3600, iat=now)
        assert status(url, valid) == 200, url
        malformed: list[dict[str, object]] = [
            {"scope": "metrics", "exp": str(now - 3600)},
            {"scope": "metrics", "exp": str(now + 3600)},
            {"scope": "metrics", "exp": now + 3600.5},
            {"scope": "metrics", "nbf": str(now)},
        ]
        for claims in malformed:
            assert status(url, raw(claims)) == 403, f"{url} {claims}"

    tenant = env.initial_tenant
    metrics_with_tenant = raw({"scope": "metrics", "tenant_id": str(tenant)})
    for url in [
        f"http://localhost:{env.pageserver.service_port.http}/v1/tenant/{tenant}",
        f"http://localhost:{env.safekeepers[0].port.http}/v1/tenant/{tenant}/timeline/{env.initial_timeline}",
        f"{env.storage_controller_api}/v1/tenant/{tenant}",
    ]:
        assert status(url, metrics_with_tenant) == 403, url


def test_route_check_keeps_own_tenant_global_and_public_access(
    neon_env_builder: NeonEnvBuilder,
):
    """
    The route check every API route runs first (K7 fix round) refuses only what it
    must: a tenant token still reaches its own tenant's data routes (but not the
    control-plane routes the user's ruling makes global-only, the tenant config routes
    included), each server's own global scope still reaches management routes, the
    public routes take no token, and the storage controller refuses the scopes none of
    its routes take.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(
        [
            ".*Error processing HTTP request: Forbidden.*",
            ".*JWT scope '.+' is ineligible for Pageserver auth.*",
        ]
    )
    env.storage_controller.allowed_errors.extend([".*Forbidden.*"])

    keys = env.auth_keys
    tenant, timeline = env.initial_tenant, env.initial_timeline
    other, _ = env.create_tenant()
    endpoint = env.endpoints.create_start("main")
    endpoint.safe_psql("CREATE TABLE t AS SELECT 1 AS x")  # the safekeeper holds the timeline
    endpoint.stop()
    own = keys.generate_tenant_token(tenant)
    no_tenant = keys.generate_token(scope=TokenScope.TENANT)
    pageserverapi = keys.generate_token(scope=TokenScope.PAGE_SERVER_API)
    safekeeperdata = keys.generate_token(scope=TokenScope.SAFEKEEPER_DATA)
    admin = keys.generate_token(scope=TokenScope.ADMIN)
    infra = keys.generate_token(scope=TokenScope.INFRA)

    def call(method: str, url: str, token: str | None, body: object | None = None) -> int:
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        return requests.request(method, url, headers=headers, json=body, timeout=60).status_code

    ps = f"http://localhost:{env.pageserver.service_port.http}"
    assert call("GET", f"{ps}/v1/tenant/{tenant}", own) == 200
    assert call("GET", f"{ps}/v1/tenant/{tenant}/timeline/{timeline}", own) == 200
    assert call("GET", f"{ps}/v1/tenant/{other}", own) == 403
    assert call("GET", f"{ps}/v1/location_config", own) == 403
    assert call("GET", f"{ps}/v1/location_config", pageserverapi) == 200
    assert call("GET", f"{ps}/v1/tenant/{other}", pageserverapi) == 200
    assert call("GET", f"{ps}/v1/tenant", admin) == 403
    # The tenant config routes take the global scope only (user ruling, final fix
    # round): no tenant token passes, whatever tenant the body names.
    for method in ("PATCH", "PUT"):
        for token in (own, no_tenant):
            for body_tenant in (tenant, other):
                body = {"tenant_id": str(body_tenant)}
                assert call(method, f"{ps}/v1/tenant/config", token, body) == 403, method
    assert call("PATCH", f"{ps}/v1/tenant/config", pageserverapi, {"tenant_id": str(tenant)}) == 200
    # So do the other control-plane routes that name a tenant (`test_route_scopes.py`
    # probes them all); the global scope still reaches them.
    assert call("GET", f"{ps}/v1/location_config/{tenant}", own) == 403
    assert call("GET", f"{ps}/v1/location_config/{tenant}", pageserverapi) == 200
    # A path parameter that isn't a tenant id is a management route for the check.
    assert call("GET", f"{ps}/v1/tenant/not-a-tenant", own) == 403
    assert call("GET", f"{ps}/v1/tenant/not-a-tenant", pageserverapi) == 400
    for path in ("/v1/status", "/v1/doc", "/swagger.yml"):
        assert call("GET", f"{ps}{path}", None) == 200, path

    sk = f"http://localhost:{env.safekeepers[0].port.http}"
    assert call("GET", f"{sk}/v1/tenant/{tenant}/timeline/{timeline}", own) == 200
    assert call("GET", f"{sk}/v1/tenant/{tenant}/timeline/{timeline}", safekeeperdata) == 200
    assert call("GET", f"{sk}/v1/utilization", safekeeperdata) == 200
    assert call("GET", f"{sk}/v1/utilization", own) == 403
    assert call("POST", f"{sk}/v1/tenant/timeline", no_tenant, {}) == 403
    assert call("GET", f"{sk}/v1/status", None) == 200

    sc = env.storage_controller_api
    assert call("PUT", f"{sc}/debug/v1/failpoints", admin, []) == 200
    assert call("PUT", f"{sc}/debug/v1/failpoints", pageserverapi, []) == 403
    assert call("POST", f"{sc}/v1/tenant/{tenant}/secondary/download", own) == 403
    assert call("GET", f"{sc}/control/v1/node", safekeeperdata) == 403
    assert call("GET", f"{sc}/control/v1/node", infra) == 200
    assert call("GET", f"{sc}/control/v1/node", admin) == 200
    for path in ("/status", "/live", "/ready"):
        assert call("GET", f"{sc}{path}", None) == 200, path
