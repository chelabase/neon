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
