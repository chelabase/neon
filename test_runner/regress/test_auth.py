from __future__ import annotations

import os
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

import jwt
import psycopg2
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fixtures.auth_tokens import AuthKeys, TokenScope
from fixtures.common_types import TenantId, TimelineId
from fixtures.neon_fixtures import (
    NeonEnv,
    NeonEnvBuilder,
    PgProtocol,
)
from fixtures.pageserver.http import PageserverApiException, PageserverHttpClient


def assert_client_authorized(env: NeonEnv, http_client: PageserverHttpClient):
    http_client.timeline_create(
        pg_version=env.pg_version,
        tenant_id=env.initial_tenant,
        new_timeline_id=TimelineId.generate(),
        ancestor_timeline_id=env.initial_timeline,
    )


def assert_client_not_authorized(env: NeonEnv, http_client: PageserverHttpClient):
    with pytest.raises(
        PageserverApiException,
        match="Forbidden: JWT authentication error",
    ):
        assert_client_authorized(env, http_client)


def test_pageserver_auth(neon_env_builder: NeonEnvBuilder):
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()

    ps = env.pageserver

    tenant_token = env.auth_keys.generate_tenant_token(env.initial_tenant)
    tenant_http_client = env.pageserver.http_client(tenant_token)
    invalid_tenant_token = env.auth_keys.generate_tenant_token(TenantId.generate())
    invalid_tenant_http_client = env.pageserver.http_client(invalid_tenant_token)

    pageserver_token = env.auth_keys.generate_pageserver_token()
    pageserver_http_client = env.pageserver.http_client(pageserver_token)

    # this does not invoke auth check and only decodes jwt and checks it for validity
    # check both tokens
    ps.safe_psql("set FOO", password=tenant_token)
    ps.safe_psql("set FOO", password=pageserver_token)

    # tenant can create branches
    assert_client_authorized(env, tenant_http_client)

    # console can create branches for tenant
    assert_client_authorized(env, pageserver_http_client)

    # fail to create branch using token with different tenant_id
    with pytest.raises(PageserverApiException, match="Forbidden: JWT authentication error"):
        assert_client_authorized(env, invalid_tenant_http_client)

    # create tenant using management token
    env.pageserver.tenant_create(TenantId.generate(), auth_token=pageserver_token)

    # fail to create tenant using tenant token
    with pytest.raises(
        PageserverApiException,
        match="Forbidden: JWT authentication error",
    ):
        env.pageserver.tenant_create(TenantId.generate(), auth_token=tenant_token)


def test_compute_auth_to_pageserver(neon_env_builder: NeonEnvBuilder):
    neon_env_builder.auth_enabled = True
    neon_env_builder.num_safekeepers = 3
    env = neon_env_builder.init_start()

    branch = "test_compute_auth_to_pageserver"
    env.create_branch(branch)
    endpoint = env.endpoints.create_start(branch)

    with closing(endpoint.connect()) as conn:
        with conn.cursor() as cur:
            # we rely upon autocommit after each statement
            # as waiting for acceptors happens there
            cur.execute("CREATE TABLE t(key int primary key, value text)")
            cur.execute("INSERT INTO t SELECT generate_series(1,100000), 'payload'")
            cur.execute("SELECT sum(key) FROM t")
            assert cur.fetchone() == (5000050000,)


def test_pageserver_multiple_keys(neon_env_builder: NeonEnvBuilder):
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(
        [".*Authentication error: InvalidSignature.*", ".*Unauthorized: malformed jwt token.*"]
    )

    pageserver_token_old = env.auth_keys.generate_pageserver_token()
    pageserver_http_client_old = env.pageserver.http_client(pageserver_token_old)

    pageserver_http_client_old.reload_auth_validation_keys()

    # This test is to ensure that the pageserver supports multiple keys.
    # The neon_local tool generates one key pair at a hardcoded path by default.
    # As a preparation for our test, move the public key of the key pair into a
    # directory at the same location as the hardcoded path by:
    # 1. moving the file at `configured_pub_key_path` to a temporary location
    # 2. creating a new directory at `configured_pub_key_path`
    # 3. moving the file from the temporary location into the newly created directory
    configured_pub_key_path = Path(env.repo_dir) / "auth_public_key.pem"
    os.rename(configured_pub_key_path, Path(env.repo_dir) / "auth_public_key.pem.file")
    os.mkdir(configured_pub_key_path)
    os.rename(
        Path(env.repo_dir) / "auth_public_key.pem.file",
        configured_pub_key_path / "auth_public_key_old.pem",
    )

    # Add a new key pair
    # This invalidates env.auth_keys and makes them be regenerated
    env.regenerate_keys_at(
        Path("auth_private_key.pem"), Path("auth_public_key.pem/auth_public_key_new.pem")
    )

    # Reload the keys on the pageserver side
    pageserver_http_client_old.reload_auth_validation_keys()

    # We can continue doing things using the old token
    assert_client_authorized(env, pageserver_http_client_old)

    pageserver_token_new = env.auth_keys.generate_pageserver_token()
    pageserver_http_client_new = env.pageserver.http_client(pageserver_token_new)

    # The new token also works
    assert_client_authorized(env, pageserver_http_client_new)

    # Remove the old token and reload
    os.remove(Path(env.repo_dir) / "auth_public_key.pem" / "auth_public_key_old.pem")
    pageserver_http_client_old.reload_auth_validation_keys()

    # Reloading fails now with the old token, but the new token still works
    assert_client_not_authorized(env, pageserver_http_client_old)
    assert_client_authorized(env, pageserver_http_client_new)


def test_pageserver_key_reload(neon_env_builder: NeonEnvBuilder):
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(
        [".*Authentication error: InvalidSignature.*", ".*Unauthorized: malformed jwt token.*"]
    )
    pageserver_token_old = env.auth_keys.generate_pageserver_token()
    pageserver_http_client_old = env.pageserver.http_client(pageserver_token_old)

    pageserver_http_client_old.reload_auth_validation_keys()

    # Regenerate the keys
    env.regenerate_keys_at(Path("auth_private_key.pem"), Path("auth_public_key.pem"))

    # Reload the keys on the pageserver side
    pageserver_http_client_old.reload_auth_validation_keys()

    # Next attempt fails as we use the old auth token
    with pytest.raises(
        PageserverApiException,
        match="Forbidden: JWT authentication error",
    ):
        pageserver_http_client_old.reload_auth_validation_keys()

    # same goes for attempts trying to create a timeline
    assert_client_not_authorized(env, pageserver_http_client_old)

    pageserver_token_new = env.auth_keys.generate_pageserver_token()
    pageserver_http_client_new = env.pageserver.http_client(pageserver_token_new)

    # timeline creation works with the new token
    assert_client_authorized(env, pageserver_http_client_new)

    # reloading also works with the new token
    pageserver_http_client_new.reload_auth_validation_keys()


@pytest.mark.parametrize("auth_enabled", [False, True])
def test_auth_failures(neon_env_builder: NeonEnvBuilder, auth_enabled: bool):
    neon_env_builder.auth_enabled = auth_enabled
    env = neon_env_builder.init_start()

    branch = f"test_auth_failures_auth_enabled_{auth_enabled}"
    timeline_id = env.create_branch(branch)
    env.endpoints.create_start(branch)

    tenant_token = env.auth_keys.generate_tenant_token(env.initial_tenant)
    invalid_tenant_token = env.auth_keys.generate_tenant_token(TenantId.generate())
    pageserver_token = env.auth_keys.generate_pageserver_token()
    safekeeper_token = env.auth_keys.generate_safekeeper_token()

    def check_connection(
        pg_protocol: PgProtocol, command: str, expect_success: bool, **conn_kwargs
    ):
        def op():
            with closing(pg_protocol.connect(**conn_kwargs)) as conn:
                with conn.cursor() as cur:
                    cur.execute(command)

        if expect_success:
            op()
        else:
            with pytest.raises(psycopg2.Error):
                op()

    def check_pageserver(expect_success: bool, **conn_kwargs):
        check_connection(
            env.pageserver,
            f"pagestream_v2 {env.initial_tenant} {env.initial_timeline}",
            expect_success,
            **conn_kwargs,
        )

    check_pageserver(not auth_enabled)
    if auth_enabled:
        check_pageserver(True, password=tenant_token)

        env.pageserver.allowed_errors.append(".*Tenant id mismatch. Permission denied.*")
        check_pageserver(False, password=invalid_tenant_token)

        check_pageserver(True, password=pageserver_token)

        env.pageserver.allowed_errors.append(".*JWT scope '.+' is ineligible for Pageserver auth.*")
        check_pageserver(False, password=safekeeper_token)

    def check_safekeeper(expect_success: bool, **conn_kwargs):
        check_connection(
            PgProtocol(
                host="localhost",
                port=env.safekeepers[0].port.pg,
                options=f"ztenantid={env.initial_tenant} ztimelineid={timeline_id}",
            ),
            "IDENTIFY_SYSTEM",
            expect_success,
            **conn_kwargs,
        )

    check_safekeeper(not auth_enabled)
    if auth_enabled:
        check_safekeeper(True, password=tenant_token)
        check_safekeeper(False, password=invalid_tenant_token)
        check_safekeeper(False, password=pageserver_token)
        check_safekeeper(True, password=safekeeper_token)


def http_status(url: str, token: str | None) -> int | str:
    """
    The status of a plain GET (no client retries), or a description of the failure
    when the server answers nothing (a handler that panicked drops the connection).
    """
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    try:
        return requests.get(url, headers=headers, timeout=60).status_code
    except requests.ConnectionError as e:
        return f"no answer ({e})"


@dataclass
class StorageServer:
    name: str
    url: str
    # The server's own global scope (storcon: admin).
    own_global: TokenScope
    # Routes the auth middleware lets through without a token.
    public_routes: list[str]
    # Routes that need a token and are neither /metrics nor a profile.
    other_routes: list[str]


METRICS_ROUTE = "/metrics"
# Valid parameters, so an accepted request answers 200 (heap profiling is on in all
# three binaries: `malloc_conf` sets `prof:true`).
PROFILE_ROUTES = ["/profile/cpu?seconds=1", "/profile/heap?format=jemalloc"]


def storage_servers(env: NeonEnv) -> list[StorageServer]:
    tenant, timeline = env.initial_tenant, env.initial_timeline
    return [
        StorageServer(
            name="pageserver",
            url=f"http://localhost:{env.pageserver.service_port.http}",
            own_global=TokenScope.PAGE_SERVER_API,
            public_routes=["/v1/status", "/v1/doc", "/swagger.yml"],
            other_routes=["/v1/tenant", f"/v1/tenant/{tenant}"],
        ),
        StorageServer(
            name="safekeeper",
            url=f"http://localhost:{env.safekeepers[0].port.http}",
            own_global=TokenScope.SAFEKEEPER_DATA,
            public_routes=["/v1/status"],
            other_routes=["/v1/utilization", f"/v1/tenant/{tenant}/timeline/{timeline}"],
        ),
        StorageServer(
            name="storage_controller",
            url=env.storage_controller_api,
            own_global=TokenScope.ADMIN,
            public_routes=["/status", "/live", "/ready"],
            other_routes=["/debug/v1/tenant", f"/v1/tenant/{tenant}"],
        ),
    ]


def test_tenant_token_without_tenant_id(neon_env_builder: NeonEnvBuilder):
    """
    A correctly signed `{"scope": "tenant"}` token (no `tenant_id`) is refused with 403 on
    tenant routes; the server neither panics nor drops the connection, and keeps serving.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()

    tenant, timeline = env.initial_tenant, env.initial_timeline
    no_tenant_token = env.auth_keys.generate_token(scope=TokenScope.TENANT)
    ps = f"http://localhost:{env.pageserver.service_port.http}"
    sk = f"http://localhost:{env.safekeepers[0].port.http}"

    assert http_status(f"{ps}/v1/tenant/{tenant}", no_tenant_token) == 403
    assert http_status(f"{sk}/v1/tenant/{tenant}/timeline/{timeline}", no_tenant_token) == 403

    # Both servers still answer, and a token for the tenant still works.
    assert http_status(f"{ps}/v1/status", None) == 200
    assert http_status(f"{sk}/v1/status", None) == 200
    tenant_token = env.auth_keys.generate_tenant_token(tenant)
    assert http_status(f"{ps}/v1/tenant/{tenant}", tenant_token) == 200


def test_metrics_and_profiles_need_a_token(neon_env_builder: NeonEnvBuilder):
    """
    With auth on, `/metrics` takes {metrics, admin, the server's own global scope} and the
    profiles {admin, own global} on the pageserver, the safekeeper and the storage
    controller; no token is 401, any other scope 403. A metrics token opens nothing else,
    libpq included, and the status and doc routes stay public.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(
        [
            ".*Unauthorized: missing authorization header.*",
            ".*JWT scope '.+' is ineligible for Pageserver auth.*",
        ]
    )
    env.storage_controller.allowed_errors.extend([".*Unauthorized.*", ".*Forbidden.*"])
    servers = storage_servers(env)

    for server in servers:
        for route in [METRICS_ROUTE, *PROFILE_ROUTES]:
            status = http_status(server.url + route, None)
            assert status == 401, f"{server.name} {route} without a token: {status}"

    for server in servers:
        for route in server.public_routes:
            status = http_status(server.url + route, None)
            assert isinstance(status, int) and status not in (401, 403), (
                f"{server.name} {route} is public: {status}"
            )

    keys = env.auth_keys
    # The fixture's scope for the wire name "metrics" (`TokenScope.METRICS`).
    metrics_scope = TokenScope("metrics")
    metrics_token = keys.generate_token(scope=metrics_scope)
    for server in servers:
        status = http_status(server.url + METRICS_ROUTE, metrics_token)
        assert status == 200, f"{server.name} /metrics with a metrics token: {status}"
        for route in [*PROFILE_ROUTES, *server.other_routes]:
            status = http_status(server.url + route, metrics_token)
            assert status == 403, f"{server.name} {route} with a metrics token: {status}"

        for scope in {TokenScope.ADMIN, server.own_global}:
            token = keys.generate_token(scope=scope)
            for route in [METRICS_ROUTE, *PROFILE_ROUTES]:
                status = http_status(server.url + route, token)
                assert status == 200, f"{server.name} {route} with {scope}: {status}"

        for scope in TokenScope:
            if scope in (metrics_scope, TokenScope.ADMIN, server.own_global):
                continue
            if scope == TokenScope.TENANT:
                token = keys.generate_tenant_token(env.initial_tenant)
            else:
                token = keys.generate_token(scope=scope)
            for route in [METRICS_ROUTE, *PROFILE_ROUTES]:
                status = http_status(server.url + route, token)
                assert status == 403, f"{server.name} {route} with {scope}: {status}"

    # `admin` opens the profiles only: every other pageserver and safekeeper route
    # still refuses it (S8).
    admin_token = keys.generate_token(scope=TokenScope.ADMIN)
    for server in servers:
        if server.own_global == TokenScope.ADMIN:
            continue
        for route in server.other_routes:
            status = http_status(server.url + route, admin_token)
            assert status == 403, f"{server.name} {route} with admin: {status}"

    # libpq: the page service and the safekeeper refuse a metrics token (RT4-5); the
    # servers' own tokens are the control.
    timeline_id = env.create_branch("test_metrics_and_profiles_need_a_token")
    env.endpoints.create_start("test_metrics_and_profiles_need_a_token")

    def libpq(pg_protocol: PgProtocol, command: str, token: str) -> None:
        with closing(pg_protocol.connect(password=token)) as conn:
            with conn.cursor() as cur:
                cur.execute(command)

    pagestream = f"pagestream_v2 {env.initial_tenant} {timeline_id}"
    safekeeper = PgProtocol(
        host="localhost",
        port=env.safekeepers[0].port.pg,
        options=f"ztenantid={env.initial_tenant} ztimelineid={timeline_id}",
    )
    libpq(env.pageserver, pagestream, keys.generate_pageserver_token())
    libpq(safekeeper, "IDENTIFY_SYSTEM", keys.generate_safekeeper_token())
    with pytest.raises(psycopg2.Error):
        libpq(env.pageserver, pagestream, metrics_token)
    with pytest.raises(psycopg2.Error):
        libpq(safekeeper, "IDENTIFY_SYSTEM", metrics_token)

    # The fixtures' own metric reads carry an accepted token when auth is on: the
    # teardown's pageserver checks, storcon's `get_metrics`, the safekeeper client.
    env.pageserver.assert_no_metric_errors()
    env.pageserver.snapshot_final_metrics()
    assert env.storage_controller.get_metric_value("storage_controller_pageserver_nodes") == 1
    assert "safekeeper_" in env.safekeepers[0].http_client().get_metrics_str()


def test_metrics_and_profiles_open_without_auth(neon_env_builder: NeonEnvBuilder):
    """With auth off nothing changes: `/metrics` and the profiles answer without a token."""
    env = neon_env_builder.init_start()
    for server in storage_servers(env):
        for route in [METRICS_ROUTE, *PROFILE_ROUTES]:
            status = http_status(server.url + route, None)
            assert status == 200, f"{server.name} {route} with auth off: {status}"


def test_token_helper_sets_numeric_exp_and_iat():
    """`AuthKeys.generate_token` keeps `exp` and `iat` numeric (RFC 7519 NumericDate)."""
    private_key = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    keys = AuthKeys(priv=private_key.decode())
    tenant = TenantId.generate()

    token = keys.generate_token(
        scope=TokenScope.TENANT, tenant_id=tenant, exp=2_000_000_000, iat=1_700_000_000
    )
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["exp"] == 2_000_000_000 and type(claims["exp"]) is int, claims
    assert claims["iat"] == 1_700_000_000 and type(claims["iat"]) is int, claims
    assert claims["tenant_id"] == str(tenant), claims
    assert claims["scope"] == "tenant", claims

    plain = jwt.decode(keys.generate_tenant_token(tenant), options={"verify_signature": False})
    assert "exp" not in plain and "iat" not in plain, plain


def test_storage_servers_validate_numeric_exp(neon_env_builder: NeonEnvBuilder):
    """
    A token with a future numeric `exp` is accepted and an expired one refused (`exp` 120 s
    in the past, beyond the 60 s leeway, SP8) with 403, as every token that fails to
    decode (`From<AuthError> for ApiError`).
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.append(".*Authentication error: ExpiredSignature.*")

    now = int(time.time())
    keys = env.auth_keys
    targets = [
        (
            f"http://localhost:{env.pageserver.service_port.http}/v1/tenant",
            TokenScope.PAGE_SERVER_API,
        ),
        (
            f"http://localhost:{env.safekeepers[0].port.http}/v1/utilization",
            TokenScope.SAFEKEEPER_DATA,
        ),
    ]
    for url, scope in targets:
        expired = keys.generate_token(scope=scope, exp=now - 120, iat=now - 3600)
        status = http_status(url, expired)
        assert status == 403, f"{url} with an expired exp: {status}"
        valid = keys.generate_token(scope=scope, exp=now + 3600, iat=now)
        status = http_status(url, valid)
        assert status == 200, f"{url} with a future exp: {status}"
