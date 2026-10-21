from __future__ import annotations

import functools
import re
import stat
from http.client import (
    BAD_REQUEST,
    CREATED,
    FORBIDDEN,
    OK,
    PRECONDITION_FAILED,
    UNAUTHORIZED,
)
from typing import TYPE_CHECKING, Any

import jwt
import psutil
import pytest
import requests
from fixtures.endpoint.http import COMPUTE_AUDIENCE, ComputeClaimsScope, EndpointHttpClient
from fixtures.utils import run_only_on_default_postgres
from requests import HTTPError, RequestException

if TYPE_CHECKING:
    from collections.abc import Callable

    from fixtures.neon_fixtures import Endpoint, NeonEnv


@run_only_on_default_postgres("The code path being tested is not dependent on Postgres version")
def test_compute_no_scope_claim(neon_simple_env: NeonEnv):
    """
    Test that if the JWT scope is not admin and no compute_id is specified,
    the external HTTP server returns a 403 Forbidden error.
    """
    env = neon_simple_env

    endpoint = env.endpoints.create_start("main")

    # Encode nothing in the token
    token = jwt.encode({}, env.auth_keys.priv, algorithm="EdDSA")

    # Create an admin-scoped HTTP client
    client = EndpointHttpClient(
        external_port=endpoint.external_http_port,
        internal_port=endpoint.internal_http_port,
        jwt=token,
    )

    try:
        client.status()
        pytest.fail("Exception should have been raised")
    except RequestException as e:
        assert e.response is not None
        assert e.response.status_code == FORBIDDEN


@pytest.mark.parametrize(
    "audience",
    (COMPUTE_AUDIENCE, "invalid", None),
    ids=["with_audience", "with_invalid_audience", "without_audience"],
)
@run_only_on_default_postgres("The code path being tested is not dependent on Postgres version")
def test_compute_admin_scope_claim(neon_simple_env: NeonEnv, audience: str | None):
    """
    Test that an admin-scoped JWT can access the compute's external HTTP server
    without the compute_id being specified in the claims.
    """
    env = neon_simple_env

    endpoint = env.endpoints.create_start("main")

    data: dict[str, str | list[str]] = {"scope": str(ComputeClaimsScope.ADMIN)}
    if audience:
        data["aud"] = [audience]

    token = jwt.encode(data, env.auth_keys.priv, algorithm="EdDSA")

    # Create an admin-scoped HTTP client
    client = EndpointHttpClient(
        external_port=endpoint.external_http_port,
        internal_port=endpoint.internal_http_port,
        jwt=token,
    )

    try:
        client.status()
        if audience != COMPUTE_AUDIENCE:
            pytest.fail("Exception should have been raised")
    except RequestException as e:
        assert e.response is not None
        assert e.response.status_code == UNAUTHORIZED


# ---------------------------------------------------------------------------
# Fork round 4, K3: compute_ctl's internal server and token files (spec §4,
# §4.1, §8; D2, RT4-6, RT4-10; plan P4, P5, SP6, SP18). Auth-off environments
# only (plan P3: the neon extension reads the storage token file from K5 on).
#
# Fixture interface (SP18): `Endpoint.internal_api_token_file` and
# `Endpoint.storage_auth_token_file` (Paths: `<endpoint dir>/compute_ctl_internal.token`
# and `<endpoint dir>/storage_auth.token`); `EndpointHttpClient` sends the
# internal secret read from its endpoint's file as the bearer on internal-port
# routes only and dials 127.0.0.1 for them; `EndpointHttpClient.storage_token(token)`
# posts `/storage_token` with the external JWT and raises on a non-2xx answer.
# ---------------------------------------------------------------------------

SECRET_FORM = re.compile(r"[0-9a-f]{64}")


def _internal_routes() -> list[tuple[str, Any]]:
    # /extensions first: a build without the check installs and answers 201.
    return [
        (
            "/extensions",
            {"extension": "neon_test_utils", "database": "postgres", "version": "1.3"},
        ),
        (
            "/grants",
            {
                "database": "postgres",
                "schema": "public",
                "privileges": ["USAGE"],
                "role": "k3_nobody",
            },
        ),
        ("/extension_server/k3_none.tar.zst", None),
        ("/refresh_configuration", None),
        ("/failpoints", []),
    ]


def _post_internal(
    endpoint: Endpoint, route: str, body: Any, authorization: str | None
) -> requests.Response:
    headers = {} if authorization is None else {"Authorization": authorization}
    return requests.post(
        f"http://127.0.0.1:{endpoint.internal_http_port}{route}",
        json=body,
        headers=headers,
        timeout=30,
    )


def _assert_refused(res: requests.Response, what: str):
    assert res.status_code == UNAUTHORIZED, f"{what}: {res.status_code} {res.text}"
    challenge = res.headers.get("WWW-Authenticate", "")
    assert challenge.startswith("Bearer"), f"{what}: WWW-Authenticate {challenge!r}"
    assert isinstance(res.json().get("error"), str), f"{what}: {res.text}"


def _conf_line(conf: str, name: str) -> str | None:
    """The last `name = value` line of a postgresql.conf, spaces removed."""
    found = None
    for line in conf.splitlines():
        squeezed = line.replace(" ", "")
        if squeezed.startswith(f"{name}="):
            found = squeezed
    return found


@run_only_on_default_postgres("compute_ctl's HTTP server doesn't depend on the Postgres version")
def test_internal_api_needs_the_token(neon_simple_env: NeonEnv):
    """
    Every internal route answers 401 without the per-start secret and runs with
    it; the secret lives in a 0600 file next to pgdata, changes at every start
    and never reaches the log.
    """
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    for route, body in _internal_routes():
        _assert_refused(_post_internal(endpoint, route, body, None), f"{route} without a bearer")

    path = endpoint.internal_api_token_file
    assert path.parent == endpoint.endpoint_path(), path
    assert not path.is_relative_to(endpoint.pg_data_dir_path()), "never inside pgdata"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    content = path.read_text()
    assert content.endswith("\n") and content.count("\n") == 1, repr(content)
    secret = content[:-1]
    assert SECRET_FORM.fullmatch(secret), "64 lowercase hex characters"

    conf = (endpoint.pg_data_dir_path() / "postgresql.conf").read_text()
    assert _conf_line(conf, "neon.compute_ctl_token_file") == (
        f"neon.compute_ctl_token_file='{path}'"
    ), conf
    assert secret not in conf, "postgresql.conf carries the path, never the secret"
    # P4: auth is off, so the compute has no storage token: an empty path, no file.
    assert _conf_line(conf, "neon.storage_auth_token_file") == "neon.storage_auth_token_file=''"
    assert not endpoint.storage_auth_token_file.exists()

    wrong = [
        "Basic Zm9vOmJhcg==",
        "Bearer",
        "Bearer wrong",
        f"Bearer {secret}x",
        f"Bearer x{secret}",
        f"Bearer {secret[:63]}",
        f"Bearer {secret.upper()}",
        f"Token {secret}",
        secret,
    ]
    for route, body in _internal_routes():
        for n, authorization in enumerate(wrong):
            res = _post_internal(endpoint, route, body, authorization)
            _assert_refused(res, f"{route} with wrong bearer #{n}")
            assert secret not in res.text, f"{route}: the secret echoed"

    ok = f"Bearer {secret}"
    version = endpoint.safe_psql(
        "SELECT default_version FROM pg_available_extensions WHERE name = 'neon_test_utils'"
    )[0][0]
    res = _post_internal(
        endpoint,
        "/extensions",
        {"extension": "neon_test_utils", "database": "postgres", "version": version},
        ok,
    )
    assert res.status_code == CREATED, res.text
    for sql in [
        "CREATE ROLE k3_owner",
        "CREATE ROLE k3_user",
        "CREATE SCHEMA k3_app AUTHORIZATION k3_owner",
    ]:
        endpoint.safe_psql(sql)
    res = _post_internal(
        endpoint,
        "/grants",
        {"database": "postgres", "schema": "k3_app", "privileges": ["USAGE"], "role": "k3_user"},
        ok,
    )
    assert res.status_code == CREATED, res.text
    res = _post_internal(endpoint, "/failpoints", [], ok)
    assert res.status_code == OK, res.text
    # No remote extension storage in this environment: the handler's own answer.
    res = _post_internal(endpoint, "/extension_server/k3_none.tar.zst", None, ok)
    assert res.status_code == PRECONDITION_FAILED, res.text

    # The fixture carries the secret on internal routes (SP18).
    client = endpoint.http_client()
    client.set_role_grants("postgres", "k3_user", "k3_app", ["CREATE"])
    client.extensions("neon_test_utils", version, "postgres")

    # A new secret at every start; the old one stops working.
    endpoint.stop()
    endpoint.start()
    new_secret = endpoint.internal_api_token_file.read_text().strip()
    assert SECRET_FORM.fullmatch(new_secret)
    assert new_secret != secret
    _assert_refused(
        _post_internal(endpoint, "/failpoints", [], f"Bearer {secret}"), "the previous secret"
    )
    res = _post_internal(endpoint, "/failpoints", [], f"Bearer {new_secret}")
    assert res.status_code == OK, res.text

    log = endpoint.logfile.read_text()
    assert secret not in log and new_secret not in log, "a secret reached compute.log"


@run_only_on_default_postgres("compute_ctl's HTTP server doesn't depend on the Postgres version")
def test_internal_api_listens_on_loopback_only(neon_simple_env: NeonEnv):
    """compute_ctl's internal port listens on 127.0.0.1 (and ::1), never on all addresses."""
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    def listening(port: int) -> set[str]:
        ips = set()
        for c in psutil.net_connections(kind="tcp"):
            # laddr is an empty tuple for a socket without a local address.
            ip, lport = c.laddr if c.laddr else ("", 0)
            if c.status == psutil.CONN_LISTEN and lport == port:
                ips.add(ip)
        return ips

    internal = listening(endpoint.internal_http_port)
    assert internal, "nothing listens on the internal port"
    assert internal <= {"127.0.0.1", "::1"}, f"internal port listens on {internal}"
    assert "127.0.0.1" in internal, internal
    # The external server is unchanged.
    assert listening(endpoint.external_http_port), "nothing listens on the external port"


def _refused_with(status: int, call: Callable[[], object], what: str):
    with pytest.raises(HTTPError) as e:
        call()
    assert e.value.response is not None
    assert e.value.response.status_code == status, (
        f"{what}: {e.value.response.status_code} {e.value.response.text}"
    )


@run_only_on_default_postgres("compute_ctl's HTTP server doesn't depend on the Postgres version")
def test_internal_grants_are_narrowed(neon_simple_env: NeonEnv):
    """
    RT4-6, the catalog rules: `/grants` works only on a schema a non-superuser
    owns, for an existing grantee that is no superuser and carries no
    `chelabase.managed_role` marker (a role-wide setting; a database-scoped one
    doesn't mark). The name rules are compute_ctl unit tests.
    """
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")
    for sql in [
        "CREATE ROLE k3_owner",
        "CREATE ROLE k3_user",
        "CREATE SCHEMA k3_app AUTHORIZATION k3_owner",
        # Superuser-owned, as the platform's schemas are.
        "CREATE SCHEMA k3_platform",
        "CREATE ROLE k3_super SUPERUSER",
        "CREATE ROLE k3_marked",
        "ALTER ROLE k3_marked SET chelabase.managed_role = 'personal'",
        "CREATE ROLE k3_marked_empty",
        "ALTER ROLE k3_marked_empty SET chelabase.managed_role = ''",
        "CREATE ROLE k3_db_marked",
        "ALTER ROLE k3_db_marked IN DATABASE postgres SET chelabase.managed_role = 'personal'",
    ]:
        endpoint.safe_psql(sql)
    client = endpoint.http_client()

    def has(role: str, schema: str, privilege: str) -> bool:
        query = f"SELECT has_schema_privilege('{role}', '{schema}', '{privilege}')"
        return bool(endpoint.safe_psql(query)[0][0])

    _refused_with(
        FORBIDDEN,
        lambda: client.set_role_grants("postgres", "k3_user", "k3_platform", ["USAGE"]),
        "a superuser-owned schema",
    )
    assert not has("k3_user", "k3_platform", "USAGE"), "nothing granted"
    for role in ["k3_super", "k3_marked", "k3_marked_empty", "k3_ghost", "public"]:
        _refused_with(
            FORBIDDEN,
            functools.partial(client.set_role_grants, "postgres", role, "k3_app", ["CREATE"]),
            f"grantee {role}",
        )
    assert not has("k3_user", "k3_app", "CREATE"), "PUBLIC got nothing"
    _refused_with(
        FORBIDDEN,
        lambda: client.set_role_grants("postgres", "k3_user", "pg_catalog", ["CREATE"]),
        "pg_catalog",
    )

    client.set_role_grants("postgres", "k3_user", "k3_app", ["USAGE", "CREATE"])
    assert has("k3_user", "k3_app", "USAGE") and has("k3_user", "k3_app", "CREATE")
    # Only a role-wide setting marks (the SP22 predicate).
    client.set_role_grants("postgres", "k3_db_marked", "k3_app", ["USAGE"])
    assert has("k3_db_marked", "k3_app", "USAGE")


@run_only_on_default_postgres("compute_ctl's HTTP server doesn't depend on the Postgres version")
def test_internal_extensions_need_a_trusted_extension(neon_simple_env: NeonEnv):
    """RT4-6: `/extensions` installs only what the owner could install itself."""
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")
    client = endpoint.http_client()

    def available(name: str) -> str:
        rows = endpoint.safe_psql(
            f"SELECT default_version FROM pg_available_extensions WHERE name = '{name}'"
        )
        assert rows, f"{name} is in this build"
        return str(rows[0][0])

    def installed(name: str) -> bool:
        query = f"SELECT count(*) FROM pg_extension WHERE extname = '{name}'"
        return bool(endpoint.safe_psql(query)[0][0])

    pageinspect = available("pageinspect")
    _refused_with(
        FORBIDDEN,
        lambda: client.extensions("pageinspect", pageinspect, "postgres"),
        "pageinspect (untrusted)",
    )
    assert not installed("pageinspect")
    for name, version in [
        ("pageinspect", "1.0' CASCADE --"),
        ("amcheck", available("amcheck")),
        ("k3_no_such_extension", "1.0"),
    ]:
        _refused_with(
            FORBIDDEN,
            functools.partial(client.extensions, name, version, "postgres"),
            f"{name} {version}",
        )
        assert not installed(name), name

    client.extensions("pg_trgm", available("pg_trgm"), "postgres")
    assert installed("pg_trgm"), "a trusted extension installs"


@run_only_on_default_postgres("compute_ctl's HTTP server doesn't depend on the Postgres version")
def test_storage_token_on_a_compute_without_storage_auth(neon_simple_env: NeonEnv):
    """
    SP6: a compute started without a storage token (auth off) wrote an empty
    token-file path, so `POST /storage_token` can't take effect before a
    restart: 400, nothing written.
    """
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    res = requests.post(
        f"http://localhost:{endpoint.external_http_port}/storage_token",
        json={"token": "k3sp6.eyJ0IjoxfQ.c2ln"},
        headers={"Authorization": f"Bearer {endpoint.generate_jwt()}"},
        timeout=30,
    )
    assert res.status_code == BAD_REQUEST, f"{res.status_code} {res.text}"
    assert "restart" in res.json()["error"].lower(), res.text
    assert "k3sp6" not in res.text
    assert endpoint.storage_auth_token_file == endpoint.endpoint_path() / "storage_auth.token"
    assert not endpoint.storage_auth_token_file.exists()

    _refused_with(
        BAD_REQUEST,
        lambda: endpoint.http_client().storage_token("k3sp6.eyJ0IjoxfQ.c2ln"),
        "the fixture's storage_token",
    )
    assert endpoint.http_client().status()["status"] == "running"
