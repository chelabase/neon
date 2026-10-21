"""
F3 coder edges beyond the RED set (fork round 4, final fix round).

- K5: a symlink to a FIFO at the storage token path is refused from the `stat()` (which
  follows the link) like a FIFO itself: no hang, one WARNING naming the path.
- K6: COMMENT ON ROLE / SECURITY LABEL ON ROLE on a managed name in another case, after
  SET ROLE from a superuser, and on a role that doesn't exist.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import psycopg2
import pytest
from fixtures.token_files import (
    PAGESERVER_AUTH_ERRORS,
    TABLE_ROWS,
    log_since,
    log_size,
    make_table,
    new_session_cannot_read,
    new_session_reads,
    reader_warnings,
    replace_file,
    start_with_storage_auth,
)
from psycopg2.errors import InsufficientPrivilege, UndefinedObject
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import NeonEnvBuilder, VanillaPostgres
    from pytest_httpserver import HTTPServer
    from werkzeug.wrappers.request import Request

MARKER = "chelabase.managed_role"
MEMBER = "cb_m_0123456789abcdef0123456789abcdef"
# The same name in capitals, quoted: another role, still managed by its name.
UPPER_QUOTED = '"' + MEMBER.upper() + '"'


def test_a_symlink_to_a_fifo_is_never_opened(neon_env_builder: NeonEnvBuilder):
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint = start_with_storage_auth(env)
    admin = make_table(endpoint)
    path = endpoint.storage_auth_token_file
    good = path.read_bytes()

    fifo = path.with_name("f3-edge.fifo")
    os.mkfifo(fifo, 0o600)
    path.unlink()
    path.symlink_to(fifo)

    endpoint.clear_buffers(cursor=admin)
    offset = log_size(endpoint)
    # A blocking open of the FIFO would hang this session (nobody writes to it).
    new_session_cannot_read(endpoint, "a symlink to a FIFO")
    text = log_since(endpoint, offset)
    assert reader_warnings(text, path), "no WARNING names the token path"
    assert "not a regular file" in text

    path.unlink()
    fifo.unlink()
    replace_file(path, good)
    assert new_session_reads(endpoint) == TABLE_ROWS


@pytest.fixture
def guarded_pg(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
):
    (host, port) = httpserver_listen_address
    endpoint = "/test/roles_and_databases"

    def record(request: Request) -> Response:
        json.loads(request.get_data(as_text=True))
        return Response(status=200)

    httpserver.expect_request(endpoint, method="PATCH").respond_with_handler(record)
    vanilla_pg.configure(
        [f"neon.console_url=http://{host}:{port}{endpoint}", "shared_preload_libraries = 'neon'"]
    )
    vanilla_pg.start()
    vanilla_pg.safe_psql_many(
        [
            "CREATE ROLE neon_superuser NOLOGIN CREATEDB CREATEROLE",
            "CREATE ROLE owner LOGIN CREATEROLE PASSWORD 'pw' IN ROLE neon_superuser",
            "CREATE ROLE alice LOGIN PASSWORD 'pw'",
            f"ALTER ROLE alice SET {MARKER} = 'personal'",
            f"CREATE ROLE {UPPER_QUOTED} LOGIN PASSWORD 'pw'",
            "GRANT alice TO owner WITH ADMIN OPTION",
            f"GRANT {UPPER_QUOTED} TO owner WITH ADMIN OPTION",
        ]
    )
    return vanilla_pg


def owner_runs(pg: VanillaPostgres, sql: str) -> None:
    login: dict[str, Any] = {"user": "owner", "password": "pw"}
    with pg.cursor(**login) as cur:
        cur.execute(sql)


def test_a_managed_name_in_another_case_is_refused(guarded_pg: VanillaPostgres):
    for sql in [
        f"COMMENT ON ROLE {UPPER_QUOTED} IS 'x'",
        f"SECURITY LABEL ON ROLE {UPPER_QUOTED} IS 'MASKED'",
    ]:
        with pytest.raises(InsufficientPrivilege) as e:
            owner_runs(guarded_pg, sql)
        expected = f"member role {UPPER_QUOTED} is managed by Chelabase"
        assert e.value.diag.message_primary == expected


def test_set_role_from_a_superuser_is_refused(guarded_pg: VanillaPostgres):
    """The guard keys on the current user: a superuser session after SET ROLE owner."""
    with guarded_pg.cursor() as cur:
        cur.execute("SET ROLE owner")
        with pytest.raises(InsufficientPrivilege):
            cur.execute("COMMENT ON ROLE alice IS 'x'")
    rows = guarded_pg.safe_psql(
        "SELECT pg_catalog.shobj_description(oid, 'pg_authid') FROM pg_catalog.pg_roles"
        " WHERE rolname = 'alice'"
    )
    assert rows == [(None,)]


def test_a_missing_role_gets_postgres_own_error(guarded_pg: VanillaPostgres):
    """An ordinary name with no role behind it is not the guard's: Postgres says it is missing."""
    with pytest.raises(UndefinedObject):
        owner_runs(guarded_pg, "COMMENT ON ROLE nobody_here IS 'x'")
    # A managed name is refused by name, whether or not the role exists.
    with pytest.raises(InsufficientPrivilege):
        owner_runs(guarded_pg, "COMMENT ON ROLE cb_m_ffffffffffffffffffffffffffffffff IS 'x'")
    with pytest.raises(psycopg2.Error):
        owner_runs(guarded_pg, "COMMENT ON ROLE nobody_here IS NULL")
