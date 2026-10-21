"""
Edge cases of the chelabase.managed_role marker guard (D1) beyond
test_member_role_guard.py: marker changes through other statement shapes,
markers that mark nothing, names that need quoting, and the guard's own
catalog lookups.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres
from psycopg2.errors import DivisionByZero, DuplicateObject, InsufficientPrivilege
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import VanillaPostgres
    from pytest_httpserver import HTTPServer
    from werkzeug.wrappers.request import Request

MARKER = "chelabase.managed_role"
MARKER_DENIED = f'permission denied to change parameter "{MARKER}"'


@pytest.fixture
def neon_pg(
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
            "CREATE ROLE bob LOGIN PASSWORD 'pw'",
            "GRANT bob TO owner WITH ADMIN OPTION",
        ]
    )
    return vanilla_pg


def role_settings(pg: VanillaPostgres, role: str) -> list[tuple[Any, ...]]:
    with pg.cursor() as cur:
        cur.execute(
            "SELECT s.setdatabase, s.setconfig FROM pg_catalog.pg_db_role_setting s"
            " JOIN pg_catalog.pg_roles r ON r.oid = s.setrole WHERE r.rolname = %s"
            " ORDER BY s.setdatabase",
            (role,),
        )
        return cur.fetchall()


def refusal(pg: VanillaPostgres, user: str, sql: str) -> InsufficientPrivilege:
    try:
        with pg.cursor(user=user, password="pw") as cur:
            cur.execute(sql)
    except InsufficientPrivilege as e:
        return e
    pytest.fail(f"{sql!r} as {user} succeeded; the role guard must refuse it")


@run_only_on_postgres(
    [PgVersion.V16, PgVersion.V17],
    "K6 H4: GRANT ... ON PARAMETER and a non-superuser's ALTER SYSTEM need PG15+, and the "
    "ADMIN rules this relies on are PG16's",
)
def test_marker_changes_through_other_shapes(neon_pg: VanillaPostgres):
    """
    With SET and ALTER SYSTEM on the marker granted by mistake, a non-superuser
    still can't change it: SET ... FROM CURRENT, ALTER ROLE ALL IN DATABASE (a
    database owner's statement), ALTER SYSTEM.
    """
    neon_pg.safe_psql_many(
        [
            f"GRANT SET, ALTER SYSTEM ON PARAMETER {MARKER} TO owner",
            "CREATE DATABASE ownerdb OWNER owner",
        ]
    )
    for sql in [
        f"ALTER ROLE bob SET {MARKER} FROM CURRENT",
        f"ALTER ROLE ALL IN DATABASE ownerdb SET {MARKER} = 'personal'",
        f"ALTER ROLE ALL IN DATABASE ownerdb RESET {MARKER}",
        f"ALTER SYSTEM SET {MARKER} = 'personal'",
        f"ALTER SYSTEM RESET {MARKER}",
        "ALTER SYSTEM SET \"Chelabase.Managed_Role\" = 'personal'",
    ]:
        e = refusal(neon_pg, "owner", sql)
        assert e.diag.message_primary == MARKER_DENIED, (sql, e.diag.message_primary)
    assert role_settings(neon_pg, "bob") == []
    assert neon_pg.safe_psql(
        f"SELECT count(*) FROM pg_catalog.pg_db_role_setting WHERE setconfig::text LIKE '%{MARKER}%'"
    ) == [(0,)]
    assert neon_pg.safe_psql(
        f"SELECT count(*) FROM pg_catalog.pg_file_settings WHERE name = '{MARKER}'"
    ) == [(0,)]
    # A database owner's ALTER ROLE ALL IN DATABASE of another setting passes:
    # it writes a database-wide row (setrole = 0), which marks no role.
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("ALTER ROLE ALL IN DATABASE ownerdb SET work_mem = '1MB'")
        cur.execute("ALTER ROLE ALL IN DATABASE ownerdb RESET work_mem")
    # Grants of other parameters are untouched.
    neon_pg.safe_psql("GRANT SET ON PARAMETER work_mem TO owner WITH GRANT OPTION")
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("GRANT SET ON PARAMETER work_mem TO bob")
        cur.execute("REVOKE SET ON PARAMETER work_mem FROM bob")


def test_rows_that_mark_no_role(neon_pg: VanillaPostgres):
    """The marker in a row for every role (ALTER ROLE ALL) marks none of them."""
    neon_pg.safe_psql_many(
        [
            f"ALTER ROLE ALL SET {MARKER} = 'personal'",
            f"ALTER ROLE ALL IN DATABASE postgres SET {MARKER} = 'personal'",
        ]
    )
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("ALTER ROLE bob PASSWORD 'pw'")
        cur.execute("ALTER ROLE bob SET work_mem = '1MB'")
    with neon_pg.cursor(user="bob", password="pw") as cur:
        cur.execute("ALTER ROLE CURRENT_USER RESET ALL")


def test_marker_among_other_settings_and_quoted_names(neon_pg: VanillaPostgres):
    """The marker marks wherever it sits in setconfig; names that need quoting work."""
    name = 'we "ird'
    quoted = '"we ""ird"'
    neon_pg.safe_psql_many(
        [
            f"CREATE ROLE {quoted} LOGIN PASSWORD 'pw'",
            f"ALTER ROLE {quoted} SET work_mem = '1MB'",
            f"ALTER ROLE {quoted} SET search_path = 'x'",
            f"ALTER ROLE {quoted} SET {MARKER} = 'personal'",
            f"GRANT {quoted} TO owner WITH ADMIN OPTION",
        ]
    )
    settings = role_settings(neon_pg, name)
    assert settings[0][1][-1] == f"{MARKER}=personal", settings
    for sql in [
        f"ALTER ROLE {quoted} PASSWORD 'x'",
        f"ALTER ROLE {quoted} RESET work_mem",
        f"GRANT {quoted} TO bob",
        f"DROP ROLE {quoted}",
    ]:
        e = refusal(neon_pg, "owner", sql)
        assert e.diag.message_primary == f'role "{name}" is managed by Chelabase', (
            sql,
            e.diag.message_primary,
        )
    assert role_settings(neon_pg, name) == settings


def test_new_names_keep_postgres_errors(neon_pg: VanillaPostgres):
    """A statement's new role name isn't looked up as marked: Postgres's own error."""
    neon_pg.safe_psql_many(
        [
            "CREATE ROLE alice LOGIN PASSWORD 'pw'",
            f"ALTER ROLE alice SET {MARKER} = 'personal'",
        ]
    )
    for sql in ["CREATE ROLE alice", "ALTER ROLE bob RENAME TO alice"]:
        with pytest.raises(DuplicateObject):
            with neon_pg.cursor(user="owner", password="pw") as cur:
                cur.execute(sql)


def test_rollback_after_a_role_change_in_an_aborted_transaction(neon_pg: VanillaPostgres):
    """
    The guard does no catalog lookup for statements it doesn't guard: a
    ROLLBACK in an aborted transaction (whose role change reset the
    superuser cache) ends cleanly.
    """
    with neon_pg.cursor(user="owner", password="pw", autocommit=False) as cur:
        cur.execute("ALTER ROLE bob CONNECTION LIMIT 3")
        with pytest.raises(DivisionByZero):
            cur.execute("SELECT 1/0")
        cur.connection.rollback()
        cur.execute("SELECT rolconnlimit FROM pg_catalog.pg_roles WHERE rolname = 'bob'")
        assert cur.fetchone() == (-1,)
