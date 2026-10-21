"""
F3 (K6): the role guard beside test_member_role_guard.py.

- H1 (user ruling 2026-10-21): COMMENT ON ROLE and SECURITY LABEL ON ROLE on a marked role
  (chelabase.managed_role) or a managed one (cb_m_*, chelabase_realtime) are refused to a
  non-superuser with 42501 and the guard's usual messages, on every major (PG14/15 let a
  CREATEROLE role do both; PG16+ lets a CREATEROLE role with ADMIN OPTION do both; with
  `anon` a label changes masking). An unmarked role and a superuser are unaffected.
- H3: the guard's two statement lists in CheckManagedRoleStatement (the early return before
  `superuser()` and the checks after it) name the same statements, and a statement that
  reaches the second switch without a case fails loudly in an assert build (`Assert(false)`
  as its `default`), not silently.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

import psycopg2
import pytest
from fixtures.paths import BASE_DIR
from psycopg2.errors import InsufficientPrivilege
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import VanillaPostgres
    from pytest_httpserver import HTTPServer
    from werkzeug.wrappers.request import Request

MARKER = "chelabase.managed_role"
MEMBER = "cb_m_0123456789abcdef0123456789abcdef"
REALTIME = "chelabase_realtime"
NO_PROVIDER = "no security label providers have been loaded"


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
            "CREATE ROLE alice LOGIN PASSWORD 'pw'",
            f"ALTER ROLE alice SET {MARKER} = 'personal'",
            # Same name but for the case: a different, unmarked role.
            "CREATE ROLE \"Alice\" LOGIN PASSWORD 'pw'",
            "CREATE ROLE bob LOGIN PASSWORD 'pw'",
            f"CREATE ROLE {MEMBER} LOGIN PASSWORD 'pw'",
            f"CREATE ROLE {REALTIME} LOGIN REPLICATION",
        ]
        # Postgres alone lets owner (CREATEROLE, plus ADMIN on PG16+) comment on and label
        # every one of them: the refusals below must come from the hook.
        + [
            f"GRANT {r} TO owner WITH ADMIN OPTION"
            for r in ["alice", '"Alice"', "bob", MEMBER, REALTIME]
        ]
    )
    return vanilla_pg


def run_as(pg: VanillaPostgres, user: str | None, sql: str):
    login: dict[str, Any] = {} if user is None else {"user": user, "password": "pw"}
    with pg.cursor(**login) as cur:
        cur.execute(sql)


def refusal(pg: VanillaPostgres, user: str, sql: str) -> InsufficientPrivilege:
    try:
        run_as(pg, user, sql)
    except InsufficientPrivilege as e:
        return e
    except Exception as e:
        pytest.fail(f"{sql!r} as {user}: {type(e).__name__} ({e}); the role guard must refuse it")
    pytest.fail(f"{sql!r} as {user} succeeded; the role guard must refuse it")


def comment(pg: VanillaPostgres, role: str) -> str | None:
    rows = pg.safe_psql(
        "SELECT pg_catalog.shobj_description(oid, 'pg_authid') FROM pg_catalog.pg_roles"
        f" WHERE rolname = '{role}'"
    )
    assert len(rows) == 1, rows
    value = rows[0][0]
    return None if value is None else str(value)


def labels(pg: VanillaPostgres) -> int:
    return int(
        pg.safe_psql(
            "SELECT count(*) FROM pg_catalog.pg_shseclabel WHERE classoid = 'pg_authid'::regclass"
        )[0][0]
    )


# (statement, the role named in the guard's message, whether it is managed by name)
ON_GUARDED = [
    ("COMMENT ON ROLE alice IS 'x'", "alice", False),
    ("COMMENT ON ROLE alice IS NULL", "alice", False),
    (f"COMMENT ON ROLE {MEMBER} IS 'x'", MEMBER, True),
    (f"COMMENT ON ROLE {REALTIME} IS 'x'", REALTIME, True),
    ("SECURITY LABEL ON ROLE alice IS 'MASKED'", "alice", False),
    ("SECURITY LABEL FOR anon ON ROLE alice IS 'MASKED'", "alice", False),
    ("SECURITY LABEL ON ROLE alice IS NULL", "alice", False),
    (f"SECURITY LABEL ON ROLE {MEMBER} IS 'MASKED'", MEMBER, True),
    (f"SECURITY LABEL FOR anon ON ROLE {REALTIME} IS 'MASKED'", REALTIME, True),
    ("DO $$BEGIN EXECUTE 'COMMENT ON ROLE alice IS ''x'''; END$$", "alice", False),
    (
        f"DO $$BEGIN EXECUTE 'SECURITY LABEL ON ROLE {MEMBER} IS ''MASKED'''; END$$",
        MEMBER,
        True,
    ),
]


def test_comments_and_labels_on_guarded_roles_are_refused(neon_pg: VanillaPostgres):
    neon_pg.safe_psql("COMMENT ON ROLE alice IS 'set by a superuser'")
    before = labels(neon_pg)
    for sql, name, by_name in ON_GUARDED:
        e = refusal(neon_pg, "owner", sql)
        expected = (
            f'member role "{name}" is managed by Chelabase'
            if by_name
            else f'role "{name}" is managed by Chelabase'
        )
        assert e.diag.message_primary == expected, (sql, e.diag.message_primary)
    assert comment(neon_pg, "alice") == "set by a superuser"
    assert comment(neon_pg, MEMBER) is None
    assert comment(neon_pg, REALTIME) is None
    assert labels(neon_pg) == before

    # From a SECURITY DEFINER function owned by owner, called by a superuser.
    neon_pg.safe_psql_many(
        [
            "CREATE FUNCTION definer_comment_alice() RETURNS void LANGUAGE plpgsql "
            "SECURITY DEFINER AS $$BEGIN EXECUTE 'COMMENT ON ROLE alice IS ''y'''; END$$",
            "ALTER FUNCTION definer_comment_alice() OWNER TO owner",
        ]
    )
    e = refusal_as_superuser(neon_pg, "SELECT definer_comment_alice()")
    assert e.diag.message_primary == 'role "alice" is managed by Chelabase'
    assert comment(neon_pg, "alice") == "set by a superuser"


def refusal_as_superuser(pg: VanillaPostgres, sql: str) -> InsufficientPrivilege:
    try:
        run_as(pg, None, sql)
    except InsufficientPrivilege as e:
        return e
    pytest.fail(f"{sql!r} succeeded; the role guard must refuse it")


def label_error(pg: VanillaPostgres, user: str | None, sql: str) -> psycopg2.Error:
    """SECURITY LABEL with no label provider loaded: Postgres' own error, never the guard's."""
    try:
        run_as(pg, user, sql)
    except InsufficientPrivilege as e:
        pytest.fail(f"{sql!r} as {user or 'the superuser'} refused by the guard: {e}")
    except psycopg2.Error as e:
        assert NO_PROVIDER in str(e), (sql, str(e))
        return e
    pytest.fail(f"{sql!r} succeeded without a label provider")


def test_comments_and_labels_elsewhere_are_unaffected(neon_pg: VanillaPostgres):
    # An unmarked role, as owner.
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("COMMENT ON ROLE bob IS 'bob'")
        cur.execute("COMMENT ON ROLE \"Alice\" IS 'other alice'")
        cur.execute("COMMENT ON ROLE bob IS NULL")
    assert comment(neon_pg, "bob") is None
    assert comment(neon_pg, "Alice") == "other alice"
    label_error(neon_pg, "owner", "SECURITY LABEL ON ROLE bob IS 'MASKED'")

    # A superuser, on every guarded role.
    for role in ["alice", MEMBER, REALTIME]:
        neon_pg.safe_psql(f"COMMENT ON ROLE {role} IS 'by a superuser'")
        assert comment(neon_pg, role) == "by a superuser"
        label_error(neon_pg, None, f"SECURITY LABEL ON ROLE {role} IS 'MASKED'")

    # Comments on other objects, as owner, are not the guard's business.
    # (PG15+: owner can't create a schema in the database, so a superuser makes it owner's.)
    neon_pg.safe_psql("CREATE SCHEMA owned AUTHORIZATION owner")
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("COMMENT ON SCHEMA owned IS 'mine'")


GUARD_SOURCE = BASE_DIR / "pgxn" / "neon" / "neon_ddl_handler.c"


def guard_body() -> str:
    text = GUARD_SOURCE.read_text()
    m = re.search(r"\nCheckManagedRoleStatement\(Node \*parseTree\)\n\{\n(.*?)\n\}\n", text, re.S)
    assert m is not None, "CheckManagedRoleStatement not found in neon_ddl_handler.c"
    return m.group(1)


def test_guard_statement_lists_agree():
    """
    The statements the early return lets through are exactly those the second switch
    checks (COMMENT and SECURITY LABEL among them, H1), and the second switch's default is
    an Assert(false): a statement let through without a check fails loudly in an assert
    build.
    """
    body = guard_body()
    early, sep, checks = body.partition("if (superuser())")
    assert sep, "no superuser() check between the two switches"
    early_cases = set(re.findall(r"case (T_\w+):", early))
    check_cases = set(re.findall(r"case (T_\w+):", checks))
    assert early_cases, "no statements in the early-return list"
    assert early_cases == check_cases, (
        f"only in the early-return list: {sorted(early_cases - check_cases)}; "
        f"only in the checks: {sorted(check_cases - early_cases)}"
    )
    assert {"T_CommentStmt", "T_SecLabelStmt"} <= early_cases, sorted(early_cases)
    default = re.search(r"default:\s*\n\s*([^\n]*)", checks)
    assert default is not None, "the second switch has no default"
    assert default.group(1).strip() == "Assert(false);", (
        f"the second switch's default is {default.group(1).strip()!r}, not Assert(false)"
    )
