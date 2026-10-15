from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from psycopg2.errors import InsufficientPrivilege
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import VanillaPostgres
    from pytest_httpserver import HTTPServer
    from werkzeug.wrappers.request import Request


@pytest.fixture
def patches() -> list[Any]:
    """Every body the control-plane mock received, in order."""
    return []


@pytest.fixture
def neon_pg(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
    patches: list[Any],
):
    (host, port) = httpserver_listen_address
    endpoint = "/test/roles_and_databases"

    def record(request: Request) -> Response:
        patches.append(json.loads(request.get_data(as_text=True)))
        return Response(status=200)

    httpserver.expect_request(endpoint, method="PATCH").respond_with_handler(record)
    vanilla_pg.configure(
        [f"neon.console_url=http://{host}:{port}{endpoint}", "shared_preload_libraries = 'neon'"]
    )
    vanilla_pg.start()
    vanilla_pg.safe_psql("CREATE ROLE neon_superuser NOLOGIN CREATEDB CREATEROLE")
    return vanilla_pg


MEMBER = "cb_m_0123456789abcdef0123456789abcdef"


def setup_roles(pg: VanillaPostgres):
    pg.safe_psql(f"CREATE ROLE {MEMBER} LOGIN PASSWORD 'pw'")
    pg.safe_psql("CREATE ROLE grp NOLOGIN")
    pg.safe_psql("CREATE ROLE chelabase_realtime LOGIN REPLICATION")
    pg.safe_psql("CREATE ROLE owner LOGIN CREATEROLE PASSWORD 'pw' IN ROLE neon_superuser")
    pg.safe_psql("GRANT grp TO owner WITH ADMIN OPTION")
    # Postgres alone would let owner (CREATEROLE + ADMIN) change the member role: the refusals
    # below must come from the hook.
    pg.safe_psql(f"GRANT {MEMBER} TO owner WITH ADMIN OPTION")


def refused(pg: VanillaPostgres, user: str, sql: str, name: str):
    with pytest.raises(InsufficientPrivilege) as e:
        with pg.cursor(user=user, password="pw") as cur:
            cur.execute(sql)
    assert f'member role "{name}" is managed by Chelabase' in str(e.value), sql


AS_OWNER = [
    (f"ALTER ROLE {MEMBER} PASSWORD 'x'", MEMBER),
    (f"ALTER ROLE {MEMBER} SET work_mem = '1MB'", MEMBER),
    (f"ALTER ROLE {MEMBER} IN DATABASE postgres SET work_mem = '1MB'", MEMBER),
    (f"ALTER ROLE {MEMBER} RENAME TO not_a_member", MEMBER),
    (
        "ALTER ROLE grp RENAME TO cb_m_ffffffffffffffffffffffffffffffff",
        "cb_m_ffffffffffffffffffffffffffffffff",
    ),
    (f"DROP ROLE {MEMBER}", MEMBER),
    ("CREATE ROLE cb_m_ffffffffffffffffffffffffffffffff", "cb_m_ffffffffffffffffffffffffffffffff"),
    ('CREATE ROLE "CB_M_X"', "CB_M_X"),
    (f"CREATE ROLE g2 ROLE {MEMBER}", MEMBER),
    (f"CREATE ROLE g3 ADMIN {MEMBER}", MEMBER),
    (f"GRANT grp TO {MEMBER}", MEMBER),
    (f"REVOKE grp FROM {MEMBER}", MEMBER),
    (f"ALTER GROUP grp ADD USER {MEMBER}", MEMBER),
    ("ALTER ROLE chelabase_realtime NOLOGIN", "chelabase_realtime"),
    ("DROP ROLE chelabase_realtime", "chelabase_realtime"),
    ("GRANT grp TO chelabase_realtime", "chelabase_realtime"),
    ("CREATE ROLE chelabase_realtime", "chelabase_realtime"),
    (f"DO $$BEGIN EXECUTE 'ALTER ROLE {MEMBER} PASSWORD ''x'''; END$$", MEMBER),
]
AS_MEMBER = [
    "ALTER ROLE CURRENT_USER PASSWORD 'x'",
    "ALTER ROLE CURRENT_ROLE PASSWORD 'x'",
    "ALTER USER CURRENT_USER PASSWORD 'y'",
    "ALTER ROLE SESSION_USER SET work_mem = '1MB'",
    "ALTER ROLE CURRENT_USER SET role = 'grp'",
]


def test_only_a_superuser_changes_member_roles(neon_pg: VanillaPostgres):
    setup_roles(neon_pg)
    for sql, name in AS_OWNER:
        refused(neon_pg, "owner", sql, name)
    for sql in AS_MEMBER:
        refused(neon_pg, MEMBER, sql, MEMBER)
    # From PL/pgSQL (SPI) too.
    neon_pg.safe_psql(
        "CREATE FUNCTION set_member_pw() RETURNS void LANGUAGE plpgsql AS "
        f"$$BEGIN EXECUTE 'ALTER ROLE {MEMBER} PASSWORD ''z'''; END$$"
    )
    neon_pg.safe_psql("GRANT EXECUTE ON FUNCTION set_member_pw() TO owner")
    refused(neon_pg, "owner", "SELECT set_member_pw()", MEMBER)
    # A superuser may.
    for sql in [
        f"ALTER ROLE {MEMBER} PASSWORD 'pw2'",
        f"ALTER ROLE {MEMBER} SET work_mem = '1MB'",
        f"GRANT grp TO {MEMBER}",
        f"REVOKE grp FROM {MEMBER}",
        "ALTER ROLE chelabase_realtime NOLOGIN",
    ]:
        neon_pg.safe_psql(sql)
    # Ordinary roles are untouched.
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("CREATE ROLE ordinary; ALTER ROLE ordinary PASSWORD 'x'; DROP ROLE ordinary")


# T5 m4: more statement shapes.
MORE_AS_OWNER = [
    (f"CREATE ROLE g4 IN ROLE {MEMBER}", MEMBER),
    (f"CREATE ROLE g5 IN GROUP {MEMBER}", MEMBER),
    ("CREATE ROLE g6 IN ROLE chelabase_realtime", "chelabase_realtime"),
    (f"ALTER GROUP grp DROP USER {MEMBER}", MEMBER),
    (f"ALTER GROUP {MEMBER} ADD USER grp", MEMBER),
    (f"ALTER ROLE {MEMBER} IN DATABASE postgres RESET ALL", MEMBER),
]
MORE_AS_MEMBER = [
    "ALTER ROLE CURRENT_USER IN DATABASE postgres SET work_mem = '1MB'",
    f"ALTER ROLE {MEMBER} IN DATABASE postgres SET work_mem = '1MB'",
    "ALTER ROLE CURRENT_USER IN DATABASE postgres RESET ALL",
    "ALTER USER CURRENT_USER IN DATABASE postgres SET search_path = 'x'",
]


def test_a_refusal_forwards_nothing(neon_pg: VanillaPostgres, patches: list[Any]):
    setup_roles(neon_pg)
    for user, cases in [
        ("owner", AS_OWNER + MORE_AS_OWNER),
        (MEMBER, [(sql, MEMBER) for sql in AS_MEMBER + MORE_AS_MEMBER]),
    ]:
        for sql, name in cases:
            before = len(patches)
            refused(neon_pg, user, sql, name)
            assert len(patches) == before, f"{sql}: forwarded {patches[before:]}"
    # Refused inside a savepoint that is rolled back to: the rest of the
    # transaction is forwarded, nothing of the refused statement.
    before = len(patches)
    with neon_pg.cursor(user="owner", password="pw", autocommit=False) as cur:
        cur.execute("CREATE ROLE kept")
        cur.execute("SAVEPOINT s")
        with pytest.raises(InsufficientPrivilege):
            cur.execute(f"ALTER ROLE {MEMBER} PASSWORD 'x'")
        cur.execute("ROLLBACK TO SAVEPOINT s")
        cur.connection.commit()
    assert len(patches) == before + 1, patches[before:]
    body = patches[-1]
    assert "dbs" not in body, body
    assert [role["name"] for role in body["roles"]] == ["kept"], body
