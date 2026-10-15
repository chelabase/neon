from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from psycopg2.errors import InsufficientPrivilege
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import VanillaPostgres
    from pytest_httpserver import HTTPServer


@pytest.fixture
def neon_pg(
    httpserver: HTTPServer, vanilla_pg: VanillaPostgres, httpserver_listen_address: ListenAddress
):
    (host, port) = httpserver_listen_address
    endpoint = "/test/roles_and_databases"
    httpserver.expect_request(endpoint, method="PATCH").respond_with_handler(
        lambda request: Response(status=200)
    )
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
