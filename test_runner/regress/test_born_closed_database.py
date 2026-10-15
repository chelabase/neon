from __future__ import annotations

from typing import TYPE_CHECKING

import psycopg2
import pytest
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


GUARD = (
    "CREATE FUNCTION guard_fn() RETURNS event_trigger LANGUAGE plpgsql AS $$BEGIN END$$;"
    "CREATE EVENT TRIGGER chelabase_schema_guard_ddl ON ddl_command_end EXECUTE FUNCTION guard_fn();"
    "ALTER EVENT TRIGGER chelabase_schema_guard_ddl ENABLE ALWAYS;"
)
REFUSAL = "on a protected branch, ALLOW_CONNECTIONS and IS_TEMPLATE are set by Chelabase"


def as_owner(pg: VanillaPostgres, sql: str, dbname: str = "postgres"):
    with pg.cursor(user="owner", password="pw", dbname=dbname) as cur:
        cur.execute(sql)


def owner_refused(pg: VanillaPostgres, sql: str, needle: str = REFUSAL, dbname: str = "postgres"):
    with pytest.raises(psycopg2.Error) as e:
        as_owner(pg, sql, dbname)
    assert needle in str(e.value), (sql, str(e.value))


def state(pg: VanillaPostgres, db: str) -> tuple[bool, list[str] | None]:
    allow = pg.safe_psql(f"SELECT datallowconn FROM pg_database WHERE datname = '{db}'")[0][0]
    marker = pg.safe_psql(
        "SELECT s.setconfig FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase "
        f"WHERE d.datname = '{db}' AND s.setrole = 0"
    )
    return allow, (marker[0][0] if marker else None)


def setup_owner(pg: VanillaPostgres):
    pg.safe_psql("CREATE ROLE owner LOGIN CREATEDB PASSWORD 'pw' IN ROLE neon_superuser")


def test_born_closed_on_a_guarded_database(neon_pg: VanillaPostgres):
    setup_owner(neon_pg)
    neon_pg.safe_psql(GUARD)
    as_owner(neon_pg, "CREATE DATABASE b1 TEMPLATE template0")
    as_owner(neon_pg, "CREATE DATABASE b2")
    for db in ["b1", "b2"]:
        assert state(neon_pg, db) == (False, ["neon.born_closed=on"]), db
    for sql in [
        "CREATE DATABASE b3 WITH ALLOW_CONNECTIONS true",
        "CREATE DATABASE b4 WITH ALLOW_CONNECTIONS false",
        "CREATE DATABASE b5 WITH IS_TEMPLATE true",
        "ALTER DATABASE b1 ALLOW_CONNECTIONS true",
        "ALTER DATABASE b1 IS_TEMPLATE true",
    ]:
        owner_refused(neon_pg, sql)
    owner_refused(neon_pg, "ALTER DATABASE b1 RESET neon.born_closed", "permission denied")
    as_owner(neon_pg, "ALTER DATABASE b1 RESET ALL")
    assert state(neon_pg, "b1") == (False, ["neon.born_closed=on"]), "RESET ALL keeps the marker"
    assert not neon_pg.safe_psql(
        "SELECT has_table_privilege('owner', 'pg_catalog.pg_database', 'UPDATE')"
    )[0][0]
    owner_refused(
        neon_pg,
        "UPDATE pg_catalog.pg_database SET datallowconn = true WHERE datname = 'b1'",
        "permission denied",
    )
    # A superuser is untouched.
    neon_pg.safe_psql("CREATE DATABASE s1")
    assert state(neon_pg, "s1") == (True, None)
    neon_pg.safe_psql("ALTER DATABASE b2 ALLOW_CONNECTIONS true")
    assert state(neon_pg, "b2")[0] is True


def test_the_targets_marker_decides_from_an_unguarded_database(neon_pg: VanillaPostgres):
    setup_owner(neon_pg)
    neon_pg.safe_psql(GUARD)
    as_owner(neon_pg, "CREATE DATABASE b1")
    neon_pg.safe_psql("CREATE DATABASE plain")
    neon_pg.safe_psql("GRANT CONNECT ON DATABASE plain TO owner")
    for sql in ["ALTER DATABASE b1 ALLOW_CONNECTIONS true", "ALTER DATABASE b1 IS_TEMPLATE true"]:
        owner_refused(neon_pg, sql, dbname="plain")
    # U2: an unmarked closed database is the owner's to reopen only outside a guarded session.
    neon_pg.safe_psql("CREATE DATABASE shut OWNER owner")
    neon_pg.safe_psql("ALTER DATABASE shut ALLOW_CONNECTIONS false")
    owner_refused(neon_pg, "ALTER DATABASE shut ALLOW_CONNECTIONS true")
    as_owner(neon_pg, "ALTER DATABASE shut ALLOW_CONNECTIONS true", dbname="plain")
    assert state(neon_pg, "shut") == (True, None)


def test_no_guard_no_change(neon_pg: VanillaPostgres):
    setup_owner(neon_pg)
    # Not ENABLE ALWAYS: not the guard.
    neon_pg.safe_psql(
        "CREATE FUNCTION g0() RETURNS event_trigger LANGUAGE plpgsql AS $$BEGIN END$$;"
        "CREATE EVENT TRIGGER chelabase_schema_guard_ddl ON ddl_command_end EXECUTE FUNCTION g0();"
    )
    as_owner(neon_pg, "CREATE DATABASE n1")
    assert state(neon_pg, "n1") == (True, None)
    neon_pg.safe_psql("DROP EVENT TRIGGER chelabase_schema_guard_ddl")
    # Owned by a non-superuser: not the guard. (PG15+: public has no CREATE for ordinary roles.)
    neon_pg.safe_psql("GRANT CREATE ON SCHEMA public TO owner")
    as_owner(
        neon_pg,
        "CREATE FUNCTION g1() RETURNS event_trigger LANGUAGE plpgsql AS $$BEGIN END$$;"
        "CREATE EVENT TRIGGER chelabase_schema_guard_ddl ON ddl_command_end EXECUTE FUNCTION g1();"
        "ALTER EVENT TRIGGER chelabase_schema_guard_ddl ENABLE ALWAYS;",
    )
    as_owner(neon_pg, "CREATE DATABASE n2")
    assert state(neon_pg, "n2") == (True, None)
    as_owner(neon_pg, "ALTER DATABASE n2 ALLOW_CONNECTIONS false")
    as_owner(neon_pg, "ALTER DATABASE n2 ALLOW_CONNECTIONS true")
