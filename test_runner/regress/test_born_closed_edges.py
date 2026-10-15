from __future__ import annotations

import os
from typing import TYPE_CHECKING

import psycopg2
import pytest
from fixtures.utils import wait_until
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import VanillaPostgres
    from pytest_httpserver import HTTPServer

REFUSAL = "on a protected branch, ALLOW_CONNECTIONS and IS_TEMPLATE are set by Chelabase"


@pytest.fixture
def neon_pg(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
):
    (host, port) = httpserver_listen_address
    endpoint = "/test/roles_and_databases"
    httpserver.expect_request(endpoint, method="PATCH").respond_with_handler(
        lambda request: Response(status=200)
    )
    vanilla_pg.configure(
        [
            f"neon.console_url=http://{host}:{port}{endpoint}",
            "shared_preload_libraries = 'neon'",
            "neon.branch_protected = off",
        ]
    )
    vanilla_pg.start()
    vanilla_pg.safe_psql("CREATE ROLE neon_superuser NOLOGIN CREATEDB CREATEROLE")
    vanilla_pg.safe_psql("CREATE ROLE owner LOGIN CREATEDB PASSWORD 'pw' IN ROLE neon_superuser")
    return vanilla_pg


def set_flag(pg: VanillaPostgres, on: bool):
    """As compute_ctl does on a reconfigure: rewrite postgresql.conf, then reload."""
    with open(os.path.join(pg.pgdatadir, "postgresql.conf"), "a") as conf:
        conf.write(f"neon.branch_protected = {'on' if on else 'off'}\n")
    pg.safe_psql("SELECT pg_reload_conf()")


def state(pg: VanillaPostgres, db: str) -> tuple[bool, bool]:
    rows = pg.safe_psql(
        "SELECT d.datallowconn, coalesce('neon.born_closed=on' = ANY (s.setconfig), false)"
        " FROM pg_database d LEFT JOIN pg_db_role_setting s"
        " ON s.setdatabase = d.oid AND s.setrole = 0"
        f" WHERE d.datname = '{db}'"
    )
    return bool(rows[0][0]), bool(rows[0][1])


def test_the_branch_flag_follows_a_reload_in_an_open_session(neon_pg: VanillaPostgres):
    """compute_ctl turns the flag on and off with a reload: a session opened
    before the change follows it at its next statement."""
    with neon_pg.cursor(user="owner", password="pw") as cur:

        def flag_is(value: str):
            cur.execute("SHOW neon.branch_protected")
            assert cur.fetchone() == (value,)

        cur.execute("CREATE DATABASE before_on")
        assert state(neon_pg, "before_on") == (True, False)

        set_flag(neon_pg, True)
        wait_until(lambda: flag_is("on"))
        cur.execute("CREATE DATABASE while_on")
        assert state(neon_pg, "while_on") == (False, True)
        with pytest.raises(psycopg2.Error) as e:
            cur.execute("ALTER DATABASE before_on ALLOW_CONNECTIONS false")
        assert REFUSAL in str(e.value)

        set_flag(neon_pg, False)
        wait_until(lambda: flag_is("off"))
        cur.execute("CREATE DATABASE after_off")
        assert state(neon_pg, "after_off") == (True, False)
        cur.execute("ALTER DATABASE before_on ALLOW_CONNECTIONS false")
        assert state(neon_pg, "before_on") == (False, False)
        # The marker outlives the flag: a born-closed database stays closed.
        with pytest.raises(psycopg2.Error) as e:
            cur.execute("ALTER DATABASE while_on ALLOW_CONNECTIONS true")
        assert REFUSAL in str(e.value)


def test_a_renamed_born_closed_database_stays_closed(neon_pg: VanillaPostgres):
    """The marker belongs to the database (its OID), not its name; other
    CREATE DATABASE options don't open it either."""
    set_flag(neon_pg, True)
    wait_until(lambda: neon_pg.safe_psql("SHOW neon.branch_protected") == [("on",)])
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("CREATE DATABASE bc1 WITH STRATEGY file_copy CONNECTION LIMIT 3")
        cur.execute("CREATE DATABASE bc2 WITH TEMPLATE template0 ENCODING 'UTF8'")
    assert state(neon_pg, "bc1") == (False, True)
    assert state(neon_pg, "bc2") == (False, True)
    set_flag(neon_pg, False)
    wait_until(lambda: neon_pg.safe_psql("SHOW neon.branch_protected") == [("off",)])
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("ALTER DATABASE bc1 RENAME TO bc1_renamed")
        with pytest.raises(psycopg2.Error) as e:
            cur.execute("ALTER DATABASE bc1_renamed ALLOW_CONNECTIONS true")
        assert REFUSAL in str(e.value)
    assert state(neon_pg, "bc1_renamed") == (False, True)
