from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from psycopg2.errors import InsufficientPrivilege
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import VanillaPostgres
    from pytest_httpserver import HTTPServer

MAIN_DB = "maindb"
REFUSAL = f"the branch's main database \"{MAIN_DB}\" can't be dropped"


def assert_refused(cur, query: str):
    with pytest.raises(InsufficientPrivilege) as exc_info:
        cur.execute(query)
    assert exc_info.value.pgcode == "42501"
    assert exc_info.value.diag.message_primary == REFUSAL


def db_connlimit(cur, name: str) -> int | None:
    cur.execute("SELECT datconnlimit FROM pg_database WHERE datname = %s", (name,))
    row = cur.fetchone()
    return None if row is None else row[0]


def test_ddl_protected_database(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
):
    """
    neon.protected_databases lists databases that a non-superuser can't drop,
    and that only a superuser can change.
    """
    (host, port) = httpserver_listen_address
    endpoint = "/test/roles_and_databases"
    # The mock control plane accepts every forwarded change
    httpserver.expect_request(endpoint, method="PATCH").respond_with_handler(
        lambda request: Response(status=200)
    )
    vanilla_pg.configure(
        [
            f"neon.console_url=http://{host}:{port}{endpoint}",
            "shared_preload_libraries = 'neon'",
            f"neon.protected_databases = '{MAIN_DB}'",
        ]
    )
    vanilla_pg.start()

    with vanilla_pg.cursor() as admin:
        # We don't have compute_ctl here, so create neon_superuser manually
        admin.execute("CREATE ROLE neon_superuser NOLOGIN CREATEDB CREATEROLE")
        admin.execute("CREATE ROLE owner LOGIN NOSUPERUSER CREATEDB PASSWORD 'pw'")
        admin.execute(f"CREATE DATABASE {MAIN_DB} OWNER owner")
        admin.execute("CREATE DATABASE other OWNER owner")

        with vanilla_pg.cursor(user="owner", password="pw") as owner:
            assert_refused(owner, f"DROP DATABASE {MAIN_DB}")
            assert_refused(owner, f"DROP DATABASE IF EXISTS {MAIN_DB}")
            assert_refused(owner, f"DROP DATABASE {MAIN_DB} WITH (FORCE)")

            # The database is untouched: valid, and it still accepts connections
            assert db_connlimit(admin, MAIN_DB) != -2
            with vanilla_pg.cursor(user="owner", password="pw", dbname=MAIN_DB) as c:
                c.execute("SELECT 1")

            # Another database drops fine
            owner.execute("DROP DATABASE other")
            assert db_connlimit(admin, "other") is None

            # A non-superuser can't change the setting
            with pytest.raises(InsufficientPrivilege, match="permission denied"):
                owner.execute("SET neon.protected_databases = ''")

        # A superuser bypasses the protection
        admin.execute(f"DROP DATABASE {MAIN_DB}")
        assert db_connlimit(admin, MAIN_DB) is None


def start_with_protected(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    host: str,
    port: int,
    protected: str,
    extra: list[str] | None = None,
):
    endpoint = "/test/roles_and_databases"
    httpserver.expect_request(endpoint, method="PATCH").respond_with_handler(
        lambda request: Response(status=200)
    )
    vanilla_pg.configure(
        [
            f"neon.console_url=http://{host}:{port}{endpoint}",
            "shared_preload_libraries = 'neon'",
            f"neon.protected_databases = '{protected}'",
            *(extra or []),
        ]
    )
    vanilla_pg.start()


def test_ddl_protected_database_forward_ddl_off(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
):
    """The protection is independent of neon.forward_ddl."""
    (host, port) = httpserver_listen_address
    start_with_protected(
        httpserver, vanilla_pg, host, port, MAIN_DB, extra=["neon.forward_ddl = off"]
    )

    with vanilla_pg.cursor() as admin:
        admin.execute("CREATE ROLE neon_superuser NOLOGIN CREATEDB CREATEROLE")
        admin.execute("CREATE ROLE owner LOGIN NOSUPERUSER CREATEDB PASSWORD 'pw'")
        admin.execute(f"CREATE DATABASE {MAIN_DB} OWNER owner")
        admin.execute("SHOW neon.forward_ddl")
        assert admin.fetchone() == ("off",)

        with vanilla_pg.cursor(user="owner", password="pw") as owner:
            assert_refused(owner, f"DROP DATABASE {MAIN_DB}")
            assert_refused(owner, f"DROP DATABASE IF EXISTS {MAIN_DB}")
        assert db_connlimit(admin, MAIN_DB) != -2


def test_ddl_protected_database_list_parsing(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
):
    """
    Names are exact, comma-separated and whitespace-trimmed: several entries
    work, spaces around them are ignored, and a name that is a prefix of a
    protected one (or the other way round) is not protected.
    """
    (host, port) = httpserver_listen_address
    start_with_protected(httpserver, vanilla_pg, host, port, "  alpha ,beta,\tgamma  , , delta")

    protected = ["alpha", "beta", "gamma", "delta"]
    unprotected = ["alp", "alph", "alphabet", "bet", "betaa", "gam", "deltas"]
    with vanilla_pg.cursor() as admin:
        admin.execute("CREATE ROLE neon_superuser NOLOGIN CREATEDB CREATEROLE")
        admin.execute("CREATE ROLE owner LOGIN NOSUPERUSER CREATEDB PASSWORD 'pw'")
        for name in protected + unprotected:
            admin.execute(f"CREATE DATABASE {name} OWNER owner")

        with vanilla_pg.cursor(user="owner", password="pw") as owner:
            for name in protected:
                with pytest.raises(InsufficientPrivilege) as exc_info:
                    owner.execute(f"DROP DATABASE {name}")
                assert exc_info.value.diag.message_primary == (
                    f"the branch's main database \"{name}\" can't be dropped"
                )
                assert db_connlimit(admin, name) is not None
            for name in unprotected:
                owner.execute(f"DROP DATABASE {name}")
                assert db_connlimit(admin, name) is None


def test_a_protected_database_cant_be_renamed(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
):
    """
    R-F3c: renaming would get around the DROP refusal (ALTER DATABASE maindb
    RENAME TO x; DROP DATABASE x), so a non-superuser can't rename a protected
    database, nor rename another database to a protected name. A superuser can.
    """
    (host, port) = httpserver_listen_address
    start_with_protected(httpserver, vanilla_pg, host, port, f"{MAIN_DB},spare")

    with vanilla_pg.cursor() as admin:
        admin.execute("CREATE ROLE neon_superuser NOLOGIN CREATEDB CREATEROLE")
        admin.execute("CREATE ROLE owner LOGIN NOSUPERUSER CREATEDB PASSWORD 'pw'")
        admin.execute(f"CREATE DATABASE {MAIN_DB} OWNER owner")
        admin.execute("CREATE DATABASE other OWNER owner")

        with vanilla_pg.cursor(user="owner", password="pw") as owner:
            for sql in [
                f"ALTER DATABASE {MAIN_DB} RENAME TO renamed",
                "ALTER DATABASE other RENAME TO spare",
                f"DO $$BEGIN EXECUTE 'ALTER DATABASE {MAIN_DB} RENAME TO renamed'; END$$",
            ]:
                with pytest.raises(InsufficientPrivilege) as exc_info:
                    owner.execute(sql)
                assert exc_info.value.pgcode == "42501", sql
            for name in [MAIN_DB, "other"]:
                assert db_connlimit(admin, name) is not None, name
            for name in ["renamed", "spare"]:
                assert db_connlimit(admin, name) is None, name
            # An unprotected database renames to an unprotected name.
            owner.execute("ALTER DATABASE other RENAME TO other2")
            assert db_connlimit(admin, "other2") is not None

        # A superuser can, both ways.
        admin.execute(f"ALTER DATABASE {MAIN_DB} RENAME TO renamed")
        admin.execute("ALTER DATABASE other2 RENAME TO spare")
        admin.execute(f"ALTER DATABASE renamed RENAME TO {MAIN_DB}")
        assert db_connlimit(admin, MAIN_DB) is not None
        assert db_connlimit(admin, "spare") is not None
