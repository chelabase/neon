from __future__ import annotations

from typing import TYPE_CHECKING

import psycopg2
import pytest
from fixtures.log_helper import log
from psycopg2.errors import ObjectNotInPrerequisiteState, UndefinedObject
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Any, Self

    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import NeonEnv, VanillaPostgres
    from pytest_httpserver import HTTPServer
    from werkzeug.wrappers.request import Request


def handle_db(dbs, roles, operation):
    if operation["op"] == "set":
        if "old_name" in operation and operation["old_name"] in dbs:
            dbs[operation["name"]] = dbs[operation["old_name"]]
            dbs.pop(operation["old_name"])
        if "owner" in operation:
            dbs[operation["name"]] = operation["owner"]
    elif operation["op"] == "del":
        dbs.pop(operation["name"])
    else:
        raise ValueError("Invalid op")


def handle_role(dbs, roles, operation):
    if operation["op"] == "set":
        if "old_name" in operation and operation["old_name"] in roles:
            roles[operation["name"]] = roles[operation["old_name"]]
            roles.pop(operation["old_name"])
            for db, owner in dbs.items():
                if owner == operation["old_name"]:
                    dbs[db] = operation["name"]
        if operation.get("password") is not None:
            roles[operation["name"]] = operation["password"]
            assert "encrypted_password" in operation
        elif "password" in operation:
            # An explicit null (PASSWORD NULL, or a CREATE without a password) drops the copy
            roles.pop(operation["name"], None)
    elif operation["op"] == "del":
        if "old_name" in operation:
            roles.pop(operation["old_name"])
        roles.pop(operation["name"])
    else:
        raise ValueError("Invalid op")


def ddl_forward_handler(
    request: Request, dbs: dict[str, str], roles: dict[str, str], ddl: DdlForwardingContext
) -> Response:
    log.info(f"Received request with data {request.get_data(as_text=True)}")
    if ddl.fail:
        log.info("FAILING")
        return Response(status=500, response="Failed just cuz")
    if request.json is None:
        log.info("Received invalid JSON")
        return Response(status=400)
    json: dict[str, list[str]] = request.json
    # Handle roles first
    for operation in json.get("roles", []):
        handle_role(dbs, roles, operation)
    for operation in json.get("dbs", []):
        handle_db(dbs, roles, operation)
    return Response(status=200)


class DdlForwardingContext:
    def __init__(self, httpserver: HTTPServer, vanilla_pg: VanillaPostgres, host: str, port: int):
        self.server = httpserver
        self.pg = vanilla_pg
        self.host = host
        self.port = port
        self.dbs: dict[str, str] = {}
        self.roles: dict[str, str] = {}
        self.fail = False
        endpoint = "/test/roles_and_databases"
        ddl_url = f"http://{host}:{port}{endpoint}"
        self.pg.configure(
            [
                f"neon.console_url={ddl_url}",
                "shared_preload_libraries = 'neon'",
            ]
        )
        log.info(f"Listening on {ddl_url}")
        self.server.expect_request(endpoint, method="PATCH").respond_with_handler(
            lambda request: ddl_forward_handler(request, self.dbs, self.roles, self)
        )

    def __enter__(self) -> Self:
        self.pg.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ):
        self.pg.stop()

    def send(self, query: str) -> list[tuple[Any, ...]]:
        return self.pg.safe_psql(query)

    def wait(self, timeout=3):
        self.server.wait(timeout=timeout)

    def failures(self, bool):
        self.fail = bool

    def send_and_wait(self, query: str, timeout=3) -> list[tuple[Any, ...]]:
        res = self.send(query)
        self.wait(timeout=timeout)
        return res


@pytest.fixture(scope="function")
def ddl(
    httpserver: HTTPServer, vanilla_pg: VanillaPostgres, httpserver_listen_address: ListenAddress
):
    (host, port) = httpserver_listen_address
    with DdlForwardingContext(httpserver, vanilla_pg, host, port) as ddl:
        yield ddl


def test_ddl_forwarding(ddl: DdlForwardingContext):
    curr_user = ddl.send("SELECT current_user")[0][0]
    log.info(f"Current user is {curr_user}")
    ddl.send_and_wait("CREATE DATABASE bork")
    assert ddl.dbs == {"bork": curr_user}
    ddl.send_and_wait("CREATE ROLE volk WITH PASSWORD 'nu_zayats'")
    ddl.send_and_wait("ALTER DATABASE bork RENAME TO nu_pogodi")
    assert ddl.dbs == {"nu_pogodi": curr_user}
    ddl.send_and_wait("ALTER DATABASE nu_pogodi OWNER TO volk")
    assert ddl.dbs == {"nu_pogodi": "volk"}
    ddl.send_and_wait("DROP DATABASE nu_pogodi")
    assert ddl.dbs == {}
    ddl.send_and_wait("DROP ROLE volk")
    assert ddl.roles == {}

    ddl.send_and_wait("CREATE ROLE tarzan WITH PASSWORD 'of_the_apes'")
    assert ddl.roles == {"tarzan": "of_the_apes"}
    ddl.send_and_wait("DROP ROLE tarzan")
    assert ddl.roles == {}
    ddl.send_and_wait("CREATE ROLE tarzan WITH PASSWORD 'of_the_apes'")
    assert ddl.roles == {"tarzan": "of_the_apes"}
    ddl.send_and_wait("ALTER ROLE tarzan WITH PASSWORD 'jungle_man'")
    assert ddl.roles == {"tarzan": "jungle_man"}
    ddl.send_and_wait("ALTER ROLE tarzan RENAME TO mowgli")
    assert ddl.roles == {"mowgli": "jungle_man"}
    ddl.send_and_wait("DROP ROLE mowgli")
    assert ddl.roles == {}

    conn = ddl.pg.connect()
    cur = conn.cursor()

    cur.execute("BEGIN")
    cur.execute("CREATE ROLE bork WITH PASSWORD 'cork'")
    cur.execute("COMMIT")
    ddl.wait()
    assert ddl.roles == {"bork": "cork"}
    cur.execute("BEGIN")
    cur.execute("CREATE ROLE stork WITH PASSWORD 'pork'")
    cur.execute("ABORT")
    ddl.wait()
    assert ("stork", "pork") not in ddl.roles.items()
    cur.execute("BEGIN")
    cur.execute("ALTER ROLE bork WITH PASSWORD 'pork'")
    cur.execute("ALTER ROLE bork RENAME TO stork")
    cur.execute("COMMIT")
    ddl.wait()
    assert ddl.roles == {"stork": "pork"}
    cur.execute("BEGIN")
    cur.execute("CREATE ROLE dork WITH PASSWORD 'york'")
    cur.execute("SAVEPOINT point")
    cur.execute("ALTER ROLE dork WITH PASSWORD 'zork'")
    cur.execute("ALTER ROLE dork RENAME TO fork")
    cur.execute("ROLLBACK TO SAVEPOINT point")
    cur.execute("ALTER ROLE dork WITH PASSWORD 'fork'")
    cur.execute("ALTER ROLE dork RENAME TO zork")
    cur.execute("RELEASE SAVEPOINT point")
    cur.execute("COMMIT")
    ddl.wait()
    assert ddl.roles == {"stork": "pork", "zork": "fork"}

    cur.execute("DROP ROLE stork")
    cur.execute("DROP ROLE zork")
    ddl.wait()
    assert ddl.roles == {}

    cur.execute("CREATE ROLE bork WITH PASSWORD 'dork'")
    cur.execute("CREATE ROLE stork WITH PASSWORD 'cork'")
    cur.execute("BEGIN")
    cur.execute("DROP ROLE bork")
    cur.execute("ALTER ROLE stork RENAME TO bork")
    cur.execute("COMMIT")
    ddl.wait()
    assert ddl.roles == {"bork": "cork"}

    cur.execute("DROP ROLE bork")
    ddl.wait()
    assert ddl.roles == {}

    cur.execute("CREATE ROLE bork WITH PASSWORD 'newyork'")
    cur.execute("BEGIN")
    cur.execute("SAVEPOINT point")
    cur.execute("DROP ROLE bork")
    cur.execute("COMMIT")
    ddl.wait()
    assert ddl.roles == {}

    cur.execute("CREATE ROLE bork WITH PASSWORD 'oldyork'")
    cur.execute("BEGIN")
    cur.execute("SAVEPOINT point")
    cur.execute("ALTER ROLE bork PASSWORD NULL")
    cur.execute("COMMIT")
    cur.execute("DROP ROLE bork")
    ddl.wait()
    assert ddl.roles == {}

    cur.execute("CREATE ROLE bork WITH PASSWORD 'dork'")
    cur.execute("CREATE DATABASE stork WITH OWNER=bork")
    cur.execute("ALTER ROLE bork RENAME TO cork")
    ddl.wait()
    assert ddl.dbs == {"stork": "cork"}

    cur.execute("DROP DATABASE stork")
    ddl.wait()
    assert ddl.dbs == {}

    with pytest.raises(psycopg2.InternalError):
        ddl.failures(True)
        cur.execute("CREATE DATABASE failure WITH OWNER=cork")
        ddl.wait()

    ddl.failures(False)
    cur.execute("CREATE DATABASE failure WITH OWNER=cork")
    ddl.wait()
    with pytest.raises(psycopg2.InternalError):
        ddl.failures(True)
        cur.execute("DROP DATABASE failure")
        ddl.wait()
    assert ddl.dbs == {"failure": "cork"}
    ddl.failures(False)

    # Check that db is still in the Postgres after failure
    cur.execute("SELECT datconnlimit FROM pg_database WHERE datname = 'failure'")
    result = cur.fetchone()
    if not result:
        raise AssertionError("Database 'failure' not found")
    # -2 means invalid database
    # It should be invalid because cplane request failed
    assert result[0] == -2, "Database 'failure' is not invalid"

    # Check that repeated drop succeeds
    cur.execute("DROP DATABASE failure")
    ddl.wait()
    assert ddl.dbs == {}

    # DB should be absent in the Postgres
    cur.execute("SELECT count(*) FROM pg_database WHERE datname = 'failure'")
    result = cur.fetchone()
    if not result:
        raise AssertionError("Could not count databases")
    assert result[0] == 0, "Database 'failure' still exists after drop"

    # We don't have compute_ctl, so here, so create neon_superuser here manually
    cur.execute("CREATE ROLE neon_superuser NOLOGIN CREATEDB CREATEROLE")

    # Contrary to popular belief, being superman does not make you superuser
    cur.execute("CREATE ROLE superman LOGIN NOSUPERUSER PASSWORD 'jungle_man'")

    with ddl.pg.cursor(user="superman", password="jungle_man") as superman_cur:
        # We allow real SUPERUSERs to ALTER neon_superuser
        with pytest.raises(psycopg2.InternalError):
            superman_cur.execute("ALTER ROLE neon_superuser LOGIN")

    cur.execute("ALTER ROLE neon_superuser LOGIN")

    with pytest.raises(psycopg2.InternalError):
        cur.execute("CREATE DATABASE trololobus WITH OWNER neon_superuser")

    cur.execute("CREATE DATABASE trololobus")
    with pytest.raises(psycopg2.InternalError):
        cur.execute("ALTER DATABASE trololobus OWNER TO neon_superuser")

    conn.close()


SCRAM = "<scram-sha-256 hash>"
# A role dropped and created again in one transaction
RECREATED = {"touched": True, "recreated": True}


class RoleBodies:
    """Captures the role lists of the PATCH bodies the compute sends."""

    def __init__(self, httpserver: HTTPServer, vanilla_pg: VanillaPostgres, host: str, port: int):
        endpoint = "/test/roles_and_databases"
        self.pg = vanilla_pg
        self.received: list[Any] = []
        httpserver.expect_request(endpoint, method="PATCH").respond_with_handler(self.handler)
        self.pg.configure(
            [
                f"neon.console_url=http://{host}:{port}{endpoint}",
                "shared_preload_libraries = 'neon'",
                "max_prepared_transactions = 2",
            ]
        )

    def handler(self, request: Request) -> Response:
        # The hash has a random salt: check its shape and replace it
        body: Any = request.json
        for role in body.get("roles", []):
            if "encrypted_password" in role:
                assert role["encrypted_password"].startswith("SCRAM-SHA-256$")
                role["encrypted_password"] = SCRAM
        self.received.append(body)
        return Response(status=200)

    def setup(self, query: str):
        """Runs `query` without forwarding."""
        self.pg.safe_psql(f"SET neon.forward_ddl = false; {query}")

    def roles_of(self, statements: list[str]) -> list[dict[str, Any]]:
        """Runs `statements` in one transaction; returns the one body's roles, sorted by name."""
        self.received.clear()
        with self.pg.cursor() as cur:
            cur.execute("BEGIN")
            for stmt in statements:
                cur.execute(stmt)
            cur.execute("COMMIT")
        assert len(self.received) == 1, self.received
        return sorted(self.received[0].get("roles", []), key=lambda r: r["name"])

    def dbs_of(self, statements: list[str]) -> list[dict[str, Any]]:
        """Like roles_of, for the body's databases."""
        self.received.clear()
        with self.pg.cursor() as cur:
            cur.execute("BEGIN")
            for stmt in statements:
                cur.execute(stmt)
            cur.execute("COMMIT")
        assert len(self.received) == 1, self.received
        return sorted(self.received[0].get("dbs", []), key=lambda d: d["name"])


@pytest.fixture(scope="function")
def role_bodies(
    httpserver: HTTPServer, vanilla_pg: VanillaPostgres, httpserver_listen_address: ListenAddress
):
    (host, port) = httpserver_listen_address
    bodies = RoleBodies(httpserver, vanilla_pg, host, port)
    vanilla_pg.start()
    bodies.setup("CREATE ROLE app LOGIN PASSWORD 'x'; CREATE ROLE grp")
    yield bodies
    vanilla_pg.stop()


def test_alter_role_nologin_forwards_login_false(role_bodies: RoleBodies):
    assert role_bodies.roles_of(["ALTER ROLE app NOLOGIN"]) == [
        {"op": "set", "name": "app", "login": False}
    ]
    assert role_bodies.roles_of(["ALTER ROLE app LOGIN"]) == [
        {"op": "set", "name": "app", "login": True}
    ]
    # The last statement wins
    assert role_bodies.roles_of(["ALTER ROLE app NOLOGIN", "ALTER ROLE app LOGIN"]) == [
        {"op": "set", "name": "app", "login": True}
    ]
    # CREATE sends the effective value: CREATE ROLE defaults to NOLOGIN, CREATE USER to LOGIN.
    # A CREATE without a password sends an explicit null (the receiver drops any stale copy)
    assert role_bodies.roles_of(
        [
            "CREATE ROLE r1",
            "CREATE USER u1",
            "CREATE ROLE r2 LOGIN PASSWORD 'p'",
            "CREATE ROLE r3 PASSWORD 'p'",
        ]
    ) == [
        {"op": "set", "name": "r1", "password": None, "login": False},
        {
            "op": "set",
            "name": "r2",
            "login": True,
            "password": "p",
            "encrypted_password": SCRAM,
        },
        {
            "op": "set",
            "name": "r3",
            "login": False,
            "password": "p",
            "encrypted_password": SCRAM,
        },
        {"op": "set", "name": "u1", "password": None, "login": True},
    ]
    # CREATE ROLE ... IN ROLE is a membership: touched
    assert role_bodies.roles_of(["CREATE ROLE r4 IN ROLE grp"]) == [
        {"op": "set", "name": "r4", "password": None, "login": False, "touched": True}
    ]


def test_drop_then_create_sends_a_new_role(role_bodies: RoleBodies):
    # One transaction: the DROP and the CREATE merge into one set without the old password,
    # marked recreated (and touched: the old role's members lost their membership)
    assert role_bodies.roles_of(["DROP ROLE app", "CREATE USER app"]) == [
        {"op": "set", "name": "app", "password": None, "login": True, **RECREATED}
    ]
    # A CREATE in a released savepoint forgets what the parent recorded before the DROP
    role_bodies.setup("ALTER ROLE app PASSWORD 'x'")
    assert role_bodies.roles_of(
        [
            "ALTER ROLE app VALID UNTIL 'infinity' CREATEDB",
            "SAVEPOINT s",
            "DROP ROLE app",
            "CREATE ROLE app",
            "RELEASE SAVEPOINT s",
        ]
    ) == [{"op": "set", "name": "app", "password": None, "login": False, **RECREATED}]
    # A role created and renamed in the same transaction is a new role under its last name:
    # no old_name (the receiver must not move whatever it holds under "a")
    assert role_bodies.roles_of(["CREATE ROLE a", "ALTER ROLE a RENAME TO b"]) == [
        {"op": "set", "name": "b", "password": None, "login": False}
    ]


def test_drop_then_create_marks_recreated(role_bodies: RoleBodies):
    # With a password: the receiver must still treat it as a DROP for the old role's data keys
    assert role_bodies.roles_of(["DROP ROLE app", "CREATE USER app PASSWORD 'y'"]) == [
        {
            "op": "set",
            "name": "app",
            "password": "y",
            "encrypted_password": SCRAM,
            "login": True,
            **RECREATED,
        }
    ]
    # Without a password
    assert role_bodies.roles_of(["DROP ROLE app", "CREATE USER app"]) == [
        {"op": "set", "name": "app", "password": None, "login": True, **RECREATED}
    ]
    # CREATE GROUP
    assert role_bodies.roles_of(["DROP ROLE grp", "CREATE GROUP grp"]) == [
        {"op": "set", "name": "grp", "password": None, "login": False, **RECREATED}
    ]
    # A plain CREATE with no DROP before it isn't recreated
    assert role_bodies.roles_of(["CREATE USER fresh PASSWORD 'p'"]) == [
        {"op": "set", "name": "fresh", "password": "p", "encrypted_password": SCRAM, "login": True}
    ]
    # A DROP rolled back with its savepoint doesn't count
    assert role_bodies.roles_of(
        [
            "SAVEPOINT s",
            "DROP ROLE fresh",
            "CREATE USER fresh",
            "ROLLBACK TO SAVEPOINT s",
            "ALTER ROLE fresh NOLOGIN",
        ]
    ) == [{"op": "set", "name": "fresh", "login": False}]


def test_recreated_across_savepoints(role_bodies: RoleBodies):
    # DROP in the parent, CREATE in a released savepoint
    assert role_bodies.roles_of(
        ["DROP ROLE app", "SAVEPOINT s", "CREATE USER app PASSWORD 'y'", "RELEASE SAVEPOINT s"]
    ) == [
        {
            "op": "set",
            "name": "app",
            "password": "y",
            "encrypted_password": SCRAM,
            "login": True,
            **RECREATED,
        }
    ]
    # DROP in a released savepoint, CREATE in the parent
    assert role_bodies.roles_of(
        ["SAVEPOINT s", "DROP ROLE app", "RELEASE SAVEPOINT s", "CREATE USER app"]
    ) == [{"op": "set", "name": "app", "password": None, "login": True, **RECREATED}]
    # DROP in the parent, CREATE two savepoints down
    assert role_bodies.roles_of(
        [
            "DROP ROLE grp",
            "SAVEPOINT s",
            "SAVEPOINT t",
            "CREATE GROUP grp",
            "RELEASE SAVEPOINT t",
            "RELEASE SAVEPOINT s",
        ]
    ) == [{"op": "set", "name": "grp", "password": None, "login": False, **RECREATED}]


def test_recreated_survives_alter_and_rename(role_bodies: RoleBodies):
    # A later ALTER, in the same transaction or a released savepoint, keeps the flag
    assert role_bodies.roles_of(
        [
            "DROP ROLE app",
            "CREATE USER app",
            "ALTER ROLE app PASSWORD 'z'",
            "SAVEPOINT s",
            "ALTER ROLE app NOLOGIN",
            "RELEASE SAVEPOINT s",
        ]
    ) == [
        {
            "op": "set",
            "name": "app",
            "password": "z",
            "encrypted_password": SCRAM,
            "login": False,
            **RECREATED,
        }
    ]
    # The new role renamed away: no role holds "app" any more, so the old one is a del (the
    # receiver's DROP check), and the new one is a plain new role under its last name
    dropped_and_new = [
        {"op": "del", "name": "app"},
        {"op": "set", "name": "app2", "password": None, "login": True},
    ]
    assert (
        role_bodies.roles_of(["DROP ROLE app", "CREATE USER app", "ALTER ROLE app RENAME TO app2"])
        == dropped_and_new
    )
    role_bodies.setup("ALTER ROLE app2 RENAME TO app")
    assert (
        role_bodies.roles_of(
            [
                "DROP ROLE app",
                "CREATE USER app",
                "SAVEPOINT s",
                "ALTER ROLE app RENAME TO app2",
                "RELEASE SAVEPOINT s",
            ]
        )
        == dropped_and_new
    )


@pytest.mark.parametrize("new_name", ["app2", "b", "c", "renamed", "zz"])
def test_recreated_rename_then_create_in_savepoint(role_bodies: RoleBodies, new_name: str):
    # The savepoint holds both the rename away from `app` and a new `app`. The role now under
    # `app` replaces the dropped one (recreated); the first new role is a plain new role under
    # its last name (no old_name: it has nothing at the receiver to move)
    assert role_bodies.roles_of(
        [
            "DROP ROLE app",
            "CREATE USER app PASSWORD 'y'",
            "SAVEPOINT s",
            f"ALTER ROLE app RENAME TO {new_name}",
            "CREATE ROLE app",
            "RELEASE SAVEPOINT s",
        ]
    ) == [
        # Every new_name sorts after "app"
        {"op": "set", "name": "app", "password": None, "login": False, **RECREATED},
        {
            "op": "set",
            "name": new_name,
            "password": "y",
            "encrypted_password": SCRAM,
            "login": True,
        },
    ]


def test_role_created_in_savepoint_ignores_old_name_state(role_bodies: RoleBodies):
    # m1: a role created (and renamed) in a savepoint doesn't inherit what the parent recorded
    # under the name it was created with
    assert role_bodies.roles_of(
        [
            "ALTER ROLE app VALID UNTIL 'infinity'",
            "SAVEPOINT s",
            "DROP ROLE app",
            "CREATE ROLE app",
            "ALTER ROLE app RENAME TO app2",
            "RELEASE SAVEPOINT s",
        ]
    ) == [
        {"op": "del", "name": "app"},
        {"op": "set", "name": "app2", "password": None, "login": False},
    ]


@pytest.mark.parametrize(
    "statements",
    [
        pytest.param(
            [
                "DROP ROLE app",
                "ALTER ROLE y RENAME TO app",
                "ALTER ROLE app RENAME TO z",
                "CREATE USER app",
            ],
            id="top_level",
        ),
        pytest.param(
            [
                "DROP ROLE app",
                "SAVEPOINT s",
                "ALTER ROLE y RENAME TO app",
                "ALTER ROLE app RENAME TO z",
                "RELEASE SAVEPOINT s",
                "CREATE USER app",
            ],
            id="renames_in_savepoint",
        ),
        pytest.param(
            [
                "SAVEPOINT s",
                "DROP ROLE app",
                "RELEASE SAVEPOINT s",
                "ALTER ROLE y RENAME TO app",
                "SAVEPOINT t",
                "ALTER ROLE app RENAME TO z",
                "CREATE USER app",
                "RELEASE SAVEPOINT t",
            ],
            id="drop_in_released_savepoint",
        ),
        pytest.param(
            [
                "SAVEPOINT s",
                "DROP ROLE app",
                "ALTER ROLE y RENAME TO app",
                "SAVEPOINT t",
                "ALTER ROLE app RENAME TO z",
                "SAVEPOINT u",
                "CREATE USER app",
                "RELEASE SAVEPOINT u",
                "RELEASE SAVEPOINT t",
                "RELEASE SAVEPOINT s",
            ],
            id="nested",
        ),
    ],
)
def test_recreated_after_rename_onto_dropped_name(role_bodies: RoleBodies, statements: list[str]):
    # A rename onto the dropped name and away again doesn't make the transaction forget the
    # DROP: the new `app` still replaces the dropped one
    role_bodies.setup("CREATE ROLE y")
    assert role_bodies.roles_of(statements) == [
        {"op": "set", "name": "app", "password": None, "login": True, **RECREATED},
        {"op": "set", "name": "z", "old_name": "y"},
    ]


@pytest.mark.parametrize(
    "statements",
    [
        pytest.param(
            ["DROP ROLE app", "ALTER ROLE y RENAME TO app", "ALTER ROLE app RENAME TO z"],
            id="top_level",
        ),
        pytest.param(
            [
                "DROP ROLE app",
                "SAVEPOINT s",
                "ALTER ROLE y RENAME TO app",
                "ALTER ROLE app RENAME TO z",
                "RELEASE SAVEPOINT s",
            ],
            id="renames_in_savepoint",
        ),
        pytest.param(
            [
                "SAVEPOINT s",
                "DROP ROLE app",
                "RELEASE SAVEPOINT s",
                "ALTER ROLE y RENAME TO app",
                "ALTER ROLE app RENAME TO z",
            ],
            id="drop_in_released_savepoint",
        ),
        pytest.param(
            [
                "SAVEPOINT s",
                "DROP ROLE app",
                "ALTER ROLE y RENAME TO app",
                "RELEASE SAVEPOINT s",
                "SAVEPOINT t",
                "ALTER ROLE app RENAME TO z",
                "RELEASE SAVEPOINT t",
            ],
            id="rename_away_in_later_savepoint",
        ),
    ],
)
def test_dropped_name_renamed_onto_and_away_is_deleted(
    role_bodies: RoleBodies, statements: list[str]
):
    # The DROP still reaches the receiver, though the name's entry was overwritten and moved
    role_bodies.setup("CREATE ROLE y")
    assert role_bodies.roles_of(statements) == [
        {"op": "del", "name": "app"},
        {"op": "set", "name": "z", "old_name": "y"},
    ]


def test_dropped_name_rolled_back_or_renamed_onto(role_bodies: RoleBodies):
    role_bodies.setup("CREATE ROLE y")
    # Rolled back with its savepoint: no del
    assert role_bodies.roles_of(
        [
            "SAVEPOINT s",
            "DROP ROLE app",
            "ALTER ROLE y RENAME TO app",
            "ALTER ROLE app RENAME TO z",
            "ROLLBACK TO SAVEPOINT s",
            "ALTER ROLE app NOLOGIN",
        ]
    ) == [{"op": "set", "name": "app", "login": False}]
    # The rename onto the dropped name stays: the rename entry decides, no del. It's touched:
    # the dropped role's members lost their membership
    assert role_bodies.roles_of(["DROP ROLE app", "ALTER ROLE y RENAME TO app"]) == [
        {"op": "set", "name": "app", "old_name": "y", "touched": True}
    ]
    role_bodies.setup("CREATE ROLE y")
    assert role_bodies.roles_of(
        ["SAVEPOINT s", "DROP ROLE app", "RELEASE SAVEPOINT s", "ALTER ROLE y RENAME TO app"]
    ) == [{"op": "set", "name": "app", "old_name": "y", "touched": True}]


def test_drop_rolled_back_then_rename_isnt_recreated(role_bodies: RoleBodies):
    # The DROP went with its savepoint; the name was freed by a rename only
    assert role_bodies.roles_of(
        [
            "SAVEPOINT s",
            "DROP ROLE app",
            "ROLLBACK TO SAVEPOINT s",
            "ALTER ROLE app RENAME TO z",
            "CREATE USER app",
        ]
    ) == [
        {"op": "set", "name": "app", "password": None, "login": True},
        {"op": "set", "name": "z", "old_name": "app"},
    ]


def test_swap_in_savepoint(role_bodies: RoleBodies):
    # Each name keeps what the parent recorded for the role now under it
    role_bodies.setup("CREATE ROLE a; CREATE ROLE b")
    assert role_bodies.roles_of(
        [
            "ALTER ROLE a PASSWORD 'pa'",
            "ALTER ROLE b LOGIN",
            "SAVEPOINT s",
            "ALTER ROLE a RENAME TO t",
            "ALTER ROLE b RENAME TO a",
            "ALTER ROLE t RENAME TO b",
            "RELEASE SAVEPOINT s",
        ]
    ) == [
        {"op": "set", "name": "a", "old_name": "b", "login": True},
        {
            "op": "set",
            "name": "b",
            "old_name": "a",
            "password": "pa",
            "encrypted_password": SCRAM,
        },
    ]


def test_rename_chain_across_nested_savepoints(role_bodies: RoleBodies):
    assert role_bodies.roles_of(
        [
            "ALTER ROLE app PASSWORD 'pa' CREATEDB",
            "SAVEPOINT s",
            "ALTER ROLE app RENAME TO b",
            "SAVEPOINT t",
            "ALTER ROLE b RENAME TO c",
            "RELEASE SAVEPOINT t",
            "RELEASE SAVEPOINT s",
        ]
    ) == [
        {
            "op": "set",
            "name": "c",
            "old_name": "app",
            "password": "pa",
            "encrypted_password": SCRAM,
            "touched": True,
        }
    ]
    # A new role renamed along the chain: the dropped role is a del, the new one a plain set
    role_bodies.setup("ALTER ROLE c RENAME TO app")
    assert role_bodies.roles_of(
        [
            "DROP ROLE app",
            "CREATE USER app",
            "SAVEPOINT s",
            "ALTER ROLE app RENAME TO b",
            "SAVEPOINT t",
            "ALTER ROLE b RENAME TO c",
            "RELEASE SAVEPOINT t",
            "RELEASE SAVEPOINT s",
        ]
    ) == [
        {"op": "del", "name": "app"},
        {"op": "set", "name": "c", "password": None, "login": True},
    ]


@pytest.mark.parametrize("password", ["PASSWORD NULL", "PASSWORD 'p9'"])
def test_rolled_back_savepoint_below_a_released_one(role_bodies: RoleBodies, password: str):
    # s2 is released into s1, then s1 is rolled back: nothing of s2 is left
    assert role_bodies.roles_of(
        [
            "SAVEPOINT s1",
            "SAVEPOINT s2",
            f"ALTER ROLE app {password}",
            "RELEASE SAVEPOINT s2",
            "ROLLBACK TO SAVEPOINT s1",
            "ALTER ROLE app NOLOGIN",
        ]
    ) == [{"op": "set", "name": "app", "login": False}]


def test_database_renames_in_savepoints(role_bodies: RoleBodies):
    role_bodies.pg.safe_psql("CREATE DATABASE p")
    role_bodies.pg.safe_psql("CREATE DATABASE y")
    # p -> x, then x and y swap in a released savepoint: p is now y, y is now x
    assert role_bodies.dbs_of(
        [
            "ALTER DATABASE p RENAME TO x",
            "SAVEPOINT s",
            "ALTER DATABASE x RENAME TO t",
            "ALTER DATABASE y RENAME TO x",
            "ALTER DATABASE t RENAME TO y",
            "RELEASE SAVEPOINT s",
        ]
    ) == [
        {"op": "set", "name": "x", "old_name": "y"},
        {"op": "set", "name": "y", "old_name": "p"},
    ]
    # A rename rolled back with its savepoint isn't sent; an owner change is, with the owner
    assert role_bodies.dbs_of(
        [
            "SAVEPOINT s",
            "ALTER DATABASE x RENAME TO z",
            "ROLLBACK TO SAVEPOINT s",
            "ALTER DATABASE x OWNER TO app",
        ]
    ) == [{"op": "set", "name": "x", "owner": "app"}]


def test_database_owner_renamed(role_bodies: RoleBodies):
    # The receiver keeps owners by name: the database is sent again with its owner's new name
    role_bodies.pg.safe_psql("CREATE DATABASE o OWNER app")
    assert role_bodies.dbs_of(["ALTER ROLE app RENAME TO app9"]) == [
        {"op": "set", "name": "o", "owner": "app9"}
    ]


def test_prepare_refused_with_pending_changes(role_bodies: RoleBodies):
    role_bodies.pg.safe_psql("CREATE DATABASE p")
    with role_bodies.pg.cursor() as cur:
        for stmt in ["ALTER ROLE app PASSWORD 'p2'", "ALTER DATABASE p RENAME TO q"]:
            cur.execute("BEGIN")
            cur.execute(stmt)
            with pytest.raises(psycopg2.Error, match="cannot PREPARE"):
                cur.execute("PREPARE TRANSACTION 'p1'")
            cur.execute("ROLLBACK")
        # Nothing pending: PREPARE works
        cur.execute("BEGIN")
        cur.execute("SELECT 1")
        cur.execute("PREPARE TRANSACTION 'p2'")
        cur.execute("COMMIT PREPARED 'p2'")
        # The refused changes weren't made
        cur.execute("SELECT count(*) FROM pg_database WHERE datname = 'p'")
        assert cur.fetchone() == (1,)


def test_valid_until_forwarded(role_bodies: RoleBodies):
    assert role_bodies.roles_of(["ALTER ROLE app VALID UNTIL '2030-01-01 00:00:00+00'"]) == [
        {"op": "set", "name": "app", "valid_until": "2030-01-01 00:00:00+00"}
    ]
    assert role_bodies.roles_of(["ALTER ROLE app VALID UNTIL 'infinity'"]) == [
        {"op": "set", "name": "app", "valid_until": "infinity"}
    ]


@pytest.mark.parametrize(
    "attribute",
    [
        "CREATEDB",
        "NOCREATEROLE",
        "NOINHERIT",
        "REPLICATION",
        "BYPASSRLS",
        "SUPERUSER",
        "CONNECTION LIMIT 5",
    ],
)
def test_createdb_marks_touched(role_bodies: RoleBodies, attribute: str):
    assert role_bodies.roles_of([f"ALTER ROLE app {attribute}"]) == [
        {"op": "set", "name": "app", "touched": True}
    ]


def test_grant_role_marks_grantee_touched(role_bodies: RoleBodies):
    touched = [
        {"op": "set", "name": "app", "touched": True},
        {"op": "set", "name": "grp", "touched": True},
    ]
    assert role_bodies.roles_of(["GRANT grp TO app"]) == touched
    assert role_bodies.roles_of(["REVOKE grp FROM app"]) == touched
    # ALTER GROUP ... ADD USER is a grant too
    assert role_bodies.roles_of(["ALTER GROUP grp ADD USER app"]) == [
        {"op": "set", "name": "grp", "touched": True}
    ]


def test_savepoint_rollback_drops_attributes(role_bodies: RoleBodies):
    # Rolled back: only the password set before the savepoint is sent
    assert role_bodies.roles_of(
        [
            "ALTER ROLE app PASSWORD 'p2'",
            "SAVEPOINT s",
            "ALTER ROLE app NOLOGIN VALID UNTIL 'infinity' CREATEDB",
            "GRANT grp TO app",
            "ROLLBACK TO SAVEPOINT s",
        ]
    ) == [{"op": "set", "name": "app", "password": "p2", "encrypted_password": SCRAM}]
    # A REVOKE rolled back with its savepoint isn't sent either
    role_bodies.setup("GRANT grp TO app")
    assert role_bodies.roles_of(
        [
            "ALTER ROLE app PASSWORD 'p4'",
            "SAVEPOINT s",
            "REVOKE grp FROM app",
            "ROLLBACK TO SAVEPOINT s",
        ]
    ) == [{"op": "set", "name": "app", "password": "p4", "encrypted_password": SCRAM}]
    # Released: the subtransaction's attributes merge in and keep the parent's password
    assert role_bodies.roles_of(
        [
            "ALTER ROLE app PASSWORD 'p3'",
            "SAVEPOINT s",
            "ALTER ROLE app NOLOGIN VALID UNTIL 'infinity' CREATEDB",
            "SAVEPOINT t",
            "ALTER ROLE app LOGIN",
            "RELEASE SAVEPOINT t",
            "RELEASE SAVEPOINT s",
        ]
    ) == [
        {
            "op": "set",
            "name": "app",
            "password": "p3",
            "encrypted_password": SCRAM,
            "login": True,
            "valid_until": "infinity",
            "touched": True,
        }
    ]
    # A rename in a subtransaction carries the parent's attributes to the new name
    assert role_bodies.roles_of(
        [
            "ALTER ROLE app NOLOGIN CREATEDB",
            "SAVEPOINT s",
            "ALTER ROLE app RENAME TO app2",
            "RELEASE SAVEPOINT s",
        ]
    ) == [{"op": "set", "name": "app2", "old_name": "app", "login": False, "touched": True}]


def test_password_only_body_unchanged(role_bodies: RoleBodies):
    assert role_bodies.roles_of(["ALTER ROLE app PASSWORD 'p'"]) == [
        {"op": "set", "name": "app", "password": "p", "encrypted_password": SCRAM}
    ]
    assert role_bodies.roles_of(["ALTER ROLE app PASSWORD NULL"]) == [{"op": "set", "name": "app"}]
    # PASSWORD NULL next to an attribute is sent as an explicit null, so the receiver can tell
    # it from an attribute-only change
    assert role_bodies.roles_of(["ALTER ROLE app PASSWORD NULL", "ALTER ROLE app CREATEDB"]) == [
        {"op": "set", "name": "app", "password": None, "touched": True}
    ]


# Assert that specified database has a specific connlimit, throwing an AssertionError otherwise
# -2 means invalid database
# -1 means no specific per-db limit (default)
def assert_db_connlimit(endpoint: Any, db_name: str, connlimit: int, msg: str):
    with endpoint.cursor() as cur:
        cur.execute("SELECT datconnlimit FROM pg_database WHERE datname = %s", (db_name,))
        result = cur.fetchone()
        if not result:
            raise AssertionError(f"Database '{db_name}' not found")
        assert result[0] == connlimit, msg


# Test that compute_ctl can deal with invalid databases (drop them).
# If Postgres extension cannot reach cplane, then DROP will be aborted
# and database will be marked as invalid. Then there are two recovery
# flows:
# 1. User can just repeat DROP DATABASE command until it succeeds
# 2. User can ignore, then compute_ctl will drop invalid databases
#    automatically during full configuration
# Here we test the latter. The first one is tested in test_ddl_forwarding
def test_ddl_forwarding_invalid_db(neon_simple_env: NeonEnv):
    env = neon_simple_env
    endpoint = env.endpoints.create_start(
        "main",
        # Some non-existent url
        config_lines=["neon.console_url=http://localhost:9999/unknown/api/v0/roles_and_databases"],
    )

    with endpoint.cursor() as cur:
        cur.execute("SET neon.forward_ddl = false")
        cur.execute("CREATE DATABASE failure")
        cur.execute("COMMIT")

    assert_db_connlimit(
        endpoint, "failure", -1, "Database 'failure' doesn't have a valid connlimit"
    )

    # The control plane is unreachable: object_not_in_prerequisite_state (SQLSTATE 55000)
    with pytest.raises(ObjectNotInPrerequisiteState):
        with endpoint.cursor() as cur:
            cur.execute("DROP DATABASE failure")
            cur.execute("COMMIT")

    # Should be invalid after failed drop
    assert_db_connlimit(endpoint, "failure", -2, "Database 'failure' ins't invalid")

    endpoint.stop()
    endpoint.start()

    # Still invalid after restart without full configuration
    assert_db_connlimit(endpoint, "failure", -2, "Database 'failure' ins't invalid")

    endpoint.stop()
    endpoint.respec(skip_pg_catalog_updates=False)
    endpoint.start()

    # Should be cleaned up by compute_ctl during full configuration
    with endpoint.cursor() as cur:
        cur.execute("SELECT count(*) FROM pg_database WHERE datname = 'failure'")
        result = cur.fetchone()
        if not result:
            raise AssertionError("Could not count databases")
        assert result[0] == 0, "Database 'failure' still exists after restart"


def test_ddl_forwarding_role_specs(neon_simple_env: NeonEnv):
    """
    Postgres has a concept of role specs:

        ROLESPEC_CSTRING: ALTER ROLE xyz
        ROLESPEC_CURRENT_USER: ALTER ROLE current_user
        ROLESPEC_CURRENT_ROLE: ALTER ROLE current_role
        ROLESPEC_SESSION_USER: ALTER ROLE session_user
        ROLESPEC_PUBLIC: ALTER ROLE public

    The extension is required to serialize these special role spec into
    usernames for the purpose of DDL forwarding.
    """
    env = neon_simple_env

    endpoint = env.endpoints.create_start("main")

    with endpoint.cursor() as cur:
        # ROLESPEC_CSTRING
        cur.execute("ALTER ROLE cloud_admin WITH PASSWORD 'york'")
        # ROLESPEC_CURRENT_USER
        cur.execute("ALTER ROLE current_user WITH PASSWORD 'pork'")
        # ROLESPEC_CURRENT_ROLE
        cur.execute("ALTER ROLE current_role WITH PASSWORD 'cork'")
        # ROLESPEC_SESSION_USER
        cur.execute("ALTER ROLE session_user WITH PASSWORD 'bork'")
        # ROLESPEC_PUBLIC
        with pytest.raises(UndefinedObject):
            cur.execute("ALTER ROLE public WITH PASSWORD 'dork'")
