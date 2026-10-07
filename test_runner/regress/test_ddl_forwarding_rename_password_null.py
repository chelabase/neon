from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from typing import Any

    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import VanillaPostgres
    from pytest_httpserver import HTTPServer
    from werkzeug.wrappers.request import Request

ENDPOINT = "/test/roles_and_databases"
SCRAM = "<scram-sha-256 hash>"


@pytest.mark.parametrize(
    "statements,expected",
    [
        # A rename plus PASSWORD NULL carries an explicit JSON null (and no encrypted_password).
        (
            "ALTER ROLE a RENAME TO b; ALTER ROLE b PASSWORD NULL",
            {"roles": [{"op": "set", "name": "b", "old_name": "a", "password": None}]},
        ),
        # PASSWORD NULL before the rename gives the same payload.
        (
            "ALTER ROLE a PASSWORD NULL; ALTER ROLE a RENAME TO b",
            {"roles": [{"op": "set", "name": "b", "old_name": "a", "password": None}]},
        ),
        # A plain rename sends only old_name and name (no password key).
        (
            "ALTER ROLE a RENAME TO b",
            {"roles": [{"op": "set", "name": "b", "old_name": "a"}]},
        ),
        # PASSWORD NULL alone keeps today's payload (no password key).
        (
            "ALTER ROLE a PASSWORD NULL",
            {"roles": [{"op": "set", "name": "a"}]},
        ),
        # rename, PASSWORD 'x', PASSWORD NULL: the last password statement wins.
        (
            "ALTER ROLE a RENAME TO b; ALTER ROLE b PASSWORD 'x'; ALTER ROLE b PASSWORD NULL",
            {"roles": [{"op": "set", "name": "b", "old_name": "a", "password": None}]},
        ),
        # rename, PASSWORD 'x': the password and its hash are sent with old_name.
        (
            "ALTER ROLE a RENAME TO b; ALTER ROLE b PASSWORD 'x'",
            {
                "roles": [
                    {
                        "op": "set",
                        "name": "b",
                        "old_name": "a",
                        "password": "x",
                        "encrypted_password": SCRAM,
                    }
                ]
            },
        ),
        # DROP after a rename deletes the role under its name before the transaction.
        (
            "ALTER ROLE a RENAME TO b; DROP ROLE b",
            {"roles": [{"op": "del", "name": "a"}]},
        ),
        # Savepoints (RELEASE) give the same payloads as the same statements without them.
        (
            "ALTER ROLE a RENAME TO b; SAVEPOINT s; ALTER ROLE b PASSWORD NULL; RELEASE s",
            {"roles": [{"op": "set", "name": "b", "old_name": "a", "password": None}]},
        ),
        (
            "ALTER ROLE a PASSWORD NULL; SAVEPOINT s; ALTER ROLE a RENAME TO b; RELEASE s",
            {"roles": [{"op": "set", "name": "b", "old_name": "a", "password": None}]},
        ),
        (
            "ALTER ROLE a PASSWORD 'x'; SAVEPOINT s; ALTER ROLE a RENAME TO b; RELEASE s",
            {
                "roles": [
                    {
                        "op": "set",
                        "name": "b",
                        "old_name": "a",
                        "password": "x",
                        "encrypted_password": SCRAM,
                    }
                ]
            },
        ),
        (
            "ALTER ROLE a RENAME TO b; SAVEPOINT s; ALTER ROLE b PASSWORD 'x'; RELEASE s",
            {
                "roles": [
                    {
                        "op": "set",
                        "name": "b",
                        "old_name": "a",
                        "password": "x",
                        "encrypted_password": SCRAM,
                    }
                ]
            },
        ),
        (
            "ALTER ROLE a RENAME TO b; SAVEPOINT s; DROP ROLE b; RELEASE s",
            {"roles": [{"op": "del", "name": "a"}]},
        ),
        # A rename in a savepoint of an untouched role.
        (
            "SAVEPOINT s; ALTER ROLE a RENAME TO b; RELEASE s",
            {"roles": [{"op": "set", "name": "b", "old_name": "a"}]},
        ),
        # ROLLBACK TO SAVEPOINT leaves the parent's state intact.
        (
            "ALTER ROLE a RENAME TO b; SAVEPOINT s; ALTER ROLE b PASSWORD NULL; ROLLBACK TO SAVEPOINT s",
            {"roles": [{"op": "set", "name": "b", "old_name": "a"}]},
        ),
        (
            "ALTER ROLE a PASSWORD NULL; SAVEPOINT s; ALTER ROLE a RENAME TO b; ROLLBACK TO SAVEPOINT s",
            {"roles": [{"op": "set", "name": "a"}]},
        ),
        (
            "ALTER ROLE a RENAME TO b; ALTER ROLE b PASSWORD NULL; SAVEPOINT s; "
            "ALTER ROLE b PASSWORD 'x'; ROLLBACK TO SAVEPOINT s",
            {"roles": [{"op": "set", "name": "b", "old_name": "a", "password": None}]},
        ),
    ],
    ids=[
        "rename_then_null",
        "null_then_rename",
        "plain_rename",
        "null_alone",
        "rename_password_null",
        "rename_then_password",
        "drop_after_rename",
        "savepoint_rename_then_null",
        "savepoint_null_then_rename",
        "savepoint_password_then_rename",
        "savepoint_rename_then_password",
        "savepoint_drop_after_rename",
        "savepoint_rename_only",
        "rollback_rename_then_null",
        "rollback_null_then_rename",
        "rollback_password_keeps_null",
    ],
)
def test_ddl_forwarding_rename_password_null(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
    statements: str,
    expected: dict[str, Any],
):
    (host, port) = httpserver_listen_address
    received: list[Any] = []

    def handler(request: Request) -> Response:
        # The hash has a random salt: check its shape and replace it
        body: Any = request.json
        for role in body.get("roles", []):
            if "encrypted_password" in role:
                assert role["encrypted_password"].startswith("SCRAM-SHA-256$")
                role["encrypted_password"] = SCRAM
        received.append(body)
        return Response(status=200)

    httpserver.expect_request(ENDPOINT, method="PATCH").respond_with_handler(handler)
    vanilla_pg.configure(
        [
            f"neon.console_url=http://{host}:{port}{ENDPOINT}",
            "shared_preload_libraries = 'neon'",
        ]
    )
    vanilla_pg.start()

    # Set up the role without forwarding, then clear what was received.
    vanilla_pg.safe_psql("SET neon.forward_ddl = false; CREATE ROLE a PASSWORD 'x'")
    received.clear()

    with vanilla_pg.cursor() as cur:
        cur.execute("BEGIN")
        for stmt in statements.split(";"):
            cur.execute(stmt.strip())
        cur.execute("COMMIT")

    assert received == [expected]
