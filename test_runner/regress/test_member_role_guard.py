from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres
from psycopg2.errors import InsufficientPrivilege, UndefinedObject
from werkzeug.wrappers.response import Response

# K6 H4: statements and catalog functions that exist only from PG16 (GRANT ... WITH INHERIT,
# ALTER ROLE ALL's PG16 error text) or PG15 (GRANT ... ON PARAMETER, pg_settings_get_flags).
PG16_PLUS = run_only_on_postgres(
    [PgVersion.V16, PgVersion.V17],
    "uses PG16+ syntax or messages (ON PARAMETER, WITH INHERIT, pg_settings_get_flags)",
)

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


# D1: roles marked with chelabase.managed_role (personal logins).
#
# A role is marked when it has a role-wide pg_db_role_setting row
# (setdatabase = 0) holding a chelabase.managed_role= entry, whatever its
# value. A superuser marks a role the way the worker does. On a build that
# doesn't define the GUC the setting is stored as a placeholder (only a
# superuser may store one), and the marker is the catalog row either way.

MARKER = "chelabase.managed_role"

# The one marker predicate (plan SP22): a role-wide row whose setconfig has an
# entry starting with "chelabase.managed_role=".
IS_MARKED = (
    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting s"
    " JOIN pg_catalog.pg_roles r ON r.oid = s.setrole,"
    " LATERAL pg_catalog.unnest(s.setconfig) AS c(entry)"
    " WHERE s.setdatabase = 0 AND r.rolname = %s"
    " AND pg_catalog.starts_with(c.entry, 'chelabase.managed_role='))"
)


def marked(pg: VanillaPostgres, role: str) -> bool:
    with pg.cursor() as cur:
        cur.execute(IS_MARKED, (role,))
        row = cur.fetchone()
        assert row is not None
        return bool(row[0])


def role_settings(pg: VanillaPostgres, role: str) -> list[tuple[Any, ...]]:
    with pg.cursor() as cur:
        cur.execute(
            "SELECT s.setdatabase, s.setconfig FROM pg_catalog.pg_db_role_setting s"
            " JOIN pg_catalog.pg_roles r ON r.oid = s.setrole WHERE r.rolname = %s"
            " ORDER BY s.setdatabase",
            (role,),
        )
        return cur.fetchall()


def setup_marked(pg: VanillaPostgres):
    pg.safe_psql_many(
        [
            "CREATE ROLE alice LOGIN PASSWORD 'pw'",
            f"ALTER ROLE alice SET {MARKER} = 'personal'",
            # Same name but for the case: a different, unmarked role.
            "CREATE ROLE \"Alice\" LOGIN PASSWORD 'pw'",
            "CREATE ROLE bob LOGIN PASSWORD 'pw'",
            "CREATE ROLE grp NOLOGIN",
            "CREATE ROLE owner LOGIN CREATEROLE PASSWORD 'pw' IN ROLE neon_superuser",
            # Postgres alone lets owner (CREATEROLE + ADMIN) change all of these
            # roles: the refusals below must come from the hook.
            "GRANT grp TO owner WITH ADMIN OPTION",
            "GRANT alice TO owner WITH ADMIN OPTION",
            'GRANT "Alice" TO owner WITH ADMIN OPTION',
            "GRANT bob TO owner WITH ADMIN OPTION",
        ]
    )
    assert marked(pg, "alice")
    assert not marked(pg, "Alice")


def run_as(pg: VanillaPostgres, user: str | None, sql: str, setup: tuple[str, ...] = ()):
    """Runs sql as user (the superuser when None), after the setup statements."""
    login: dict[str, Any] = {} if user is None else {"user": user, "password": "pw"}
    with pg.cursor(**login) as cur:
        for statement in setup:
            cur.execute(statement)
        cur.execute(sql)


def refusal(
    pg: VanillaPostgres, user: str | None, sql: str, setup: tuple[str, ...] = ()
) -> InsufficientPrivilege:
    try:
        run_as(pg, user, sql, setup)
    except InsufficientPrivilege as e:
        return e
    pytest.fail(f"{sql!r} as {user or 'the superuser'} succeeded; the role guard must refuse it")


def refused_marked(
    pg: VanillaPostgres,
    user: str | None,
    sql: str,
    name: str = "alice",
    setup: tuple[str, ...] = (),
):
    e = refusal(pg, user, sql, setup)
    assert e.diag.message_primary == f'role "{name}" is managed by Chelabase', (
        sql,
        e.diag.message_primary,
    )


# Every round-3 statement form, naming the marked role alice, as owner (who
# holds CREATEROLE and ADMIN on every role involved).
OWNER_ON_MARKED = [
    "ALTER ROLE alice PASSWORD 'x'",
    "ALTER ROLE alice NOLOGIN",
    "ALTER ROLE alice CONNECTION LIMIT 1",
    "ALTER ROLE alice VALID UNTIL 'infinity'",
    "ALTER USER alice PASSWORD 'x'",
    "ALTER ROLE alice SET work_mem = '1MB'",
    "ALTER ROLE alice RESET work_mem",
    "ALTER ROLE alice RESET ALL",
    "ALTER USER alice SET work_mem = '1MB'",
    "ALTER ROLE alice IN DATABASE postgres SET work_mem = '1MB'",
    "ALTER ROLE alice IN DATABASE postgres RESET work_mem",
    "ALTER ROLE alice IN DATABASE postgres RESET ALL",
    "ALTER USER alice IN DATABASE postgres SET work_mem = '1MB'",
    "ALTER ROLE alice RENAME TO alice2",
    "ALTER USER alice RENAME TO alice2",
    "DROP ROLE alice",
    "DROP ROLE IF EXISTS alice",
    "DROP ROLE IF EXISTS nobody_here, alice",
    "DROP USER alice",
    "CREATE ROLE g1 IN ROLE alice",
    "CREATE ROLE g2 IN GROUP alice",
    "CREATE ROLE g3 IN ROLE grp, alice",
    "CREATE ROLE g4 ROLE alice",
    "CREATE ROLE g5 ADMIN alice",
    "CREATE USER g6 IN ROLE alice",
    "CREATE GROUP g7 USER alice",
    "GRANT grp TO alice",
    "GRANT grp TO bob, alice",
    "GRANT grp TO alice WITH INHERIT FALSE",
    "REVOKE grp FROM alice",
    "REVOKE ADMIN OPTION FOR grp FROM alice",
    "GRANT alice TO grp",
    "GRANT grp, alice TO bob",
    "REVOKE alice FROM grp",
    "ALTER GROUP grp ADD USER alice",
    "ALTER GROUP grp ADD USER bob, alice",
    "ALTER GROUP grp DROP USER alice",
    "ALTER GROUP alice ADD USER grp",
    "ALTER GROUP alice DROP USER grp",
    "DO $$BEGIN EXECUTE 'ALTER ROLE alice PASSWORD ''x'''; END$$",
]

# The marked role on itself: a personal login can't change its own password or
# settings from SQL.
MARKED_ON_ITSELF = [
    "ALTER ROLE CURRENT_USER PASSWORD 'x'",
    "ALTER ROLE CURRENT_ROLE PASSWORD 'x'",
    "ALTER USER CURRENT_USER PASSWORD 'x'",
    "ALTER ROLE SESSION_USER PASSWORD 'x'",
    "ALTER ROLE alice PASSWORD 'x'",
    "ALTER ROLE CURRENT_USER SET work_mem = '1MB'",
    "ALTER ROLE SESSION_USER SET work_mem = '1MB'",
    "ALTER ROLE CURRENT_USER SET role = 'grp'",
    "ALTER ROLE CURRENT_USER RESET work_mem",
    "ALTER ROLE CURRENT_USER RESET ALL",
    "ALTER ROLE CURRENT_USER IN DATABASE postgres SET work_mem = '1MB'",
    "ALTER ROLE CURRENT_USER IN DATABASE postgres RESET ALL",
    "ALTER USER CURRENT_USER IN DATABASE postgres SET search_path = 'x'",
    "DO $$BEGIN EXECUTE 'ALTER ROLE CURRENT_USER PASSWORD ''x'''; END$$",
]


@PG16_PLUS
def test_marked_role_statements_refused_for_owner(neon_pg: VanillaPostgres):
    setup_marked(neon_pg)
    for sql in OWNER_ON_MARKED:
        refused_marked(neon_pg, "owner", sql)
    # Nothing changed.
    assert marked(neon_pg, "alice")
    assert role_settings(neon_pg, "alice") == [(0, [f"{MARKER}=personal"])]


def test_marked_role_refuses_itself(neon_pg: VanillaPostgres):
    setup_marked(neon_pg)
    for sql in MARKED_ON_ITSELF:
        refused_marked(neon_pg, "alice", sql)
    # Its own marker can't be removed either (Postgres refuses too).
    for sql in [
        f"ALTER ROLE CURRENT_USER RESET {MARKER}",
        f"ALTER ROLE CURRENT_USER SET {MARKER} = ''",
    ]:
        refusal(neon_pg, "alice", sql)
    assert role_settings(neon_pg, "alice") == [(0, [f"{MARKER}=personal"])]


def test_marked_role_nested_statements_are_guarded(neon_pg: VanillaPostgres):
    setup_marked(neon_pg)
    refused_marked(neon_pg, "owner", "DO $$BEGIN EXECUTE 'ALTER ROLE alice PASSWORD ''x'''; END$$")
    neon_pg.safe_psql_many(
        [
            "CREATE FUNCTION plpgsql_alter_alice() RETURNS void LANGUAGE plpgsql AS "
            "$$BEGIN EXECUTE 'ALTER ROLE alice PASSWORD ''x'''; END$$",
            "CREATE FUNCTION plpgsql_grant_to_alice() RETURNS void LANGUAGE plpgsql AS "
            "$$BEGIN GRANT grp TO alice; END$$",
            "CREATE FUNCTION sql_alter_alice() RETURNS void LANGUAGE sql AS "
            "$$ALTER ROLE alice SET work_mem = '1MB'$$",
            "CREATE PROCEDURE proc_drop_alice() LANGUAGE plpgsql AS $$BEGIN DROP ROLE alice; END$$",
            # Owned by owner: inside it the current user is owner, whoever calls it.
            "CREATE FUNCTION definer_alter_alice() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS "
            "$$BEGIN EXECUTE 'ALTER ROLE alice PASSWORD ''x'''; END$$",
            "ALTER FUNCTION definer_alter_alice() OWNER TO owner",
        ]
    )
    for sql in [
        "SELECT plpgsql_alter_alice()",
        "SELECT plpgsql_grant_to_alice()",
        "SELECT sql_alter_alice()",
        "CALL proc_drop_alice()",
    ]:
        refused_marked(neon_pg, "owner", sql)
    # The guard looks at the current user, not the session user: a superuser
    # session acting as owner is refused.
    refused_marked(neon_pg, None, "SELECT definer_alter_alice()")
    refused_marked(neon_pg, None, "ALTER ROLE alice PASSWORD 'x'", setup=("SET ROLE owner",))
    assert role_settings(neon_pg, "alice") == [(0, [f"{MARKER}=personal"])]


def test_marked_role_marker_rules(neon_pg: VanillaPostgres):
    """Any value marks; only a role-wide row marks; names are matched exactly."""
    setup_marked(neon_pg)
    roles = ["erin", "frank", "carol", "dave"]
    neon_pg.safe_psql_many(
        [f"CREATE ROLE {r} LOGIN PASSWORD 'pw'" for r in roles]
        + [f"GRANT {r} TO owner WITH ADMIN OPTION" for r in roles]
        + [
            f"ALTER ROLE erin SET {MARKER} = ''",
            f"ALTER ROLE frank SET {MARKER} = 'off'",
            # Database-scoped: doesn't mark.
            f"ALTER ROLE carol IN DATABASE postgres SET {MARKER} = 'personal'",
            # Another name with the marker's prefix: doesn't mark.
            f"ALTER ROLE dave SET {MARKER}s = 'personal'",
            # A database-wide row (setrole = 0) marks no role, and the session
            # value it gives the GUC doesn't matter.
            f"ALTER DATABASE postgres SET {MARKER} = 'personal'",
        ]
    )
    refused_marked(neon_pg, "owner", "ALTER ROLE erin PASSWORD 'x'", "erin")
    refused_marked(neon_pg, "owner", "ALTER ROLE frank PASSWORD 'x'", "frank")
    refused_marked(neon_pg, "erin", "ALTER ROLE CURRENT_USER PASSWORD 'x'", "erin")
    assert [marked(neon_pg, r) for r in roles] == [True, True, False, False]
    with neon_pg.cursor(user="owner", password="pw") as cur:
        for role in ["carol", "dave", '"Alice"', "bob"]:
            cur.execute(f"ALTER ROLE {role} PASSWORD 'pw'")
            cur.execute(f"ALTER ROLE {role} SET work_mem = '1MB'")
            cur.execute(f"ALTER ROLE {role} IN DATABASE postgres SET work_mem = '1MB'")
            cur.execute(f"GRANT grp TO {role}")
            cur.execute(f"REVOKE grp FROM {role}")
        cur.execute('ALTER ROLE "Alice" RENAME TO "Alice2"')
        cur.execute('DROP ROLE "Alice2"')
    with neon_pg.cursor(user="carol", password="pw") as cur:
        cur.execute("ALTER ROLE CURRENT_USER PASSWORD 'pw'")


@PG16_PLUS
def test_marked_role_marker_changes_refused_for_non_superusers(neon_pg: VanillaPostgres):
    """
    Changing the marker is refused to every non-superuser, for any role, even
    with a SET privilege on it granted by mistake (without one Postgres alone
    refuses most of these).
    """
    setup_marked(neon_pg)
    neon_pg.safe_psql_many(
        [
            f"GRANT SET, ALTER SYSTEM ON PARAMETER {MARKER} TO owner WITH GRANT OPTION",
            f"GRANT SET ON PARAMETER {MARKER} TO bob",
            "GRANT SET ON PARAMETER work_mem TO owner WITH GRANT OPTION",
        ]
    )
    as_owner = [
        f"ALTER ROLE bob SET {MARKER} = 'personal'",
        f"ALTER ROLE bob SET {MARKER} = ''",
        f"ALTER ROLE bob SET {MARKER} TO DEFAULT",
        f"ALTER ROLE bob RESET {MARKER}",
        f"ALTER USER bob SET {MARKER} = 'personal'",
        f"ALTER ROLE bob IN DATABASE postgres SET {MARKER} = 'personal'",
        f"ALTER ROLE bob IN DATABASE postgres RESET {MARKER}",
        "ALTER ROLE bob SET \"CHELABASE.MANAGED_ROLE\" = 'personal'",
        f"ALTER ROLE owner SET {MARKER} = 'personal'",
        f"ALTER ROLE CURRENT_USER SET {MARKER} = 'personal'",
        f"ALTER ROLE alice RESET {MARKER}",
        f"ALTER ROLE alice SET {MARKER} = 'other'",
        f"DO $$BEGIN EXECUTE 'ALTER ROLE bob SET {MARKER} = ''personal'''; END$$",
        f"GRANT SET ON PARAMETER {MARKER} TO bob",
        f"GRANT ALTER SYSTEM ON PARAMETER {MARKER} TO bob",
        f"GRANT SET, ALTER SYSTEM ON PARAMETER {MARKER} TO bob",
        f"GRANT ALL ON PARAMETER {MARKER} TO bob",
        f"GRANT SET ON PARAMETER work_mem, {MARKER} TO bob",
        'GRANT SET ON PARAMETER "Chelabase.Managed_Role" TO bob',
        f"REVOKE SET ON PARAMETER {MARKER} FROM bob",
        f"REVOKE ALTER SYSTEM ON PARAMETER {MARKER} FROM bob",
        f"REVOKE ALL ON PARAMETER {MARKER} FROM bob",
        f"REVOKE GRANT OPTION FOR SET ON PARAMETER {MARKER} FROM bob",
    ]
    for sql in as_owner:
        refusal(neon_pg, "owner", sql)
    # bob marking itself with its own (mistaken) SET privilege.
    refusal(neon_pg, "bob", f"ALTER ROLE CURRENT_USER SET {MARKER} = 'personal'")
    assert not marked(neon_pg, "bob")
    assert not marked(neon_pg, "owner")
    assert role_settings(neon_pg, "bob") == []
    assert role_settings(neon_pg, "alice") == [(0, [f"{MARKER}=personal"])]
    # ALTER ROLE ALL (no database) already needs a superuser.
    e = refusal(neon_pg, "owner", "ALTER ROLE ALL SET work_mem = '1MB'")
    assert e.diag.message_primary == "permission denied to alter setting", e.diag.message_primary
    refusal(neon_pg, "owner", f"ALTER ROLE ALL SET {MARKER} = 'personal'")


def test_marked_role_reset_all(neon_pg: VanillaPostgres):
    setup_marked(neon_pg)
    refused_marked(neon_pg, "owner", "ALTER ROLE alice RESET ALL")
    refused_marked(neon_pg, "owner", "ALTER ROLE alice IN DATABASE postgres RESET ALL")
    refused_marked(neon_pg, "alice", "ALTER ROLE CURRENT_USER RESET ALL")
    assert role_settings(neon_pg, "alice") == [(0, [f"{MARKER}=personal"])]
    # An unmarked role: unaffected.
    neon_pg.safe_psql_many(
        [
            "ALTER ROLE bob SET work_mem = '1MB'",
            "ALTER ROLE bob IN DATABASE postgres SET work_mem = '2MB'",
        ]
    )
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("ALTER ROLE bob RESET ALL")
        cur.execute("ALTER ROLE bob IN DATABASE postgres RESET ALL")
    assert role_settings(neon_pg, "bob") == []
    neon_pg.safe_psql("ALTER ROLE bob SET work_mem = '1MB'")
    with neon_pg.cursor(user="bob", password="pw") as cur:
        cur.execute("ALTER ROLE CURRENT_USER RESET ALL")
    assert role_settings(neon_pg, "bob") == []


def test_marked_role_superuser_untouched_and_unmarking_releases(neon_pg: VanillaPostgres):
    setup_marked(neon_pg)
    refused_marked(neon_pg, "owner", "ALTER ROLE alice PASSWORD 'x'")
    neon_pg.safe_psql_many(
        [
            "ALTER ROLE alice PASSWORD 'pw'",
            "ALTER ROLE alice CONNECTION LIMIT 5",
            "ALTER ROLE alice SET work_mem = '1MB'",
            "ALTER ROLE alice RESET work_mem",
            "ALTER ROLE alice IN DATABASE postgres SET work_mem = '1MB'",
            "ALTER ROLE alice IN DATABASE postgres RESET ALL",
            "GRANT grp TO alice",
            "REVOKE grp FROM alice",
            "GRANT alice TO grp",
            "REVOKE alice FROM grp",
            "ALTER GROUP grp ADD USER alice",
            "ALTER GROUP grp DROP USER alice",
            "CREATE ROLE s1 IN ROLE alice",
            "DROP ROLE s1",
            "ALTER ROLE alice RENAME TO alice2",
        ]
    )
    # The marker belongs to the role, not to its name.
    assert marked(neon_pg, "alice2")
    refused_marked(neon_pg, "owner", "ALTER ROLE alice2 PASSWORD 'x'", "alice2")
    neon_pg.safe_psql("ALTER ROLE alice2 RENAME TO alice")
    # A superuser unmarks: the role is released.
    neon_pg.safe_psql(f"ALTER ROLE alice RESET {MARKER}")
    assert not marked(neon_pg, "alice")
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("ALTER ROLE alice PASSWORD 'pw'")
        cur.execute("ALTER ROLE alice SET work_mem = '1MB'")
        cur.execute("GRANT grp TO alice")
        cur.execute("REVOKE grp FROM alice")
    # Marked again, guarded again; a superuser's RESET ALL unmarks too.
    neon_pg.safe_psql(f"ALTER ROLE alice SET {MARKER} = 'personal'")
    refused_marked(neon_pg, "owner", "ALTER ROLE alice PASSWORD 'x'")
    neon_pg.safe_psql("ALTER ROLE alice RESET ALL")
    assert not marked(neon_pg, "alice")
    # A superuser drops a marked role; its marker row goes with it.
    neon_pg.safe_psql(f"ALTER ROLE alice SET {MARKER} = 'personal'")
    neon_pg.safe_psql("DROP ROLE alice")
    assert neon_pg.safe_psql(
        "SELECT count(*) FROM pg_catalog.pg_db_role_setting"
        " WHERE setrole <> 0 AND setrole NOT IN (SELECT oid FROM pg_catalog.pg_roles)"
    ) == [(0,)]


def test_marked_role_unknown_names_are_not_marked(neon_pg: VanillaPostgres):
    setup_marked(neon_pg)
    refused_marked(neon_pg, "owner", "ALTER ROLE alice PASSWORD 'x'")
    with neon_pg.cursor(user="owner", password="pw") as cur:
        cur.execute("CREATE ROLE newcomer")
        cur.execute("CREATE ROLE newcomer2 IN ROLE grp")
        cur.execute("DROP ROLE IF EXISTS ghost")
        cur.execute("DROP ROLE newcomer, newcomer2")
    # A missing role is Postgres's own error, not the guard's.
    for sql in [
        "ALTER ROLE ghost PASSWORD 'x'",
        "ALTER ROLE ghost SET work_mem = '1MB'",
        "ALTER ROLE ghost RENAME TO ghost2",
        "DROP ROLE ghost",
        "GRANT grp TO ghost",
        "GRANT ghost TO grp",
    ]:
        with pytest.raises(UndefinedObject):
            run_as(neon_pg, "owner", sql)


@PG16_PLUS
def test_marked_role_guc_is_a_superuser_string(neon_pg: VanillaPostgres):
    rows = neon_pg.safe_psql(
        "SELECT context, vartype, boot_val, reset_val FROM pg_catalog.pg_settings"
        f" WHERE name = '{MARKER}'"
    )
    assert rows == [("superuser", "string", "", "")], (
        f"{MARKER} isn't defined as a PGC_SUSET string"
    )
    flags = neon_pg.safe_psql(f"SELECT pg_catalog.pg_settings_get_flags('{MARKER}')")[0][0]
    assert "NOT_IN_SAMPLE" in flags, flags
    setup_marked(neon_pg)
    e = refusal(neon_pg, "owner", f"SET {MARKER} = 'personal'")
    assert e.diag.message_primary == f'permission denied to set parameter "{MARKER}"', (
        e.diag.message_primary
    )


@PG16_PLUS
def test_marked_role_refusal_forwards_nothing(neon_pg: VanillaPostgres, patches: list[Any]):
    setup_marked(neon_pg)
    for user, statements in [("owner", OWNER_ON_MARKED), ("alice", MARKED_ON_ITSELF)]:
        for sql in statements:
            before = len(patches)
            refused_marked(neon_pg, user, sql)
            assert len(patches) == before, f"{sql}: forwarded {patches[before:]}"
    # Refused inside a savepoint that is rolled back to: the rest of the
    # transaction is forwarded, nothing of the refused statement.
    before = len(patches)
    with neon_pg.cursor(user="owner", password="pw", autocommit=False) as cur:
        cur.execute("CREATE ROLE kept")
        cur.execute("SAVEPOINT s")
        with pytest.raises(InsufficientPrivilege):
            cur.execute("ALTER ROLE alice PASSWORD 'x'")
        cur.execute("ROLLBACK TO SAVEPOINT s")
        cur.connection.commit()
    assert len(patches) == before + 1, patches[before:]
    body = patches[-1]
    assert "dbs" not in body, body
    assert [role["name"] for role in body["roles"]] == ["kept"], body
