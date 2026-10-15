from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import psycopg2
import pytest
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


def superuser_name(pg: VanillaPostgres) -> str:
    return pg.safe_psql("SELECT current_user")[0][0]


def test_a_customer_trigger_handed_to_a_superuser_is_not_the_guard(neon_pg: VanillaPostgres):
    """T5 m1: the guard's function must be a superuser's too, not only the trigger."""
    setup_owner(neon_pg)
    neon_pg.safe_psql("GRANT CREATE ON SCHEMA public TO owner")
    su = superuser_name(neon_pg)
    # Postgres lets the trigger's owner give it to any superuser (event_trigger.c).
    as_owner(
        neon_pg,
        "CREATE FUNCTION g2() RETURNS event_trigger LANGUAGE plpgsql AS $$BEGIN END$$;"
        "CREATE EVENT TRIGGER chelabase_schema_guard_ddl ON ddl_command_end EXECUTE FUNCTION g2();"
        "ALTER EVENT TRIGGER chelabase_schema_guard_ddl ENABLE ALWAYS;"
        f'ALTER EVENT TRIGGER chelabase_schema_guard_ddl OWNER TO "{su}";',
    )
    assert neon_pg.safe_psql(
        "SELECT r.rolsuper, t.evtenabled, p.proowner = 'owner'::regrole"
        " FROM pg_event_trigger t JOIN pg_roles r ON r.oid = t.evtowner"
        " JOIN pg_proc p ON p.oid = t.evtfoid WHERE t.evtname = 'chelabase_schema_guard_ddl'"
    ) == [(True, "A", True)], "the look-alike: superuser-owned, ALWAYS, the owner's function"
    as_owner(neon_pg, "CREATE DATABASE n3")
    assert state(neon_pg, "n3") == (True, None), "a customer's function: not the guard"
    as_owner(neon_pg, "ALTER DATABASE n3 ALLOW_CONNECTIONS false")
    as_owner(neon_pg, "ALTER DATABASE n3 ALLOW_CONNECTIONS true")


def test_is_template_default_and_a_missing_database(neon_pg: VanillaPostgres):
    """T5 m3: IS_TEMPLATE DEFAULT means false; Postgres' "does not exist" wins."""
    setup_owner(neon_pg)
    neon_pg.safe_psql(GUARD)
    as_owner(neon_pg, "CREATE DATABASE d1 WITH IS_TEMPLATE DEFAULT")
    assert state(neon_pg, "d1") == (False, ["neon.born_closed=on"])
    as_owner(neon_pg, "CREATE DATABASE d2 WITH IS_TEMPLATE false")
    assert state(neon_pg, "d2") == (False, ["neon.born_closed=on"])
    assert neon_pg.safe_psql(
        "SELECT bool_or(datistemplate) FROM pg_database WHERE datname IN ('d1', 'd2')"
    ) == [(False,)]
    for sql in [
        "ALTER DATABASE nosuch ALLOW_CONNECTIONS true",
        "ALTER DATABASE nosuch IS_TEMPLATE true",
        "ALTER DATABASE nosuch IS_TEMPLATE DEFAULT",
    ]:
        owner_refused(neon_pg, sql, 'database "nosuch" does not exist')


def test_an_open_user_template_counts_as_guarded(neon_pg: VanillaPostgres):
    """E-I2: on a protected branch an open user template carries the guard (RT3-5),
    so a session there, or a CREATE DATABASE from it, is treated as guarded even
    before the reconcile reached it. template1 isn't a user template."""
    setup_owner(neon_pg)
    neon_pg.safe_psql("CREATE DATABASE tpl OWNER owner TEMPLATE template0")
    neon_pg.safe_psql("ALTER DATABASE tpl IS_TEMPLATE true")
    neon_pg.safe_psql("CREATE DATABASE shut OWNER owner TEMPLATE template0")
    neon_pg.safe_psql("ALTER DATABASE shut ALLOW_CONNECTIONS false")
    # A session in the open template: born closed.
    as_owner(neon_pg, "CREATE DATABASE e1 TEMPLATE template0", dbname="tpl")
    assert state(neon_pg, "e1") == (False, ["neon.born_closed=on"]), "from the template"
    # The template named by CREATE DATABASE, from an unguarded database.
    as_owner(neon_pg, "CREATE DATABASE e2 TEMPLATE tpl")
    assert state(neon_pg, "e2") == (False, ["neon.born_closed=on"]), "TEMPLATE tpl"
    # Reopening an owner-closed database from the open template.
    owner_refused(neon_pg, "ALTER DATABASE shut ALLOW_CONNECTIONS true", dbname="tpl")
    owner_refused(neon_pg, "CREATE DATABASE e3 WITH ALLOW_CONNECTIONS true", dbname="tpl")
    assert state(neon_pg, "shut") == (False, None)
    # template1 (no guard here) and a closed template change nothing.
    as_owner(neon_pg, "CREATE DATABASE e4 TEMPLATE template0", dbname="template1")
    assert state(neon_pg, "e4") == (True, None), "template1 isn't a user template"
    neon_pg.safe_psql("ALTER DATABASE tpl ALLOW_CONNECTIONS false")
    as_owner(neon_pg, "CREATE DATABASE e5 TEMPLATE tpl")
    assert state(neon_pg, "e5") == (True, None), "a closed template isn't connectable"


# ---------------------------------------------------------------------------
# The invariant, exhaustively (F3; E-I2 is the second finding in this area):
#
#   every non-superuser path that can create or open a database on a protected
#   branch ends born closed or guarded.
#
# The extension sees only the session database's event triggers and the shared
# catalogs. A statement counts as made on a protected branch when the session's
# database carries the guard or is an open user template (datistemplate AND
# datallowconn, not template1: those carry the guard too, RT3-5), and a CREATE
# DATABASE also when its template is an open user template (U1). Then:
# - CREATE DATABASE with ALLOW_CONNECTIONS (any value) or IS_TEMPLATE true is
#   refused; otherwise it is born closed with the marker (IS_TEMPLATE false or
#   DEFAULT: not a template);
# - ALTER DATABASE ... ALLOW_CONNECTIONS / IS_TEMPLATE (any value) is refused, as
#   it is on a marked target from anywhere (RT3-5); CONNECTION LIMIT stays the
#   owner's;
# - a missing database or template: Postgres' "does not exist" comes first;
# - superusers are untouched; a member (no CREATEDB, owns nothing) is refused by
#   Postgres or the hook, and nothing changes;
# - a refused statement forwards nothing to the control plane.
# ---------------------------------------------------------------------------

MEMBER = "cb_m_0123456789abcdef0123456789abcdef"
SESSIONS = ["sg", "su", "otpl_g", "otpl_u"]
ROLES = ["superuser", "owner", MEMBER]
# Databases set up with the superuser-owned guard.
GUARDED = ["sg", "otpl_g", "tg"]
# (allow_connections, is_template, marked) at setup; all owned by "owner".
SETUP: dict[str, tuple[bool, bool, bool]] = {
    "sg": (True, False, False),  # guarded session database
    "su": (True, False, False),  # unguarded session database
    "otpl_g": (True, True, False),  # open user template, guarded
    "otpl_u": (True, True, False),  # open user template, not guarded yet
    "ctpl": (False, True, False),  # closed user template
    "tg": (True, False, False),  # ALTER targets: guarded,
    "tu": (True, False, False),  # unguarded,
    "tc": (False, False, False),  # closed by its owner,
    "tb": (False, False, True),  # born closed (marked),
    "t_otpl": (True, True, False),  # an open user template,
    "t_ctpl": (False, True, False),  # a closed user template
}
CREATE_TEMPLATES: list[str | None] = [None, "template0", "otpl_g", "otpl_u", "ctpl", "nosuch"]
CREATE_OPTIONS = [
    "",
    "ALLOW_CONNECTIONS true",
    "ALLOW_CONNECTIONS false",
    "ALLOW_CONNECTIONS DEFAULT",
    "IS_TEMPLATE true",
    "IS_TEMPLATE false",
    "IS_TEMPLATE DEFAULT",
]
ALTER_TARGETS = ["tg", "tu", "tc", "tb", "t_otpl", "t_ctpl", "nosuch"]
ALTER_OPTIONS = [
    "ALLOW_CONNECTIONS true",
    "ALLOW_CONNECTIONS false",
    "ALLOW_CONNECTIONS DEFAULT",
    "IS_TEMPLATE true",
    "IS_TEMPLATE false",
    "IS_TEMPLATE DEFAULT",
    "CONNECTION LIMIT 5",
]

# An expected outcome: ("error", needle or None for any error) or
# ("ok", (allow_connections, is_template, connection_limit, marked)).
Outcome = tuple[str, Any]


def setup_matrix(pg: VanillaPostgres) -> set[str]:
    """Creates the matrix's roles and databases; returns the open user templates."""
    pg.safe_psql("CREATE ROLE owner LOGIN CREATEDB PASSWORD 'pw' IN ROLE neon_superuser")
    pg.safe_psql(f"CREATE ROLE {MEMBER} LOGIN PASSWORD 'pw'")
    for db in SETUP:
        pg.safe_psql(f"CREATE DATABASE {db} OWNER owner TEMPLATE template0")
    for db in GUARDED:
        pg.safe_psql(GUARD, dbname=db)
    for db, (allow, template, marked) in SETUP.items():
        reset_db(pg, db, allow, template)
        if marked:
            pg.safe_psql(f"ALTER DATABASE {db} SET neon.born_closed = on")
    rows = pg.safe_psql(
        "SELECT datname FROM pg_database"
        " WHERE datistemplate AND datallowconn AND datname <> 'template1'"
    )
    return {r[0] for r in rows}


def reset_db(pg: VanillaPostgres, db: str, allow: bool, template: bool):
    pg.safe_psql(
        f"ALTER DATABASE {db} WITH ALLOW_CONNECTIONS {str(allow).lower()}"
        f" IS_TEMPLATE {str(template).lower()} CONNECTION LIMIT -1"
    )


def attrs(pg: VanillaPostgres, db: str) -> tuple[bool, bool, int, bool] | None:
    rows = pg.safe_psql(
        "SELECT d.datallowconn, d.datistemplate, d.datconnlimit,"
        " coalesce('neon.born_closed=on' = ANY (s.setconfig), false)"
        " FROM pg_database d LEFT JOIN pg_db_role_setting s"
        " ON s.setdatabase = d.oid AND s.setrole = 0"
        f" WHERE d.datname = '{db}'"
    )
    return tuple(rows[0]) if rows else None  # type: ignore[return-value]


def run_as(pg: VanillaPostgres, role: str, dbname: str, sql: str) -> str | None:
    """Runs sql as role in dbname; returns the error text, or None."""
    kwargs: dict[str, Any] = {"dbname": dbname}
    if role != "superuser":
        kwargs.update(user=role, password="pw")
    try:
        with pg.cursor(**kwargs) as cur:
            cur.execute(sql)
    except psycopg2.Error as e:
        return str(e)
    return None


def split_option(opt: str) -> tuple[str, str]:
    name, _, value = opt.rpartition(" ")
    return name, value


def protected(session: str, open_templates: set[str]) -> bool:
    return session in GUARDED or session in open_templates


def expect_create(
    role: str, session: str, template: str | None, opt: str, open_templates: set[str]
) -> Outcome:
    if role == MEMBER:
        return ("error", None)
    if template == "nosuch":
        return ("error", 'template database "nosuch" does not exist')
    name, value = split_option(opt)
    if role == "owner" and (protected(session, open_templates) or template in open_templates):
        if name == "ALLOW_CONNECTIONS" or (name == "IS_TEMPLATE" and value == "true"):
            return ("error", REFUSAL)
        return ("ok", (False, False, -1, True))
    allow = not (name == "ALLOW_CONNECTIONS" and value == "false")
    is_template = name == "IS_TEMPLATE" and value == "true"
    return ("ok", (allow, is_template, -1, False))


def expect_alter(
    role: str, session: str, target: str, opt: str, open_templates: set[str]
) -> Outcome:
    if target == "nosuch":
        return ("error", 'database "nosuch" does not exist')
    if role == MEMBER:
        return ("error", None)
    allow, template, marked = SETUP[target]
    name, value = split_option(opt)
    if name in ("ALLOW_CONNECTIONS", "IS_TEMPLATE") and role == "owner":
        if marked or protected(session, open_templates):
            return ("error", REFUSAL)
    limit = -1
    if name == "ALLOW_CONNECTIONS":
        allow = value != "false"  # DEFAULT is true (dbcommands.c)
    elif name == "IS_TEMPLATE":
        template = value == "true"  # DEFAULT is false
    else:
        limit = 5
    return ("ok", (allow, template, limit, marked))


def check(
    sql: str,
    expected: Outcome,
    err: str | None,
    got: tuple[bool, bool, int, bool] | None,
    before: tuple[bool, bool, int, bool] | None,
    forwarded: int,
) -> str | None:
    kind, value = expected
    if kind == "error":
        if err is None:
            return f"{sql}: expected an error ({value}), it ran; now {got}"
        if value is not None and value not in err:
            return f"{sql}: expected {value!r}, got {err.strip()!r}"
        if got != before:
            return f"{sql}: refused, but the database changed: {before} -> {got}"
        if forwarded:
            return f"{sql}: refused, but {forwarded} PATCH(es) were forwarded"
        return None
    if err is not None:
        return f"{sql}: expected {value}, got the error {err.strip()!r}"
    if got != value:
        return f"{sql}: expected {value}, got {got}"
    return None


def drop_db(pg: VanillaPostgres, db: str):
    row = attrs(pg, db)
    if row is None:
        return
    if row[1]:
        pg.safe_psql(f"ALTER DATABASE {db} IS_TEMPLATE false")
    pg.safe_psql(f"DROP DATABASE {db}")


@pytest.mark.parametrize("session", SESSIONS)
def test_create_database_invariant(neon_pg: VanillaPostgres, patches: list[Any], session: str):
    open_templates = setup_matrix(neon_pg)
    assert open_templates == {"otpl_g", "otpl_u", "t_otpl"}
    violations: list[str] = []
    cells = 0
    for role in ROLES:
        for template in CREATE_TEMPLATES:
            for opt in CREATE_OPTIONS:
                if template == "nosuch" and opt:
                    continue
                cells += 1
                db = f"c{cells}"
                # WITH comes first: CREATE DATABASE x WITH TEMPLATE t ALLOW_CONNECTIONS ...
                clauses = ([f"TEMPLATE {template}"] if template else []) + ([opt] if opt else [])
                sql = f"CREATE DATABASE {db}"
                sql += f" WITH {' '.join(clauses)}" if clauses else ""
                label = f"[{role} in {session}] {sql}"
                expected = expect_create(role, session, template, opt, open_templates)
                forwarded_before = len(patches)
                err = run_as(neon_pg, role, session, sql)
                problem = check(
                    label,
                    expected,
                    err,
                    attrs(neon_pg, db),
                    None,
                    len(patches) - forwarded_before,
                )
                if problem:
                    violations.append(problem)
                drop_db(neon_pg, db)
    assert not violations, f"{len(violations)} of {cells} cells:\n" + "\n".join(violations)


@pytest.mark.parametrize("session", SESSIONS)
def test_alter_database_invariant(neon_pg: VanillaPostgres, patches: list[Any], session: str):
    open_templates = setup_matrix(neon_pg)
    assert open_templates == {"otpl_g", "otpl_u", "t_otpl"}
    violations: list[str] = []
    cells = 0
    for role in ROLES:
        for target in ALTER_TARGETS:
            for opt in ALTER_OPTIONS:
                cells += 1
                sql = f"ALTER DATABASE {target} WITH {opt}"
                label = f"[{role} in {session}] {sql}"
                expected = expect_alter(role, session, target, opt, open_templates)
                before = attrs(neon_pg, target)
                forwarded_before = len(patches)
                err = run_as(neon_pg, role, session, sql)
                problem = check(
                    label,
                    expected,
                    err,
                    attrs(neon_pg, target),
                    before,
                    len(patches) - forwarded_before,
                )
                if problem:
                    violations.append(problem)
                if target in SETUP:
                    allow, template, _ = SETUP[target]
                    reset_db(neon_pg, target, allow, template)
    assert not violations, f"{len(violations)} of {cells} cells:\n" + "\n".join(violations)
