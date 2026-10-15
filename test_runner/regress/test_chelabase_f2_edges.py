"""Edge cases added by the F2 coder beyond the RED set: chelabase_realtime's "options"
startup parameter (T3 m1) and chelabase_keys' per-column keys (T2 I1) and option grammar
(T2 m1)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import psycopg2
import pytest
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres
from psycopg2.extensions import make_dsn
from psycopg2.extras import LogicalReplicationConnection

if TYPE_CHECKING:
    from fixtures.neon_fixtures import VanillaPostgres

pytestmark = run_only_on_postgres([PgVersion.V17], "chelabase_keys and the role are v17 only")
RT = "chelabase_realtime"


def utf8_db(pg: VanillaPostgres) -> VanillaPostgres:
    pg.configure(["wal_level = logical", "max_replication_slots = 4"])
    pg.start()
    # initdb ran in the C locale (SQL_ASCII), which chelabase_keys refuses
    pg.safe_psql(
        "CREATE DATABASE u8 TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
    )
    pg.default_options["dbname"] = "u8"
    return pg


def rt_dsn(pg: VanillaPostgres, **kw: Any) -> str:
    opts = {**pg.default_options, "user": RT, **kw}
    if "options" not in kw:
        opts.pop("options", None)
    return str(make_dsn(**{k: v for k, v in opts.items() if v is not None}))


@pytest.mark.parametrize(
    "options, name",
    [
        # allowed as a startup key, but "options" may carry nothing at all
        ("-c application_name=rt", "application_name"),
        ("-c client_encoding=UTF8", "client_encoding"),
        ("--wal_sender_timeout=0", "wal_sender_timeout"),
        ("-cwal_sender_timeout=0", "wal_sender_timeout"),
        ("-c wal-sender-timeout=0", "wal_sender_timeout"),
        ("-B 10", "-B"),
    ],
)
def test_realtime_options_carry_nothing(vanilla_pg: VanillaPostgres, options: str, name: str):
    pg = utf8_db(vanilla_pg)
    pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    with pytest.raises(psycopg2.OperationalError) as e:
        psycopg2.connect(
            rt_dsn(pg, options=options), connection_factory=LogicalReplicationConnection
        )
    assert f'role "{RT}" may not set parameter "{name}"' in str(e.value), str(e.value)


def test_realtime_blank_options_set_nothing(vanilla_pg: VanillaPostgres):
    pg = utf8_db(vanilla_pg)
    pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    conn = psycopg2.connect(
        rt_dsn(pg, options="  "), connection_factory=LogicalReplicationConnection
    )
    try:
        cur = conn.cursor()
        cur.execute("IDENTIFY_SYSTEM")
        assert len(cur.fetchall()) == 1
    finally:
        conn.close()


def changes(pg: VanillaPostgres, *opts: str) -> list[dict[str, Any]]:
    args = "".join(f", '{o}'" for o in opts)
    rows = pg.safe_psql(f"SELECT data FROM pg_logical_slot_get_changes('k', NULL, NULL{args})")
    return [json.loads(r[0]) for r in rows]


def ops(msg: dict[str, Any], short: dict[str, str]) -> list[tuple[str, list[list[str]]]]:
    def s(v: str) -> str:
        return short.get(v, v)

    return [(c["op"], [[s(v) for v in k] for k in c["k"]]) for c in msg["changes"]]


def test_keys_with_two_unchanged_out_of_line_key_columns(vanilla_pg: VanillaPostgres):
    """T2 I1 with two out-of-line key columns: each unchanged one comes from the old key."""
    pg = utf8_db(vanilla_pg)
    pg.safe_psql("SELECT pg_create_logical_replication_slot('k', 'chelabase_keys')")
    pg.safe_psql("CREATE TABLE t2 (a text, b text, c int, PRIMARY KEY (a, b, c))")
    pg.safe_psql("ALTER TABLE t2 ALTER COLUMN a SET STORAGE EXTERNAL")
    pg.safe_psql("ALTER TABLE t2 ALTER COLUMN b SET STORAGE EXTERNAL")
    pg.safe_psql("INSERT INTO t2 VALUES (repeat('x', 2500), repeat('y', 2500), 1)")
    pg.safe_psql("UPDATE t2 SET c = 2")
    pg.safe_psql("UPDATE t2 SET a = repeat('z', 2500)")
    short = {"x" * 2500: "X", "y" * 2500: "Y", "z" * 2500: "Z"}
    assert [ops(m, short) for m in changes(pg)] == [
        [("i", [["X", "Y", "1"]])],
        [("i", [["X", "Y", "2"]]), ("d", [["X", "Y", "1"]])],
        [("i", [["Z", "Y", "2"]]), ("d", [["X", "Y", "2"]])],
    ]


def test_option_digits_with_leading_zeros(vanilla_pg: VanillaPostgres):
    """T2 m1: the grammar is decimal digits; leading zeros are digits."""
    pg = utf8_db(vanilla_pg)
    pg.safe_psql("SELECT pg_create_logical_replication_slot('k', 'chelabase_keys')")
    pg.safe_psql("CREATE TABLE z (id int PRIMARY KEY)")
    pg.safe_psql("INSERT INTO z VALUES (1)")
    assert [m.get("all") for m in changes(pg, "max_tables", "0001")] == [None]
    with pytest.raises(psycopg2.Error) as e:
        changes(pg, "max_tables", "")
    assert 'option "max_tables" must be an integer' in str(e.value)
