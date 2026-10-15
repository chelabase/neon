from __future__ import annotations

import json
import select
import time
from typing import TYPE_CHECKING, Any

import psycopg2
import pytest
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres
from psycopg2.extensions import make_dsn
from psycopg2.extras import LogicalReplicationConnection

if TYPE_CHECKING:
    from fixtures.neon_fixtures import NeonEnv, PgProtocol, VanillaPostgres

RT = "chelabase_realtime"


def rt_dsn(node: PgProtocol, **kw: Any) -> str:
    """chelabase_realtime's connection string. PgProtocol.conn_options adds
    `options=-cstatement_timeout=120s` to every connection, a setting the role may not send
    (T3 m1), so this one is built from the node's defaults without their options; options
    the caller passes are sent."""
    opts = {**node.default_options, "user": RT}
    opts.pop("options", None)
    opts.update(kw)
    return str(make_dsn(**{k: v for k, v in opts.items() if v is not None}))


def read_payload(conn, cur, timeout: float = 20.0) -> Any:
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = cur.read_message()
        if msg is not None:
            return msg.payload
        select.select([conn], [], [], 0.5)
    raise AssertionError("no message from chelabase_keys")


def read_one(conn, cur, timeout: float = 20.0) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(read_payload(conn, cur, timeout))
    return payload


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_keys_over_replication_and_restart(neon_simple_env: NeonEnv):
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")
    endpoint.safe_psql("CREATE ROLE chelabase_realtime LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    endpoint.safe_psql("CREATE TABLE t (id int PRIMARY KEY, v int)")
    conn = psycopg2.connect(rt_dsn(endpoint), connection_factory=LogicalReplicationConnection)
    cur = conn.cursor()
    cur.execute(
        "CREATE_REPLICATION_SLOT rt_t TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')"
    )
    cur.fetchall()
    cur.start_replication_expert("START_REPLICATION SLOT rt_t LOGICAL 0/0", decode=True)
    endpoint.safe_psql("INSERT INTO t VALUES (1, 0), (2, 0)")
    msg = read_one(conn, cur)
    assert msg["v"] == 1
    assert msg["changes"] == [
        {"rel": msg["changes"][0]["rel"], "s": "public", "t": "t", "op": "i", "k": [["1"], ["2"]]}
    ]
    assert (
        endpoint.safe_psql("SELECT count(*) FROM pg_replication_slots WHERE slot_name = 'rt_t'")[0][
            0
        ]
        == 1
    )
    endpoint.stop()
    endpoint.start()
    assert (
        endpoint.safe_psql("SELECT count(*) FROM pg_replication_slots WHERE slot_type = 'logical'")[
            0
        ][0]
        == 0
    )
    # The old walsender may end its stream (CopyDone) before its socket closes: read until
    # the connection breaks.
    broken = False
    deadline = time.time() + 20
    while not broken and not conn.closed and time.time() < deadline:
        try:
            cur.read_message()
            conn.poll()
        except psycopg2.Error:
            broken = True
        else:
            select.select([conn], [], [], 0.5)
    assert broken or conn.closed, "the replication connection must end with the compute"


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_xid_is_the_full_transaction_id(vanilla_pg: VanillaPostgres):
    vanilla_pg.configure(["wal_level = logical", "max_replication_slots = 4"])
    vanilla_pg.pg_bin.run_capture(["pg_resetwal", "-e", "1", "-D", str(vanilla_pg.pgdatadir)])
    vanilla_pg.start()
    # initdb ran in the C locale (SQL_ASCII), which chelabase_keys refuses (U4)
    vanilla_pg.safe_psql(
        "CREATE DATABASE x8 TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
    )
    vanilla_pg.default_options["dbname"] = "x8"
    vanilla_pg.safe_psql("CREATE TABLE xt (id int PRIMARY KEY)")
    vanilla_pg.safe_psql("SELECT pg_create_logical_replication_slot('epoch', 'chelabase_keys')")
    with vanilla_pg.cursor(autocommit=False) as cur:
        cur.execute("INSERT INTO xt VALUES (1)")
        cur.execute("SELECT pg_current_xact_id()::text")
        row = cur.fetchone()
        assert row is not None
        xid = int(row[0])
        cur.connection.commit()
    assert xid >= 2**32, f"the epoch must be above 0: {xid}"
    rows = vanilla_pg.safe_psql("SELECT data FROM pg_logical_slot_get_changes('epoch', NULL, NULL)")
    assert [json.loads(r[0])["xid"] for r in rows] == [xid]


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
@pytest.mark.parametrize(
    "encoding, schema, table, key",
    [("LATIN1", "sché", "tâb", "café"), ("EUC_JP", "スキ", "表", "日本")],
    ids=["LATIN1", "EUC_JP"],
)
def test_keys_and_names_arrive_as_utf8(
    vanilla_pg: VanillaPostgres, encoding: str, schema: str, table: str, key: str
):
    """U4: over the walsender, as realtime reads it, every string of a message is UTF-8
    whatever the database encoding (single-byte LATIN1, multi-byte EUC_JP)."""
    vanilla_pg.configure(["wal_level = logical", "max_replication_slots = 4"])
    vanilla_pg.start()
    vanilla_pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    vanilla_pg.safe_psql(
        f"CREATE DATABASE enc TEMPLATE template0 ENCODING '{encoding}' LC_COLLATE 'C' LC_CTYPE 'C'"
    )
    vanilla_pg.safe_psql(f'CREATE SCHEMA "{schema}"', dbname="enc")
    vanilla_pg.safe_psql(f'CREATE TABLE "{schema}"."{table}" (id text PRIMARY KEY)', dbname="enc")
    conn = psycopg2.connect(
        rt_dsn(vanilla_pg, dbname="enc"), connection_factory=LogicalReplicationConnection
    )
    try:
        cur = conn.cursor()
        cur.execute(
            "CREATE_REPLICATION_SLOT rt_u TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')"
        )
        cur.fetchall()
        cur.start_replication_expert("START_REPLICATION SLOT rt_u LOGICAL 0/0", decode=False)
        vanilla_pg.safe_psql(f'INSERT INTO "{schema}"."{table}" VALUES (\'{key}\')', dbname="enc")
        raw: bytes = read_payload(conn, cur)
    finally:
        # a streaming walsender whose client never confirms holds up the fast shutdown
        conn.close()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    assert text is not None, f"not UTF-8: {raw!r}"
    change = json.loads(text)["changes"][0]
    assert (change["s"], change["t"], change["k"]) == (schema, table, [[key]])


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_a_sql_ascii_database_is_refused_at_slot_creation(vanilla_pg: VanillaPostgres):
    """U4: SQL_ASCII has no encoding to convert from; the plugin refuses it when it starts,
    so realtime sees the database as not live (and no slot is left)."""
    vanilla_pg.configure(["wal_level = logical", "max_replication_slots = 4"])
    vanilla_pg.start()
    vanilla_pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    vanilla_pg.safe_psql(
        "CREATE DATABASE ascii_db TEMPLATE template0 ENCODING 'SQL_ASCII' LC_COLLATE 'C' LC_CTYPE 'C'"
    )
    conn = psycopg2.connect(
        rt_dsn(vanilla_pg, dbname="ascii_db"), connection_factory=LogicalReplicationConnection
    )
    cur = conn.cursor()
    with pytest.raises(psycopg2.Error) as e:
        cur.execute(
            "CREATE_REPLICATION_SLOT rt_a TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')"
        )
    assert 'chelabase_keys: database encoding "SQL_ASCII" can\'t be converted to UTF-8' in str(
        e.value
    )
    assert vanilla_pg.safe_psql("SELECT count(*) FROM pg_replication_slots")[0][0] == 0
