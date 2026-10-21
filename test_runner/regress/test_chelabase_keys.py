from __future__ import annotations

import json
import os
import re
import select
import time
from pathlib import Path
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


# ---- W9: streaming of large transactions ----

STREAM_DB = "w9"

# 1792 bytes of hex that don't compress: a row stays under the TOAST threshold, so
# every change of a large transaction can be streamed as soon as it is decoded
PAD_SQL = "(SELECT string_agg(md5(g::text || ':' || i), '') FROM generate_series(1, 56) i)"


def start_logical(vanilla_pg: VanillaPostgres) -> None:
    """A logical-decoding server with a UTF-8 database (initdb ran in the C locale,
    SQL_ASCII, which chelabase_keys refuses), the default database of every
    connection."""
    vanilla_pg.configure(
        ["wal_level = logical", "max_replication_slots = 8", "max_wal_senders = 8"]
    )
    vanilla_pg.start()
    vanilla_pg.safe_psql(
        f"CREATE DATABASE {STREAM_DB} TEMPLATE template0 ENCODING 'UTF8' "
        "LC_COLLATE 'C' LC_CTYPE 'C'"
    )
    vanilla_pg.default_options["dbname"] = STREAM_DB
    vanilla_pg.safe_psql("CREATE TABLE big (id int PRIMARY KEY, pad text)")
    vanilla_pg.safe_psql("CREATE TABLE marker (id int PRIMARY KEY)")


def insert_big_sql(first: int, rows: int) -> str:
    last = first + rows - 1
    return f"INSERT INTO big SELECT g, {PAD_SQL} FROM generate_series({first}, {last}) g"


def slot_stats(pg: VanillaPostgres, slot: str) -> dict[str, int]:
    rows = pg.safe_psql(
        "SELECT total_txns, stream_txns, spill_txns FROM pg_stat_replication_slots "
        f"WHERE slot_name = '{slot}'"
    )
    if not rows:
        return {"total_txns": 0, "stream_txns": 0, "spill_txns": 0}
    total, stream, spill = rows[0]
    return {"total_txns": total, "stream_txns": stream, "spill_txns": spill}


def wait_slot_stats(pg: VanillaPostgres, slot: str, total_txns: int) -> dict[str, int]:
    """The slot's stats once it has decoded at least `total_txns` transactions (the
    decoder reports them as it goes)."""
    deadline = time.time() + 20
    stats = slot_stats(pg, slot)
    while stats["total_txns"] < total_txns and time.time() < deadline:
        time.sleep(0.2)
        stats = slot_stats(pg, slot)
    return stats


def replication_conn(pg: VanillaPostgres, user: str, slot: str):
    conn = psycopg2.connect(
        rt_dsn(pg, user=user, dbname=STREAM_DB), connection_factory=LogicalReplicationConnection
    )
    cur = conn.cursor()
    cur.execute(
        f"CREATE_REPLICATION_SLOT {slot} TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')"
    )
    cur.fetchall()
    return conn, cur


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_role_setting_streams_in_the_walsender(vanilla_pg: VanillaPostgres):
    """W9: a database walsender applies chelabase_realtime's role setting
    (logical_decoding_work_mem = 64kB, as RT1 sets it) and the plugin streams a
    transaction past it, reporting each relation as "c", without spilling; a
    replication login without the setting (64MB) decodes the same transaction at its
    commit, with keys."""
    start_logical(vanilla_pg)
    vanilla_pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    # a role setting, never a startup option: the role may not send options (T3 m1)
    vanilla_pg.safe_psql(f"ALTER ROLE {RT} SET logical_decoding_work_mem = '64kB'")
    vanilla_pg.safe_psql("CREATE ROLE ctl_login LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    # "rt_" slot names are reserved for chelabase_realtime (round 3)
    ctl_conn, ctl_cur = replication_conn(vanilla_pg, "ctl_login", "ctl_s")
    rt_conn, rt_cur = replication_conn(vanilla_pg, RT, "rt_s")
    try:
        # (chelabase_realtime's walsender refuses SQL such as SHOW, round 3: the setting
        # shows in how it decodes)
        rt_cur.start_replication_expert("START_REPLICATION SLOT rt_s LOGICAL 0/0", decode=True)
        ctl_cur.start_replication_expert("START_REPLICATION SLOT ctl_s LOGICAL 0/0", decode=True)
        # ~1.6 MB in one transaction: past 64kB, far under 64MB; 900 keys stay under
        # max_keys_per_table (1000), so a commit-time decoding lists them
        vanilla_pg.safe_psql(insert_big_sql(1, 900))

        msg = read_one(rt_conn, rt_cur)
        changes = msg["changes"]
        assert [(c["t"], c["op"]) for c in changes] == [("big", "c")], (
            f"a streamed transaction reports its relations as c: {json.dumps(msg)[:300]}"
        )
        assert changes == [{"rel": changes[0]["rel"], "s": "public", "t": "big", "op": "c"}]
        rt_stats = wait_slot_stats(vanilla_pg, "rt_s", 1)
        assert rt_stats["stream_txns"] > 0, f"the transaction must be streamed: {rt_stats}"
        assert rt_stats["spill_txns"] == 0, f"a streamed transaction doesn't spill: {rt_stats}"

        ctl = read_one(ctl_conn, ctl_cur)
        assert [(c["t"], c["op"], len(c["k"])) for c in ctl["changes"]] == [("big", "i", 900)]
        assert ctl["xid"] == msg["xid"] and ctl["lsn"] == msg["lsn"]
        ctl_stats = wait_slot_stats(vanilla_pg, "ctl_s", 1)
        assert ctl_stats["stream_txns"] == 0 and ctl_stats["spill_txns"] == 0, ctl_stats
    finally:
        # a streaming walsender whose client never confirms holds up the fast shutdown
        rt_conn.close()
        ctl_conn.close()


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_a_streamed_transaction_cut_by_a_crash_writes_nothing(vanilla_pg: VanillaPostgres):
    """RT4-13: a transaction in progress at a crash is streamed when its changes are
    decoded, then aborted implicitly (ReorderBufferAbortOld, at the next running-xacts
    record): it writes nothing, and the next transaction's message holds only its own
    relation."""
    start_logical(vanilla_pg)
    # a persistent slot: it outlives the crash (the plugin's own suite uses them too)
    vanilla_pg.safe_psql("SELECT pg_create_logical_replication_slot('crash', 'chelabase_keys')")
    cut = vanilla_pg.connect(autocommit=False)
    try:
        with cut.cursor() as cur:
            cur.execute(insert_big_sql(1, 900))
        # the open transaction's WAL reaches the disk (a checkpoint flushes it)
        vanilla_pg.safe_psql("CHECKPOINT")
        vanilla_pg.pg_bin.run_capture(
            ["pg_ctl", "-w", "-D", str(vanilla_pg.pgdatadir), "-m", "immediate", "stop"]
        )
        vanilla_pg.running = False
    finally:
        try:
            cut.close()
        except psycopg2.Error:
            pass
    vanilla_pg.start()
    # the running-xacts record that aborts the cut transaction for the decoder
    vanilla_pg.safe_psql("SELECT pg_log_standby_snapshot()")
    vanilla_pg.safe_psql("INSERT INTO marker VALUES (1)")
    with vanilla_pg.cursor() as cur:
        cur.execute("SET logical_decoding_work_mem = '64kB'")
        cur.execute("SELECT data FROM pg_logical_slot_get_changes('crash', NULL, NULL)")
        rows = [json.loads(r[0]) for r in cur.fetchall()]
    stats = slot_stats(vanilla_pg, "crash")
    assert stats["stream_txns"] > 0, f"the cut transaction must be streamed: {stats}"
    assert [[(c["t"], c["op"], c.get("k")) for c in m["changes"]] for m in rows] == [
        [("marker", "i", [["1"]])]
    ], f"only the marker's message: {rows}"
    vanilla_pg.safe_psql("SELECT pg_drop_replication_slot('crash')")


# One context's line in a pg_log_backend_memory_contexts dump, and the summary line of the
# children past the first 100 of a parent.
CONTEXT_LINE = re.compile(r"level: (\d+); (.+?): \d+ total in \d+ blocks;.*?(\d+) used")
MORE_LINE = re.compile(r"level: (\d+); \d+ more child contexts containing .*?(\d+) used")


def decoding_context_used(pg: VanillaPostgres, pid: int) -> int:
    """Bytes used by the walsender's logical decoding context and everything under it
    (the plugin's own contexts, the reorder buffer, the snapshot builder), read from a
    pg_log_backend_memory_contexts dump in the server log (default log_line_prefix
    '%m [%p] ')."""
    log = Path(pg.pgdatadir) / "pg.log"
    start = os.path.getsize(log)
    assert pg.safe_psql(f"SELECT pg_log_backend_memory_contexts({pid})")[0][0] is True
    tag = f"[{pid}] "
    deadline = time.time() + 20
    lines: list[str] = []
    while time.time() < deadline:
        with open(log, encoding="utf-8", errors="replace") as f:
            f.seek(start)
            lines = [line for line in f.read().splitlines() if tag in line]
        if any("Grand total:" in line for line in lines):
            break
        time.sleep(0.2)
    else:
        raise AssertionError(f"no memory context dump of the walsender {pid}")
    used = 0
    base_level = None
    for line in lines:
        m = CONTEXT_LINE.search(line)
        level, name, n = (int(m.group(1)), m.group(2), int(m.group(3))) if m else (0, "", 0)
        if m is None:
            more = MORE_LINE.search(line)
            if more is None:
                continue
            level, n = int(more.group(1)), int(more.group(2))
        if base_level is None:
            if name == "Logical decoding context":
                base_level = level
                used += n
            continue
        if level <= base_level:
            break
        used += n
    assert base_level is not None, "no logical decoding context in the walsender's dump"
    return used


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_a_long_walsender_session_keeps_the_plugin_memory_flat(vanilla_pg: VanillaPostgres):
    """RT4-13: the per-transaction state of streamed transactions is freed at every end
    (commit and top-level abort), so a walsender that streams transaction after
    transaction keeps a flat decoding context."""
    start_logical(vanilla_pg)
    vanilla_pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    vanilla_pg.safe_psql(f"ALTER ROLE {RT} SET logical_decoding_work_mem = '64kB'")
    conn, cur = replication_conn(vanilla_pg, RT, "rt_m")
    warmup, rounds, rows = 10, 60, 200
    messages: list[dict[str, Any]] = []
    try:
        cur.start_replication_expert("START_REPLICATION SLOT rt_m LOGICAL 0/0", decode=True)
        pid = vanilla_pg.safe_psql(
            "SELECT active_pid FROM pg_replication_slots WHERE slot_name = 'rt_m'"
        )[0][0]
        before = 0
        with vanilla_pg.cursor(autocommit=False) as w:
            for i in range(rounds):
                # ~360 kB committed, ~360 kB rolled back, then a small marker; each
                # round ends with the marker's message, so the decoder is idle after it
                w.execute(insert_big_sql(i * 1000 + 1, rows))
                w.connection.commit()
                w.execute(insert_big_sql(i * 1000 + 500, rows))
                w.connection.rollback()
                w.execute(f"INSERT INTO marker VALUES ({i})")
                w.connection.commit()
                messages.append(read_one(conn, cur))
                messages.append(read_one(conn, cur))
                if i + 1 == warmup:
                    before = decoding_context_used(vanilla_pg, pid)
        after = decoding_context_used(vanilla_pg, pid)

        stats = wait_slot_stats(vanilla_pg, "rt_m", 2 * rounds)
        assert stats["stream_txns"] >= 2 * rounds, (
            f"every large transaction, committed or rolled back, is streamed: {stats}"
        )
        assert stats["spill_txns"] == 0, stats
        assert [[(c["t"], c["op"]) for c in m["changes"]] for m in messages] == [
            [("big", "c")],
            [("marker", "i")],
        ] * rounds
        # a leak of even one small allocation per streamed transaction (100 of them
        # after the warm-up) shows; a flat context moves by a few bytes at most
        assert after - before <= 8192, (
            f"the decoding context grew from {before} to {after} bytes over "
            f"{rounds - warmup} rounds"
        )
    finally:
        conn.close()
