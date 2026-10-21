from __future__ import annotations

import json
import os
import re
import select
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import psycopg2
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres
from psycopg2.extensions import make_dsn
from psycopg2.extras import LogicalReplicationConnection

if TYPE_CHECKING:
    from fixtures.neon_fixtures import VanillaPostgres

# W9 edges of chelabase_keys' streaming beside test_chelabase_keys.py: many streamed
# transactions in progress at once in one walsender, most of them rolled back.

RT = "chelabase_realtime"
DB = "w9c"
PAD_SQL = "(SELECT string_agg(md5(g::text || ':' || i), '') FROM generate_series(1, 56) i)"
CONTEXT_LINE = re.compile(r"level: (\d+); (.+?): \d+ total in \d+ blocks;.*?(\d+) used")
MORE_LINE = re.compile(r"level: (\d+); \d+ more child contexts containing .*?(\d+) used")


def read_one(conn, cur, timeout: float = 20.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = cur.read_message()
        if msg is not None:
            payload: dict[str, Any] = json.loads(msg.payload)
            return payload
        select.select([conn], [], [], 0.5)
    raise AssertionError("no message from chelabase_keys")


def decoding_context_used(pg: VanillaPostgres, pid: int) -> int:
    """Bytes used by the walsender's "Logical decoding context" subtree, from a
    pg_log_backend_memory_contexts dump in the server log."""
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
        if m is not None:
            level, name, n = int(m.group(1)), m.group(2), int(m.group(3))
        else:
            more = MORE_LINE.search(line)
            if more is None:
                continue
            level, name, n = int(more.group(1)), "", int(more.group(2))
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


def start_walsender(pg: VanillaPostgres, slot: str):
    """A logical-decoding server with a UTF-8 database, and chelabase_realtime's
    walsender (logical_decoding_work_mem = 64kB as a role setting, as RT1 sets it)
    streaming `slot`."""
    pg.configure(["wal_level = logical", "max_replication_slots = 8", "max_wal_senders = 8"])
    pg.start()
    pg.safe_psql(
        f"CREATE DATABASE {DB} TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
    )
    pg.default_options["dbname"] = DB
    pg.safe_psql("CREATE TABLE big (id int PRIMARY KEY, pad text)")
    pg.safe_psql("CREATE TABLE other (id int PRIMARY KEY, pad text)")
    pg.safe_psql("CREATE TABLE marker (id int PRIMARY KEY)")
    pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    pg.safe_psql(f"ALTER ROLE {RT} SET logical_decoding_work_mem = '64kB'")
    # the role may not send options (T3 m1): the fixture's statement_timeout is dropped
    opts = {**pg.default_options, "user": RT, "dbname": DB}
    opts.pop("options", None)
    conn = psycopg2.connect(
        str(make_dsn(**{k: v for k, v in opts.items() if v is not None})),
        connection_factory=LogicalReplicationConnection,
    )
    cur = conn.cursor()
    cur.execute(
        f"CREATE_REPLICATION_SLOT {slot} TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')"
    )
    cur.fetchall()
    cur.start_replication_expert(f"START_REPLICATION SLOT {slot} LOGICAL 0/0", decode=True)
    return conn, cur


def wait_stream_txns(pg: VanillaPostgres, slot: str, at_least: int) -> tuple[int, int]:
    """(stream_txns, spill_txns) of the slot once it has streamed `at_least`
    transactions, or after 20 s (the walsender reports its stats as it goes)."""
    deadline = time.time() + 20
    while True:
        rows = pg.safe_psql(
            "SELECT stream_txns, spill_txns FROM pg_stat_replication_slots "
            f"WHERE slot_name = '{slot}'"
        )
        stats = (int(rows[0][0]), int(rows[0][1])) if rows else (0, 0)
        if stats[0] >= at_least or time.time() > deadline:
            return stats
        time.sleep(0.2)


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_concurrent_streamed_transactions_free_their_state(vanilla_pg: VanillaPostgres):
    """RT4-13 with many streamed xids at once: four large transactions open together in
    every round, three rolled back and one committed; the walsender writes only the
    committed one's message and its decoding context stays flat."""
    conn, cur = start_walsender(vanilla_pg, "rt_c")
    writers = [vanilla_pg.connect(autocommit=False) for _ in range(4)]
    warmup, rounds, rows = 5, 30, 200
    messages: list[dict[str, Any]] = []
    try:
        pid = vanilla_pg.safe_psql(
            "SELECT active_pid FROM pg_replication_slots WHERE slot_name = 'rt_c'"
        )[0][0]
        before = 0
        for i in range(rounds):
            # the four transactions' changes interleave in the WAL, a few rows at a time
            for part in range(4):
                for j, w in enumerate(writers):
                    first = i * 10000 + j * 1000 + part * (rows // 4) + 1
                    last = first + rows // 4 - 1
                    with w.cursor() as c:
                        c.execute(
                            f"INSERT INTO big SELECT g, {PAD_SQL} "
                            f"FROM generate_series({first}, {last}) g"
                        )
            keep = i % 4
            for j, w in enumerate(writers):
                if j != keep:
                    w.rollback()
            writers[keep].commit()
            with vanilla_pg.cursor() as c:
                c.execute(f"INSERT INTO marker VALUES ({i})")
            messages.append(read_one(conn, cur))
            messages.append(read_one(conn, cur))
            if i + 1 == warmup:
                before = decoding_context_used(vanilla_pg, pid)
        after = decoding_context_used(vanilla_pg, pid)

        # every large transaction, committed or rolled back, is streamed, none spilled
        stats = wait_stream_txns(vanilla_pg, "rt_c", 4 * rounds)
        assert stats[0] >= 4 * rounds and stats[1] == 0, stats
        assert [[(ch["t"], ch["op"]) for ch in m["changes"]] for m in messages] == [
            [("big", "c")],
            [("marker", "i")],
        ] * rounds
        assert after - before <= 8192, (
            f"the decoding context grew from {before} to {after} bytes over "
            f"{rounds - warmup} rounds"
        )
    finally:
        for w in writers:
            w.close()
        conn.close()


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_a_subtransaction_streamed_while_it_ran_keeps_its_relation(vanilla_pg: VanillaPostgres):
    """W9: a subtransaction's changes streamed by the walsender while it runs, then
    rolled back (ROLLBACK TO), leave its relation in the committed transaction's
    message: an extra refetch, never a lost one."""
    conn, cur = start_walsender(vanilla_pg, "rt_k")
    w = vanilla_pg.connect(autocommit=False)
    try:
        with w.cursor() as c:
            c.execute("INSERT INTO big VALUES (1, 'x')")
            c.execute("SAVEPOINT p")
            c.execute(
                f"INSERT INTO other SELECT g, {PAD_SQL} FROM generate_series(1, 900) g"
            )
        # another commit flushes the WAL, the open transaction's changes included; the
        # walsender decodes them and streams them past 64kB while they still run
        vanilla_pg.safe_psql("INSERT INTO marker VALUES (1)")
        assert [(ch["t"], ch["op"]) for ch in read_one(conn, cur)["changes"]] == [("marker", "i")]
        stats = wait_stream_txns(vanilla_pg, "rt_k", 1)
        assert stats[0] >= 1, f"the open transaction must be streamed before the rollback: {stats}"
        with w.cursor() as c:
            c.execute("ROLLBACK TO p")
            c.execute("INSERT INTO big VALUES (2, 'y')")
        w.commit()
        msg = read_one(conn, cur)
        assert [(ch["t"], ch["op"]) for ch in msg["changes"]] == [("big", "c"), ("other", "c")], msg
    finally:
        w.close()
        conn.close()
