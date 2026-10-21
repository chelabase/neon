"""
F3 (K2 audit): the flip point of max_message_bytes for a streamed transaction.

A streamed transaction's budget (chelabase_keys.c `stream_add_rel`) is the longest message
frame, `{"v":1,"lsn":"FFFFFFFF/FFFFFFFF","xid":18446744073709551615,"changes":[]}`, plus
each listed relation's `{"rel":…,"s":…,"t":…,"op":"c"}` and the commas between them; past
max_message_bytes the transaction is "all". So with S = that budget for a given
transaction, max_message_bytes = S lists every relation and S - 1 gives "all".
"""

from __future__ import annotations

import json
from contextlib import closing
from typing import TYPE_CHECKING

from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres

if TYPE_CHECKING:
    from fixtures.neon_fixtures import VanillaPostgres
    from psycopg2.extensions import cursor as PgCursor

DB = "w9lim"
SLOT = "lim"
TABLES = 300
SCHEMA = '"' * 63
FRAME_MAX = len('{"v":1,"lsn":"FFFFFFFF/FFFFFFFF","xid":18446744073709551615,"changes":[]}')
CHANGES_OPEN = '"changes":['


def table(i: int) -> str:
    return '"' * 55 + str(i)


def peek(cur: PgCursor, max_message_bytes: int) -> list[str]:
    cur.execute(
        "SELECT data FROM pg_logical_slot_peek_changes(%s, NULL, NULL, "
        "'max_tables', '1000', 'max_message_bytes', %s)",
        (SLOT, str(max_message_bytes)),
    )
    return [str(r[0]) for r in cur.fetchall()]


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_streamed_max_message_bytes_flip_point(vanilla_pg: VanillaPostgres):
    vanilla_pg.configure(["wal_level = logical", "max_replication_slots = 8"])
    vanilla_pg.start()
    vanilla_pg.safe_psql(
        f"CREATE DATABASE {DB} TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
    )
    vanilla_pg.default_options["dbname"] = DB

    with closing(vanilla_pg.connect()) as conn:
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SET logical_decoding_work_mem = '64kB'")
        cur.execute("SET debug_logical_replication_streaming = immediate")
        cur.execute("DO $$ BEGIN EXECUTE format('CREATE SCHEMA %I', repeat('\"', 63)); END $$")
        cur.execute(
            f"DO $$ BEGIN FOR i IN 1..{TABLES} LOOP "
            "EXECUTE format('CREATE TABLE %I.%I (id int)', repeat('\"', 63), "
            "repeat('\"', 55) || i); END LOOP; END $$"
        )
        cur.execute(
            "SELECT 'created' FROM pg_create_logical_replication_slot(%s, 'chelabase_keys')",
            (SLOT,),
        )
        # One transaction touching every table, in table order.
        cur.execute(
            f"DO $$ BEGIN FOR i IN 1..{TABLES} LOOP "
            "EXECUTE format('INSERT INTO %I.%I VALUES (1)', repeat('\"', 63), "
            "repeat('\"', 55) || i); END LOOP; END $$"
        )

        listed = peek(cur, 16777216)
        assert len(listed) == 1, f"setup: one message, got {len(listed)}"
        data = listed[0]
        msg = json.loads(data)
        changes = msg["changes"]
        assert [(c["s"], c["t"], c["op"]) for c in changes] == [
            (SCHEMA, table(i), "c") for i in range(1, TABLES + 1)
        ], "setup: the streamed transaction lists every table as c"
        cur.execute(
            "SELECT stream_txns > 0, spill_txns FROM pg_stat_replication_slots "
            "WHERE slot_name = %s",
            (SLOT,),
        )
        assert cur.fetchone() == (True, 0), "setup: the transaction was streamed"

        # The budget: the frame's upper bound plus the listed relations, commas included.
        start = data.index(CHANGES_OPEN) + len(CHANGES_OPEN)
        assert data.endswith("]}"), data[-20:]
        budget = FRAME_MAX + len(data) - start - len("]}")
        assert budget - 1 >= 65536, f"setup: the budget {budget} is under the option's minimum"

        at = peek(cur, budget)
        assert at == [data], (
            f"max_message_bytes = {budget} (the transaction's budget) must list every relation: "
            f"{at[0][:200] if at else at}"
        )

        under = peek(cur, budget - 1)
        assert len(under) == 1, under
        assert json.loads(under[0]) == {
            "v": 1,
            "lsn": msg["lsn"],
            "xid": msg["xid"],
            "all": True,
        }, f"max_message_bytes = {budget - 1} must give all: {under[0][:200]}"
