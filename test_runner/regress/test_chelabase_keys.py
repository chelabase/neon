from __future__ import annotations

import json
import select
import time
from typing import TYPE_CHECKING

import psycopg2
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres
from psycopg2.extras import LogicalReplicationConnection

if TYPE_CHECKING:
    from fixtures.neon_fixtures import NeonEnv, VanillaPostgres


def read_one(conn, cur, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = cur.read_message()
        if msg is not None:
            return json.loads(msg.payload)
        select.select([conn], [], [], 0.5)
    raise AssertionError("no message from chelabase_keys")


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_keys_over_replication_and_restart(neon_simple_env: NeonEnv):
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")
    endpoint.safe_psql("CREATE ROLE chelabase_realtime LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    endpoint.safe_psql("CREATE TABLE t (id int PRIMARY KEY, v int)")
    conn = psycopg2.connect(
        endpoint.connstr(user="chelabase_realtime"), connection_factory=LogicalReplicationConnection
    )
    cur = conn.cursor()
    cur.execute("CREATE_REPLICATION_SLOT rt_t TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')")
    cur.fetchall()
    cur.start_replication_expert("START_REPLICATION SLOT rt_t LOGICAL 0/0", decode=True)
    endpoint.safe_psql("INSERT INTO t VALUES (1, 0), (2, 0)")
    msg = read_one(conn, cur)
    assert msg["v"] == 1
    assert msg["changes"] == [
        {"rel": msg["changes"][0]["rel"], "s": "public", "t": "t", "op": "i", "k": [["1"], ["2"]]}
    ]
    assert endpoint.safe_psql("SELECT count(*) FROM pg_replication_slots WHERE slot_name = 'rt_t'")[0][0] == 1
    endpoint.stop()
    endpoint.start()
    assert endpoint.safe_psql("SELECT count(*) FROM pg_replication_slots")[0][0] == 0
    try:
        cur.read_message()
        conn.poll()
        broken = False
    except psycopg2.Error:
        broken = True
    assert broken or conn.closed, "the replication connection must end with the compute"


@run_only_on_postgres([PgVersion.V17], "chelabase_keys is in the v17 fork only")
def test_xid_is_the_full_transaction_id(vanilla_pg: VanillaPostgres):
    vanilla_pg.configure(["wal_level = logical", "max_replication_slots = 4"])
    vanilla_pg.pg_bin.run_capture(["pg_resetwal", "-e", "1", "-D", str(vanilla_pg.pgdatadir)])
    vanilla_pg.start()
    vanilla_pg.safe_psql("CREATE TABLE xt (id int PRIMARY KEY)")
    vanilla_pg.safe_psql("SELECT pg_create_logical_replication_slot('epoch', 'chelabase_keys')")
    with vanilla_pg.cursor(autocommit=False) as cur:
        cur.execute("INSERT INTO xt VALUES (1)")
        cur.execute("SELECT pg_current_xact_id()::text")
        xid = int(cur.fetchone()[0])
        cur.connection.commit()
    assert xid >= 2**32, f"the epoch must be above 0: {xid}"
    rows = vanilla_pg.safe_psql("SELECT data FROM pg_logical_slot_get_changes('epoch', NULL, NULL)")
    assert [json.loads(r[0])["xid"] for r in rows] == [xid]
