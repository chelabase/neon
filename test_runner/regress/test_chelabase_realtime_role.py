from __future__ import annotations

import json
import select
import time
from typing import TYPE_CHECKING

import psycopg2
import pytest
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres
from psycopg2.errors import InsufficientPrivilege
from psycopg2.extras import LogicalReplicationConnection, PhysicalReplicationConnection

if TYPE_CHECKING:
    from fixtures.neon_fixtures import VanillaPostgres

pytestmark = run_only_on_postgres([PgVersion.V17], "the restriction is in the v17 fork only")
RT = "chelabase_realtime"


@pytest.fixture
def pg(vanilla_pg: VanillaPostgres) -> VanillaPostgres:
    vanilla_pg.configure(
        ["wal_level = logical", "max_replication_slots = 16", "max_wal_senders = 16"]
    )
    vanilla_pg.start()
    vanilla_pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    vanilla_pg.safe_psql("CREATE ROLE repl LOGIN REPLICATION")
    vanilla_pg.safe_psql("CREATE TABLE t (id int PRIMARY KEY)")
    return vanilla_pg


def logical(pg: VanillaPostgres, user: str = RT):
    conn = psycopg2.connect(pg.connstr(user=user), connection_factory=LogicalReplicationConnection)
    return conn, conn.cursor()


def refused(cur, command: str, needle: str):
    with pytest.raises(InsufficientPrivilege) as e:
        cur.execute(command)
    assert needle in str(e.value), (command, str(e.value))


def test_normal_and_physical_logins_are_refused(pg: VanillaPostgres):
    for factory in [None, PhysicalReplicationConnection]:
        with pytest.raises(psycopg2.OperationalError) as e:
            if factory:
                psycopg2.connect(pg.connstr(user=RT), connection_factory=factory)
            else:
                psycopg2.connect(pg.connstr(user=RT))
        assert 'role "chelabase_realtime" may only open logical replication connections' in str(
            e.value
        )


def test_no_sql_in_the_walsender(pg: VanillaPostgres):
    _, cur = logical(pg)
    for sql in [
        "SELECT 1",
        "SELECT pg_create_logical_replication_slot('x', 'test_decoding')",
        "BEGIN",
    ]:
        refused(cur, sql, "can't run SQL in a replication connection")


def test_other_commands_are_refused(pg: VanillaPostgres):
    _, cur = logical(pg)
    for command, tag in [
        ("DROP_REPLICATION_SLOT rt_none", "DROP_REPLICATION_SLOT"),
        ("ALTER_REPLICATION_SLOT rt_none (FAILOVER false)", "ALTER_REPLICATION_SLOT"),
        ("READ_REPLICATION_SLOT rt_none", "READ_REPLICATION_SLOT"),
        ("BASE_BACKUP", "BASE_BACKUP"),
        ("TIMELINE_HISTORY 1", "TIMELINE_HISTORY"),
        ("SHOW wal_level", "SHOW"),
    ]:
        refused(cur, command, f'permission denied for replication command "{tag}"')


@pytest.mark.parametrize(
    "command",
    [
        "CREATE_REPLICATION_SLOT rt_g LOGICAL chelabase_keys",
        "CREATE_REPLICATION_SLOT rt_f TEMPORARY PHYSICAL",
        "CREATE_REPLICATION_SLOT rt_e TEMPORARY LOGICAL test_decoding",
        "CREATE_REPLICATION_SLOT x_h TEMPORARY LOGICAL chelabase_keys",
        "CREATE_REPLICATION_SLOT rt_i TEMPORARY LOGICAL chelabase_keys (TWO_PHASE)",
        "CREATE_REPLICATION_SLOT rt_j TEMPORARY LOGICAL chelabase_keys (FAILOVER)",
        "CREATE_REPLICATION_SLOT rt_k TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'use')",
    ],
)
def test_only_temporary_chelabase_keys_rt_slots(pg: VanillaPostgres, command: str):
    _, cur = logical(pg)
    refused(cur, command, 'permission denied for replication command "CREATE_REPLICATION_SLOT"')


def test_one_slot_per_session_and_only_its_own(pg: VanillaPostgres):
    pg.safe_psql("SELECT pg_create_logical_replication_slot('cust', 'test_decoding')")
    _, other = logical(pg)
    other.execute(
        "CREATE_REPLICATION_SLOT rt_b TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')"
    )
    other.fetchall()
    _, cur = logical(pg)
    cur.execute(
        "CREATE_REPLICATION_SLOT rt_c TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')"
    )
    cur.fetchall()
    refused(
        cur,
        "CREATE_REPLICATION_SLOT rt_d TEMPORARY LOGICAL chelabase_keys",
        "CREATE_REPLICATION_SLOT",
    )
    for command in [
        "START_REPLICATION SLOT cust LOGICAL 0/0",
        "START_REPLICATION SLOT rt_b LOGICAL 0/0",
        "START_REPLICATION SLOT rt_c PHYSICAL 0/0",
    ]:
        with pytest.raises(InsufficientPrivilege) as e:
            cur.start_replication_expert(command)
        assert 'permission denied for replication command "START_REPLICATION"' in str(e.value), (
            command
        )
    assert pg.safe_psql(
        "SELECT confirmed_flush_lsn IS NOT NULL FROM pg_replication_slots WHERE slot_name = 'cust'"
    )[0][0]


def test_the_allowed_path(pg: VanillaPostgres):
    conn, cur = logical(pg)
    cur.execute("IDENTIFY_SYSTEM")
    assert len(cur.fetchall()) == 1
    cur.execute(
        "CREATE_REPLICATION_SLOT rt_a TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')"
    )
    cur.fetchall()
    cur.start_replication_expert(
        "START_REPLICATION SLOT rt_a LOGICAL 0/0 (max_tables '10')", decode=True
    )
    pg.safe_psql("INSERT INTO t VALUES (7)")
    deadline = time.time() + 20
    while time.time() < deadline:
        msg = cur.read_message()
        if msg is not None:
            assert json.loads(msg.payload)["changes"][0]["k"] == [["7"]]
            break
        select.select([conn], [], [], 0.5)
    else:
        raise AssertionError("no message")


def test_another_replication_role_is_not_restricted(pg: VanillaPostgres):
    _, cur = logical(pg, user="repl")
    cur.execute("IDENTIFY_SYSTEM")
    cur.fetchall()
    cur.execute("CREATE_REPLICATION_SLOT plain_slot TEMPORARY LOGICAL test_decoding")
    cur.fetchall()
    cur.execute("SHOW wal_level")
    assert cur.fetchall()[0][0] == "logical"


def test_rt_names_are_realtimes_alone(pg: VanillaPostgres):
    needle = 'replication slot names starting with "rt_" are reserved for chelabase_realtime'
    with pg.cursor() as su:
        for sql in [
            "SELECT pg_create_logical_replication_slot('rt_x', 'test_decoding', true)",
            "SELECT pg_create_logical_replication_slot('rt_y', 'test_decoding')",
            "SELECT pg_create_physical_replication_slot('rt_z')",
        ]:
            with pytest.raises(InsufficientPrivilege) as e:
                su.execute(sql)
            assert needle in str(e.value), sql
        su.execute("SELECT pg_create_logical_replication_slot('src', 'test_decoding')")
        with pytest.raises(InsufficientPrivilege) as e:
            su.execute("SELECT pg_copy_logical_replication_slot('src', 'rt_copy')")
        assert needle in str(e.value)
        su.execute("SELECT pg_create_logical_replication_slot('fine', 'test_decoding')")
    _, cur = logical(pg, user="repl")
    with pytest.raises(InsufficientPrivilege) as e:
        cur.execute("CREATE_REPLICATION_SLOT rt_w TEMPORARY LOGICAL test_decoding")
    assert needle in str(e.value)
