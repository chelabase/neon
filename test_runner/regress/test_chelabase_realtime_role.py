from __future__ import annotations

import json
import select
import socket
import struct
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import psycopg2
import pytest
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres
from psycopg2.errors import InsufficientPrivilege
from psycopg2.extensions import make_dsn
from psycopg2.extras import LogicalReplicationConnection, PhysicalReplicationConnection

if TYPE_CHECKING:
    from fixtures.neon_fixtures import NeonEnv, PgProtocol, VanillaPostgres

pytestmark = run_only_on_postgres([PgVersion.V17], "the restriction is in the v17 fork only")
RT = "chelabase_realtime"


def prepare(vanilla_pg: VanillaPostgres, extra: list[str] | None = None) -> VanillaPostgres:
    vanilla_pg.configure(
        [
            "wal_level = logical",
            "max_replication_slots = 16",
            "max_wal_senders = 16",
            *(extra or []),
        ]
    )
    vanilla_pg.start()
    # The build image runs initdb in the C locale, whose default encoding is SQL_ASCII, which
    # chelabase_keys refuses (U4): the tests run in a UTF8 database.
    vanilla_pg.safe_psql(
        "CREATE DATABASE rt TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
    )
    vanilla_pg.default_options["dbname"] = "rt"
    vanilla_pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION NOBYPASSRLS NOINHERIT")
    vanilla_pg.safe_psql("CREATE ROLE repl LOGIN REPLICATION")
    vanilla_pg.safe_psql("CREATE TABLE t (id int PRIMARY KEY)")
    return vanilla_pg


def close_raw_sessions():
    for s in Raw.opened:
        s.close()
    Raw.opened.clear()


@pytest.fixture
def vpg(vanilla_pg: VanillaPostgres) -> Iterator[VanillaPostgres]:
    """vanilla_pg, whose raw sessions are closed before it stops: a walsender whose client
    never confirms holds up a fast shutdown until wal_sender_timeout."""
    yield vanilla_pg
    close_raw_sessions()


@pytest.fixture
def neon_env(neon_simple_env: NeonEnv) -> Iterator[NeonEnv]:
    yield neon_simple_env
    close_raw_sessions()


@pytest.fixture
def pg(vpg: VanillaPostgres) -> VanillaPostgres:
    return prepare(vpg)


def rt_dsn(node: PgProtocol, **kw: Any) -> str:
    """chelabase_realtime's connection string. PgProtocol.conn_options adds
    `options=-cstatement_timeout=120s` to every connection, a setting the role may not send
    (T3 m1), so this one is built from the node's defaults without their options; options
    the caller passes are sent."""
    opts = {**node.default_options, "user": RT}
    opts.pop("options", None)
    opts.update(kw)
    return str(make_dsn(**{k: v for k, v in opts.items() if v is not None}))


def logical(pg: VanillaPostgres, user: str = RT):
    dsn = rt_dsn(pg) if user == RT else pg.connstr(user=user)
    conn = psycopg2.connect(dsn, connection_factory=LogicalReplicationConnection)
    return conn, conn.cursor()


def refused(cur, command: str, needle: str):
    with pytest.raises(InsufficientPrivilege) as e:
        cur.execute(command)
    assert needle in str(e.value), (command, str(e.value))


# ---- a raw protocol client ----


class RawError(Exception):
    def __init__(self, fields: dict[str, str]):
        self.fields = fields
        self.sqlstate = fields.get("C", "")
        self.message = fields.get("M", "")
        super().__init__(f"{fields.get('S', '')} {self.sqlstate}: {self.message}")


def parse_fields(payload: bytes) -> dict[str, str]:
    fields = {}
    for part in payload.split(b"\0"):
        if part:
            fields[part[:1].decode()] = part[1:].decode(errors="replace")
    return fields


def parse_row(payload: bytes) -> tuple[str | None, ...]:
    (n,) = struct.unpack("!h", payload[:2])
    pos = 2
    row: list[str | None] = []
    for _ in range(n):
        (size,) = struct.unpack("!i", payload[pos : pos + 4])
        pos += 4
        if size < 0:
            row.append(None)
        else:
            row.append(payload[pos : pos + size].decode())
            pos += size
    return tuple(row)


class Raw:
    """A minimal protocol-3 client with trust authentication: any startup parameters, simple
    queries and raw frontend messages in CopyBoth mode. psycopg2 can send neither arbitrary
    startup parameters nor a hot-standby feedback ('h') message."""

    opened: list[Raw] = []

    def __init__(self, pg: PgProtocol, params: dict[str, str]):
        self.sock = socket.create_connection(("localhost", int(pg.default_options["port"])), 20)
        Raw.opened.append(self)
        body = struct.pack("!i", 196608)
        for k, v in params.items():
            body += k.encode() + b"\0" + v.encode() + b"\0"
        body += b"\0"
        self.sock.sendall(struct.pack("!i", len(body) + 4) + body)
        self.pid = 0
        while True:
            kind, payload = self.read()
            if kind == b"R":
                (code,) = struct.unpack("!i", payload[:4])
                assert code == 0, f"authentication request {code}: the tests expect trust"
            elif kind == b"K":
                (self.pid,) = struct.unpack("!i", payload[:4])
            elif kind == b"E":
                self.sock.close()
                raise RawError(parse_fields(payload))
            elif kind == b"Z":
                return

    def _exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("the server closed the connection")
            buf += chunk
        return buf

    def read(self) -> tuple[bytes, bytes]:
        head = self._exact(5)
        (n,) = struct.unpack("!i", head[1:])
        return head[:1], self._exact(n - 4)

    def send(self, kind: bytes, payload: bytes = b""):
        self.sock.sendall(kind + struct.pack("!i", len(payload) + 4) + payload)

    def query(self, sql: str) -> list[tuple[str | None, ...]]:
        self.send(b"Q", sql.encode() + b"\0")
        rows: list[tuple[str | None, ...]] = []
        error = None
        while True:
            kind, payload = self.read()
            if kind == b"D":
                rows.append(parse_row(payload))
            elif kind == b"E":
                error = RawError(parse_fields(payload))
            elif kind == b"G":  # CopyIn (UPLOAD_MANIFEST, were it allowed): give up
                self.send(b"f", b"not sending\0")
            elif kind == b"Z":
                if error is not None:
                    raise error
                return rows

    def start(self, command: str):
        """Sends a START_REPLICATION command and waits for CopyBoth."""
        self.send(b"Q", command.encode() + b"\0")
        while True:
            kind, payload = self.read()
            if kind == b"W":
                return
            if kind == b"E":
                error = RawError(parse_fields(payload))
                while self.read()[0] != b"Z":
                    pass
                raise error

    def copy_data(self, payload: bytes):
        self.send(b"d", payload)

    def until_ready(self):
        """Reads (skipping streamed data) until ReadyForQuery."""
        while self.read()[0] != b"Z":
            pass

    def close(self):
        try:
            self.send(b"X")
        except OSError:
            pass
        self.sock.close()


def walsender_params(pg: PgProtocol, user: str) -> dict[str, str]:
    return {"user": user, "database": str(pg.default_options["dbname"]), "replication": "database"}


def pg_now() -> int:
    """Microseconds since 2000-01-01, the protocol's timestamps."""
    return int((time.time() - 946684800) * 1_000_000)


def hs_feedback(xmin: int, epoch: int, catalog_xmin: int, catalog_epoch: int) -> bytes:
    """A hot-standby feedback message, as XLogWalRcvSendHSFeedback() builds it."""
    return b"h" + struct.pack("!qIIII", pg_now(), xmin, epoch, catalog_xmin, catalog_epoch)


def status_update(write: int, flush: int = 0, apply: int = 0) -> bytes:
    """A standby status update, as XLogWalRcvSendReply() builds it."""
    return b"r" + struct.pack("!QQQqB", write, flush, apply, pg_now(), 0)


def lsn_text(lsn: int) -> str:
    return f"{lsn >> 32:X}/{lsn & 0xFFFFFFFF:X}"


def lsn_int(text: str) -> int:
    hi, lo = text.split("/")
    return (int(hi, 16) << 32) | int(lo, 16)


def poll(fn: Callable[[], Any], what: str, timeout: float = 30.0) -> Any:
    deadline = time.time() + timeout
    value = None
    while time.time() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {what} (last: {value!r})")


def streaming(pg: PgProtocol, s: Raw):
    """Waits until the walsender has caught up (and so set its sync priority)."""
    poll(
        lambda: pg.safe_psql(f"SELECT state FROM pg_stat_replication WHERE pid = {s.pid}")
        == [("streaming",)],
        f"walsender {s.pid} streaming",
    )


def sync(pg: PgProtocol, s: Raw, marker: int):
    """Waits until the walsender has processed everything sent before: it reports `marker`
    as its write position (a status update without a flush position, which confirms
    nothing on the slot), or it has exited."""
    try:
        s.copy_data(status_update(marker))
    except OSError:
        pass

    def done():
        rows = pg.safe_psql(
            f"SELECT state, write_lsn::text FROM pg_stat_replication WHERE pid = {s.pid}"
        )
        return rows == [] or rows[0][0] != "streaming" or rows[0][1] == lsn_text(marker)

    poll(done, f"walsender {s.pid} to process its input")


def confirm(pg: PgProtocol, s: Raw, lsn: int) -> list[tuple[Any, ...]]:
    """Confirms `lsn` as written, flushed and applied, as a standby does (a walsender counts
    as a synchronous standby candidate only once it reports a flush position), and returns
    the session's (sync_priority, sync_state), if it is still streaming."""
    try:
        s.copy_data(status_update(lsn, lsn, lsn))
    except OSError:
        pass
    query = (
        "SELECT state, flush_lsn::text, sync_priority, sync_state"
        f" FROM pg_stat_replication WHERE pid = {s.pid}"
    )

    def done():
        rows = pg.safe_psql(query)
        if rows == [] or rows[0][0] != "streaming":
            return [()]
        return [rows[0][2:]] if rows[0][1] == lsn_text(lsn) else None

    rows: list[tuple[Any, ...]] = [r for r in poll(done, f"walsender {s.pid} to confirm") if r]
    return rows


def current_lsn(pg: PgProtocol) -> int:
    return lsn_int(pg.safe_psql("SELECT pg_current_wal_flush_lsn()::text")[0][0])


def recent_xid(pg: PgProtocol) -> tuple[int, int]:
    """A recent xid and its epoch (accepted as feedback: in the past, not wrapped), above the
    catalog_xmin of any slot made before the call."""
    for _ in range(3):
        pg.safe_psql("SELECT pg_current_xact_id()")
    nxt = int(pg.safe_psql("SELECT pg_snapshot_xmax(pg_current_snapshot())::text")[0][0])
    return (nxt - 1) & 0xFFFFFFFF, (nxt - 1) >> 32


def slot_xmins(pg: PgProtocol, slot: str) -> tuple[str | None, str | None]:
    rows = pg.safe_psql(
        f"SELECT xmin::text, catalog_xmin::text FROM pg_replication_slots WHERE slot_name = '{slot}'"
    )
    assert len(rows) == 1, (slot, rows)
    return rows[0][0], rows[0][1]


# ---- the restriction ----


def test_normal_and_physical_logins_are_refused(pg: VanillaPostgres):
    for factory in [None, PhysicalReplicationConnection]:
        with pytest.raises(psycopg2.OperationalError) as e:
            if factory:
                psycopg2.connect(rt_dsn(pg), connection_factory=factory)
            else:
                psycopg2.connect(rt_dsn(pg))
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


def read_keys(conn, cur) -> list[list[str]]:
    deadline = time.time() + 20
    while time.time() < deadline:
        msg = cur.read_message()
        if msg is not None:
            keys: list[list[str]] = json.loads(msg.payload)["changes"][0]["k"]
            return keys
        select.select([conn], [], [], 0.5)
    raise AssertionError("no message")


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
    assert read_keys(conn, cur) == [["7"]]


def test_the_allowed_path_with_an_exported_snapshot(pg: VanillaPostgres):
    """T3 m2: RT1 creates its slot without a SNAPSHOT option (the default exports one)."""
    conn, cur = logical(pg)
    cur.execute("CREATE_REPLICATION_SLOT rt_x TEMPORARY LOGICAL chelabase_keys")
    row = cur.fetchall()[0]
    assert row[0] == "rt_x" and row[2] is not None, row
    cur.start_replication_expert("START_REPLICATION SLOT rt_x LOGICAL 0/0", decode=True)
    pg.safe_psql("INSERT INTO t VALUES (8)")
    assert read_keys(conn, cur) == [["8"]]


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


# ---- T3 m1: startup parameters ----


@pytest.mark.parametrize(
    "params, name",
    [
        ({"wal_sender_timeout": "0"}, "wal_sender_timeout"),
        ({"logical_decoding_work_mem": "1GB"}, "logical_decoding_work_mem"),
        ({"application_name": "rt", "search_path": "public"}, "search_path"),
        ({"options": "-c wal_sender_timeout=0"}, "wal_sender_timeout"),
        ({"options": "-c logical_decoding_work_mem=1GB"}, "logical_decoding_work_mem"),
        ({"options": "-c statement_timeout=120s"}, "statement_timeout"),
    ],
    ids=[
        "key-wal_sender_timeout",
        "key-logical_decoding_work_mem",
        "key-search_path",
        "options-wal_sender_timeout",
        "options-logical_decoding_work_mem",
        "options-statement_timeout",
    ],
)
def test_realtime_may_not_set_parameters(pg: VanillaPostgres, params: dict[str, str], name: str):
    """chelabase_realtime's startup packet may set client_encoding and application_name
    (besides user, database and replication), nothing else, as a key or through options."""
    with pytest.raises(RawError) as e:
        Raw(pg, {**walsender_params(pg, RT), **params})
    assert (e.value.sqlstate, e.value.message) == (
        "42501",
        f'role "chelabase_realtime" may not set parameter "{name}"',
    )


def test_realtime_may_not_set_parameters_through_libpq(pg: VanillaPostgres):
    with pytest.raises(psycopg2.OperationalError) as e:
        psycopg2.connect(
            rt_dsn(pg, options="-c wal_sender_timeout=0"),
            connection_factory=LogicalReplicationConnection,
        )
    assert 'role "chelabase_realtime" may not set parameter "wal_sender_timeout"' in str(e.value)


def test_realtime_may_name_itself_and_its_encoding(pg: VanillaPostgres):
    s = Raw(
        pg, {**walsender_params(pg, RT), "application_name": "rt-worker", "client_encoding": "UTF8"}
    )
    assert len(s.query("IDENTIFY_SYSTEM")) == 1
    conn = psycopg2.connect(
        rt_dsn(pg, application_name="rt-worker", client_encoding="UTF8"),
        connection_factory=LogicalReplicationConnection,
    )
    conn.cursor().execute("IDENTIFY_SYSTEM")
    assert (
        pg.safe_psql(
            f"SELECT count(*) FROM pg_stat_activity WHERE usename = '{RT}' AND application_name = 'rt-worker'"
        )[0][0]
        == 2
    )


def test_other_roles_may_set_parameters(pg: VanillaPostgres):
    s = Raw(
        pg,
        {
            **walsender_params(pg, "repl"),
            "wal_sender_timeout": "0",
            "options": "-c logical_decoding_work_mem=128MB",
        },
    )
    assert s.query("SHOW wal_sender_timeout") == [("0",)]
    assert s.query("SHOW logical_decoding_work_mem") == [("128MB",)]


# ---- T3 I1 / U6: hot-standby feedback on logical slots ----


FEEDBACK: dict[str, Callable[[int, int], bytes]] = {
    "xmin": lambda xid, epoch: hs_feedback(xid, epoch, 0, 0),
    "catalog_xmin": lambda xid, epoch: hs_feedback(0, 0, xid, epoch),
    "both": lambda xid, epoch: hs_feedback(xid, epoch, xid, epoch),
    "zero": lambda xid, epoch: hs_feedback(0, 0, 0, 0),
}


@pytest.mark.parametrize("feedback", list(FEEDBACK))
@pytest.mark.parametrize("user", [RT, "repl"])
def test_hot_standby_feedback_is_ignored_on_logical_slots(
    pg: VanillaPostgres, user: str, feedback: str
):
    """A logical slot's xmin stays unset and its catalog_xmin is neither moved nor cleared by
    'h' messages, whoever sends them (a slot xmin would hold back vacuum for every table, a
    cleared catalog_xmin would let vacuum remove catalog rows decoding still needs)."""
    slot, plugin = ("rt_h", "chelabase_keys") if user == RT else ("h", "test_decoding")
    s = Raw(pg, walsender_params(pg, user))
    s.query(f"CREATE_REPLICATION_SLOT {slot} TEMPORARY LOGICAL {plugin} (SNAPSHOT 'nothing')")
    s.start(f"START_REPLICATION SLOT {slot} LOGICAL 0/0")
    xid, epoch = recent_xid(pg)
    streaming(pg, s)
    sync(pg, s, 1)
    before = slot_xmins(pg, slot)
    assert before[0] is None and before[1] is not None, before
    s.copy_data(FEEDBACK[feedback](xid, epoch))
    sync(pg, s, 2)
    assert slot_xmins(pg, slot) == before, (user, feedback, xid, before)


def test_feedback_still_reaches_a_physical_slot_and_a_slotless_walsender(pg: VanillaPostgres):
    flush = pg.safe_psql("SELECT pg_current_wal_flush_lsn()::text")[0][0]
    s = Raw(pg, {"user": "repl", "replication": "true"})
    s.query("CREATE_REPLICATION_SLOT p TEMPORARY PHYSICAL (RESERVE_WAL)")
    s.start(f"START_REPLICATION SLOT p PHYSICAL {flush}")
    xid, epoch = recent_xid(pg)
    streaming(pg, s)
    s.copy_data(hs_feedback(xid, epoch, 0, 0))
    sync(pg, s, 1)
    assert slot_xmins(pg, "p") == (str(xid), None)
    n = Raw(pg, {"user": "repl", "replication": "true"})
    n.start(f"START_REPLICATION PHYSICAL {flush}")
    streaming(pg, n)
    n.copy_data(hs_feedback(xid, epoch, 0, 0))
    sync(pg, n, 1)
    assert pg.safe_psql(
        f"SELECT backend_xmin::text FROM pg_stat_replication WHERE pid = {n.pid}"
    ) == [(str(xid),)]


# ---- T3 I2 / U7, U7b: on a compute only the walproposer is a synchronous standby ----
#
# U7b: the restriction holds only where the neon walproposer runs in the server: the neon
# extension sets the core global `chelabase_walproposer_active` (replication/chelabase.h) in
# the postmaster when it registers the walproposer background worker, and every backend
# inherits it. It is no GUC, so no session can change it. Without it (plain Postgres),
# synchronous replication is stock.

WALPROPOSER_FLAG = "chelabase_walproposer_active"


@pytest.mark.parametrize(
    "ssn, name, state",
    [
        ("*", "walproposer", "sync"),
        ("*", "rt-worker", "sync"),
        ("FIRST 1 (walproposer)", "walproposer", "sync"),
        ("ANY 1 (x)", "x", "quorum"),
        ("walproposer", "WalProposer", "sync"),
    ],
    ids=["star-walproposer", "star-other", "first-walproposer", "any-x", "name-case"],
)
def test_without_a_walproposer_sync_replication_is_stock(
    vpg: VanillaPostgres, ssn: str, name: str, state: str
):
    """U7b: plain Postgres (no walproposer registered): a client walsender named in
    synchronous_standby_names that reports flush positions becomes a synchronous standby
    (each client here is the only one connected), whatever its kind or role."""
    pg = prepare(vpg, [f"synchronous_standby_names = '{ssn}'", "synchronous_commit = local"])
    flush = pg.safe_psql("SELECT pg_current_wal_flush_lsn()::text")[0][0]
    clients: list[tuple[str, str, dict[str, str], str | None, str]] = [
        (
            "repl",
            "physical",
            {"user": "repl", "replication": "true"},
            None,
            f"START_REPLICATION PHYSICAL {flush}",
        ),
        (
            "repl",
            "logical",
            walsender_params(pg, "repl"),
            "CREATE_REPLICATION_SLOT s TEMPORARY LOGICAL test_decoding (SNAPSHOT 'nothing')",
            "START_REPLICATION SLOT s LOGICAL 0/0",
        ),
        (
            RT,
            "logical",
            walsender_params(pg, RT),
            "CREATE_REPLICATION_SLOT rt_s TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')",
            "START_REPLICATION SLOT rt_s LOGICAL 0/0",
        ),
    ]
    seen = []
    for user, kind, params, create, start in clients:
        s = Raw(pg, {**params, "application_name": name})
        if create is not None:
            s.query(create)
        s.start(start)
        streaming(pg, s)
        rows = confirm(pg, s, current_lsn(pg))
        assert len(rows) == 1, (user, kind, rows)
        seen.append((user, kind, *rows[0]))
        s.close()
    assert seen == [(user, kind, 1, state) for user, kind, *_ in clients]


def test_the_walproposer_flag_is_no_setting(pg: VanillaPostgres):
    """U7b: no session can see or flip the flag: there is no such parameter, not through
    SQL, not in a startup packet."""
    for sql in [f"SHOW {WALPROPOSER_FLAG}", f"SET {WALPROPOSER_FLAG} = on"]:
        with pytest.raises(psycopg2.errors.UndefinedObject):
            pg.safe_psql(sql)
    with pytest.raises(RawError) as e:
        Raw(pg, {**walsender_params(pg, "repl"), WALPROPOSER_FLAG: "on"})
    assert e.value.message == f'unrecognized configuration parameter "{WALPROPOSER_FLAG}"', e.value


def test_the_walproposer_stays_the_synchronous_standby(neon_env: NeonEnv):
    """On a compute (synchronous_standby_names = 'walproposer'), a client walsender that
    names itself walproposer and reports flush positions stays async; the walproposer
    stays the synchronous standby. No session can turn the restriction off."""
    endpoint = neon_env.endpoints.create_start("main")
    endpoint.safe_psql("CREATE TABLE w (id int)")
    for sql in [f"SHOW {WALPROPOSER_FLAG}", f"SET {WALPROPOSER_FLAG} = off"]:
        with pytest.raises(psycopg2.errors.UndefinedObject):
            endpoint.safe_psql(sql)
    s = Raw(
        endpoint,
        {
            "user": "cloud_admin",
            "database": "postgres",
            "replication": "database",
            "application_name": "walproposer",
        },
    )
    s.query("CREATE_REPLICATION_SLOT wp TEMPORARY LOGICAL test_decoding (SNAPSHOT 'nothing')")
    s.start("START_REPLICATION SLOT wp LOGICAL 0/0")
    query = (
        f"SELECT pid = {s.pid} AS client, state, flush_lsn::text, sync_priority, sync_state"
        " FROM pg_stat_get_wal_senders()"
    )

    def settled():
        endpoint.safe_psql("INSERT INTO w VALUES (1)")
        lsn = current_lsn(endpoint)
        s.copy_data(status_update(lsn, lsn, lsn))
        rows = sorted(endpoint.safe_psql(query))
        client = [r for r in rows if r[0]]
        if len(rows) == 2 and client and client[0][1] == "streaming" and client[0][2] is not None:
            return rows
        return None

    rows = poll(settled, "the client walsender and the walproposer")
    assert [(r[0], r[3], r[4]) for r in rows] == [(False, 1, "sync"), (True, 0, "async")], rows


# ---- the invariant ----
#
# A chelabase_realtime walsender can't change any server state beyond its own rt_ slots'
# confirmed position: whatever it sends (startup parameters, replication commands, SQL,
# status updates, hot-standby feedback, unknown or truncated messages, CopyDone,
# Terminate), every other slot is unchanged, its own slot never gets an xmin, its
# catalog_xmin moves only with a confirmation, and disallowed startup parameters are
# refused. Synchronous replication is the one exception, by design (U7b): this server runs
# no walproposer, so a realtime walsender named in synchronous_standby_names is a stock
# synchronous standby here (on a compute it never is: the walproposer test above).

OWN = "rt_inv"
SLOT_COLUMNS = [
    "slot_type",
    "plugin",
    "database",
    "temporary",
    "two_phase",
    "failover",
    "xmin::text",
    "catalog_xmin::text",
    "restart_lsn::text",
    "confirmed_flush_lsn::text",
    "active_pid",
]
XMIN, CATALOG_XMIN = SLOT_COLUMNS.index("xmin::text"), SLOT_COLUMNS.index("catalog_xmin::text")
MOVABLE = {
    SLOT_COLUMNS.index("restart_lsn::text"),
    SLOT_COLUMNS.index("confirmed_flush_lsn::text"),
    SLOT_COLUMNS.index("active_pid"),
}

Message = Callable[[int, int, int], tuple[bytes, bytes]]


@dataclass
class Act:
    startup: dict[str, str] | None = None
    command: str | None = None
    messages: list[Message] | None = None
    refused: bool = False
    confirms: bool = False
    leaves_copy: bool = False
    # (sync_priority, sync_state) after a confirmation; None: never a candidate
    sync: tuple[int, str] | None = None


def data(build: Callable[[int, int, int], bytes]) -> Message:
    return lambda xid, epoch, lsn: (b"d", build(xid, epoch, lsn))


ACTIONS = [
    pytest.param(
        Act(startup={"application_name": "walproposer"}, sync=(1, "sync")),
        id="startup-walproposer",
    ),
    pytest.param(Act(startup={"application_name": "rt-worker"}), id="startup-application_name"),
    pytest.param(Act(startup={"client_encoding": "UTF8"}), id="startup-client_encoding"),
    *[
        pytest.param(Act(startup={k: v}, refused=True), id=f"startup-{k}")
        for k, v in [
            ("wal_sender_timeout", "0"),
            ("logical_decoding_work_mem", "1GB"),
            ("statement_timeout", "0"),
            ("search_path", "public"),
            ("synchronous_commit", "off"),
        ]
    ],
    *[
        pytest.param(Act(startup={"options": f"-c {k}={v}"}, refused=True), id=f"options-{k}")
        for k, v in [
            ("wal_sender_timeout", "0"),
            ("logical_decoding_work_mem", "1GB"),
            ("statement_timeout", "120s"),
        ]
    ],
    pytest.param(Act(command="IDENTIFY_SYSTEM"), id="IDENTIFY_SYSTEM"),
    *[
        pytest.param(Act(command=command, refused=True), id=name)
        for name, command in [
            ("SHOW", "SHOW wal_level"),
            ("DROP-customer", "DROP_REPLICATION_SLOT cust"),
            ("DROP-own", f"DROP_REPLICATION_SLOT {OWN}"),
            ("ALTER-customer", "ALTER_REPLICATION_SLOT cust (FAILOVER true)"),
            ("READ-physical", "READ_REPLICATION_SLOT phys"),
            ("BASE_BACKUP", "BASE_BACKUP"),
            ("TIMELINE_HISTORY", "TIMELINE_HISTORY 1"),
            ("UPLOAD_MANIFEST", "UPLOAD_MANIFEST"),
            ("SQL-drop", "SELECT pg_drop_replication_slot('cust')"),
            ("SQL-advance", "SELECT pg_replication_slot_advance('cust', pg_current_wal_lsn())"),
            (
                "CREATE-second",
                "CREATE_REPLICATION_SLOT rt_two TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')",
            ),
            ("START-customer", "START_REPLICATION SLOT cust LOGICAL 0/0"),
            ("START-physical", "START_REPLICATION SLOT phys PHYSICAL 0/0"),
        ]
    ],
    pytest.param(
        Act(messages=[data(lambda xid, epoch, lsn: status_update(lsn, lsn, lsn))], confirms=True),
        id="r-confirm",
    ),
    pytest.param(
        Act(messages=[data(lambda xid, epoch, lsn: hs_feedback(xid, epoch, 0, 0))]), id="h-xmin"
    ),
    pytest.param(
        Act(messages=[data(lambda xid, epoch, lsn: hs_feedback(0, 0, xid, epoch))]),
        id="h-catalog_xmin",
    ),
    pytest.param(
        Act(messages=[data(lambda xid, epoch, lsn: hs_feedback(xid, epoch, xid, epoch))]),
        id="h-both",
    ),
    pytest.param(
        Act(messages=[data(lambda xid, epoch, lsn: hs_feedback(0, 0, 0, 0))]), id="h-zero"
    ),
    pytest.param(
        Act(
            messages=[
                data(lambda xid, epoch, lsn: hs_feedback((xid + 1000) & 0xFFFFFFFF, epoch, 0, 0))
            ]
        ),
        id="h-future",
    ),
    pytest.param(
        Act(
            messages=[
                data(lambda xid, epoch, lsn: hs_feedback(xid, epoch, 0, 0)),
                data(lambda xid, epoch, lsn: status_update(lsn, lsn, lsn)),
                data(lambda xid, epoch, lsn: hs_feedback(0, 0, 0, 0)),
            ],
            confirms=True,
        ),
        id="h-r-h",
    ),
    pytest.param(Act(messages=[data(lambda xid, epoch, lsn: b"h" + bytes(7))]), id="h-short"),
    pytest.param(Act(messages=[data(lambda xid, epoch, lsn: b"z")]), id="unknown-type"),
    pytest.param(
        Act(messages=[lambda xid, epoch, lsn: (b"c", b"")], leaves_copy=True), id="copy-done"
    ),
    pytest.param(Act(messages=[lambda xid, epoch, lsn: (b"X", b"")]), id="terminate"),
]


def server_state(pg: PgProtocol) -> dict[str, tuple[Any, ...]]:
    rows = pg.safe_psql(f"SELECT slot_name, {', '.join(SLOT_COLUMNS)} FROM pg_replication_slots")
    return {r[0]: tuple(r[1:]) for r in rows}


def beyond_own_position(
    before: dict[str, tuple[Any, ...]], after: dict[str, tuple[Any, ...]], confirms: bool
) -> list[str]:
    problems = []
    for name in sorted(set(before) | set(after)):
        b, a = before.get(name), after.get(name)
        if name != OWN:
            if b != a:
                problems.append(f"{name}: {b} -> {a}")
            continue
        if a is None:
            continue  # the session's temporary slot ends with the session
        if a[XMIN] is not None:
            problems.append(f"{OWN}: xmin {a[XMIN]}")
        if b is None:
            continue
        for i, column in enumerate(SLOT_COLUMNS):
            if i in MOVABLE or (confirms and i == CATALOG_XMIN):
                continue
            if b[i] != a[i]:
                problems.append(f"{OWN}: {column} {b[i]} -> {a[i]}")
        if confirms and (a[CATALOG_XMIN] is None or int(a[CATALOG_XMIN]) < int(b[CATALOG_XMIN])):
            problems.append(f"{OWN}: catalog_xmin {b[CATALOG_XMIN]} -> {a[CATALOG_XMIN]}")
    return problems


@pytest.mark.parametrize("action", ACTIONS)
def test_realtime_changes_nothing_beyond_its_own_slot_position(vpg: VanillaPostgres, action: Act):
    pg = prepare(vpg, ["synchronous_standby_names = 'walproposer'", "synchronous_commit = local"])
    pg.safe_psql("SELECT pg_create_logical_replication_slot('cust', 'test_decoding')")
    pg.safe_psql("SELECT pg_create_physical_replication_slot('phys', true)")
    pg.safe_psql("INSERT INTO t VALUES (1)")
    before = server_state(pg)
    outcome = "allowed"
    priorities: list[tuple[Any, ...]] = []
    after: dict[str, tuple[Any, ...]] | None = None
    try:
        s = Raw(pg, {**walsender_params(pg, RT), **(action.startup or {})})
    except RawError:
        outcome = "refused"
    else:
        s.query(
            f"CREATE_REPLICATION_SLOT {OWN} TEMPORARY LOGICAL chelabase_keys (SNAPSHOT 'nothing')"
        )
        if action.command is not None:
            before = server_state(pg)
            try:
                s.query(action.command)
            except RawError:
                outcome = "refused"
        else:
            s.start(f"START_REPLICATION SLOT {OWN} LOGICAL 0/0")
            xid, epoch = recent_xid(pg)
            lsn = current_lsn(pg)
            messages = [m(xid, epoch, lsn) for m in action.messages or []]
            streaming(pg, s)
            sync(pg, s, 1)
            before = server_state(pg)
            for kind, payload in messages:
                try:
                    s.send(kind, payload)
                except OSError:
                    break
            if action.leaves_copy:
                s.until_ready()
            else:
                sync(pg, s, 2)
            after = server_state(pg)
            # then, as a standby would, report a flush position: still never synchronous
            priorities = confirm(pg, s, current_lsn(pg))
    if after is None:
        after = server_state(pg)
    assert outcome == ("refused" if action.refused else "allowed")
    assert beyond_own_position(before, after, action.confirms) == []
    if action.sync is None:
        assert all(p[0] == 0 for p in priorities), priorities
    else:
        assert [tuple(p) for p in priorities] == [action.sync]
