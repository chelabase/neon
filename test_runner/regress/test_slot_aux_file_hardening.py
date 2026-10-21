"""
F3 (K1 audit): the slot aux files beyond test_temp_slot_aux_files.py.

- A `pg_replslot/<slot>/state` aux entry the compute's `RestoreSlotFromDisk` would PANIC on
  (too short for its header, wrong magic, another major's version, a length that isn't the
  state's, a CRC-32C mismatch) is skipped by the basebackup with a pageserver warning naming
  its path, so the next start succeeds. Pinned: the warning contains
  "malformed replication slot state" and the entry's path.
- A replica start and its promotion remove no aux file the pageserver doesn't have.
- A persistent slot's state is copied to the pageserver exactly once at its creation (the
  ephemeral save before `ReplicationSlotPersist` and a CHECKPOINT or shutdown with nothing
  changed copy nothing).

After a postmaster crash-restart, nothing may be recorded for local temporary slots (K1 audit
b): not testable here. Neon computes run with `restart_after_crash = off` (neon_local's
endpoint config and `compute/manifest.yaml`), and with it on, `neon.signal` (never unlinked)
makes the restart a basebackup start from a stale prev-LSN. It is traced by reading.
"""

from __future__ import annotations

import re
import struct
from contextlib import closing
from typing import TYPE_CHECKING

import psycopg2
import pytest
from fixtures.neon_fixtures import wait_for_last_flush_lsn, wait_replica_caughtup
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres, wait_until

if TYPE_CHECKING:
    from fixtures.common_types import Lsn
    from fixtures.neon_fixtures import Endpoint, NeonEnv

pytestmark = run_only_on_postgres([PgVersion.V17], "U16's slot.c change is in the v17 fork only")

REMOVING_MISSING = r"removing non-existing aux file: pg_replslot/"
MALFORMED = "malformed replication slot state"

# ReplicationSlotOnDisk (v17): magic (4), checksum (4), version (4), length (4), then 184
# bytes of slotdata; persistency at 84, restart_lsn at 96; sizeof 200.
CHECKSUM_AT = 4
VERSION_AT = 8
LENGTH_AT = 12
CHECKSUMMED_FROM = 8
PERSISTENCY_AT = 84
RESTART_LSN_AT = 96
STATE_SIZE = 200
RS_PERSISTENT = 0
RS_TEMPORARY = 2


def crc32c(data: bytes) -> int:
    """CRC-32C (Castagnoli), as Postgres' INIT/COMP/FIN_CRC32C."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def state_path(slot: str) -> str:
    return f"pg_replslot/{slot}/state"


def aux_paths(env: NeonEnv, lsn: Lsn) -> set[str]:
    files = env.pageserver.http_client().list_aux_files(
        env.initial_tenant, env.initial_timeline, lsn
    )
    return set(files.keys())


def flushed(env: NeonEnv, endpoint: Endpoint) -> Lsn:
    return wait_for_last_flush_lsn(env, endpoint, env.initial_tenant, env.initial_timeline)


def logical_slots(endpoint: Endpoint) -> list[str]:
    rows = endpoint.safe_psql(
        "SELECT slot_name FROM pg_replication_slots WHERE slot_type = 'logical' ORDER BY 1"
    )
    return [r[0] for r in rows]


def temporary_slot_state(endpoint: Endpoint, slot: str) -> bytes:
    """A valid on-disk state of a temporary test_decoding slot `slot`; the slot is gone
    when this returns."""
    with closing(endpoint.connect()) as conn:
        cur = conn.cursor()
        cur.execute("SELECT pg_create_logical_replication_slot(%s, 'test_decoding', true)", (slot,))
        cur.execute("SELECT pg_read_binary_file(%s)", (state_path(slot),))
        row = cur.fetchone()
        assert row is not None
        state = bytes(row[0])

    def gone():
        assert slot not in logical_slots(endpoint)

    wait_until(gone)
    assert len(state) == STATE_SIZE, f"setup: a {len(state)}-byte slot state"
    (persistency,) = struct.unpack_from("<I", state, PERSISTENCY_AT)
    assert persistency == RS_TEMPORARY, f"setup: persistency {persistency}"
    (checksum,) = struct.unpack_from("<I", state, CHECKSUM_AT)
    assert crc32c(state[CHECKSUMMED_FROM:]) == checksum, "setup: crc32c matches Postgres"
    return state


def reseal(buf: bytearray) -> bytes:
    struct.pack_into("<I", buf, CHECKSUM_AT, crc32c(bytes(buf[CHECKSUMMED_FROM:])))
    return bytes(buf)


def emit_copy(endpoint: Endpoint, slot: str, state: bytes):
    """Write an aux copy of `state` the way SaveSlotToPath does."""
    with endpoint.cursor() as cur:
        cur.execute(
            "SELECT pg_logical_emit_message(false, %s, %s, true)",
            (f"neon-file:{state_path(slot)}", psycopg2.Binary(state)),
        )


def assert_no_missing_removal(env: NeonEnv):
    assert env.pageserver.log_contains(REMOVING_MISSING) is None, (
        "a compute removed a slot state the pageserver never had"
    )


def malformed_states(template: bytes) -> dict[str, bytes]:
    """One state per way RestoreSlotFromDisk PANICs, each from a persistent copy of
    `template` (so a shipped one would also count towards restart.lsn)."""
    good = bytearray(template)
    struct.pack_into("<I", good, PERSISTENCY_AT, RS_PERSISTENT)
    good_bytes = reseal(good)

    magic = bytearray(good_bytes)
    struct.pack_into("<I", magic, 0, 0x0BADBEEF)

    version = bytearray(good_bytes)
    struct.pack_into("<I", version, VERSION_AT, 4)

    length = bytearray(good_bytes)
    struct.pack_into("<I", length, LENGTH_AT, STATE_SIZE - 16 - 1)

    crc = bytearray(good_bytes)
    crc[RESTART_LSN_AT] ^= 0x40

    return {
        "mal_short": good_bytes[:12],
        "mal_truncated": good_bytes[:150],
        "mal_magic": bytes(magic),
        "mal_version": reseal(version),
        "mal_length": reseal(length),
        "mal_crc": bytes(crc),
    }


def test_slot_aux_files_malformed_copy_is_not_shipped(neon_simple_env: NeonEnv):
    """Malformed slot states on the timeline (what a broken writer could leave) don't stop
    the next start: the basebackup skips each with a warning naming it, the compute starts
    without those slots, and a well-formed persistent slot is still shipped."""
    env = neon_simple_env
    env.pageserver.allowed_errors.append(f".*{MALFORMED}.*")
    endpoint = env.endpoints.create_start("main")

    endpoint.safe_psql("SELECT pg_create_logical_replication_slot('kept', 'test_decoding')")
    bad = malformed_states(temporary_slot_state(endpoint, "template"))
    for slot, state in bad.items():
        emit_copy(endpoint, slot, state)
    seeded_at = flushed(env, endpoint)
    assert {state_path(s) for s in [*bad, "kept"]} <= aux_paths(env, seeded_at), (
        "setup: every malformed copy is on the timeline"
    )

    endpoint.stop()
    try:
        endpoint.start()
    except Exception as e:
        pytest.fail(
            f"the compute did not start: a malformed slot state was shipped into its "
            f"basebackup ({type(e).__name__}: {str(e)[-500:]})"
        )

    assert logical_slots(endpoint) == ["kept"]
    for slot in bad:
        path = re.escape(state_path(slot))
        assert (
            env.pageserver.log_contains(f"{MALFORMED}.*{path}|{path}.*{MALFORMED}") is not None
        ), f"no pageserver warning names the skipped {state_path(slot)}"
    assert env.pageserver.log_contains(f"{MALFORMED}.*kept|kept.*{MALFORMED}") is None
    assert_no_missing_removal(env)

    # A second start skips them again and still starts.
    endpoint.stop()
    endpoint.start()
    assert logical_slots(endpoint) == ["kept"]


def test_slot_aux_files_replica_promote_removes_nothing(neon_simple_env: NeonEnv):
    """A replica's basebackup ships no slots, so neither its start nor its promotion removes
    an aux file: the stale copy and the persistent slot's copy stay for the next primary
    start, which removes only the stale one."""
    env = neon_simple_env
    primary = env.endpoints.create_start("main", endpoint_id="primary")
    primary.safe_psql("SELECT pg_create_logical_replication_slot('kept', 'test_decoding')")
    emit_copy(primary, "stale_tmp", temporary_slot_state(primary, "stale_tmp"))
    primary.safe_psql("CREATE TABLE t (x int)")
    primary.safe_psql("INSERT INTO t VALUES (1)")
    seeded_at = flushed(env, primary)
    assert {state_path("kept"), state_path("stale_tmp")} <= aux_paths(env, seeded_at), (
        "setup: both copies are on the timeline"
    )
    safekeepers = primary.safe_psql("SHOW neon.safekeepers")[0][0]

    replica = env.endpoints.new_replica_start(origin=primary, endpoint_id="replica")
    wait_replica_caughtup(primary, replica)
    assert logical_slots(replica) == [], "a replica's basebackup ships no slots"
    assert_no_missing_removal(env)

    # As test_replica_promotes.py's "postgres" method: no shutdown checkpoint the replica
    # hasn't replayed.
    wait_replica_caughtup(primary, replica)
    primary.stop(mode="immediate-terminate")
    with closing(replica.connect()) as conn:
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(f"ALTER SYSTEM SET neon.safekeepers = '{safekeepers}'")
        cur.execute("SELECT pg_reload_conf()")
        cur.execute("SELECT pg_promote()")
        assert cur.fetchone() == (True,)
    replica.safe_psql("INSERT INTO t VALUES (2)")
    replica.safe_psql("CHECKPOINT")
    promoted_at = flushed(env, replica)
    assert logical_slots(replica) == []
    assert_no_missing_removal(env)
    assert {state_path("kept"), state_path("stale_tmp")} <= aux_paths(env, promoted_at), (
        "the promotion removed a copy"
    )
    replica.stop()

    primary2 = env.endpoints.create_start("main", endpoint_id="primary2")
    after = flushed(env, primary2)
    paths = aux_paths(env, after)
    assert state_path("stale_tmp") not in paths
    assert state_path("kept") in paths
    assert logical_slots(primary2) == ["kept"]
    assert primary2.safe_psql("SELECT count(*) FROM t") == [(2,)]
    assert_no_missing_removal(env)


def save_lines(endpoint: Endpoint, slot: str) -> list[str]:
    """The compute's "Save replication slot at <path>" lines for `slot` (SaveSlotToPath logs
    one per neon-file: copy), the creation's temporary directory included."""
    pattern = re.compile(rf"Save replication slot at pg_replslot/{re.escape(slot)}(\.tmp)?/state")
    text = endpoint.logfile.read_text(errors="replace")
    return [line for line in text.splitlines() if pattern.search(line)]


def test_slot_aux_files_persisted_slot_is_copied_once(neon_simple_env: NeonEnv):
    """A persistent slot is copied once, by ReplicationSlotPersist: its ephemeral saves
    (CreateSlotOnDisk's under <slot>.tmp, CreateInitDecodingContext's) copy nothing, and a
    CHECKPOINT or a shutdown with nothing changed copy it again neither."""
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    endpoint.safe_psql("SELECT pg_create_logical_replication_slot('once', 'test_decoding')")
    lines = save_lines(endpoint, "once")
    assert len(lines) == 1, f"the slot was copied {len(lines)} times at its creation: {lines}"
    assert "pg_replslot/once/state" in lines[0], lines[0]

    endpoint.safe_psql("CHECKPOINT")
    lsn = flushed(env, endpoint)
    paths = aux_paths(env, lsn)
    assert state_path("once") in paths
    assert state_path("once.tmp") not in paths, "the creation's temporary directory was copied"
    lines = save_lines(endpoint, "once")
    assert len(lines) == 1, f"a CHECKPOINT with nothing changed copied the slot again: {lines}"

    endpoint.stop()
    lines = save_lines(endpoint, "once")
    assert len(lines) == 1, f"a shutdown with nothing changed copied the slot again: {lines}"
