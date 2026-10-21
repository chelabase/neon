"""
U16 edge cases beyond test_temp_slot_aux_files.py: several stale copies of non-persistent
slots (temporary and ephemeral) are all removed by one start, each with one log line in the
compute's log, while a persistent slot's copy is kept.
"""

from __future__ import annotations

import struct
from contextlib import closing
from typing import TYPE_CHECKING

import psycopg2
from fixtures.neon_fixtures import wait_for_last_flush_lsn
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres, wait_until

if TYPE_CHECKING:
    from fixtures.common_types import Lsn
    from fixtures.neon_fixtures import Endpoint, NeonEnv

pytestmark = run_only_on_postgres([PgVersion.V17], "U16's slot.c change is in the v17 fork only")

REMOVING_MISSING = r"removing non-existing aux file: pg_replslot/"

# ReplicationSlotOnDisk (v17): magic (4), checksum (4), then the checksummed part; persistency
# at offset 84; sizeof 200. RS_EPHEMERAL = 1, RS_TEMPORARY = 2.
CHECKSUM_AT = 4
CHECKSUMMED_FROM = 8
PERSISTENCY_AT = 84
STATE_SIZE = 200
RS_EPHEMERAL = 1
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


def with_persistency(state: bytes, persistency: int) -> bytes:
    """`state` with another persistency and its checksum recomputed."""
    buf = bytearray(state)
    struct.pack_into("<I", buf, PERSISTENCY_AT, persistency)
    struct.pack_into("<I", buf, CHECKSUM_AT, crc32c(bytes(buf[CHECKSUMMED_FROM:])))
    return bytes(buf)


def emit_copy(endpoint: Endpoint, slot: str, state: bytes):
    """Write an aux copy of `state` the way an older compute's SaveSlotToPath did."""
    with endpoint.cursor() as cur:
        cur.execute(
            "SELECT pg_logical_emit_message(false, %s, %s, true)",
            (f"neon-file:{state_path(slot)}", psycopg2.Binary(state)),
        )


def test_temp_slot_aux_files_every_stale_copy_is_removed_at_start(neon_simple_env: NeonEnv):
    """Two stale temporary copies and a stale ephemeral copy (an older compute copied an
    ephemeral slot with a valid restart_lsn too) are all removed by one start; the
    persistent slot's copy and the slot itself are kept."""
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    endpoint.safe_psql("SELECT pg_create_logical_replication_slot('kept', 'test_decoding')")
    stale = ["stale_a", "stale_b", "stale_eph"]
    emit_copy(endpoint, "stale_a", temporary_slot_state(endpoint, "stale_a"))
    emit_copy(endpoint, "stale_b", temporary_slot_state(endpoint, "stale_b"))
    emit_copy(
        endpoint,
        "stale_eph",
        with_persistency(temporary_slot_state(endpoint, "stale_eph"), RS_EPHEMERAL),
    )
    seeded_at = flushed(env, endpoint)
    assert {state_path(s) for s in stale + ["kept"]} <= aux_paths(env, seeded_at), (
        "setup: every stale copy and the persistent slot's copy are on the timeline"
    )

    endpoint.stop()
    endpoint.start()
    after_start = flushed(env, endpoint)
    paths = aux_paths(env, after_start)
    assert not {state_path(s) for s in stale} & paths, paths
    assert state_path("kept") in paths
    assert logical_slots(endpoint) == ["kept"]
    for slot in stale:
        assert endpoint.log_contains(
            f'Remove the stored state of discarded replication slot "{slot}"'
        ), f"no log line for {slot}"
    assert (
        endpoint.log_contains('Remove the stored state of discarded replication slot "kept"')
        is None
    )
    assert env.pageserver.log_contains(REMOVING_MISSING) is None
