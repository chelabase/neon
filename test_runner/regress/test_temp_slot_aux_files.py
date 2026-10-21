"""
U16: a temporary (or ephemeral) replication slot's state never reaches the pageserver as a
`neon-file:pg_replslot/<slot>/state` aux file, and a stale copy left by an older compute is
removed when the compute starts.

The pageserver keeps a logical slot's state as an aux file, written by a `neon-file:` logical
message from `SaveSlotToPath` and removed by an empty one from `ReplicationSlotDropPtr`. Only
persistent slots may be copied (rule 1), only those copies are removed on a drop (rule 2), and
`LogDiscardedSlotFiles()` removes, at start, the copy of every non-persistent slot the startup
process found in the basebackup and deleted (rule 3).
"""

from __future__ import annotations

import struct
from contextlib import closing
from typing import TYPE_CHECKING

import psycopg2
import pytest
from fixtures.neon_fixtures import wait_for_last_flush_lsn
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres, wait_until

if TYPE_CHECKING:
    from fixtures.common_types import Lsn, TimelineId
    from fixtures.neon_fixtures import Endpoint, NeonEnv

pytestmark = run_only_on_postgres([PgVersion.V17], "U16's slot.c change is in the v17 fork only")

# What the pageserver logs when a compute removes an aux file it never had.
REMOVING_MISSING = r"removing non-existing aux file: pg_replslot/"

# ReplicationSlotOnDisk (v17): persistency at offset 84, sizeof 200; RS_TEMPORARY = 2.
PERSISTENCY_AT = 84
STATE_SIZE = 200
RS_TEMPORARY = 2


def state_path(slot: str) -> str:
    return f"pg_replslot/{slot}/state"


def aux_paths(env: NeonEnv, timeline: TimelineId, lsn: Lsn) -> set[str]:
    files = env.pageserver.http_client().list_aux_files(env.initial_tenant, timeline, lsn)
    return set(files.keys())


def flushed(env: NeonEnv, endpoint: Endpoint, timeline: TimelineId | None = None) -> Lsn:
    """The endpoint's flush LSN once the pageserver has it (after a CHECKPOINT)."""
    return wait_for_last_flush_lsn(
        env, endpoint, env.initial_tenant, timeline or env.initial_timeline
    )


def logical_slots(endpoint: Endpoint) -> list[str]:
    # Every primary also has the physical wal_proposer_slot; only logical slots count here.
    rows = endpoint.safe_psql(
        "SELECT slot_name FROM pg_replication_slots WHERE slot_type = 'logical' ORDER BY 1"
    )
    return [r[0] for r in rows]


def wait_slot_gone(endpoint: Endpoint, slot: str):
    """A temporary slot is dropped when its session ends, which the server sees a little
    after the client closes it."""

    def gone():
        assert slot not in logical_slots(endpoint)

    wait_until(gone)


def assert_no_missing_removal(env: NeonEnv):
    assert env.pageserver.log_contains(REMOVING_MISSING) is None, (
        "a compute removed a slot state the pageserver never had"
    )


def temporary_slot_state(endpoint: Endpoint, slot: str) -> bytes:
    """The on-disk state of a temporary test_decoding slot named `slot` (a valid state file,
    checksum included, with persistency RS_TEMPORARY), read while the slot exists; the slot
    is gone when this returns."""
    with closing(endpoint.connect()) as conn:
        cur = conn.cursor()
        cur.execute("SELECT pg_create_logical_replication_slot(%s, 'test_decoding', true)", (slot,))
        cur.execute("SELECT pg_read_binary_file(%s)", (state_path(slot),))
        row = cur.fetchone()
        assert row is not None
        state = bytes(row[0])
    wait_slot_gone(endpoint, slot)
    assert len(state) == STATE_SIZE, f"setup: a {len(state)}-byte slot state"
    (persistency,) = struct.unpack_from("<I", state, PERSISTENCY_AT)
    assert persistency == RS_TEMPORARY, f"setup: persistency {persistency}"
    return state


def seed_stale_state(endpoint: Endpoint, slot: str):
    """Leave on the timeline what an older compute left after a crash: the aux copy of a
    temporary slot that no longer exists. The compute writes it the way SaveSlotToPath does,
    as a non-transactional `neon-file:` logical message."""
    state = temporary_slot_state(endpoint, slot)
    with endpoint.cursor() as cur:
        cur.execute(
            "SELECT pg_logical_emit_message(false, %s, %s, true)",
            (f"neon-file:{state_path(slot)}", psycopg2.Binary(state)),
        )


def test_temp_slot_aux_files_temporary_slot_is_not_copied(neon_simple_env: NeonEnv):
    """Rule 1 and 2: a temporary slot held across a CHECKPOINT has no aux copy, and its end
    removes nothing; a persistent slot's copy appears and goes with the slot; an ephemeral
    slot whose creation fails leaves nothing either."""
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    held = endpoint.connect()
    held.cursor().execute(
        "SELECT pg_create_logical_replication_slot('tmp_held', 'test_decoding', true)"
    )
    endpoint.safe_psql("CHECKPOINT")
    lsn = flushed(env, endpoint)
    assert state_path("tmp_held") not in aux_paths(env, env.initial_timeline, lsn), (
        "a temporary slot's state reached the pageserver"
    )

    endpoint.safe_psql("SELECT pg_create_logical_replication_slot('kept', 'test_decoding')")
    lsn = flushed(env, endpoint)
    assert state_path("kept") in aux_paths(env, env.initial_timeline, lsn), (
        "a persistent slot's state is copied once it is created"
    )
    endpoint.safe_psql("SELECT pg_drop_replication_slot('kept')")
    lsn = flushed(env, endpoint)
    assert state_path("kept") not in aux_paths(env, env.initial_timeline, lsn)

    # The temporary slot ends with its session; there is no copy to remove.
    held.close()
    wait_slot_gone(endpoint, "tmp_held")

    # A failed creation: the slot is ephemeral while its plugin loads, then dropped.
    with pytest.raises(psycopg2.Error, match="no_such_plugin"):
        endpoint.safe_psql(
            "SELECT pg_create_logical_replication_slot('eph_fails', 'no_such_plugin')"
        )
    lsn = flushed(env, endpoint)
    paths = aux_paths(env, env.initial_timeline, lsn)
    assert not {p for p in paths if p.startswith("pg_replslot/")}, paths
    assert_no_missing_removal(env)


def test_temp_slot_aux_files_crashed_compute_leaves_no_copy(neon_simple_env: NeonEnv):
    """A compute killed while it holds a temporary chelabase_keys slot (as realtime's rt_
    slots are) leaves no aux copy, so the next start has no slot and nothing to clean."""
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    held = endpoint.connect()
    held.cursor().execute(
        "SELECT pg_create_logical_replication_slot('keys_tmp', 'chelabase_keys', true)"
    )
    endpoint.safe_psql("CHECKPOINT")
    before_kill = flushed(env, endpoint)
    endpoint.stop(
        mode="immediate", sks_wait_walreceiver_gone=(env.safekeepers, env.initial_timeline)
    )
    try:
        held.close()
    except psycopg2.Error:
        pass

    assert state_path("keys_tmp") not in aux_paths(env, env.initial_timeline, before_kill), (
        "the temporary chelabase_keys slot's state reached the pageserver"
    )

    endpoint.start()
    assert logical_slots(endpoint) == []
    after_start = flushed(env, endpoint)
    assert state_path("keys_tmp") not in aux_paths(env, env.initial_timeline, after_start)
    assert_no_missing_removal(env)


def test_temp_slot_aux_files_stale_copy_is_removed_at_start(neon_simple_env: NeonEnv):
    """Rule 3: a stale copy of a temporary slot's state (what an older compute left) is
    removed by the next start, once; a persistent slot's copy is kept."""
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    endpoint.safe_psql("SELECT pg_create_logical_replication_slot('kept', 'test_decoding')")
    seed_stale_state(endpoint, "stale_tmp")
    seeded_at = flushed(env, endpoint)
    assert {state_path("kept"), state_path("stale_tmp")} <= aux_paths(
        env, env.initial_timeline, seeded_at
    ), "setup: the stale copy and the persistent slot's copy are on the timeline"

    endpoint.stop()
    endpoint.start()
    after_start = flushed(env, endpoint)
    paths = aux_paths(env, env.initial_timeline, after_start)
    assert state_path("stale_tmp") not in paths, "the stale copy outlived the start"
    assert state_path("kept") in paths, "the persistent slot's copy is kept"
    assert logical_slots(endpoint) == ["kept"]
    assert_no_missing_removal(env)

    # Idempotent: the next start has nothing left to remove.
    endpoint.stop()
    endpoint.start()
    after_second = flushed(env, endpoint)
    paths = aux_paths(env, env.initial_timeline, after_second)
    assert state_path("stale_tmp") not in paths
    assert state_path("kept") in paths
    assert logical_slots(endpoint) == ["kept"]
    assert_no_missing_removal(env)


def test_temp_slot_aux_files_child_branch_inherits_no_copy(neon_simple_env: NeonEnv):
    """A child branch created from an LSN before the cleanup: aux files are not inherited by
    a branch (pageserver_api key.rs: NON_INHERITED_RANGE and the sparse non-inherited
    keyspace), so the child has no copy of the parent's stale state, starts without the
    slot, and removes nothing it never had."""
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    seed_stale_state(endpoint, "stale_tmp")
    seeded_at = flushed(env, endpoint)
    assert state_path("stale_tmp") in aux_paths(env, env.initial_timeline, seeded_at), (
        "setup: the stale copy is on the parent"
    )

    child = env.create_branch("child", ancestor_branch_name="main", ancestor_start_lsn=seeded_at)
    paths = aux_paths(env, child, seeded_at)
    assert not {p for p in paths if p.startswith("pg_replslot/")}, paths

    child_endpoint = env.endpoints.create_start("child")
    assert logical_slots(child_endpoint) == []
    after_start = flushed(env, child_endpoint, child)
    paths = aux_paths(env, child, after_start)
    assert not {p for p in paths if p.startswith("pg_replslot/")}, paths
    assert_no_missing_removal(env)
