from __future__ import annotations

import os
import re
import subprocess
import threading
from typing import TYPE_CHECKING

from fixtures.common_types import Lsn
from fixtures.log_helper import log
from fixtures.neon_fixtures import NeonEnv, check_restored_datadir_content
from fixtures.utils import query_scalar

if TYPE_CHECKING:
    from fixtures.neon_fixtures import PgBin


#
# Test multixact state after branching
# Now this test is very minimalistic -
# it only checks next_multixact_id field in restored pg_control,
# since we don't have functions to check multixact internals.
# We do check that the datadir contents exported from the
# pageserver match what the running PostgreSQL produced. This
# is enough to verify that the WAL records are handled correctly
# in the pageserver.
#
def test_multixact(neon_simple_env: NeonEnv, test_output_dir):
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")

    cur = endpoint.connect().cursor()
    cur.execute(
        """
        CREATE TABLE t1(i int primary key, n_updated int);
        INSERT INTO t1 select g, 0 from generate_series(1, 50) g;
    """
    )

    next_multixact_id_old = query_scalar(
        cur, "SELECT next_multixact_id FROM pg_control_checkpoint()"
    )

    # Lock entries using parallel connections in a round-robin fashion.
    nclients = 20
    update_every = 97
    connections = []
    for _ in range(nclients):
        # Do not turn on autocommit. We want to hold the key-share locks.
        conn = endpoint.connect(autocommit=False)
        connections.append(conn)

    # On each iteration, we commit the previous transaction on a connection,
    # and issue another select. Each SELECT generates a new multixact that
    # includes the new XID, and the XIDs of all the other parallel transactions.
    # This generates enough traffic on both multixact offsets and members SLRUs
    # to cross page boundaries.
    for i in range(20000):
        conn = connections[i % nclients]
        conn.commit()

        # Perform some non-key UPDATEs too, to exercise different multixact
        # member statuses.
        if i % update_every == 0:
            conn.cursor().execute(f"update t1 set n_updated = n_updated + 1 where i = {i % 50}")
        else:
            conn.cursor().execute("select * from t1 for key share")

    # We have multixacts now. We can close the connections.
    for c in connections:
        c.close()

    # force wal flush
    cur.execute("checkpoint")

    cur.execute(
        "SELECT next_multixact_id, pg_current_wal_insert_lsn() FROM pg_control_checkpoint()"
    )
    res = cur.fetchone()
    assert res is not None
    next_multixact_id = res[0]
    lsn = res[1]

    # Ensure that we did lock some tuples
    assert int(next_multixact_id) > int(next_multixact_id_old)

    # Branch at this point
    env.create_branch("test_multixact_new", ancestor_branch_name="main", ancestor_start_lsn=lsn)
    endpoint_new = env.endpoints.create_start("test_multixact_new")

    next_multixact_id_new = endpoint_new.safe_psql(
        "SELECT next_multixact_id FROM pg_control_checkpoint()"
    )[0][0]

    # Check that we restored pg_controlfile correctly
    assert next_multixact_id_new == next_multixact_id

    # Check that we can restore the content of the datadir correctly
    check_restored_datadir_content(test_output_dir, env, endpoint)


CREATE_ID_RE = re.compile(r"lsn: ([0-9A-F]+/[0-9A-F]+), .*desc: (\w+)(?: (\d+) offset)?")


def multixact_records(pg_bin: PgBin, pg_wal_dir: str) -> list[tuple[str, str, int | None]]:
    """(start LSN, record type, mid for CREATE_ID) of every MultiXact WAL record, in WAL order."""
    segments = sorted(f for f in os.listdir(pg_wal_dir) if re.fullmatch(r"[0-9A-F]{24}", f))
    pg_waldump = os.path.join(pg_bin.pg_bin_path, "pg_waldump")
    # --ignore: neon WAL starts with a gap. pg_waldump follows the later segments by
    # itself and stops with an error at the end of the written WAL, which is expected.
    out = subprocess.run(
        [pg_waldump, "--ignore", "-r", "MultiXact", os.path.join(pg_wal_dir, segments[0])],
        capture_output=True,
        text=True,
    ).stdout
    records: list[tuple[str, str, int | None]] = []
    for line in out.splitlines():
        m = CREATE_ID_RE.search(line)
        if m:
            mid = int(m.group(3)) if m.group(3) is not None else None
            records.append((m.group(1), m.group(2), mid))
    return records


def find_next_offset_gap(records: list[tuple[str, str, int | None]]) -> tuple[str, int] | None:
    """
    Find a point in the WAL where multixact `mid` exists, `mid + 1` was assigned but its
    CREATE_ID record isn't logged yet, and a later multixact is. Returns (LSN of the next
    MultiXact record, mid): a branch there has nextMulti > mid + 1 and no record for mid + 1.
    """
    created: set[int] = set()
    missing: set[int] = set()
    max_mid: int | None = None
    for i, (_, kind, mid) in enumerate(records[:-1]):
        if kind != "CREATE_ID" or mid is None:
            continue
        created.add(mid)
        if max_mid is None:
            max_mid = mid
        elif mid > max_mid:
            missing.update(range(max_mid + 1, mid))
            max_mid = mid
        else:
            missing.discard(mid)
        for m in missing:
            if m - 1 in created:
                return records[i + 1][0], m - 1
    return None


#
# Postgres' RecordNewMultiXact also writes the next multixact's starting offset, and
# GetMultiXactIdMembers relies on it ("MultiXact N has invalid next offset") when the
# next multixact was assigned but its own record isn't there. That happens when two
# backends create multixacts concurrently and the later one is logged first; a branch
# (or a restarted compute) cut between the two records keeps the gap forever.
# Neon's redo used to write only the multixact's own entry.
#
def test_multixact_next_offset_after_restart(neon_simple_env: NeonEnv, pg_bin: PgBin):
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main")
    assert endpoint.pgdata_dir
    pg_wal_dir = os.path.join(endpoint.pgdata_dir, "pg_wal")

    nthreads = 16
    per_thread = 400
    with endpoint.cursor() as cur:
        for t in range(nthreads):
            cur.execute(f"CREATE TABLE t{t}(i int primary key); INSERT INTO t{t} VALUES (1)")

    def create_multixacts():
        # Each table's row is share-locked by a long-lived holder; every FOR SHARE from
        # another transaction then creates a new multixact. The threads use separate
        # tables, so the multixact creations really run in parallel.
        holders = []
        for t in range(nthreads):
            holder = endpoint.connect(autocommit=False)
            holder.cursor().execute(f"SELECT * FROM t{t} FOR SHARE")
            holders.append(holder)

        barrier = threading.Barrier(nthreads)
        errors: list[BaseException] = []

        def worker(t: int):
            try:
                with endpoint.cursor() as cur:
                    barrier.wait()
                    for _ in range(per_thread):
                        cur.execute(f"SELECT * FROM t{t} FOR SHARE")
            except BaseException as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(nthreads)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        for holder in holders:
            holder.close()
        assert errors == []

    # Out-of-order logging is a race; it shows up within a round or two in practice.
    gap = None
    creates = 0
    for attempt in range(5):
        create_multixacts()
        records = multixact_records(pg_bin, pg_wal_dir)
        creates = sum(1 for r in records if r[1] == "CREATE_ID")
        gap = find_next_offset_gap(records)
        log.info(f"attempt {attempt}: {creates} CREATE_ID records, gap {gap}")
        if gap is not None:
            break
    assert gap is not None, "no out-of-order multixact creation was logged"
    # Enough multixacts to span several offsets pages (2048 entries each).
    assert creates > 2 * 2048

    lsn, mid = gap
    # Whether mid + 1's entry is on the next offsets page (the cross-page path).
    log.info(f"gap at mid {mid}, straddles an offsets page: {(mid + 1) % 2048 == 0}")
    env.create_branch("mx_gap", ancestor_branch_name="main", ancestor_start_lsn=Lsn(lsn))
    endpoint_gap = env.endpoints.create_start("mx_gap")

    # Reading the members needs mid + 1's offset, which only mid's record set.
    members = endpoint_gap.safe_psql(f"SELECT xid FROM pg_get_multixact_members('{mid}')")
    assert len(members) >= 2
