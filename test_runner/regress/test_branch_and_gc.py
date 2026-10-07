from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import pytest
from fixtures.common_types import Lsn, TimelineId
from fixtures.log_helper import log
from fixtures.neon_fixtures import wait_for_last_flush_lsn
from fixtures.pageserver.http import TimelineCreate406
from fixtures.pageserver.utils import timeline_delete_wait_completed
from fixtures.utils import query_scalar, skip_in_debug_build, wait_until

if TYPE_CHECKING:
    from fixtures.neon_fixtures import NeonEnv


# Test the GC implementation when running with branching.
# This test reproduces the issue https://github.com/neondatabase/neon/issues/707.
#
# Consider two LSNs `lsn1` and `lsn2` with some delta files as follows:
# ...
# p   -> has an image layer xx_p with p < lsn1
# ...
# lsn1
# ...
# q   -> has an image layer yy_q with lsn1 < q < lsn2
# ...
# lsn2
#
# Consider running a GC iteration such that the GC horizon is between p and lsn1
# ...
# p       -> has an image layer xx_p with p < lsn1
# D_start -> is a delta layer D's start (e.g D = '...-...-D_start-D_end')
# ...
# GC_h    -> is a gc horizon such that p < GC_h < lsn1
# ...
# lsn1
# ...
# D_end   -> is a delta layer D's end
# ...
# q       -> has an image layer yy_q with lsn1 < q < lsn2
# ...
# lsn2
#
# As described in the issue #707, the image layer xx_p will be deleted as
# its range is below the GC horizon and there exists a newer image layer yy_q (q > p).
# However, removing xx_p will corrupt any delta layers that depend on xx_p that
# are not deleted by GC. For example, the delta layer D is corrupted in the
# above example because D depends on the image layer xx_p for value reconstruction.
#
# Because the delta layer D covering lsn1 is corrupted, creating a branch
# starting from lsn1 should return an error as follows:
#     could not find data for key ... at LSN ..., for request at LSN ...
@skip_in_debug_build("times out in debug builds")
def test_branch_and_gc(neon_simple_env: NeonEnv):
    env = neon_simple_env
    pageserver_http_client = env.pageserver.http_client()

    tenant, timeline_main = env.create_tenant(
        conf={
            # disable background GC
            "gc_period": "0s",
            # small checkpoint distance to create more delta layer files
            "checkpoint_distance": f"{1024**2}",
            # set the target size to be large to allow the image layer to cover the whole key space
            "compaction_target_size": f"{1024**3}",
            # tweak the default settings to allow quickly create image layers and L1 layers
            "compaction_period": "1 s",
            "compaction_threshold": "2",
            "l0_flush_delay_threshold": "20",
            "l0_flush_stall_threshold": "40",
            "image_creation_threshold": "1",
            # Disable PITR, this test will set an explicit space-based GC limit
            "pitr_interval": "0 s",
        }
    )

    endpoint_main = env.endpoints.create_start("main", tenant_id=tenant)

    main_cur = endpoint_main.connect().cursor()

    main_cur.execute(
        "CREATE TABLE foo(key serial primary key, t text default 'foooooooooooooooooooooooooooooooooooooooooooooooooooo')"
    )
    main_cur.execute("INSERT INTO foo SELECT FROM generate_series(1, 100000)")
    lsn1 = Lsn(query_scalar(main_cur, "SELECT pg_current_wal_insert_lsn()"))
    log.info(f"LSN1: {lsn1}")

    main_cur.execute("INSERT INTO foo SELECT FROM generate_series(1, 100000)")
    lsn2 = Lsn(query_scalar(main_cur, "SELECT pg_current_wal_insert_lsn()"))
    log.info(f"LSN2: {lsn2}")

    # Set the GC horizon so that lsn1 is inside the horizon, which means
    # we can create a new branch starting from lsn1.
    pageserver_http_client.timeline_checkpoint(tenant, timeline_main)
    pageserver_http_client.timeline_gc(tenant, timeline_main, lsn2 - lsn1 + 1024)

    env.create_branch(
        "test_branch", ancestor_branch_name="main", ancestor_start_lsn=lsn1, tenant_id=tenant
    )
    endpoint_branch = env.endpoints.create_start("test_branch", tenant_id=tenant)

    branch_cur = endpoint_branch.connect().cursor()
    branch_cur.execute("INSERT INTO foo SELECT FROM generate_series(1, 100000)")

    assert query_scalar(branch_cur, "SELECT count(*) FROM foo") == 200000


# This test simulates a race condition happening when branch creation and GC are performed concurrently.
#
# Suppose we want to create a new timeline 't' from a source timeline 's' starting
# from a lsn 'lsn'. Upon creating 't', if we don't hold the GC lock and compare 'lsn' with
# the latest GC information carefully, it's possible for GC to accidentally remove data
# needed by the new timeline.
#
# In this test, GC is requested before the branch creation but is delayed to happen after branch creation.
# As a result, when doing GC for the source timeline, we don't have any information about
# the upcoming new branches, so it's possible to remove data that may be needed by the new branches.
# It's the branch creation task's job to make sure the starting 'lsn' is not out of scope
# and prevent creating branches with invalid starting LSNs.
#
# For more details, see discussion in https://github.com/neondatabase/neon/pull/2101#issuecomment-1185273447.
def test_branch_creation_before_gc(neon_simple_env: NeonEnv):
    env = neon_simple_env
    pageserver_http_client = env.pageserver.http_client()

    error_regexes = [
        ".*invalid branch start lsn: less than latest GC cutoff.*",
        ".*invalid branch start lsn: less than planned GC cutoff.*",
    ]
    env.pageserver.allowed_errors.extend(error_regexes)
    env.storage_controller.allowed_errors.extend(error_regexes)

    # Disable background GC but set the `pitr_interval` to be small, so GC can delete something
    tenant, _ = env.create_tenant(
        conf={
            # disable background GC
            "gc_period": "0s",
            # small checkpoint distance to create more delta layer files
            "checkpoint_distance": f"{1024**2}",
            # set the target size to be large to allow the image layer to cover the whole key space
            "compaction_target_size": f"{1024**3}",
            # tweak the default settings to allow quickly create image layers and L1 layers
            "compaction_period": "1 s",
            "compaction_threshold": "2",
            "image_creation_threshold": "1",
            # set PITR interval to be small, so we can do GC
            "pitr_interval": "0 s",
            "lsn_lease_length": "0s",
        }
    )

    b0 = env.create_branch("b0", tenant_id=tenant)
    endpoint0 = env.endpoints.create_start("b0", tenant_id=tenant)
    res = endpoint0.safe_psql_many(
        queries=[
            "CREATE TABLE t(key serial primary key)",
            "INSERT INTO t SELECT FROM generate_series(1, 100000)",
            "SELECT pg_current_wal_insert_lsn()",
            "INSERT INTO t SELECT FROM generate_series(1, 100000)",
        ]
    )
    lsn = Lsn(res[2][0][0])

    # Wait for all WAL to reach the pageserver, so GC cutoff LSN is greater than `lsn`.
    wait_for_last_flush_lsn(env, endpoint0, tenant, b0)

    # Use `failpoint=sleep` and `threading` to make the GC iteration triggers *before* the
    # branch creation task but the individual timeline GC iteration happens *after*
    # the branch creation task.
    pageserver_http_client.configure_failpoints(("before-timeline-gc", "sleep(2000)"))
    pageserver_http_client.timeline_checkpoint(tenant, b0)

    def do_gc():
        pageserver_http_client.timeline_gc(tenant, b0, 0)

    thread = threading.Thread(target=do_gc, daemon=True)
    thread.start()

    # because of network latency and other factors, GC iteration might be processed
    # after the `create_branch` request. Add a sleep here to make sure that GC is
    # always processed before.
    time.sleep(1.0)

    # The starting LSN is invalid as the corresponding record is scheduled to be removed by in-queue GC.
    with pytest.raises(Exception, match="invalid branch start lsn: .*"):
        env.create_branch("b1", ancestor_branch_name="b0", ancestor_start_lsn=lsn, tenant_id=tenant)
    # retry the same with the HTTP API, so that we can inspect the status code
    with pytest.raises(TimelineCreate406):
        new_timeline_id = TimelineId.generate()
        log.info(
            f"Expecting failure for branch behind gc'ing LSN, new_timeline_id={new_timeline_id}"
        )
        pageserver_http_client.timeline_create(env.pg_version, tenant, new_timeline_id, b0, lsn)

    thread.join()


@pytest.mark.parametrize("grpc", [False, True])
def test_read_at_retained_lsn_below_gc_cutoff(neon_simple_env: NeonEnv, grpc: bool):
    """
    A child's branch point stays readable on the parent after GC moved the applied cutoff
    past it: the parent keeps the data at that exact LSN for the child, so a static compute
    (basebackup and get_page) and a new branch there both work. An LSN below the cutoff that
    nothing retains is still refused. The static compute leases the point (D19), so it keeps
    reading there after the children are deleted and GC and gc-compaction ran; a second kept
    point that nothing leased is refused after the same deletion and GC.
    """
    env = neon_simple_env
    ps_http = env.pageserver.http_client()
    refused_basebackup = ".*invalid basebackup (lsn|LSN).*"
    env.pageserver.allowed_errors.extend(
        [
            refused_basebackup,
            # The unretained static compute's own lease request.
            ".*tried to request an lsn lease for an lsn below the latest gc cutoff.*",
        ]
    )

    tenant, main = env.create_tenant(
        conf={
            # GC is triggered by hand
            "gc_period": "0s",
            "compaction_period": "0s",
            "pitr_interval": "0s",
            # Long enough for compute_ctl to renew the static compute's lease; GC waits this
            # long after attach (the lease deadline) before it runs.
            "lsn_lease_length": "20s",
        }
    )
    ep_main = env.endpoints.create_start("main", tenant_id=tenant, grpc=grpc)
    with ep_main.cursor() as cur:
        cur.execute("CREATE TABLE t(x int)")
        cur.execute("INSERT INTO t SELECT generate_series(1, 100)")
        retained = Lsn(query_scalar(cur, "SELECT pg_current_wal_insert_lsn()"))
    wait_for_last_flush_lsn(env, ep_main, tenant, main)
    child = env.create_branch(
        "child", ancestor_branch_name="main", ancestor_start_lsn=retained, tenant_id=tenant
    )

    # A second kept point that no compute ever leases: kept only by its child.
    with ep_main.cursor() as cur:
        cur.execute("INSERT INTO t SELECT generate_series(1001, 1050)")
        kept_unleased = Lsn(query_scalar(cur, "SELECT pg_current_wal_insert_lsn()"))
    wait_for_last_flush_lsn(env, ep_main, tenant, main)
    child_unleased = env.create_branch(
        "child-unleased",
        ancestor_branch_name="main",
        ancestor_start_lsn=kept_unleased,
        tenant_id=tenant,
    )

    with ep_main.cursor() as cur:
        cur.execute("INSERT INTO t SELECT generate_series(101, 200)")
        unretained = Lsn(query_scalar(cur, "SELECT pg_current_wal_insert_lsn()"))
        cur.execute("INSERT INTO t SELECT generate_series(201, 300)")
    wait_for_last_flush_lsn(env, ep_main, tenant, main)
    ps_http.timeline_checkpoint(tenant, main)

    def gc_moved_cutoff_past(lsn: Lsn) -> Lsn:
        ps_http.timeline_gc(tenant, main, 0)
        cutoff = Lsn(ps_http.timeline_detail(tenant, main)["applied_gc_cutoff_lsn"])
        assert cutoff > lsn, f"GC cutoff {cutoff} not past {lsn} yet (lease deadline)"
        return cutoff

    cutoff = wait_until(lambda: gc_moved_cutoff_past(unretained), timeout=60)
    log.info(f"{retained=} {kept_unleased=} {unretained=} {cutoff=}")
    assert retained < kept_unleased < unretained < cutoff

    # A static compute at the retained LSN; neon_local and compute_ctl lease it (D19: a lease
    # below the cutoff is granted at a point GC keeps whole).
    ep_static = env.endpoints.create_start(
        "main",
        endpoint_id="ep-retained",
        tenant_id=tenant,
        lsn=retained,
        grpc=grpc,
    )
    with ep_static.cursor() as cur:
        assert query_scalar(cur, "SELECT count(*) FROM t") == 100
    assert env.pageserver.log_contains(refused_basebackup) is None

    # A new branch at the retained LSN, with a writable compute on it.
    child2 = env.create_branch(
        "child2", ancestor_branch_name="main", ancestor_start_lsn=retained, tenant_id=tenant
    )
    ep_child2 = env.endpoints.create_start("child2", tenant_id=tenant, grpc=grpc)
    with ep_child2.cursor() as cur:
        assert query_scalar(cur, "SELECT count(*) FROM t") == 100
        cur.execute("INSERT INTO t VALUES (0)")
        assert query_scalar(cur, "SELECT count(*) FROM t") == 101
    ep_child2.stop()

    # The children go away; the static compute's lease keeps the point through GC and
    # gc-compaction, and a fresh start there (basebackup and get_page) still reads it.
    for timeline in (child, child2, child_unleased):
        timeline_delete_wait_completed(env.storage_controller.pageserver_api(), tenant, timeline)
    with ep_main.cursor() as cur:
        cur.execute("INSERT INTO t SELECT generate_series(301, 400)")
    wait_for_last_flush_lsn(env, ep_main, tenant, main)
    ps_http.timeline_checkpoint(tenant, main)
    ps_http.timeline_gc(tenant, main, 0)
    ps_http.timeline_compact(tenant, main, enhanced_gc_bottom_most_compaction=True)
    ep_static.stop()
    ep_static.start()
    with ep_static.cursor() as cur:
        assert query_scalar(cur, "SELECT count(*) FROM t") == 100
    ep_static.stop()
    assert env.pageserver.log_contains(refused_basebackup) is None

    # The lease is what kept `retained`: the point kept only by the same deleted children,
    # with no lease, is gone after the same GC.
    with pytest.raises(Exception, match="failed to get basebackup"):
        env.endpoints.create_start(
            "main",
            endpoint_id="ep-kept-unleased",
            tenant_id=tenant,
            lsn=kept_unleased,
            grpc=grpc,
            pageserver_id=env.pageserver.id,
            basebackup_request_tries=1,
        )
    env.pageserver.assert_log_contains(refused_basebackup)

    # An unretained LSN below the cutoff is still refused.
    with pytest.raises(Exception, match="failed to get basebackup"):
        env.endpoints.create_start(
            "main",
            endpoint_id="ep-unretained",
            tenant_id=tenant,
            lsn=unretained,
            grpc=grpc,
            pageserver_id=env.pageserver.id,
            basebackup_request_tries=1,
        )
    env.pageserver.assert_log_contains(refused_basebackup)
