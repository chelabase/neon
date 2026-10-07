from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
from fixtures.common_types import Lsn
from fixtures.log_helper import log
from fixtures.neon_fixtures import NeonEnvBuilder, wait_for_last_flush_lsn
from fixtures.pageserver.utils import last_record_lsn
from fixtures.utils import query_scalar

if TYPE_CHECKING:
    from pathlib import Path

    from fixtures.common_types import TenantId, TimelineId
    from fixtures.pageserver.http import PageserverHttpClient

RECOVERIES = 3


def wait_ingested(
    client: PageserverHttpClient,
    tenant: TenantId,
    timeline: TimelineId,
    lsn: Lsn,
    timeout: float = 1200.0,
) -> None:
    deadline = time.monotonic() + timeout
    while last_record_lsn(client, tenant, timeline) < lsn:
        if time.monotonic() > deadline:
            raise Exception(f"pageserver did not reach {lsn} in {timeout}s")
        time.sleep(0.02)


@pytest.mark.timeout(3600)
def test_multixact_ingest(neon_env_builder: NeonEnvBuilder, test_output_dir: Path):
    """
    Pageserver WAL ingest time for a multixact-heavy workload (~100k CREATE_IDs from
    10 connections taking FOR SHARE locks in turn). The WAL is generated once, then
    re-ingested by the pageserver alone RECOVERIES times (tenant deleted and recreated,
    timeline re-bootstrapped), as in test_ingest_logical_message.py's
    pageserver_recover_ingest. Prints `MXPERF ...` lines and writes them to mxperf.log.

    Not part of any gate. To run it with ci-local.sh (which runs test_runner/regress
    only), copy it into test_runner/regress/ and use
    `--only regress -k test_multixact_ingest -n 1`; compare builds by the
    `ingest_secs` of the three recoveries.
    """
    env = neon_env_builder.init_start()
    endpoint = env.endpoints.create_start(
        "main",
        config_lines=[
            # No backpressure: the compute must not wait for the pageserver.
            "max_replication_apply_lag = 0",
            "max_replication_flush_lag = 0",
            "max_replication_write_lag = 0",
        ],
    )
    client = env.pageserver.http_client()
    tenant, timeline = env.initial_tenant, env.initial_timeline
    wait_for_last_flush_lsn(env, endpoint, tenant, timeline)

    cur = endpoint.connect().cursor()
    cur.execute("CREATE TABLE t(i int primary key, n int)")
    cur.execute("INSERT INTO t SELECT g, 0 FROM generate_series(1, 5) g")
    cur.execute("CHECKPOINT")
    mx_start = int(query_scalar(cur, "SELECT next_multixact_id FROM pg_control_checkpoint()"))
    start_lsn = Lsn(query_scalar(cur, "SELECT pg_current_wal_insert_lsn()"))

    # As test_multixact: each FOR SHARE by one of nclients open transactions gives every
    # locked row a multixact holding the other clients' xids; Postgres reuses one
    # multixact per member set, so each iteration creates one (heap lock records per row).
    nclients = 10
    iterations = 100000
    conns = [endpoint.connect(autocommit=False) for _ in range(nclients)]
    t0 = time.monotonic()
    for i in range(iterations):
        conn = conns[i % nclients]
        conn.commit()
        conn.cursor().execute("SELECT * FROM t FOR SHARE")
    for c in conns:
        c.commit()
        c.close()
    gen_secs = time.monotonic() - t0

    cur.execute("CHECKPOINT")
    mx_end = int(query_scalar(cur, "SELECT next_multixact_id FROM pg_control_checkpoint()"))
    end_lsn = Lsn(query_scalar(cur, "SELECT pg_current_wal_insert_lsn()"))
    wait_for_last_flush_lsn(env, endpoint, tenant, timeline)
    recover_to = Lsn(endpoint.safe_psql("SELECT pg_current_wal_flush_lsn()")[0][0])
    endpoint.stop()

    multixacts = mx_end - mx_start
    wal_mb = (end_lsn - start_lsn) / (1024 * 1024)
    lines = [
        f"MXPERF workload multixacts={multixacts} wal_mb={wal_mb:.1f} gen_secs={gen_secs:.1f}"
    ]

    for r in range(RECOVERIES):
        status = env.storage_controller.inspect(tenant_shard_id=tenant)
        assert status is not None
        client.tenant_delete(tenant)
        env.pageserver.tenant_create(tenant_id=tenant, generation=status[0])
        t_create = time.monotonic()
        client.timeline_create(env.pg_version, tenant, timeline)
        t_ingest = time.monotonic()
        wait_ingested(client, tenant, timeline, recover_to)
        t_done = time.monotonic()
        ingest = t_done - t_ingest
        lines.append(
            f"MXPERF recovery={r} ingest_secs={ingest:.2f} total_secs={t_done - t_create:.2f} "
            f"mx_per_sec={multixacts / ingest:.0f} mb_per_sec={wal_mb / ingest:.1f}"
        )
        log.info(lines[-1])

    # The pageserver really has the data: the endpoint starts and reads the table.
    endpoint.start()
    assert query_scalar(endpoint.connect().cursor(), "SELECT count(*) FROM t") == 5

    for line in lines:
        log.info(line)
        print(line)
    (test_output_dir / "mxperf.log").write_text("\n".join(lines) + "\n")
