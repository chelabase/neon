from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from fixtures.compute_migrations import NUM_COMPUTE_MIGRATIONS

if TYPE_CHECKING:
    from pathlib import Path

    from fixtures.neon_fixtures import NeonEnv


def test_compute_migrations_retry(neon_simple_env: NeonEnv, compute_migrations_dir: Path):
    """
    U3: a failure that leaves a fail-open migration unapplied (0001, 0002) fails the start;
    a later one (fail-closed or skip) is logged and the compute starts. Either way the next
    start applies the rest.
    """
    env = neon_simple_env
    endpoint = env.endpoints.create("main")
    endpoint.respec(skip_pg_catalog_updates=False)

    for i in range(1, NUM_COMPUTE_MIGRATIONS + 1):
        failpoint = {"FAILPOINTS": f"compute-migration=return({i})"}
        if i <= 2:
            with pytest.raises(Exception, match="compute startup failed"):
                endpoint.start(env=failpoint)
            assert endpoint.log_contains(f"migration {i} was configured to fail")
            env.neon_cli.endpoint_stop(
                endpoint.endpoint_id, check_return_code=False, mode="immediate"
            )
            continue
        endpoint.start(env=failpoint)
        endpoint.wait_for_migrations(wait_for=i - 1)
        with endpoint.cursor() as cur:
            cur.execute("SELECT id FROM neon_migration.migration_id")
            assert cast("int", cur.fetchall()[0][0]) == i - 1
        endpoint.stop()

    endpoint.start()
    with endpoint.cursor() as cur:
        cur.execute("SELECT id FROM neon_migration.migration_id")
        assert cast("int", cur.fetchall()[0][0]) == NUM_COMPUTE_MIGRATIONS


def test_compute_migrations_e2e(
    neon_simple_env: NeonEnv,
    compute_migrations_dir: Path,
    compute_migrations_test_dir: Path,
    migration: tuple[int, str],
):
    """
    Test that the migrations perform as advertised.
    """
    env = neon_simple_env

    migration_id = migration[0]
    migration_filename = migration[1]

    migration_query = (compute_migrations_dir / migration_filename).read_text(encoding="utf-8")
    if migration_query.startswith("-- SKIP"):
        pytest.skip("The migration is marked as SKIP")

    endpoint = env.endpoints.create("main")
    endpoint.respec(skip_pg_catalog_updates=False)

    # Stop applying migrations after the one we want to test, so that we can
    # test the state of the cluster at the given migration ID
    endpoint.start(env={"FAILPOINTS": f"compute-migration=return({migration_id + 1})"})

    endpoint.wait_for_migrations(wait_for=migration_id)

    check_query = (compute_migrations_test_dir / migration_filename).read_text(encoding="utf-8")
    endpoint.safe_psql(check_query)


def test_migrations_done_when_running(neon_simple_env: NeonEnv):
    env = neon_simple_env
    endpoint = env.endpoints.create("main")
    endpoint.respec(skip_pg_catalog_updates=False)
    endpoint.start()
    with endpoint.cursor() as cur:
        cur.execute("SELECT id FROM neon_migration.migration_id")
        assert cast("int", cur.fetchall()[0][0]) == NUM_COMPUTE_MIGRATIONS


def test_fail_open_migration_failure_fails_the_start(neon_simple_env: NeonEnv):
    env = neon_simple_env
    endpoint = env.endpoints.create("main")
    endpoint.respec(skip_pg_catalog_updates=False)
    with pytest.raises(Exception, match="migration 2"):
        endpoint.start(env={"FAILPOINTS": "compute-migration=return(2)"})
    env.neon_cli.endpoint_stop(endpoint.endpoint_id, check_return_code=False, mode="immediate")
    endpoint.start()
    with endpoint.cursor() as cur:
        cur.execute("SELECT id FROM neon_migration.migration_id")
        assert cast("int", cur.fetchall()[0][0]) == NUM_COMPUTE_MIGRATIONS


def test_fail_closed_migration_failure_starts(neon_simple_env: NeonEnv):
    env = neon_simple_env
    endpoint = env.endpoints.create("main")
    endpoint.respec(skip_pg_catalog_updates=False)
    endpoint.start(env={"FAILPOINTS": f"compute-migration=return({NUM_COMPUTE_MIGRATIONS})"})
    with endpoint.cursor() as cur:
        cur.execute("SELECT id FROM neon_migration.migration_id")
        assert cast("int", cur.fetchall()[0][0]) == NUM_COMPUTE_MIGRATIONS - 1
