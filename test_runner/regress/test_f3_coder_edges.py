"""
F3 coder edges beyond the RED set (fork round 4, final fix round).

- K5: a symlink to a FIFO at the storage token path is refused from the `stat()` (which
  follows the link) like a FIFO itself: no hang, one WARNING naming the path.
- K6: COMMENT ON ROLE / SECURITY LABEL ON ROLE on a managed name in another case, after
  SET ROLE from a superuser, and on a role that doesn't exist.
- K1(b): a restart of the compute's own data directory after a clean shutdown records no
  discarded slot copy (only a basebackup start does).
- The fixture: `Endpoint.clear_buffers()`, with and without a cursor, leaves none of a
  table's pages in the LFC (its 0-then-restore of the limit is asynchronous).
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import psycopg2
import pytest
from fixtures.pg_version import PgVersion
from fixtures.token_files import (
    PAGESERVER_AUTH_ERRORS,
    TABLE_ROWS,
    log_since,
    log_size,
    make_table,
    new_session_cannot_read,
    new_session_reads,
    reader_warnings,
    replace_file,
    start_with_storage_auth,
)
from fixtures.utils import USE_LFC, run_only_on_postgres
from psycopg2.errors import InsufficientPrivilege, UndefinedObject
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import NeonEnv, NeonEnvBuilder, PgBin, VanillaPostgres
    from pytest_httpserver import HTTPServer
    from werkzeug.wrappers.request import Request

MARKER = "chelabase.managed_role"
MEMBER = "cb_m_0123456789abcdef0123456789abcdef"
# The same name in capitals, quoted: another role, still managed by its name.
UPPER_QUOTED = '"' + MEMBER.upper() + '"'


@run_only_on_postgres([PgVersion.V17], "the slot.c change is in the v17 fork only")
def test_a_restart_after_a_clean_shutdown_records_no_discarded_slot(
    neon_simple_env: NeonEnv, pg_bin: PgBin
):
    """
    K1(b), audit hardening: a walsender killed after the shutdown checkpoint can leave its
    temporary slot's directory behind under DB_SHUTDOWNED. A restart of that same data
    directory deletes the slot but must not remove a pageserver copy it never had: only a
    basebackup start (DB_SHUTDOWNED with checkpoint location 0) records discarded names.
    neon.signal is removed so Postgres starts as a plain restart of its own directory.
    """
    endpoint = neon_simple_env.endpoints.create_start("main")
    slot = "left_tmp"
    with endpoint.cursor() as cur:
        cur.execute("SELECT pg_create_logical_replication_slot(%s, 'test_decoding', true)", (slot,))
        cur.execute("SELECT pg_read_binary_file(%s)", (f"pg_replslot/{slot}/state",))
        row = cur.fetchone()
        assert row is not None
        state = bytes(row[0])
    endpoint.stop()

    pgdata = endpoint.pg_data_dir_path()
    slot_dir = pgdata / "pg_replslot" / slot
    slot_dir.mkdir(mode=0o700)
    (slot_dir / "state").write_bytes(state)
    (pgdata / "neon.signal").unlink(missing_ok=True)

    log_path = pgdata.parent / "restart.log"
    # Without safekeepers: the walproposer refuses a start that isn't the safekeepers' latest
    # basebackup LSN (it PANICs), and nothing here needs WAL to leave the compute.
    pg_bin.run(
        [
            "pg_ctl",
            "-D",
            str(pgdata),
            "-l",
            str(log_path),
            "-o",
            "-c neon.safekeepers=",
            "-w",
            "-t",
            "60",
            "start",
        ]
    )
    try:
        assert endpoint.safe_psql("SELECT 1") == [(1,)]
        assert not slot_dir.exists(), "setup: the left-behind slot wasn't restored and deleted"
    finally:
        pg_bin.run(["pg_ctl", "-D", str(pgdata), "-m", "fast", "-w", "stop"])

    text = log_path.read_text(errors="replace")
    assert "database system was shut down" in text, "setup: not a restart after a clean shutdown"
    assert f'discarded replication slot "{slot}"' not in text, (
        "a restart of the compute's own data directory removed a slot copy it never had"
    )


@pytest.mark.skipif(not USE_LFC, reason="needs the LFC")
def test_clear_buffers_empties_the_lfc_of_a_table(neon_simple_env: NeonEnv):
    """Each time right after a full read of the table, so the clear races the reload."""
    # A 1 MB LFC holds a single chunk, which the catalogs share: make room for the table.
    endpoint = neon_simple_env.endpoints.create_start(
        "main",
        config_lines=[
            "autovacuum=off",
            "neon.max_file_cache_size=64MB",
            "neon.file_cache_size_limit=64MB",
        ],
    )
    conn = endpoint.connect()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("CREATE EXTENSION IF NOT EXISTS neon")
    cur.execute("CREATE EXTENSION IF NOT EXISTS neon_test_utils")
    cur.execute(
        "CREATE TABLE lfc_t AS SELECT g, repeat('x', 200) AS pad FROM generate_series(1, 2000) g"
    )

    def cached_pages() -> int:
        cur.execute(
            "SELECT count(*) FROM local_cache WHERE relfilenode = pg_relation_filenode('lfc_t')"
        )
        row = cur.fetchone()
        assert row is not None
        return int(row[0])

    for with_cursor in [False, True] * 5:
        cur.execute("SELECT clear_buffer_cache()")
        cur.execute("SELECT count(*) FROM lfc_t")
        assert cached_pages() > 0, "setup: the read didn't fill the LFC"
        endpoint.clear_buffers(cursor=cur if with_cursor else None)
        assert cached_pages() == 0, f"clear_buffers(cursor={with_cursor}) left pages in the LFC"


def test_a_symlink_to_a_fifo_is_never_opened(neon_env_builder: NeonEnvBuilder):
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint = start_with_storage_auth(env)
    admin = make_table(endpoint)
    path = endpoint.storage_auth_token_file
    good = path.read_bytes()

    fifo = path.with_name("f3-edge.fifo")
    os.mkfifo(fifo, 0o600)
    path.unlink()
    path.symlink_to(fifo)

    endpoint.clear_buffers(cursor=admin)
    offset = log_size(endpoint)
    # A blocking open of the FIFO would hang this session (nobody writes to it).
    new_session_cannot_read(endpoint, "a symlink to a FIFO")
    text = log_since(endpoint, offset)
    assert reader_warnings(text, path), "no WARNING names the token path"
    assert "not a regular file" in text

    path.unlink()
    fifo.unlink()
    replace_file(path, good)
    assert new_session_reads(endpoint) == TABLE_ROWS


@pytest.fixture
def guarded_pg(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
):
    (host, port) = httpserver_listen_address
    endpoint = "/test/roles_and_databases"

    def record(request: Request) -> Response:
        json.loads(request.get_data(as_text=True))
        return Response(status=200)

    httpserver.expect_request(endpoint, method="PATCH").respond_with_handler(record)
    vanilla_pg.configure(
        [f"neon.console_url=http://{host}:{port}{endpoint}", "shared_preload_libraries = 'neon'"]
    )
    vanilla_pg.start()
    vanilla_pg.safe_psql_many(
        [
            "CREATE ROLE neon_superuser NOLOGIN CREATEDB CREATEROLE",
            "CREATE ROLE owner LOGIN CREATEROLE PASSWORD 'pw' IN ROLE neon_superuser",
            "CREATE ROLE alice LOGIN PASSWORD 'pw'",
            f"ALTER ROLE alice SET {MARKER} = 'personal'",
            f"CREATE ROLE {UPPER_QUOTED} LOGIN PASSWORD 'pw'",
            "GRANT alice TO owner WITH ADMIN OPTION",
            f"GRANT {UPPER_QUOTED} TO owner WITH ADMIN OPTION",
        ]
    )
    return vanilla_pg


def owner_runs(pg: VanillaPostgres, sql: str) -> None:
    login: dict[str, Any] = {"user": "owner", "password": "pw"}
    with pg.cursor(**login) as cur:
        cur.execute(sql)


def test_a_managed_name_in_another_case_is_refused(guarded_pg: VanillaPostgres):
    for sql in [
        f"COMMENT ON ROLE {UPPER_QUOTED} IS 'x'",
        f"SECURITY LABEL ON ROLE {UPPER_QUOTED} IS 'MASKED'",
    ]:
        with pytest.raises(InsufficientPrivilege) as e:
            owner_runs(guarded_pg, sql)
        expected = f"member role {UPPER_QUOTED} is managed by Chelabase"
        assert e.value.diag.message_primary == expected


def test_set_role_from_a_superuser_is_refused(guarded_pg: VanillaPostgres):
    """The guard keys on the current user: a superuser session after SET ROLE owner."""
    with guarded_pg.cursor() as cur:
        cur.execute("SET ROLE owner")
        with pytest.raises(InsufficientPrivilege):
            cur.execute("COMMENT ON ROLE alice IS 'x'")
    rows = guarded_pg.safe_psql(
        "SELECT pg_catalog.shobj_description(oid, 'pg_authid') FROM pg_catalog.pg_roles"
        " WHERE rolname = 'alice'"
    )
    assert rows == [(None,)]


def test_a_missing_role_gets_postgres_own_error(guarded_pg: VanillaPostgres):
    """An ordinary name with no role behind it is not the guard's: Postgres says it is missing."""
    with pytest.raises(UndefinedObject):
        owner_runs(guarded_pg, "COMMENT ON ROLE nobody_here IS 'x'")
    # A managed name is refused by name, whether or not the role exists.
    with pytest.raises(InsufficientPrivilege):
        owner_runs(guarded_pg, "COMMENT ON ROLE cb_m_ffffffffffffffffffffffffffffffff IS 'x'")
    with pytest.raises(psycopg2.Error):
        owner_runs(guarded_pg, "COMMENT ON ROLE nobody_here IS NULL")
