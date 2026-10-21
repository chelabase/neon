"""
The neon extension's token reader (spec §4.1, reader side; K5).

compute_ctl writes the internal API secret and the tenant storage token to
files outside pgdata (`<endpoint dir>/compute_ctl_internal.token`,
`<endpoint dir>/storage_auth.token`) and names them in `postgresql.conf` as
`neon.compute_ctl_token_file` and `neon.storage_auth_token_file`
(`PGC_POSTMASTER` string GUCs, default ''). The extension reads the storage
token before each new pageserver or safekeeper connection and the secret
before each call to compute_ctl's internal server, through a per-process
cache `{path, st_dev, st_ino, st_size, st_mtim, value}` refreshed when one
`stat()` shows another identity. A missing, unreadable, empty, oversized or
invalid file gives no token (fail closed; the cached value is dropped) and one
`WARNING` naming the path and the reason, never the content, per state change.
The reader accepts one line of `[A-Za-z0-9._~+/=-]`, 1-8191 bytes, one
trailing `\n` stripped, the whole file at most 8 KiB.

The tests write the files themselves (they run as compute_ctl's user):
compute_ctl writes the storage file only at start, at `/configure` and at
`POST /storage_token`, none of which these tests call while a file is broken,
so nothing races them.

The `extensions-all` image part of spec §4's list (every trusted extension's
file readers and HTTP clients refused) is X6's harness test, not here.
"""

from __future__ import annotations

import os
import platform
import re
import stat
import subprocess
import tarfile
from contextlib import closing
from typing import TYPE_CHECKING

import psycopg2
import pytest
import zstandard
from fixtures.metrics import parse_metrics
from fixtures.paths import BASE_DIR
from fixtures.token_files import (
    FAST_FAIL,
    PAGESERVER_AUTH_ERRORS,
    TABLE_ROWS,
    assert_no_token_in_logs,
    assert_one_warning_per_process,
    log_since,
    log_size,
    make_table,
    new_session_cannot_read,
    new_session_reads,
    overwrite_in_place,
    replace_file,
    restart_pageserver,
    setting,
    start_with_storage_auth,
    token_signature,
)

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any

    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import NeonEnv, NeonEnvBuilder, PgBin
    from fixtures.pg_version import PgVersion
    from pytest_httpserver import HTTPServer


# ---------------------------------------------------------------------------
# Settings and files
# ---------------------------------------------------------------------------


def test_token_file_settings_name_the_files(neon_env_builder: NeonEnvBuilder):
    """
    Both settings exist as postmaster-level settings naming compute_ctl's
    files; the files are 0600, ours, outside pgdata, one line each; the
    postmaster's environment carries no token (the file is the one source).
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    endpoint = start_with_storage_auth(env)

    storage = endpoint.storage_auth_token_file
    internal = endpoint.internal_api_token_file
    assert setting(endpoint, "neon.storage_auth_token_file") == (str(storage), "postmaster")
    assert setting(endpoint, "neon.compute_ctl_token_file") == (str(internal), "postmaster")

    for path in (storage, internal):
        st = path.stat()
        assert stat.S_ISREG(st.st_mode), path
        assert stat.S_IMODE(st.st_mode) == 0o600, path
        assert st.st_uid == os.getuid(), path
        assert not path.is_relative_to(endpoint.pg_data_dir_path()), f"{path} is inside pgdata"
        content = path.read_text()
        assert content.endswith("\n") and content.count("\n") == 1, path

    token = storage.read_text()[:-1]
    assert endpoint.get_compute_spec()["storage_auth_token"] == token

    postmaster_pid = int((endpoint.pg_data_dir_path() / "postmaster.pid").read_text().split()[0])
    with open(f"/proc/{postmaster_pid}/environ", "rb") as f:
        environ = f.read()
    assert b"NEON_AUTH_TOKEN" not in environ
    assert token.encode() not in environ

    # Nobody moves the reader in a session (postmaster context).
    endpoint.safe_psql("CREATE ROLE k5_plain LOGIN")
    with endpoint.cursor(user="k5_plain") as cur:
        with pytest.raises(psycopg2.Error):
            cur.execute("SET neon.storage_auth_token_file = '/tmp/k5-elsewhere'")

    assert_no_token_in_logs(env, endpoint, [token])


def test_no_storage_token_file_without_storage_auth(neon_simple_env: NeonEnv):
    """
    P4: a compute started without a storage token gets an empty storage path:
    no file, no password, no warning; the internal secret's path is always set.
    """
    env = neon_simple_env
    endpoint = env.endpoints.create_start("main", config_lines=[FAST_FAIL])

    assert setting(endpoint, "neon.storage_auth_token_file") == ("", "postmaster")
    assert setting(endpoint, "neon.compute_ctl_token_file") == (
        str(endpoint.internal_api_token_file),
        "postmaster",
    )
    assert not endpoint.storage_auth_token_file.exists()

    admin = make_table(endpoint)
    endpoint.clear_buffers(cursor=admin)
    assert new_session_reads(endpoint) == TABLE_ROWS

    log = endpoint.logfile.read_text()
    token_warnings = [
        line
        for line in log.splitlines()
        if "WARNING:" in line and re.search("token", line, re.IGNORECASE)
    ]
    assert not token_warnings, token_warnings


def test_owner_cannot_read_the_token_files(neon_env_builder: NeonEnvBuilder):
    """
    Spec §4.1: no SQL path lets the database owner (a spec role, so a
    `neon_superuser` member; here also in `pg_monitor`) read either file.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    endpoint = start_with_storage_auth(env)
    endpoint.respec_deep(
        **{
            "spec": {
                "skip_pg_catalog_updates": False,
                "cluster": {"roles": [{"name": "k5_owner", "options": []}]},
            },
        }
    )
    endpoint.reconfigure()
    endpoint.safe_psql("GRANT pg_monitor TO k5_owner")
    # PG15+: the owner can't create in `public`; a schema of its own it can.
    endpoint.safe_psql("CREATE SCHEMA k5_owned AUTHORIZATION k5_owner")
    file_fdw = endpoint.safe_psql(
        "SELECT count(*) FROM pg_available_extensions WHERE name = 'file_fdw'"
    ) == [(1,)]

    with endpoint.cursor(user="k5_owner") as cur:
        cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        assert cur.fetchone() == (False,)
        cur.execute("CREATE TABLE k5_owned.k5_copy (line text)")
        for path in (endpoint.storage_auth_token_file, endpoint.internal_api_token_file):
            p = str(path).replace("'", "''")
            d = str(path.parent).replace("'", "''")
            for statement in [
                f"SELECT pg_read_file('{p}')",
                f"SELECT pg_read_binary_file('{p}')",
                f"SELECT pg_stat_file('{p}')",
                f"SELECT pg_ls_dir('{d}')",
                f"COPY k5_owned.k5_copy FROM '{p}'",
                f"SELECT lo_import('{p}')",
            ]:
                with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                    cur.execute(statement)
        if file_fdw:
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cur.execute("CREATE EXTENSION file_fdw")


# ---------------------------------------------------------------------------
# The storage token reader
# ---------------------------------------------------------------------------


def test_a_broken_storage_token_file_fails_closed(neon_env_builder: NeonEnvBuilder):
    """
    For each way the file can be wrong, new connections go without a token
    (the pageserver refuses them), one WARNING per process names the path and
    never the content, and the next valid file is read again. A symlinked file
    is read like a file.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint = start_with_storage_auth(env)
    admin = make_table(endpoint)

    path = endpoint.storage_auth_token_file
    good = path.read_bytes()
    token = good.decode()[:-1]
    assert new_session_reads(endpoint) == TABLE_ROWS

    def unreadable() -> None:
        replace_file(path, good)
        os.chmod(path, 0)

    broken: list[tuple[str, Any]] = [
        ("missing", lambda: path.unlink()),
        ("empty", lambda: overwrite_in_place(path, b"")),
        ("newline only", lambda: overwrite_in_place(path, b"\n")),
        ("an 8192-byte token", lambda: replace_file(path, b"A" * 8192 + b"\n")),
        ("larger than 8 KiB", lambda: replace_file(path, b"A" * 9000)),
        ("a space", lambda: replace_file(path, (token[:20] + " " + token[20:] + "\n").encode())),
        ("a quote", lambda: replace_file(path, (token[:20] + "'" + token[20:] + "\n").encode())),
        ("two lines", lambda: replace_file(path, good + good)),
        ("CRLF", lambda: replace_file(path, token.encode() + b"\r\n")),
        (
            "a NUL byte",
            lambda: replace_file(path, token[:20].encode() + b"\0" + token[20:].encode() + b"\n"),
        ),
        ("non-ASCII", lambda: replace_file(path, token.encode() + "é\n".encode())),
        ("unreadable", unreadable),
    ]

    for what, breaks in broken:
        endpoint.clear_buffers(cursor=admin)
        offset = log_size(endpoint)
        breaks()
        new_session_cannot_read(endpoint, what)
        assert_one_warning_per_process(log_since(endpoint, offset), path, what)

        # Recovery: the next valid write is read by the next connection.
        if path.exists():
            os.chmod(path, 0o600)
        replace_file(path, good)
        assert new_session_reads(endpoint) == TABLE_ROWS, f"after {what}"

    # A symlink to a valid token file is read like the file.
    elsewhere = path.with_name("k5-elsewhere.token")
    replace_file(elsewhere, good)
    path.unlink()
    path.symlink_to(elsewhere)
    endpoint.clear_buffers(cursor=admin)
    assert new_session_reads(endpoint) == TABLE_ROWS
    path.unlink()
    replace_file(path, good)

    assert_no_token_in_logs(env, endpoint, [token])
    assert "A" * 64 not in endpoint.logfile.read_text(), "a file's content reached compute.log"


def test_a_failed_reread_drops_the_cached_token(neon_env_builder: NeonEnvBuilder):
    """
    RT4-12: a session that has read a valid token and then finds the file
    empty (same inode, other size and mtime) drops its cached value: its next
    pageserver connection goes without a token. A valid file restores it.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint = start_with_storage_auth(env)
    admin = make_table(endpoint)
    path = endpoint.storage_auth_token_file
    good = path.read_bytes()

    with closing(endpoint.connect()) as session:
        cur = session.cursor()
        endpoint.clear_buffers(cursor=admin)
        cur.execute("SELECT count(*) FROM k5_t")
        assert cur.fetchone() == (TABLE_ROWS,)

        endpoint.clear_buffers(cursor=admin)
        overwrite_in_place(path, b"")
        restart_pageserver(env)

        with pytest.raises(psycopg2.Error):
            cur.execute("SELECT count(*) FROM k5_t")
            raise AssertionError("the session reconnected with its cached token")

        replace_file(path, good)
        cur.execute("SELECT count(*) FROM k5_t")
        assert cur.fetchone() == (TABLE_ROWS,)


def test_a_same_tick_replacement_is_read(neon_env_builder: NeonEnvBuilder):
    """
    RT4-12: replacements with the same size and the same mtime (one tick)
    still force a re-read: each rename gives a new inode, and the cache keys on
    the identity of the descriptor it read.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint = start_with_storage_auth(env)
    admin = make_table(endpoint)
    path = endpoint.storage_auth_token_file
    good = path.read_bytes()
    tick = path.stat().st_mtime_ns

    # Same length, same alphabet, a broken signature: the reader takes it, the
    # pageserver refuses it.
    token = good.decode()[:-1]
    i = len(token) - 10
    forged = token[:i] + ("A" if token[i] != "A" else "B") + token[i + 1 :]

    with closing(endpoint.connect()) as session:
        cur = session.cursor()
        endpoint.clear_buffers(cursor=admin)
        cur.execute("SELECT count(*) FROM k5_t")
        assert cur.fetchone() == (TABLE_ROWS,)

        replace_file(path, (forged + "\n").encode(), mtime_ns=tick)
        st = path.stat()
        assert (st.st_size, st.st_mtime_ns) == (len(good), tick)
        endpoint.clear_buffers(cursor=admin)
        restart_pageserver(env)
        with pytest.raises(psycopg2.Error):
            cur.execute("SELECT count(*) FROM k5_t")
            raise AssertionError("the session kept the token of a replaced file")

        replace_file(path, good, mtime_ns=tick)
        cur.execute("SELECT count(*) FROM k5_t")
        assert cur.fetchone() == (TABLE_ROWS,)


def test_sync_safekeepers_reads_the_storage_token_file(
    neon_env_builder: NeonEnvBuilder, pg_bin: PgBin
):
    """
    RT4-11: `postgres --sync-safekeepers` (no shared memory, `CallExtMain`)
    finds the file's path in `postgresql.conf` and authenticates with it; no
    `NEON_AUTH_TOKEN` is needed or used. With a broken file it can't reach the
    safekeepers (it keeps retrying, or gives up); with the file back it
    finishes. Run by hand on the stopped endpoint's pgdata, as compute_ctl
    runs it, because compute_ctl's own start skips it when the safekeepers
    are already in sync.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    endpoint = start_with_storage_auth(env)
    endpoint.safe_psql("CREATE TABLE k5_sync AS SELECT 1 AS x")
    endpoint.stop()

    path = endpoint.storage_auth_token_file
    good = path.read_bytes()
    postgres = pg_bin.pg_bin_path / "postgres"
    sync_env = {k: v for k, v in pg_bin.env.items() if k != "NEON_AUTH_TOKEN"}
    sync_env["PGDATA"] = str(endpoint.pg_data_dir_path())

    def sync(timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(postgres), "--sync-safekeepers"],
            env=sync_env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    done = sync(timeout=60)
    assert done.returncode == 0, done.stderr[-2000:]
    assert re.fullmatch(r"[0-9A-F]+/[0-9A-F]+", done.stdout.strip()), done.stdout

    overwrite_in_place(path, b"")
    try:
        refused = sync(timeout=10)
        assert refused.returncode != 0, "synced with an empty storage token file"
    except subprocess.TimeoutExpired:
        pass

    replace_file(path, good)
    done = sync(timeout=60)
    assert done.returncode == 0, done.stderr[-2000:]
    assert token_signature(good.decode()[:-1]) not in done.stderr


# ---------------------------------------------------------------------------
# The internal API secret reader (compute_ctl's internal server)
# ---------------------------------------------------------------------------

SQL_ONLY = "test_extension_sql_only"
SQL_ONLY_DIR = BASE_DIR / "test_runner" / "regress" / "data" / "test_remote_extensions" / SQL_ONLY


def test_extension_download_needs_the_internal_token(
    httpserver: HTTPServer,
    neon_env_builder_local: NeonEnvBuilder,
    httpserver_listen_address: ListenAddress,
    test_output_dir: Path,
    pg_version: PgVersion,
):
    """
    The extension's `/extension_server` call carries the secret read from
    `neon.compute_ctl_token_file`: with a wrong, empty or missing file the call
    is refused before the handler and nothing is downloaded; with the right
    file again the download works. The same session throughout, so its cache
    goes through every state.
    """
    (host, port) = httpserver_listen_address
    base_url = f"http://{host}:{port}/pg-ext-s3-gateway"

    tarball = test_output_dir / f"{SQL_ONLY}.tar"
    with tarfile.open(tarball, "x") as tarf:
        for version in ("1.0", "1.0--1.1"):
            name = f"{SQL_ONLY}--{version}.sql"
            tarf.add(SQL_ONLY_DIR / "sql" / name, arcname=f"share/extension/{name}")
    compressed = zstandard.ZstdCompressor().compress(tarball.read_bytes())

    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine(), platform.machine())
    build_tag = os.environ.get("BUILD_TAG", "latest")
    httpserver.expect_request(
        f"/pg-ext-s3-gateway/{build_tag}/{arch}/v{pg_version}/extensions/{SQL_ONLY}.tar.zst",
        method="GET",
    ).respond_with_data(compressed, content_type="application/octet-stream")

    env = neon_env_builder_local.init_start()
    endpoint = env.endpoints.create("main")
    spec: dict[str, Any] = {
        "public_extensions": [SQL_ONLY],
        "custom_extensions": None,
        "library_index": {SQL_ONLY: SQL_ONLY},
        "extension_data": {
            SQL_ONLY: {
                "archive_path": "",
                "control_data": {
                    f"{SQL_ONLY}.control": (SQL_ONLY_DIR / f"{SQL_ONLY}.control").read_text()
                },
            },
        },
    }
    endpoint.create_remote_extension_spec(spec)
    endpoint.start(remote_ext_base_url=base_url)

    path = endpoint.internal_api_token_file
    assert setting(endpoint, "neon.compute_ctl_token_file") == (str(path), "postmaster")
    secret = path.read_bytes()
    wrong = (("0" if secret[:1] != b"0" else "1") * 64 + "\n").encode()

    with closing(endpoint.connect()) as conn:
        cur = conn.cursor()
        states: list[tuple[str, Any, bool]] = [
            ("a wrong secret", lambda: replace_file(path, wrong), False),
            ("an empty file", lambda: overwrite_in_place(path, b""), True),
            ("no file", lambda: path.unlink(), True),
        ]
        for what, breaks, reader_refuses in states:
            offset = log_size(endpoint)
            breaks()
            with pytest.raises(psycopg2.Error):
                cur.execute(f"CREATE EXTENSION {SQL_ONLY} VERSION '1.0'")
                raise AssertionError(f"{what}: the extension was downloaded")
            if reader_refuses:
                assert_one_warning_per_process(log_since(endpoint, offset), path, what)

        replace_file(path, secret)
        cur.execute(f"CREATE EXTENSION {SQL_ONLY} VERSION '1.0'")
        cur.execute(f"SELECT {SQL_ONLY}.motd()")

    # Only the call with the right secret reached the handler.
    metrics = parse_metrics(endpoint.http_client().metrics())
    samples = metrics.query_all(
        "compute_ctl_remote_ext_requests_total", {"filename": f"{SQL_ONLY}.tar.zst"}
    )
    assert [s.value for s in samples] == [1], samples

    log = endpoint.logfile.read_text()
    assert secret.decode().strip() not in log, "the secret reached compute.log"
    assert wrong.decode().strip() not in log, "a file's content reached compute.log"
