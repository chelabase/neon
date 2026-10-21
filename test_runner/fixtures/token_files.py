"""
Helpers for the token-file tests (`test_token_files.py`,
`test_storage_token_reload.py`; spec §4.1 and §8).

compute_ctl writes the tenant storage token to `Endpoint.storage_auth_token_file`
and the internal API secret to `Endpoint.internal_api_token_file`; the neon
extension reads them (`neon.storage_auth_token_file`, `neon.compute_ctl_token_file`).
The tests run as compute_ctl's user, so they can rewrite the files themselves.

A page read reaches the pageserver only when neither shared buffers nor the LFC
hold the page: `Endpoint.clear_buffers` empties both. A new session's startup
then reads catalog pages through a new pageserver connection, which carries the
token the extension read from the file.
"""

from __future__ import annotations

import os
import re
import time
from typing import TYPE_CHECKING

import jwt
import psycopg2
import pytest

from fixtures.pageserver.utils import wait_until_tenant_active

if TYPE_CHECKING:
    from pathlib import Path

    from psycopg2.extensions import cursor as PgCursor

    from fixtures.common_types import TenantId
    from fixtures.neon_fixtures import Endpoint, NeonEnv

# New connections give up quickly when the pageserver refuses them (the
# default, 60 attempts, takes about a minute). A session that must ride out a
# pageserver restart raises it for itself (`SET`, it is `PGC_USERSET`).
FAST_FAIL = "neon.max_reconnect_attempts=3"

# What the pageserver logs when a compute presents a bad token.
PAGESERVER_AUTH_ERRORS = [
    ".*Unauthorized.*",
    ".*[Aa]uthentication error.*",
    ".*JWT.*",
    ".*[Pp]ermission denied.*",
]

TABLE_ROWS = 2000

PID = re.compile(r"\[(\d+)\]")


def setting(endpoint: Endpoint, name: str) -> tuple[str, str] | None:
    """`(setting, context)` of a GUC from `pg_settings`, or None when unknown."""
    with endpoint.cursor() as cur:
        cur.execute("SELECT setting, context FROM pg_settings WHERE name = %s", (name,))
        row = cur.fetchone()
    return None if row is None else (row[0], row[1])


def start_with_storage_auth(env: NeonEnv, config_lines: list[str] | None = None) -> Endpoint:
    """
    Creates and starts an endpoint on `main` of an auth-enabled environment.
    The start opens a session (the fixture's `SHOW`s), which reads pages
    through a pageserver connection authenticated by the storage token file.
    """
    endpoint = env.endpoints.create(
        "main", config_lines=[FAST_FAIL, "autovacuum=off", *(config_lines or [])]
    )
    try:
        endpoint.start()
    except psycopg2.Error as e:
        raise AssertionError(
            "a compute with storage auth can't open a session (its pageserver connection "
            f"carries no token from {endpoint.storage_auth_token_file}): {e}"
        ) from e
    return endpoint


def replace_file(path: Path, content: bytes, mtime_ns: int | None = None) -> None:
    """Replaces `path` atomically (a new inode), as compute_ctl does."""
    tmp = path.with_name(path.name + ".k5-test")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, content)
        os.fsync(fd)
    finally:
        os.close(fd)
    if mtime_ns is not None:
        os.utime(tmp, ns=(mtime_ns, mtime_ns))
    os.rename(tmp, path)


def overwrite_in_place(path: Path, content: bytes) -> None:
    """Rewrites `path` in place: the same inode, a new size and mtime."""
    with open(path, "wb") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())


def log_size(endpoint: Endpoint) -> int:
    return endpoint.logfile.stat().st_size


def log_since(endpoint: Endpoint, offset: int) -> str:
    with open(endpoint.logfile, "rb") as f:
        f.seek(offset)
        return f.read().decode(errors="replace")


def reader_warnings(text: str, path: Path) -> list[tuple[str, str]]:
    """`(pid, line)` of every Postgres WARNING line naming `path`."""
    found = []
    for line in text.splitlines():
        if "WARNING:" in line and str(path) in line:
            m = PID.search(line)
            found.append((m.group(1) if m else "", line))
    return found


def assert_one_warning_per_process(text: str, path: Path, what: str) -> None:
    """At least one WARNING names `path`, and no process gives more than one."""
    warnings = reader_warnings(text, path)
    assert warnings, f"{what}: no WARNING names {path}"
    per_pid: dict[str, int] = {}
    for pid, _ in warnings:
        per_pid[pid] = per_pid.get(pid, 0) + 1
    repeated = {pid: n for pid, n in per_pid.items() if n > 1}
    assert not repeated, f"{what}: more than one WARNING per process for one state: {warnings}"


def make_table(endpoint: Endpoint) -> PgCursor:
    """
    Creates `k5_t` and returns an admin cursor whose pageserver connection is
    open (it read the table cold), for clearing the buffers later.
    """
    conn = endpoint.connect()
    cur = conn.cursor()
    cur.execute("CREATE EXTENSION IF NOT EXISTS neon_test_utils")
    cur.execute(
        "CREATE TABLE k5_t AS SELECT g, repeat('x', 200) AS pad "
        f"FROM generate_series(1, {TABLE_ROWS}) g"
    )
    endpoint.clear_buffers(cursor=cur)
    cur.execute("SELECT count(*) FROM k5_t")
    assert cur.fetchone() == (TABLE_ROWS,)
    return cur


def new_session_reads(endpoint: Endpoint) -> int:
    """A new session counts `k5_t`."""
    with endpoint.cursor() as cur:
        cur.execute("SELECT count(*) FROM k5_t")
        row = cur.fetchone()
    assert row is not None
    return int(row[0])


def new_session_cannot_read(endpoint: Endpoint, what: str) -> None:
    """A new session, or its first read, fails: its pageserver connection is refused."""
    with pytest.raises(psycopg2.Error):
        new_session_reads(endpoint)
        raise AssertionError(f"{what}: a new session read pages")


def restart_pageserver(env: NeonEnv) -> None:
    """Drops every open pageserver connection; returns once the tenant is active."""
    env.pageserver.stop()
    env.pageserver.start()
    client = env.pageserver.http_client(auth_token=env.auth_keys.generate_pageserver_token())
    wait_until_tenant_active(client, env.initial_tenant, iterations=60, period=1.0)


def mint_tenant_token(env: NeonEnv, tenant_id: TenantId, exp: int) -> str:
    """A tenant token with numeric `iat` and `exp` (the fixture's helper stringifies claims)."""
    return jwt.encode(
        {"scope": "tenant", "tenant_id": str(tenant_id), "iat": int(time.time()), "exp": exp},
        env.auth_keys.priv,
        algorithm="EdDSA",
    )


def expired_tenant_token(env: NeonEnv, tenant_id: TenantId) -> str:
    """Expired beyond the storage servers' 60 s `exp` leeway (SP8)."""
    return mint_tenant_token(env, tenant_id, exp=int(time.time()) - 300)


def fresh_tenant_token(env: NeonEnv, tenant_id: TenantId, ttl: int = 3600) -> str:
    return mint_tenant_token(env, tenant_id, exp=int(time.time()) + ttl)


def token_signature(token: str) -> str:
    """The JWT's signature segment: unique per token (the header isn't)."""
    return token.rsplit(".", 1)[-1]


def assert_no_token_in_logs(env: NeonEnv, endpoint: Endpoint, tokens: list[str]) -> None:
    """No token reaches the compute's, the pageserver's or a safekeeper's log."""
    logs = [endpoint.logfile, env.pageserver.logfile, *(sk.logfile for sk in env.safekeepers)]
    for logfile in logs:
        if not logfile.exists():
            continue
        text = logfile.read_text(errors="replace")
        for token in tokens:
            assert token_signature(token) not in text, f"a storage token reached {logfile}"
