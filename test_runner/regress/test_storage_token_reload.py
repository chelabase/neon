"""
Storage token refresh (spec §8; K5 with K3's compute_ctl side).

compute_ctl writes the tenant storage token to its file at start, first in
every `/configure` and on `POST /storage_token`; the neon extension reads the
file before every new pageserver connection (libpagestore, each reconnect,
mid-statement included) and every new safekeeper connection (the
walproposer, `neon_walreader`), so a new token reaches new connections with no
reload and no restart, while open connections keep working past `exp` (the
servers check a token at connection start only).

Tokens are minted here with numeric `exp`/`iat` (PyJWT; the fixture's helper
stringifies claims). The storage servers allow 60 s of `exp` leeway, so an
expired token is minted 300 s in the past (SP8).
"""

from __future__ import annotations

import threading
import time
from contextlib import closing
from typing import TYPE_CHECKING

import psycopg2
from fixtures.token_files import (
    PAGESERVER_AUTH_ERRORS,
    TABLE_ROWS,
    assert_no_token_in_logs,
    expired_tenant_token,
    fresh_tenant_token,
    log_since,
    log_size,
    make_table,
    new_session_cannot_read,
    new_session_reads,
    restart_pageserver,
    start_with_storage_auth,
)
from fixtures.utils import wait_until

if TYPE_CHECKING:
    from typing import Any

    from fixtures.neon_fixtures import Endpoint, NeonEnvBuilder


def _conf_load_time(endpoint: Endpoint) -> Any:
    with endpoint.cursor() as cur:
        cur.execute("SELECT pg_conf_load_time()")
        row = cur.fetchone()
    assert row is not None
    return row[0]


def _conf_load_time_on(cur: Any) -> Any:
    """
    `pg_conf_load_time()` seen by an open session, for when a new session
    can't connect (an expired token in the file). A backend takes a pending
    SIGHUP before its next command, so the first command after a short wait
    processes any reload and the second reports it.
    """
    time.sleep(0.5)
    cur.execute("SELECT 1")
    cur.execute("SELECT pg_conf_load_time()")
    row = cur.fetchone()
    assert row is not None
    return row[0]


def test_configure_with_a_new_token_reaches_new_sessions(neon_env_builder: NeonEnvBuilder):
    """
    `/configure` with a new token rewrites the file, and the next new session's
    pageserver connection presents it: an expired one is refused, a fresh one
    reads pages.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint = start_with_storage_auth(env)
    original = endpoint.storage_auth_token_file.read_text()[:-1]
    admin = make_table(endpoint)

    expired = expired_tenant_token(env, env.initial_tenant)
    endpoint.respec_deep(spec={"storage_auth_token": expired})
    endpoint.reconfigure()
    assert endpoint.storage_auth_token_file.read_text() == expired + "\n"
    endpoint.clear_buffers(cursor=admin)
    new_session_cannot_read(endpoint, "an expired token through /configure")

    fresh = fresh_tenant_token(env, env.initial_tenant)
    endpoint.respec_deep(spec={"storage_auth_token": fresh})
    endpoint.reconfigure()
    assert endpoint.storage_auth_token_file.read_text() == fresh + "\n"
    assert new_session_reads(endpoint) == TABLE_ROWS

    assert_no_token_in_logs(env, endpoint, [original, expired, fresh])


def test_an_expired_token_refuses_new_sessions_only(neon_env_builder: NeonEnvBuilder):
    """
    A token pushed already expired (`POST /storage_token`): a new session's
    page read fails, an open session keeps reading on its connection, and a
    fresh push restores new sessions, with no reload at any point.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint = start_with_storage_auth(env)
    original = endpoint.storage_auth_token_file.read_text()[:-1]
    admin = make_table(endpoint)
    http = endpoint.http_client()

    with closing(endpoint.connect()) as session:
        open_cur = session.cursor()
        endpoint.clear_buffers(cursor=admin)
        open_cur.execute("SELECT count(*) FROM k5_t")
        assert open_cur.fetchone() == (TABLE_ROWS,)

        loaded = _conf_load_time_on(open_cur)
        expired = expired_tenant_token(env, env.initial_tenant)
        http.storage_token(expired)
        assert endpoint.storage_auth_token_file.read_text() == expired + "\n"
        # Measured on the open session: a new one is refused from now on.
        assert _conf_load_time_on(open_cur) == loaded, "the refresh reloaded the configuration"

        endpoint.clear_buffers(cursor=admin)
        new_session_cannot_read(endpoint, "an expired token through /storage_token")

        # The open session's pageserver connection was authenticated at its
        # start; it keeps working.
        endpoint.clear_buffers(cursor=open_cur)
        open_cur.execute("SELECT count(*) FROM k5_t")
        assert open_cur.fetchone() == (TABLE_ROWS,)

        # `clear_buffers` above reloaded (ALTER SYSTEM resets the LFC); take the
        # baseline after it, on the open session (the expired token is still in
        # the file, so a new session is refused).
        loaded = _conf_load_time_on(open_cur)
        fresh = fresh_tenant_token(env, env.initial_tenant)
        http.storage_token(fresh)
        assert new_session_reads(endpoint) == TABLE_ROWS
        # The same session's view both times: each backend stamps a reload
        # when it takes the SIGHUP, so sessions can differ.
        assert _conf_load_time_on(open_cur) == loaded, "the refresh reloaded the configuration"

    assert http.status()["status"] == "running"
    assert_no_token_in_logs(env, endpoint, [original, expired, fresh])


def test_refresh_never_fails_a_running_compute(neon_env_builder: NeonEnvBuilder):
    """
    RT4-3: `POST /storage_token` only replaces the file: the compute stays
    `running`, Postgres is neither reloaded nor restarted, and repeated
    refreshes are each read by the next new connection.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    endpoint = start_with_storage_auth(env)
    original = endpoint.storage_auth_token_file.read_text()[:-1]
    admin = make_table(endpoint)
    http = endpoint.http_client()
    assert "storage_token_refresh" in http.status().get("capabilities", [])

    postmaster = (endpoint.pg_data_dir_path() / "postmaster.pid").read_text().split()[0]
    pushed: list[str] = []
    for _ in range(5):
        # `clear_buffers` reloads (it resets the LFC through ALTER SYSTEM), so
        # the load time is compared around the refresh itself.
        loaded = _conf_load_time(endpoint)
        token = fresh_tenant_token(env, env.initial_tenant, ttl=3600 + len(pushed))
        http.storage_token(token)
        pushed.append(token)
        assert _conf_load_time(endpoint) == loaded, "the refresh reloaded the configuration"
        assert http.status()["status"] == "running"
        assert endpoint.storage_auth_token_file.read_text() == token + "\n"
        endpoint.clear_buffers(cursor=admin)
        assert new_session_reads(endpoint) == TABLE_ROWS

    assert (endpoint.pg_data_dir_path() / "postmaster.pid").read_text().split()[0] == postmaster
    assert_no_token_in_logs(env, endpoint, [original, *pushed])


def test_a_long_statement_reconnects_with_the_new_token(neon_env_builder: NeonEnvBuilder):
    """
    A statement whose pageserver connection breaks mid-way reconnects with
    the file as it is then: refused while it holds an expired token, served
    once a fresh token is pushed, all within the one statement.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint = start_with_storage_auth(env)
    original = endpoint.storage_auth_token_file.read_text()[:-1]
    admin = make_table(endpoint)
    admin.execute(
        """
        CREATE FUNCTION k5_slow_count(secs float8) RETURNS bigint LANGUAGE plpgsql AS $$
        DECLARE n bigint;
        BEGIN
            PERFORM count(*) FROM k5_t;
            PERFORM pg_sleep(secs);
            SELECT count(*) INTO n FROM k5_t;
            RETURN n;
        END $$
        """
    )
    http = endpoint.http_client()

    with closing(endpoint.connect()) as session:
        cur = session.cursor()
        # Ride out the pageserver restart and the expired token.
        cur.execute("SET neon.max_reconnect_attempts = 600")
        cur.execute("SELECT pg_backend_pid()")
        row = cur.fetchone()
        assert row is not None
        pid = int(row[0])
        endpoint.clear_buffers(cursor=admin)

        result: dict[str, Any] = {}

        def run():
            try:
                cur.execute("SELECT k5_slow_count(20)")
                fetched = cur.fetchone()
                result["count"] = None if fetched is None else fetched[0]
            except Exception as e:
                result["error"] = e

        statement = threading.Thread(target=run)
        statement.start()

        def sleeping():
            admin.execute("SELECT wait_event FROM pg_stat_activity WHERE pid = %s", (pid,))
            assert admin.fetchone() == ("PgSleep",)

        wait_until(sleeping, timeout=30)

        offset = log_size(endpoint)
        expired = expired_tenant_token(env, env.initial_tenant)
        http.storage_token(expired)
        endpoint.clear_buffers(cursor=admin)
        restart_pageserver(env)

        def refused_with_the_expired_token():
            lines = [
                line
                for line in log_since(endpoint, offset).splitlines()
                if f"[{pid}]" in line
                and "could not connect to pageserver" in line
                and "JWT authentication error" in line
            ]
            assert lines, "the statement hasn't been refused yet"

        wait_until(refused_with_the_expired_token, timeout=90)

        fresh = fresh_tenant_token(env, env.initial_tenant)
        http.storage_token(fresh)
        statement.join(timeout=120)
        assert not statement.is_alive(), "the statement didn't finish"
        assert result == {"count": TABLE_ROWS}, result

    assert_no_token_in_logs(env, endpoint, [original, expired, fresh])


def test_walproposer_reconnects_with_the_refreshed_token(neon_env_builder: NeonEnvBuilder):
    """
    The walproposer reads the file at every safekeeper connect: after a
    safekeeper restart it can't reconnect while the file holds an expired
    token, and does once a fresh one is pushed; commits flow again.
    """
    neon_env_builder.auth_enabled = True
    neon_env_builder.num_safekeepers = 1
    env = neon_env_builder.init_start()
    endpoint = start_with_storage_auth(env)
    original = endpoint.storage_auth_token_file.read_text()[:-1]
    http = endpoint.http_client()
    endpoint.safe_psql("CREATE TABLE k5_w (x int)")
    endpoint.safe_psql("INSERT INTO k5_w VALUES (1)")

    sk = env.safekeepers[0]
    sk_http = sk.http_client()

    def walreceivers() -> int:
        status = sk_http.timeline_status(env.initial_tenant, env.initial_timeline)
        return len(status.walreceivers)

    def connected():
        assert walreceivers() > 0

    wait_until(connected, timeout=30)

    offset = log_size(endpoint)
    expired = expired_tenant_token(env, env.initial_tenant)
    http.storage_token(expired)
    sk.stop()
    sk.start()

    def refused():
        lines = [
            line
            for line in log_since(endpoint, offset).splitlines()
            if "[WP]" in line and "JWT authentication error" in line
        ]
        assert lines, "the walproposer hasn't been refused yet"

    wait_until(refused, timeout=60)
    for _ in range(10):
        assert walreceivers() == 0, "the walproposer reconnected with an expired token"
        time.sleep(0.5)

    fresh = fresh_tenant_token(env, env.initial_tenant)
    http.storage_token(fresh)
    wait_until(connected, timeout=60)
    endpoint.safe_psql("INSERT INTO k5_w VALUES (2)")
    assert endpoint.safe_psql("SELECT count(*) FROM k5_w") == [(2,)]

    assert_no_token_in_logs(env, endpoint, [original, expired, fresh])


def test_refresh_racing_new_connections(neon_env_builder: NeonEnvBuilder):
    """
    A burst of new connections while the token is refreshed again and again:
    every connection reads a whole, valid token (compute_ctl renames complete
    files; the reader records the inode it actually read).
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    endpoint = start_with_storage_auth(env)
    original = endpoint.storage_auth_token_file.read_text()[:-1]
    admin = make_table(endpoint)
    tokens = [fresh_tenant_token(env, env.initial_tenant, ttl=3600 + i) for i in range(2)]
    endpoint.clear_buffers(cursor=admin)

    stop = threading.Event()
    errors: list[BaseException] = []
    refreshes = [0]

    def refresher():
        try:
            client = endpoint.http_client()
            while not stop.is_set():
                client.storage_token(tokens[refreshes[0] % 2])
                refreshes[0] += 1
        except BaseException as e:
            errors.append(e)

    def clearer():
        try:
            with closing(endpoint.connect()) as conn:
                cur = conn.cursor()
                while not stop.is_set():
                    cur.execute("SELECT clear_buffer_cache()")
                    time.sleep(0.05)
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=refresher), threading.Thread(target=clearer)]
    for t in threads:
        t.start()
    try:
        failures = []
        for i in range(40):
            try:
                assert new_session_reads(endpoint) == TABLE_ROWS
            except psycopg2.Error as e:
                failures.append((i, e))
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=60)

    assert not errors, errors
    assert not failures, failures
    assert refreshes[0] > 0
    assert_no_token_in_logs(env, endpoint, [original, *tokens])
