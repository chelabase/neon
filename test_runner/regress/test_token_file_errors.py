"""
F3 (K5 audit): how the neon extension's token reader (`pgxn/neon/token_file.c`) treats a
failed `open()`/`read()` and a file that isn't a regular file, beside test_token_files.py.

- A transient error (EMFILE, ENFILE, ENOMEM, EIO on `open`; EIO on `read`) is not cached:
  the next call reads the file again although it hasn't changed.
- A permission error (EACCES, EPERM on `open`) stays cached under the file's identity: no
  new `open()` until the file changes (a chmod or a replacement changes its ctime).
- A FIFO or a directory at the path is refused from the `stat()` before any `open()`.

The errors are injected with an LD_PRELOAD shim built here (Postgres' own compiler) that
wraps `open`/`open64`/`read`/`close` for the storage token file only: it logs every `open`
and `read` of the file with the calling pid, and fails one backend's `open` or `read` of it
with a given errno while its control file says so. The storage token is read at each new
pageserver connection, so each step restarts the pageserver and reads a table cold.
"""

from __future__ import annotations

import errno
import os
from contextlib import closing
from typing import TYPE_CHECKING, cast

import psycopg2
import pytest
from fixtures.pg_config import PgConfigKey
from fixtures.token_files import (
    FAST_FAIL,
    PAGESERVER_AUTH_ERRORS,
    TABLE_ROWS,
    assert_one_warning_per_process,
    log_since,
    log_size,
    make_table,
    replace_file,
    restart_pageserver,
    setting,
)
from fixtures.utils import WITH_SANITIZERS, subprocess_capture

if TYPE_CHECKING:
    from pathlib import Path

    from fixtures.neon_fixtures import Endpoint, NeonEnv, NeonEnvBuilder
    from fixtures.pg_config import PgConfig
    from psycopg2.extensions import cursor as PgCursor

SHIM_C = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef int (*open_fn) (const char *, int, ...);
typedef ssize_t (*read_fn) (int, void *, size_t);
typedef int (*close_fn) (int);

static int	target_fd = -1;

static int
real_open(const char *name, const char *path, int flags, mode_t mode)
{
	open_fn		fn = (open_fn) dlsym(RTLD_NEXT, name);

	if (fn == NULL)
		fn = (open_fn) dlsym(RTLD_NEXT, "open");
	return fn(path, flags, mode);
}

static int
is_target(const char *path)
{
	const char *target = getenv("F3_SHIM_TARGET");

	return target != NULL && path != NULL && strcmp(path, target) == 0;
}

/* Appends "<op> <pid>" to $F3_SHIM_LOG. */
static void
log_op(const char *op)
{
	const char *logpath = getenv("F3_SHIM_LOG");
	char		buf[64];
	int			fd,
				n;
	int			saved = errno;

	if (logpath == NULL)
		return;
	fd = real_open("open", logpath, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (fd >= 0)
	{
		n = snprintf(buf, sizeof(buf), "%s %d\n", op, (int) getpid());
		if (write(fd, buf, n) < 0)
		{
		}
		((close_fn) dlsym(RTLD_NEXT, "close")) (fd);
	}
	errno = saved;
}

/* The errno to inject for `op` in this process: $F3_SHIM_CONTROL is "<pid> <errno> <op>". */
static int
injected(const char *op)
{
	const char *control = getenv("F3_SHIM_CONTROL");
	char		buf[64];
	char		want[16];
	int			pid = 0,
				err = 0,
				fd,
				n;

	if (control == NULL)
		return 0;
	fd = real_open("open", control, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0)
		return 0;
	n = (int) ((read_fn) dlsym(RTLD_NEXT, "read")) (fd, buf, sizeof(buf) - 1);
	((close_fn) dlsym(RTLD_NEXT, "close")) (fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	if (sscanf(buf, "%d %d %15s", &pid, &err, want) != 3)
		return 0;
	if (pid != (int) getpid() || strcmp(want, op) != 0)
		return 0;
	return err;
}

static int
shim_open(const char *name, const char *path, int flags, mode_t mode)
{
	int			fd,
				err;

	if (!is_target(path))
		return real_open(name, path, flags, mode);
	log_op("open");
	err = injected("open");
	if (err != 0)
	{
		errno = err;
		return -1;
	}
	fd = real_open(name, path, flags, mode);
	if (fd >= 0)
		target_fd = fd;
	return fd;
}

#define MODE_ARG(flags, mode) \
	do { \
		if (((flags) & O_CREAT) || (((flags) & O_TMPFILE) == O_TMPFILE)) \
		{ \
			va_list ap; \
			va_start(ap, flags); \
			mode = (mode_t) va_arg(ap, int); \
			va_end(ap); \
		} \
	} while (0)

int
open(const char *path, int flags, ...)
{
	mode_t		mode = 0;

	MODE_ARG(flags, mode);
	return shim_open("open", path, flags, mode);
}

int
open64(const char *path, int flags, ...)
{
	mode_t		mode = 0;

	MODE_ARG(flags, mode);
	return shim_open("open64", path, flags, mode);
}

int
__open_2(const char *path, int flags)
{
	return shim_open("open", path, flags, 0);
}

int
__open64_2(const char *path, int flags)
{
	return shim_open("open64", path, flags, 0);
}

ssize_t
read(int fd, void *buf, size_t count)
{
	static read_fn real_read = NULL;

	if (real_read == NULL)
		real_read = (read_fn) dlsym(RTLD_NEXT, "read");
	if (fd >= 0 && fd == target_fd)
	{
		int			err;

		log_op("read");
		err = injected("read");
		if (err != 0)
		{
			errno = err;
			return -1;
		}
	}
	return real_read(fd, buf, count);
}

int
close(int fd)
{
	static close_fn real_close = NULL;

	if (real_close == NULL)
		real_close = (close_fn) dlsym(RTLD_NEXT, "close");
	if (fd >= 0 && fd == target_fd)
		target_fd = -1;
	return real_close(fd);
}
"""


@pytest.fixture
def open_shim(test_output_dir: Path, pg_config: PgConfig) -> Path:
    if WITH_SANITIZERS:
        pytest.skip("an LD_PRELOAD shim doesn't mix with the sanitizer runtime")
    src = test_output_dir / "f3_open_shim.c"
    src.write_text(SHIM_C)
    so = test_output_dir / "f3_open_shim.so"
    cc = cast("list[str]", pg_config[PgConfigKey.CC])
    subprocess_capture(
        test_output_dir,
        [*cc, "-shared", "-fPIC", "-O1", "-o", str(so), str(src), "-ldl"],
        check=True,
    )
    return so


class Shim:
    """The control and log files of the open/read shim, for one target file."""

    def __init__(self, workdir: Path, so: Path, target: Path):
        self.control = workdir / "f3_shim.control"
        self.log = workdir / "f3_shim.log"
        self.control.write_text("")
        self.log.write_text("")
        self.env = {
            "LD_PRELOAD": str(so),
            "F3_SHIM_TARGET": str(target),
            "F3_SHIM_CONTROL": str(self.control),
            "F3_SHIM_LOG": str(self.log),
        }

    def _write_control(self, text: str) -> None:
        tmp = self.control.with_name(self.control.name + ".tmp")
        tmp.write_text(text)
        os.replace(tmp, self.control)

    def inject(self, pid: int, err: int, op: str) -> None:
        """Fail every `op` ("open" or "read") of the target by `pid` with `err`."""
        self._write_control(f"{pid} {err} {op}\n")

    def clear(self) -> None:
        self._write_control("")

    def count(self, op: str, pid: int) -> int:
        return self.log.read_text().splitlines().count(f"{op} {pid}")


def start_with_shim(env: NeonEnv, so: Path, workdir: Path) -> tuple[Endpoint, Shim]:
    endpoint = env.endpoints.create("main", config_lines=[FAST_FAIL, "autovacuum=off"])
    shim = Shim(workdir, so, endpoint.storage_auth_token_file)
    endpoint.start(env=shim.env)
    assert setting(endpoint, "neon.storage_auth_token_file") == (
        str(endpoint.storage_auth_token_file),
        "postmaster",
    ), "setup: the shim's target is the path the reader is given"
    return endpoint, shim


def open_session(endpoint: Endpoint) -> tuple[psycopg2.extensions.connection, PgCursor, int]:
    conn = endpoint.connect()
    conn.autocommit = True
    cur = conn.cursor()
    # The reconnects below must never ask compute_ctl for a configuration refresh.
    cur.execute("SET hadron.conf_refresh_reconnect_attempt_threshold = 1000")
    cur.execute("SELECT pg_backend_pid()")
    row = cur.fetchone()
    assert row is not None
    return conn, cur, int(row[0])


def reconnect_and_count(cur: PgCursor) -> int:
    cur.execute("SELECT count(*) FROM k5_t")
    row = cur.fetchone()
    assert row is not None
    return int(row[0])


def cold_restart(env: NeonEnv, endpoint: Endpoint, admin: PgCursor) -> None:
    """Empties the buffers and drops every pageserver connection: the next read of k5_t
    connects again, reading the storage token file."""
    endpoint.clear_buffers(cursor=admin)
    restart_pageserver(env)


def cannot_read(cur: PgCursor, what: str) -> None:
    with pytest.raises(psycopg2.Error):
        reconnect_and_count(cur)
        raise AssertionError(f"{what}: the session read pages without a usable token")


TRANSIENT = [
    ("open EMFILE", errno.EMFILE, "open"),
    ("open ENFILE", errno.ENFILE, "open"),
    ("open ENOMEM", errno.ENOMEM, "open"),
    ("open EIO", errno.EIO, "open"),
    ("read EIO", errno.EIO, "read"),
]


def test_a_transient_token_file_error_is_retried(
    neon_env_builder: NeonEnvBuilder, open_shim: Path, test_output_dir: Path
):
    """
    After a transient open or read error the reader has no token for that connection,
    and the next connection of the same backend reads the unchanged file again and
    gets the token: the failure is not cached under the file's identity.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint, shim = start_with_shim(env, open_shim, test_output_dir)
    admin = make_table(endpoint)
    path = endpoint.storage_auth_token_file
    good = path.read_bytes()

    conn, cur, pid = open_session(endpoint)
    with closing(conn):
        endpoint.clear_buffers(cursor=admin)
        assert reconnect_and_count(cur) == TABLE_ROWS
        assert shim.count("open", pid) >= 1, "setup: the shim doesn't see the reader's open()"
        assert shim.count("read", pid) >= 1, "setup: the shim doesn't see the reader's read()"

        for what, err, op in TRANSIENT:
            # A new identity, so the next connection opens and reads the file.
            replace_file(path, good)
            shim.inject(pid, err, op)
            cold_restart(env, endpoint, admin)
            offset = log_size(endpoint)
            cannot_read(cur, what)
            assert os.strerror(err) in log_since(endpoint, offset), (
                f"setup: the reader didn't hit {what}"
            )

            # The file is unchanged: only a retry can get the token back.
            shim.clear()
            opens = shim.count("open", pid)
            try:
                rows = reconnect_and_count(cur)
            except psycopg2.Error as e:
                pytest.fail(
                    f"{what} was cached: the backend never read the unchanged file again "
                    f"({shim.count('open', pid) - opens} new open() calls): {e}"
                )
            assert rows == TABLE_ROWS
            assert shim.count("open", pid) > opens


PERMANENT = [
    ("open EACCES", errno.EACCES),
    ("open EPERM", errno.EPERM),
]


def test_a_permission_error_stays_cached(
    neon_env_builder: NeonEnvBuilder, open_shim: Path, test_output_dir: Path
):
    """
    EACCES and EPERM are decided for the file's identity: while the file stays the same
    the backend doesn't open it again (one WARNING), and a changed file is read again.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint, shim = start_with_shim(env, open_shim, test_output_dir)
    admin = make_table(endpoint)
    path = endpoint.storage_auth_token_file
    good = path.read_bytes()

    conn, cur, pid = open_session(endpoint)
    with closing(conn):
        endpoint.clear_buffers(cursor=admin)
        assert reconnect_and_count(cur) == TABLE_ROWS
        assert shim.count("open", pid) >= 1, "setup: the shim doesn't see the reader's open()"

        for what, err in PERMANENT:
            replace_file(path, good)
            shim.inject(pid, err, "open")
            cold_restart(env, endpoint, admin)
            offset = log_size(endpoint)
            cannot_read(cur, what)
            opens = shim.count("open", pid)

            # Unchanged file, error no longer injected: still no token and no new open().
            shim.clear()
            cold_restart(env, endpoint, admin)
            cannot_read(cur, f"{what}, unchanged file")
            assert shim.count("open", pid) == opens, f"{what}: the unchanged file was opened again"
            assert_one_warning_per_process(log_since(endpoint, offset), path, what)

            # A changed file is read again.
            replace_file(path, good)
            assert reconnect_and_count(cur) == TABLE_ROWS, f"after {what}"


def test_a_non_regular_token_file_is_never_opened(
    neon_env_builder: NeonEnvBuilder, open_shim: Path, test_output_dir: Path
):
    """
    A FIFO or a directory at the path is refused from the stat() alone: the backend never
    opens it (an open of a FIFO can wake a writer blocked on it), logs one WARNING, and
    reads the next regular file.
    """
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint, shim = start_with_shim(env, open_shim, test_output_dir)
    admin = make_table(endpoint)
    path = endpoint.storage_auth_token_file
    good = path.read_bytes()

    def fifo() -> None:
        path.unlink()
        os.mkfifo(path, 0o600)

    def directory() -> None:
        path.unlink()
        path.mkdir(mode=0o700)

    def remove_fifo() -> None:
        path.unlink()

    def remove_directory() -> None:
        path.rmdir()

    conn, cur, pid = open_session(endpoint)
    with closing(conn):
        endpoint.clear_buffers(cursor=admin)
        assert reconnect_and_count(cur) == TABLE_ROWS
        assert shim.count("open", pid) >= 1, "setup: the shim doesn't see the reader's open()"

        for what, breaks, undo in [
            ("a FIFO", fifo, remove_fifo),
            ("a directory", directory, remove_directory),
        ]:
            breaks()
            opens = shim.count("open", pid)
            cold_restart(env, endpoint, admin)
            offset = log_size(endpoint)
            cannot_read(cur, what)
            assert shim.count("open", pid) == opens, f"{what} was opened before it was refused"
            assert_one_warning_per_process(log_since(endpoint, offset), path, what)
            assert "not a regular file" in log_since(endpoint, offset)

            undo()
            replace_file(path, good)
            assert reconnect_and_count(cur) == TABLE_ROWS, f"after {what}"
