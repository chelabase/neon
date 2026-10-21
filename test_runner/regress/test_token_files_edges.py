"""
Edge cases of the neon extension's token reader (spec §4.1, reader side)
beyond `test_token_files.py`: the trailing newline is optional, the longest
token the reader takes (8191 bytes) is passed on, and a FIFO or a directory
in the file's place fails closed without hanging the connecting backend.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from fixtures.token_files import (
    PAGESERVER_AUTH_ERRORS,
    TABLE_ROWS,
    assert_no_token_in_logs,
    assert_one_warning_per_process,
    log_since,
    log_size,
    make_table,
    new_session_cannot_read,
    new_session_reads,
    reader_warnings,
    replace_file,
    start_with_storage_auth,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from fixtures.neon_fixtures import NeonEnvBuilder


def test_storage_token_file_edge_shapes(neon_env_builder: NeonEnvBuilder):
    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(PAGESERVER_AUTH_ERRORS)
    endpoint = start_with_storage_auth(env)
    admin = make_table(endpoint)

    path = endpoint.storage_auth_token_file
    good = path.read_bytes()
    token = good.decode()[:-1]

    # No trailing newline: the same token.
    endpoint.clear_buffers(cursor=admin)
    replace_file(path, token.encode())
    assert new_session_reads(endpoint) == TABLE_ROWS

    # The longest token the reader takes is passed on (no reader WARNING);
    # the pageserver refuses it, being no JWT.
    endpoint.clear_buffers(cursor=admin)
    offset = log_size(endpoint)
    replace_file(path, b"A" * 8191 + b"\n")
    new_session_cannot_read(endpoint, "an 8191-byte token")
    assert not reader_warnings(log_since(endpoint, offset), path)
    replace_file(path, good)
    assert new_session_reads(endpoint) == TABLE_ROWS

    # Not a regular file: refused, one WARNING, and the open doesn't block on
    # a FIFO with no writer.
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

    cases: list[tuple[str, Callable[[], None], Callable[[], None]]] = [
        ("a FIFO", fifo, remove_fifo),
        ("a directory", directory, remove_directory),
    ]
    for what, breaks, undo in cases:
        endpoint.clear_buffers(cursor=admin)
        offset = log_size(endpoint)
        breaks()
        new_session_cannot_read(endpoint, what)
        assert_one_warning_per_process(log_since(endpoint, offset), path, what)
        undo()
        replace_file(path, good)
        assert new_session_reads(endpoint) == TABLE_ROWS, f"after {what}"

    assert_no_token_in_logs(env, endpoint, [token])
