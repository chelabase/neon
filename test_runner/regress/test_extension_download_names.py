"""
F3 (K5 audit): the neon extension builds compute_ctl's `/extension_server/<name>` URL from a
name the session chooses (`CREATE EXTENSION`'s name, or a library name), so the name is
escaped (`curl_easy_escape`): reserved URL characters stay part of the name and never become
a query string or a fragment. Here `CREATE EXTENSION "f3evil?is_library=true"` must not turn
into a library download of what `library_index` maps `f3evil` to.
"""

from __future__ import annotations

import os
import platform
import tarfile
from contextlib import closing
from typing import TYPE_CHECKING

import psycopg2
import pytest
import zstandard
from fixtures.metrics import parse_metrics
from fixtures.paths import BASE_DIR

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any

    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import NeonEnvBuilder
    from fixtures.pg_version import PgVersion
    from pytest_httpserver import HTTPServer

SQL_ONLY = "test_extension_sql_only"
SQL_ONLY_DIR = BASE_DIR / "test_runner" / "regress" / "data" / "test_remote_extensions" / SQL_ONLY
# "?" would start a query string, "#" a fragment, "%" an escape; "=" and "&" are query syntax.
EVIL = ["f3evil?is_library=true", "f3evil#frag", "f3evil%3Fis_library=true", "f3evil&x=1"]


def test_extension_names_are_escaped_in_the_url(
    httpserver: HTTPServer,
    neon_env_builder_local: NeonEnvBuilder,
    httpserver_listen_address: ListenAddress,
    test_output_dir: Path,
    pg_version: PgVersion,
):
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

    control = (SQL_ONLY_DIR / f"{SQL_ONLY}.control").read_text()
    env = neon_env_builder_local.init_start()
    endpoint = env.endpoints.create("main")
    # SQL_ONLY is public, and the library `f3evil` maps to it. Each evil name only gets a
    # control file (create_control_files writes every extension_data entry when
    # custom_extensions is None), so CREATE EXTENSION reaches the download hook; none of
    # them is public, so compute_ctl must refuse each as itself.
    spec: dict[str, Any] = {
        "public_extensions": [SQL_ONLY],
        "custom_extensions": None,
        "library_index": {SQL_ONLY: SQL_ONLY, "f3evil": SQL_ONLY},
        "extension_data": {
            SQL_ONLY: {
                "archive_path": "",
                "control_data": {f"{SQL_ONLY}.control": control},
            },
            **{
                name: {"archive_path": "", "control_data": {f"{name}.control": control}}
                for name in EVIL
            },
        },
    }
    endpoint.create_remote_extension_spec(spec)
    endpoint.start(remote_ext_base_url=base_url)

    with closing(endpoint.connect()) as conn:
        conn.autocommit = True
        cur = conn.cursor()
        for name in EVIL:
            quoted = '"' + name.replace('"', '""') + '"'
            with pytest.raises(psycopg2.Error):
                cur.execute(f"CREATE EXTENSION {quoted} VERSION '1.0'")
                raise AssertionError(f"CREATE EXTENSION {quoted} succeeded")

        metrics = parse_metrics(endpoint.http_client().metrics())
        samples = metrics.query_all(
            "compute_ctl_remote_ext_requests_total", {"filename": f"{SQL_ONLY}.tar.zst"}
        )
        assert samples == [], (
            "a name with reserved URL characters reached compute_ctl as another request "
            f"(it downloaded {SQL_ONLY}): {samples}"
        )

        # A plain name still downloads.
        cur.execute(f"CREATE EXTENSION {SQL_ONLY} VERSION '1.0'")
        cur.execute(f"SELECT {SQL_ONLY}.motd()")
