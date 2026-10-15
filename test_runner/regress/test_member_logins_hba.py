from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING

import psycopg2
import pytest
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres

if TYPE_CHECKING:
    from pathlib import Path

    from fixtures.neon_fixtures import VanillaPostgres

MEMBER = "cb_m_0123456789abcdef0123456789abcdef"
REJECT = [
    "host\tall\t/^[Cc][Bb]_[Mm]_\tall\treject",
    "host\treplication\t/^[Cc][Bb]_[Mm]_\tall\treject",
    "local\tall\t/^[Cc][Bb]_[Mm]_\treject",
    "local\treplication\t/^[Cc][Bb]_[Mm]_\treject",
]


def block(cidr: str) -> list[str]:
    return [
        "# chelabase: member logins (cb_m_*) only from the orchestrator",
        f"hostssl\tall\t/^cb_m_[0-9a-f]{{32}}$\t{cidr}\tscram-sha-256\tclientcert=verify-full\tmap=chelabase_member",
        *REJECT,
        "# chelabase: end of member logins",
    ]


def openssl(*args: str | Path):
    subprocess.run(["openssl", *[str(a) for a in args]], check=True, capture_output=True)


def issue(d: Path, name: str, cn: str):
    key, csr, crt = d / f"{name}.key", d / f"{name}.csr", d / f"{name}.crt"
    openssl(
        "req",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        key,
        "-out",
        csr,
        "-subj",
        f"/CN={cn}",
    )
    openssl(
        "x509",
        "-req",
        "-in",
        csr,
        "-CA",
        d / "ca.crt",
        "-CAkey",
        d / "ca.key",
        "-CAcreateserial",
        "-days",
        "2",
        "-out",
        crt,
    )
    os.chmod(key, 0o600)


@pytest.fixture
def certs(tmp_path: Path) -> Path:
    openssl(
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        tmp_path / "ca.key",
        "-out",
        tmp_path / "ca.crt",
        "-days",
        "2",
        "-subj",
        "/CN=test compute CA",
    )
    issue(tmp_path, "server", "localhost")
    issue(tmp_path, "orchestrator", "chelabase-orchestrator")
    issue(tmp_path, "compute", "ep-x.compute.chelabase.internal")
    return tmp_path


def setup(pg: VanillaPostgres, certs: Path, cidr: str):
    pg.configure(
        [
            "ssl = on",
            f"ssl_cert_file = '{certs / 'server.crt'}'",
            f"ssl_key_file = '{certs / 'server.key'}'",
            f"ssl_ca_file = '{certs / 'ca.crt'}'",
            "password_encryption = 'scram-sha-256'",
        ]
    )
    hba = pg.pgdatadir / "pg_hba.conf"
    original = hba.read_text()
    hba.write_text("\n".join(block(cidr)) + "\n" + original)
    with open(pg.pgdatadir / "pg_ident.conf", "a") as f:
        f.write("chelabase_member\tchelabase-orchestrator\t/^cb_m_[0-9a-f]{32}$\n")


def member(pg: VanillaPostgres, certs: Path, cert: str | None, **kw):
    opts = dict(
        user=MEMBER,
        password="pw",
        host="127.0.0.1",
        sslmode="require",
        sslrootcert=str(certs / "ca.crt"),
    )
    if cert:
        opts.update(sslcert=str(certs / f"{cert}.crt"), sslkey=str(certs / f"{cert}.key"))
    opts.update(kw)
    with pg.cursor(**opts) as cur:
        cur.execute("SELECT current_user")
        return cur.fetchone()[0]


@run_only_on_postgres([PgVersion.V17], "the hba map change is v17 only")
def test_member_logins_need_the_certificate_and_the_address(
    vanilla_pg: VanillaPostgres, certs: Path
):
    setup(vanilla_pg, certs, "127.0.0.1/32")
    vanilla_pg.start()
    vanilla_pg.safe_psql(f"CREATE ROLE {MEMBER} LOGIN PASSWORD 'pw'")
    vanilla_pg.safe_psql("CREATE ROLE plain LOGIN PASSWORD 'pw'")
    assert member(vanilla_pg, certs, "orchestrator") == MEMBER
    for cert, kw, needle in [
        (None, {}, "connection requires a valid client certificate"),
        # A CN the map doesn't name fails after the password check; the client sees only the
        # generic auth failure (auth.c:645-653, :2785-2805 logs the CN mismatch server-side).
        ("compute", {}, "password authentication failed"),
        (
            "orchestrator",
            {"sslmode": "disable", "sslrootcert": None},
            "pg_hba.conf rejects connection",
        ),
        (
            None,
            {"host": "/tmp", "sslmode": "disable", "sslrootcert": None},
            "pg_hba.conf rejects connection",
        ),
    ]:
        with pytest.raises(psycopg2.OperationalError) as e:
            member(vanilla_pg, certs, cert, **kw)
        assert needle in str(e.value), (cert, kw, str(e.value))
    with vanilla_pg.cursor(user="plain", password="pw", host="127.0.0.1", sslmode="disable") as cur:
        cur.execute("SELECT 1")
    vanilla_pg.stop()
    hba = vanilla_pg.pgdatadir / "pg_hba.conf"
    hba.write_text(hba.read_text().replace("127.0.0.1/32\tscram", "10.255.255.254/32\tscram"))
    vanilla_pg.start()
    with pytest.raises(psycopg2.OperationalError) as e:
        member(vanilla_pg, certs, "orchestrator")
    assert "pg_hba.conf rejects connection" in str(e.value)


@run_only_on_postgres([PgVersion.V17], "the hba map change is v17 only")
def test_an_empty_list_is_no_address_rule(vanilla_pg: VanillaPostgres, certs: Path):
    setup(vanilla_pg, certs, "all")
    vanilla_pg.start()
    vanilla_pg.safe_psql(f"CREATE ROLE {MEMBER} LOGIN PASSWORD 'pw'")
    assert member(vanilla_pg, certs, "orchestrator") == MEMBER


@run_only_on_postgres([PgVersion.V17], "the hba map change is v17 only")
def test_map_without_verify_full_stays_refused(vanilla_pg: VanillaPostgres, certs: Path):
    setup(vanilla_pg, certs, "127.0.0.1/32")
    vanilla_pg.start()
    with open(vanilla_pg.pgdatadir / "pg_hba.conf", "a") as f:
        f.write("hostssl\tall\tbad_map\t127.0.0.1/32\tscram-sha-256\tmap=chelabase_member\n")
        f.write(
            "hostssl\tall\tgood_map\t127.0.0.1/32\tscram-sha-256\tmap=chelabase_member\tclientcert=verify-full\n"
        )
    rows = dict(
        vanilla_pg.safe_psql(
            "SELECT user_name[1], coalesce(error, '') FROM pg_hba_file_rules WHERE user_name[1] IN ('bad_map', 'good_map')"
        )
    )
    assert 'authentication option "map" is only valid' in rows["bad_map"]
    assert rows["good_map"] == ""
