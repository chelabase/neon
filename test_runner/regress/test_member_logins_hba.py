from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING, Any

import psycopg2
import pytest
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres
from psycopg2.extensions import make_dsn
from psycopg2.extras import LogicalReplicationConnection, PhysicalReplicationConnection

if TYPE_CHECKING:
    from pathlib import Path

    from fixtures.neon_fixtures import NeonEnv, PgProtocol, VanillaPostgres

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


def setup_hba(pg: VanillaPostgres, certs: Path, cidr: str):
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
    opts: dict[str, Any] = dict(
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
        row = cur.fetchone()
        assert row is not None
        return row[0]


@run_only_on_postgres([PgVersion.V17], "the hba map change is v17 only")
def test_member_logins_need_the_certificate_and_the_address(
    vanilla_pg: VanillaPostgres, certs: Path
):
    setup_hba(vanilla_pg, certs, "127.0.0.1/32")
    vanilla_pg.start()
    vanilla_pg.safe_psql(f"CREATE ROLE {MEMBER} LOGIN PASSWORD 'pw'")
    vanilla_pg.safe_psql("CREATE ROLE plain LOGIN PASSWORD 'pw'")
    assert member(vanilla_pg, certs, "orchestrator") == MEMBER
    cases: list[tuple[str | None, dict[str, Any], str]] = [
        (None, {}, "connection requires a valid client certificate"),
        # A CN the map doesn't name fails after the password check; the client sees only the
        # generic auth failure (auth.c:645-653, :2785-2805 logs the CN mismatch server-side).
        ("compute", {}, "password authentication failed"),
        # T4 m2: the orchestrator's certificate doesn't stand in for the password
        ("orchestrator", {"password": "wrong"}, "password authentication failed"),
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
    ]
    for cert, kw, needle in cases:
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
    setup_hba(vanilla_pg, certs, "all")
    vanilla_pg.start()
    vanilla_pg.safe_psql(f"CREATE ROLE {MEMBER} LOGIN PASSWORD 'pw'")
    assert member(vanilla_pg, certs, "orchestrator") == MEMBER


@run_only_on_postgres([PgVersion.V17], "the hba map change is v17 only")
def test_map_without_verify_full_stays_refused(vanilla_pg: VanillaPostgres, certs: Path):
    setup_hba(vanilla_pg, certs, "127.0.0.1/32")
    vanilla_pg.start()
    with open(vanilla_pg.pgdatadir / "pg_hba.conf", "a") as f:
        f.write("hostssl\tall\tbad_map\t127.0.0.1/32\tscram-sha-256\tmap=chelabase_member\n")
        # T4 m1: verify-ca checks the chain but not the name, so it doesn't make map valid
        f.write(
            "hostssl\tall\tca_map\t127.0.0.1/32\tscram-sha-256\tclientcert=verify-ca\tmap=chelabase_member\n"
        )
        f.write(
            "hostssl\tall\tgood_map\t127.0.0.1/32\tscram-sha-256\tmap=chelabase_member\tclientcert=verify-full\n"
        )
    rows = vanilla_pg.safe_psql(
        "SELECT coalesce(user_name[1], ''), coalesce(error, '') FROM pg_hba_file_rules ORDER BY line_number DESC LIMIT 3"
    )
    assert rows[0] == ("good_map", ""), rows
    for row in rows[1:]:
        assert row[0] == "" and 'authentication option "map" is only valid' in row[1], rows


# ---------------------------------------------------------------------------
# Fork round 4, K4 (W31, spec §10): chelabase_realtime logs in only over TLS, from
# `realtime_logins.allowed_cidrs`, with the realtime certificate. compute_ctl writes
# a second marked block right after the member block (before the basebackup's
# `trust` lines) and a marked pg_ident block; without `realtime_logins`, without TLS
# or below v17 the block holds only the reject lines.
# ---------------------------------------------------------------------------

RT = "chelabase_realtime"
RT_REJECT = [
    "host\tall\tchelabase_realtime\tall\treject",
    "host\treplication\tchelabase_realtime\tall\treject",
    "local\tall\tchelabase_realtime\treject",
    "local\treplication\tchelabase_realtime\treject",
]
RT_HEAD = "# chelabase: realtime logins"
RT_TAIL = "# chelabase: end of realtime logins"
RT_IDENT_HEAD = "# chelabase: realtime certificate map (chelabase_realtime)"
RT_IDENT_TAIL = "# chelabase: end of realtime certificate map"


def realtime_block(cidrs: list[str]) -> list[str]:
    allow = [
        f"hostssl\tall\tchelabase_realtime\t{cidr}\tscram-sha-256\tclientcert=verify-full\tmap=chelabase_realtime"
        for cidr in cidrs
    ]
    return [RT_HEAD, *allow, *RT_REJECT, RT_TAIL]


def rt_dsn(node: PgProtocol, **kw: Any) -> str:
    """chelabase_realtime's connection string, without the `options` PgProtocol adds to
    every connection (the role may not send any)."""
    opts = {**node.default_options, "user": RT}
    opts.pop("options", None)
    opts.update(kw)
    return str(make_dsn(**{k: v for k, v in opts.items() if v is not None}))


def realtime(pg: PgProtocol, certs: Path | None, cert: str | None, physical: bool = False, **kw):
    """Logs in as chelabase_realtime over a replication connection (logical, as realtime
    does, unless `physical`) and runs IDENTIFY_SYSTEM."""
    opts: dict[str, Any] = dict(host="127.0.0.1", password="pw")
    if certs is not None:
        opts.update(sslmode="require", sslrootcert=str(certs / "ca.crt"))
    if cert is not None and certs is not None:
        opts.update(sslcert=str(certs / f"{cert}.crt"), sslkey=str(certs / f"{cert}.key"))
    opts.update(kw)
    factory = PhysicalReplicationConnection if physical else LogicalReplicationConnection
    conn = psycopg2.connect(rt_dsn(pg, **opts), connection_factory=factory)
    try:
        cur = conn.cursor()
        cur.execute("IDENTIFY_SYSTEM")
        assert len(cur.fetchall()) == 1
    finally:
        conn.close()


@run_only_on_postgres([PgVersion.V17], "the hba map change is v17 only")
def test_realtime_logins(neon_simple_env: NeonEnv, vanilla_pg: VanillaPostgres, certs: Path):
    # A compute without realtime_logins (and without TLS, as neon_local's): compute_ctl's
    # block only rejects, so the role logs in from nowhere (today it logs in through the
    # basebackup's loopback `trust` lines, or the catch-all `md5` from anywhere else).
    endpoint = neon_simple_env.endpoints.create_start("main")
    endpoint.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION PASSWORD 'pw'")
    for host in ["127.0.0.1", "localhost"]:
        with pytest.raises(psycopg2.OperationalError) as e:
            realtime(endpoint, None, None, host=host)
        assert "pg_hba.conf rejects connection" in str(e.value), (host, str(e.value))
    with pytest.raises(psycopg2.OperationalError) as e:
        realtime(endpoint, None, None, physical=True)
    assert "pg_hba.conf rejects replication connection" in str(e.value), str(e.value)

    pgdata = endpoint.pg_data_dir_path()
    hba = (pgdata / "pg_hba.conf").read_text().splitlines()
    assert hba.count(RT_HEAD) == 1 and hba.count(RT_TAIL) == 1, hba
    head, tail = hba.index(RT_HEAD), hba.index(RT_TAIL)
    assert hba[head - 1] == "# chelabase: end of member logins", "right after the member block"
    assert hba[head + 1 : tail] == RT_REJECT, hba[head:tail]
    rules = [(i, line.split()) for i, line in enumerate(hba) if not line.startswith("#")]
    trust = [i for i, fields in rules if fields and fields[-1] == "trust"]
    assert trust and tail < min(trust), "before the basebackup's trust lines"
    ident = (pgdata / "pg_ident.conf").read_text().splitlines()
    assert ident.count(RT_IDENT_HEAD) == 1 and ident.count(RT_IDENT_TAIL) == 1, ident
    assert ident.index(RT_IDENT_TAIL) == ident.index(RT_IDENT_HEAD) + 1, "no CN is mapped"

    # The block itself, as compute_ctl writes it with realtime_logins and TLS on v17, on
    # a plain server: only the realtime certificate, over TLS, from a listed address.
    issue(certs, "realtime", "chelabase-realtime")
    pg = vanilla_pg
    setup_hba(pg, certs, "127.0.0.1/32")
    path = pg.pgdatadir / "pg_hba.conf"
    member_tail = "# chelabase: end of member logins\n"
    path.write_text(
        path.read_text().replace(
            member_tail, member_tail + "\n".join(realtime_block(["127.0.0.1/32"])) + "\n", 1
        )
    )
    with open(pg.pgdatadir / "pg_ident.conf", "a") as f:
        f.write(f"{RT_IDENT_HEAD}\n{RT}\tchelabase-realtime\t{RT}\n{RT_IDENT_TAIL}\n")
    pg.start()
    pg.safe_psql(f"CREATE ROLE {RT} LOGIN REPLICATION PASSWORD 'pw'")
    pg.safe_psql(f"CREATE ROLE {MEMBER} LOGIN PASSWORD 'pw'")

    realtime(pg, certs, "realtime")
    cases: list[tuple[str, str | None, dict[str, Any], str]] = [
        ("no certificate", None, {}, "connection requires a valid client certificate"),
        # A CN the map doesn't name fails after the password check (auth.c logs the CN).
        ("the orchestrator's certificate", "orchestrator", {}, "password authentication failed"),
        ("a compute's certificate", "compute", {}, "password authentication failed"),
        ("a wrong password", "realtime", {"password": "wrong"}, "password authentication failed"),
        (
            "plain TCP",
            "realtime",
            {"sslmode": "disable", "sslrootcert": None, "sslcert": None, "sslkey": None},
            "pg_hba.conf rejects connection",
        ),
        (
            "the Unix socket",
            None,
            {"host": "/tmp", "sslmode": "disable", "sslrootcert": None},
            "pg_hba.conf rejects connection",
        ),
    ]
    for what, cert, kw, needle in cases:
        with pytest.raises(psycopg2.OperationalError) as e:
            realtime(pg, certs, cert, **kw)
        assert needle in str(e.value), (what, str(e.value))
    with pytest.raises(psycopg2.OperationalError) as e:
        realtime(pg, certs, "realtime", physical=True)
    assert "pg_hba.conf rejects replication connection" in str(e.value), str(e.value)
    # The member block is untouched by the realtime one, and the other way round.
    assert member(pg, certs, "orchestrator") == MEMBER
    with pytest.raises(psycopg2.OperationalError) as e:
        member(pg, certs, "realtime")
    assert "password authentication failed" in str(e.value), str(e.value)

    # An address outside the list.
    pg.stop()
    path.write_text(path.read_text().replace(f"{RT}\t127.0.0.1/32", f"{RT}\t10.255.255.254/32"))
    pg.start()
    with pytest.raises(psycopg2.OperationalError) as e:
        realtime(pg, certs, "realtime")
    assert "pg_hba.conf rejects connection" in str(e.value), str(e.value)
    assert member(pg, certs, "orchestrator") == MEMBER
