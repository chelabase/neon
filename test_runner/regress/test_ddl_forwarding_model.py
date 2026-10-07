"""
Model-based exhaustive check of DDL forwarding (patch 5).

Every role-operation sequence up to a bounded length, over the names a, b, c (a and b exist
before the transaction), runs in one transaction on a real Postgres with the neon extension.
The forwarded payload is applied to a Python model of Chelabase's receiver
(services/orchestrator/src/internal/ddl.rs: steps(), decide(), apply(), finish_role_moves()),
starting from the receiver's state before the transaction, and the result is checked against
pg_authid after the commit.

The invariant. Before the transaction the receiver holds a copy (verifier, login) for every
role with a password, and role a backs a live data key (b backs none). After applying the
payload:

1. Keys: the receiver refuses (409, as DROP ROLE would) exactly when a role that backs a live
   key no longer exists under any name. Otherwise every live key sits under the current name of
   the role it belongs to (identity by OID), never under a name that's gone or that now holds
   another role.
2. Copies: the names with a copy are exactly the roles that have a password, each with the
   role's current verifier and login flag (a renamed role is reached through its old_name
   chain; a dropped role leaves no copy).
3. recreated: exactly the names that held a role before the transaction, whose role is gone
   (dropped, under any name), and that now hold a role created in the transaction carry
   "recreated": true (a name freed only by a rename doesn't). "recreated" appears only on set
   entries, and always with "touched": true.
4. A transaction that dropped a role from before it asks for a resync (some entry touched, or
   a del): the role's members lost their membership.

Sequences Postgres rejects are skipped (run, then rolled back); the generator already prunes
the obvious ones (an unknown role, a taken name).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import psycopg2
import pytest
from fixtures.log_helper import log
from werkzeug.wrappers.response import Response

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Any

    from fixtures.httpserver import ListenAddress
    from fixtures.neon_fixtures import VanillaPostgres
    from pytest_httpserver import HTTPServer
    from werkzeug.wrappers.request import Request

NAMES = ["a", "b", "c"]
INITIAL = ("a", "b")
KEYED = ("a",)
OWNER = "cloud_admin"

Op = tuple[str, ...]


# ---- The generator ----


def ops_from(exists: frozenset[str], depth: int, full: bool) -> Iterator[Op]:
    for n in NAMES:
        if n not in exists:
            yield ("create_user", n)
            if full:
                yield ("create_role", n)
        else:
            yield ("drop", n)
            yield ("password", n)
            if full:
                yield ("password_null", n)
                yield ("nologin", n)
            for m in NAMES:
                if m not in exists:
                    yield ("rename", n, m)
    if depth < 2:
        yield ("savepoint",)
    if depth > 0:
        yield ("release",)
        yield ("rollback_to",)


@dataclass(frozen=True)
class Sim:
    """What Postgres does, by identity: name -> role token, and the (token, name) drops."""

    names: dict[str, str]
    dropped: frozenset[tuple[str, str]]
    stack: tuple[Any, ...] = ()

    def apply(self, op: Op, k: int) -> Sim:
        names = dict(self.names)
        kind = op[0]
        if kind in ("create_user", "create_role"):
            names[op[1]] = f"new{k}"
            return Sim(names, self.dropped, self.stack)
        if kind == "drop":
            token = names.pop(op[1])
            return Sim(names, self.dropped | {(token, op[1])}, self.stack)
        if kind == "rename":
            names[op[2]] = names.pop(op[1])
            return Sim(names, self.dropped, self.stack)
        if kind == "savepoint":
            return Sim(names, self.dropped, self.stack + ((self.names, self.dropped),))
        if kind == "release":
            return Sim(names, self.dropped, self.stack[:-1])
        if kind == "rollback_to":
            saved_names, saved_dropped = self.stack[-1]
            return Sim(dict(saved_names), saved_dropped, self.stack)
        return self


def initial_sim() -> Sim:
    return Sim({n: f"orig_{n}" for n in INITIAL}, frozenset())


def sequences(length: int, full: bool) -> Iterator[list[Op]]:
    def rec(prefix: list[Op], sim: Sim) -> Iterator[list[Op]]:
        if prefix:
            yield prefix
        if len(prefix) == length:
            return
        for op in ops_from(frozenset(sim.names), len(sim.stack), full):
            yield from rec(prefix + [op], sim.apply(op, len(prefix)))

    yield from rec([], initial_sim())


def sql(op: Op, prefix: str, k: int) -> str:
    def q(n: str) -> str:
        return f"{prefix}{n}"

    kind = op[0]
    if kind == "create_user":
        return f"CREATE USER {q(op[1])} PASSWORD '{prefix}p{k}'"
    if kind == "create_role":
        return f"CREATE ROLE {q(op[1])}"
    if kind == "drop":
        return f"DROP ROLE {q(op[1])}"
    if kind == "rename":
        return f"ALTER ROLE {q(op[1])} RENAME TO {q(op[2])}"
    if kind == "password":
        return f"ALTER ROLE {q(op[1])} PASSWORD '{prefix}r{k}'"
    if kind == "password_null":
        return f"ALTER ROLE {q(op[1])} PASSWORD NULL"
    if kind == "nologin":
        return f"ALTER ROLE {q(op[1])} NOLOGIN"
    if kind == "savepoint":
        return f"SAVEPOINT s{k}"
    if kind == "release":
        return "RELEASE SAVEPOINT {sp}"
    if kind == "rollback_to":
        return "ROLLBACK TO SAVEPOINT {sp}"
    raise AssertionError(op)


def transaction(ops: list[Op], prefix: str) -> str:
    stmts = ["BEGIN"]
    open_sps: list[str] = []
    for k, op in enumerate(ops):
        text = sql(op, prefix, k)
        if op[0] == "savepoint":
            open_sps.append(f"s{k}")
        elif op[0] == "release":
            text = text.format(sp=open_sps.pop())
        elif op[0] == "rollback_to":
            text = text.format(sp=open_sps[-1])
        stmts.append(text)
    stmts.append("COMMIT")
    return "; ".join(stmts)


# ---- The receiver's model (ddl.rs) ----


class Refused(Exception):
    pass


@dataclass
class Copy:
    verifier: str
    login: bool


@dataclass
class Receiver:
    rows: dict[str, Copy] = field(default_factory=dict)
    # Live data keys: role name -> the OIDs of the roles they were made for
    keys: dict[str, set[int]] = field(default_factory=dict)

    def rename_copy(self, old: str, new: str):
        # Moves the row, if any, and every key of the old name (ddl.rs rename_copy)
        if old in self.rows:
            self.rows[new] = self.rows.pop(old)
        if old in self.keys:
            self.keys.setdefault(new, set()).update(self.keys.pop(old))

    def live(self, name: str) -> bool:
        return bool(self.keys.get(name))

    def apply(self, delta: dict[str, Any]):
        roles = delta.get("roles", [])
        steps: list[tuple[Any, ...]] = []
        for r in roles:
            if r.get("old_name") is not None:
                steps.append(("rename", r["old_name"], r["name"]))
        for r in roles:
            if r["op"] != "set":
                continue
            has_pw = "password" in r
            pw = r.get("password")
            explicit_null = has_pw and pw is None
            attribute_only = (
                not has_pw
                and "encrypted_password" not in r
                and ("login" in r or "valid_until" in r or r.get("touched", False))
            )
            if r.get("recreated", False):
                steps.append(("check_recreated", r["name"]))
            if not attribute_only and (
                r.get("old_name") is None or pw is not None or explicit_null
            ):
                steps.append(
                    ("set_role", r["name"], r.get("encrypted_password") if pw is not None else None)
                )
            if "login" in r:
                steps.append(("set_login", r["name"], r["login"]))
        for r in roles:
            if r["op"] == "del":
                steps.append(("del_role", r["name"]))

        moves: list[tuple[str, str]] = []

        def finish_moves():
            for _, new in moves:
                if self.live(new):
                    raise Refused(f"rename onto {new} with live keys")
            for aside, new in moves:
                self.rows.pop(new, None)
                self.rename_copy(aside, new)
            moves.clear()

        for step in steps:
            kind = step[0]
            if kind != "rename":
                finish_moves()
            if kind == "rename":
                _, old, new = step
                if OWNER in (old, new):
                    raise Refused("owner")
                aside = f"\x01aside {len(moves)}"
                self.rename_copy(old, aside)
                moves.append((aside, new))
            elif kind == "set_role":
                _, name, verifier = step
                if name == OWNER:
                    raise Refused("owner")
                if verifier is not None:
                    if name in self.rows:
                        self.rows[name].verifier = verifier
                    else:
                        self.rows[name] = Copy(verifier, True)
                else:
                    self.rows.pop(name, None)
            elif kind == "set_login":
                _, name, login = step
                if name in self.rows and name != OWNER:
                    self.rows[name].login = login
            elif kind == "check_recreated":
                if self.live(step[1]):
                    raise Refused(f"recreated {step[1]} with live keys")
            elif kind == "del_role":
                if self.live(step[1]):
                    raise Refused(f"drop {step[1]} with live keys")
                self.rows.pop(step[1], None)
        finish_moves()


# ---- The check ----


@dataclass
class Role:
    oid: int
    password: str | None
    login: bool


def check(
    ops: list[Op],
    prefix: str,
    before: dict[str, Role],
    after: dict[str, Role],
    payloads: list[dict[str, Any]],
) -> list[str]:
    def q(n: str) -> str:
        return f"{prefix}{n}"

    problems: list[str] = []
    sim = initial_sim()
    for k, op in enumerate(ops):
        sim = sim.apply(op, k)
    if set(after) != {q(n) for n in sim.names}:
        return [f"simulator disagrees with Postgres: {sorted(after)} vs {sorted(sim.names)}"]

    roles = [r for p in payloads for r in p.get("roles", [])]
    for r in roles:
        if r.get("recreated", False) and (r["op"] != "set" or not r.get("touched", False)):
            problems.append(f"recreated without set/touched: {r}")
    # 3. recreated exactly where a new role holds the name of a role from before that is gone
    for n in NAMES:
        required = (
            n in INITIAL
            and sim.names.get(n, "").startswith("new")
            and f"orig_{n}" not in sim.names.values()
        )
        sent = any(r["name"] == q(n) and r.get("recreated", False) for r in roles)
        if required and not sent:
            problems.append(f"{n}: a new role on a dropped role's name, not marked recreated")
        if sent and not required:
            problems.append(f"{n}: marked recreated, but no new role took a dropped role's name")
    # 4. a dropped role from before the transaction asks for a resync (one created and
    # dropped in the transaction had no members outside it)
    dropped_orig = any(token.startswith("orig_") for token, _ in sim.dropped)
    if dropped_orig and not any(r.get("touched", False) or r["op"] == "del" for r in roles):
        problems.append("a role was dropped and no resync is asked for")

    receiver = Receiver(
        rows={
            name: Copy(role.password, role.login)
            for name, role in before.items()
            if role.password is not None
        },
        keys={q(n): {before[q(n)].oid} for n in KEYED},
    )
    refused = None
    try:
        for p in payloads:
            receiver.apply(p)
    except Refused as e:
        refused = str(e)
    oids_after = {role.oid: name for name, role in after.items()}
    keyed_gone = [n for n in KEYED if before[q(n)].oid not in oids_after]
    # 1. keys
    if refused is not None:
        if not keyed_gone:
            problems.append(f"refused though no keyed role was dropped: {refused}")
        return problems
    if keyed_gone:
        problems.append(f"accepted though keyed role(s) {keyed_gone} were dropped")
    for name, oids in receiver.keys.items():
        if not oids:
            continue
        if name not in after or oids != {after[name].oid}:
            problems.append(f"keys under {name} belong to {oids}, not to the role there now")
    # 2. copies
    want = {name: role for name, role in after.items() if role.password is not None}
    if set(receiver.rows) != set(want):
        problems.append(f"copies {sorted(receiver.rows)} != roles with a password {sorted(want)}")
    for name, row in receiver.rows.items():
        if name in want:
            if row.verifier != want[name].password:
                problems.append(f"{name}: the copy's verifier is stale")
            if row.login != want[name].login:
                problems.append(f"{name}: the copy's login is {row.login}, not {want[name].login}")
    return problems


# ---- The run ----


class Capture:
    def __init__(self, httpserver: HTTPServer, vanilla_pg: VanillaPostgres, host: str, port: int):
        endpoint = "/test/roles_and_databases"
        self.received: list[Any] = []
        httpserver.expect_request(endpoint, method="PATCH").respond_with_handler(self.handler)
        vanilla_pg.configure(
            [
                f"neon.console_url=http://{host}:{port}{endpoint}",
                "shared_preload_libraries = 'neon'",
            ]
        )

    def handler(self, request: Request) -> Response:
        self.received.append(request.json)
        return Response(status=200)


def read_roles(cur: Any) -> dict[str, dict[str, Role]]:
    """The test's roles, by sequence prefix (`q<i>_`)."""
    cur.execute("SELECT oid, rolname, rolpassword, rolcanlogin FROM pg_authid WHERE rolname ~ '^q'")
    out: dict[str, dict[str, Role]] = {}
    for oid, name, pw, login in cur.fetchall():
        prefix = name[: name.index("_") + 1]
        out.setdefault(prefix, {})[name] = Role(oid, pw, login)
    return out


SHARDS = 4


@pytest.mark.timeout(1800)
# Deterministic: a rerun would only repeat the same sequences
@pytest.mark.flaky(reruns=0)
@pytest.mark.parametrize("shard", range(SHARDS))
@pytest.mark.parametrize(
    "alphabet, length",
    [
        # CREATE USER ... PASSWORD, DROP, RENAME, ALTER ... PASSWORD and savepoints
        pytest.param("lean", 5, id="lean-5"),
        # also CREATE ROLE (no password), PASSWORD NULL and NOLOGIN
        pytest.param("full", 4, id="full-4"),
    ],
)
def test_ddl_forwarding_model(
    httpserver: HTTPServer,
    vanilla_pg: VanillaPostgres,
    httpserver_listen_address: ListenAddress,
    alphabet: str,
    length: int,
    shard: int,
):
    """Shard `shard` of SHARDS: the sequences whose index is shard modulo SHARDS."""
    (host, port) = httpserver_listen_address
    capture = Capture(httpserver, vanilla_pg, host, port)
    vanilla_pg.start()
    conn = vanilla_pg.connect()
    conn.autocommit = True
    cur = conn.cursor()

    started = time.monotonic()
    checked = 0
    rejected = 0
    violations: list[tuple[list[Op], list[str]]] = []
    batch_size = 2000
    all_sequences = [
        ops for i, ops in enumerate(sequences(length, alphabet == "full")) if i % SHARDS == shard
    ]
    rejections: list[tuple[list[Op], str]] = []
    for start in range(0, len(all_sequences), batch_size):
        batch = all_sequences[start : start + batch_size]
        prefixes = [f"q{start + i}_" for i in range(len(batch))]
        setup = ["SET neon.forward_ddl = false"]
        for p in prefixes:
            setup.append(f"CREATE ROLE {p}a LOGIN PASSWORD '{p}a'")
            setup.append(f"CREATE ROLE {p}b LOGIN PASSWORD '{p}b'")
        setup.append("RESET neon.forward_ddl")
        cur.execute("; ".join(setup))
        before = read_roles(cur)

        payloads: list[list[dict[str, Any]]] = []
        ok: list[bool] = []
        for ops, p in zip(batch, prefixes, strict=True):
            capture.received.clear()
            try:
                cur.execute(transaction(ops, p))
                ok.append(True)
            except psycopg2.Error as e:
                cur.execute("ROLLBACK")
                ok.append(False)
                rejections.append((ops, str(e).strip()))
            payloads.append(list(capture.received))

        after = read_roles(cur)
        for ops, p, sent, accepted in zip(batch, prefixes, payloads, ok, strict=True):
            if not accepted:
                rejected += 1
                continue
            checked += 1
            problems = check(ops, p, before.get(p, {}), after.get(p, {}), sent)
            if problems:
                violations.append((ops, problems))

        cur.execute(
            "SET neon.forward_ddl = false; DROP ROLE IF EXISTS "
            + ", ".join(f"{p}{n}" for p in prefixes for n in NAMES)
            + "; RESET neon.forward_ddl"
        )

    elapsed = time.monotonic() - started
    log.info(
        f"{alphabet}-{length} shard {shard}/{SHARDS}: {checked} sequences checked, "
        f"{rejected} rejected by Postgres, {len(violations)} violations, {elapsed:.0f} s"
    )
    for ops, error in rejections[:5]:
        log.info(f"rejected by Postgres: {ops}: {error}")
    violations.sort(key=lambda v: len(v[0]))
    # The shortest sequence of each kind of violation (its text without role names)
    kinds: dict[str, tuple[int, list[Op], list[str]]] = {}
    for ops, problems in violations:
        for problem in problems:
            kind = " ".join(w for w in problem.split() if not w.startswith(("q", "{", "[")))
            count, first_ops, first_problems = kinds.get(kind, (0, ops, problems))
            kinds[kind] = (count + 1, first_ops, first_problems)
    for kind, (count, ops, problems) in kinds.items():
        log.info(f"violation kind ({count}x) {kind!r}: shortest {ops}: {problems}")
    assert violations == [], f"{len(violations)} violations; shortest: {violations[:5]}"
