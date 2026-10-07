"""
Model-based exhaustive check of DDL forwarding (patch 5).

Every role and database operation sequence up to a bounded length, over the role names a, b, c
(a and b exist before the transaction) and the database names d, e, f (d and e exist; d is
owned by role b), runs in one transaction on a real Postgres with the neon extension. The
forwarded payload is applied to a Python model of Chelabase's receiver
(services/orchestrator/src/internal/ddl.rs: steps(), decide(), apply(), finish_role_moves(),
finish_db_moves()), starting from the receiver's state before the transaction, and the result is
checked against the catalog after the commit.

The invariant. Before the transaction the receiver holds a copy (verifier, login) for every
role with a password, a row (name, owner name) for every database, and live data keys for the
keyed roles. After applying the payload:

1. Refusals: the receiver refuses (409) exactly when Postgres' commit broke one of its rules: a
   role that backs a live key is gone under every name (as DROP ROLE would be refused), the
   branch owner is gone, renamed or lost its password, a role has a reserved name, or more
   copies than the role cap exist. Otherwise:
2. Keys: every live key sits under the current name of the role it belongs to (identity by
   OID), never under a name that's gone or that now holds another role.
3. Copies: the names with a copy are exactly the roles that have a password, each with the
   role's current verifier and login flag (the owner's row keeps the owner's verifier).
4. Passwords: every forwarded plain password is the one the forwarded verifier was made from
   (the receiver's strength check is a function of that plain text).
5. Databases: the receiver's databases are exactly the catalog's, each with its owner's
   current name.
6. recreated: exactly the names that held a role before the transaction, whose role is gone
   (dropped under any name), and that now hold a role created in the transaction carry
   "recreated": true (a name freed only by a rename doesn't). "recreated" appears only on set
   entries, and always with "touched": true.
7. A transaction that dropped a role from before it asks for a resync (some entry touched, or
   a del): the role's members lost their membership.

1-5 are checked against two receiver models: the receiver as it is, and with the receiver
fixes the model found (RECEIVER_FIXES). The test fails on any violation with the fixed model
(those are the fork's); the extra violations of the current model are logged as receiver gaps.

Sequences Postgres rejects are skipped (run, then rolled back); the generator prunes the obvious
ones (an unknown object, a taken name).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

import psycopg2
import pytest
from fixtures.log_helper import log

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Any

    from fixtures.neon_fixtures import VanillaPostgres

NAMES = ["a", "b", "c"]
INITIAL = ("a", "b")
DBS = ["d", "e", "f"]
INITIAL_DBS = ("d", "e")
MAX_DEPTH = 3

# The receiver changes the model needs to see no violation (see the module docstring):
# - the branch owner dropped and created again in one transaction is refused, as its DROP is
#   (CheckRecreated on the owner's name);
# - the role cap counts the copies after the whole delta (dels apply after sets, so DROP a;
#   CREATE USER c at the cap was refused, and PASSWORD NULL beside a new copy depended on the
#   payload's order).
RECEIVER_FIXES = ("recreated owner", "cap after the delta")

Op = tuple[str, ...]


@dataclass(frozen=True)
class Config:
    length: int
    full: bool  # also CREATE ROLE (no password), PASSWORD NULL and NOLOGIN
    dbs: bool = False  # also ALTER DATABASE ... RENAME
    keyed: tuple[str, ...] = ("a",)
    # The receiver's rules, by logical name
    owner: str | None = None
    reserved: tuple[str, ...] = ()
    cap: int = 1_000_000
    shards: int = 4


CONFIGS = {
    # Roles: CREATE USER ... PASSWORD, DROP, RENAME, ALTER ... PASSWORD and savepoints
    "lean": Config(length=5, full=False, shards=4),
    # Roles, the whole alphabet
    "full": Config(length=5, full=True, shards=24),
    # Roles and database renames (chains and swaps), d owned by b
    "db": Config(length=5, full=False, dbs=True, shards=8),
    # The receiver's refusals: b is the branch owner and c a reserved name
    "owner": Config(length=4, full=True, keyed=(), owner="b", reserved=("c",), shards=2),
    # The role cap: two copies allowed (a and b have them)
    "cap": Config(length=4, full=True, keyed=(), cap=2, shards=2),
}


# ---- The generator ----


def ops_from(exists: frozenset[str], dbs: frozenset[str], depth: int, cfg: Config) -> Iterator[Op]:
    for n in NAMES:
        if n not in exists:
            yield ("create_user", n)
            if cfg.full:
                yield ("create_role", n)
        else:
            yield ("drop", n)
            yield ("password", n)
            if cfg.full:
                yield ("password_null", n)
                yield ("nologin", n)
            for m in NAMES:
                if m not in exists:
                    yield ("rename", n, m)
    if cfg.dbs:
        for x in DBS:
            if x in dbs:
                for y in DBS:
                    if y not in dbs:
                        yield ("db_rename", x, y)
    if depth < MAX_DEPTH:
        yield ("savepoint",)
    if depth > 0:
        yield ("release",)
        yield ("rollback_to",)


@dataclass(frozen=True)
class Sim:
    """What Postgres does, by identity: name -> token, and the (token, name) role drops."""

    names: dict[str, str]
    dbs: dict[str, str]
    dropped: frozenset[tuple[str, str]]
    stack: tuple[Any, ...] = ()

    def apply(self, op: Op, k: int) -> Sim:
        names = dict(self.names)
        dbs = dict(self.dbs)
        dropped = self.dropped
        stack = self.stack
        kind = op[0]
        if kind in ("create_user", "create_role"):
            names[op[1]] = f"new{k}"
        elif kind == "drop":
            dropped = dropped | {(names.pop(op[1]), op[1])}
        elif kind == "rename":
            names[op[2]] = names.pop(op[1])
        elif kind == "db_rename":
            dbs[op[2]] = dbs.pop(op[1])
        elif kind == "savepoint":
            stack = stack + ((self.names, self.dbs, self.dropped),)
        elif kind == "release":
            stack = stack[:-1]
        elif kind == "rollback_to":
            saved_names, saved_dbs, dropped = stack[-1]
            names, dbs = dict(saved_names), dict(saved_dbs)
        return Sim(names, dbs, dropped, stack)


def initial_sim() -> Sim:
    return Sim(
        {n: f"orig_{n}" for n in INITIAL}, {d: f"orig_{d}" for d in INITIAL_DBS}, frozenset()
    )


def sequences(cfg: Config) -> Iterator[list[Op]]:
    def rec(prefix: list[Op], sim: Sim) -> Iterator[list[Op]]:
        if prefix:
            yield prefix
        if len(prefix) == cfg.length:
            return
        for op in ops_from(frozenset(sim.names), frozenset(sim.dbs), len(sim.stack), cfg):
            yield from rec(prefix + [op], sim.apply(op, len(prefix)))

    yield from rec([], initial_sim())


def transaction(ops: list[Op], prefix: str, db_prefix: str) -> str:
    def q(n: str) -> str:
        return f"{prefix}{n}"

    stmts = ["BEGIN"]
    open_sps: list[str] = []
    for k, op in enumerate(ops):
        kind = op[0]
        if kind == "create_user":
            stmts.append(f"CREATE USER {q(op[1])} PASSWORD '{prefix}p{k}'")
        elif kind == "create_role":
            stmts.append(f"CREATE ROLE {q(op[1])}")
        elif kind == "drop":
            stmts.append(f"DROP ROLE {q(op[1])}")
        elif kind == "rename":
            stmts.append(f"ALTER ROLE {q(op[1])} RENAME TO {q(op[2])}")
        elif kind == "password":
            stmts.append(f"ALTER ROLE {q(op[1])} PASSWORD '{prefix}r{k}'")
        elif kind == "password_null":
            stmts.append(f"ALTER ROLE {q(op[1])} PASSWORD NULL")
        elif kind == "nologin":
            stmts.append(f"ALTER ROLE {q(op[1])} NOLOGIN")
        elif kind == "db_rename":
            stmts.append(f"ALTER DATABASE {db_prefix}{op[1]} RENAME TO {db_prefix}{op[2]}")
        elif kind == "savepoint":
            open_sps.append(f"s{k}")
            stmts.append(f"SAVEPOINT s{k}")
        elif kind == "release":
            stmts.append(f"RELEASE SAVEPOINT {open_sps.pop()}")
        elif kind == "rollback_to":
            stmts.append(f"ROLLBACK TO SAVEPOINT {open_sps[-1]}")
        else:
            raise AssertionError(op)
    stmts.append("COMMIT")
    return "; ".join(stmts)


# ---- The receiver's model (ddl.rs) ----


class Refused(Exception):
    pass


@dataclass
class Copy:
    verifier: str
    login: bool
    owner: bool = False  # the branch owner's row (origin owner)


def scram_matches(plain: str, verifier: str) -> bool:
    """Whether `verifier` (SCRAM-SHA-256$iter:salt$stored:server) was made from `plain`."""
    method, rest = verifier.split("$", 1)
    if method != "SCRAM-SHA-256":
        return False
    params, keys = rest.split("$")
    iterations, salt = params.split(":")
    stored = keys.split(":")[0]
    salted = hashlib.pbkdf2_hmac("sha256", plain.encode(), base64.b64decode(salt), int(iterations))
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    return hashlib.sha256(client_key).digest() == base64.b64decode(stored)


@dataclass
class Receiver:
    owner: str | None
    reserved: frozenset[str]
    cap: int
    fixed: bool  # with RECEIVER_FIXES
    rows: dict[str, Copy] = field(default_factory=dict)
    # Live data keys: role name -> the OIDs of the roles they were made for
    keys: dict[str, set[int]] = field(default_factory=dict)
    # Databases: name -> owner name
    dbs: dict[str, str] = field(default_factory=dict)
    bad_passwords: list[str] = field(default_factory=list)

    def is_reserved(self, name: str) -> bool:
        return name.lower().startswith("pg_") or (name in self.reserved and name != self.owner)

    def check_reserved(self, name: str):
        if self.is_reserved(name):
            raise Refused(f"reserved {name}")

    def rename_copy(self, old: str, new: str):
        # Moves the row, if any, and every key of the old name (ddl.rs rename_copy)
        if old in self.rows:
            self.rows[new] = self.rows.pop(old)
        if old in self.keys:
            self.keys.setdefault(new, set()).update(self.keys.pop(old))

    def remove_copy(self, name: str):
        if name in self.rows and not self.rows[name].owner:
            del self.rows[name]

    def live(self, name: str) -> bool:
        return bool(self.keys.get(name))

    def copy_count(self) -> int:
        return sum(1 for r in self.rows.values() if not r.owner)

    def apply(self, delta: dict[str, Any]):
        roles = delta.get("roles", [])
        dbs = delta.get("dbs", [])
        copies_before = self.copy_count()
        steps: list[tuple[Any, ...]] = []
        # steps(): role renames, role sets, role dels, then databases the same way
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
                password = (pw, r.get("encrypted_password", "")) if pw is not None else None
                steps.append(("set_role", r["name"], password))
            if "login" in r:
                steps.append(("set_login", r["name"], r["login"]))
        for r in roles:
            if r["op"] == "del":
                steps.append(("del_role", r["name"]))
        for d in dbs:
            if d.get("old_name") is not None:
                steps.append(("rename_db", d["old_name"], d["name"]))
        for d in dbs:
            if d["op"] == "set" and d.get("owner") is not None:
                steps.append(("set_db", d["name"], d["owner"]))
        for d in dbs:
            if d["op"] == "del":
                steps.append(("del_db", d["name"]))

        moves: list[tuple[str, str]] = []
        db_moves: list[tuple[str | None, str]] = []

        def finish_moves():
            for _, new in moves:
                if self.live(new):
                    raise Refused(f"rename onto {new} with live keys")
            for aside, new in moves:
                self.remove_copy(new)
                self.rename_copy(aside, new)
            moves.clear()

        def finish_db_moves():
            for aside, new in db_moves:
                self.dbs.pop(new, None)
                if aside is not None:
                    self.dbs[new] = self.dbs.pop(aside)
            db_moves.clear()

        for step in steps:
            kind = step[0]
            if kind != "rename":
                finish_moves()
            if kind != "rename_db":
                finish_db_moves()
            if kind == "rename":
                _, old, new = step
                if self.owner in (old, new):
                    raise Refused("owner renamed")
                self.check_reserved(old)
                self.check_reserved(new)
                aside = f"\x01aside {len(moves)}"
                self.rename_copy(old, aside)
                moves.append((aside, new))
            elif kind == "set_role":
                _, name, password = step
                if password is not None:
                    plain, encrypted = password
                    if self.fixed and not scram_matches(plain, encrypted):
                        self.bad_passwords.append(name)
                    if name == self.owner:
                        self.rows[name].verifier = encrypted
                        continue
                    self.check_reserved(name)
                    new_copy = name not in self.rows
                    if not self.fixed and new_copy and self.copy_count() >= self.cap:
                        raise Refused("role cap")
                    if name in self.rows:
                        self.rows[name].verifier = encrypted
                    else:
                        self.rows[name] = Copy(encrypted, True)
                else:
                    if name == self.owner:
                        raise Refused("owner password removed")
                    self.check_reserved(name)
                    self.remove_copy(name)
            elif kind == "set_login":
                _, name, login = step
                if name != self.owner and not self.is_reserved(name) and name in self.rows:
                    self.rows[name].login = login
            elif kind == "check_recreated":
                if self.fixed and step[1] == self.owner:
                    raise Refused("owner recreated")
                if self.live(step[1]):
                    raise Refused(f"recreated {step[1]} with live keys")
            elif kind == "del_role":
                name = step[1]
                if name == self.owner:
                    raise Refused("owner dropped")
                self.check_reserved(name)
                if self.live(name):
                    raise Refused(f"drop {name} with live keys")
                self.remove_copy(name)
            elif kind == "rename_db":
                _, old, new = step
                aside = f"\x01db aside {len(db_moves)}"
                moved = old in self.dbs
                if moved:
                    self.dbs[aside] = self.dbs.pop(old)
                db_moves.append((aside if moved else None, new))
            elif kind == "set_db":
                self.dbs[step[1]] = step[2]
            elif kind == "del_db":
                self.dbs.pop(step[1], None)
        finish_moves()
        finish_db_moves()
        if self.fixed and self.copy_count() > max(self.cap, copies_before):
            raise Refused("role cap")


# ---- The check ----


@dataclass
class Role:
    oid: int
    password: str | None
    login: bool


@dataclass
class State:
    roles: dict[str, Role]
    # Databases: name -> (oid, owner name)
    dbs: dict[str, tuple[int, str]]


def check(
    cfg: Config,
    ops: list[Op],
    prefix: str,
    db_prefix: str,
    before: State,
    after: State,
    payloads: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """The violations with the fixed receiver, and the receiver gaps (the current one's extra)."""

    def q(n: str) -> str:
        return f"{prefix}{n}"

    problems: list[str] = []
    sim = initial_sim()
    for k, op in enumerate(ops):
        sim = sim.apply(op, k)
    if set(after.roles) != {q(n) for n in sim.names}:
        return [f"simulator disagrees: roles {sorted(after.roles)} vs {sorted(sim.names)}"], []
    if cfg.dbs and set(after.dbs) != {f"{db_prefix}{d}" for d in sim.dbs}:
        return [f"simulator disagrees: databases {sorted(after.dbs)} vs {sorted(sim.dbs)}"], []

    roles = [r for p in payloads for r in p.get("roles", [])]
    for r in roles:
        if r.get("recreated", False) and (r["op"] != "set" or not r.get("touched", False)):
            problems.append(f"recreated without set/touched: {r}")
    # 6. recreated exactly where a new role holds the name of a role from before that is gone
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
    # 7. a dropped role from before the transaction asks for a resync
    dropped_orig = any(token.startswith("orig_") for token, _ in sim.dropped)
    if dropped_orig and not any(r.get("touched", False) or r["op"] == "del" for r in roles):
        problems.append("a role was dropped and no resync is asked for")

    # 1. the rules Postgres' commit broke
    owner = q(cfg.owner) if cfg.owner else None
    oids_after = {role.oid: name for name, role in after.roles.items()}
    broken = [f"keyed {n} gone" for n in cfg.keyed if before.roles[q(n)].oid not in oids_after]
    if owner is not None:
        if oids_after.get(before.roles[owner].oid) != owner:
            broken.append("owner gone or renamed")
        elif after.roles[owner].password is None:
            broken.append("owner password removed")
    broken += [f"reserved {n} taken" for n in cfg.reserved if q(n) in after.roles]
    copies = [n for n, r in after.roles.items() if r.password is not None and n != owner]
    if len(copies) > cfg.cap:
        broken.append("over the role cap")

    def receiver_problems(fixed: bool) -> list[str]:
        out: list[str] = []
        receiver = Receiver(
            owner=owner,
            reserved=frozenset(q(n) for n in cfg.reserved),
            cap=cfg.cap,
            fixed=fixed,
            rows={
                name: Copy(role.password, role.login, owner=name == owner)
                for name, role in before.roles.items()
                if role.password is not None
            },
            keys={q(n): {before.roles[q(n)].oid} for n in cfg.keyed},
            dbs={name: owner_name for name, (_, owner_name) in before.dbs.items()},
        )
        refused = None
        try:
            for p in payloads:
                receiver.apply(p)
        except Refused as e:
            refused = str(e)
        # 4. the plain passwords
        for name in receiver.bad_passwords:
            out.append(f"{name}: the forwarded password isn't the verifier's")
        if refused is not None:
            if not broken:
                out.append(f"refused though Postgres broke no rule: {refused}")
            return out
        if broken:
            out.append(f"accepted though {broken}")
        # 2. keys
        for name, oids in receiver.keys.items():
            if oids and (name not in after.roles or oids != {after.roles[name].oid}):
                out.append(f"keys under {name} belong to {oids}, not to the role there now")
        # 3. copies
        want = {name: role for name, role in after.roles.items() if role.password is not None}
        if set(receiver.rows) != set(want):
            out.append(f"copies {sorted(receiver.rows)} != roles with a password {sorted(want)}")
        for name, row in receiver.rows.items():
            if name in want:
                if row.verifier != want[name].password:
                    out.append(f"{name}: the copy's verifier is stale")
                if not row.owner and row.login != want[name].login:
                    out.append(f"{name}: the copy's login is {row.login}, not {want[name].login}")
        # 5. databases
        if cfg.dbs:
            catalog = {name: owner_name for name, (_, owner_name) in after.dbs.items()}
            if receiver.dbs != catalog:
                out.append(f"databases {receiver.dbs} != the catalog's {catalog}")
        return out

    fixed = receiver_problems(True)
    current = receiver_problems(False)
    return problems + fixed, [p for p in current if p not in fixed]


# ---- The run ----


class Capture:
    """A keep-alive HTTP/1.1 mock of the receiver's endpoint: records every PATCH body."""

    def __init__(self):
        self.received: list[Any] = []
        capture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_PATCH(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                capture.received.append(json.loads(body))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: Any):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def read_roles(cur: Any) -> dict[str, dict[str, Role]]:
    """The test's roles, by sequence prefix (`q<i>_`)."""
    cur.execute("SELECT oid, rolname, rolpassword, rolcanlogin FROM pg_authid WHERE rolname ~ '^q'")
    out: dict[str, dict[str, Role]] = {}
    for oid, name, pw, login in cur.fetchall():
        prefix = name[: name.index("_") + 1]
        out.setdefault(prefix, {})[name] = Role(oid, pw, login)
    return out


def read_dbs(cur: Any) -> dict[str, tuple[int, str]]:
    cur.execute(
        "SELECT d.oid, d.datname, r.rolname FROM pg_database d "
        "JOIN pg_roles r ON r.oid = d.datdba WHERE d.datname ~ '^m_'"
    )
    return {name: (oid, owner) for oid, name, owner in cur.fetchall()}


def summary(label: str, found: list[tuple[list[Op], list[str]]]):
    """The shortest sequence of each kind of problem (its text without names)."""
    found = sorted(found, key=lambda v: len(v[0]))
    kinds: dict[str, tuple[int, list[Op], list[str]]] = {}
    for ops, problems in found:
        for problem in problems:
            kind = " ".join(w for w in problem.split() if not w.startswith(("q", "{", "[", "'")))
            count, first_ops, first_problems = kinds.get(kind, (0, ops, problems))
            kinds[kind] = (count + 1, first_ops, first_problems)
    for kind, (count, ops, problems) in kinds.items():
        log.info(f"{label} ({count}x) {kind!r}: shortest {ops}: {problems}")


@pytest.mark.timeout(3600)
# Deterministic: a rerun would only repeat the same sequences
@pytest.mark.flaky(reruns=0)
@pytest.mark.parametrize(
    "config, shard",
    [
        pytest.param(name, shard, id=f"{name}-{shard}")
        for name, cfg in CONFIGS.items()
        for shard in range(cfg.shards)
    ],
)
def test_ddl_forwarding_model(vanilla_pg: VanillaPostgres, config: str, shard: int):
    """The sequences of CONFIGS[config] whose index is shard modulo its shard count."""
    cfg = CONFIGS[config]
    capture = Capture()
    vanilla_pg.configure(
        [
            f"neon.console_url=http://127.0.0.1:{capture.port}/roles_and_databases",
            "shared_preload_libraries = 'neon'",
            "fsync = off",
            "synchronous_commit = off",
        ]
    )
    vanilla_pg.start()
    conn = vanilla_pg.connect()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT current_user")
    row = cur.fetchone()
    assert row is not None
    superuser = row[0]
    db_prefix = "m_"
    if cfg.dbs:
        cur.execute(f"CREATE DATABASE {db_prefix}d")
        cur.execute(f"CREATE DATABASE {db_prefix}e")

    started = time.monotonic()
    checked = 0
    rejections: list[tuple[list[Op], str]] = []
    violations: list[tuple[list[Op], list[str]]] = []
    gaps: list[tuple[list[Op], list[str]]] = []
    batch_size = 2000
    all_sequences = [ops for i, ops in enumerate(sequences(cfg)) if i % cfg.shards == shard]
    for start in range(0, len(all_sequences), batch_size):
        batch = all_sequences[start : start + batch_size]
        prefixes = [f"q{start + i}_" for i in range(len(batch))]
        setup = ["SET neon.forward_ddl = false"]
        for p in prefixes:
            setup.append(f"CREATE ROLE {p}a LOGIN PASSWORD '{p}a'")
            setup.append(f"CREATE ROLE {p}b LOGIN PASSWORD '{p}b'")
        setup.append("RESET neon.forward_ddl")
        cur.execute("; ".join(setup))
        before_roles = read_roles(cur)

        results: list[tuple[list[Op], list[Any], State, State] | None] = []
        for ops, p in zip(batch, prefixes, strict=True):
            db_before: dict[str, tuple[int, str]] = {}
            if cfg.dbs:
                cur.execute(
                    f"SET neon.forward_ddl = false; ALTER DATABASE {db_prefix}d OWNER TO {p}b; "
                    "RESET neon.forward_ddl"
                )
                db_before = read_dbs(cur)
            capture.received.clear()
            try:
                cur.execute(transaction(ops, p, db_prefix))
            except psycopg2.Error as e:
                cur.execute("ROLLBACK")
                rejections.append((ops, str(e).strip()))
                results.append(None)
            else:
                db_after = read_dbs(cur) if cfg.dbs else {}
                results.append(
                    (ops, list(capture.received), State({}, db_before), State({}, db_after))
                )
            if cfg.dbs:
                # Back to m_d (owned by the superuser) and m_e, without forwarding
                names = {oid: name for name, (oid, _) in read_dbs(cur).items()}
                d_oid, e_oid = db_before[f"{db_prefix}d"][0], db_before[f"{db_prefix}e"][0]
                cur.execute(
                    "SET neon.forward_ddl = false; "
                    f"ALTER DATABASE {names[d_oid]} RENAME TO {db_prefix}tmp_d; "
                    f"ALTER DATABASE {names[e_oid]} RENAME TO {db_prefix}tmp_e; "
                    f"ALTER DATABASE {db_prefix}tmp_d RENAME TO {db_prefix}d; "
                    f"ALTER DATABASE {db_prefix}tmp_e RENAME TO {db_prefix}e; "
                    f"ALTER DATABASE {db_prefix}d OWNER TO {superuser}; "
                    "RESET neon.forward_ddl"
                )

        after_roles = read_roles(cur)
        for p, result in zip(prefixes, results, strict=True):
            if result is None:
                continue
            ops, sent, before, after = result
            before.roles = before_roles.get(p, {})
            after.roles = after_roles.get(p, {})
            checked += 1
            problems, receiver_gaps = check(cfg, ops, p, db_prefix, before, after, sent)
            if problems:
                violations.append((ops, problems))
            if receiver_gaps:
                gaps.append((ops, receiver_gaps))

        cur.execute(
            "SET neon.forward_ddl = false; DROP ROLE IF EXISTS "
            + ", ".join(f"{p}{n}" for p in prefixes for n in NAMES)
            + "; RESET neon.forward_ddl"
        )

    conn.close()
    vanilla_pg.stop()
    capture.close()
    elapsed = time.monotonic() - started
    log.info(
        f"{config} shard {shard}/{cfg.shards}: {checked} sequences checked, "
        f"{len(rejections)} rejected by Postgres, {len(violations)} violations, "
        f"{len(gaps)} receiver gaps, {elapsed:.0f} s"
    )
    for ops, error in rejections[:3]:
        log.info(f"rejected by Postgres: {ops}: {error}")
    summary("violation kind", violations)
    summary("receiver gap", gaps)
    assert violations == [], f"{len(violations)} violations; shortest: {violations[:5]}"
