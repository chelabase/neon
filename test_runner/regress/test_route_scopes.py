"""
The route-scope invariant of the storage servers' HTTP APIs (K7 fix round).

With auth on, every registered route of the pageserver, the safekeeper and the storage
controller refuses, with 403, both a `metrics` token and a tenant token for another
tenant than the one the route names. The exceptions are `/metrics` (a `metrics` token
reads it) and the public routes (`PUBLIC_ROUTES`), which take no token.

The route list is read from the router itself, and proven complete:

- each server builds its whole HTTP router in one function, `make_router`; the parser
  reads every routerify registration in its body (`.get/.put/.post/.delete/.patch(...)`
  and the rest of `RouterBuilder`'s route methods), and refuses any form it can't read
  exactly (a path that isn't a string literal, `.add`, `.scope`, `.any_method`, a
  catch-all other than `.any(handler_404)`), so a registration can't slip past it;
- the base it starts from adds no route (`http_utils::endpoint::make_router`), and the
  OpenAPI pages (`attach_openapi_ui`) are read from its call;
- across the whole crate, `make_router`'s signature is the only `RouterBuilder` in sight,
  nothing calls `Router::builder`, and every caller builds the result straight away
  (`make_router(...)?.build()`), so no route is added anywhere else;
- every parsed route is then requested on the running server: a path the parser got
  wrong answers 404, not 403, and fails the test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
import requests
from fixtures.auth_tokens import TokenScope
from fixtures.common_types import Lsn, TenantId, TimelineId
from fixtures.paths import BASE_DIR
from fixtures.safekeeper.http import MembershipConfiguration, TimelineCreateRequest

if TYPE_CHECKING:
    from pathlib import Path

    from fixtures.neon_fixtures import NeonEnv, NeonEnvBuilder

# routerify's `RouterBuilder` methods that register routes, and the HTTP method each
# registers (`None`: a form the parser refuses, so a new route can't hide behind it).
ROUTE_METHODS: dict[str, str | None] = {
    "get": "GET",
    "get_or_head": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "head": "HEAD",
    "trace": "TRACE",
    "connect": "CONNECT",
    "patch": "PATCH",
    "options": "OPTIONS",
    "any_method": None,
    "add": None,
    "scope": None,
    "any": None,
}

# The one catch-all a router may end with: it answers 404 to every unknown path.
ALLOWED_CATCH_ALLS = {"handler_404"}


class RouteParseError(AssertionError):
    pass


@dataclass(frozen=True)
class Route:
    method: str
    path: str


@dataclass(frozen=True)
class RouterSource:
    crate_src: str
    router_file: str
    # The public routes the plan pins ("Shared interfaces → Storage auth").
    public_routes: frozenset[str]


ROUTERS: dict[str, RouterSource] = {
    "pageserver": RouterSource(
        crate_src="pageserver/src",
        router_file="pageserver/src/http/routes.rs",
        public_routes=frozenset({"/v1/status", "/v1/doc", "/swagger.yml"}),
    ),
    "safekeeper": RouterSource(
        crate_src="safekeeper/src",
        router_file="safekeeper/src/http/routes.rs",
        public_routes=frozenset({"/v1/status"}),
    ),
    "storage_controller": RouterSource(
        crate_src="storage_controller/src",
        router_file="storage_controller/src/http.rs",
        public_routes=frozenset({"/status", "/live", "/ready"}),
    ),
}

BASE_ROUTER_FILE = "libs/http-utils/src/endpoint.rs"

CHAR_LITERAL = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'\n])'")
RAW_STRING_START = re.compile(r'b?r(#*)"')


def mask(src: str) -> str:
    """
    `src` with comments blanked and the contents of string and char literals replaced by
    `x`, keeping every offset: braces, parentheses and method calls can then be matched
    on the result, and literals read back from `src` at the same positions.
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        prev_ident = i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_")
        if src.startswith("//", i):
            end = src.find("\n", i)
            end = n if end < 0 else end
            out.append(" " * (end - i))
            i = end
        elif src.startswith("/*", i):
            depth, j = 0, i
            while j < n:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                    if depth == 0:
                        break
                else:
                    j += 1
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif not prev_ident and (m := RAW_STRING_START.match(src, i)):
            close = '"' + m.group(1)
            end = src.find(close, m.end())
            if end < 0:
                raise RouteParseError(f"unterminated raw string at offset {i}")
            out.append(m.group(0) + "x" * (end - m.end()) + close)
            i = end + len(close)
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise RouteParseError(f"unterminated string at offset {i}")
            out.append('"' + "x" * (j - i - 1) + '"')
            i = j + 1
        elif c == "'" and (m := CHAR_LITERAL.match(src, i)):
            out.append("'" + "x" * (m.end() - i - 2) + "'")
            i = m.end()
        else:
            out.append(c)
            i += 1
    masked = "".join(out)
    assert len(masked) == len(src)
    return masked


def matching(masked: str, open_at: int) -> int:
    """The offset of the bracket that closes the one at `open_at`."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    opener = masked[open_at]
    closer = pairs[opener]
    depth = 0
    for j in range(open_at, len(masked)):
        if masked[j] == opener:
            depth += 1
        elif masked[j] == closer:
            depth -= 1
            if depth == 0:
                return j
    raise RouteParseError(f"unbalanced {opener!r} at offset {open_at}")


def top_level_args(src: str, masked: str, open_paren: int) -> list[str]:
    """The arguments of the call whose `(` is at `open_paren`, split on top-level commas."""
    close = matching(masked, open_paren)
    args, depth, start = [], 0, open_paren + 1
    for j in range(open_paren + 1, close):
        ch = masked[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(src[start:j].strip())
            start = j + 1
    last = src[start:close].strip()
    if last:
        args.append(last)
    return args


def string_literal(arg: str) -> str | None:
    m = re.fullmatch(r'"([^"\\]*)"', arg)
    return m.group(1) if m else None


def make_router_body(src: str, masked: str) -> tuple[int, int, int]:
    """(start of `pub fn make_router`, its body's `{`, its body's `}`)."""
    defs = [m.start() for m in re.finditer(r"\bpub fn make_router\s*\(", masked)]
    if len(defs) != 1:
        raise RouteParseError(f"expected one `pub fn make_router`, found {len(defs)}")
    params_open = masked.index("(", defs[0])
    body_open = masked.index("{", matching(masked, params_open))
    return defs[0], body_open, matching(masked, body_open)


def parse_registrations(src: str) -> list[Route]:
    """Every route `make_router` in `src` registers; refuses any form it can't read."""
    masked = mask(src)
    _, body_open, body_close = make_router_body(src, masked)
    body = masked[body_open:body_close]
    routes: list[Route] = []
    for m in re.finditer(r"\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
        name = m.group(1)
        if name not in ROUTE_METHODS:
            continue
        open_paren = body_open + m.end() - 1
        args = top_level_args(src, masked, open_paren)
        call = f".{name}({', '.join(args)[:80]})"
        if name == "any":
            if len(args) == 1 and args[0] in ALLOWED_CATCH_ALLS:
                continue
            raise RouteParseError(f"unknown catch-all {call}")
        method = ROUTE_METHODS[name]
        if method is None:
            raise RouteParseError(f"the parser can't read {call}: list its routes by hand")
        path = string_literal(args[0]) if args else None
        if path is None:
            raise RouteParseError(f"route path is not a string literal: {call}")
        routes.append(Route(method, path))
    for m in re.finditer(r"\battach_openapi_ui\s*\(", body):
        args = top_level_args(src, masked, body_open + m.end() - 1)
        paths = [string_literal(a) for a in args[2:]]
        if len(args) != 4 or None in paths:
            raise RouteParseError(f"attach_openapi_ui needs literal paths: {args}")
        routes.extend(Route("GET", p) for p in paths if p is not None)
    return routes


def parse_public_routes(src: str) -> set[str]:
    m = re.search(r"pub const PUBLIC_ROUTES: &\[&str\] = &\[(.*?)\];", src, re.S)
    if m is None:
        raise RouteParseError("no `pub const PUBLIC_ROUTES: &[&str]`")
    return set(re.findall(r'"([^"]*)"', m.group(1)))


def check_router_is_built_only_by_make_router(crate_src: Path, router_file: Path) -> None:
    """
    No route can be added outside `make_router`: its signature is the crate's only
    `RouterBuilder`, nothing else starts a router, and every caller builds its result
    straight away.
    """
    builders: list[str] = []
    for path in sorted(crate_src.rglob("*.rs")):
        src = path.read_text()
        masked = mask(src)
        where = path.relative_to(BASE_DIR)
        definition = None
        if path == router_file:
            start, body_open, body_close = make_router_body(src, masked)
            definition = (start, body_open, body_close)
        for m in re.finditer(r"\bRouterBuilder\s*<", masked):
            if definition is None or not definition[0] <= m.start() < definition[1]:
                builders.append(f"{where}:{src.count(chr(10), 0, m.start()) + 1}")
        if re.search(r"\bRouter\s*::\s*builder\s*\(", masked):
            raise RouteParseError(f"{where} starts a router with Router::builder")
        for m in re.finditer(r"\bmake_router\s*\(", masked):
            line = src.count("\n", 0, m.start()) + 1
            if re.search(r"\bfn\s+$", masked[: m.start()]):
                continue  # the definition
            if re.search(r"endpoint\s*::\s*$", masked[: m.start()]):
                # The base router: called once, at the top of `make_router`.
                if definition is None or not definition[1] < m.start() < definition[2]:
                    raise RouteParseError(f"{where}:{line}: base router outside make_router")
                continue
            close = matching(masked, m.end() - 1)
            if not re.match(r"\s*\??\s*\.\s*build\s*\(", masked[close + 1 :]):
                raise RouteParseError(f"{where}:{line}: make_router(...) is not built at once")
    if builders:
        raise RouteParseError(f"RouterBuilder outside make_router's signature: {builders}")


def route_table(server: str) -> tuple[list[Route], set[str]]:
    """The routes `server` registers and its public routes, checked complete."""
    source = ROUTERS[server]
    router_file = BASE_DIR / source.router_file
    src = router_file.read_text()
    routes = parse_registrations(src)

    base_src = (BASE_DIR / BASE_ROUTER_FILE).read_text()
    if parse_registrations(base_src):
        raise RouteParseError(f"{BASE_ROUTER_FILE}: the base router registers routes")
    check_router_is_built_only_by_make_router(BASE_DIR / source.crate_src, router_file)

    duplicates = {r for r in routes if routes.count(r) > 1}
    assert not duplicates, f"{server}: routes registered twice: {duplicates}"
    public = parse_public_routes(src)
    assert public == source.public_routes, f"{server}: PUBLIC_ROUTES {public}"
    registered_paths = {r.path for r in routes}
    assert public <= registered_paths, f"{server}: unregistered public routes"
    assert "/metrics" in registered_paths, f"{server}: no /metrics route"
    return routes, public


# A syntactically valid delta layer name (`LayerName::from_str`).
LAYER_NAME = (
    "000000000000000000000000000000000000-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "__0000000001696070-00000000016960E9"
)


def fill(pattern: str, tenant: TenantId, timeline: TimelineId) -> str:
    """The route's path with every parameter naming `tenant` and its `timeline`."""
    values = {
        "tenant_id": str(tenant),
        "tenant_shard_id": str(tenant),  # unsharded: the shard id is the tenant id
        "timeline_id": str(timeline),
        "source_timeline_id": str(timeline),
        "layer_file_name": LAYER_NAME,
        "layer_name": LAYER_NAME,
        "flag_key": "route-scope-probe",
        "node_id": "1",
        "id": "1",
        "destination_id": "1",
    }
    segments = []
    for segment in pattern.split("/"):
        if segment.startswith(":"):
            name = segment[1:]
            assert name in values, f"no value for :{name} in {pattern}: add one to fill()"
            segments.append(values[name])
        elif segment == "*":
            segments.append("timeline")
        else:
            segments.append(segment)
    return "/".join(segments)


def request_body(server: str, route: Route, tenant: TenantId) -> str | None:
    """
    The body sent with a probe. Routes whose tenant is named only in the body get a
    valid body naming `tenant`; every other route gets `{}` (or nothing for GET and
    DELETE): the token is checked before the body or the query is read.
    """
    if (server, route.method, route.path) in {
        ("pageserver", "PUT", "/v1/tenant/config"),
        ("pageserver", "PATCH", "/v1/tenant/config"),
    }:
        return f'{{"tenant_id": "{tenant}"}}'
    if (server, route.method, route.path) == ("safekeeper", "POST", "/v1/tenant/timeline"):
        return TimelineCreateRequest(
            tenant_id=tenant,
            timeline_id=TimelineId.generate(),
            mconf=MembershipConfiguration(generation=1, members=[], new_members=None),
            pg_version=170000,
            start_lsn=Lsn("0/1000000"),
            commit_lsn=None,
        ).to_json()
    return None if route.method in ("GET", "DELETE", "HEAD") else "{}"


def probe(method: str, url: str, token: str, body: str | None) -> int | str:
    """The status of one request (no client retries), or why there was none."""
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        return requests.request(method, url, headers=headers, data=body, timeout=30).status_code
    except requests.RequestException as e:
        return f"no answer ({type(e).__name__})"


def server_url(env: NeonEnv, server: str) -> str:
    if server == "pageserver":
        return f"http://localhost:{env.pageserver.service_port.http}"
    if server == "safekeeper":
        return f"http://localhost:{env.safekeepers[0].port.http}"
    return env.storage_controller_api


def test_route_tables_are_complete():
    """
    The route list of each server is read from its router and proven complete (no
    registration the parser can't read, no route added outside `make_router`), and its
    public routes are the pinned ones.
    """
    for server in ROUTERS:
        routes, _ = route_table(server)
        assert len(routes) >= 10, f"{server}: only {len(routes)} routes parsed"


@pytest.mark.parametrize(
    "src, error",
    [
        ("pub fn make_router() -> X { r.get(PATH, |r| h(r)) }", "not a string literal"),
        ('pub fn make_router() -> X { r.add("/a", vec![], h) }', "can't read"),
        ('pub fn make_router() -> X { r.scope("/a", other) }', "can't read"),
        ('pub fn make_router() -> X { r.any_method("/a", h) }', "can't read"),
        ("pub fn make_router() -> X { r.any(other_handler) }", "unknown catch-all"),
        ('pub fn make_router() -> X { attach_openapi_ui(b, s, SPEC, "/doc") }', "literal"),
    ],
)
def test_route_parser_refuses_what_it_cant_read(src: str, error: str):
    """The parser fails closed: a registration it can't read exactly is an error."""
    with pytest.raises(RouteParseError, match=error):
        parse_registrations(src)


def test_route_parser_reads_literals_comments_and_strings():
    """Comments, strings holding `.get(` and nested closures don't confuse the parser."""
    src = """
    pub fn make_router(a: A) -> RouterBuilder<B, E> {
        // .get("/commented", h)
        /* .post("/block", h) /* nested */ */
        let s = ".put(\\"/in-a-string\\", h)";
        let c = '"';
        attach_openapi_ui(endpoint::make_router(), spec, "/swagger.yml", "/v1/doc")
            .get("/metrics", move |r| request_span(r, |r| async move { h(r, (1, 2)).await }))
            .put(
                "/v1/tenant/:tenant_id/x",
                |r| api_handler(r, h),
            )
            .any(handler_404)
    }
    """
    assert set(parse_registrations(src)) == {
        Route("GET", "/metrics"),
        Route("PUT", "/v1/tenant/:tenant_id/x"),
        Route("GET", "/swagger.yml"),
        Route("GET", "/v1/doc"),
    }


@pytest.mark.parametrize("server", list(ROUTERS))
def test_every_route_refuses_metrics_and_foreign_tenant_tokens(
    neon_env_builder: NeonEnvBuilder, server: str
):
    """
    Every registered route answers 403 to a `metrics` token and to a tenant token for
    another tenant than the route's, before its handler does anything; `/metrics` is
    the one route a `metrics` token reads, and the public routes take no token.
    """
    routes, public = route_table(server)

    neon_env_builder.auth_enabled = True
    env = neon_env_builder.init_start()
    env.pageserver.allowed_errors.extend(
        [
            ".*Error processing HTTP request: Forbidden.*",
            ".*JWT scope '.+' is ineligible for Pageserver auth.*",
        ]
    )
    env.storage_controller.allowed_errors.extend([".*Forbidden.*"])

    # The routes name the victim tenant; the tenant token belongs to the initial one.
    victim_tenant, victim_timeline = env.create_tenant()
    endpoint = env.endpoints.create_start("main", tenant_id=victim_tenant)
    endpoint.safe_psql("CREATE TABLE t AS SELECT 1 AS x")  # the safekeeper holds the timeline
    endpoint.stop()

    keys = env.auth_keys
    tokens = {
        "metrics": keys.generate_token(scope=TokenScope.METRICS),
        "foreign tenant": keys.generate_tenant_token(env.initial_tenant),
    }
    assert env.initial_tenant != victim_tenant

    base = server_url(env, server)
    # Reads first, deletions last: a route that let a token through can't hide the
    # others' answers by removing the victim first.
    order = {"GET": 0, "HEAD": 0, "DELETE": 2}
    violations: list[str] = []
    probed = 0
    for route in sorted(routes, key=lambda r: (order.get(r.method, 1), r.path)):
        if route.path in public:
            continue
        url = base + fill(route.path, victim_tenant, victim_timeline)
        body = request_body(server, route, victim_tenant)
        for label, token in tokens.items():
            expected = 200 if (route.path == "/metrics" and label == "metrics") else 403
            status = probe(route.method, url, token, body)
            probed += 1
            if status != expected:
                violations.append(
                    f"{route.method} {route.path} with a {label} token: {status} (want {expected})"
                )

    assert not violations, (
        f"{server}: {len(violations)} of {probed} probes broke the route-scope invariant:\n"
        + "\n".join(violations)
    )
