#!/usr/bin/env bash
# F3 (review D1): the extension harness's pageserver writes its runtime state into the
# bind-mounted docker-compose/pageserver_config/ (docker-compose.yml: ./pageserver_config ->
# /data/.neon/). That state is never committed, and .gitignore covers it, so a harness run
# leaves `git status` clean. Only the two config files are tracked there. Run from anywhere:
#   .github/scripts/runtime_state_test.sh
# Pinned for the coder: add it to ci-local.sh's lint self-tests.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
failures=0

expect() {
    if [[ "$2" == "$3" ]]; then echo "ok: $1"; else
        echo "FAIL: $1: expected [$2], got [$3]"
        failures=$((failures + 1))
    fi
}

tracked="$(git -C "$ROOT" ls-files docker-compose/pageserver_config/tenants)"
expect "no tenant state is committed under docker-compose/pageserver_config/tenants" "" "$tracked"

expect "only the config files are tracked in docker-compose/pageserver_config" \
    "docker-compose/pageserver_config/identity.toml docker-compose/pageserver_config/pageserver.toml" \
    "$(git -C "$ROOT" ls-files docker-compose/pageserver_config | LC_ALL=C sort | paste -sd' ' -)"

# What a harness run writes there (a tenant's config and layers, the deletion queue) is ignored.
for p in \
    docker-compose/pageserver_config/tenants/b26436a651b65ed31304e3c29f2385ea/config-v1 \
    docker-compose/pageserver_config/tenants/0123456789abcdef0123456789abcdef/timelines/0123456789abcdef0123456789abcdef/000000000000000000000000000000000000-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF__00000000014E8F30-00000000014E8FA9-v1-00000001 \
    docker-compose/pageserver_config/deletion/header-01; do
    if git -C "$ROOT" check-ignore -q --no-index "$p"; then got=ignored; else got="not ignored"; fi
    expect "$p is ignored" ignored "$got"
done

# The config files themselves stay tracked, not ignored.
for p in docker-compose/pageserver_config/identity.toml docker-compose/pageserver_config/pageserver.toml; do
    if git -C "$ROOT" check-ignore -q --no-index "$p"; then got=ignored; else got="not ignored"; fi
    expect "$p is not ignored" "not ignored" "$got"
done

if ((failures > 0)); then
    echo "$failures failure(s)"
    exit 1
fi
