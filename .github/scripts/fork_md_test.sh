#!/usr/bin/env bash
# F3 (review D6): FORK.md records every fork round 4 change the end-of-step review listed, and
# none of its statements is wrong. A checklist, not prose review: each item names the words a
# description of the change can't do without (several on one line = in one bullet; FORK.md's
# bullets are single lines). Run from anywhere:
#   .github/scripts/fork_md_test.sh
# Pinned for the coder: add it to ci-local.sh's lint self-tests.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FORK_MD="$ROOT/FORK.md"
failures=0

fail() {
    echo "FAIL: $1"
    failures=$((failures + 1))
}

# line_has <what> <ERE>...: some line of FORK.md matches every ERE (case-insensitive).
line_has() {
    local what="$1" line re ok
    shift
    while IFS= read -r line; do
        ok=true
        for re in "$@"; do
            if ! grep -qiE -- "$re" <<<"$line"; then
                ok=false
                break
            fi
        done
        if $ok; then
            echo "ok: $what"
            return
        fi
    done <"$FORK_MD"
    fail "$what: no line of FORK.md matches all of: $*"
}

# section <heading>: the lines of the "## <heading>" section.
section() {
    awk -v h="## $1" '$0 == h { on = 1; next } /^## / { on = 0 } on' "$FORK_MD"
}

[[ -f "$FORK_MD" ]] || {
    echo "FAIL: FORK.md does not exist"
    exit 1
}

# compute_ctl
line_has "the internal API on loopback behind its secret" '(loopback|127\.0\.0\.1)' 'secret'
line_has "the external API answers 401, INSTANCE_ID bypasses nothing" '\b401\b' 'INSTANCE_ID'
line_has "POST /storage_token" 'POST /storage_token'
line_has "the storage_token_refresh capability" 'storage_token_refresh'
line_has "RT4-6: /grants narrowed, /extensions trusted only" '/grants' '/extensions' 'trusted'
line_has "RT4-7: /configure without the token on a compute that has one is refused" \
    '/configure' 'storage_auth_token' '(400|refus)'
line_has "the DuckDB pins" 'duckdb\.disabled_filesystems'
line_has "the realtime pg_hba block" 'realtime_logins' 'pg_hba'
# storage auth
line_has "the metrics scope" '`?metrics`? scope|scope[^.]*`?metrics`?|Scope::Metrics'
line_has "route authorization" '\broutes?\b' 'authori[sz]'
line_has "check_permission made total" 'check_permission' 'total'
line_has "nbf validation" '\bnbf\b'
# proxy
line_has "the proxy's Valkey password file" '--redis-plain-password-file'
line_has "local_proxy's compute_ctl token file" '--compute-ctl-token-file'
line_has "the proxy's control-plane token file" '--control-plane-token-file'
# storage controller
line_has "storcon's serialization-failure backoff" 'backoff' '(storcon|storage controller|storage_controller)'

# Wrong statements.
if grep -qiE 'minimal compute: only|only what chelabase runs' "$FORK_MD"; then
    fail "FORK.md still says the compute is minimal only (the extensions-all image and its harness are kept)"
else
    echo "ok: no minimal-compute-only claim"
fi
line_has "the extensions-all image is named" '(extensions-all|EXTENSIONS=all)'

postgres="$(section "Postgres changes")"
if [[ -z "$postgres" ]]; then
    fail "no \"## Postgres changes\" section"
elif ! grep -qF 'REL_17_STABLE_chelabase' <<<"$postgres"; then
    fail "the Postgres changes section doesn't name REL_17_STABLE_chelabase (the branch after ship)"
else
    echo "ok: the Postgres changes section names REL_17_STABLE_chelabase"
fi
if grep -qF 'round-4-v17' "$FORK_MD"; then
    fail "FORK.md names the round branch round-4-v17, which is gone after ship"
else
    echo "ok: no round branch named"
fi

if ((failures > 0)); then
    echo "$failures failure(s)"
    exit 1
fi
