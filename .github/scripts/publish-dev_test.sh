#!/usr/bin/env bash
# Self-test for the pure logic of publish-dev.sh (argument parsing, tags, the build-tools
# tag, submodule status, login detection, digest parsing, the existing-tag check). It sources
# the script, which does nothing when sourced. Run from anywhere:
#   .github/scripts/publish-dev_test.sh
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=publish-dev.sh
source "$here/publish-dev.sh"

failures=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# expect <name> <expected> <actual>
expect() {
    if [[ "$2" == "$3" ]]; then
        echo "ok: $1"
    else
        echo "FAIL: $1: expected [$2], got [$3]"
        failures=$((failures + 1))
    fi
}

# expect_ok / expect_fail <name> <command...>
expect_ok() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then echo "ok: $name"; else echo "FAIL: $name: expected success"; failures=$((failures + 1)); fi
}
expect_fail() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then echo "FAIL: $name: expected failure"; failures=$((failures + 1)); else echo "ok: $name"; fi
}

# parse <args...>: prints the resulting settings on one line.
parse() {
    (
        parse_args "$@" || exit 1
        echo "no_push=$NO_PUSH only=$ONLY dirty=$ALLOW_DIRTY unpushed=$ALLOW_UNPUSHED force=$FORCE_RETAG"
    )
}
expect "defaults" "no_push=0 only= dirty=0 unpushed=0 force=0" "$(parse)"
expect "all flags" "no_push=1 only=compute dirty=1 unpushed=1 force=1" \
    "$(parse --no-push --only compute --allow-dirty --allow-unpushed --force-retag)"
expect "only storage" "no_push=0 only=storage dirty=0 unpushed=0 force=0" "$(parse --only storage)"
expect_fail "only needs a value" parse --only
expect_fail "only rejects other names" parse --only nope
expect_fail "unknown argument" parse --bogus
expect "help returns 2" "2" "$(
    parse_args --help >/dev/null 2>&1
    echo $?
)"

# sha12
sha=7dc4d86b7d48aabbccddeeff00112233445566ff
expect "sha12" "7dc4d86b7d48" "$(sha12 "$sha")"

# image refs
expect "storage ref" "ghcr.io/chelabase/neon-storage:7dc4d86b7d48-dev" "$(image_ref storage 7dc4d86b7d48)"
expect "compute ref" "ghcr.io/chelabase/neon-compute-v17:7dc4d86b7d48-dev" "$(image_ref compute 7dc4d86b7d48)"
expect_fail "unknown image name" image_ref other 7dc4d86b7d48

# build-tools tag: first 12 hex of sha256sum build-tools/Dockerfile
mkdir -p "$tmp/root/build-tools"
printf 'FROM scratch\n' >"$tmp/root/build-tools/Dockerfile"
expected="$(sha256sum "$tmp/root/build-tools/Dockerfile" | cut -c1-12)"
expect "build-tools tag" "$expected" "$(build_tools_tag "$tmp/root")"
expect "build-tools tag has 12 hex" "12" "$(build_tools_tag "$tmp/root" | tr -d '\n' | wc -c)"

# submodule status: any '-', '+' or 'U' prefix is a failure
ok_status=" 0ce4410764df1a67931de1036e45704f1798d14f vendor/postgres-v14 (heads/x)
 473d64ac837c741c2cbb2cbd2e8e6c80e47f3d8d vendor/postgres-v17 (heads/y)"
expect_ok "submodules clean" submodules_ok "$ok_status"
expect_fail "submodule uninitialised" submodules_ok "-0ce4410764df1a67931de1036e45704f1798d14f vendor/postgres-v14"
expect_fail "submodule moved" submodules_ok "+0ce4410764df1a67931de1036e45704f1798d14f vendor/postgres-v14 (x)"
expect_fail "submodule conflict" submodules_ok "U0ce4410764df1a67931de1036e45704f1798d14f vendor/postgres-v14"
expect_fail "no submodules at all" submodules_ok ""

# ghcr.io login detection
printf '{"auths":{"ghcr.io":{"auth":"x"}}}\n' >"$tmp/auths.json"
printf '{"auths":{"https://index.docker.io/v1/":{}}}\n' >"$tmp/other.json"
printf '{"credHelpers":{"ghcr.io":"pass"}}\n' >"$tmp/helper.json"
printf '{"credsStore":"desktop"}\n' >"$tmp/store.json"
expect_ok "login in auths" ghcr_login_present "$tmp/auths.json"
expect_ok "login via credHelpers" ghcr_login_present "$tmp/helper.json"
expect_ok "login via credsStore" ghcr_login_present "$tmp/store.json"
expect_fail "no ghcr login" ghcr_login_present "$tmp/other.json"
expect_fail "no config file" ghcr_login_present "$tmp/missing.json"

# digest from `docker buildx imagetools inspect` output
inspect_out="Name:      ghcr.io/chelabase/neon-storage:7dc4d86b7d48-dev
MediaType: application/vnd.oci.image.index.v1+json
Digest:    sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
"
expect "digest parse" "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
    "$(digest_from_inspect "$inspect_out")"
expect_fail "digest parse of garbage" digest_from_inspect "nothing here"
expect "pin form" "ghcr.io/chelabase/neon-compute-v17:7dc4d86b7d48-dev@sha256:abc" \
    "$(pin_ref ghcr.io/chelabase/neon-compute-v17:7dc4d86b7d48-dev sha256:abc)"

# existing-tag check, with `docker` stubbed
# shellcheck disable=SC2329 # called by tag_exists
docker() { [[ "$*" == "buildx imagetools inspect ghcr.io/x/exists:1" ]]; }
expect_ok "tag_exists true" tag_exists ghcr.io/x/exists:1
expect_fail "tag_exists false" tag_exists ghcr.io/x/missing:1
FORCE_RETAG=0
expect_fail "refuses existing tag" check_tag_free ghcr.io/x/exists:1
expect_ok "free tag passes" check_tag_free ghcr.io/x/missing:1
FORCE_RETAG=1
expect_ok "force-retag allows existing tag" check_tag_free ghcr.io/x/exists:1
unset -f docker

# --push-only: argument parsing
parse_po() {
    (
        parse_args "$@" || exit 1
        echo "push_only=$PUSH_ONLY no_push=$NO_PUSH only=$ONLY"
    )
}
expect "push-only default off" "push_only=0 no_push=0 only=" "$(parse_po)"
expect "push-only on" "push_only=1 no_push=0 only=" "$(parse_po --push-only)"
expect "push-only with only" "push_only=1 no_push=0 only=compute" "$(parse_po --push-only --only compute)"
expect_fail "push-only refuses --no-push" parse_po --push-only --no-push
expect_fail "--no-push refuses push-only (other order)" parse_po --no-push --push-only
expect_fail "push-only refuses --allow-unpushed" parse_po --push-only --allow-unpushed
expect_ok "push-only accepts --allow-dirty and --force-retag" parse_po --push-only --allow-dirty --force-retag
expect_ok "usage documents push-only" grep -q -- --push-only <<<"$(usage 2>&1)"

# --push-only: the local image must carry the build SHA of HEAD (the revision label)
full=7dc4d86b7d48aabbccddeeff00112233445566ff
other=1111111111112222222222223333333333334444
# shellcheck disable=SC2329 # called by image_revision
docker() {
    case "$*" in
    "image inspect --format {{index .Config.Labels \"org.opencontainers.image.revision\"}} ghcr.io/x/good:1") echo "$full" ;;
    "image inspect --format {{index .Config.Labels \"org.opencontainers.image.revision\"}} ghcr.io/x/stale:1") echo "$other" ;;
    "image inspect --format {{index .Config.Labels \"org.opencontainers.image.revision\"}} ghcr.io/x/nolabel:1") echo "" ;;
    *) return 1 ;;
    esac
}
expect "image_revision reads the label" "$full" "$(image_revision ghcr.io/x/good:1)"
expect_fail "image_revision of a missing image" image_revision ghcr.io/x/absent:1
expect_ok "matching image passes" check_local_image ghcr.io/x/good:1 "$full"
expect_fail "missing image refused" check_local_image ghcr.io/x/absent:1 "$full"
expect_fail "stale image refused" check_local_image ghcr.io/x/stale:1 "$full"
expect_fail "image without a revision label refused" check_local_image ghcr.io/x/nolabel:1 "$full"
expect "missing image message" "1" "$(check_local_image ghcr.io/x/absent:1 "$full" 2>&1 | grep -c 'not found locally')"
expect "stale image message" "1" "$(check_local_image ghcr.io/x/stale:1 "$full" 2>&1 | grep -c 'built from')"
unset -f docker

# --push-only: whole-run behaviour with git, docker and the login stubbed
calls="$tmp/calls"
# run_main <local-images: good|stale|none> <tag-exists: 0|1> <args...>: prints output, then calls
run_main() {
    local imgs="$1" exists="$2"
    shift 2
    : >"$calls"
    (
        # shellcheck disable=SC2329 # called by main
        git() {
            case "$*" in
            *"rev-parse HEAD") echo "$full" ;;
            *"status --porcelain") echo "${FAKE_STATUS:-}" ;;
            *"submodule status") echo "-deadbeef vendor/postgres-v17" ;;
            *"merge-base --is-ancestor"*) return "${FAKE_ANCESTOR:-0}" ;;
            *) return 0 ;;
            esac
        }
        # shellcheck disable=SC2329 # called by main
        docker() {
            echo "docker $*" >>"$calls"
            case "$1 $2" in
            "image inspect")
                case "$imgs" in
                good) echo "$full" ;;
                stale) echo "$other" ;;
                *) return 1 ;;
                esac
                ;;
            "buildx imagetools")
                if [[ "$exists" == 1 && "${FAKE_PUSHED:-0}" == 0 ]]; then return 0; fi
                if [[ "${FAKE_PUSHED:-0}" == 1 ]]; then
                    echo "Digest:    sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    return 0
                fi
                return 1
                ;;
            push\ *) FAKE_PUSHED=1 ;;
            esac
            return 0
        }
        # shellcheck disable=SC2329 # called by main
        ghcr_login_present() { return "${FAKE_LOGIN:-0}"; }
        main "$@"
    ) 2>&1
    cat "$calls"
}
pushes() { grep -c '^docker push ' "$calls"; }

out="$(run_main good 0 --push-only)"
expect "push-only pushes both images" "2" "$(pushes)"
expect "push-only never builds" "0" "$(grep -c 'buildx build' "$calls")"
expect "push-only skips the variant test" "0" "$(grep -c 'image_variant_test' <<<"$out")"
expect "push-only prints pin-ready digests" "2" \
    "$(grep -c '^  ghcr.io/chelabase/neon-.*-dev@sha256:0123456789abcdef' <<<"$out")"
out="$(run_main good 0 --push-only --only compute)"
expect "push-only --only pushes one image" "1" "$(pushes)"
out="$(run_main stale 0 --push-only)"
expect "push-only refuses a stale image" "0" "$(pushes)"
expect "stale refusal is explained" "1" "$(grep -c 'built from' <<<"$out")"
out="$(run_main none 0 --push-only)"
expect "push-only refuses a missing image" "0" "$(pushes)"
expect "missing refusal is explained" "1" "$(grep -c 'not found locally' <<<"$out")"
out="$(run_main good 1 --push-only)"
expect "push-only refuses an existing tag" "0" "$(pushes)"
out="$(run_main good 1 --push-only --force-retag)"
expect "push-only --force-retag overrides the tag check" "2" "$(pushes)"
FAKE_LOGIN=1; out="$(run_main good 0 --push-only)"
expect "push-only needs a ghcr login" "0" "$(pushes)"
unset FAKE_LOGIN
FAKE_STATUS=" M x"; out="$(run_main good 0 --push-only)"
expect "push-only refuses a dirty tree" "0" "$(pushes)"
unset FAKE_STATUS
FAKE_STATUS=" M x"; out="$(run_main good 0 --push-only --allow-dirty)"
expect "push-only --allow-dirty pushes" "2" "$(pushes)"
unset FAKE_STATUS
FAKE_ANCESTOR=1; out="$(run_main good 0 --push-only)"
expect "push-only needs HEAD on origin/main" "0" "$(pushes)"
unset FAKE_ANCESTOR

if ((failures > 0)); then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
