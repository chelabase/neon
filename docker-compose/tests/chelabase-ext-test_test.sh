#!/usr/bin/env bash
# Tests for docker-compose/chelabase-ext-test.sh (the extension-test harness wrapper), the
# `ONLY` selection and `SKIP` list of docker_compose_test.sh and run-tests.sh, and the removal
# of the extensions dropped in fork round 4 (X0). Needs only bash: `docker`, `docker compose`,
# `psql` and `sleep` are stubbed through PATH shims that record their arguments; nothing
# touches the network or a Docker daemon. Run from anywhere:
#   docker-compose/tests/chelabase-ext-test_test.sh
#
# Interface pinned for the wrapper (the coder may not change it without a deviation):
#   chelabase-ext-test.sh [--storage-image <ref>] [--only <dir,...>] [--keep-images <tag>] [--help]
#   * flags take their value as the next argument (no `--flag=value` form); a missing, empty or
#     flag-looking value, an unknown flag or a positional argument prints "usage" to stderr and
#     exits 2 before any docker call; --help prints usage on stdout and exits 0.
#   * REPOSITORY=chelabase-local, TAG=ext-test (or the --keep-images tag), exported to the harness.
#   * two `docker build` / `docker buildx build` calls from the checkout root (the last argument),
#     in the form `--file X`, `--target X`, `--tag X`, `--build-arg K=V` (space-separated):
#       compute:  --file <root>/compute/compute-node.Dockerfile --build-arg PG_VERSION=v17
#                 --build-arg EXTENSIONS=all --build-arg DEBIAN_VERSION=bookworm
#                 --build-arg BUILD_TAG=<TAG> --tag chelabase-local/compute-node-v17:<TAG>
#       tests:    the same plus --target extension-tests
#                 --tag chelabase-local/neon-test-extensions-v17:<TAG>
#   * --storage-image <ref>: `docker tag <ref> chelabase-local/neon:<TAG>` before the harness;
#     without it, no `docker tag` and no storage build.
#   * then <root>/docker-compose/docker_compose_test.sh with TEST_VERSION_ONLY=17 and ONLY=<value>
#     (unset or empty without --only); its exit status is the wrapper's.
#   * unless --keep-images, `docker rmi` of the compute and test images runs after the harness,
#     pass or fail; with it, nothing is removed. A failed build stops the wrapper (non-zero, no
#     harness).
# Interface pinned for the harness scripts:
#   * run-tests.sh: ONLY=<dir,...> restricts the run to those directories of <extdir>; an entry
#     in ONLY runs even if SKIP lists it; an ONLY entry that is not a directory is an error
#     (non-zero exit, nothing run).
#   * docker_compose_test.sh: when ONLY is set it passes `-e ONLY=<value>` to the `/ext-src`
#     run-tests.sh exec and does not run the `/postgres/contrib` suite; without ONLY neither
#     changes. The SKIP of the `/ext-src` exec is exactly
#     pg_jsonschema-src,rdkit-src,timescaledb-src (X1/X3/X4 un-skip theirs later, P9).
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$here/../.." && pwd)"
WRAPPER_SRC="$ROOT/docker-compose/chelabase-ext-test.sh"
SELF="$(basename "${BASH_SOURCE[0]}")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failures=0
n=0

die_case() {
    echo "$*"
    exit 1
}

# eq <what> <expected> <actual>
eq() {
    [[ "$2" == "$3" ]] || die_case "$1: expected [$2], got [$3]"
}

# has <what> <line> <token sequence>: the sequence occurs in the line as whole words.
has() {
    [[ " $2 " == *" $3 "* ]] || die_case "$1: expected [$3] in [$2]"
}

lacks() {
    [[ " $2 " != *" $3 "* ]] || die_case "$1: did not expect [$3] in [$2]"
}

# make_shims <dir>: PATH shims. `docker` logs "docker <args>" to $FAKE_LOG; `sleep` returns at once.
make_shims() {
    local d="$1"
    mkdir -p "$d"
    cat >"$d/docker" <<'EOF'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >>"${FAKE_LOG:?}"
case "${1:-}" in
build | buildx)
    if [[ "${FAKE_DOCKER_FAIL:-}" == build ]]; then exit 1; fi
    ;;
compose)
    if [[ "${2:-}" == logs ]]; then echo "All computes are started"; fi
    ;;
esac
exit 0
EOF
    cat >"$d/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    cat >"$d/psql" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "$d/docker" "$d/sleep" "$d/psql"
}

# sandbox <name>: a fresh fake checkout under $tmp/<name>/co with the real scripts that exist,
# a fake harness that logs its environment, and shims. Sets SB, CO, LOG, SHIMS.
sandbox() {
    SB="$tmp/$1"
    CO="$SB/co"
    LOG="$SB/log"
    SHIMS="$SB/shims"
    rm -rf "$SB"
    mkdir -p "$CO/docker-compose" "$CO/compute/patches"
    : >"$LOG"
    : >"$CO/compute/compute-node.Dockerfile"
    : >"$CO/compute/patches/contrib_pg17.patch"
    make_shims "$SHIMS"
    cat >"$CO/docker-compose/docker_compose_test.sh" <<'EOF'
#!/usr/bin/env bash
printf 'HARNESS TEST_VERSION_ONLY=%s ONLY=%s REPOSITORY=%s TAG=%s\n' \
    "${TEST_VERSION_ONLY-<unset>}" "${ONLY-<unset>}" "${REPOSITORY-<unset>}" "${TAG-<unset>}" >>"${FAKE_LOG:?}"
exit "${FAKE_HARNESS_RC:-0}"
EOF
    chmod +x "$CO/docker-compose/docker_compose_test.sh"
    if [[ -f "$WRAPPER_SRC" ]]; then
        cp "$WRAPPER_SRC" "$CO/docker-compose/chelabase-ext-test.sh"
        chmod +x "$CO/docker-compose/chelabase-ext-test.sh"
    fi
    CO="$(cd "$CO" && pwd -P)"
}

need_wrapper() {
    [[ -f "$WRAPPER_SRC" ]] || die_case "docker-compose/chelabase-ext-test.sh does not exist"
}

# run_wrapper <args...>: runs the sandboxed wrapper; sets RC, OUT, ERR, and LINES (the log).
run_wrapper() {
    RC=0
    FAKE_LOG="$LOG" PATH="$SHIMS:$PATH" bash "$CO/docker-compose/chelabase-ext-test.sh" "$@" \
        >"$SB/out" 2>"$SB/err" </dev/null || RC=$?
    OUT="$(cat "$SB/out")"
    ERR="$(cat "$SB/err")"
    LINES_="$(cat "$LOG")"
}

# build_line <pattern>: the one logged build call whose line matches the glob.
build_lines() {
    grep -E '^docker (buildx )?build ' "$LOG" || true
}

compute_build() {
    build_lines | grep -F -- "compute-node-v17:" | grep -vF -- "--target extension-tests" | head -1
}

tests_build() {
    build_lines | grep -F -- "--target extension-tests" | head -1
}

harness_line() {
    grep '^HARNESS ' "$LOG" | head -1
}

# ---------------------------------------------------------------------------------------------
# Wrapper: arguments

case_wrapper_exists() {
    need_wrapper
    bash -n "$WRAPPER_SRC" || die_case "syntax error"
    [[ -x "$WRAPPER_SRC" ]] || die_case "not executable"
}

case_usage_errors() {
    need_wrapper
    local args
    for args in "--bogus" "--only" "--storage-image" "--keep-images" "--only --keep-images t" \
        "--storage-image --only a" "--keep-images --only a" "positional" "--only=a"; do
        sandbox "usage"
        # shellcheck disable=SC2086
        run_wrapper $args
        eq "exit status for [$args]" 2 "$RC"
        [[ "$ERR" == *[Uu]sage* ]] || die_case "no usage on stderr for [$args]: [$ERR]"
        [[ ! -s "$LOG" ]] || die_case "docker or the harness ran for [$args]: $(cat "$LOG")"
    done
    sandbox "usage-empty"
    run_wrapper --only ""
    eq "exit status for an empty --only" 2 "$RC"
    [[ ! -s "$LOG" ]] || die_case "docker ran for an empty --only"
    sandbox "usage-empty2"
    run_wrapper --keep-images ""
    eq "exit status for an empty --keep-images" 2 "$RC"
    [[ ! -s "$LOG" ]] || die_case "docker ran for an empty --keep-images"
}

case_help() {
    need_wrapper
    sandbox "help"
    run_wrapper --help
    eq "exit status" 0 "$RC"
    [[ "$OUT" == *[Uu]sage* ]] || die_case "no usage on stdout: [$OUT]"
    [[ ! -s "$LOG" ]] || die_case "docker ran for --help"
}

# ---------------------------------------------------------------------------------------------
# Wrapper: builds and harness

case_defaults_builds() {
    need_wrapper
    sandbox "defaults"
    run_wrapper
    eq "exit status" 0 "$RC"
    local c t
    c="$(compute_build)"
    t="$(tests_build)"
    [[ -n "$c" ]] || die_case "no compute build in: $(cat "$LOG")"
    [[ -n "$t" ]] || die_case "no extension-tests build in: $(cat "$LOG")"
    eq "number of builds" 2 "$(build_lines | wc -l | tr -d ' ')"
    for l in "$c" "$t"; do
        has "file" "$l" "--file $CO/compute/compute-node.Dockerfile"
        has "pg version" "$l" "--build-arg PG_VERSION=v17"
        has "extensions" "$l" "--build-arg EXTENSIONS=all"
        has "debian" "$l" "--build-arg DEBIAN_VERSION=bookworm"
        has "build tag" "$l" "--build-arg BUILD_TAG=ext-test"
        eq "build context (the checkout root, last argument)" "$CO" "${l##* }"
    done
    has "compute tag" "$c" "--tag chelabase-local/compute-node-v17:ext-test"
    lacks "compute target" "$c" "--target extension-tests"
    has "tests tag" "$t" "--tag chelabase-local/neon-test-extensions-v17:ext-test"
    has "tests target" "$t" "--target extension-tests"
}

case_defaults_harness() {
    need_wrapper
    sandbox "harness"
    run_wrapper
    eq "exit status" 0 "$RC"
    local h
    h="$(harness_line)"
    [[ -n "$h" ]] || die_case "harness not run: $(cat "$LOG")"
    has "pg version" "$h" "TEST_VERSION_ONLY=17"
    has "repository" "$h" "REPOSITORY=chelabase-local"
    has "tag" "$h" "TAG=ext-test"
    [[ "$h" == *"ONLY=<unset>"* || "$h" == *"ONLY= "* ]] || die_case "ONLY set without --only: [$h]"
    # Builds first, harness last.
    local last
    last="$(grep -nE '^(HARNESS|docker (buildx )?build )' "$LOG" | tail -1)"
    [[ "$last" == *HARNESS* ]] || die_case "the harness did not run after both builds: $(cat "$LOG")"
    # Default: no storage image is tagged or built.
    ! grep -qE '^docker tag ' "$LOG" || die_case "docker tag without --storage-image"
    # Default: the images are removed afterwards.
    grep -E '^docker (rmi|image rm) ' "$LOG" | grep -qF "compute-node-v17:ext-test" ||
        die_case "compute image not removed: $(cat "$LOG")"
    grep -E '^docker (rmi|image rm) ' "$LOG" | grep -qF "neon-test-extensions-v17:ext-test" ||
        die_case "test image not removed: $(cat "$LOG")"
}

case_only_passthrough() {
    need_wrapper
    sandbox "only"
    run_wrapper --only pg_uuidv7-src,hll-src
    eq "exit status" 0 "$RC"
    has "ONLY passed through" "$(harness_line)" "ONLY=pg_uuidv7-src,hll-src"
    has "pg version" "$(harness_line)" "TEST_VERSION_ONLY=17"
}

case_storage_image() {
    need_wrapper
    sandbox "storage"
    run_wrapper --storage-image ghcr.io/chelabase/neon-storage:abc123def456-dev
    eq "exit status" 0 "$RC"
    local tag_line harness_pos tag_pos
    tag_line="$(grep -E '^docker tag ' "$LOG" | head -1)"
    eq "tag call" "docker tag ghcr.io/chelabase/neon-storage:abc123def456-dev chelabase-local/neon:ext-test" "$tag_line"
    tag_pos="$(grep -n '^docker tag ' "$LOG" | head -1 | cut -d: -f1)"
    harness_pos="$(grep -n '^HARNESS ' "$LOG" | head -1 | cut -d: -f1)"
    ((tag_pos < harness_pos)) || die_case "the storage image was tagged after the harness ran"
    eq "builds (the storage image is never built)" 2 "$(build_lines | wc -l | tr -d ' ')"
}

case_keep_images() {
    need_wrapper
    sandbox "keep"
    run_wrapper --keep-images round4-base --storage-image some/storage:1
    eq "exit status" 0 "$RC"
    has "compute tag" "$(compute_build)" "--tag chelabase-local/compute-node-v17:round4-base"
    has "tests tag" "$(tests_build)" "--tag chelabase-local/neon-test-extensions-v17:round4-base"
    has "build tag" "$(compute_build)" "--build-arg BUILD_TAG=round4-base"
    has "harness tag" "$(harness_line)" "TAG=round4-base"
    eq "storage tag" "docker tag some/storage:1 chelabase-local/neon:round4-base" "$(grep -E '^docker tag ' "$LOG" | head -1)"
    ! grep -qE '^docker (rmi|image rm|image prune|system prune|builder prune)' "$LOG" ||
        die_case "images removed despite --keep-images: $(cat "$LOG")"
}

case_harness_failure() {
    need_wrapper
    sandbox "hfail"
    FAKE_HARNESS_RC=3 run_wrapper --only hll-src
    eq "the harness's exit status is the wrapper's" 3 "$RC"
    grep -E '^docker (rmi|image rm) ' "$LOG" | grep -qF "compute-node-v17:ext-test" ||
        die_case "images not removed after a failed harness: $(cat "$LOG")"
}

case_build_failure() {
    need_wrapper
    sandbox "bfail"
    FAKE_DOCKER_FAIL=build run_wrapper
    [[ "$RC" -ne 0 ]] || die_case "exit status 0 after a failed build"
    ! grep -q '^HARNESS ' "$LOG" || die_case "the harness ran after a failed build"
}

# ---------------------------------------------------------------------------------------------
# docker_compose_test.sh: ONLY and SKIP

# run_harness [VAR=value ...]: runs the real docker_compose_test.sh in a sandbox for v17.
run_harness() {
    sandbox "dct"
    mkdir -p "$CO/docker-compose"
    cp "$ROOT/docker-compose/docker_compose_test.sh" "$ROOT/docker-compose/docker-compose.yml" \
        "$ROOT/docker-compose/run-tests.sh" "$CO/docker-compose/"
    RC=0
    env FAKE_LOG="$LOG" PATH="$SHIMS:$PATH" TEST_VERSION_ONLY=17 "$@" \
        bash "$CO/docker-compose/docker_compose_test.sh" >"$SB/out" 2>"$SB/err" </dev/null || RC=$?
}

ext_exec_line() {
    grep -E '^docker compose exec .*/run-tests.sh /ext-src' "$LOG" | head -1
}

case_harness_only() {
    run_harness ONLY=pg_uuidv7-src,hll-src
    eq "exit status (stderr: $(tail -5 "$SB/err"))" 0 "$RC"
    local l
    l="$(ext_exec_line)"
    [[ -n "$l" ]] || die_case "the /ext-src suite did not run: $(cat "$LOG")"
    has "ONLY passed to run-tests.sh" "$l" "-e ONLY=pg_uuidv7-src,hll-src"
    ! grep -qF -- "/run-tests.sh /postgres/contrib" "$LOG" ||
        die_case "the contrib suite ran although ONLY is set"
}

case_harness_without_only() {
    run_harness
    eq "exit status (stderr: $(tail -5 "$SB/err"))" 0 "$RC"
    local l
    l="$(ext_exec_line)"
    [[ -n "$l" ]] || die_case "the /ext-src suite did not run: $(cat "$LOG")"
    [[ "$l" != *"-e ONLY="* ]] || die_case "ONLY passed without being set: [$l]"
    grep -qF -- "/run-tests.sh /postgres/contrib" "$LOG" ||
        die_case "the contrib suite did not run without ONLY"
}

case_harness_skip_list() {
    run_harness
    eq "exit status (stderr: $(tail -5 "$SB/err"))" 0 "$RC"
    local l skip got
    l="$(ext_exec_line)"
    [[ -n "$l" ]] || die_case "the /ext-src suite did not run: $(cat "$LOG")"
    skip="$(grep -o -- '-e SKIP=[^ ]*' <<<"$l" | head -1)"
    skip="${skip#-e SKIP=}"
    got="$(tr ',' '\n' <<<"$skip" | sort | paste -sd, -)"
    eq "SKIP list of the /ext-src suite" "pg_jsonschema-src,rdkit-src,timescaledb-src" "$got"
}

# ---------------------------------------------------------------------------------------------
# run-tests.sh: ONLY

# ext_dirs <names...>: $SB/ext with one directory per name; each neon-test.sh logs its name.
ext_dirs() {
    sandbox "ext"
    mkdir -p "$SB/ext"
    : >"$SB/ran"
    local d
    for d in "$@"; do
        mkdir -p "$SB/ext/$d"
        printf '#!/usr/bin/env bash\necho %s >>%s\n' "$d" "$SB/ran" >"$SB/ext/$d/neon-test.sh"
        chmod +x "$SB/ext/$d/neon-test.sh"
    done
}

# run_tests <VAR=value ...>: runs the real run-tests.sh over $SB/ext.
run_tests() {
    RC=0
    env PATH="$SHIMS:$PATH" PARALLEL_COMPUTES=1 "$@" bash "$ROOT/docker-compose/run-tests.sh" "$SB/ext" \
        >"$SB/out" 2>"$SB/err" </dev/null || RC=$?
}

ran() {
    paste -sd, "$SB/ran"
}

case_run_tests_only_one() {
    ext_dirs alpha-src beta-src gamma-src
    run_tests ONLY=beta-src SKIP=
    eq "exit status" 0 "$RC"
    eq "directories run" "beta-src" "$(ran)"
}

case_run_tests_only_two() {
    ext_dirs alpha-src beta-src gamma-src
    run_tests ONLY=gamma-src,alpha-src SKIP=
    eq "exit status" 0 "$RC"
    eq "directories run" "alpha-src,gamma-src" "$(sort "$SB/ran" | paste -sd, -)"
}

case_run_tests_no_only() {
    ext_dirs alpha-src beta-src gamma-src
    run_tests SKIP=beta-src
    eq "exit status" 0 "$RC"
    eq "directories run (SKIP still works without ONLY)" "alpha-src,gamma-src" "$(sort "$SB/ran" | paste -sd, -)"
}

case_run_tests_only_beats_skip() {
    ext_dirs alpha-src beta-src
    run_tests ONLY=beta-src SKIP=beta-src
    eq "exit status" 0 "$RC"
    eq "an explicit ONLY entry runs even if SKIP lists it" "beta-src" "$(ran)"
}

case_run_tests_only_unknown() {
    ext_dirs alpha-src beta-src
    run_tests ONLY=alpha-src,nope-src SKIP=
    [[ "$RC" -ne 0 ]] || die_case "exit status 0 for an ONLY entry that is not a directory"
    eq "nothing runs when ONLY names a missing directory" "" "$(ran)"
}

# ---------------------------------------------------------------------------------------------
# Removals

case_removed_names_grep() {
    local hits
    hits="$(cd "$ROOT" && grep -rIn "mooncake\|pgrag\|pgjwt\|tiktoken\|rag_bge\|rag_jina\|onnx" . \
        --exclude-dir=vendor --exclude-dir=target --exclude-dir=.git --exclude-dir=.ci-local \
        --exclude="$SELF" | cut -c1-110 || true)"
    [[ -z "$hits" ]] || die_case "$(wc -l <<<"$hits" | tr -d ' ') hits, in $(cut -d: -f1 <<<"$hits" | sort -u | wc -l | tr -d ' ') files; first:
$(head -8 <<<"$hits")"
}

case_removed_paths() {
    local p found=""
    for p in docker-compose/ext-src/pgjwt-src docker-compose/ext-src/pgrag-src \
        docker-compose/ext-src/pg_tiktoken-src docker-compose/ext-src/rag_bge_small_en_v15-src \
        docker-compose/ext-src/rag_jina_reranker_v1_tiny_en-src \
        compute/patches/onnxruntime.patch compute/patches/duckdb_v113.patch; do
        [[ ! -e "$ROOT/$p" ]] || found="$found $p"
    done
    [[ -z "$found" ]] || die_case "still present:$found"
}

dockerfile="$ROOT/compute/compute-node.Dockerfile"

case_old_pgx_ulid_gone_pgrx12_kept() {
    ! grep -qE '^FROM .* AS pgx_ulid-(src|build)$' "$dockerfile" || die_case "the v14-v16 pgx_ulid stages (pgx_ulid-src / pgx_ulid-build) remain"
    ! grep -q -- '--from=pgx_ulid-build ' "$dockerfile" || die_case "a COPY --from=pgx_ulid-build remains"
    # SP14: the v17 build is X1's and must survive X0.
    grep -qE '^FROM .* AS pgx_ulid-pgrx12-src$' "$dockerfile" || die_case "pgx_ulid-pgrx12-src was removed (SP14)"
    grep -qE '^FROM .* AS pgx_ulid-pgrx12-build$' "$dockerfile" || die_case "pgx_ulid-pgrx12-build was removed (SP14)"
    grep -q -- '--from=pgx_ulid-pgrx12-build ' "$dockerfile" || die_case "the extensions-all COPY of pgx_ulid-pgrx12-build was removed (SP14)"
}

case_extensions_minimal_stage() {
    local copies
    copies="$(awk '/^FROM .* AS extensions-minimal$/ {on=1; next} /^FROM / {on=0} on && /^COPY --from=/ {split($2, a, "="); print a[2]}' "$dockerfile" | sort | paste -sd, -)"
    eq "extensions-minimal stages" "pg_cron-build,pg_partman-build,timescaledb-build" "$copies"
}

case_extension_tests_stage_kept() {
    grep -qE '^FROM pg-build AS extension-tests$' "$dockerfile" || die_case "the extension-tests stage is gone"
    grep -qE '^COPY docker-compose/ext-src/ /ext-src/$' "$dockerfile" || die_case "the extension-tests stage lost its ext-src COPY"
}

# ---------------------------------------------------------------------------------------------

run_case() {
    local name="$1" out
    n=$((n + 1))
    if out="$("$name" 2>&1)"; then
        echo "ok: $name"
    else
        echo "FAIL: $name"
        sed 's/^/    /' <<<"$out"
        failures=$((failures + 1))
    fi
}

for c in \
    case_wrapper_exists case_usage_errors case_help \
    case_defaults_builds case_defaults_harness case_only_passthrough case_storage_image \
    case_keep_images case_harness_failure case_build_failure \
    case_harness_only case_harness_without_only case_harness_skip_list \
    case_run_tests_only_one case_run_tests_only_two case_run_tests_no_only \
    case_run_tests_only_beats_skip case_run_tests_only_unknown \
    case_removed_names_grep case_removed_paths case_old_pgx_ulid_gone_pgrx12_kept \
    case_extensions_minimal_stage case_extension_tests_stage_kept; do
    run_case "$c"
done

echo "$((n - failures))/$n passed"
[[ "$failures" -eq 0 ]]
