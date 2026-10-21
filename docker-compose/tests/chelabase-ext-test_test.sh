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
#   * X4: `--extensions minimal|all` (default all; any other value is a usage error). The value
#     is the compute build's and the tests build's `--build-arg EXTENSIONS=<value>`. With `all`
#     the tests build targets `extension-tests`; with `minimal` it targets
#     `extension-tests-minimal` (a Dockerfile stage `FROM pg-build` that copies only the
#     `docker-compose/ext-src/{pg_cron,pg_partman,timescaledb}-src` directories, their upstream
#     `*-src` stages, and run-tests.sh; no PostGIS or other stage). Tags, ONLY, --storage-image,
#     --keep-images and the cleanup behave the same for both. `--help` documents the option, and so does every usage error:
#     the usage text contains the literal `[--extensions minimal|all]` on its first line and a
#     `  --extensions ` description line.
#   * X4 ext-src: each of timescaledb-src, pg_partman-src and pg_cron-src has an executable
#     neon-test.sh that fails unless `SELECT extversion FROM pg_extension WHERE extname = ...`
#     is 2.31.0, 5.5.0 and 1.6 (pg_cron's default_version stays 1.6 through v1.6.8, so it also
#     needs the v1.6.8-only GUC cron.match_dom_and_dow). timescaledb-src and pg_partman-src also
#     run a smoke.sql; pg_cron-src then runs `make installcheck`.
#   * X4 harness compute config (docker-compose/compute_wrapper/var/db/postgres/configs/config.json):
#     shared_preload_libraries lists pg_cron and timescaledb, and pg_cron's database is set with
#     its real name `cron.database_name` (the base has the nonexistent `cron.database`).
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
#     (non-zero exit, nothing run). F3: an ONLY entry must match ^[A-Za-z0-9._-]+$ and not be
#     `.` or `..`; otherwise run-tests.sh exits 2 before running anything, even when such a
#     directory exists.
#   * F3: the wrapper's cleanup runs a best-effort `docker compose ... down` of the harness's
#     project (docker-compose/docker-compose.yml, profile test-extensions: by `-f`/`--file`, by
#     COMPOSE_FILE, or from that directory; by `--profile` or COMPOSE_PROFILES) after the harness,
#     pass or fail, with or without --keep-images, before any `docker rmi`; a failing down
#     doesn't change the exit status. `--help` says, in the sentence naming
#     chelabase-local/neon:<tag>, that the retag is removed afterwards.
#   * docker_compose_test.sh: when ONLY is set it passes `-e ONLY=<value>` to the `/ext-src`
#     run-tests.sh exec and does not run the `/postgres/contrib` suite; without ONLY neither
#     changes. The SKIP of the `/ext-src` exec is exactly
#     pg_jsonschema-src,rdkit-src (X4 un-skipped timescaledb-src; X1/X3 un-skip theirs later, P9).
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
    # F3: where each compose call points (cwd, compose env, arguments), separated by \037.
    printf '%s\037%s\037%s\037%s\n' "$(pwd -P)" "${COMPOSE_FILE-}" "${COMPOSE_PROFILES-}" "$*" >>"${FAKE_LOG:?}.compose"
    if [[ "${FAKE_DOCKER_FAIL:-}" == down && " $* " == *" down "* ]]; then exit 1; fi
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
    eq "SKIP list of the /ext-src suite" "pg_jsonschema-src,rdkit-src" "$got"
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

# F3 (X0 hardening): run-tests.sh takes only ONLY entries matching ^[A-Za-z0-9._-]+$, never
# `.` or `..`, even when such a directory exists; a refused entry exits 2 before anything runs.
# A `make` shim logs into the ran file, so a directory without neon-test.sh shows up too.
make_shim_logs_runs() {
    printf '#!/usr/bin/env bash\necho "make $*" >>%s\n' "$SB/ran" >"$SHIMS/make"
    chmod +x "$SHIMS/make"
}

case_run_tests_only_refuses_odd_names() {
    local entry
    for entry in "." ".." "we ird-src" 'a$b-src' "semi;colon-src" "star*-src" "alpha-src,.." \
        "..,alpha-src" "./alpha-src" "alpha-src/"; do
        ext_dirs alpha-src "we ird-src" 'a$b-src' "semi;colon-src" "star*-src"
        make_shim_logs_runs
        run_tests ONLY="$entry" SKIP=
        eq "exit status for ONLY=[$entry]" 2 "$RC"
        eq "nothing runs for ONLY=[$entry]" "" "$(ran)"
    done
}

case_run_tests_only_takes_plain_names() {
    ext_dirs alpha-src a.b_c-1 Z9
    make_shim_logs_runs
    run_tests ONLY=a.b_c-1,Z9 SKIP=
    eq "exit status" 0 "$RC"
    eq "directories run" "Z9,a.b_c-1" "$(LC_ALL=C sort "$SB/ran" | paste -sd, -)"
}

# F3 (X0 hardening): the wrapper's cleanup runs a best-effort `docker compose down` of the
# harness's project (docker-compose/docker-compose.yml with the test-extensions profile) after
# the harness, pass or fail, with or without --keep-images, and before any `docker rmi`.
compose_log() {
    cat "$LOG.compose" 2>/dev/null || true
}

# down_line: the first logged compose call whose arguments include `down`.
down_line() {
    compose_log | awk -F'\037' '{ n = split($4, a, " "); for (i = 1; i <= n; i++) if (a[i] == "down") { print; exit } }'
}

# down_targets_harness <compose log line: cwd, COMPOSE_FILE, COMPOSE_PROFILES, args, \037-separated>
down_targets_harness() {
    local pwd_ file profiles args harness_dir="$CO/docker-compose"
    IFS=$'\037' read -r pwd_ file profiles args <<<"$1"
    local f="$harness_dir/docker-compose.yml" by_file=false by_profile=false
    if [[ " $args " == *" -f $f "* || " $args " == *" --file $f "* || " $args " == *" --file=$f "* ||
        "$file" == "$f" ]]; then
        by_file=true
    elif [[ ("$pwd_" == "$harness_dir" || " $args " == *" --project-directory $harness_dir "*) &&
        ("$file" == "" || "$file" == "docker-compose.yml") ]]; then
        by_file=true
    fi
    if [[ " $args " == *" --profile test-extensions "* || " $args " == *" --profile=test-extensions "* ||
        ",$profiles," == *",test-extensions,"* ]]; then
        by_profile=true
    fi
    $by_file || die_case "the down doesn't use docker-compose/docker-compose.yml: [$1]"
    $by_profile || die_case "the down doesn't select the test-extensions profile: [$1]"
}

line_of() {
    grep -nE "$1" "$LOG" | head -1 | cut -d: -f1
}

case_cleanup_compose_down() {
    need_wrapper
    local rc_case d h r
    for rc_case in 0 3; do
        sandbox "down-$rc_case"
        FAKE_HARNESS_RC=$rc_case run_wrapper --only hll-src
        eq "exit status" "$rc_case" "$RC"
        d="$(down_line)"
        [[ -n "$d" ]] || die_case "no docker compose down after a harness exiting $rc_case: $(cat "$LOG")"
        down_targets_harness "$d"
        h="$(line_of '^HARNESS ')"
        local down_at
        down_at="$(grep -nE '^docker compose .*(^| )down( |$)' "$LOG" | head -1 | cut -d: -f1)"
        [[ -n "$down_at" ]] || die_case "the down isn't in the docker log: $(cat "$LOG")"
        ((down_at > h)) || die_case "the down ran before the harness"
        r="$(line_of '^docker (rmi|image rm) ')"
        [[ -n "$r" ]] || die_case "images not removed: $(cat "$LOG")"
        ((r > down_at)) || die_case "images removed before the containers went down"
    done
    sandbox "down-keep"
    run_wrapper --keep-images kept --only hll-src
    eq "exit status" 0 "$RC"
    d="$(down_line)"
    [[ -n "$d" ]] || die_case "no docker compose down with --keep-images: $(cat "$LOG")"
    down_targets_harness "$d"
    # A down that fails doesn't change the wrapper's exit status (best effort).
    sandbox "down-fails"
    FAKE_DOCKER_FAIL=down run_wrapper --only hll-src
    eq "exit status with a failing down" 0 "$RC"
}

# F3 (X0 hardening): --help says the storage image is retagged as chelabase-local/neon:<tag>
# and that the retag is removed afterwards (in the same sentence).
case_help_mentions_storage_retag_removal() {
    need_wrapper
    sandbox "help-retag"
    run_wrapper --help
    eq "exit status" 0 "$RC"
    local flat re='chelabase-local/neon:<tag>[^.]*[Rr]emov'
    flat="$(tr '\n' ' ' <<<"$OUT")"
    [[ "$flat" =~ $re ]] || die_case "--help doesn't say chelabase-local/neon:<tag> is removed: [$OUT]"
}

# F3 round 2: the cleanup's down also removes orphans (compute2..N of
# docker-compose-parallel.yml, which docker-compose.yml doesn't name).
case_cleanup_down_removes_orphans() {
    need_wrapper
    sandbox "down-orphans"
    run_wrapper --only hll-src
    eq "exit status" 0 "$RC"
    local d
    d="$(grep -E '^docker compose .*(^| )down( |$)' "$LOG" | head -1)"
    [[ -n "$d" ]] || die_case "no docker compose down: $(cat "$LOG")"
    has "the down" "$d" "--remove-orphans"
}

# F3 round 2: --only entries are checked up front like run-tests.sh's ONLY (plain names,
# never `.` or `..`): exit 2 with usage, before any build or harness run.
case_only_refuses_odd_names_before_building() {
    need_wrapper
    local entry
    for entry in "." ".." "a b-src" 'a$b-src' "alpha-src,.." "..,alpha-src" "./alpha-src" \
        "alpha-src/" "alpha-src,,beta-src" ","; do
        sandbox "only-odd"
        run_wrapper --only "$entry"
        eq "exit status for --only [$entry]" 2 "$RC"
        [[ "$ERR" == *[Uu]sage* ]] || die_case "no usage on stderr for --only [$entry]: [$ERR]"
        [[ ! -s "$LOG" ]] || die_case "docker or the harness ran for --only [$entry]: $(cat "$LOG")"
    done
    sandbox "only-plain"
    run_wrapper --only a.b_c-1,Z9
    eq "exit status for plain names" 0 "$RC"
    grep -q '^HARNESS .*ONLY=a.b_c-1,Z9 ' "$LOG" || die_case "plain names not passed: $(cat "$LOG")"
}

# ---------------------------------------------------------------------------------------------
# Removals

case_removed_names_grep() {
    local hits
    hits="$(cd "$ROOT" && grep -rIn "mooncake\|pgrag\|pgjwt\|tiktoken\|rag_bge\|rag_jina\|onnx" . \
        --exclude-dir=vendor --exclude-dir=target --exclude-dir=.git --exclude-dir=.ci-local \
        --exclude="$SELF" --exclude=FORK.md | cut -c1-110 || true)"
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
# X4: --extensions minimal|all and the slim test image

case_extensions_default_is_all() {
    need_wrapper
    sandbox "ext-default"
    run_wrapper
    eq "exit status" 0 "$RC"
    has "compute extensions" "$(compute_build)" "--build-arg EXTENSIONS=all"
    has "tests extensions" "$(tests_build)" "--build-arg EXTENSIONS=all"
    has "tests target" "$(tests_build)" "--target extension-tests"
    lacks "slim target" "$(tests_build)" "--target extension-tests-minimal"
}

case_extensions_all_explicit() {
    need_wrapper
    sandbox "ext-all"
    run_wrapper --extensions all
    eq "exit status (stderr: $ERR)" 0 "$RC"
    eq "number of builds" 2 "$(build_lines | wc -l | tr -d ' ')"
    has "compute extensions" "$(compute_build)" "--build-arg EXTENSIONS=all"
    has "tests extensions" "$(tests_build)" "--build-arg EXTENSIONS=all"
    has "tests target" "$(tests_build)" "--target extension-tests"
    lacks "slim target" "$(tests_build)" "--target extension-tests-minimal"
    has "tests tag" "$(tests_build)" "--tag chelabase-local/neon-test-extensions-v17:ext-test"
}

case_extensions_minimal_builds() {
    need_wrapper
    sandbox "ext-min"
    run_wrapper --extensions minimal
    eq "exit status (stderr: $ERR)" 0 "$RC"
    local c t l
    c="$(compute_build)"
    t="$(tests_build)"
    [[ -n "$c" ]] || die_case "no compute build in: $(cat "$LOG")"
    [[ -n "$t" ]] || die_case "no tests build in: $(cat "$LOG")"
    eq "number of builds" 2 "$(build_lines | wc -l | tr -d ' ')"
    for l in "$c" "$t"; do
        has "file" "$l" "--file $CO/compute/compute-node.Dockerfile"
        has "pg version" "$l" "--build-arg PG_VERSION=v17"
        has "extensions" "$l" "--build-arg EXTENSIONS=minimal"
        lacks "all extensions" "$l" "--build-arg EXTENSIONS=all"
        has "debian" "$l" "--build-arg DEBIAN_VERSION=bookworm"
        has "build tag" "$l" "--build-arg BUILD_TAG=ext-test"
        eq "build context (the checkout root, last argument)" "$CO" "${l##* }"
    done
    has "compute tag" "$c" "--tag chelabase-local/compute-node-v17:ext-test"
    lacks "compute target" "$c" "--target extension-tests-minimal"
    has "tests target" "$t" "--target extension-tests-minimal"
    lacks "full tests target" "$t" "--target extension-tests"
    has "tests tag" "$t" "--tag chelabase-local/neon-test-extensions-v17:ext-test"
}

case_extensions_minimal_harness_and_cleanup() {
    need_wrapper
    sandbox "ext-min2"
    run_wrapper --extensions minimal --only pg_cron-src,timescaledb-src
    eq "exit status" 0 "$RC"
    local h
    h="$(harness_line)"
    has "pg version" "$h" "TEST_VERSION_ONLY=17"
    has "ONLY" "$h" "ONLY=pg_cron-src,timescaledb-src"
    has "tag" "$h" "TAG=ext-test"
    local last
    last="$(grep -nE '^(HARNESS|docker (buildx )?build )' "$LOG" | tail -1)"
    [[ "$last" == *HARNESS* ]] || die_case "the harness did not run after both builds"
    grep -E '^docker (rmi|image rm) ' "$LOG" | grep -qF "compute-node-v17:ext-test" ||
        die_case "compute image not removed: $(cat "$LOG")"
    grep -E '^docker (rmi|image rm) ' "$LOG" | grep -qF "neon-test-extensions-v17:ext-test" ||
        die_case "test image not removed: $(cat "$LOG")"
}

case_extensions_minimal_with_keep_and_storage() {
    need_wrapper
    sandbox "ext-min3"
    # The option may come anywhere among the flags.
    run_wrapper --keep-images round4-min --extensions minimal --storage-image some/storage:1
    eq "exit status (stderr: $ERR)" 0 "$RC"
    has "compute tag" "$(compute_build)" "--tag chelabase-local/compute-node-v17:round4-min"
    has "compute extensions" "$(compute_build)" "--build-arg EXTENSIONS=minimal"
    has "tests tag" "$(tests_build)" "--tag chelabase-local/neon-test-extensions-v17:round4-min"
    has "tests target" "$(tests_build)" "--target extension-tests-minimal"
    has "tests build tag" "$(tests_build)" "--build-arg BUILD_TAG=round4-min"
    has "harness tag" "$(harness_line)" "TAG=round4-min"
    eq "storage tag" "docker tag some/storage:1 chelabase-local/neon:round4-min" "$(grep -E '^docker tag ' "$LOG" | head -1)"
    ! grep -qE '^docker (rmi|image rm|image prune|system prune|builder prune)' "$LOG" ||
        die_case "images removed despite --keep-images: $(cat "$LOG")"
}

case_extensions_minimal_build_failure() {
    need_wrapper
    sandbox "ext-min-fail"
    FAKE_DOCKER_FAIL=build run_wrapper --extensions minimal
    [[ "$RC" -ne 0 ]] || die_case "exit status 0 after a failed build"
    ! grep -q '^HARNESS ' "$LOG" || die_case "the harness ran after a failed build"
    grep -E '^docker (buildx )?build ' "$LOG" | grep -qF -- "EXTENSIONS=minimal" ||
        die_case "no minimal build was attempted: $(cat "$LOG")"
}

case_extensions_usage_errors() {
    need_wrapper
    local args
    for args in "--extensions" "--extensions bogus" "--extensions Minimal" "--extensions ALL" \
        "--extensions --only a" "--extensions=minimal" "--extensions minimal,all" "--extensions mini"; do
        sandbox "ext-usage"
        # shellcheck disable=SC2086
        run_wrapper $args
        eq "exit status for [$args]" 2 "$RC"
        [[ "$ERR" == *[Uu]sage* ]] || die_case "no usage on stderr for [$args]: [$ERR]"
        # The usage text names the option's values (the base rejects --extensions as an unknown flag).
        [[ "$ERR" == *"--extensions minimal|all"* ]] || die_case "usage for [$args] does not document '--extensions minimal|all': [$ERR]"
        [[ ! -s "$LOG" ]] || die_case "docker or the harness ran for [$args]: $(cat "$LOG")"
    done
    sandbox "ext-usage-empty"
    run_wrapper --extensions ""
    eq "exit status for an empty --extensions" 2 "$RC"
    [[ "$ERR" == *"--extensions minimal|all"* ]] || die_case "usage for an empty --extensions does not document it: [$ERR]"
    [[ ! -s "$LOG" ]] || die_case "docker ran for an empty --extensions"
}

case_help_mentions_extensions() {
    need_wrapper
    sandbox "ext-help"
    run_wrapper --help
    eq "exit status" 0 "$RC"
    has "usage line" "$(grep -i '^usage' <<<"$OUT" | head -1)" "[--extensions minimal|all]"
    grep -qE '^ +--extensions ' <<<"$OUT" || die_case "no --extensions description in the help: [$OUT]"
}

# The slim stage: only the three minimal extensions' directories and sources.
extension_tests_minimal_copies() {
    awk '/^FROM .* AS extension-tests-minimal$/ {on=1; next} /^FROM / {on=0} on && /^COPY / {print}' "$dockerfile"
}

case_extension_tests_minimal_stage() {
    grep -qE '^FROM pg-build AS extension-tests-minimal$' "$dockerfile" ||
        die_case "no 'FROM pg-build AS extension-tests-minimal' stage"
    local copies froms dirs
    copies="$(extension_tests_minimal_copies)"
    [[ -n "$copies" ]] || die_case "the stage has no COPY lines"
    # COPY --from=<stage> sources, minus pg-build (the base).
    froms="$(grep -oE -- '--from=[A-Za-z0-9_.-]+' <<<"$copies" | cut -d= -f2 | grep -vx pg-build | sort -u | paste -sd, -)"
    eq "upstream source stages copied into extension-tests-minimal" "pg_cron-src,pg_partman-src,timescaledb-src" "$froms"
    # COPY docker-compose/ext-src/<dir>/ ... : exactly the three directories, never the whole tree.
    dirs="$(grep -oE 'docker-compose/ext-src/[A-Za-z0-9_.-]*/?' <<<"$copies" | sed 's|docker-compose/ext-src/||; s|/$||' | sort -u | paste -sd, -)"
    eq "docker-compose/ext-src directories copied into extension-tests-minimal" "pg_cron-src,pg_partman-src,timescaledb-src" "$dirs"
    ! grep -qE 'COPY docker-compose/ext-src/ ' <<<"$copies" || die_case "the stage copies the whole ext-src tree"
    grep -qF 'docker-compose/run-tests.sh /run-tests.sh' <<<"$copies" || die_case "the stage does not copy run-tests.sh"
    # None of the heavy stages.
    ! grep -qE 'postgis|plv8|sfcgal|pgrouting|h3-pg|rdkit|duckdb|pg_repack' <<<"$copies" ||
        die_case "the stage copies a heavy extension: $(grep -E 'postgis|plv8|sfcgal|pgrouting|h3-pg|rdkit|duckdb|pg_repack' <<<"$copies")"
}

case_extension_tests_full_stage_unchanged() {
    grep -qE '^FROM pg-build AS extension-tests$' "$dockerfile" || die_case "the extension-tests stage is gone"
    grep -qE '^COPY docker-compose/ext-src/ /ext-src/$' "$dockerfile" || die_case "extension-tests lost its ext-src COPY"
    local full
    full="$(awk '/^FROM .* AS extension-tests$/ {on=1; next} /^FROM / {on=0} on' "$dockerfile")"
    grep -qF -- '--from=postgis-build' <<<"$full" || die_case "extension-tests no longer copies postgis-build"
}

# ---------------------------------------------------------------------------------------------
# X4: the three ext-src version tests

# ext_shims <dir>: PATH shims for psql, dropdb, createdb and make. `psql` logs its arguments (and
# stdin, which is empty) and answers the version query with $FAKE_EXTVERSION and the pg_settings
# query with $FAKE_GUC_COUNT (default 1); every other call succeeds.
ext_shims() {
    local d="$1"
    mkdir -p "$d"
    cat >"$d/psql" <<'EOF'
#!/usr/bin/env bash
printf 'psql %s\n' "$*" >>"${FAKE_LOG:?}"
case "$*" in
*extversion*) echo "${FAKE_EXTVERSION:-}" ;;
*pg_settings*) echo "${FAKE_GUC_COUNT:-1}" ;;
esac
exit "${FAKE_PSQL_RC:-0}"
EOF
    for t in dropdb createdb make; do
        printf '#!/usr/bin/env bash\nprintf "%s %%s\\n" "$*" >>"${FAKE_LOG:?}"\nexit 0\n' "$t" >"$d/$t"
    done
    chmod +x "$d"/*
}

# run_ext_test <dir> <extversion> [guc count]: runs <dir>/neon-test.sh with the shims.
run_ext_test() {
    local dir="$1" ver="$2" guc="${3:-1}"
    local sb="$tmp/ext-test"
    rm -rf "$sb"
    mkdir -p "$sb"
    : >"$sb/log"
    ext_shims "$sb/shims"
    RC=0
    FAKE_LOG="$sb/log" FAKE_EXTVERSION="$ver" FAKE_GUC_COUNT="$guc" PATH="$sb/shims:$PATH" \
        bash "$ROOT/docker-compose/ext-src/$dir/neon-test.sh" >"$sb/out" 2>"$sb/err" </dev/null || RC=$?
    ERR="$(cat "$sb/err")"
    EXT_LOG="$(cat "$sb/log")"
}

case_ext_src_version_scripts_exist() {
    local d
    for d in timescaledb-src pg_partman-src pg_cron-src; do
        [[ -f "$ROOT/docker-compose/ext-src/$d/neon-test.sh" ]] || die_case "docker-compose/ext-src/$d/neon-test.sh does not exist"
        [[ -x "$ROOT/docker-compose/ext-src/$d/neon-test.sh" ]] || die_case "$d/neon-test.sh is not executable"
        bash -n "$ROOT/docker-compose/ext-src/$d/neon-test.sh" || die_case "$d/neon-test.sh: syntax error"
    done
    for d in timescaledb-src pg_partman-src; do
        [[ -s "$ROOT/docker-compose/ext-src/$d/smoke.sql" ]] || die_case "$d/smoke.sql does not exist or is empty"
    done
    # The version queries are the pinned form.
    grep -qF "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'" "$ROOT/docker-compose/ext-src/timescaledb-src/neon-test.sh" ||
        die_case "timescaledb-src does not query extversion"
    grep -qF "SELECT extversion FROM pg_extension WHERE extname = 'pg_partman'" "$ROOT/docker-compose/ext-src/pg_partman-src/neon-test.sh" ||
        die_case "pg_partman-src does not query extversion"
    grep -qF "SELECT extversion FROM pg_extension WHERE extname = 'pg_cron'" "$ROOT/docker-compose/ext-src/pg_cron-src/neon-test.sh" ||
        die_case "pg_cron-src does not query extversion"
}

case_ext_src_timescaledb_version() {
    [[ -f "$ROOT/docker-compose/ext-src/timescaledb-src/neon-test.sh" ]] || die_case "timescaledb-src/neon-test.sh does not exist"
    run_ext_test timescaledb-src 2.31.0
    eq "exit status at 2.31.0 (stderr: $ERR)" 0 "$RC"
    grep -q 'smoke.sql' <<<"$EXT_LOG" || die_case "the smoke test did not run: $EXT_LOG"
    for v in 2.17.1 2.30.2 2.31.1 "" 2.31; do
        run_ext_test timescaledb-src "$v"
        [[ "$RC" -ne 0 ]] || die_case "timescaledb-src passed with extversion [$v]"
        ! grep -q 'smoke.sql' <<<"$EXT_LOG" || die_case "the smoke test ran after a wrong version [$v]"
    done
}

case_ext_src_pg_partman_version() {
    [[ -f "$ROOT/docker-compose/ext-src/pg_partman-src/neon-test.sh" ]] || die_case "pg_partman-src/neon-test.sh does not exist"
    run_ext_test pg_partman-src 5.5.0
    eq "exit status at 5.5.0 (stderr: $ERR)" 0 "$RC"
    grep -q 'smoke.sql' <<<"$EXT_LOG" || die_case "the smoke test did not run: $EXT_LOG"
    for v in 5.1.0 5.4.0 5.5.1 "" 5.5; do
        run_ext_test pg_partman-src "$v"
        [[ "$RC" -ne 0 ]] || die_case "pg_partman-src passed with extversion [$v]"
        ! grep -q 'smoke.sql' <<<"$EXT_LOG" || die_case "the smoke test ran after a wrong version [$v]"
    done
}

case_ext_src_pg_cron_version() {
    [[ -f "$ROOT/docker-compose/ext-src/pg_cron-src/neon-test.sh" ]] || die_case "pg_cron-src/neon-test.sh does not exist"
    run_ext_test pg_cron-src 1.6 1
    eq "exit status at 1.6 with the v1.6.8 GUC (stderr: $ERR)" 0 "$RC"
    grep -q '^make .*installcheck' <<<"$EXT_LOG" || die_case "make installcheck did not run: $EXT_LOG"
    # v1.6.4 also reports 1.6: the missing cron.match_dom_and_dow is what fails.
    run_ext_test pg_cron-src 1.6 0
    [[ "$RC" -ne 0 ]] || die_case "pg_cron-src passed without cron.match_dom_and_dow"
    ! grep -q '^make ' <<<"$EXT_LOG" || die_case "installcheck ran after a failed GUC check"
    for v in 1.5 1.7 1.6.8 ""; do
        run_ext_test pg_cron-src "$v" 1
        [[ "$RC" -ne 0 ]] || die_case "pg_cron-src passed with extversion [$v]"
    done
}

# ---------------------------------------------------------------------------------------------
# X4: the harness compute's configuration

harness_config="$ROOT/docker-compose/compute_wrapper/var/db/postgres/configs/config.json"

case_harness_compute_config() {
    local spl
    spl="$(grep -A1 '"name": "shared_preload_libraries"' "$harness_config" | grep '"value"')"
    [[ -n "$spl" ]] || die_case "no shared_preload_libraries setting in $harness_config"
    has "shared_preload_libraries has pg_cron" "$(tr ',"' '  ' <<<"$spl")" "pg_cron"
    has "shared_preload_libraries has timescaledb" "$(tr ',"' '  ' <<<"$spl")" "timescaledb"
    grep -qF '"name": "cron.database_name"' "$harness_config" ||
        die_case "pg_cron's database is not set through cron.database_name"
    ! grep -qE '"name": "cron\.database"' "$harness_config" ||
        die_case "the nonexistent setting cron.database is still there"
    # pg_partman's background worker stays off this round (spec 17.4): not preloaded.
    ! grep -q 'pg_partman_bgw' "$harness_config" || die_case "pg_partman_bgw must not be preloaded in this round"
}

# ---------------------------------------------------------------------------------------------

case_harness_compose_has_no_minio() {
    local f="$ROOT/docker-compose/docker-compose.yml"
    ! grep -qiE '^[[:space:]]*image:.*minio' "$f" || die_case "docker-compose.yml still uses a minio image (not pullable)"
    grep -qE '^[[:space:]]*image:[[:space:]]*chrislusf/seaweedfs:4\.47@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882$' "$f" ||
        die_case "docker-compose.yml does not use the pinned SeaweedFS image"
    ! grep -rq 'minio:9000' "$ROOT/docker-compose" --include=*.yml --include=*.toml --include=*.json ||
        die_case "a config still points at the minio endpoint"
}

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
    case_extensions_minimal_stage case_extension_tests_stage_kept \
    case_extensions_default_is_all case_extensions_all_explicit case_extensions_minimal_builds \
    case_extensions_minimal_harness_and_cleanup case_extensions_minimal_with_keep_and_storage \
    case_extensions_minimal_build_failure case_extensions_usage_errors case_help_mentions_extensions \
    case_extension_tests_minimal_stage case_extension_tests_full_stage_unchanged \
    case_ext_src_version_scripts_exist case_ext_src_timescaledb_version case_ext_src_pg_partman_version \
    case_ext_src_pg_cron_version case_harness_compute_config case_harness_compose_has_no_minio \
    case_run_tests_only_refuses_odd_names case_run_tests_only_takes_plain_names \
    case_cleanup_compose_down case_help_mentions_storage_retag_removal \
    case_cleanup_down_removes_orphans case_only_refuses_odd_names_before_building; do
    run_case "$c"
done

echo "$((n - failures))/$n passed"
[[ "$failures" -eq 0 ]]
