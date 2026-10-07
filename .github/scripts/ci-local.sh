#!/usr/bin/env bash
# Runs the checks of .github/workflows/pr.yml on this machine, inside the same
# build-tools image the workflow uses, so a PR can be checked without GitHub CI.
#
#   .github/scripts/ci-local.sh [--pg v14|v15|v16|v17] [--build-type release|debug]
#                               [--regress [-k <pytest expr>] [-n <workers>]]
#                               [--only build,rust-tests,regress [--test-filter <nextest expr>]]
#
# The default run (lint + build + rust-tests) is the gate for every PR. Neon's
# regression suite is opt-in: use --regress for a targeted run (for example to
# debug one test with -k); it is required for no PR.
#
#   --pg          Postgres major the build (and --regress) use (default v17)
#   --build-type  release (default) or debug
#   --regress     also run Neon's pytest regression suite (opt-in)
#   -k EXPR       pytest -k expression (needs --regress)
#   -n N          pytest-xdist workers (needs --regress; default 6)
#   --only STEPS  comma list of build, rust-tests, regress: run just those, in
#                 pipeline order, skipping lint (regress implies --regress)
#   --test-filter EXPR  cargo nextest -E filter, ANDed with the quarantine
#                 (needs --only with rust-tests)
#
# Env CHELA_NEON_VOLUME_SUFFIX=<suffix> (^[a-z0-9-]+$) uses the volumes
# chela-neon-cargo-<suffix> and chela-neon-target-<suffix>, so parallel clones
# don't share build state.
#
# Steps (each in its own `docker run --rm` of the build-tools image, as the
# image's `nonroot` user, mirroring pr.yml's jobs and commands):
#   lint        self-tests, actionlint, cargo fmt, clippy, cargo deny (advisories,
#               bans, licenses, sources; all blocking, as in pr.yml), ruff, mypy
#   build       Postgres <pg> + extensions + Rust binaries (`make ... all`)
#   rust-tests  Postgres v14-v17 + extensions, cargo test --doc, cargo nextest
#   regress     (only with --regress) pytest test_runner/regress in one process with -n <workers> and
#               --reruns 2, deselecting test_runner/known_failures.txt and
#               test_runner/known_failures.local.txt
#
# Caches live in two named Docker volumes: chela-neon-cargo (cargo registry and
# git, poetry venvs) and chela-neon-target (target/, pg_install/, build/ of the
# checkout). No `--network host`: the test ports stay inside the container, so
# they never clash with the chelabase Compose stack.
#
# The full log and one log per step go to .ci-local/<timestamp>/ (git-ignored),
# with the regression suite's logs in test-logs.tar.zst. The exit status is
# non-zero when any step failed.
#
# Requires `docker login ghcr.io` (the build-tools package is private). The
# checkout must be a normal clone (not a `git worktree`): its .git is mounted.

IMAGE_REPO="ghcr.io/chelabase/neon-build-tools"
CARGO_VOLUME="chela-neon-cargo"
TARGET_VOLUME="chela-neon-target"
MAJORS=(v14 v15 v16 v17)

usage() {
    sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

# parse_args <args...>: sets PG, BUILD_TYPE, REGRESS, KEXPR, WORKERS.
parse_args() {
    PG=v17
    BUILD_TYPE=release
    REGRESS=0
    KEXPR=""
    WORKERS=6
    ONLY_STEPS=()
    TEST_FILTER=""
    local k_given=0 n_given=0
    while (($# > 0)); do
        case "$1" in
        --pg)
            [[ $# -ge 2 ]] || { echo "ci-local.sh: --pg needs a value" >&2; return 1; }
            case "$2" in
            v14 | v15 | v16 | v17) PG="$2" ;;
            *) echo "ci-local.sh: --pg must be v14, v15, v16 or v17, not '$2'" >&2; return 1 ;;
            esac
            shift 2
            ;;
        --build-type)
            [[ $# -ge 2 ]] || { echo "ci-local.sh: --build-type needs a value" >&2; return 1; }
            case "$2" in
            release | debug) BUILD_TYPE="$2" ;;
            *) echo "ci-local.sh: --build-type must be release or debug, not '$2'" >&2; return 1 ;;
            esac
            shift 2
            ;;
        --regress)
            REGRESS=1
            shift
            ;;
        -k)
            [[ $# -ge 2 ]] || { echo "ci-local.sh: -k needs a value" >&2; return 1; }
            KEXPR="$2"
            k_given=1
            shift 2
            ;;
        -n)
            [[ $# -ge 2 ]] || { echo "ci-local.sh: -n needs a value" >&2; return 1; }
            [[ "$2" =~ ^[1-9][0-9]*$ ]] || { echo "ci-local.sh: -n must be a positive integer, not '$2'" >&2; return 1; }
            WORKERS="$2"
            n_given=1
            shift 2
            ;;
        --only)
            [[ $# -ge 2 ]] || { echo "ci-local.sh: --only needs a value" >&2; return 1; }
            local s
            ONLY_STEPS=()
            IFS=, read -r -a ONLY_STEPS <<<"$2"
            ((${#ONLY_STEPS[@]} > 0)) || { echo "ci-local.sh: --only needs at least one step" >&2; return 1; }
            for s in "${ONLY_STEPS[@]}"; do
                case "$s" in
                build | rust-tests) ;;
                regress) REGRESS=1 ;;
                *) echo "ci-local.sh: --only steps are build, rust-tests, regress; not '$s'" >&2; return 1 ;;
                esac
            done
            shift 2
            ;;
        --test-filter)
            [[ $# -ge 2 ]] || { echo "ci-local.sh: --test-filter needs a value" >&2; return 1; }
            [[ -n "$2" ]] || { echo "ci-local.sh: --test-filter needs a non-empty expression" >&2; return 1; }
            TEST_FILTER="$2"
            shift 2
            ;;
        -h | --help)
            usage
            return 2
            ;;
        *)
            echo "ci-local.sh: unknown argument '$1'" >&2
            return 1
            ;;
        esac
    done
    if ((REGRESS == 0 && (k_given || n_given))); then
        echo "ci-local.sh: -k and -n only apply with --regress" >&2
        return 1
    fi
    if [[ -n "$TEST_FILTER" ]]; then
        local s found=0
        for s in "${ONLY_STEPS[@]}"; do [[ "$s" == rust-tests ]] && found=1; done
        ((found)) || { echo "ci-local.sh: --test-filter needs --only with rust-tests" >&2; return 1; }
    fi
}

# selected_steps: the steps to run, in pipeline order, one per line.
selected_steps() {
    local s
    if ((${#ONLY_STEPS[@]} > 0)); then
        for s in build rust-tests regress; do
            case " ${ONLY_STEPS[*]} " in *" $s "*) echo "$s" ;; esac
        done
        return 0
    fi
    echo lint
    echo build
    echo rust-tests
    ((REGRESS == 1)) && echo regress
    return 0
}

# init_volumes: sets CARGO_VOLUME and TARGET_VOLUME from CHELA_NEON_VOLUME_SUFFIX
# (unset: the plain names, so a clone without it shares the original pair).
init_volumes() {
    CARGO_VOLUME="chela-neon-cargo"
    TARGET_VOLUME="chela-neon-target"
    if [[ -v CHELA_NEON_VOLUME_SUFFIX ]]; then
        if [[ ! "$CHELA_NEON_VOLUME_SUFFIX" =~ ^[a-z0-9-]+$ ]]; then
            echo "ci-local.sh: CHELA_NEON_VOLUME_SUFFIX must match ^[a-z0-9-]+\$, not '$CHELA_NEON_VOLUME_SUFFIX'" >&2
            return 1
        fi
        CARGO_VOLUME="chela-neon-cargo-$CHELA_NEON_VOLUME_SUFFIX"
        TARGET_VOLUME="chela-neon-target-$CHELA_NEON_VOLUME_SUFFIX"
    fi
}

# nextest_expr: the -E filter of the rust-tests step (TEST_FILTER narrows it).
nextest_expr() {
    local base='not (package(remote_storage) and binary(test_real_gcs))'
    if [[ -n "${TEST_FILTER:-}" ]]; then
        echo "($base) and ($TEST_FILTER)"
    else
        echo "$base"
    fi
}

# image_name <repo root>: computed exactly as pr.yml and build-tools.yml do.
image_name() {
    echo "${IMAGE_REPO}:$(sha256sum "$1/build-tools/Dockerfile" | cut -c1-12)"
}

# build_versions <pg>: POSTGRES_VERSIONS for the build step. walproposer-lib
# (built by `make all`) always uses v17 (Makefile: `walproposer-lib:
# neon-pg-ext-v17`), so v17 stays in the list for a v14-v16 build.
build_versions() {
    if [[ "$1" == "v17" ]]; then echo "v17"; else echo "$1 v17"; fi
}

# docker_args <repo root> <pg> <build type> <step> [run dir name]: the `docker run`
# options (one per line) shared by every step.
docker_args() {
    local root="$1" pg="$2" bt="$3" step="$4" run="${5:-run}"
    # seccomp=unconfined is for io_uring; lint doesn't need it.
    local seccomp=(--security-opt seccomp=unconfined)
    [[ "$step" == lint ]] && seccomp=(--label chela-neon-ci=lint)
    local vol_c="type=volume,src=${CARGO_VOLUME}" vol_t="type=volume,src=${TARGET_VOLUME}"
    printf '%s\n' \
        --rm --init \
        --name "chela-neon-ci-${step}-$$" \
        --user 1000:1000 \
        --shm-size=512mb \
        --ulimit memlock=67108864:67108864 \
        "${seccomp[@]}" \
        -v "$root:/work" -w /work \
        --mount "${vol_c},dst=/home/nonroot/.cargo/registry,volume-subpath=registry" \
        --mount "${vol_c},dst=/home/nonroot/.cargo/git,volume-subpath=git" \
        --mount "${vol_c},dst=/home/nonroot/poetry-cache,volume-subpath=poetry" \
        --mount "${vol_t},dst=/work/target,volume-subpath=target" \
        --mount "${vol_t},dst=/work/pg_install,volume-subpath=pg_install" \
        --mount "${vol_t},dst=/work/build,volume-subpath=build" \
        -e "PG_VERSION=$pg" \
        -e "BUILD_TYPE=$bt" \
        -e "CI_LOCAL_RUN=$run" \
        -e "WORKERS=${WORKERS:-6}" \
        -e "KEXPR=${KEXPR:-}" \
        -e "TEST_FILTER=${TEST_FILTER:-}" \
        -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e 'GIT_CONFIG_VALUE_0=*'
}

# ---------------------------------------------------------------------------
# Steps that run inside the container (`ci-local.sh --inside <step>`).
# The environment mirrors the `env` block of pr.yml.
# ---------------------------------------------------------------------------

inside_env() {
    export CARGO_FLAGS="--locked --features testing"
    export CARGO_HOME=/home/nonroot/.cargo
    export CARGO_TERM_COLOR=never
    export RUST_BACKTRACE=1
    export COPT=-Werror
    export POETRY_CACHE_DIR=/home/nonroot/poetry-cache
    RELEASE_FLAG=""
    [[ "$BUILD_TYPE" == "release" ]] && RELEASE_FLAG="--release"
    return 0
}

FAILED_CHECKS=()

# check <name> <command...>: runs it, records a failure, carries on (as pr.yml's
# `if: !cancelled()` steps do).
check() {
    local name="$1"
    shift
    echo
    echo "=== lint: $name"
    if "$@"; then
        echo "--- lint: $name: ok"
    else
        echo "--- lint: $name: FAILED"
        FAILED_CHECKS+=("$name")
    fi
}

lint_clippy() {
    local args
    args="$(source .neon_clippy_args; echo "$CLIPPY_COMMON_ARGS")"
    # shellcheck disable=SC2086
    cargo clippy --features testing $args
}

lint_actionlint() {
    local v=1.7.12 sha=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
    curl -sSfL -o /tmp/actionlint.tar.gz \
        "https://github.com/rhysd/actionlint/releases/download/v${v}/actionlint_${v}_linux_amd64.tar.gz" &&
        echo "${sha}  /tmp/actionlint.tar.gz" | sha256sum --check &&
        tar -xzf /tmp/actionlint.tar.gz -C /tmp actionlint &&
        /tmp/actionlint
}

lint_ruff_mypy() {
    poetry run ruff check . && poetry run ruff format --check . && poetry run mypy .
}

step_lint() {
    check "known_failures.sh self-test" .github/scripts/known_failures_test.sh
    check "advisory_issue.sh self-test" .github/scripts/advisory_issue_test.sh
    check "ci-local.sh self-test" .github/scripts/ci-local_test.sh
    check "publish-dev.sh self-test" .github/scripts/publish-dev_test.sh
    check "check_tag_free.sh self-test" .github/scripts/check_tag_free_test.sh
    check "actionlint" lint_actionlint
    check "cargo fmt" cargo fmt --all -- --check
    check "postgres headers" make -j"$(nproc)" postgres-headers
    check "cargo clippy" lint_clippy
    check "cargo deny (advisories, bans, licenses, sources)" cargo deny check --hide-inclusion-graph
    check "python deps" ./scripts/pysync
    check "ruff and mypy" lint_ruff_mypy
    echo
    if ((${#FAILED_CHECKS[@]} > 0)); then
        printf 'lint: failed: %s\n' "${FAILED_CHECKS[@]}"
        return 1
    fi
    echo "lint: all checks passed"
}

step_build() {
    local start v
    start=$(date +%s)
    df -h /work /work/target
    # postgres_ffi generates bindings for every major, so it needs all headers.
    local others=()
    for v in "${MAJORS[@]}"; do
        [[ "$v" == "$PG_VERSION" ]] || others+=("postgres-headers-install-$v")
    done
    make -j"$(nproc)" "${others[@]}"
    # shellcheck disable=SC2086
    mold -run make -j"$(nproc)" POSTGRES_VERSIONS="$(build_versions "$PG_VERSION")" \
        BUILD_TYPE="$BUILD_TYPE" CARGO_BUILD_FLAGS="$CARGO_FLAGS" all
    df -h /work /work/target
    du -sh target pg_install build 2>/dev/null || true
    echo "build took $(($(date +%s) - start))s"
}

step_rust_tests() {
    local start
    start=$(date +%s)
    # The unit tests (postgres_ffi's wal_craft, the pageserver's walredo) start
    # Postgres of every major, so this builds v14-v17.
    # shellcheck disable=SC2086
    mold -run make -j"$(nproc)" BUILD_TYPE="$BUILD_TYPE" CARGO_BUILD_FLAGS="$CARGO_FLAGS" \
        postgres-install neon-pg-ext walproposer-lib
    echo "postgres build took $(($(date +%s) - start))s"
    start=$(date +%s)
    export NEXTEST_RETRIES=3
    export LD_LIBRARY_PATH="$PWD/pg_install/$PG_VERSION/lib"
    # shellcheck disable=SC2086
    mold -run cargo test --doc $CARGO_FLAGS $RELEASE_FLAG
    # Quarantined Rust tests, each with its reason:
    # - binary(test_real_gcs): needs a real GCS bucket (GCS_TEST_BUCKET); unlike
    #   the S3 and Azure suites it doesn't skip itself when unconfigured.
    # shellcheck disable=SC2086
    mold -run cargo nextest run $CARGO_FLAGS $RELEASE_FLAG --no-fail-fast \
        -E "$(nextest_expr)"
    echo "rust tests took $(($(date +%s) - start))s"
}

collect_test_logs() {
    [[ -d "$TEST_OUTPUT" ]] || return 0
    local out=".ci-local/$CI_LOCAL_RUN/test-logs.tar.zst"
    (cd "$TEST_OUTPUT" &&
        find . \( -name '*.log' -o -name '*.diffs' -o -name 'junit.xml' -o -name '*.stderr' -o -name '*.stdout' \) \
            -size -50M -print0 | tar --null -T - -I 'zstd -T0 -3' -cf "/work/$out") || true
    ls -lh "/work/$out" || true
}

step_regress() {
    local start rc=0
    export NEON_BIN="$PWD/target/$BUILD_TYPE"
    export POSTGRES_DISTRIB_DIR="$PWD/pg_install"
    export TEST_OUTPUT=/tmp/test_output
    export PAGESERVER_VIRTUAL_FILE_IO_ENGINE=tokio-epoll-uring
    export PLATFORM=ci-local
    export DEFAULT_PG_VERSION="${PG_VERSION#v}"
    export LD_LIBRARY_PATH="$POSTGRES_DISTRIB_DIR/$PG_VERSION/lib"
    ./scripts/pysync

    # Checked separately: `mapfile < <(...)` would swallow the script's exit status.
    local list=/tmp/known_failures.args deselect
    .github/scripts/known_failures.sh test_runner/known_failures.txt test_runner/known_failures.local.txt >"$list"
    mapfile -t deselect <"$list"
    echo "deselecting $((${#deselect[@]} / 2)) quarantined test(s)"

    local extra=()
    [[ -n "${KEXPR:-}" ]] && extra=(-k "$KEXPR")
    trap collect_test_logs EXIT
    start=$(date +%s)
    # One process with -n <workers>: no --splits, no .test_durations.
    ./scripts/pytest test_runner/regress \
        -n "$WORKERS" --dist=loadgroup \
        --reruns 2 \
        --session-timeout=14400 \
        --tb=short --verbose -rA \
        --junitxml="$TEST_OUTPUT/junit.xml" \
        "${extra[@]}" \
        "${deselect[@]}" || rc=$?
    echo "pytest took $(($(date +%s) - start))s"
    return $rc
}

# ---------------------------------------------------------------------------
# Host side.
# ---------------------------------------------------------------------------

fmt_time() {
    printf '%dm%02ds' $(($1 / 60)) $(($1 % 60))
}

STEP_NAMES=()
STEP_RESULTS=()
STEP_TIMES=()
CONTAINER=""

on_interrupt() {
    echo "ci-local.sh: interrupted" >&2
    [[ -n "$CONTAINER" ]] && docker rm -f "$CONTAINER" >/dev/null 2>&1
    exit 130
}

# run_step <name> <step function name>
run_step() {
    local name="$1" fn="$2" start rc
    local args=()
    mapfile -t args < <(docker_args "$ROOT" "$PG" "$BUILD_TYPE" "$name" "$RUN_NAME")
    CONTAINER="chela-neon-ci-${name}-$$"
    echo
    echo "##### $name (pg=$PG, build=$BUILD_TYPE) $(date '+%H:%M:%S')"
    start=$(date +%s)
    docker run "${args[@]}" "$IMAGE" \
        bash -euo pipefail .github/scripts/ci-local.sh --inside "$fn" 2>&1 | tee "$RUN_DIR/$name.log"
    rc=${PIPESTATUS[0]}
    CONTAINER=""
    STEP_NAMES+=("$name")
    STEP_TIMES+=($(($(date +%s) - start)))
    if ((rc == 0)); then STEP_RESULTS+=(pass); else STEP_RESULTS+=(FAIL); fi
    return "$rc"
}

summary() {
    local i totals
    echo
    echo "================ ci-local summary (pg=$PG, build=$BUILD_TYPE, image tag ${IMAGE##*:}) ================"
    for i in "${!STEP_NAMES[@]}"; do
        printf '  %-12s %-5s %s\n' "${STEP_NAMES[$i]}" "${STEP_RESULTS[$i]}" "$(fmt_time "${STEP_TIMES[$i]}")"
    done
    if [[ -f "$RUN_DIR/regress.log" ]]; then
        totals="$(grep -E '^=+ .*(passed|failed|error).* in [0-9.]+s' "$RUN_DIR/regress.log" | tail -1 | sed 's/^=* *//; s/ *=*$//')"
        [[ -n "$totals" ]] && echo "  pytest: $totals"
    fi
    echo "  logs: $RUN_DIR"
    if ((OVERALL == 0)); then echo "  result: PASS"; else echo "  result: FAIL"; fi
}

ensure_submodules() {
    local v missing=()
    for v in "${MAJORS[@]}"; do
        if [[ ! -e "$ROOT/vendor/postgres-$v/.git" ]]; then
            missing+=("vendor/postgres-$v")
        fi
    done
    ((${#missing[@]} == 0)) && return 0
    echo "ci-local.sh: initialising submodules: ${missing[*]}"
    if ! git -C "$ROOT" submodule update --init -- "${missing[@]}"; then
        echo "ci-local.sh: could not initialise ${missing[*]} (they come from github.com/chelabase/postgres)." >&2
        echo "  Check network access, then run: git submodule update --init" >&2
        return 1
    fi
}

ensure_image() {
    docker image inspect "$IMAGE" >/dev/null 2>&1 && return 0
    echo "ci-local.sh: pulling $IMAGE"
    if ! docker pull "$IMAGE"; then
        echo "ci-local.sh: could not pull $IMAGE." >&2
        echo "  The package is private: run 'docker login ghcr.io' with a token that has read:packages." >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Stale build state. The chela-neon-target volume keeps build/, pg_install/ and
# target/ across runs, and several clones share it. postgres.mk never
# re-configures once build/<v>/config.status exists, and make's mtime checks can
# skip recompiling a changed pgxn source when another clone left newer .o files.
# So each run compares a stamp of what the state was built from with the one of
# this checkout, and wipes the affected dirs when they differ.
#
# Stamp: key=value lines: image, bt (build type), mk (Makefile + postgres.mk),
# v14..v17 (the checked-out submodule commit, plus a diff hash if dirty) and
# pgxn (hash of the contents of every pgxn/ file, tracked or not, so a dirty
# tree counts).
# ---------------------------------------------------------------------------

STAMP_FILE="ci-local.stamp" # at the root of the target volume

# stamp_get <stamp> <key>: the value, empty if absent.
stamp_get() {
    local line
    while IFS= read -r line; do
        [[ "${line%%=*}" == "$2" ]] && { echo "${line#*=}"; return 0; }
    done <<<"$1"
    return 0
}

# stale_dirs <old stamp> <new stamp>: the dirs inside the target volume to wipe,
# one per line, sorted, without duplicates. A Postgres major's change wipes its
# build, install and pgxn build (v17 also walproposer-lib, which links against
# it); a pgxn change wipes every pgxn build and walproposer-lib; a different
# image, build type or Makefile/postgres.mk, or a missing or incomplete old
# stamp, wipes everything.
stale_dirs() {
    local old="$1" new="$2" k v all=0 pgxn=0
    local dirs=()
    for k in image bt mk v14 v15 v16 v17 pgxn; do
        [[ -n "$(stamp_get "$old" "$k")" ]] || all=1
    done
    for k in image bt mk; do
        [[ "$(stamp_get "$old" "$k")" == "$(stamp_get "$new" "$k")" ]] || all=1
    done
    [[ "$(stamp_get "$old" pgxn)" == "$(stamp_get "$new" pgxn)" ]] || pgxn=1
    for v in "${MAJORS[@]}"; do
        if ((all)) || [[ "$(stamp_get "$old" "$v")" != "$(stamp_get "$new" "$v")" ]]; then
            dirs+=("build/$v" "pg_install/$v" "build/pgxn-$v")
            [[ "$v" == v17 ]] && dirs+=(build/walproposer-lib)
        fi
        if ((all || pgxn)); then
            dirs+=("build/pgxn-$v" build/walproposer-lib)
        fi
    done
    ((${#dirs[@]} == 0)) && return 0
    printf '%s\n' "${dirs[@]}" | sort -u
}

# hash_dirty <git dir>: a short hash of the uncommitted changes, empty if clean.
hash_dirty() {
    local d
    d="$(git -C "$1" status --porcelain --untracked-files=all 2>/dev/null)" || true
    [[ -z "$d" ]] && return 0
    { echo "$d"; git -C "$1" diff HEAD 2>/dev/null || true; } | sha256sum | cut -c1-12
}

# build_stamp <repo root> <image>: the stamp of this checkout.
build_stamp() {
    local root="$1" v rev dirty pgxn mk
    echo "image=${2##*:}"
    echo "bt=$BUILD_TYPE"
    mk="$(cat "$root/Makefile" "$root/postgres.mk" | sha256sum | cut -c1-12)"
    echo "mk=$mk"
    for v in "${MAJORS[@]}"; do
        rev="$(git -C "$root/vendor/postgres-$v" rev-parse HEAD 2>/dev/null || echo none)"
        dirty="$(hash_dirty "$root/vendor/postgres-$v")"
        echo "$v=$rev${dirty:+-dirty$dirty}"
    done
    pgxn="$(cd "$root" && git ls-files -z --cached --others --exclude-standard pgxn |
        sort -z | xargs -0 -r sha256sum 2>/dev/null | sha256sum | cut -c1-12)"
    echo "pgxn=$pgxn"
}

# sync_build_state: wipes the stale dirs of the volume (if any) and records the stamp.
sync_build_state() {
    local old new dirs
    new="$(build_stamp "$ROOT" "$IMAGE")"
    old="$(docker run --rm --user root -v "${TARGET_VOLUME}:/t" "$IMAGE" \
        bash -c "cat /t/$STAMP_FILE 2>/dev/null || true")"
    dirs="$(stale_dirs "$old" "$new")"
    if [[ -n "$dirs" ]]; then
        echo "ci-local: build state differs from the last run's stamp; wiping: $(paste -sd' ' - <<<"$dirs")"
        # shellcheck disable=SC2046
        docker run --rm --user root -v "${TARGET_VOLUME}:/t" "$IMAGE" \
            bash -c 'cd /t && rm -rf -- "$@" && mkdir -p build pg_install && chown nonroot:nonroot build pg_install' _ \
            $(paste -sd' ' - <<<"$dirs")
    else
        echo "ci-local: build state matches the last run's stamp; nothing to wipe"
    fi
    docker run --rm --user root -e "STAMP=$new" -v "${TARGET_VOLUME}:/t" "$IMAGE" \
        bash -c "printf '%s\\n' \"\$STAMP\" >/t/$STAMP_FILE"
}

ensure_volumes() {
    docker run --rm --user root \
        -v "${CARGO_VOLUME}:/c" -v "${TARGET_VOLUME}:/t" "$IMAGE" \
        bash -c 'mkdir -p /c/registry /c/git /c/poetry /t/target /t/pg_install /t/build &&
                 chown nonroot:nonroot /c /t /c/* /t/*'
}

main() {
    set -euo pipefail
    local rc=0
    parse_args "$@" || rc=$?
    if ((rc == 2)); then exit 0; elif ((rc != 0)); then usage; exit 1; fi

    init_volumes || exit 1
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    cd "$ROOT"
    command -v docker >/dev/null || { echo "ci-local.sh: docker not found" >&2; exit 1; }

    RUN_NAME="$(date +%Y%m%d-%H%M%S)-${PG}-${BUILD_TYPE}"
    RUN_DIR="$ROOT/.ci-local/$RUN_NAME"
    mkdir -p "$RUN_DIR"

    # Two runs would fight over the volumes.
    exec 9>"$ROOT/.ci-local/lock"
    flock -n 9 || { echo "ci-local.sh: another ci-local.sh run is in progress" >&2; exit 1; }

    exec > >(tee -a "$RUN_DIR/ci-local.log") 2>&1
    trap on_interrupt INT TERM

    IMAGE="$(image_name "$ROOT")"
    echo "ci-local: $IMAGE, pg=$PG, build=$BUILD_TYPE, regress=$REGRESS, workers=$WORKERS, -k [${KEXPR}]"
    ensure_submodules
    ensure_image
    ensure_volumes
    sync_build_state

    OVERALL=0
    local build_ok=1 step
    for step in $(selected_steps); do
        case "$step" in
        lint) run_step lint step_lint || OVERALL=1 ;;
        build) run_step build step_build || { OVERALL=1; build_ok=0; } ;;
        rust-tests) run_step rust-tests step_rust_tests || OVERALL=1 ;;
        regress)
            if ((build_ok)); then
                run_step regress step_regress || OVERALL=1
            else
                echo "regress skipped: the build failed"
            fi
            ;;
        esac
    done
    summary
    exit "$OVERALL"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "${1:-}" == "--inside" ]]; then
        # Container side: the environment comes from docker_args.
        step="$2"
        inside_env
        "$step"
    else
        main "$@"
    fi
fi
