#!/usr/bin/env bash
# Self-test for the pure logic of ci-local.sh (argument parsing, the image tag
# and the docker command line). It sources the script, which does nothing when
# sourced. Run from anywhere:
#   .github/scripts/ci-local_test.sh
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci-local.sh
source "$here/ci-local.sh"

failures=0

# expect <name> <expected> <actual>
expect() {
    if [[ "$2" == "$3" ]]; then
        echo "ok: $1"
    else
        echo "FAIL: $1: expected [$2], got [$3]"
        failures=$((failures + 1))
    fi
}

# parse <args...>: prints the resulting settings on one line.
parse() {
    (
        parse_args "$@" || exit 1
        echo "pg=$PG build=$BUILD_TYPE regress=$REGRESS k=$KEXPR n=$WORKERS"
    )
}

expect "defaults (no regression suite)" "pg=v17 build=release regress=0 k= n=6" "$(parse)"
expect "--pg and --build-type" "pg=v16 build=debug regress=0 k= n=6" "$(parse --pg v16 --build-type debug)"
expect "--regress" "pg=v17 build=release regress=1 k= n=6" "$(parse --regress)"
expect "--regress with -k and -n" "pg=v17 build=release regress=1 k=test_a or test_b n=3" "$(parse --regress -k 'test_a or test_b' -n 3)"
expect "-k and -n in either order" "pg=v17 build=release regress=1 k=x n=2" "$(parse -k x -n 2 --regress)"
expect "every major is accepted" "pg=v14 build=release regress=0 k= n=6" "$(parse --pg v14)"

for bad in "--pg v18" "--pg" "--build-type fast" "-n 0" "-n x" "--bogus" "-k" "--quick" "-k x" "-n 3"; do
    # shellcheck disable=SC2086
    if parse $bad >/dev/null 2>&1; then
        echo "FAIL: [$bad] must be rejected"
        failures=$((failures + 1))
    else
        echo "ok: [$bad] is rejected"
    fi
done

# The build step's POSTGRES_VERSIONS: walproposer-lib (part of `make all`)
# always links against v17, so a v14-v16 build must keep v17 in the list.
expect "build versions for v17" "v17" "$(build_versions v17)"
expect "build versions for v16 keep v17" "v16 v17" "$(build_versions v16)"
expect "build versions for v14 keep v17" "v14 v17" "$(build_versions v14)"

# The image tag is the first 12 hex characters of sha256sum build-tools/Dockerfile,
# exactly as pr.yml and build-tools.yml compute it.
root="$(cd "$here/../.." && pwd)"
expected="ghcr.io/chelabase/neon-build-tools:$(sha256sum "$root/build-tools/Dockerfile" | cut -c1-12)"
expect "image name" "$expected" "$(image_name "$root")"

# The docker command line: caches in the two named volumes, never host networking.
cmd="$(docker_args "$root" v17 release lint | paste -sd' ' -)"
if [[ "$cmd" == *chela-neon-cargo* && "$cmd" == *chela-neon-target* ]]; then
    echo "ok: docker args use both named volumes"
else
    echo "FAIL: docker args must use both named volumes: $cmd"
    failures=$((failures + 1))
fi
if [[ "$cmd" != *--network* ]]; then
    echo "ok: docker args do not set --network"
else
    echo "FAIL: docker args must not set --network: $cmd"
    failures=$((failures + 1))
fi

# The stale-state decision: old stamp + new stamp -> the dirs (inside the
# chela-neon-target volume) to wipe before building. Stamp lines are key=value.
base=$'image=i1\nbt=release\nmk=m1\nv14=a\nv15=b\nv16=c\nv17=d\npgxn=p1'
all_dirs="build/pgxn-v14 build/pgxn-v15 build/pgxn-v16 build/pgxn-v17 build/v14 build/v15 build/v16 build/v17 build/walproposer-lib pg_install/v14 pg_install/v15 pg_install/v16 pg_install/v17"
wipe() { stale_dirs "$1" "$2" | paste -sd' ' -; }
expect "same stamp: nothing to wipe" "" "$(wipe "$base" "$base")"
expect "no old stamp: wipe everything" "$all_dirs" "$(wipe "" "$base")"
expect "v16 sha changed: its build, install and pgxn build" \
    "build/pgxn-v16 build/v16 pg_install/v16" "$(wipe "$base" "${base/v16=c/v16=c2}")"
expect "v17 sha changed: also walproposer-lib" \
    "build/pgxn-v17 build/v17 build/walproposer-lib pg_install/v17" "$(wipe "$base" "${base/v17=d/v17=d2}")"
expect "pgxn hash changed: every pgxn build and walproposer-lib, no Postgres build" \
    "build/pgxn-v14 build/pgxn-v15 build/pgxn-v16 build/pgxn-v17 build/walproposer-lib" "$(wipe "$base" "${base/pgxn=p1/pgxn=p2}")"
expect "v15 and pgxn changed: combined without duplicates" \
    "build/pgxn-v14 build/pgxn-v15 build/pgxn-v16 build/pgxn-v17 build/v15 build/walproposer-lib pg_install/v15" \
    "$(both="${base/v15=b/v15=b2}"; wipe "$base" "${both/pgxn=p1/pgxn=p2}")"
expect "build-tools image changed: wipe everything" "$all_dirs" "$(wipe "$base" "${base/image=i1/image=i2}")"
expect "build type changed: wipe everything" "$all_dirs" "$(wipe "$base" "${base/bt=release/bt=debug}")"
expect "Makefile/postgres.mk hash changed: wipe everything" "$all_dirs" "$(wipe "$base" "${base/mk=m1/mk=m2}")"
expect "old stamp missing a key: wipe everything" "$all_dirs" "$(wipe $'image=i1\nbt=release' "$base")"

# seccomp=unconfined is for io_uring (the pageserver's tokio-epoll-uring); lint
# (fmt, clippy, headers, self-tests) doesn't need it, the other steps do.
if [[ "$(docker_args "$root" v17 release lint | paste -sd' ' -)" != *seccomp* ]]; then
    echo "ok: the lint step runs with the default seccomp profile"
else
    echo "FAIL: the lint step must not use seccomp=unconfined"
    failures=$((failures + 1))
fi
for step in build rust-tests regress; do
    if [[ "$(docker_args "$root" v17 release "$step" | paste -sd' ' -)" == *seccomp=unconfined* ]]; then
        echo "ok: the $step step keeps seccomp=unconfined"
    else
        echo "FAIL: the $step step needs seccomp=unconfined"
        failures=$((failures + 1))
    fi
done

# Volume names: CHELA_NEON_VOLUME_SUFFIX gives each clone its own pair.
vols() {
    (
        if [[ $# -gt 0 ]]; then export CHELA_NEON_VOLUME_SUFFIX="$1"; else unset CHELA_NEON_VOLUME_SUFFIX; fi
        init_volumes || exit 1
        echo "$CARGO_VOLUME $TARGET_VOLUME"
    )
}
expect "volume names default" "chela-neon-cargo chela-neon-target" "$(vols)"
expect "volume names with suffix p4" "chela-neon-cargo-p4 chela-neon-target-p4" "$(vols p4)"
expect "suffix with digits and dashes" "chela-neon-cargo-a-1 chela-neon-target-a-1" "$(vols a-1)"
for bad in P4 a/b "" "a b" "p_4"; do
    if vols "$bad" >/dev/null 2>&1; then
        echo "FAIL: suffix [$bad] must be refused"
        failures=$((failures + 1))
    else
        echo "ok: suffix [$bad] is refused"
    fi
done
suffixed="$(CHELA_NEON_VOLUME_SUFFIX=p4 bash -c 'source "$1"; init_volumes; docker_args /r v17 release build | paste -sd" " -' _ "$here/ci-local.sh")"
if [[ "$suffixed" == *src=chela-neon-cargo-p4,* && "$suffixed" == *src=chela-neon-target-p4,* ]]; then
    echo "ok: docker args use the suffixed volumes"
else
    echo "FAIL: docker args must use the suffixed volumes: $suffixed"
    failures=$((failures + 1))
fi

# --only and --test-filter.
steps() {
    (
        parse_args "$@" || exit 1
        echo "$(selected_steps | paste -sd, -) regress=$REGRESS"
    )
}
expect "default steps" "lint,build,rust-tests regress=0" "$(steps)"
expect "--regress adds regress" "lint,build,rust-tests,regress regress=1" "$(steps --regress)"
expect "--only build runs only build" "build regress=0" "$(steps --only build)"
expect "--only build,rust-tests runs both" "build,rust-tests regress=0" "$(steps --only build,rust-tests)"
expect "--only runs in pipeline order" "build,rust-tests regress=0" "$(steps --only rust-tests,build)"
expect "--only regress sets regress=1" "regress regress=1" "$(steps --only regress)"
for bad in "--only lint" "--only" "--only build,foo" "--only ," "--test-filter x" "--test-filter" "--only build --test-filter x"; do
    # shellcheck disable=SC2086
    if steps $bad >/dev/null 2>&1; then
        echo "FAIL: [$bad] must be rejected"
        failures=$((failures + 1))
    else
        echo "ok: [$bad] is rejected"
    fi
done
expect "--test-filter with rust-tests" "rust-tests regress=0" "$(steps --only rust-tests --test-filter 'test(foo)')"
expect "--only regress then --only build: the last wins completely" "build regress=0" "$(steps --only regress --only build)"
expect "--regress then --only build: regress does not run" "build regress=0" "$(steps --regress --only build)"
expect "--only build then --only regress" "regress regress=1" "$(steps --only build --only regress)"
if steps --only rust-tests --test-filter $'a\nb' >/dev/null 2>&1; then
    echo "FAIL: a --test-filter with a newline must be rejected"
    failures=$((failures + 1))
else
    echo "ok: a --test-filter with a newline is rejected"
fi

# The real nextest argument list (one per line), as the rust-tests step runs it.
nextest_line() {
    (
        BUILD_TYPE=release
        inside_env
        TEST_FILTER="$1"
        nextest_args | paste -sd'|' -
    )
}
base_expr='not (package(remote_storage) and binary(test_real_gcs))'
common='run|--locked|--features|testing|--release|--no-fail-fast|-E'
expect "nextest args with a filter" "$common|($base_expr) and (test(foo))" "$(nextest_line 'test(foo)')"
expect "nextest args without a filter" "$common|$base_expr" "$(nextest_line '')"
# nextest's -E filter can't narrow `cargo test --doc`, so a filtered run skips it.
if (TEST_FILTER=x doc_tests_enabled); then
    echo "FAIL: doc tests must be skipped with a --test-filter"
    failures=$((failures + 1))
else
    echo "ok: doc tests are skipped with a --test-filter"
fi
if (TEST_FILTER='' doc_tests_enabled); then
    echo "ok: doc tests run without a --test-filter"
else
    echo "FAIL: doc tests must run without a --test-filter"
    failures=$((failures + 1))
fi
if [[ "$(TEST_FILTER=x docker_args /r v17 release rust-tests | paste -sd' ' -)" == *"TEST_FILTER=x"* ]]; then
    echo "ok: docker args pass TEST_FILTER"
else
    echo "FAIL: docker args must pass TEST_FILTER"
    failures=$((failures + 1))
fi

if ((failures > 0)); then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
