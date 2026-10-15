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

# pg-check (round 3): only through --only, after rust-tests, before regress.
expect "--only pg-check runs only pg-check" "pg-check regress=0" "$(steps --only pg-check)"
expect "--only pg-check,build runs in pipeline order" "build,pg-check regress=0" "$(steps --only pg-check,build)"
expect "--only regress,pg-check,rust-tests runs in pipeline order" "rust-tests,pg-check,regress regress=1" "$(steps --only regress,pg-check,rust-tests)"
expect "pg-check is not in the default run" "lint,build,rust-tests regress=0" "$(steps)"
expect "pg-check directories for v17" "build/v17 build/v17/contrib/chelabase_keys" "$(pg_check_dirs v17 | paste -sd' ' -)"
expect "pg-check directories for v16: core only" "build/v16" "$(pg_check_dirs v16 | paste -sd' ' -)"
if steps --only pg-check --test-filter 'test(x)' >/dev/null 2>&1; then
    echo "FAIL: --test-filter without rust-tests must still be refused with pg-check"
    failures=$((failures + 1))
else
    echo "ok: --test-filter needs rust-tests even with pg-check"
fi

# Shared compiler cache (round 3, T1b): every container mounts one sccache volume, whatever
# CHELA_NEON_VOLUME_SUFFIX is, and wraps rustc with a static sccache binary mounted read-only.
for step in build rust-tests pg-check; do
    args="$(CHELA_NEON_VOLUME_SUFFIX=t9 docker_args /r v17 release "$step" | paste -sd' ' -)"
    for want in \
        "type=volume,src=chela-neon-sccache,dst=/sccache-cache" \
        "SCCACHE_DIR=/sccache-cache" \
        "RUSTC_WRAPPER=/opt/sccache/sccache" \
        "dst=/opt/sccache,readonly"; do
        if [[ "$args" == *"$want"* ]]; then
            echo "ok: $step args carry $want"
        else
            echo "FAIL: $step args must carry $want"
            failures=$((failures + 1))
        fi
    done
done

# T0b (round 3): the Rust toolchain is 1.99.0, pinned identically in rust-toolchain.toml and
# the build-tools image.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
toolchain_pin="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$repo_root/rust-toolchain.toml")"
image_pin="$(sed -n 's/^ENV RUSTC_VERSION=\(.*\)$/\1/p' "$repo_root/build-tools/Dockerfile")"
expect "rust-toolchain.toml pins Rust 1.99.0" "1.99.0" "$toolchain_pin"
expect "the build-tools image pins the same Rust" "$toolchain_pin" "$image_pin"

# T1b fix round: a damaged installed sccache (truncated copy, interrupted install) is never
# trusted; the installed binary's own sha256 is pinned and checked on every run.
expect "the installed binary's sha256 is pinned" "64" "$(v="${SCCACHE_BIN_SHA256:-}"; echo "${#v}")"
fake_cache="$(mktemp -d)"
mkdir -p "$fake_cache/chela-neon/sccache-$SCCACHE_VERSION"
printf 'truncated' >"$fake_cache/chela-neon/sccache-$SCCACHE_VERSION/sccache"
chmod 755 "$fake_cache/chela-neon/sccache-$SCCACHE_VERSION/sccache"
if (
    XDG_CACHE_HOME="$fake_cache"
    curl() { return 7; }
    ensure_sccache
) >/dev/null 2>&1; then
    echo "FAIL: ensure_sccache must not trust a damaged sccache binary"
    failures=$((failures + 1))
else
    echo "ok: a damaged sccache binary is not trusted"
fi
rm -rf "$fake_cache"

# RT3-6 (T7): chelabase_keys is installed into pg_install for v17 only. The install recipe is
# printed with MAKE=echo (its recursive $(MAKE) lines run even under -n) and its
# prerequisites treated as done (-o).
install_recipe() {
    make -s -f "$root/postgres.mk" POSTGRES_VERSIONS="v14 v15 v16 v17" BUILD_DIR=/x \
        POSTGRES_INSTALL_DIR=/y MAKE=echo -o "postgres-configure-$1" \
        -o "postgres-headers-install-$1" "postgres-install-$1" 2>&1
}
if install_recipe v17 | grep -q 'contrib/chelabase_keys install'; then
    echo "ok: v17 installs chelabase_keys"
else
    echo "FAIL: v17 must install chelabase_keys"
    failures=$((failures + 1))
fi
for v in v14 v15 v16; do
    if install_recipe "$v" | grep -q 'chelabase_keys'; then
        echo "FAIL: $v must not install chelabase_keys"
        failures=$((failures + 1))
    else
        echo "ok: $v skips chelabase_keys"
    fi
done
expect "revisions.json pins the v17 submodule" "$(git -C "$root" rev-parse HEAD:vendor/postgres-v17)" "$(jq -r '.v17[1]' "$root/vendor/revisions.json")"

# F1 (round 3 final fix round): pg-check command construction, diff handling and the
# neon_rmgr preload for chelabase_keys, all testable without Docker.
# Pinned helpers (ci-local.sh): pg_check_diffs_file <dir>, pg_check_clean_diffs <dir>,
# pg_check_print_diffs <dir>, pg_check_make_args <dir> <jobs>, pg_check_temp_config_content,
# pg_check_build_targets <pg>, pg_check_require_rmgr <pg_install_dir>, lint_hakari.
for fn in pg_check_diffs_file pg_check_clean_diffs pg_check_print_diffs pg_check_make_args \
    pg_check_temp_config_content pg_check_build_targets pg_check_require_rmgr lint_hakari; do
    if declare -F "$fn" >/dev/null; then
        echo "ok: $fn is defined"
    else
        echo "FAIL: $fn is not defined in ci-local.sh"
        failures=$((failures + 1))
    fi
done

# Core's diffs are written where pg_regress runs: build/<pg>/src/test/regress; contrib's in its own dir.
expect "core diffs file" "build/v17/src/test/regress/regression.diffs" "$(pg_check_diffs_file build/v17 2>/dev/null)"
expect "contrib diffs file" "build/v17/contrib/chelabase_keys/regression.diffs" "$(pg_check_diffs_file build/v17/contrib/chelabase_keys 2>/dev/null)"
expect "v16 core diffs file" "build/v16/src/test/regress/regression.diffs" "$(pg_check_diffs_file build/v16 2>/dev/null)"

pgc="$(mktemp -d)"
core_d="$pgc/build/v17"
contrib_d="$pgc/build/v17/contrib/chelabase_keys"
mkdir -p "$core_d/src/test/regress" "$contrib_d"
seed_diffs() {
    printf 'CORE-DIFF\n' >"$core_d/src/test/regress/regression.diffs"
    printf 'CONTRIB-DIFF\n' >"$contrib_d/regression.diffs"
}

# Core failing, contrib passing (no contrib diffs): only core's diffs under the core heading.
seed_diffs
rm -f "$contrib_d/regression.diffs"
out="$(pg_check_print_diffs "$core_d" 2>/dev/null)"
if [[ "$out" == *CORE-DIFF* && "$out" != *CONTRIB-DIFF* ]]; then
    echo "ok: core heading prints core's diffs only"
else
    echo "FAIL: core heading must print only core's diffs, got [$out]"
    failures=$((failures + 1))
fi
# Core passing, contrib failing: the core heading prints nothing (contrib's diffs are not core's).
seed_diffs
rm -f "$core_d/src/test/regress/regression.diffs"
out="$(pg_check_print_diffs "$core_d" 2>/dev/null)"
if [[ "$out" != *CONTRIB-DIFF* ]]; then
    echo "ok: contrib's diffs never appear under the core heading"
else
    echo "FAIL: contrib's diffs appeared under the core heading: [$out]"
    failures=$((failures + 1))
fi
out="$(pg_check_print_diffs "$contrib_d" 2>/dev/null)"
if [[ "$out" == *CONTRIB-DIFF* && "$out" != *CORE-DIFF* ]]; then
    echo "ok: contrib heading prints contrib's diffs only"
else
    echo "FAIL: contrib heading must print only contrib's diffs, got [$out]"
    failures=$((failures + 1))
fi
# No diffs file: nothing printed and no error.
rm -f "$contrib_d/regression.diffs"
if out="$(pg_check_print_diffs "$contrib_d" 2>&1)" && [[ -z "$out" ]]; then
    echo "ok: no diffs file prints nothing"
else
    echo "FAIL: a missing diffs file must print nothing and succeed, got [$out]"
    failures=$((failures + 1))
fi

# A stale regression.diffs from an earlier run is removed before the next make check, and
# cleaning one directory leaves the other's file alone.
seed_diffs
pg_check_clean_diffs "$core_d" 2>/dev/null
if [[ ! -e "$core_d/src/test/regress/regression.diffs" && -e "$contrib_d/regression.diffs" ]]; then
    echo "ok: cleaning core removes core's stale diffs only"
else
    echo "FAIL: cleaning core must remove core's diffs and keep contrib's"
    failures=$((failures + 1))
fi
seed_diffs
pg_check_clean_diffs "$contrib_d" 2>/dev/null
if [[ ! -e "$contrib_d/regression.diffs" && -e "$core_d/src/test/regress/regression.diffs" ]]; then
    echo "ok: cleaning contrib removes contrib's stale diffs only"
else
    echo "FAIL: cleaning contrib must remove contrib's diffs and keep core's"
    failures=$((failures + 1))
fi
# Cleaning a directory with nothing to clean is not an error.
if pg_check_clean_diffs "$pgc/build/v99" 2>/dev/null; then
    echo "ok: cleaning a directory with no diffs succeeds"
else
    echo "FAIL: cleaning a directory with no diffs must succeed"
    failures=$((failures + 1))
fi
rm -rf "$pgc"

# make arguments: parallel (-j<jobs>), the right directory; TEMP_CONFIG only for chelabase_keys.
core_args="$(pg_check_make_args build/v17 4 2>/dev/null | paste -sd' ' -)"
contrib_args="$(pg_check_make_args build/v17/contrib/chelabase_keys 4 2>/dev/null | paste -sd' ' -)"
v16_args="$(pg_check_make_args build/v16 4 2>/dev/null | paste -sd' ' -)"
expect "core make args: no TEMP_CONFIG" "-j4 -C build/v17 check" "$core_args"
expect "v16 make args: no TEMP_CONFIG" "-j4 -C build/v16 check" "$v16_args"
if [[ "$contrib_args" == "-j4 -C build/v17/contrib/chelabase_keys check TEMP_CONFIG="?* ]]; then
    echo "ok: chelabase_keys make args carry TEMP_CONFIG"
else
    echo "FAIL: chelabase_keys make args must be '-j4 -C <dir> check TEMP_CONFIG=<file>', got [$contrib_args]"
    failures=$((failures + 1))
fi
expect "jobs value is passed through" "-j1 -C build/v17 check" "$(pg_check_make_args build/v17 1 2>/dev/null | paste -sd' ' -)"

# The TEMP_CONFIG preloads neon_rmgr (heap DML logs under RM_NEON_ID) and finds it in the
# container's pg_install (the volume's /work/pg_install/v17/lib/postgresql).
conf="$(pg_check_temp_config_content 2>/dev/null)"
if grep -qxF "shared_preload_libraries = 'neon_rmgr'" <<<"$conf"; then
    echo "ok: temp config preloads neon_rmgr"
else
    echo "FAIL: temp config must contain shared_preload_libraries = 'neon_rmgr', got [$conf]"
    failures=$((failures + 1))
fi
if grep -qxF "dynamic_library_path = '\$libdir:/work/pg_install/v17/lib/postgresql'" <<<"$conf"; then
    echo "ok: temp config finds neon_rmgr in pg_install"
else
    echo "FAIL: temp config must contain dynamic_library_path = '\$libdir:/work/pg_install/v17/lib/postgresql', got [$conf]"
    failures=$((failures + 1))
fi

# pg-check needs the neon extensions built for v17 (not for other majors), alongside Postgres.
expect "pg-check build targets for v17" "postgres-v17 neon-pg-ext-v17" "$(pg_check_build_targets v17 2>/dev/null | paste -sd' ' -)"
expect "pg-check build targets for v16" "postgres-v16" "$(pg_check_build_targets v16 2>/dev/null | paste -sd' ' -)"

# A pg_install without neon_rmgr.so fails with a clear message, not a Postgres startup error.
inst="$(mktemp -d)"
mkdir -p "$inst/lib/postgresql"
if msg="$(pg_check_require_rmgr "$inst" 2>&1)"; then
    echo "FAIL: pg_check_require_rmgr must fail without neon_rmgr.so"
    failures=$((failures + 1))
elif [[ "$msg" == *neon_rmgr* && "$msg" == *build* ]]; then
    echo "ok: a missing neon_rmgr.so is reported clearly"
else
    echo "FAIL: the message must name neon_rmgr and the build step, got [$msg]"
    failures=$((failures + 1))
fi
: >"$inst/lib/postgresql/neon_rmgr.so"
if pg_check_require_rmgr "$inst" >/dev/null 2>&1; then
    echo "ok: an installed neon_rmgr.so passes"
else
    echo "FAIL: pg_check_require_rmgr must pass when neon_rmgr.so is installed"
    failures=$((failures + 1))
fi
rm -rf "$inst"

# T0b m2: the lint step verifies workspace_hack (hakari) is up to date and consistent.
hk="$(declare -f lint_hakari 2>/dev/null)"
if [[ "$hk" == *"cargo hakari generate --diff"* && "$hk" == *"cargo hakari verify"* ]]; then
    echo "ok: lint_hakari runs generate --diff and verify"
else
    echo "FAIL: lint_hakari must run 'cargo hakari generate --diff' and 'cargo hakari verify'"
    failures=$((failures + 1))
fi
if [[ "$(declare -f step_lint)" == *lint_hakari* ]]; then
    echo "ok: the lint step runs lint_hakari"
else
    echo "FAIL: step_lint must run lint_hakari"
    failures=$((failures + 1))
fi
# The pg-check step uses the helpers (no hand-built make line, no unbounded find).
pgstep="$(declare -f step_pg_check)"
for want in pg_check_make_args pg_check_clean_diffs pg_check_print_diffs pg_check_build_targets pg_check_require_rmgr; do
    if [[ "$pgstep" == *"$want"* ]]; then
        echo "ok: step_pg_check uses $want"
    else
        echo "FAIL: step_pg_check must use $want"
        failures=$((failures + 1))
    fi
done
if [[ "$pgstep" != *"find "* ]]; then
    echo "ok: step_pg_check no longer searches for regression.diffs"
else
    echo "FAIL: step_pg_check must not use find for regression.diffs"
    failures=$((failures + 1))
fi

# T0b C1: with both rustls crypto providers compiled in, a provider-less
# ServerConfig::builder() / ClientConfig::builder() panics at runtime. Every source file that
# uses one must install the process default (http_utils::tls_certs::install_default_crypto_provider);
# the *_with_provider builders are fine. (Workspace crates only; vendor/ and target/ are not ours to scan here.)
bare_builders="$(grep -rlE '(Server|Client)Config::builder\(\)' --include='*.rs' \
    "$repo_root/pageserver" "$repo_root/safekeeper" "$repo_root/storage_controller" \
    "$repo_root/storage_broker" "$repo_root/storage_scrubber" "$repo_root/proxy" \
    "$repo_root/compute_tools" "$repo_root/control_plane" "$repo_root/endpoint_storage" \
    "$repo_root/libs" 2>/dev/null | grep -v '/tests/tls_provider_startup.rs$' | sort)"
bare_missing=""
for f in $bare_builders; do
    grep -q 'install_default_crypto_provider' "$f" || bare_missing+=" ${f#"$repo_root"/}"
done
expect "every file with a provider-less rustls builder installs the default provider" "" "$bare_missing"

# Invariant (F1 audit): EVERY binary target in the workspace installs the aws-lc-rs process default
# (http_utils::tls_certs::install_default_crypto_provider()) as the first statement of main. A
# dependency may build a provider-less rustls config at any point (redis 0.29's `rediss://`
# connection does), which panics when ring and aws-lc-rs are both compiled in. The bin targets
# come from `cargo metadata`; a bin whose main only calls `proxy::binary::<x>::run()` is checked
# at the first statement of that run().
# first_statement <file> <fn regex>: the first code line of that function's body.
first_statement() {
    awk -v re="$2" '
        !found && $0 ~ re { found = 1 }
        found && !open { if ($0 ~ /\{[[:space:]]*$/) open = 1; next }
        found && open {
            if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^[[:space:]]*\/\// || $0 ~ /^[[:space:]]*#\[/) next
            print; exit
        }' "$1"
}
# Bins that provably never touch TLS (each with its reason); nothing else may be exempted.
#   wal_craft: local test tool, postgres::NoTls only.
#   compaction-simulator: pure in-memory simulation, no network.
#   test_helper_slow_client_reads: test helper, plain tokio-postgres NoTls to a local pageserver.
tls_free_bins=" wal_craft compaction-simulator test_helper_slow_client_reads "
bins_listing="$(cd "$repo_root" && cargo metadata --no-deps --format-version 1 2>/dev/null |
    jq -r '.packages[].targets[] | select(.kind | index("bin")) | "\(.name) \(.src_path)"')"
expect "cargo metadata lists the workspace's bin targets" "yes" "$([[ "$(wc -l <<<"$bins_listing")" -ge 17 ]] && echo yes || echo no)"
no_provider=""
while read -r bin_name bin_src; do
    [[ -n "$bin_name" ]] || continue
    [[ "$tls_free_bins" == *" $bin_name "* ]] && continue
    stmt="$(first_statement "$bin_src" 'fn main\(')"
    if [[ "$stmt" =~ proxy::binary::([a-z_]+)::run\( ]]; then
        stmt="$(first_statement "$repo_root/proxy/src/binary/${BASH_REMATCH[1]}.rs" 'fn run\(')"
    fi
    [[ "$stmt" == *install_default_crypto_provider* ]] || no_provider+=" $bin_name"
done <<<"$bins_listing"
expect "every bin target installs the crypto provider first in main (offenders listed)" "" "$no_provider"

if ((failures > 0)); then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
