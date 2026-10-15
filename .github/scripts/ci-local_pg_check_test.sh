#!/usr/bin/env bash
# Edge cases of ci-local.sh's pg-check helpers beyond ci-local_test.sh (paths as the step
# passes them, trailing slashes, absolute paths, a missing install). No Docker needed.
#   .github/scripts/ci-local_pg_check_test.sh
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci-local.sh
source "$here/ci-local.sh"

failures=0
expect() {
    if [[ "$2" == "$3" ]]; then
        echo "ok: $1"
    else
        echo "FAIL: $1: expected [$2], got [$3]"
        failures=$((failures + 1))
    fi
}
args() { pg_check_make_args "$@" | paste -sd' ' -; }

# Every directory pg_check_dirs yields gets the right diffs file and make args.
for pg in v14 v15 v16 v17; do
    while read -r dir; do
        case "$dir" in
            build/"$pg")
                expect "$pg core diffs" "build/$pg/src/test/regress/regression.diffs" "$(pg_check_diffs_file "$dir")"
                expect "$pg core args" "-j2 -C build/$pg check" "$(args "$dir" 2)"
                ;;
            build/v17/contrib/chelabase_keys)
                expect "chelabase_keys diffs" "$dir/regression.diffs" "$(pg_check_diffs_file "$dir")"
                expect "chelabase_keys args" "-j2 -C $dir check TEMP_CONFIG=$PG_CHECK_TEMP_CONFIG" "$(args "$dir" 2)"
                ;;
            *) expect "unexpected pg-check dir" "" "$dir" ;;
        esac
    done < <(pg_check_dirs "$pg")
done

# Trailing slashes and absolute paths.
expect "core with a trailing slash" "build/v17/src/test/regress/regression.diffs" "$(pg_check_diffs_file build/v17/)"
expect "absolute core" "/work/build/v16/src/test/regress/regression.diffs" "$(pg_check_diffs_file /work/build/v16)"
expect "absolute chelabase_keys args" "-j8 -C /work/build/v17/contrib/chelabase_keys check TEMP_CONFIG=$PG_CHECK_TEMP_CONFIG" \
    "$(args /work/build/v17/contrib/chelabase_keys 8)"
# Another contrib module, or a v16 one, gets no neon_rmgr preload.
expect "another contrib module" "-j2 -C build/v17/contrib/pgcrypto check" "$(args build/v17/contrib/pgcrypto 2)"
expect "a module whose name extends chelabase_keys" "-j2 -C build/v17/contrib/chelabase_keys2 check" "$(args build/v17/contrib/chelabase_keys2 2)"
expect "chelabase_keys under v16" "-j2 -C build/v16/contrib/chelabase_keys check" "$(args build/v16/contrib/chelabase_keys 2)"

# The temp config is absolute (make -C changes directory) and the content is exactly two lines.
[[ "$PG_CHECK_TEMP_CONFIG" == /* ]] && echo "ok: temp config path is absolute" ||
    { echo "FAIL: temp config path must be absolute"; failures=$((failures + 1)); }
expect "temp config has two lines" "2" "$(pg_check_temp_config_content | wc -l | tr -d ' ')"

# A pg_install that doesn't exist at all is reported the same way as a missing neon_rmgr.so.
if msg="$(pg_check_require_rmgr /nonexistent/pg_install/v17 2>&1)"; then
    echo "FAIL: a missing pg_install must fail"
    failures=$((failures + 1))
else
    expect "missing pg_install names neon_rmgr" "1" "$([[ "$msg" == *neon_rmgr* ]] && echo 1)"
fi

if ((failures > 0)); then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
