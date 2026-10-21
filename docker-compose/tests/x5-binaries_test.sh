#!/usr/bin/env bash
# X5: the binaries the compute image ships (pgbouncer and the three exporters), and the
# sql_exporter pin of the build-tools image. Runs the built compute image's binaries, so it needs
# a Docker daemon and the image (it never builds):
#   COMPUTE_IMAGE=chelabase-local/compute-node-v17:<tag> docker-compose/tests/x5-binaries_test.sh
# COMPUTE_IMAGE defaults to chelabase-local/compute-node-v17:round4-x4 (the base of X5).
# Checks (spec 17.2 rows 34-37):
#   * `--version` of pgbouncer 1.26.1, postgres_exporter v0.20.1, pgbouncer_exporter v0.12.1 and
#     sql_exporter 0.24.11 inside the image;
#   * the amd64 sha256 of the three exporter binaries inside the image (the image under test is
#     built for the host arch; the sha check is skipped on other arches, the Dockerfile check
#     below still covers both);
#   * compute/compute-node.Dockerfile: PGBOUNCER_TAG=pgbouncer_1_26_1, the tag commit
#     f03e9bf263d7ccd5d1d152a61811bf3258dd6b87 asserted against the clone (`rev-parse HEAD`), the
#     exporter download URLs at the new versions and both arches' sha256s;
#   * build-tools/Dockerfile: ENV SQL_EXPORTER_VERSION=0.24.11.
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${COMPUTE_IMAGE:-chelabase-local/compute-node-v17:round4-x4}"
fails=0

fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
ok() { echo "ok: $*"; }

# in_image <binary> <args...>: run a binary of the image, bypassing its entrypoint.
in_image() {
  local bin="$1"
  shift
  docker run --rm --entrypoint "$bin" "$image" "$@" 2>&1
}

expect_version() {
  local bin="$1" want="$2" out
  out="$(in_image "$bin" --version | head -n 1)"
  if [[ "$out" == *"$want"* ]]; then ok "$bin: $out"; else fail "$bin --version is '$out', want '$want'"; fi
}

expect_version pgbouncer "PgBouncer 1.26.1"
expect_version postgres_exporter "version 0.20.1 "
expect_version pgbouncer_exporter "version 0.12.1 "
expect_version sql_exporter "version 0.24.11 "

if [[ "$(uname -m)" == x86_64 ]]; then
  while read -r bin sha; do
    got="$(in_image sha256sum "/bin/$bin" | awk '{print $1}')"
    if [[ "$got" == "$sha" ]]; then ok "$bin sha256"; else fail "$bin sha256 is '$got', want '$sha'"; fi
  done <<'EOF'
postgres_exporter f9314f6eb5b45f83c713cc4129778513054a064062b21a7ffd0aaac80ae06dca
pgbouncer_exporter dcc4d01375128b7ca9b7cfc2b8bc80e4a2631e0d2c547f2b05282c1a2af2e615
sql_exporter 4ce4de40958bf90351e8366aa331ec075f0860aca8608933e77189eb0655dc3d
EOF
fi

compute="$root/compute/compute-node.Dockerfile"
want_in_file() {
  local file="$1" needle="$2" what="$3"
  if grep -qF -- "$needle" "$file"; then ok "$what"; else fail "$(basename "$(dirname "$file")")/$(basename "$file") lacks $what ('$needle')"; fi
}

want_in_file "$compute" "PGBOUNCER_TAG=pgbouncer_1_26_1" "pgbouncer tag"
want_in_file "$compute" "f03e9bf263d7ccd5d1d152a61811bf3258dd6b87" "pgbouncer tag commit"
want_in_file "$compute" "postgres_exporter/releases/download/v0.20.1/postgres_exporter-0.20.1.linux-" "postgres_exporter URL"
want_in_file "$compute" "pgbouncer_exporter/releases/download/v0.12.1/pgbouncer_exporter-0.12.1.linux-" "pgbouncer_exporter URL"
want_in_file "$compute" "sql_exporter/releases/download/0.24.11/sql_exporter-0.24.11.linux-" "sql_exporter URL"
for sha in \
  f9314f6eb5b45f83c713cc4129778513054a064062b21a7ffd0aaac80ae06dca \
  6f6fb7ac68b84866e21201387d6d131eb9e7da00cf6d28ebb7e2886e39746bf3 \
  dcc4d01375128b7ca9b7cfc2b8bc80e4a2631e0d2c547f2b05282c1a2af2e615 \
  05e658f73762c0a36a9008fb004117fce73a027394e1454262823152fde7c732 \
  4ce4de40958bf90351e8366aa331ec075f0860aca8608933e77189eb0655dc3d \
  aa0fc357a48b45817c022132d0ee49fd5c399fa2699a79843e28ffd22ff92589; do
  want_in_file "$compute" "$sha" "sha256 $sha"
done
# The clone is verified against the tag commit, not just the tag name.
if grep -Eq 'rev-parse HEAD.*f03e9bf2|f03e9bf2.*rev-parse HEAD' <(tr '\n\\' '  ' <"$compute"); then
  ok "clone checked against the tag commit"
else
  fail "compute-node.Dockerfile does not compare 'git rev-parse HEAD' with the tag commit"
fi

want_in_file "$root/build-tools/Dockerfile" "ENV SQL_EXPORTER_VERSION=0.24.11" "build-tools sql_exporter pin"

if [[ "$fails" -ne 0 ]]; then
  echo "$fails check(s) failed" >&2
  exit 1
fi
echo "all x5 checks passed"
