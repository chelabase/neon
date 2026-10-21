#!/usr/bin/env bash
# timescaledb on a compute: the installed extension is the pinned release (X4: 2.31.0), and a
# hypertable works end to end. The upstream suite needs timescaledb's own CMake build tree and
# is not run here.
set -ex
cd "$(dirname "${0}")"
expected_version="2.31.0"
dropdb --if-exists contrib_regression
createdb contrib_regression
psql -X -v ON_ERROR_STOP=1 -d contrib_regression -c "CREATE EXTENSION timescaledb"
version="$(psql -X -At -d contrib_regression -c "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'")"
if [ "${version}" != "${expected_version}" ]; then
    echo "timescaledb extversion is '${version}', expected '${expected_version}'" >&2
    exit 1
fi
psql -X -v ON_ERROR_STOP=1 -d contrib_regression -f smoke.sql
