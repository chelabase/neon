#!/usr/bin/env bash
# pg_partman on a compute: the installed extension is the pinned release (X4: 5.5.0), and a
# time-partitioned parent is set up and maintained. The upstream scripts under test/ need
# their own harness and are not run here.
set -ex
cd "$(dirname "${0}")"
expected_version="5.5.0"
dropdb --if-exists contrib_regression
createdb contrib_regression
psql -X -v ON_ERROR_STOP=1 -d contrib_regression -c "CREATE SCHEMA partman" -c "CREATE EXTENSION pg_partman SCHEMA partman"
version="$(psql -X -At -d contrib_regression -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_partman'")"
if [ "${version}" != "${expected_version}" ]; then
    echo "pg_partman extversion is '${version}', expected '${expected_version}'" >&2
    exit 1
fi
psql -X -v ON_ERROR_STOP=1 -d contrib_regression -f smoke.sql
