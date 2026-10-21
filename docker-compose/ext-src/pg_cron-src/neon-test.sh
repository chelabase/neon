#!/usr/bin/env bash
# pg_cron on a compute: the installed extension is the pinned release (X4: v1.6.8), then the
# upstream regression runs as before (the harness used `make installcheck` for this directory).
#
# The control file's default_version stays '1.6' across the 1.6.x releases, so extversion alone
# can't tell v1.6.8 from v1.6.4. cron.match_dom_and_dow exists from v1.6.8 on (a SIGHUP setting
# that is visible to superusers once pg_cron is in shared_preload_libraries).
set -ex
cd "$(dirname "${0}")"
expected_version="1.6"
dropdb --if-exists contrib_regression
createdb contrib_regression
psql -X -v ON_ERROR_STOP=1 -d contrib_regression -c "CREATE EXTENSION pg_cron"
version="$(psql -X -At -d contrib_regression -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_cron'")"
if [ "${version}" != "${expected_version}" ]; then
    echo "pg_cron extversion is '${version}', expected '${expected_version}'" >&2
    exit 1
fi
guc="$(psql -X -At -d contrib_regression -c "SELECT count(*) FROM pg_settings WHERE name = 'cron.match_dom_and_dow'")"
if [ "${guc}" != "1" ]; then
    echo "cron.match_dom_and_dow is missing (count ${guc}): the library is not v1.6.8 or is not preloaded" >&2
    exit 1
fi
USE_PGXS=1 make -C . installcheck
