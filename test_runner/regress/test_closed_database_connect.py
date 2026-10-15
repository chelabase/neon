from __future__ import annotations

from typing import TYPE_CHECKING

import psycopg2
import pytest
from fixtures.pg_version import PgVersion
from fixtures.utils import run_only_on_postgres

if TYPE_CHECKING:
    from fixtures.neon_fixtures import VanillaPostgres


@run_only_on_postgres([PgVersion.V17], "the connect rule is in the v17 fork only")
def test_a_superuser_connects_to_a_closed_non_template_database(vanilla_pg: VanillaPostgres):
    vanilla_pg.start()
    vanilla_pg.safe_psql("CREATE DATABASE c1")
    vanilla_pg.safe_psql("ALTER DATABASE c1 ALLOW_CONNECTIONS false")
    vanilla_pg.safe_psql("CREATE ROLE plain LOGIN")
    assert vanilla_pg.safe_psql("SELECT current_database()", dbname="c1")[0][0] == "c1"
    for kw in [{"dbname": "template0"}, {"dbname": "c1", "user": "plain"}]:
        with pytest.raises(psycopg2.OperationalError) as e:
            vanilla_pg.safe_psql("SELECT 1", **kw)
        assert "is not currently accepting connections" in str(e.value), kw
