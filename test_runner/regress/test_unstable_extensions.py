from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from psycopg2.errors import InsufficientPrivilege

if TYPE_CHECKING:
    from fixtures.neon_fixtures import NeonEnv


def test_unstable_extensions_installation(neon_simple_env: NeonEnv):
    """
    Test that the unstable extension support within the neon extension can
    block extension installation.
    """
    env = neon_simple_env

    neon_unstable_extensions = "pg_prewarm,amcheck"

    endpoint = env.endpoints.create(
        "main",
        config_lines=[
            "neon.allow_unstable_extensions=false",
            f"neon.unstable_extensions='{neon_unstable_extensions}'",
        ],
    )
    endpoint.respec(skip_pg_catalog_updates=False)
    endpoint.start()

    with endpoint.cursor() as cursor:
        cursor.execute("SELECT current_setting('neon.unstable_extensions')")
        result = cursor.fetchone()
        assert result is not None
        setting = cast("str", result[0])
        assert setting == neon_unstable_extensions

        with pytest.raises(InsufficientPrivilege):
            cursor.execute("CREATE EXTENSION pg_prewarm")

        with pytest.raises(InsufficientPrivilege):
            cursor.execute("CREATE EXTENSION amcheck")

        # Make sure that we can install a "stable" extension
        cursor.execute("CREATE EXTENSION pageinspect")

        cursor.execute("BEGIN")
        cursor.execute("SET neon.allow_unstable_extensions TO true")
        cursor.execute("CREATE EXTENSION pg_prewarm")
        cursor.execute("COMMIT")


def test_owner_cannot_allow_unstable_extensions(neon_simple_env: NeonEnv):
    """
    RT4-1: `neon.allow_unstable_extensions` is `PGC_SUSET`. The database owner
    (a spec role, so a `neon_superuser` member, as the owner of a Chelabase
    database is) can't turn it on in any way: not with `SET`, `SET LOCAL`,
    `set_config()`, nor per role or per database. Only a superuser can.
    """
    env = neon_simple_env

    endpoint = env.endpoints.create(
        "main",
        config_lines=[
            "neon.allow_unstable_extensions=false",
            "neon.unstable_extensions='pg_prewarm'",
        ],
    )
    endpoint.start()
    # The owner is made by compute_ctl from the spec, with the grants a real
    # owner gets (`neon_superuser`).
    endpoint.respec_deep(
        **{
            "spec": {
                "skip_pg_catalog_updates": False,
                "cluster": {"roles": [{"name": "k5_owner", "options": []}]},
            },
        }
    )
    endpoint.reconfigure()

    with endpoint.cursor(user="k5_owner") as cur:
        # A plain `SET` by the owner is refused.
        with pytest.raises(InsufficientPrivilege):
            cur.execute("SET neon.allow_unstable_extensions TO true")

    with endpoint.cursor(user="k5_owner") as cur:
        cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        assert cur.fetchone() == (False,)
        cur.execute("SELECT context FROM pg_settings WHERE name = 'neon.allow_unstable_extensions'")
        assert cur.fetchone() == ("superuser",)

        # A database the owner owns, so `ALTER DATABASE` is refused for the
        # setting, not for the ownership.
        cur.execute("CREATE DATABASE k5_owned")
        for statement in [
            "SET LOCAL neon.allow_unstable_extensions TO on",
            "SELECT set_config('neon.allow_unstable_extensions', 'on', false)",
            "SELECT set_config('neon.allow_unstable_extensions', 'on', true)",
            "ALTER ROLE k5_owner SET neon.allow_unstable_extensions = on",
            "ALTER ROLE k5_owner IN DATABASE k5_owned SET neon.allow_unstable_extensions = on",
            "ALTER DATABASE k5_owned SET neon.allow_unstable_extensions = on",
            "GRANT SET ON PARAMETER neon.allow_unstable_extensions TO k5_owner",
        ]:
            cur.execute("BEGIN")
            with pytest.raises(InsufficientPrivilege):
                cur.execute(statement)
            cur.execute("ROLLBACK")

        cur.execute("SHOW neon.allow_unstable_extensions")
        assert cur.fetchone() == ("off",)
        # The setting stays off, so an unstable extension stays out of reach.
        with pytest.raises(InsufficientPrivilege):
            cur.execute("CREATE EXTENSION pg_prewarm")

    # A new session of the owner starts with it off too (nothing was stored
    # for the role or the database).
    with endpoint.cursor(user="k5_owner") as cur:
        cur.execute("SHOW neon.allow_unstable_extensions")
        assert cur.fetchone() == ("off",)

    # A superuser still can (`cloud_admin`, as the first test does).
    with endpoint.cursor() as cur:
        cur.execute("BEGIN")
        cur.execute("SET LOCAL neon.allow_unstable_extensions TO true")
        cur.execute("SHOW neon.allow_unstable_extensions")
        assert cur.fetchone() == ("on",)
        cur.execute("ROLLBACK")
