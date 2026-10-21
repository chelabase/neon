\echo Use "ALTER EXTENSION f1_install_path UPDATE TO '1.1'" to load this file. \quit

CREATE OR REPLACE FUNCTION f1_install_path_version() RETURNS text
    LANGUAGE sql IMMUTABLE AS $$ SELECT '1.1' $$;
