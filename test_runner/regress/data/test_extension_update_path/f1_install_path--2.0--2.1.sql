\echo Use "ALTER EXTENSION f1_install_path UPDATE TO '2.1'" to load this file. \quit

CREATE OR REPLACE FUNCTION f1_install_path_version() RETURNS text
    LANGUAGE sql IMMUTABLE AS $$ SELECT '2.1' $$;
