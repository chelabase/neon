\echo Use "CREATE EXTENSION f1_install_path" to load this file. \quit

CREATE FUNCTION f1_install_path_version() RETURNS text
    LANGUAGE sql IMMUTABLE AS $$ SELECT '1.0' $$;
