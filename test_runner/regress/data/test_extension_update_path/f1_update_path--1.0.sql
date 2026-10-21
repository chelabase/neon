\echo Use "CREATE EXTENSION f1_update_path" to load this file. \quit

CREATE FUNCTION f1_update_path_version() RETURNS text
    LANGUAGE sql IMMUTABLE AS $$ SELECT '1.0' $$;
