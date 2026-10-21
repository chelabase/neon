-- A hypertable on a compute: creation, chunking, insert, time_bucket, the information views.
CREATE TABLE conditions (
    time timestamptz NOT NULL,
    device int NOT NULL,
    temp double precision
);
SELECT create_hypertable('conditions', 'time', chunk_time_interval => interval '1 day');

INSERT INTO conditions
SELECT t, d, 20 + d
FROM generate_series(timestamptz '2026-01-01 00:00+00', timestamptz '2026-01-05 00:00+00', interval '1 hour') AS t,
     generate_series(1, 3) AS d;

DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM conditions;
    IF n <> 291 THEN
        RAISE EXCEPTION 'expected 291 rows, got %', n;
    END IF;

    SELECT count(*) INTO n FROM timescaledb_information.hypertables WHERE hypertable_name = 'conditions';
    IF n <> 1 THEN
        RAISE EXCEPTION 'conditions is not listed as a hypertable (% rows)', n;
    END IF;

    SELECT count(*) INTO n FROM timescaledb_information.chunks WHERE hypertable_name = 'conditions';
    IF n < 4 THEN
        RAISE EXCEPTION 'expected at least 4 chunks, got %', n;
    END IF;

    SELECT count(DISTINCT time_bucket(interval '1 day', time)) INTO n FROM conditions;
    IF n < 4 THEN
        RAISE EXCEPTION 'expected at least 4 daily buckets, got %', n;
    END IF;
END
$$;
