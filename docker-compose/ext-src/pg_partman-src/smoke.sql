-- A native time-partitioned parent: create_parent, premade children, routing, maintenance.
CREATE TABLE public.events (
    id bigint GENERATED ALWAYS AS IDENTITY,
    ts timestamptz NOT NULL,
    payload text
) PARTITION BY RANGE (ts);

SELECT partman.create_parent(
    p_parent_table := 'public.events',
    p_control := 'ts',
    p_interval := '1 day',
    p_premake := 3
);

INSERT INTO public.events (ts, payload) VALUES (now(), 'now'), (now() + interval '1 day', 'tomorrow');

SELECT partman.run_maintenance();

DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM partman.part_config WHERE parent_table = 'public.events';
    IF n <> 1 THEN
        RAISE EXCEPTION 'public.events is not registered in part_config (% rows)', n;
    END IF;

    SELECT count(*) INTO n
    FROM pg_inherits
    WHERE inhparent = 'public.events'::regclass;
    IF n < 4 THEN
        RAISE EXCEPTION 'expected at least 4 partitions (premake 3 plus the current one), got %', n;
    END IF;

    SELECT count(*) INTO n FROM public.events;
    IF n <> 2 THEN
        RAISE EXCEPTION 'expected 2 rows in public.events, got %', n;
    END IF;
END
$$;
