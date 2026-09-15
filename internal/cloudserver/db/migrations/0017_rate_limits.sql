-- 0017_rate_limits.sql — shared fixed-window rate-limit counters (W6e).
--
-- The API used to keep these counters in each process's memory.  That is
-- correct for one replica, but every additional API replica multiplied the
-- effective cap.  This table and its SECURITY DEFINER function make one
-- counter authoritative for every replica while keeping the counter store
-- outside the tenant data model: the bucket/key are supplied by trusted API
-- code, and the function is the only application access path.
--
-- The function uses Unix-epoch-aligned windows.  A request exactly at a
-- boundary belongs to the new window, which makes the boundary deterministic
-- across replicas.  The API-facing wrapper takes no timestamp: it always uses
-- the database's clock_timestamp().  A separate, ungranted `_at` helper keeps
-- deterministic boundary tests/admin repair tooling possible without letting
-- sbci_api or sbci_app choose the clock used for an admission decision.

CREATE TABLE sbci_rate_limit_counters (
    bucket          text        NOT NULL,
    counter_key_hash text       NOT NULL,
    window_start    timestamptz NOT NULL,
    -- CHECK is >= 0, not > 0, so the admission function can seed a fresh row at
    -- 0 and let ONE uniform increment path advance it (0->1 fresh, n->n+1
    -- existing).  The 0 is only ever visible inside the admission transaction
    -- (the same statement UPDATEs it to >= 1 before commit) and never persists.
    -- Every persisted value is >= 1: an admitted hit is >= 1, the first-denial
    -- marker is limit+1, and the policy-decrease collapse is p_limit+1.
    hit_count       bigint      NOT NULL CHECK (hit_count >= 0),
    -- A retained over-cap marker is distinct from the admitted-hit count.  It
    -- lets a later policy increase recover the exact newly-added headroom
    -- rather than consuming one slot because `hit_count = old_limit + 1`.
    over_cap        boolean     NOT NULL DEFAULT false,
    expires_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (bucket, counter_key_hash, window_start),
    CHECK (octet_length(bucket) BETWEEN 1 AND 64),
    CHECK (counter_key_hash ~ '^[0-9a-f]{64}$')
);

-- The function removes prior windows for the key it touches and also sweeps a
-- bounded batch of expired rows on each call.  The latter bounds abandoned,
-- one-off keys that never receive a later request.
CREATE INDEX sbci_rate_limit_counters_expiry_idx
    ON sbci_rate_limit_counters (expires_at);

-- Only the SECURITY DEFINER owner gets table DML.  In particular, neither the
-- API role nor the worker role can read or mutate counters directly; this
-- prevents an accidental endpoint query from becoming a cross-key oracle.
GRANT SELECT, INSERT, UPDATE, DELETE ON sbci_rate_limit_counters TO sbci_defs;
REVOKE ALL ON sbci_rate_limit_counters FROM PUBLIC, sbci_app, sbci_api,
    sbci_worker, sbci_aggregator;

-- Deterministic/admin-only implementation.  No application role receives
-- EXECUTE: the public four-argument wrapper below is the sole runtime entry
-- point for sbci_api/sbci_app.
--
-- INVARIANT (ratified, W6e): a "limit N" window admits EXACTLY N requests; the
-- (N+1)th and every later request in the window is denied.  While over_cap is
-- false, hit_count is the number of ADMITTED hits so far (1-based: the first
-- admitted request stores hit_count=1).  On the first denial (the (N+1)th
-- request) the row stores the marker hit_count=N+1 with over_cap=true, and
-- repeated denials leave that marker unchanged so a hostile burst grows no
-- rows.  On a limit RAISE from N to M (M >= marker) the next request restores
-- the admitted count to marker-1 (= N), clears over_cap, and then admits
-- normally, so a raise admits exactly M-N new requests including that first
-- post-raise request.  A fresh key is seeded at hit_count=0 (see the table
-- CHECK note) so its first admitted request lands hit_count=1.
CREATE OR REPLACE FUNCTION sbci_rate_limit_at(
    p_bucket          text,
    p_counter_key_hash text,
    p_limit           integer,
    p_window_ms       bigint,
    p_now             timestamptz
)
RETURNS TABLE (
    allowed        boolean,
    retry_after_ms bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_now          timestamptz;
    v_window       interval;
    v_window_start timestamptz;
    v_count        bigint;
    v_over_cap     boolean;
    v_retry_ms     bigint;
BEGIN
    -- A disabled dimension must be a no-op.  Do this before validating the
    -- key/window so Store.AllowRateLimit can disable a dimension without a
    -- database round trip at all.
    IF p_limit <= 0 THEN
        allowed := true;
        retry_after_ms := 0;
        RETURN NEXT;
        RETURN;
    END IF;

    IF p_bucket IS NULL OR btrim(p_bucket) = ''
       OR octet_length(p_bucket) > 64 THEN
        RAISE EXCEPTION 'rate-limit bucket must be 1..64 bytes'
            USING ERRCODE = '22023';
    END IF;
    IF p_counter_key_hash IS NULL
       OR p_counter_key_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'rate-limit key hash must be 64 lowercase hexadecimal bytes'
            USING ERRCODE = '22023';
    END IF;
    IF p_window_ms IS NULL OR p_window_ms <= 0 THEN
        RAISE EXCEPTION 'rate-limit window must be positive milliseconds'
            USING ERRCODE = '22023';
    END IF;

    v_now := coalesce(p_now, clock_timestamp());
    -- Millisecond precision is the wire contract.  floor() is intentional:
    -- at exactly a window boundary the request is in the following window.
    v_window_start := to_timestamp((
        floor(extract(epoch FROM v_now) * 1000.0 / p_window_ms)
        * p_window_ms / 1000.0
    )::double precision);
    v_window := make_interval(secs => p_window_ms::double precision / 1000.0);

    -- Keep one current row per key in normal monotonic operation.  The
    -- retention predicate is scoped to this key so concurrent requests for
    -- unrelated keys never contend on old rows.
    DELETE FROM sbci_rate_limit_counters
     WHERE bucket = p_bucket
       AND counter_key_hash = p_counter_key_hash
       AND window_start < v_window_start;

    -- An abandoned key must not remain forever merely because it never gets
    -- another request.  A bounded SKIP LOCKED batch keeps this maintenance
    -- cheap on the hot path while ensuring active traffic eventually cleans
    -- old rows for every key.  Retention is at least one whole window, so an
    -- active counter cannot be removed before its window closes.
    WITH expired AS (
        SELECT ctid
          FROM sbci_rate_limit_counters
         WHERE expires_at <= v_now
         ORDER BY expires_at
         LIMIT 100
         FOR UPDATE SKIP LOCKED
    )
    DELETE FROM sbci_rate_limit_counters c
     USING expired
     WHERE c.ctid = expired.ctid;

    -- Seed the row, then lock it explicitly.  INSERT ... ON CONFLICT DO
    -- NOTHING handles the first concurrent writer; the SELECT FOR UPDATE is
    -- the single serialized admission point for both existing and newly
    -- inserted rows.
    -- Seed a fresh row at hit_count=0.  The admission branch below then applies
    -- ONE uniform increment (0->1 for this fresh row, n->n+1 for an existing
    -- one), so a "limit N" window admits exactly N requests.  Seeding at 1 would
    -- double-count the first request (it would also be incremented), making the
    -- window one request too strict.
    INSERT INTO sbci_rate_limit_counters
        (bucket, counter_key_hash, window_start, hit_count, over_cap,
         expires_at, updated_at)
    VALUES (p_bucket, p_counter_key_hash, v_window_start, 0, false,
            v_window_start + v_window + interval '1 hour', v_now)
    ON CONFLICT (bucket, counter_key_hash, window_start) DO NOTHING;

    SELECT c.hit_count, c.over_cap
      INTO v_count, v_over_cap
      FROM sbci_rate_limit_counters AS c
     WHERE c.bucket = p_bucket
       AND c.counter_key_hash = p_counter_key_hash
       AND c.window_start = v_window_start
     FOR UPDATE;

    -- The marker stores one count above the policy that produced the first
    -- denial and sets over_cap=true.  If the operator raises the limit to at
    -- least that marker, first restore the admitted-hit count (marker - 1),
    -- then process this request normally.  This means a raise from L to M
    -- admits exactly M-L new requests, including the request that first
    -- observes the raised policy.  Without the separate boolean, the marker
    -- would be indistinguishable from an ordinary admitted hit at the new
    -- limit and would consume one slot after every policy raise.
    IF v_over_cap THEN
        IF p_limit < v_count THEN
            allowed := false;
        ELSE
            v_count := v_count - 1;
            v_over_cap := false;
        END IF;
    END IF;

    IF v_over_cap THEN
        -- The current policy is still at or below the retained marker.
        NULL;
    ELSIF v_count < p_limit THEN
        v_count := v_count + 1;
        allowed := true;
    ELSIF v_count = p_limit THEN
        -- Retain exactly one marker for the first denied request.  Subsequent
        -- denials leave it unchanged, so a hostile burst cannot grow rows.
        v_count := v_count + 1;
        v_over_cap := true;
        allowed := false;
    ELSE
        -- A policy decrease can leave an ordinary admitted count above the new
        -- cap.  Collapse it to the new cap's marker and deny this request.
        v_count := p_limit + 1;
        v_over_cap := true;
        allowed := false;
    END IF;

    UPDATE sbci_rate_limit_counters
       SET hit_count = v_count,
           over_cap = v_over_cap,
           expires_at = v_window_start + v_window + interval '1 hour',
           updated_at = v_now
     WHERE bucket = p_bucket
       AND counter_key_hash = p_counter_key_hash
       AND window_start = v_window_start;

    IF allowed THEN
        retry_after_ms := 0;
    ELSE
        v_retry_ms := ceil(extract(epoch FROM
            (v_window_start + v_window - v_now)) * 1000.0)::bigint;
        IF v_retry_ms < 1 THEN
            v_retry_ms := 1;
        END IF;
        retry_after_ms := v_retry_ms;
    END IF;
    RETURN NEXT;
END$$;

ALTER FUNCTION sbci_rate_limit_at(text, text, integer, bigint, timestamptz)
    OWNER TO sbci_defs;

REVOKE ALL ON FUNCTION sbci_rate_limit_at(text, text, integer, bigint, timestamptz)
    FROM PUBLIC, sbci_app, sbci_api, sbci_worker, sbci_aggregator;

-- Runtime API wrapper.  Its four-argument signature makes the database clock
-- authoritative: sbci_api/sbci_app have no callable path that accepts p_now.
CREATE OR REPLACE FUNCTION sbci_rate_limit(
    p_bucket           text,
    p_counter_key_hash text,
    p_limit            integer,
    p_window_ms        bigint
)
RETURNS TABLE (
    allowed        boolean,
    retry_after_ms bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT *
      FROM sbci_rate_limit_at(
          p_bucket, p_counter_key_hash, p_limit, p_window_ms,
          clock_timestamp()
      )
$$;

ALTER FUNCTION sbci_rate_limit(text, text, integer, bigint)
    OWNER TO sbci_defs;

REVOKE ALL ON FUNCTION sbci_rate_limit(text, text, integer, bigint)
    FROM PUBLIC, sbci_worker, sbci_aggregator;
GRANT EXECUTE ON FUNCTION sbci_rate_limit(text, text, integer, bigint)
    TO sbci_api, sbci_app;

COMMENT ON FUNCTION sbci_rate_limit(text, text, integer, bigint)
    IS 'W6e atomic Unix-epoch fixed-window admission counter; server clock authoritative; only sbci_api/sbci_app may execute it';

COMMENT ON FUNCTION sbci_rate_limit_at(text, text, integer, bigint, timestamptz)
    IS 'W6e deterministic/admin-only counter implementation; application roles must use sbci_rate_limit()';
