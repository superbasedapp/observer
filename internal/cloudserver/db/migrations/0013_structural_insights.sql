-- 0013_structural_insights.sql — the hosted half of the structural-insights
-- rail (cloud-intelligence divergence remediation plan rev 4.1, §3 W2 "Server
-- half"; operator ruling R1 for the standing-grant binding set).
--
-- Three tables, all TENANT (RLS ENABLE + FORCE + the sbci_current_account()
-- policy every 0002/0012 tenant table carries):
--
--   structural_snapshots       — the immutable per-device per-window snapshot,
--                                stored as the EXACT canonical bytes the node
--                                digested and uploaded. Never overwritten: a
--                                changed window is a new REVISION.
--   structural_grants          — the server-side registration of a STANDING
--                                consent grant, per account per purpose. See
--                                the "why a new table" note below.
--   structural_account_days    — the server-DERIVED account-day
--                                materialization the portal Overview reads,
--                                recomputed from the current snapshots of an
--                                (account, period) whenever a revision lands.
--
-- All three are account data: they purge with the account (the deletion
-- skeleton in internal/cloudserver/store/deletion.go enumerates them
-- explicitly), and the FK to accounts keeps 0002's default NO ACTION rather
-- than 0011's cascade, because how account DATA is removed stays the deletion
-- pipeline's explicit decision.
--
-- ---------------------------------------------------------------------------
-- Why structural_grants is a NEW table rather than an extension of
-- consent_receipts
-- ---------------------------------------------------------------------------
--
-- consent_receipts is the PER-UPLOAD receipt: `upload_digest text NOT NULL` is
-- its identity, ReceiptForDigest looks a row up BY that digest, and its whole
-- meaning is "these exact bytes were previewed and confirmed". A standing grant
-- is the opposite shape — it authorizes a SCHEMA for an open-ended series of
-- future windows, has no bytes to bind, is unique per (account, purpose)
-- rather than per digest, and needs a revocation column and the R1 binding set
-- (data-dictionary digest, declared timezone, source-window rule) that the
-- receipt table has nowhere to put.
--
-- Extending consent_receipts would have meant a nullable upload_digest (losing
-- the NOT NULL that makes the per-upload contract checkable), a second
-- interpretation of "most recent row for this account", and one table owning
-- two different consent shapes. A separate table keeps ONE owner per piece of
-- state (CLAUDE.md #4). The generation COUNTER is still the account-wide
-- accounts.consent_generation the node already reports — this table records
-- which generation a purpose's standing terms were last agreed at, it does not
-- mint a competing counter.

-- ---------------------------------------------------------------------------
-- structural_grants (TENANT) — standing-grant registration
-- ---------------------------------------------------------------------------
CREATE TABLE structural_grants (
    account_id             uuid NOT NULL REFERENCES accounts(account_id),
    -- The consent purpose this registration authorizes. It is derived
    -- SERVER-SIDE from the route the upload arrived on, never read from a
    -- client field: the route is single-purpose, so the purpose is a property
    -- of the endpoint rather than a claim the caller makes.
    purpose                text NOT NULL,
    -- The schema-level digest the grant binds (cloudcontract
    -- StructuralDataDictionaryDigest). A snapshot whose dictionary digest is
    -- not this one is not covered by this grant.
    data_dictionary_digest text NOT NULL,
    -- The snapshot schema version the terms were agreed against.
    schema_version         text NOT NULL,
    -- The monotonic consent generation the terms were last agreed at. A HIGHER
    -- generation on an arriving upload means the developer re-agreed newer
    -- terms and updates this row; a LOWER one is a stale client and is refused.
    consent_generation     bigint NOT NULL CHECK (consent_generation >= 1),
    -- The IANA zone that gives a window period its meaning, and the versioned
    -- rule naming WHICH activity the grant covers (R1's binding set).
    declared_timezone      text NOT NULL DEFAULT '',
    source_window_rule     text NOT NULL DEFAULT '',
    first_seen_at          timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    -- Set when the registration is withdrawn server-side (today: account
    -- deletion). A revoked registration refuses every upload; it is never
    -- silently re-registered by a later upload.
    revoked_at             timestamptz,
    PRIMARY KEY (account_id, purpose)
);

ALTER TABLE structural_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE structural_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY structural_grants_tenant ON structural_grants
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- ---------------------------------------------------------------------------
-- structural_snapshots (TENANT) — the immutable per-device window store
-- ---------------------------------------------------------------------------
CREATE TABLE structural_snapshots (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id          uuid NOT NULL REFERENCES accounts(account_id),
    -- The DEVICE the snapshot came from, taken from the authenticated
    -- proof-of-possession principal — never an envelope field.
    device_id           uuid NOT NULL,
    -- "YYYY-MM-DD" in the account's DECLARED timezone. Stored as text, not
    -- date, deliberately: the period string is inside the digested canonical
    -- bytes, so storing it verbatim keeps the row and the bytes provably in
    -- agreement (a date column would round-trip through Postgres' own
    -- formatting). ISO day strings sort lexicographically = chronologically,
    -- so ORDER BY period still means what it looks like.
    period              text NOT NULL CHECK (period ~ '^\d{4}-\d{2}-\d{2}$'),
    period_rule_version int  NOT NULL CHECK (period_rule_version >= 1),
    schema_version      text NOT NULL,
    revision            int  NOT NULL CHECK (revision >= 1),
    -- The snapshot's own NON-SELF-REFERENTIAL content digest, RECOMPUTED by the
    -- server from the received bytes. The client-declared value is never
    -- trusted (mirror of the two-digest check in api/jobs.go).
    digest              text NOT NULL,
    -- The exact canonical bytes received. Bounded: the schema's own limits
    -- (64 mix entries x 2 mixes, 64-byte keys, fixed scalar fields) put a real
    -- snapshot around 10 KiB, so 64 KiB is generous headroom AND a hard wall.
    canonical_bytes     bytea NOT NULL CHECK (octet_length(canonical_bytes) <= 65536),
    declared_timezone   text NOT NULL,
    -- RFC3339 max local event time included; '' for a window that carried none.
    source_watermark    text NOT NULL DEFAULT '',
    -- The consent generation the upload declared (what the developer had agreed
    -- to when this window was sent).
    consent_generation  bigint NOT NULL CHECK (consent_generation >= 1),
    received_at         timestamptz NOT NULL DEFAULT now(),
    -- NULL = this is the CURRENT snapshot for its window. Set either when a
    -- higher revision supersedes it, or AT INSERT when a lower revision arrives
    -- after a higher one (r2-before-r1): currency is decided by revision
    -- NUMBER, never by arrival order.
    superseded_at       timestamptz,
    PRIMARY KEY (id),
    UNIQUE (account_id, id),
    FOREIGN KEY (account_id, device_id) REFERENCES device_registrations(account_id, id),
    -- Idempotency, as a DATABASE constraint rather than application logic: the
    -- same window key + revision can exist exactly once.
    UNIQUE (account_id, device_id, period, period_rule_version, schema_version, revision)
);

-- Exactly ONE current row per window. This is what makes supersession
-- checkable: two writers cannot both leave a row un-superseded.
CREATE UNIQUE INDEX structural_snapshots_one_current
    ON structural_snapshots (account_id, device_id, period, period_rule_version, schema_version)
    WHERE superseded_at IS NULL;

-- The materialization recompute reads the current rows of one (account,
-- period); the portal reads a date range for an account.
CREATE INDEX structural_snapshots_account_period
    ON structural_snapshots (account_id, period);

-- Immutability, defense in depth (mirroring 0002's sbci_evidence_immutable_ttl
-- and 0012's sbci_plans_immutable): every column except superseded_at is frozen
-- once written, even for the table owner. A "correction" is a new revision.
CREATE OR REPLACE FUNCTION sbci_structural_snapshot_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.account_id, NEW.device_id, NEW.period, NEW.period_rule_version,
        NEW.schema_version, NEW.revision, NEW.digest, NEW.canonical_bytes,
        NEW.declared_timezone, NEW.source_watermark, NEW.consent_generation,
        NEW.received_at)
       IS DISTINCT FROM
       (OLD.account_id, OLD.device_id, OLD.period, OLD.period_rule_version,
        OLD.schema_version, OLD.revision, OLD.digest, OLD.canonical_bytes,
        OLD.declared_timezone, OLD.source_watermark, OLD.consent_generation,
        OLD.received_at)
    THEN
        RAISE EXCEPTION 'structural_snapshots rows are immutable (W2): only superseded_at may change — a changed window is a NEW revision';
    END IF;
    RETURN NEW;
END$$;

CREATE TRIGGER sbci_structural_snapshot_immutable
    BEFORE UPDATE ON structural_snapshots
    FOR EACH ROW EXECUTE FUNCTION sbci_structural_snapshot_immutable();

-- ---------------------------------------------------------------------------
-- structural_account_days (TENANT) — the server-derived account-day rollup
-- ---------------------------------------------------------------------------
--
-- It is a MATERIALIZATION, not a second source of truth: every column is
-- recomputed, in the same transaction as the insert, from the CURRENT snapshots
-- of that (account, period). The snapshots' canonical bytes remain the one
-- owner of the numbers; this table exists so the portal reads one indexed row
-- per day instead of parsing every device's bytes on every page load.
CREATE TABLE structural_account_days (
    account_id               uuid NOT NULL REFERENCES accounts(account_id),
    period                   text NOT NULL CHECK (period ~ '^\d{4}-\d{2}-\d{2}$'),
    -- How many DEVICES contributed a current snapshot to this day. It is the
    -- honesty qualifier for every other column: a day with one device is not
    -- the developer's whole day if they work on two machines.
    device_count             int    NOT NULL DEFAULT 0 CHECK (device_count >= 0),
    session_count            int    NOT NULL DEFAULT 0 CHECK (session_count >= 0),
    action_count             int    NOT NULL DEFAULT 0 CHECK (action_count >= 0),
    tokens_in                bigint NOT NULL DEFAULT 0 CHECK (tokens_in >= 0),
    tokens_out               bigint NOT NULL DEFAULT 0 CHECK (tokens_out >= 0),
    cache_read_tokens        bigint NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0),
    cost_usd                 double precision NOT NULL DEFAULT 0 CHECK (cost_usd >= 0),
    -- Merged categorical mixes: a JSON array of {"key":...,"count":...},
    -- key-ascending, counts summed across devices. jsonb rather than a child
    -- table because it is a bounded (<=64 entries) opaque display value that is
    -- always read whole and never joined.
    tool_mix                 jsonb  NOT NULL DEFAULT '[]'::jsonb,
    model_family_mix         jsonb  NOT NULL DEFAULT '[]'::jsonb,
    sessions_with_outcomes   int    NOT NULL DEFAULT 0 CHECK (sessions_with_outcomes >= 0),
    sessions_with_verification int  NOT NULL DEFAULT 0 CHECK (sessions_with_verification >= 0),
    -- Bands RE-DERIVED from the merged numerators over the merged session
    -- count, not averaged from the per-device bands (averaging bands would be
    -- arithmetic on a vocabulary).
    verification_coverage_band text NOT NULL DEFAULT 'none',
    outcome_evidence_band      text NOT NULL DEFAULT 'none',
    computed_at              timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, period)
);

ALTER TABLE structural_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE structural_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY structural_snapshots_tenant ON structural_snapshots
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

ALTER TABLE structural_account_days ENABLE ROW LEVEL SECURITY;
ALTER TABLE structural_account_days FORCE ROW LEVEL SECURITY;
CREATE POLICY structural_account_days_tenant ON structural_account_days
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
-- Full DML on all three (RLS still constrains each row). DELETE is granted
-- because account deletion purges these tables outright — unlike the consent
-- audit trail, a structural snapshot is the developer's own activity data with
-- no retention basis once the account is gone.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    structural_grants, structural_snapshots, structural_account_days
TO sbci_app;
