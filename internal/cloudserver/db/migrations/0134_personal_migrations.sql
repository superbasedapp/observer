-- 0134_personal_migrations.sql - the ledger of `observer-cloud migrate-personal`,
-- the cloud half of stage E3 (managed-SaaS plan 06 section 9.4; plan 07 M9.3;
-- docs/plans/managed-saas/individuals/inventory.md D-IND-4, D-IND-5, D-IND-6;
-- docs/security.md IND-5).
--
-- step: expand
--
-- WHY. The control plane holds no credential to tenant data (plan 06 5.4), so
-- the cloud half moves each personal-plane account onto its personal org and
-- writes a bundle the operator carries to the tenant host. The run is long and
-- must survive a crash: every account's stage is recorded here before the run
-- moves on, so a rerun picks up where it stopped. One row per account.
--
-- STAGES (internal/cloudserver/personalmig.KnownStages, the stage machine is
-- there): planned -> org_ready -> rekeyed -> exported -> verified, plus
-- skipped with a reason. An account with no results to carry goes from
-- rekeyed straight to verified (nothing to import).
--
-- WHAT IS NOT HERE. No content: counts, the personal org, the re-keyed Paddle
-- subscription id, the bundle's SHA-256 and the tenant receipt's counts. The
-- error text is the command's own wording, bounded.
--
-- CLASS S (no row-level security), like the other operator-only system tables
-- (0094 account_team_org_limits, 0095 org_plan_grants): only the operator role
-- (sbci_app, the admin DSN `migrate-personal` connects with) reads and writes
-- it; sbci_api and sbci_worker hold nothing. No DELETE for any role: the rows
-- go with the account row when its tombstone is swept (ON DELETE CASCADE).
-- org_id has a foreign key with no cascade: orgs rows are never deleted.

SET LOCAL lock_timeout = '5s';

CREATE TABLE personal_migrations (
    account_id              uuid        NOT NULL PRIMARY KEY REFERENCES accounts (account_id) ON DELETE CASCADE,
    org_id                  uuid        REFERENCES orgs (org_id),
    stage                   text        NOT NULL
        CHECK (stage IN ('planned', 'org_ready', 'rekeyed', 'exported', 'verified', 'skipped')),
    skip_reason             text        CHECK (skip_reason IS NULL OR char_length(skip_reason) BETWEEN 1 AND 500),
    -- Results considered, exported and left out (by the personalmig result
    -- table: not a session result, superseded, tombstoned, invalid).
    results_total           integer     NOT NULL DEFAULT 0 CHECK (results_total >= 0),
    results_exported        integer     NOT NULL DEFAULT 0 CHECK (results_exported >= 0),
    results_skipped         integer     NOT NULL DEFAULT 0 CHECK (results_skipped >= 0),
    -- The Paddle subscription re-keyed onto the org; NULL when there was none.
    rekeyed_subscription_id text        CHECK (rekeyed_subscription_id IS NULL OR rekeyed_subscription_id <> ''),
    bundle_sha256           text        CHECK (bundle_sha256 IS NULL OR bundle_sha256 ~ '^[0-9a-f]{64}$'),
    -- The tenant receipt's counts (cloudcontract.PersonalImportReceipt),
    -- NULL until `verify` read one.
    receipt_inserted        integer     CHECK (receipt_inserted IS NULL OR receipt_inserted >= 0),
    receipt_already_present integer     CHECK (receipt_already_present IS NULL OR receipt_already_present >= 0),
    receipt_present         integer     CHECK (receipt_present IS NULL OR receipt_present >= 0),
    last_error              text        CHECK (last_error IS NULL OR char_length(last_error) BETWEEN 1 AND 1000),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT personal_migrations_skip_has_reason CHECK ((stage = 'skipped') = (skip_reason IS NOT NULL)),
    CONSTRAINT personal_migrations_org_after_planned CHECK (
        stage IN ('planned', 'skipped') OR org_id IS NOT NULL),
    CONSTRAINT personal_migrations_exported_has_bundle CHECK (
        stage <> 'exported' OR bundle_sha256 IS NOT NULL),
    CONSTRAINT personal_migrations_counts CHECK (results_exported + results_skipped <= results_total)
);

CREATE INDEX personal_migrations_stage ON personal_migrations (stage, account_id);

COMMENT ON TABLE personal_migrations IS
    'E3 (D-IND-4..6): one row per personal-plane account moved onto its personal org by observer-cloud migrate-personal; counts and digests only (class S).';

GRANT SELECT, INSERT, UPDATE ON personal_migrations TO sbci_app;
