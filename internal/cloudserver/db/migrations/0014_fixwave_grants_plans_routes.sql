-- 0014_fixwave_grants_plans_routes.sql — the schema half of the Sol group-review
-- fix wave (findings F9, F10, F12).
--
-- Three unrelated-looking changes ride together because they are one review
-- round's dispositions and one deploy:
--
--   F12  account_plans gains a real NO-OVERLAP exclusion constraint. 0012's
--        partial unique index only forbids two OPEN rows; two FINITE rows could
--        overlap freely, so a scheduled assignment could sit inside a running
--        one and resolvePlanTx's "ORDER BY effective_from DESC LIMIT 1" would
--        silently pick one of two equally-valid answers.
--
--   F10  route_registry gains an `environment` discriminator so the fixture-only
--        proving lane and the production worker operate on DISJOINT route sets.
--        Before this, `observer-cloud prove` accepted any ACTIVE route — the
--        production one included — and the attestation records it wrote are the
--        same rows the worker's gate reads.
--
--   F9   the portal consent screen gets real server state: a per-(account,
--        purpose) choice row plus an append-only change log, so a signed-in
--        developer's choices survive a reload, a new browser, and a support
--        question about what they actually agreed to.

-- ---------------------------------------------------------------------------
-- F12 — account_plans: no overlapping assignment windows, ever
-- ---------------------------------------------------------------------------
--
-- btree_gist is what lets a GiST exclusion constraint carry the plain-equality
-- account_id operand alongside the range-overlap one. It is a stock contrib
-- extension (present on Azure Database for PostgreSQL Flexible Server's
-- allow-list) and creating it is idempotent.
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- The half-open range [effective_from, effective_until) — an open row extends to
-- 'infinity' — must not overlap another row for the same account. This SUBSUMES
-- 0012's account_plans_one_open index (two open rows are two [x, infinity)
-- ranges, which always overlap); that index is kept because it names the
-- specific invariant and gives a clearer error, and a redundant guard on a
-- correctness rule is not a cost worth optimizing away.
--
-- AssignPlan's normal path stays legal: it CLOSES the running row (UPDATE
-- ... SET effective_until = start) and only then INSERTs the new row starting at
-- exactly that instant. The constraint is checked per STATEMENT, the update runs
-- first, and half-open ranges make [openFrom, start) and [start, infinity)
-- disjoint — so the close-then-open pair does not self-conflict.
ALTER TABLE account_plans
    ADD CONSTRAINT account_plans_no_overlap
    EXCLUDE USING gist (
        account_id WITH =,
        tstzrange(effective_from, coalesce(effective_until, 'infinity'::timestamptz)) WITH &&
    );

-- ---------------------------------------------------------------------------
-- F10 — route_registry.environment: the prove lane and the worker are disjoint
-- ---------------------------------------------------------------------------
--
-- DEFAULT 'production' is the fail-closed direction for BOTH readers: an
-- existing route (and any route an operator forgets to classify) is production,
-- which the worker will serve and the proving lane will REFUSE. A route only
-- becomes provable when an operator deliberately marks it 'nonproduction', and
-- at that moment the worker starts refusing it. The two sets can never intersect,
-- which is precisely why the two lanes may keep sharing the provider_attestations
-- cache: a cached record is keyed by route_id, and no route_id is readable by
-- both lanes.
ALTER TABLE route_registry
    ADD COLUMN environment text NOT NULL DEFAULT 'production'
        CHECK (environment IN ('production', 'nonproduction'));

-- ---------------------------------------------------------------------------
-- F9 — portal consent state (TENANT)
-- ---------------------------------------------------------------------------
--
-- SCOPE, stated once here so nobody later "unifies" these with the node's
-- consent: these rows are PORTAL-plane preferences. They record what the
-- signed-in developer chose on the browser consent screen, and they gate
-- SERVER-SIDE surfaces. They are NOT the authority for what a node may upload —
-- node egress consent is NODE-authoritative (the node holds the grant, declares
-- its generation on every upload, and the server validates against its
-- structural_grants REGISTRATION, which follows the node's declared generation
-- monotonically). Neither table is read by the upload path.
CREATE TABLE portal_consent_choices (
    account_id uuid    NOT NULL REFERENCES accounts(account_id),
    -- A cloudcontract Purpose id. Text rather than an enum: the vocabulary lives
    -- in Go (cloudcontract.AllPurposes) and the API validates against the
    -- OFFERED subset before writing, so a DB enum would be a second owner of a
    -- vocabulary that already has one.
    purpose    text    NOT NULL,
    granted    boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, purpose)
);

ALTER TABLE portal_consent_choices ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_consent_choices FORCE ROW LEVEL SECURITY;
CREATE POLICY portal_consent_choices_tenant ON portal_consent_choices
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- The append-only trail. The choices table holds the CURRENT answer; this holds
-- how it got there, so "when did I turn that off" is answerable from the data
-- rather than from a log line. One row per actual CHANGE (an unchanged purpose
-- in a re-submitted choice set appends nothing), which keeps the trail a history
-- of decisions rather than of page loads.
CREATE TABLE portal_consent_events (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(account_id),
    purpose    text NOT NULL,
    action     text NOT NULL CHECK (action IN ('granted', 'revoked')),
    at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX portal_consent_events_account_at
    ON portal_consent_events (account_id, at DESC);

ALTER TABLE portal_consent_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_consent_events FORCE ROW LEVEL SECURITY;
CREATE POLICY portal_consent_events_tenant ON portal_consent_events
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- Grants. The choices table takes full DML: it is the developer's live
-- preference and account deletion purges it. The events table is APPEND-ONLY BY
-- PRIVILEGE (no UPDATE, no DELETE) exactly like analysis_usage_ledger and for
-- the same reason as consent_events: a consent audit trail that the application
-- can rewrite is not an audit trail.
GRANT SELECT, INSERT, UPDATE, DELETE ON portal_consent_choices TO sbci_app;
GRANT SELECT, INSERT ON portal_consent_events TO sbci_app;
