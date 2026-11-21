-- 0078_enrichment_token_budgets.sql - enrichment data budgets in tokens
-- (managed-SaaS plan 07, ruling R-AI1 as adjusted and approved 2026-11-13).
--
-- step: expand
--
-- One step of two. This step adds the schema; 0079 publishes the plan
-- versions that use it and moves assignments onto them.
--
-- THE RULING. No cap on the NUMBER of sessions enriched; a cap on the DATA
-- used. Every account keeps a token budget per UTC day and per UTC month and
-- the concurrency cap; every session has a CUMULATIVE token budget across its
-- re-enrichments; every tier has an evidence budget (how much of one session
-- is sent). Free runs gpt-oss-20b, paid gpt-oss-120b, and all of it is
-- platform configuration. The pool's USD spend ceiling (0044) is unchanged.
--
-- WHAT MOVES
--
--   enrichment_tiers   SYSTEM table, the platform configuration ("meta
--                      layer"): tier -> (route id, evidence budget, session /
--                      daily / monthly token budgets). Versioned and
--                      immutable like plans: a change is a NEW (tier,
--                      version) row, published by the operator verb
--                      `observer-cloud tier set`, which refuses a route that
--                      is not active, bound, priced and attested. The highest
--                      version of a tier is in force. route_id is a foreign
--                      key, so a tier can only ever NAME a route_registry row:
--                      it carries no endpoint and no credential.
--   plans.enrichment_tier   nullable. NULL = the legacy count caps (every
--                      plan up to v4, unchanged); set = the tier's token
--                      budgets replace the plan's daily/monthly COUNT caps
--                      for session enrichment.
--   usage_token_windows  TENANT table: one lockable counter per (account,
--                      feature, daily|monthly, window key), committed tokens =
--                      settled actuals + open holds at their worst case.
--   usage_reservations.budget_unit / token_hold / session_pk   a token
--                      reservation records its unit, the tokens it holds and
--                      the session whose cumulative budget it charges, so a
--                      settle/release corrects exactly what it held.
--   cloud_sessions.enrichment_tokens_committed   the PER-SESSION ledger
--                      (cumulative across re-enrichments of the same cloud
--                      session id; see docs/cloud-intelligence.md).
--   route 'session_enrichment.gpt-oss-20b.v1'   the free tier's model on
--                      OVH AI Endpoints, plan_pinned (never a feature default
--                      by accident). Ships INACTIVE and UNBOUND like 0046's
--                      120b row: `observer-cloud route bind-openai-compatible
--                      --route-id session_enrichment.gpt-oss-20b.v1 --activate`
--                      binds it. Until then the free tier's jobs degrade to
--                      the feature default with the plan_route_unavailable
--                      signal (store.ResolveRouteForPlan), never to no service.
--
-- WHY THE PER-SESSION LEDGER IS A COLUMN ON cloud_sessions. The budget is
-- per (account, cloud session id), which is exactly that row's key; the
-- submit transaction already upserts and can lock it; account deletion
-- already purges it; RLS already confines it. A separate table would be a
-- second owner of the same identity.
--
-- PRIVILEGES. enrichment_tiers: sbci_api and sbci_worker read it (admission
-- and usage), sbci_app also inserts (the operator verb). usage_token_windows
-- mirrors usage_cycles: sbci_api reserves and deletes (account deletion),
-- sbci_worker reads and updates (settle/release), sbci_app holds full DML.
-- The worker gets a COLUMN-level UPDATE on cloud_sessions for the session
-- ledger only (settle/release), never on the session's other columns.

SET LOCAL lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- 1) The free tier's route (seed rows, allowed in any step).
-- ---------------------------------------------------------------------------
INSERT INTO route_registry (
    route_id, feature, deployment, dialect, route_version, prompt_version,
    price_version, active, plan_pinned, max_output_tokens,
    input_price_per_mtok, output_price_per_mtok)
VALUES (
    'session_enrichment.gpt-oss-20b.v1', 'session_enrichment', 'gpt-oss-20b', 'openai_compatible', 4, 1,
    'unset', false, true, 4096,
    0, 0)
ON CONFLICT (route_id) DO NOTHING;

INSERT INTO kill_switches (scope, key, active, generation)
    VALUES ('route', 'session_enrichment.gpt-oss-20b.v1', false, 0)
    ON CONFLICT (scope, key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2) enrichment_tiers (SYSTEM): the platform configuration.
-- ---------------------------------------------------------------------------
CREATE TABLE enrichment_tiers (
    tier                  text   NOT NULL CHECK (tier ~ '^[a-z][a-z0-9_]{0,31}$'),
    version               int    NOT NULL CHECK (version >= 1),
    route_id              text   NOT NULL REFERENCES route_registry(route_id),
    evidence_token_budget int    NOT NULL CHECK (evidence_token_budget BETWEEN 1000 AND 32000),
    session_token_budget  bigint NOT NULL CHECK (session_token_budget BETWEEN 1 AND 1000000000),
    daily_token_budget    bigint NOT NULL CHECK (daily_token_budget BETWEEN 1 AND 1000000000),
    monthly_token_budget  bigint NOT NULL CHECK (monthly_token_budget BETWEEN 1 AND 1000000000),
    published_by          text   NOT NULL DEFAULT 'migration',
    note                  text   NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tier, version),
    CHECK (monthly_token_budget >= daily_token_budget)
);

-- Immutability (0012's plans precedent, extended to DELETE: a published tier
-- version is the record of what every reservation under it was held to).
CREATE FUNCTION sbci_enrichment_tiers_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'enrichment_tiers rows are immutable (R-AI1): publish a new (tier, version) instead of changing %/%',
        OLD.tier, OLD.version;
END$$;

CREATE TRIGGER sbci_enrichment_tiers_immutable
    BEFORE UPDATE OR DELETE ON enrichment_tiers
    FOR EACH ROW EXECUTE FUNCTION sbci_enrichment_tiers_immutable();

GRANT SELECT         ON enrichment_tiers TO sbci_api;
GRANT SELECT         ON enrichment_tiers TO sbci_worker;
GRANT SELECT, INSERT ON enrichment_tiers TO sbci_app;

-- The defaults (S-3 "Recommended defaults"; the token budgets are the lead's
-- proposal, a ruling for the operator - see docs/cloud-intelligence.md).
-- One worst-case call at the evidence budget holds 13,360 tokens on free
-- and 25,744 on paid (enrichbudget.WorstCaseForEvidenceBudget), so each
-- session budget admits several re-enrichments and each daily budget many
-- sessions; a typical call books about 8k (free) / 17k (paid) at settle.
INSERT INTO enrichment_tiers (tier, version, route_id, evidence_token_budget,
                              session_token_budget, daily_token_budget, monthly_token_budget, note)
VALUES
    ('free', 1, 'session_enrichment.gpt-oss-20b.v1', 4000, 60000, 250000, 3000000,
     'R-AI1 default: gpt-oss-20b, 4,000 evidence tokens'),
    ('paid', 1, 'session_enrichment.gpt-oss-120b.v1', 12000, 200000, 1000000, 15000000,
     'R-AI1 default: gpt-oss-120b, 12,000 evidence tokens')
ON CONFLICT (tier, version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3) plans.enrichment_tier: which tier a plan version uses (NULL = legacy).
-- ---------------------------------------------------------------------------
ALTER TABLE plans ADD COLUMN enrichment_tier text;

-- ---------------------------------------------------------------------------
-- 4) usage_token_windows (TENANT): the per-account token windows.
-- ---------------------------------------------------------------------------
CREATE TABLE usage_token_windows (
    account_id       uuid   NOT NULL REFERENCES accounts(account_id),
    feature          text   NOT NULL,
    window_kind      text   NOT NULL CHECK (window_kind IN ('daily', 'monthly')),
    window_key       text   NOT NULL,
    committed_tokens bigint NOT NULL DEFAULT 0 CHECK (committed_tokens >= 0),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, feature, window_kind, window_key)
);

ALTER TABLE usage_token_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_token_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY usage_token_windows_tenant ON usage_token_windows
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

GRANT SELECT, INSERT, UPDATE, DELETE ON usage_token_windows TO sbci_api;
GRANT SELECT, UPDATE                 ON usage_token_windows TO sbci_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON usage_token_windows TO sbci_app;

-- ---------------------------------------------------------------------------
-- 5) Token reservations and the per-session ledger.
-- ---------------------------------------------------------------------------
ALTER TABLE usage_reservations ADD COLUMN budget_unit text NOT NULL DEFAULT 'count';
ALTER TABLE usage_reservations ADD COLUMN token_hold bigint NOT NULL DEFAULT 0;
ALTER TABLE usage_reservations ADD COLUMN session_pk uuid;

ALTER TABLE cloud_sessions ADD COLUMN enrichment_tokens_committed bigint NOT NULL DEFAULT 0;
GRANT UPDATE (enrichment_tokens_committed) ON cloud_sessions TO sbci_worker;
