-- 0039_plan_v2_allowances_and_plan_routes.sql - plan v2 allowances + the
-- per-plan model route (cloud-service allowance/routing change, 2026-09-15).
--
-- WHAT MOVES
--
--   free v2       daily 5 -> 20. Monthly 100 is KEPT, concurrency 2 is kept,
--                 and route_id stays NULL: free keeps resolving the feature's
--                 DEFAULT route (Luna), exactly as today.
--   plus_beta v2  daily 25 kept, monthly 500 -> 60, concurrency 4 kept, and
--                 route_id is PINNED to the new 'session_enrichment.sol.v1'
--                 route (deployment gpt-5.6-sol).
--
-- Plan rows are IMMUTABLE (0012's sbci_plans_immutable trigger): a change is a
-- NEW version row, never an UPDATE. Both plans therefore land as v2 and their
-- v1 rows stay byte-for-byte as they were, so any assignment still pointing at
-- v1 keeps resolving exactly what it resolved yesterday. Every column this
-- migration does not deliberately move (label, budget_pool, digest_weekly,
-- results_retention_days) is COPIED from the v1 row by INSERT ... SELECT, so a
-- later column addition cannot be silently dropped on the floor here.
--
-- WHY 60 ON PLUS. 60 is a COST cap, not a generosity dial. An enrichment on
-- gpt-5.6-sol costs roughly $0.10-$0.15 at the $5 / $30 per-MTok public rates,
-- so 60 enrichments is about $9 of COGS at FULL use against a $15 plan. Plus
-- deliberately buys a MORE CAPABLE model with FEWER runs; free buys more runs
-- on the cheaper default route. It is a plain plan-row value, so an operator
-- who wants to raise it publishes a v3 row - no code change, no deploy.
--
-- THE SOL ROUTE SHIPS INACTIVE AND UNBOUND, ON PURPOSE. Production enrichment
-- is LIVE for paying users on the bound + attested Luna route, and the
-- production Foundry resource (sbci-prod-foundry) has NO gpt-5.6-sol deployment
-- yet (staging, sbci-staging-foundry35022, does). So this row lands with
-- active=false, no endpoint and no api_version, and
-- store.ResolveRouteForPlan DEGRADES a plan pinned to a route that is inactive,
-- unbound or feature-mismatched to the FEATURE DEFAULT (Luna) while emitting an
-- observable plan_route_unavailable fallback signal. A paid plan degrades to
-- the default model; it never degrades to no service. Applying this migration
-- on production therefore changes NOTHING about which model serves a Plus job -
-- only the allowance moves - and the switch-on later is a single
-- `UPDATE route_registry SET active = true WHERE route_id =
-- 'session_enrichment.sol.v1'` once the deployment exists, is bound
-- (store.SetRouteBinding) and attests.
--
-- PRIVILEGE NOTE. The account_plans DML at the bottom is the same shape as
-- 0012's `UPDATE entitlements SET overrides_plan = false` - DML on a
-- FORCE-ROW-LEVEL-SECURITY tenant table from the migrator's connection - and
-- needs the same privilege that migration already required. No new grant is
-- introduced by this file: plans / route_registry / kill_switches are granted
-- at TABLE level (0004, 0012, 0015, 0037), so a new COLUMN and new ROWS are
-- covered by the existing grants.

-- ---------------------------------------------------------------------------
-- 1) plans.route_id - the route a plan's jobs are routed to.
-- ---------------------------------------------------------------------------
--
-- NULL = "use the feature's default route", which is what every plan that
-- predates this column means and what free v2 keeps meaning.
--
-- Deliberately NOT a foreign key, for exactly the reason 0012 gives for
-- budget_pool: a plan row is an immutable catalogue entry while a route row is
-- operational state (it is bound, rebound, deactivated, generation-bumped), and
-- an FK would let ordinary route maintenance fail against the immutable
-- catalogue. store.ResolveRouteForPlan fails CLOSED instead - a pinned route
-- that is missing, inactive or belongs to another feature is an error, never a
-- silent fallback to a different (cheaper, weaker) model for a paid plan.
ALTER TABLE plans ADD COLUMN route_id text;

-- ---------------------------------------------------------------------------
-- 2) route_registry.plan_pinned - a plan-pinned route is never a feature default
-- ---------------------------------------------------------------------------
--
-- store.ResolveRoute picks a feature's default with
-- `WHERE feature = $1 AND active ORDER BY route_version DESC LIMIT 1`. The Sol
-- row is inactive today, but the DAY IT IS ACTIVATED there would be two active
-- session_enrichment routes at the same route_version and that ordering becomes
-- a coin flip - a coin that decides whether a FREE account is served by Luna or
-- by the expensive Sol deployment. This flag is the marker that resolves it: a
-- route that exists only to be pinned by a plan is excluded from the default
-- pick, so the default stays Luna no matter how many plan routes are added
-- later. DEFAULT false keeps every existing route (Luna included) a default
-- candidate.
ALTER TABLE route_registry ADD COLUMN plan_pinned boolean NOT NULL DEFAULT false;

-- The Sol route. Chat Completions dialect like Luna; 4096 max output tokens
-- because REASONING tokens are billed and counted as completion tokens on this
-- dialect, so Luna's 1024 would truncate a Sol answer mid-structure.
-- active=false and the binding columns (endpoint / api_version) empty ⇒ Plus
-- keeps being served by the Luna default until an operator deploys, binds,
-- attests and activates it (see the header). Prices are the public $5 / $30
-- per-MTok snapshot the 120/month cost cap above is computed from (same shape as
-- 0005's Luna snapshot; price_version stays 'unset' until the operator stamps a
-- real cut).
INSERT INTO route_registry (
    route_id, feature, deployment, dialect, route_version, prompt_version,
    price_version, active, plan_pinned, max_output_tokens,
    input_price_per_mtok, output_price_per_mtok)
VALUES (
    'session_enrichment.sol.v1', 'session_enrichment', 'gpt-5.6-sol', 'chat_completions', 1, 1,
    'unset', false, true, 4096,
    5.0, 30.0)
ON CONFLICT (route_id) DO NOTHING;

-- Per-route kill switch, default OFF (0004's pattern: every route has one, and
-- store.KillSwitches treats a MISSING sentinel as ACTIVE/paused).
INSERT INTO kill_switches (scope, key, active, generation)
    VALUES ('route', 'session_enrichment.sol.v1', false, 0)
    ON CONFLICT (scope, key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3) The v2 plan rows.
-- ---------------------------------------------------------------------------
INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap,
                   budget_pool, digest_weekly, results_retention_days, route_id)
SELECT 'free', 2, p.label, 20, 100, 2,
       p.budget_pool, p.digest_weekly, p.results_retention_days, NULL
  FROM plans p
 WHERE p.name = 'free' AND p.version = 1
ON CONFLICT (name, version) DO NOTHING;

INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap,
                   budget_pool, digest_weekly, results_retention_days, route_id)
SELECT 'plus_beta', 2, p.label, 25, 120, 4,
       p.budget_pool, p.digest_weekly, p.results_retention_days, 'session_enrichment.sol.v1'
  FROM plans p
 WHERE p.name = 'plus_beta' AND p.version = 1
ON CONFLICT (name, version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 4) Move the accounts that are ON plus_beta v1 right now to v2.
-- ---------------------------------------------------------------------------
--
-- Free accounts need nothing: an account with no assignment resolves
-- store.DefaultFreePlanVersion, which this change bumps to 2 in the same
-- commit. Paying subscribers DO have an account_plans row pinned to the
-- immutable v1 plan_id, so without this they would keep the old 500/month
-- allowance and the old (default, Luna) route until someone re-assigned them -
-- and the moment that "someone" is a code deploy, it is a race. This closes it
-- in the same transaction that publishes v2.
--
-- Shape: close the in-force row at now(), then open a v2 row at exactly now(),
-- PRESERVING the closed row's own effective_until. Preserving it is what keeps
-- an account with a pending scheduled change (a cancellation's cycle-boundary
-- downgrade to free, say) legal against account_plans_no_overlap - the new row
-- ends where the old one was already going to end, instead of running to
-- infinity straight through the scheduled row. now() is transaction_timestamp,
-- so every statement below sees the identical instant.
--
-- The staging table carries the OLD effective_until across the UPDATE, which is
-- the one thing a PG16 `UPDATE ... RETURNING` cannot give us (no OLD.* until
-- PG18) and which a single data-modifying CTE cannot do safely against an
-- exclusion constraint.
CREATE TEMP TABLE sbci_0039_plus_moves ON COMMIT DROP AS
SELECT ap.id, ap.account_id, ap.source, ap.effective_until AS old_until
  FROM account_plans ap
  JOIN plans p ON p.plan_id = ap.plan_id
 WHERE p.name = 'plus_beta'
   AND p.version = 1
   -- Strictly BEFORE now(): closing a row at its own effective_from would
   -- violate 0012's CHECK (effective_until > effective_from). Unreachable in
   -- practice (a committed row's timestamp always precedes this transaction),
   -- and skipping is the safe direction if it ever were reachable.
   AND ap.effective_from < now()
   AND (ap.effective_until IS NULL OR ap.effective_until > now());

UPDATE account_plans
   SET effective_until = now()
 WHERE id IN (SELECT id FROM sbci_0039_plus_moves);

INSERT INTO account_plans (account_id, plan_id, effective_from, effective_until, source)
SELECT m.account_id, v2.plan_id, now(), m.old_until, m.source
  FROM sbci_0039_plus_moves m
 CROSS JOIN (SELECT plan_id FROM plans WHERE name = 'plus_beta' AND version = 2) v2;
