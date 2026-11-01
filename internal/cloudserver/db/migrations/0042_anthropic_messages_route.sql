-- 0042_anthropic_messages_route.sql - the Anthropic Messages dialect and the
-- Claude Haiku 5.5 enrichment route (operator ruling, lane CIHAIKU, 2026-10-20:
-- Azure is gone; Cloud Intelligence runs on ONE Oracle ARM box with an
-- Anthropic client on model claude-haiku-5-5, attestation in disclosed mode).
--
-- WHAT MOVES
--
--   dialect   route_registry.dialect's CHECK grows 'anthropic_messages' (the
--             SQL mirror of internal/cloudserver/inference's dialect table).
--   route     'session_enrichment.claude-haiku-5-5.v1' is a NEW route_registry
--             row: feature session_enrichment, deployment = the PUBLIC model id
--             'claude-haiku-5-5' (the anthropic_messages dialect declares
--             DeploymentIsModelID, so a call is priced from the shared pricing
--             table by that id), route_version 3 so the day it is activated it
--             outranks luna.v1 (1) and gpt-6-luna.v1 (2) in pickDefaultRoute by
--             version. plan_pinned = false: it is the FEATURE DEFAULT candidate.
--
-- WHY IT SHIPS INACTIVE AND UNBOUND. Exactly 0041's posture: a route that is
-- active but unbound would fail every admission (no credential, no attestation)
-- and 503 the fleet. The operator binds and activates it with
--   observer-cloud route bind-anthropic --activate
-- which writes the endpoint + api_version + the provider resource identity
-- ('anthropic:messages:claude-haiku-5-5', the value the disclosed attestation
-- is scoped to), stamps the per-MTok price snapshot FROM THE PRICING TABLE
-- (never a literal here), and flips active. The 7-step execution lease, the
-- kill switches and the credential-absence gate are unchanged.
--
-- PRICE SNAPSHOT. Deliberately 0 / 0 with price_version 'unset': the bind
-- command copies the current pricing-table row (internal/intelligence/cost,
-- pricing_snapshot.json) onto the route, and the worker prices each call from
-- that same table at completion time (jobs.Pricer), recording the table's
-- version on the result's provenance. Nothing in SQL hard-codes a rate.
--
-- max_output_tokens 4096: on Claude Haiku 5.5 adaptive thinking is on by
-- default and its tokens count against max_tokens, so the cap leaves room for
-- thinking plus the JSON answer. At the table's 0.50 USD per MTok output rate
-- the worst case is about 0.002 USD per call. A truncated answer is incomplete
-- JSON, rejected as invalid output, never stored.
--
-- PLANS ARE NOT TOUCHED. free v3 / plus_beta v3 still pin
-- 'session_enrichment.gpt-6-luna.v1' (0041). With that route inactive,
-- store.ResolveRouteForPlan degrades every submission to the feature default
-- (this route once active) and records the observable plan_route_unavailable
-- signal (reason 'inactive'). Re-pinning the plans is a separate plan-catalogue
-- migration, deferred so this one stays additive.
--
-- POSTGRES PORTABILITY. Nothing here (or anywhere in this lineage) needs an
-- Azure Flexible Server feature: the only extension the lineage uses is
-- btree_gist (0014), which ships in the stock postgres image's contrib.
--
-- PRIVILEGE NOTE. route_registry / kill_switches are granted at TABLE level
-- (0004/0015); no new grant.

ALTER TABLE route_registry DROP CONSTRAINT IF EXISTS route_registry_dialect_check;
ALTER TABLE route_registry ADD CONSTRAINT route_registry_dialect_check
    CHECK (dialect IN ('chat_completions', 'responses_store_false', 'anthropic_messages'));

INSERT INTO route_registry (
    route_id, feature, deployment, dialect, route_version, prompt_version,
    price_version, active, plan_pinned, max_output_tokens,
    input_price_per_mtok, output_price_per_mtok)
VALUES (
    'session_enrichment.claude-haiku-5-5.v1', 'session_enrichment', 'claude-haiku-5-5', 'anthropic_messages', 3, 1,
    'unset', false, false, 4096,
    0, 0)
ON CONFLICT (route_id) DO NOTHING;

-- Per-route kill switch, default OFF (0004's pattern; store.KillSwitches
-- treats a MISSING sentinel as ACTIVE/paused, so every route needs one).
INSERT INTO kill_switches (scope, key, active, generation)
    VALUES ('route', 'session_enrichment.claude-haiku-5-5.v1', false, 0)
    ON CONFLICT (scope, key) DO NOTHING;
