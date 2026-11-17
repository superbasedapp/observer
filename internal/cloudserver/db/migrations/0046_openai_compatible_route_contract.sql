-- 0046_openai_compatible_route_contract.sql - step 2 of 2 for the
-- openai_compatible dialect and the gpt-oss-120b route (0045 has the why).
--
-- step: contract
--
-- Contract: it drops the old route_registry_dialect_check, which the release
-- before 0045 relies on to refuse unknown dialects; the widened
-- route_registry_dialect_check_v2 (0045) replaces it and is validated here.
-- Applying it to the production cloud database needs the operator's go.
-- route_registry holds a handful of rows, so the validation is instant.
--
-- Then the route row and its kill switch (seed INSERTs, allowed in any step),
-- shipped INACTIVE and UNBOUND as 0045's header describes. The operator binds
-- and activates it with
--   observer-cloud route bind-openai-compatible --activate

SET LOCAL lock_timeout = '5s';

ALTER TABLE route_registry DROP CONSTRAINT IF EXISTS route_registry_dialect_check;
ALTER TABLE route_registry VALIDATE CONSTRAINT route_registry_dialect_check_v2;

INSERT INTO route_registry (
    route_id, feature, deployment, dialect, route_version, prompt_version,
    price_version, active, plan_pinned, max_output_tokens,
    input_price_per_mtok, output_price_per_mtok)
VALUES (
    'session_enrichment.gpt-oss-120b.v1', 'session_enrichment', 'gpt-oss-120b', 'openai_compatible', 4, 1,
    'unset', false, false, 4096,
    0, 0)
ON CONFLICT (route_id) DO NOTHING;

-- Per-route kill switch, default OFF (0004's pattern; store.KillSwitches
-- treats a MISSING sentinel as ACTIVE/paused, so every route needs one).
INSERT INTO kill_switches (scope, key, active, generation)
    VALUES ('route', 'session_enrichment.gpt-oss-120b.v1', false, 0)
    ON CONFLICT (scope, key) DO NOTHING;
