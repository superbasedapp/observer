-- 0045_openai_compatible_route.sql - step 1 of 2 for the openai_compatible
-- dialect and the gpt-oss-120b enrichment route on OVH AI Endpoints (managed-SaaS plan 07,
-- E1.1; operator answer D-3: AI Endpoints are paid by Startup credits).
--
-- step: expand
--
-- THIS STEP adds the widened dialect CHECK as route_registry_dialect_check_v2,
-- NOT VALID (migcheck: a CHECK is added NOT VALID and validated in a later
-- step). The old route_registry_dialect_check still holds until 0046 drops it,
-- so the running release is unaffected. 0046 (contract) drops the old check,
-- validates v2 and inserts the route. From 0046 on the dialect check is named
-- route_registry_dialect_check_v2; a later widening drops THAT name.
--
-- WHAT MOVES
--
--   dialect   route_registry.dialect's CHECK grows 'openai_compatible' (the
--             SQL mirror of internal/cloudserver/inference's dialect table).
--   route     'session_enrichment.gpt-oss-120b.v1' is a NEW route_registry
--             row: feature session_enrichment, deployment = the provider's
--             public model id 'gpt-oss-120b' (the openai_compatible dialect
--             declares DeploymentIsModelID), route_version 4 so the day it is
--             activated it outranks claude-haiku-5-5.v1 (3) in
--             pickDefaultRoute. plan_pinned = false: it is a FEATURE DEFAULT
--             candidate.
--
-- WHY IT SHIPS INACTIVE AND UNBOUND. 0042's posture: an active, unbound route
-- would fail every admission. The operator binds and activates it with
--   observer-cloud route bind-openai-compatible --activate
-- which writes the endpoint (OVH's https://oai.endpoints.kepler.ai.cloud.ovh.net/v1
-- by default), the provider resource identity the disclosed attestation is
-- scoped to ('openai_compatible:chat:gpt-oss-120b'), and the per-MTok price
-- snapshot FROM THE PRICING TABLE (never a literal here).
--
-- PRICE SNAPSHOT. 0 / 0 with price_version 'unset' until the bind, as 0042.
--
-- max_output_tokens 4096: gpt-oss is a reasoning model and its reasoning
-- tokens count against max_tokens (a 20-token live probe on 2026-11-13 spent
-- all 20 on reasoning and returned finish_reason length), so the cap leaves
-- room for reasoning plus the JSON answer. A truncated answer is incomplete
-- JSON, rejected as invalid output, never stored.
--
-- PRIVILEGE NOTE. route_registry / kill_switches are granted at TABLE level
-- (0004/0015); no new grant.

SET LOCAL lock_timeout = '5s';

ALTER TABLE route_registry ADD CONSTRAINT route_registry_dialect_check_v2
    CHECK (dialect IN ('chat_completions', 'responses_store_false', 'anthropic_messages', 'openai_compatible')) NOT VALID;
