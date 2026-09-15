-- 106_org_pricing_cache.sql -- the node's persisted copy of the ORG's signed
-- price document (docs/plans/enterprise-pricing-and-admin-assistant-plan-
-- 2026-09-08.md §3.3, allocated to wave W1; WRITTEN by W2).
--
-- ONE table, NODE-LOCAL, and its name is in tests/invariant/privacy_test.go's
-- forbidden set: it must never appear as a string literal inside
-- internal/store/orgpush.go. The direction is what makes that unambiguous --
-- this row is a document the SERVER authored and SIGNED, travelling
-- server -> node on GET /api/agent/pricing. The node's only contribution back
-- is the enum-only PricingSource / PricingVersion pair on
-- orgcontract.BudgetPostureRow (server migration 132's two columns), composed
-- the way updateposture.go composes the update posture. Naming this table on
-- the node -> server push wire would be both nonsensical and a boundary
-- violation -- the update_state/105 posture exactly.
--
-- WHY IT IS PERSISTED AT ALL, rather than the in-memory cache the sibling
-- budget rail uses (internal/orgclient/budgetpolicy.go): a mis-priced captured
-- turn is PERMANENT. api_turns.cost_usd is stamped at capture and there is no
-- retroactive re-pricing in this arc (ruling R8 / gap PRICE-REPRICE-1). A
-- restart that lost the org's rates would silently re-price every subsequent
-- turn at seed prices, and the budget the org enforces would be enforced
-- against numbers the org does not pay. A cap the node merely refuses to raise
-- for one poll is recoverable; a wrong dollar figure written into a row is not.
--
-- WHY A SINGLE-ROW TABLE (CHECK id = 1). The pricing document is FLEET-WIDE:
-- unlike the per-caller budget body, it binds no subject, so a node holds
-- exactly one of them and two rows would be two answers to "what prices is this
-- node applying". The row is created here so every reader can SELECT without a
-- NULL-vs-missing branch and so the first write is an UPDATE -- the
-- update_state/105 shape, and what lets store.SaveOrgPricing be the one writer.
--
-- WHAT IT STORES:
--   version              the document's monotonic version. Replay refusal
--                        (a body whose version is not strictly greater than the
--                        stored one is REFUSED) is its only consumer.
--   org_key_fingerprint  which TOFU-pinned org key verified this body. A body
--                        signed by a DIFFERENT key than the pinned one is
--                        refused, so recording the fingerprint that was
--                        accepted is what makes a later key rotation
--                        diagnosable instead of merely fatal.
--   body_json            the accepted document's canonical bytes -- the org's
--                        own signed document coming BACK, never node data going
--                        out. It is what the engine re-composes from on a cold
--                        start, before any fetch has succeeded.
--   fetched_at           when the 200 that produced this row landed.
--   state                the HTTP-ladder outcome the node last observed
--                        (verified | no_pricing | not_supported | auth_failed |
--                        channel_off | unreachable | unverified, plan §3.3).
--                        It is a closed enum in Go and is NOT declared as a
--                        CHECK here, deliberately: the vocabulary lives in one
--                        place (the orgclient ladder) and is normalised at the
--                        write seam, so a future member cannot be refused at
--                        write time by a constraint that would need its own
--                        migration -- the org_node_budget_posture/130
--                        rationale, mirrored.
--
-- Only a SIGNED body may ever EMPTY this table (plan §3.3 / N1): every non-200
-- path fails open onto whatever is stored here, and a 404 from a server that
-- predates the rail leaves it untouched. An unsigned signal that could clear it
-- would be a one-header lever to drop a whole fleet back to seed prices.
--
-- No paired SERVER migration: the org half is server migration 132
-- (org_model_prices / org_pricing_version), which shares no column with this.

CREATE TABLE IF NOT EXISTS org_pricing_cache (
    -- id is pinned to 1: this is the node's single applied pricing document.
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    version             INTEGER NOT NULL DEFAULT 0,
    org_key_fingerprint TEXT    NOT NULL DEFAULT '',
    body_json           TEXT    NOT NULL DEFAULT '',
    fetched_at          TEXT    NOT NULL DEFAULT '',
    state               TEXT    NOT NULL DEFAULT ''
);

INSERT INTO org_pricing_cache (id, version, org_key_fingerprint, body_json, fetched_at, state)
VALUES (1, 0, '', '', '', '')
ON CONFLICT (id) DO NOTHING;
