-- 113_pricing_feed_cache.sql -- the STANDALONE node's persisted copy of the
-- PUBLIC pricing feed (docs/plans/pricing-sync-tokenomics-to-platform-plan-
-- 2026-09-11.md §C.3 / §H, Wave N).
--
-- ONE table, NODE-LOCAL, and its name is in tests/invariant/privacy_test.go's
-- forbidden set (forbiddenCacheTables): it must never appear as a string
-- literal inside internal/store/orgpush.go. The direction is what makes that
-- unambiguous -- this row is a document a PUBLIC publisher (the Tokenomics
-- platform) authored and SIGNED, travelling publisher -> node over
-- GET /api/pricing/v1/observer-pricing. It names no org and no subject, so it
-- is the SAME body for every consumer on earth; naming it on the node -> server
-- push wire would be both nonsensical and a boundary violation. The
-- org_pricing_cache / 106 posture, for the standalone case instead of the
-- enrolled one.
--
-- WHY ONLY A STANDALONE NODE EVER FILLS IT. An ENROLLED node (individual or
-- managed) ignores the public feed entirely -- its prices arrive through the
-- org rail (org_pricing_cache / 106), which is the one authority per enrolled
-- node (§C.3 / D8). `observer pricing sync` refuses on an enrolled node and the
-- cost-engine loader never reads this table there. The table still EXISTS on
-- every node (the migration is unconditional) so a node that un-enrols can use
-- the feed without a schema change, but it is inert while enrolled.
--
-- WHY IT IS PERSISTED AT ALL, rather than re-fetched each start: the exact
-- reason org_pricing_cache is. api_turns.cost_usd is stamped at CAPTURE and
-- there is no retroactive re-pricing in this arc (ruling R8 / gap
-- PRICE-REPRICE-1). A restart that had to wait for the next (opt-in, possibly
-- 24h-away) poll before pricing correctly would stamp every turn in between at
-- seed rates, permanently. So the verified envelope lands here and the engine
-- composes from it on a cold start, before any fetch.
--
-- WHY A SINGLE-ROW TABLE (CHECK id = 1). The feed is FLEET-WIDE and binds no
-- subject, so a node holds exactly one of them; two rows would be two answers
-- to "what public prices is this node applying". The row is seeded here so
-- every reader SELECTs without a NULL-vs-missing branch and the first write is
-- an UPDATE -- the org_pricing_cache / update_state shape, and what lets
-- store.SavePricingFeed be the one writer.
--
-- WHAT IT STORES:
--   version    the feed's monotonic feed_version. Replay refusal (a body whose
--              version is not strictly greater than the stored one is REFUSED
--              by `observer pricing sync`, unless the signing key changed) is
--              its only consumer besides display.
--   key_id     which compiled vendor key (pricingfeed.PricingFeedKeyIDV1, or a
--              rotation-slot id) verified this body. Recorded so a later key
--              rotation is diagnosable rather than merely fatal.
--   digest     the envelope's content digest -- the If-None-Match / ETag
--              substrate, so the next poll can short-circuit a 304 and a
--              corrected-in-place rate re-applies even without a version bump.
--   body_json  the VERIFIED envelope's bytes (the whole pricingfeed.Envelope):
--              the publisher's own signed document coming BACK, never node data
--              going out. It is what the engine re-composes rows + economics
--              from on a cold start.
--   fetched_at when the 200 that produced this row landed (RFC3339).
--   state      the fetch-ladder outcome the node last observed (verified |
--              no_pricing | unreachable | unverified). A closed Go enum,
--              deliberately NOT a CHECK here -- the vocabulary lives in one
--              place (the sync ladder) and is normalised at the write seam, so
--              a future member cannot be refused at write time by a constraint
--              that would need its own migration (the org_pricing_cache / 106
--              and org_node_budget_posture / 130 rationale, mirrored).
--
-- Only a SIGNED body may ever EMPTY this table: `observer pricing sync` writes
-- NOTHING outside the verified-200 branch, so a transport error, a 304, an
-- unsigned body or a replay all leave it exactly as it was. There is no header,
-- status line or timeout that could clear a whole fleet back to seed prices.
--
-- No paired SERVER migration, by construction: the public feed is a
-- publisher -> node rail that never touches the org server's DB (the org server
-- consumes the feed through its OWN importer + server bookkeeping table, a
-- separate arc wave).

CREATE TABLE IF NOT EXISTS pricing_feed_cache (
    -- id is pinned to 1: this is the node's single applied public-feed document.
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    version    INTEGER NOT NULL DEFAULT 0,
    key_id     TEXT    NOT NULL DEFAULT '',
    digest     TEXT    NOT NULL DEFAULT '',
    body_json  TEXT    NOT NULL DEFAULT '',
    fetched_at TEXT    NOT NULL DEFAULT '',
    state      TEXT    NOT NULL DEFAULT ''
);

INSERT INTO pricing_feed_cache (id, version, key_id, digest, body_json, fetched_at, state)
VALUES (1, 0, '', '', '', '', '')
ON CONFLICT (id) DO NOTHING;
