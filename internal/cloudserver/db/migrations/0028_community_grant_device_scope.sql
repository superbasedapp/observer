-- 0028_community_grant_device_scope.sql — GPT-5.6 Sol adversarial review of
-- the W5 contribution-upload wave, finding F8 (MAJOR).
--
-- F8: community_grants (0026) is keyed only by (account_id, purpose). The
-- consent generation is a per-DEVICE fact (each node mints its own monotonic
-- counter as the developer re-confirms terms on that machine), but the
-- registration row is account-wide. Two devices under the same account
-- therefore fight over ONE row: whichever device last registered the higher
-- generation "wins", and a lower-generation device — which has done nothing
-- wrong, it simply hasn't been re-confirmed as many times locally — is
-- refused as stale (ErrCommunityGenerationStale) even though it never saw the
-- other device's generation at all. Device A can drive the row's generation
-- to a very high value and permanently lock Device B out.
--
-- The authenticated principal already carries DeviceID (proof-of-possession,
-- server.go's Principal) — RegisterCommunityGrant simply never threaded it
-- through. This is the same per-device shape structural_snapshots (0013)
-- already uses for its own window key; community_grants gets the same
-- treatment for the registration row itself (community's write path has no
-- separate per-device value table the way structural does, so the grant row
-- IS where the device scope has to live).
--
-- 0026 has not yet reached prod (staging still runs a pre-W9 image), so this
-- table is empty in every deployed environment today. The migration is still
-- written to be valid against a populated table: DEFAULT '' backfills any
-- existing row into a single ""-device bucket before the NOT NULL is proven,
-- rather than assuming emptiness.
--
-- Scope note: 0027's sweep purges community_grants by account_id alone (the
-- 24-month CTE's `WHERE account_id IN (SELECT account_id FROM due)`), which
-- is correct regardless of how many device rows an account now has per
-- purpose — no change needed there.

-- ===========================================================================
-- Widen the primary key to (account_id, device_id, purpose).
-- ===========================================================================
ALTER TABLE community_grants
    ADD COLUMN device_id text NOT NULL DEFAULT '';

ALTER TABLE community_grants
    DROP CONSTRAINT community_grants_pkey;

ALTER TABLE community_grants
    ADD PRIMARY KEY (account_id, device_id, purpose);

-- RLS (ENABLE + FORCE + the sbci_current_account() USING/WITH CHECK policy)
-- and the table-level GRANTs (sbci_api/sbci_app full DML, sbci_defs
-- SELECT+DELETE for the retention sweep) are all independent of the primary
-- key definition — dropping and re-adding a PRIMARY KEY constraint changes
-- only the constraint + its backing unique index, never a table's policies or
-- ACL. Nothing here needs to be re-asserted.

COMMENT ON TABLE community_grants IS
    'W5 server-side registration of a NODE (account, device) standing community_cohort_benchmarking grant; retained-then-swept like structural_grants. Device-scoped since 0028 (Sol F8) so one device cannot stale/lock out another under the same account.';

COMMENT ON COLUMN community_grants.device_id IS
    'The authenticated device this registration belongs to (Principal.DeviceID), never a client-declared field. Part of the primary key alongside account_id + purpose so devices register and advance their consent generation independently.';
