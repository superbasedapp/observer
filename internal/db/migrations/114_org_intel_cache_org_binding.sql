-- Org-served Cloud Intelligence, node side — bind the result cache to the
-- enrolment identity (org-served-cloud-intelligence plan §2.4/§3.5; adversarial
-- finding 6). org_intel_cache (migration 112) held the org server's own derived
-- per-session enrichment results but did NOT record which enrolment they came
-- from, so a node that re-enrolled into a DIFFERENT org could keep rendering the
-- previous org's cached intel, and the in-memory pull cursor could page org B
-- with org A's `since`.
--
-- This adds the org binding: every cached row records the org_id it was pulled
-- under. The node drops foreign-org rows on an identity change and clears the
-- whole table on de-enrolment (store.DeleteEnrolment), and the in-memory cursor
-- resets when the live enrolment's org no longer matches the cursor's org.
--
-- BACKFILL (adversarial finding 7). A bare `DEFAULT ''` would stamp every
-- pre-114 cached row UNBOUND, and the very next identity-bound pull
-- (FetchIntelResults, which fires DeleteForeignOrgIntelResults when the cursor
-- org differs from the enrolment org) would treat org_id='' as foreign and
-- delete EVERY pre-114 row. Since 114 has not run on any real node yet, we
-- backfill the column from the node's own enrolment (org_enrolment.id=1) as
-- part of the migration, so a node enrolled at upgrade time keeps its cached
-- results. A row stays '' only when the node is NOT enrolled, which is exactly
-- "unbound / foreign" — and DeleteEnrolment clears the whole table anyway, so
-- an unbound pre-114 row can only exist on a node with no enrolment, where it
-- renders nothing.
--
-- STILL NODE-LOCAL: org_intel_cache never enters the org-push wire (the table
-- name is in the privacy sentinel's forbidden set, tests/invariant/
-- privacy_test.go, INV-3). No new table name is introduced here.
ALTER TABLE org_intel_cache ADD COLUMN org_id TEXT NOT NULL DEFAULT '';
UPDATE org_intel_cache
   SET org_id = COALESCE((SELECT org_id FROM org_enrolment WHERE id = 1), '')
 WHERE org_id = '';
CREATE INDEX idx_org_intel_cache_org ON org_intel_cache(org_id);
