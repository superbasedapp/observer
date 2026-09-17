-- Org-served Cloud Intelligence, node side — cache the five NARRATIVE result
-- lists (org-served-cloud-intelligence plan §1.3/§2.4/§3.5). The server half is
-- server migration 156 / pgmigrations 0022; this is the node's mirror of it.
--
-- org_intel_cache (migration 112) held the org's derived per-session result as
-- the node last pulled it, but only the title / description / tags /
-- limitations half. The org rail has been PRODUCING work_done /
-- plans_implemented / issues_found / failures / next_steps all along — the
-- executor prompts for them, bounds them, scrubs them and rejects a leaky one —
-- and dropping them at the server's own storage layer meant the node dashboard
-- rendered a strictly thinner card than the personal cloud plane does for the
-- same session. These five columns are what lets the shared IntelResultCard
-- show the same answer on both drawers.
--
-- NULLABLE, no DEFAULT — the server-side 156 rule, mirrored: the four existing
-- list columns default to '[]', and these deliberately do not. NULL means "this
-- cached row predates the narrative fields, or the org returned none", which
-- must never read as five empty answers. The reader COALESCEs to '[]' at the
-- scan, so no caller branches on NULL, and a pre-124 cached row upgrades in
-- place on the next pull of the same (session_id, job_id) — the upsert rewrites
-- the row, it is never re-keyed.
--
-- STILL NODE-LOCAL: org_intel_cache never enters the org-push wire (the table
-- name is in the privacy sentinel's forbidden set, tests/invariant/
-- privacy_test.go, INV-3). No new table name is introduced here, so the
-- sentinel set is unchanged.
ALTER TABLE org_intel_cache ADD COLUMN work_done TEXT;
ALTER TABLE org_intel_cache ADD COLUMN plans_implemented TEXT;
ALTER TABLE org_intel_cache ADD COLUMN issues_found TEXT;
ALTER TABLE org_intel_cache ADD COLUMN failures TEXT;
ALTER TABLE org_intel_cache ADD COLUMN next_steps TEXT;
