-- 146_limit_cursor_seed_and_commit_local_author.sql - two NODE-LOCAL fixes
-- from the 2026-09-29 adversarial review (lane H-WIRE), one migration number
-- because the lane was assigned one. No server pair for either.
--
-- PART 1: seed the per-session rate-limit window push cursor for a node that
-- was ALREADY enrolled when it upgraded (review finding 2).
--
-- WHY. The per-session limit-window wire (lane F-WIRE,
-- orgcontract.SessionLimitSnapshotRow) is a cursor wire keyed on
-- schema_meta 'org_push_cursor_limit_snapshots'. Enrolment seeds every
-- cursor key at the live high-water mark (store.CurrentMaxIDs), so a node
-- enrolled AFTER the key existed never ships its pre-enrolment windows. A
-- node enrolled BEFORE the key existed has every other cursor key but not
-- this one, and store.LoadPushCursor reads a missing key as 0 - so its first
-- push after the upgrade shipped its whole limit_snapshots history,
-- including every window observed before the developer enrolled.
--
-- WHAT. For a node that holds ANY other push cursor key (it enrolled at some
-- point) and has no limit-snapshot key yet, write the key at the current
-- limit_snapshots head. Snapshots recorded before this upgrade therefore
-- never ship; the gauge only needs the NEWEST window, which the next proxied
-- turn records again.
--
-- IDEMPOTENT AND NON-CLOBBERING. INSERT OR IGNORE: a key that already exists
-- (a node enrolled under a build that seeds it, or one this migration
-- already seeded) is never moved, and a never-enrolled node (no cursor keys
-- at all) gets nothing - its enrolment seeds the key through CurrentMaxIDs
-- exactly as before. The migration runs inside the migration transaction
-- before any push loop can read the cursor, so no push can observe the gap.
INSERT OR IGNORE INTO schema_meta (key, value)
SELECT 'org_push_cursor_limit_snapshots',
       CAST((SELECT COALESCE(MAX(id), 0) FROM limit_snapshots) AS TEXT)
 WHERE EXISTS (SELECT 1 FROM schema_meta
                WHERE key IN ('org_push_cursor_sessions', 'org_push_cursor_actions',
                              'org_push_cursor_api_turns', 'org_push_cursor_token_usage',
                              'org_push_cursor_guard_events', 'org_push_cursor_otel_content',
                              'org_push_cursor_mcp_relay'));

-- PART 2: project_commit_scan.local_author_hash (review finding 8). The hash
-- of the repository's configured identity (the user.name config value, the
-- %an field the commit scanner hashes) under the SAME unsalted 16-hex
-- internal/commitlog hashing as project_commits.author_hash, resolved by the
-- commit scanner on each successful tick. The ownership fold compares it with
-- each commit's author_hash: a commit by a DIFFERENT author (a teammate's
-- commit pulled into the checkout) carries nothing and has no owner
-- (internal/projectroi O2b foreign_author). '' = the local identity is
-- unknown (user.name unset, or not scanned since this migration), and the
-- rule then keeps its pre-author-check behaviour. Never selected onto the
-- org wire (project_commit_scan is in the privacy sentinel's forbidden set).
ALTER TABLE project_commit_scan ADD COLUMN local_author_hash TEXT NOT NULL DEFAULT '';
