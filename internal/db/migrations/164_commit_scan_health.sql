-- 164_commit_scan_health.sql - commit-capture health you can act on
-- (docs/projects-page.md "Commit capture health", 2026-10-15).
--
-- The Projects page said "the last commit scan failed (a timeout, or an
-- unreadable or deleted root) - the ledger may be stale" for 34 of 70
-- scanned projects on the operator's node. None of them had timed out:
-- 13 were folders that are not git repositories, 16 were deleted
-- scratch / arena folders, 2 were "[cursor]"-style placeholders, and 3
-- were Windows paths (C:\...) a WSL daemon never translated. Their failure
-- state also never cleared, because a deleted folder is skipped before a
-- scan and so never wrote a new state.
--
-- NODE-LOCAL, like the rest of project_commit_scan (privacy sentinel). Only
-- internal/store/commits.go writes these columns.
--
--   last_error_kind  the closed failure vocabulary internal/commitscan
--                    classifies a failure into (failure.go). '' = no failure.
--   last_success_at  when a scan last completed (the page says "last good
--                    scan 2 h ago" instead of guessing).
--   last_head_sha    the HEAD commit whose whole history is in the ledger.
--                    The next scan reads only `git log <new HEAD> ^<this>`,
--                    and skips git log entirely when HEAD has not moved.
--   history_pending  1 while a full-history walk is still in progress (a
--                    large repository is walked over several ticks instead
--                    of timing out). backfill_rev / backfill_skip are its
--                    resume cursor: the pinned commit being walked and how
--                    many commits of it are already in.

ALTER TABLE project_commit_scan ADD COLUMN last_error_kind TEXT NOT NULL DEFAULT '';
ALTER TABLE project_commit_scan ADD COLUMN last_success_at TEXT NOT NULL DEFAULT '';
ALTER TABLE project_commit_scan ADD COLUMN last_head_sha   TEXT NOT NULL DEFAULT '';
ALTER TABLE project_commit_scan ADD COLUMN history_pending INTEGER NOT NULL DEFAULT 0;
ALTER TABLE project_commit_scan ADD COLUMN backfill_rev    TEXT NOT NULL DEFAULT '';
ALTER TABLE project_commit_scan ADD COLUMN backfill_skip   INTEGER NOT NULL DEFAULT 0;

-- Classify every stored failure once, from the text git already gave us, so
-- a project that is no longer scanned (inactive, or its folder gone) still
-- shows the specific reason after the upgrade. Same order as
-- internal/commitscan/failure.go's table.
UPDATE project_commit_scan
   SET last_error_kind = CASE
       WHEN last_error = '' THEN ''
       WHEN last_error LIKE '%git not found%' THEN 'git_missing'
       WHEN last_error LIKE '%timed out%' THEN 'timeout'
       WHEN last_error LIKE '%cannot change to%' THEN
            CASE WHEN (SELECT p.root_path FROM projects p WHERE p.id = project_commit_scan.project_id) LIKE '/%'
                   OR (SELECT p.root_path FROM projects p WHERE p.id = project_commit_scan.project_id) LIKE '_:%'
                   OR (SELECT p.root_path FROM projects p WHERE p.id = project_commit_scan.project_id) LIKE '\\%'
                 THEN 'root_missing' ELSE 'no_folder' END
       WHEN last_error LIKE '%not a git repository%' THEN 'not_repo'
       WHEN last_error LIKE '%dubious ownership%' THEN 'dubious_ownership'
       WHEN last_error LIKE '%permission denied%' THEN 'permission_denied'
       ELSE 'other'
   END;

-- A structural failure (no folder, folder gone, not a repository) is pinned
-- at one failure, as the scanner now records it: its count is not a
-- backoff signal, and "45 failed attempts" would read like a flaky error.
UPDATE project_commit_scan SET consecutive_failures = 1
 WHERE last_error_kind IN ('no_folder', 'root_missing', 'not_repo') AND consecutive_failures > 1;

UPDATE project_commit_scan SET last_success_at = last_scan_at WHERE last_error = '';

-- A zero watermark used to be stored as the scan's own wall-clock time
-- (store.timestamp maps a zero time to "now"), so a project whose first
-- scan failed or found no commits looked as if its history had been read.
-- last_sha = '' means no commit was ever seen: clear the fake watermark.
UPDATE project_commit_scan SET last_committed_at = '' WHERE last_sha = '';

-- One verified full-history walk for every project. The old incremental
-- scan asked `git log --since=<newest commit seen>`, which misses a pulled
-- commit whose committer date is older than that (a teammate's work
-- fast-forwarded in). The walk is idempotent (UpsertCommits) and resumable.
UPDATE project_commit_scan SET history_pending = 1, backfill_rev = '', backfill_skip = 0;
