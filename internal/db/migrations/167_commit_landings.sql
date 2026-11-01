-- 167_commit_landings.sql - one delivery outcome per AI-touched commit
-- (commit-pr-merge-tracking plan sections 4, 6.1 and 12.3, D-689).
--
-- Written ONLY by internal/store/delivery.go (UpsertCommitLandings), from
-- internal/delivery.Evaluate's ordered rule table. NODE-LOCAL (privacy
-- sentinel); the org receives only the daily COUNTS composed in
-- internal/store/deliverysummary.go.
--
--   status          in_flight | local_only | pushed | in_pr | landed |
--                   likely_landed | abandoned | landing_lost
--   kind            exact_sha | merge | squash | rebase | patch_id |
--                   squash_files | content ('' unless landed)
--   rule_id / rule_version  which table row decided, under which version
--                   (a changed rule re-evaluates older rows).
--   contributors_json  the AI sessions that contributed to the commit, as the
--                   Ownership fold last saw them, so a commit that later
--                   falls out of HEAD (a deleted, squash-merged branch) still
--                   answers "whose work landed".
--
-- Timestamps are RFC3339 UTC strings ('' = unknown).

CREATE TABLE IF NOT EXISTS commit_landings (
    commit_id         INTEGER PRIMARY KEY REFERENCES project_commits(id) ON DELETE CASCADE,
    project_id        INTEGER NOT NULL,
    status            TEXT NOT NULL,
    kind              TEXT NOT NULL DEFAULT '',
    confidence        TEXT NOT NULL DEFAULT '',
    rule_id           TEXT NOT NULL DEFAULT '',
    rule_version      INTEGER NOT NULL DEFAULT 0,
    landing_sha       TEXT NOT NULL DEFAULT '',
    pr_id             INTEGER,
    pr_number         INTEGER NOT NULL DEFAULT 0,
    abandon_reason    TEXT NOT NULL DEFAULT '',
    source            TEXT NOT NULL DEFAULT '',
    first_pushed_at   TEXT NOT NULL DEFAULT '',
    landed_at         TEXT NOT NULL DEFAULT '',
    landed_at_source  TEXT NOT NULL DEFAULT '',
    evaluated_at      TEXT NOT NULL,
    contributors_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_commit_landings_project ON commit_landings(project_id, status);
CREATE INDEX IF NOT EXISTS idx_commit_landings_pr ON commit_landings(pr_id);
