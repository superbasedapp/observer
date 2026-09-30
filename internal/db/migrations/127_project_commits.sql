-- 127_project_commits.sql — read-only git-commit-history capture, node-side
-- (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md §2
-- R2/R3/R11/R12, §3.2).
--
-- Three tables back a daemon-lifetime scanner (internal/commitscan) that
-- polls every ACTIVE project's HEAD via read-only `git log`
-- (internal/gitview.RunReadOnly + internal/commitlog.ParseLog) — never a
-- git hook install, never a write to the repository.
--
--   project_commits      — one row per (project, sha): the commit's own
--                           metadata (parents, hashed author, both dates,
--                           the scrubbed subject) plus the numstat totals
--                           (files_count/added/deleted) and a
--                           REACHABILITY flag. A commit that later falls
--                           out of `git rev-list HEAD` history (rebase,
--                           branch reset, force-push) is flagged
--                           reachable=0, NEVER deleted — R4's attribution
--                           rule needs the row to explain why a prompt
--                           that once looked "committed" no longer does.
--   project_commit_files — one row per changed path within a commit.
--                           path_hash is internal/loc.PathHash(rel) — the
--                           SAME hash file_changes.file_path_hash uses
--                           (R3), so this table is the join key between a
--                           commit and the AI edits that reached it.
--                           rel_path is stored for on-screen display only
--                           (same posture as actions.target); like
--                           file_changes it never leaves this node.
--   project_commit_scan  — the scanner's own per-project watermark +
--                           health: the last sha/committed_at it saw, the
--                           last time it ran, and a fail-soft error +
--                           consecutive-failure counter for backoff (a
--                           deleted/unmounted/foreign root is not retried
--                           every tick).
--
-- Plus idx_api_turns_project (F13/R11): api_turns.project_id had no index,
-- and the Projects page's per-session/per-tool/per-day spend reads all
-- filter on it.
--
-- PRIVACY (R12): commit capture observes OTHER CONTRIBUTORS' metadata in a
-- shared repository — a hashed author name, the commit subject, and the
-- list of files it touched. NODE-LOCAL, exactly like file_changes: NEVER
-- selected by internal/store/orgpush.go::SelectUnpushedSince, and pinned
-- in the forbidden-table sentinel (tests/invariant/privacy_test.go).
-- author_hash is an UNSALTED 16-hex sha256 prefix of the trimmed git
-- author name (internal/commitlog.hashAuthor) — adequate as a same-repo
-- join key, but NOT adequate pseudonymisation for any future org
-- projection (docs/security.md ledger row COMMIT-2 records this).
--
-- Timestamps are RFC3339 UTC strings, matching every other table in this
-- schema.

CREATE TABLE IF NOT EXISTS project_commits (
    id            INTEGER PRIMARY KEY,
    project_id    INTEGER NOT NULL REFERENCES projects(id),
    sha           TEXT NOT NULL,
    parents_json  TEXT NOT NULL DEFAULT '[]',
    author_hash   TEXT NOT NULL DEFAULT '',
    authored_at   TEXT NOT NULL,
    committed_at  TEXT NOT NULL,
    subject       TEXT NOT NULL DEFAULT '',
    is_merge      INTEGER NOT NULL DEFAULT 0,
    reachable     INTEGER NOT NULL DEFAULT 1,
    files_count   INTEGER NOT NULL DEFAULT 0,
    added         INTEGER NOT NULL DEFAULT 0,
    deleted       INTEGER NOT NULL DEFAULT 0,
    scanned_at    TEXT NOT NULL,
    UNIQUE(project_id, sha)
);

CREATE INDEX IF NOT EXISTS idx_project_commits_project_time
    ON project_commits(project_id, committed_at);

CREATE TABLE IF NOT EXISTS project_commit_files (
    commit_id  INTEGER NOT NULL REFERENCES project_commits(id) ON DELETE CASCADE,
    rel_path   TEXT NOT NULL,
    path_hash  TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT '',
    added      INTEGER NOT NULL DEFAULT 0,
    deleted    INTEGER NOT NULL DEFAULT 0,
    binary     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_project_commit_files_commit ON project_commit_files(commit_id);
CREATE INDEX IF NOT EXISTS idx_project_commit_files_hash ON project_commit_files(path_hash);

CREATE TABLE IF NOT EXISTS project_commit_scan (
    project_id           INTEGER PRIMARY KEY REFERENCES projects(id),
    last_sha              TEXT NOT NULL DEFAULT '',
    last_committed_at     TEXT NOT NULL DEFAULT '',
    last_scan_at          TEXT NOT NULL DEFAULT '',
    last_error            TEXT NOT NULL DEFAULT '',
    consecutive_failures  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_api_turns_project ON api_turns(project_id);
