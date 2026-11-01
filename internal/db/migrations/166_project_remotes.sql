-- 166_project_remotes.sql - each project's git remotes as the landing scan
-- read them (commit-pr-merge-tracking plan 6.1 / 12.3, D-689).
--
-- Written ONLY by internal/store/delivery.go (UpsertProjectRemote).
-- NODE-LOCAL: never named by internal/store/orgpush.go (privacy sentinel).
--
-- url is the remote with any userinfo STRIPPED before it reaches this table
-- (internal/delivery.ParseRemoteURL; a credential in a remote URL is never
-- stored or logged). repo_slug ("owner/repo") names a client or codename,
-- so it only ever leaves the node inside a PullRequestRow under the
-- raw-content gate. default_ref_sha is the user's own remote-tracking ref as
-- read (Observer never fetches into the user's repository, plan 12.2);
-- fetch_head_at is the mtime of the user's .git/FETCH_HEAD ('' = absent).

CREATE TABLE IF NOT EXISTS project_remotes (
    project_id       INTEGER NOT NULL REFERENCES projects(id),
    remote_name      TEXT NOT NULL,
    url              TEXT NOT NULL DEFAULT '',
    host             TEXT NOT NULL DEFAULT '',
    provider         TEXT NOT NULL DEFAULT 'unknown',
    repo_slug        TEXT NOT NULL DEFAULT '',
    default_branch   TEXT NOT NULL DEFAULT '',
    default_ref_sha  TEXT NOT NULL DEFAULT '',
    fetch_head_at    TEXT NOT NULL DEFAULT '',
    observed_at      TEXT NOT NULL,
    PRIMARY KEY (project_id, remote_name)
);

CREATE INDEX IF NOT EXISTS idx_project_remotes_host ON project_remotes(host, repo_slug);
