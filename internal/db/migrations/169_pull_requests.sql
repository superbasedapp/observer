-- 169_pull_requests.sql - provider pull requests that hold an AI-touched
-- commit, and their commit lists (commit-pr-merge-tracking plan 5, 6.1 and
-- 12.3, D-689).
--
-- Written ONLY by internal/store/delivery.go (UpsertPullRequest). NODE-LOCAL
-- (privacy sentinel): title, url and repo_slug name clients and codenames;
-- they reach the org only inside orgcontract.PullRequestRow, composed in
-- internal/store/deliverysummary.go under the raw-content gate.
--
--   pr_state         draft | open | merged | closed_unmerged
--   merge_readiness  ready | conflicts | checks_failing | checks_pending |
--                    changes_requested | review_required | behind |
--                    blocked_other | unknown ('' unless open)
--   facets_json      internal/delivery.Facets
--   provider_raw_state  the provider's own strings, for a tooltip
--   title            scrubbed, capped at 512 bytes
--
-- pull_request_commits is capped at 250 per PR (GitHub's own list cap);
-- patch_fp is filled when the commit is present locally.

CREATE TABLE IF NOT EXISTS pull_requests (
    id                  INTEGER PRIMARY KEY,
    provider_link_id    INTEGER NOT NULL DEFAULT 0,
    provider            TEXT NOT NULL,
    host                TEXT NOT NULL DEFAULT '',
    repo_slug           TEXT NOT NULL,
    number              INTEGER NOT NULL,
    title               TEXT NOT NULL DEFAULT '',
    url                 TEXT NOT NULL DEFAULT '',
    author_login        TEXT NOT NULL DEFAULT '',
    pr_state            TEXT NOT NULL,
    merge_readiness     TEXT NOT NULL DEFAULT '',
    facets_json         TEXT NOT NULL DEFAULT '{}',
    provider_raw_state  TEXT NOT NULL DEFAULT '',
    head_sha            TEXT NOT NULL DEFAULT '',
    base_ref            TEXT NOT NULL DEFAULT '',
    merge_commit_sha    TEXT NOT NULL DEFAULT '',
    merge_method        TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL DEFAULT '',
    merged_at           TEXT NOT NULL DEFAULT '',
    closed_at           TEXT NOT NULL DEFAULT '',
    updated_at          TEXT NOT NULL DEFAULT '',
    fetched_at          TEXT NOT NULL,
    UNIQUE (provider_link_id, repo_slug, number)
);

CREATE TABLE IF NOT EXISTS pull_request_commits (
    pr_id     INTEGER NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    sha       TEXT NOT NULL,
    position  INTEGER NOT NULL DEFAULT 0,
    patch_fp  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (pr_id, sha)
);

CREATE INDEX IF NOT EXISTS idx_pull_request_commits_sha ON pull_request_commits(sha);
