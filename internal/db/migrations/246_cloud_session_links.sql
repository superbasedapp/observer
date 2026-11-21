-- 246_cloud_session_links.sql - the pull requests and branches a cloud
-- coding agent's vendor said a cloud session produced, and the head branch
-- of a provider PR (cloud-agents arc, lane CA-C5 "Delivery attribution of
-- cloud PRs"; docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md
-- section 8; docs/projects-page.md "Cloud-agent credit").
--
-- cloud_session_links - one row per (session, repository, PR number,
--     branch) pointer a cloud-agent connector read from the vendor:
--     Copilot's pullRequestNumber / pullRequestUrl, Devin's
--     pull_requests[].pr_url, a Cursor run's git.branches[] {repoUrl,
--     branch}. Written ONLY by internal/store/cloudsessionlinks.go
--     (RecordCloudSessionLinks, called once per landed task by
--     internal/cloudagentssvc), read by the cloud-credit loader that feeds
--     internal/projectroi.CreditCloud. remote is the lowercased
--     "host/owner/repo" the claim compares on; pr_number 0 = no PR stated;
--     branch '' = no branch stated (a row carries at least one). first_seen_at
--     keeps the first observation, last_seen_at moves on every re-read.
--     No foreign key to sessions: the loader joins sessions, so a row whose
--     session is gone is inert.
--
-- pull_requests.head_ref - the PR's head branch as the provider reported
--     it (GET /repos/{o}/{r}/pulls[/{n}] head.ref), '' when not reported.
--     Written only by UpsertPullRequest (the table's one writer); an empty
--     value never clears a stored one. It lets a branch-only cloud claim (a
--     Cursor run) resolve to its PR (claim rule branch_head_ref).
--
-- NODE-LOCAL, both: branch names encode ticket ids and codenames (the M2
-- precedent) and repository slugs name clients. cloud_session_links joins
-- the privacy sentinel's forbidden-table set; pull_requests already does,
-- and orgcontract.PullRequestRow does not carry head_ref. No paired server
-- migration. What the credit changes on the org wire is only the existing
-- CommitOwnershipRow's owner, reason and share basis (structure; the owner
-- is a session id that already ships as its own session row).
--
-- Numbered 246, inside the cloud-agents reservation (node 240-249, CA-D14).
CREATE TABLE cloud_session_links (
    id            INTEGER PRIMARY KEY,
    session_id    TEXT NOT NULL,
    connector     TEXT NOT NULL,
    remote        TEXT NOT NULL,
    pr_number     INTEGER NOT NULL DEFAULT 0 CHECK (pr_number >= 0),
    branch        TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    CHECK (pr_number > 0 OR branch <> ''),
    UNIQUE (session_id, remote, pr_number, branch)
);

CREATE INDEX idx_cloud_session_links_remote ON cloud_session_links (remote);

ALTER TABLE pull_requests ADD COLUMN head_ref TEXT NOT NULL DEFAULT '';
