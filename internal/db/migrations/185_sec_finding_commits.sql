-- 185_sec_finding_commits.sql - the commits each open finding was seen
-- added in, kept until that commit is pushed (security pillar plan
-- sections 4.8 and 5.3; lane sec-gate3, decision log P-033 follow-up).
-- A secret committed and then removed from the working tree (a human
-- edit, an `rm`, a later commit that deletes the line, `git rm --cached`)
-- is still in the history the next push sends. A finding with a row here
-- never closes, so the posture keeps it blocking and S-792 still gates the
-- push, until the daemon sees the commit on a remote-tracking ref (pushed)
-- or on no local branch, tag or HEAD any more (rewritten away).
--
-- NODE-LOCAL: in the privacy sentinel's forbidden-table list, so
-- internal/store/orgpush.go can never select it by name. NO server pair.
-- One writer: internal/store/secfindings.go (UpsertSecFinding adds a row
-- for a commit-scope finding that names its commit, DropSecFindingCommit
-- removes the rows the daemon proved pushed or gone). Never content: a
-- commit id and a timestamp.

CREATE TABLE IF NOT EXISTS sec_finding_commits (
    finding_id TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (finding_id, commit_sha)
);

CREATE INDEX IF NOT EXISTS idx_sec_finding_commits_sha ON sec_finding_commits (commit_sha);

-- Every open finding stored before this table existed that a commit scan
-- recorded keeps its one known commit, so it is checked like a new one.
-- Only a full commit id (40 or 64 hex characters, stored lower case, the
-- form store.IsCommitSHA and DropSecFindingCommit accept) is copied: a
-- malformed one could never be released and would hold its finding open
-- for good.
INSERT OR IGNORE INTO sec_finding_commits (finding_id, commit_sha, last_seen)
    SELECT id, lower(commit_sha), last_seen FROM sec_findings
    WHERE status = 'open' AND scope = 'commit'
        AND length(commit_sha) IN (40, 64)
        AND lower(commit_sha) NOT GLOB '*[^0-9a-f]*';
