-- 188_sec_finding_remotes.sql (renumbered from 186 at merge) - which
-- remotes already hold each held commit, and when a finding's secret
-- first reached a remote (security pillar plan sections 4.8 and 5.3; lane
-- sec-gate4, decision log P-039
-- follow-ups 1 and 2).
--
-- sec_finding_commits.remotes_json is the JSON list of the configured
-- remotes whose remote-tracking refs the daemon last saw holding the
-- commit (empty: none, or not checked yet). The push gate (S-792) counts a
-- held commit as pushed only for those remotes: a push to one remote no
-- longer releases the hold for every other one. A commit every configured
-- remote holds is released (its row deleted), as before.
--
-- sec_findings.reached_remote_at is when a commit holding the finding was
-- first seen on a remote ('' never). Such a finding stays open with the
-- fixed note "already pushed: rotate the secret" instead of closing as not
-- reproduced, and stops blocking once no file and no held commit holds it
-- any more; triage closes it.
--
-- NODE-LOCAL: both tables are in the privacy sentinel's forbidden-table
-- list. NO server pair. One writer: internal/store/secfindings.go. Never
-- content: remote names (local config names) and a timestamp.

ALTER TABLE sec_finding_commits ADD COLUMN remotes_json TEXT NOT NULL DEFAULT '';
ALTER TABLE sec_findings ADD COLUMN reached_remote_at TEXT NOT NULL DEFAULT '';
