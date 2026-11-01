-- 192_sec_finding_run_id.sql - the sandbox run a finding came back with
-- (security pillar plan sections 4.8 "Copy workspaces" and 5.3, M7; lane
-- sec-box).
--
-- sec_findings.run_id is the sandbox run whose box made the change a
-- commit-scope finding was found in: a commit returned by the sandbox
-- return step (refs/observer/sandbox/<run>) or walked on a box ref. ''
-- for every other finding. It is a lineage id beside session_id and
-- action_id, written once when the finding is first seen.
--
-- NODE-LOCAL: sec_findings is in the privacy sentinel's forbidden-table
-- list and the org row builder never selects this column. NO server pair.
-- One writer: internal/store/secfindings.go. Never content: an opaque run
-- id.

ALTER TABLE sec_findings ADD COLUMN run_id TEXT NOT NULL DEFAULT '';
