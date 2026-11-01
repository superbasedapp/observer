-- 165_project_commits_patch_fp.sql - the per-commit patch fingerprint
-- (docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md sections 2.3, 6.1
-- and 12.3, operator decision D-689).
--
-- A rebase merge or a cherry-pick lands the same change under a NEW sha, so
-- "is this sha on the default branch" misses it. The fingerprint is the
-- `git patch-id --stable` id of the commit's diff (internal/commitlog.
-- PatchFingerprint), computed by the landing scan (internal/landingscan)
-- while the commit's objects are still local and stored here, because the
-- local branch is often deleted after the merge.
--
-- OWNER: internal/store/commits.go (SetCommitPatchFingerprint), the one
-- writer of project_commits. NODE-LOCAL like the rest of the table (privacy
-- sentinel).
--
--   patch_fp        40-hex fingerprint; NULL until computed or when the
--                   state is not 'ok'.
--   patch_fp_state  pending | ok | too_large | binary_only | empty | error.
--                   'pending' makes the matching rule defer (rule G2).

ALTER TABLE project_commits ADD COLUMN patch_fp TEXT;
ALTER TABLE project_commits ADD COLUMN patch_fp_state TEXT NOT NULL DEFAULT 'pending';
