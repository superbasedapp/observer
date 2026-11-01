-- 172_delivery_branch_tips.sql - local branch tips that hold an AI-touched
-- commit not landed yet (commit-pr-merge-tracking plan 2.3, 6.1 and 12.3,
-- D-689).
--
-- Written ONLY by internal/store/delivery.go (UpsertBranchTips). NODE-LOCAL
-- (privacy sentinel). Recorded while the branch exists so the squash rules
-- (L3: the default branch gained a commit whose fingerprint equals this
-- range's cumulative fingerprint; L4: same files, patch changed while
-- merging) still work after the branch is deleted.
--
-- BRANCH NAMES ARE SENSITIVE (they encode ticket ids and codenames, the M2
-- precedent): the key is ref_name_hash (sha256 hex of the full ref name);
-- ref_name is kept only for this node's own dashboard and never leaves it.
--
--   range_fp / range_fp_state  fingerprint of the cumulative diff
--                   merge_base_sha..tip_sha, same states as
--                   project_commits.patch_fp_state
--   member_shas_json  the commits in that range (capped)
--   files_json      repository-relative paths the cumulative diff touches

CREATE TABLE IF NOT EXISTS delivery_branch_tips (
    project_id        INTEGER NOT NULL REFERENCES projects(id),
    ref_name_hash     TEXT NOT NULL,
    ref_name          TEXT NOT NULL DEFAULT '',
    tip_sha           TEXT NOT NULL,
    merge_base_sha    TEXT NOT NULL DEFAULT '',
    range_fp          TEXT NOT NULL DEFAULT '',
    range_fp_state    TEXT NOT NULL DEFAULT 'pending',
    member_shas_json  TEXT NOT NULL DEFAULT '[]',
    files_json        TEXT NOT NULL DEFAULT '[]',
    observed_at       TEXT NOT NULL,
    PRIMARY KEY (project_id, ref_name_hash)
);
