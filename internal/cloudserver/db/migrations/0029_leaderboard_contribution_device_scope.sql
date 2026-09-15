-- 0029_leaderboard_contribution_device_scope.sql — GPT-5.6 Sol adversarial
-- review of the W5 contribution-upload wave, finding F9 recommendation #1.
-- Companion to 0028 (F8): same theme (a registration/value row that should be
-- device-scoped but wasn't), a different fix shape.
--
-- F9 #1: leaderboard_contributions' natural key is (account_id, cohort_key,
-- metric_id, metric_version, window_id) — no device dimension. UpsertContribution's
-- `ON CONFLICT ... DO UPDATE SET value = EXCLUDED.value` is therefore silent
-- last-writer-wins across two devices under one account: Device A syncs a
-- window's value, Device B (same account, different machine, e.g. a stale or
-- misconfigured second install) syncs a DIFFERENT value for the identical
-- window, and Device A's contribution is silently overwritten with no signal
-- to either device that a conflict happened.
--
-- Unlike F8, the fix here is NOT to widen the natural key — the natural key
-- names the thing being measured (one contribution per account per cohort/
-- metric/window), and letting two devices each hold a row would double count
-- in the cross-tenant aggregation this table feeds. Instead: record which
-- device WROTE the row, and make a second, different device's write a refusal
-- (ErrCrossDeviceConflict in store/community.go) rather than a silent
-- overwrite. First device to sync a window wins; the operator has an
-- explicit, actionable error instead of a value that quietly changed under
-- them.
--
-- 0022 (leaderboard_contributions' origin) has not yet reached prod (staging
-- runs a pre-W9 image, same as 0028's note), so this table is empty in every
-- deployed environment today. Still written to be valid against a populated
-- table: DEFAULT '' backfills any existing row into a single ""-device
-- bucket before the NOT NULL is proven.
--
-- Scope note: this does NOT touch the table's PRIMARY KEY / UNIQUE
-- constraint (account_id, cohort_key, metric_id, metric_version, window_id) —
-- device_id is a plain column, not part of the natural key. 0027's sweep
-- purges leaderboard_contributions by account_id alone; unaffected.

ALTER TABLE leaderboard_contributions
    ADD COLUMN device_id text NOT NULL DEFAULT '';

-- RLS (ENABLE + FORCE + the sbci_current_account() tenant policy) and the
-- table-level GRANTs (sbci_api/sbci_app full DML, sbci_defs SELECT for the
-- percentile-banding function) are unaffected by adding a plain column —
-- nothing here needs to be re-asserted.

COMMENT ON COLUMN leaderboard_contributions.device_id IS
    'The authenticated device (Principal.DeviceID) that wrote this row, never a client-declared field. Not part of the natural key: UpsertContribution (Sol F9) refuses a write from a DIFFERENT device to an existing (account, cohort, metric, version, window) row instead of silently overwriting it — first device to sync a window wins.';
