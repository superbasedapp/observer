-- 115: cloud_enrich_policy — the developer's own STANDING INTENT for
-- per-session Cloud Intelligence enrichment (value-upgrade plan of record,
-- docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md §W2).
--
-- One singleton row (id=1) records which level `observer cloud enable` /
-- `observer cloud disable` last set: which purpose the BACKGROUND path may
-- mint per-session receipts under ('off' mints none, 'titles' mints
-- structural_activity_insights receipts, 'excerpts' mints
-- bounded_context_enrichment receipts — which itself always implies
-- structural, cmd/observer/cloud.go::cloudPurposeSet), and whether the
-- background path runs at all.
--
-- THIS ROW IS NOT A CONSENT RECEIPT. A receipt (cloud_consent_receipts,
-- migration 097/098) binds the exact bytes or schema a developer confirmed and
-- is what the consent-gated egress seam (internal/cloudgateway) checks before
-- every send. This row binds nothing and authorizes no upload by itself — the
-- gateway still demands a live receipt per upload regardless of what this row
-- says. It exists purely so the background enrichment path knows WHICH level
-- to operate at (and whether to run unattended), the way a thermostat's set
-- point is not itself the furnace's safety interlock.
--
-- NODE-LOCAL, same posture as every other cloud_* table (migration 097's
-- header): never on the org-push wire. Its name joins the forbidden-table
-- sentinel walked by tests/invariant/privacy_test.go.
CREATE TABLE cloud_enrich_policy (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    level          TEXT NOT NULL CHECK (level IN ('off', 'titles', 'excerpts')),
    background     INTEGER NOT NULL DEFAULT 1,
    policy_version TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL
);
