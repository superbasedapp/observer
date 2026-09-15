-- 100: cloud_dispatch_leases — the cross-process DISPATCH LEASE for the two
-- standing cloud rails (Sol re-review of the W5-upload remediation, N2 —
-- docs/plans/arc2-sol-rereview-node-fixes-notes-2026-09-02.md).
--
-- BACKGROUND. Every standing-rail upload (structural snapshot, community
-- contribution) re-checks its consent receipt immediately before each physical
-- HTTP attempt (the PreAttempt hook). That check reads the receipt and returns;
-- the transport then dispatches. Between the two there is a window — a
-- scheduler pause of any length — in which `observer cloud consent revoke` (or a
-- superseding `consent grant`) can commit, print "nothing further will be
-- sent", and return, while the paused sender still goes on to put bytes on the
-- wire under the receipt it just retired. An in-memory mutex cannot close it:
-- grant, revoke and sync are separate PROCESSES sharing only this database.
--
-- THE LEASE. A sender takes a row here immediately before every physical
-- attempt, inside one immediate transaction that re-verifies the EXACT receipt
-- (id + consent generation) is still live, and releases it right after the
-- attempt returns. Revoke and supersede cancel the leases under the receipts
-- they retire and then WAIT until none of those leases is active any more —
-- released, or expired — before returning. A lease acquired under a receipt
-- that is no longer live is refused at acquisition. The lease's expiry equals
-- the per-attempt HTTP timeout and is applied to the attempt's own request
-- context, so an attempt descheduled past its lease can never begin dispatch:
-- the wait is therefore bounded and the promise revoke prints is true.
--
-- CONTENT-FREE: ids, a purpose label, a generation number, timestamps. Nothing
-- here is derived from what the developer was working on. NODE-LOCAL like the
-- whole cloud_* family: the table joins the forbidden-table denylist walked by
-- tests/invariant/privacy_test.go, there is no org share key, and there is no
-- paired orgserver migration.
--
-- Times are RFC3339(Nano) TEXT via internal/store/cloudlocal.go's
-- cloudFormatTime/cloudParseTime. No down-migration; a pre-100 binary never
-- reads the table.
CREATE TABLE cloud_dispatch_leases (
    id                 TEXT    PRIMARY KEY,
    receipt_id         TEXT    NOT NULL,
    purpose            TEXT    NOT NULL,
    consent_generation INTEGER NOT NULL,
    acquired_at        TEXT    NOT NULL,
    expires_at         TEXT    NOT NULL,
    released_at        TEXT,
    cancelled_at       TEXT
);
CREATE INDEX idx_cloud_dispatch_leases_receipt ON cloud_dispatch_leases(receipt_id, released_at);
