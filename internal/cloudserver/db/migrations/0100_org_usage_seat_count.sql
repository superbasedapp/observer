-- 0100_org_usage_seat_count.sql - the seat count of an org's usage day kept
-- after its member ids are minimised (managed-SaaS plan 07 wave 16 lane
-- plan-policy; lead decision W16-D9; L-124 C3.ENTL-usage-retention;
-- docs/security.md USAGE-1).
--
-- step: expand
--
-- WHY. org_usage_days (0085) is the usage behind an invoice, kept 10 years
-- from its day (L-124; the deletion matrix in docs/cloud-intelligence.md).
-- Its seat_member_ids are needed only while the day can still enter a bill
-- or a dispute: 13 months (one annual cycle and a month). After that the
-- worker's minimisation pass (cmd/observer-cloud usageretention.go,
-- store.MinimiseOrgUsageDays) keeps the count in seat_count, stamps
-- minimised_at and empties the ids.
--
-- seat_count is NULL until the row is minimised (a live row's count is the
-- cardinality of its ids); minimised_at is NULL until then. The two checks
-- are added NOT VALID here and validated in 0101: every existing row has
-- both columns NULL and passes them.

SET LOCAL lock_timeout = '5s';

ALTER TABLE org_usage_days ADD COLUMN seat_count integer;
ALTER TABLE org_usage_days ADD COLUMN minimised_at timestamptz;

ALTER TABLE org_usage_days
    ADD CONSTRAINT org_usage_days_seat_count_check
    CHECK (seat_count IS NULL OR seat_count >= 0) NOT VALID;

-- A minimised row holds its count and no member id; a live row holds no
-- count of its own.
ALTER TABLE org_usage_days
    ADD CONSTRAINT org_usage_days_minimised_check
    CHECK ((minimised_at IS NULL AND seat_count IS NULL)
        OR (minimised_at IS NOT NULL AND seat_count IS NOT NULL AND cardinality(seat_member_ids) = 0)) NOT VALID;

-- sbci_portal_org_seats (rewritten in 0101) reads the count.
GRANT SELECT (seat_count) ON org_usage_days TO sbci_defs;
