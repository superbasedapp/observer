-- 0070_staff_policies.sql - row-level security on the staff tables 0069
-- created (managed-SaaS plan 07 M6.8; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.2, 3.5).
--
-- step: expand
--
-- The grants in 0069 are the access control. These policies bind every row
-- to the roles those grants name, so a grant given to any other role later
-- (a schema-wide GRANT, a mistaken line in a later step) still reads and
-- writes nothing: a row is visible only to sbci_staff, and availability
-- inputs also to sbci_worker for reading. FORCE applies them to the table
-- owner too.
--
-- staff_actions has a SELECT and an INSERT policy and nothing else, so even a
-- granted UPDATE or DELETE matches no row: the log stays append-only.
--
-- A step of its own (migcheck: policy and row-level-security changes).

SET LOCAL lock_timeout = '5s';

ALTER TABLE staff_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE staff_users FORCE ROW LEVEL SECURITY;
CREATE POLICY staff_users_staff ON staff_users
    FOR ALL TO sbci_staff USING (true) WITH CHECK (true);

ALTER TABLE staff_webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE staff_webauthn_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY staff_webauthn_credentials_staff ON staff_webauthn_credentials
    FOR ALL TO sbci_staff USING (true) WITH CHECK (true);

ALTER TABLE staff_enrolments ENABLE ROW LEVEL SECURITY;
ALTER TABLE staff_enrolments FORCE ROW LEVEL SECURITY;
CREATE POLICY staff_enrolments_staff ON staff_enrolments
    FOR ALL TO sbci_staff USING (true) WITH CHECK (true);

ALTER TABLE staff_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE staff_ceremonies FORCE ROW LEVEL SECURITY;
CREATE POLICY staff_ceremonies_staff ON staff_ceremonies
    FOR ALL TO sbci_staff USING (true) WITH CHECK (true);

ALTER TABLE staff_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE staff_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY staff_sessions_staff ON staff_sessions
    FOR ALL TO sbci_staff USING (true) WITH CHECK (true);

ALTER TABLE staff_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE staff_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY staff_actions_read ON staff_actions
    FOR SELECT TO sbci_staff USING (true);
CREATE POLICY staff_actions_append ON staff_actions
    FOR INSERT TO sbci_staff WITH CHECK (true);

ALTER TABLE availability_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE availability_inputs FORCE ROW LEVEL SECURITY;
CREATE POLICY availability_inputs_staff ON availability_inputs
    FOR ALL TO sbci_staff USING (true) WITH CHECK (true);
CREATE POLICY availability_inputs_worker_read ON availability_inputs
    FOR SELECT TO sbci_worker USING (true);
