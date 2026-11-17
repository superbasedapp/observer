-- 255: org_enrolment keeps the connection's name and online address
-- (Getting started v2 lane 8, job 2; docs/plans/onboarding-v2-connect-flow.md
-- section 12).
--
-- `observer connect` learns the dashboard's display name and its online
-- address from the cloud's approval; neither is on the enrol response. The
-- local status (GET /api/connect/status, internal/frontdoor) and the
-- dashboard's "Open online" button need both after a daemon restart, and
-- for a connection the CLI or an installer made, so they live with the
-- enrolment itself:
--
--   display_name  the target's name as the person chose it ("your personal
--                 dashboard" for an unnamed personal dashboard); '' = not
--                 recorded (an enrolment `observer enroll` made directly)
--   online_url    the target's online dashboard address, for a button
--                 only: never printed in CLI text (a personal dashboard's
--                 own host is never shown); '' = not recorded
--
-- Written by store.SetEnrolmentConnection after a connect attaches, and
-- cleared by store.WriteEnrolment on every enrolment (the next connect
-- writes them again), so a name never outlives the dashboard it names.
-- Additive only: existing rows read '' for both. A binary predating this step
-- never names them.
--
-- NODE-LOCAL: org_enrolment never crosses the push wire (orgpush.go never
-- names it; the privacy sentinel lists it as this node's enrolment record).

ALTER TABLE org_enrolment ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE org_enrolment ADD COLUMN online_url TEXT NOT NULL DEFAULT '';
