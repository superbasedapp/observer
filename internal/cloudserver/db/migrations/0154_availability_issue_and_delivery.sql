-- 0154_availability_issue_and_delivery.sql - the availability envelope's
-- issue requests and its per-host delivery state (managed-SaaS plan 07 M6.3;
-- design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.5;
-- lane fix/sr-17-staff-control; ledger STAFF-8).
--
-- step: expand
--
-- WHY. Staff write availability_inputs (0069); nothing composed them into a
-- signed sbo-availability-v1 envelope, so no staff write ever reached a host
-- (staff console e2e finding SC-4, docs/audits/staff-console-e2e-2026-11-23.md).
-- The staff process cannot reach the document signer (its socket is mounted
-- into the worker only), so an issue is a REQUEST the staff process records
-- and the worker carries out: compose from the inputs, check they are still
-- the inputs the staff member previewed (inputs_digest) and that no other
-- envelope was issued since (base_version), sign, store in availability_docs
-- (0055) and push to every host.
--
-- TABLES
--
--   availability_issue_requests  one row per staff "Issue" (reason required,
--                                logged in staff_actions in the same
--                                transaction). At most one is pending
--                                (partial unique index). The worker moves it
--                                to issued (result_version), stale (the
--                                inputs or the issued version moved, or
--                                nothing to issue) or failed (error_class).
--                                Ops or admin may cancel a pending request
--                                (failed, error_class 'cancelled'; reason,
--                                fresh passkey, staff_actions row in the
--                                same transaction): with the worker's
--                                availability loops off nothing else
--                                finishes it, and it would refuse every
--                                later issue.
--   availability_deliveries      per host (the hosts file's id), the newest
--                                envelope version the host answered is in
--                                force, the version last sent, and the last
--                                attempt's state and error class. The worker
--                                writes it; the staff console reads it.
--
-- GRANTS AND ROW-LEVEL SECURITY (as availability_inputs, 0069/0070): only the
-- roles below, each through a policy bound to that role, so a stray grant to
-- any other role still reads nothing. Neither table carries customer data.
--
--   sbci_staff   availability_issue_requests SELECT, INSERT, and UPDATE of
--                state, error_class and done_at only to cancel: a pending
--                row may become failed with error_class 'cancelled', and
--                nothing else (policy availability_issue_requests_staff_cancel);
--                availability_deliveries SELECT.
--   sbci_worker  availability_issue_requests SELECT, UPDATE of the outcome
--                columns only; availability_deliveries SELECT, INSERT,
--                UPDATE.
--
-- sbci_api, sbci_app and sbci_aggregator hold nothing here.

SET LOCAL lock_timeout = '5s';

CREATE TABLE availability_issue_requests (
    request_id     uuid        NOT NULL PRIMARY KEY,
    requested_by   text        NOT NULL CHECK (requested_by ~ '^staff:[A-Za-z0-9_-]{1,64}$'),
    reason         text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1000),
    -- availcompose.Digest of the inputs the staff member previewed.
    inputs_digest  text        NOT NULL CHECK (inputs_digest ~ '^[0-9a-f]{64}$'),
    -- The newest issued envelope version the preview was against (0: none).
    base_version   bigint      NOT NULL CHECK (base_version >= 0),
    state          text        NOT NULL DEFAULT 'pending'
                               CHECK (state IN ('pending', 'issued', 'stale', 'failed')),
    result_version bigint      CHECK (result_version > 0),
    error_class    text        CHECK (error_class ~ '^[a-z0-9_:.-]{1,64}$'),
    requested_at   timestamptz NOT NULL,
    done_at        timestamptz,
    CONSTRAINT availability_issue_requests_done
        CHECK ((state = 'pending') = (done_at IS NULL)),
    CONSTRAINT availability_issue_requests_result
        CHECK ((state = 'issued') = (result_version IS NOT NULL))
);

CREATE UNIQUE INDEX availability_issue_requests_one_pending
    ON availability_issue_requests ((true)) WHERE state = 'pending';
CREATE INDEX availability_issue_requests_newest
    ON availability_issue_requests (requested_at DESC);

CREATE TABLE availability_deliveries (
    host_id           text        NOT NULL PRIMARY KEY CHECK (host_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    -- The version the host answered is in force (0: not known yet).
    version           bigint      NOT NULL CHECK (version >= 0),
    -- The version last sent.
    attempted_version bigint      NOT NULL CHECK (attempted_version > 0),
    state             text        NOT NULL CHECK (state IN ('delivered', 'retry', 'refused')),
    attempts          integer     NOT NULL CHECK (attempts >= 0),
    error_class       text        CHECK (error_class ~ '^[a-z0-9_:.-]{1,64}$'),
    updated_at        timestamptz NOT NULL
);

COMMENT ON TABLE availability_issue_requests IS
    'M6.3: staff requests to issue the availability envelope; the worker composes, signs, stores and delivers (staff + worker only).';
COMMENT ON TABLE availability_deliveries IS
    'M6.3: per host, the availability envelope version in force and the last delivery attempt (worker writes, staff reads).';

GRANT SELECT, INSERT ON availability_issue_requests TO sbci_staff;
GRANT UPDATE (state, error_class, done_at) ON availability_issue_requests TO sbci_staff;
GRANT SELECT ON availability_issue_requests TO sbci_worker;
GRANT UPDATE (state, result_version, error_class, done_at) ON availability_issue_requests TO sbci_worker;

GRANT SELECT ON availability_deliveries TO sbci_staff;
GRANT SELECT, INSERT, UPDATE ON availability_deliveries TO sbci_worker;

ALTER TABLE availability_issue_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE availability_issue_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY availability_issue_requests_staff_read ON availability_issue_requests
    FOR SELECT TO sbci_staff USING (true);
CREATE POLICY availability_issue_requests_staff_append ON availability_issue_requests
    FOR INSERT TO sbci_staff WITH CHECK (state = 'pending');
CREATE POLICY availability_issue_requests_staff_cancel ON availability_issue_requests
    FOR UPDATE TO sbci_staff USING (state = 'pending')
    WITH CHECK (state = 'failed' AND error_class = 'cancelled' AND done_at IS NOT NULL);
CREATE POLICY availability_issue_requests_worker_read ON availability_issue_requests
    FOR SELECT TO sbci_worker USING (true);
CREATE POLICY availability_issue_requests_worker_finish ON availability_issue_requests
    FOR UPDATE TO sbci_worker USING (state = 'pending') WITH CHECK (state <> 'pending');

ALTER TABLE availability_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE availability_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY availability_deliveries_staff_read ON availability_deliveries
    FOR SELECT TO sbci_staff USING (true);
CREATE POLICY availability_deliveries_worker ON availability_deliveries
    FOR ALL TO sbci_worker USING (true) WITH CHECK (true);
