-- 0032_api_role_grant_completeness.sql
--
-- Follow-up to 0031 (already applied to staging on 2026-09-03 before the
-- api-suite-as-sbci_api harness surfaced the rest of the class). Two more
-- front-door writes 0015 never granted.
-- Same class, second table, same first roll: the portal browser sign-in start
-- (store.portalauth BeginAuthTransaction) prunes expired/consumed rows with
-- `DELETE FROM auth_transactions ... WHERE account-less short-lived txn` before
-- inserting the new one, and 0015 granted sbci_api SELECT, INSERT, UPDATE only.
-- Live symptom: `GET /portal/auth/workos/start` → 500 "could not start sign-in"
-- on every attempt. The api-suite-as-sbci_api harness now pins it.
GRANT DELETE ON auth_transactions TO sbci_api;

-- Third table, same roll: store.SubmitJob reserves the allowance in-tx
-- (reserveAllowanceTx → `INSERT INTO usage_reservations`), and 0015 gave
-- sbci_api SELECT, UPDATE only — its own comment ("reserve allowance") promised
-- the INSERT it never granted. Live symptom: `POST /v1/jobs` → 500 "could not
-- submit job" for every account on the sbci_api-bound serve binary.
GRANT INSERT ON usage_reservations TO sbci_api;
