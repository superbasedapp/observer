-- 0019_deletion_completion.sql — bring account deletion to substantive
-- COMPLETION (cloud-intelligence divergence remediation plan rev 4.2, §3 "W6d";
-- closes E6, feeds D11). The 0018-and-earlier skeleton fenced the account,
-- tombstoned result text, revoked credentials and deleted a few tables but left
-- the request 'processing' forever and left most tenant tables populated. W6d
-- makes the deletion a complete, FK-safe purge-or-pseudonymize per the plan's
-- enumerated matrix, flips the request to 'done', and (in Go) writes an
-- append-only deletion journal OUTSIDE the Postgres restore domain so a PITR
-- restore to before the request can re-apply the tombstone before reopening.
--
-- This migration adds the durable state the completion needs:
--
--   1. accounts pseudonymization columns. The account ROW is KEPT (its random
--      UUID is already opaque — no PK rotation, so no FK breakage) as an
--      irreversible tombstone: status='deleted', deletion timestamps, and
--      consent_generation nulled to a RESERVED non-authorizing state. Grant
--      validation already refuses a non-'active' account at the auth gate
--      (IntrospectToken requires status='active'; every credential is purged),
--      and a NULL consent_generation is belt-and-suspenders — no live grant can
--      resolve against it.
--
--        * consent_generation is made NULLABLE (was NOT NULL DEFAULT 0). Only a
--          tombstoned account ever holds NULL; a live account always has a
--          concrete generation. The reads that authorize work (lease
--          revalidation, structural grant checks) are all gated behind
--          status='active' auth, so they never observe the NULL.
--        * deleted_at / purge_after record the tombstone clock. purge_after =
--          done + 24 months (abuse/forensics basis, same clock as
--          security_audit_events); a later retention pass purges the row
--          outright after that.
--
--   2. DELETE grants for the purge targets. Account deletion is an
--      API-initiated COMPLETE purge of the account's own tenant data; every one
--      of these tables is RLS'd on sbci_current_account(), so the grant can only
--      ever remove the deleting account's OWN rows — never another tenant's.
--      The api role already holds tenant-scoped write/neutralize access to these
--      tables (UPDATE evidence_objects, UPDATE analysis_jobs, DELETE
--      evidence_blobs, revoke devices/tokens/sessions), so adding the row-purge
--      DELETE is not a cross-tenant escalation; RLS remains the isolation
--      boundary. Granted to BOTH sbci_api (the production serve role that runs
--      the deletion) and sbci_app (the shared/admin + test role). A
--      grant-introspection test pins that sbci_api holds these.

-- 1. accounts pseudonymization columns.
ALTER TABLE accounts ALTER COLUMN consent_generation DROP NOT NULL;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS deleted_at   timestamptz;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS purge_after  timestamptz;

-- 2. DELETE grants for the purge targets (idempotent). The tables the skeleton
-- already deletes (evidence_blobs, structural_snapshots, structural_account_days,
-- portal_consent_choices) already carry the grant and are re-granted here
-- harmlessly for a single authoritative list.
-- Enrichment cluster (result_revisions/analysis_results only had SELECT/INSERT/
-- UPDATE before — deletion now purges the rows).
GRANT DELETE ON result_revisions        TO sbci_api, sbci_app;
GRANT DELETE ON analysis_results        TO sbci_api, sbci_app;
GRANT DELETE ON identity_links          TO sbci_api, sbci_app;
GRANT DELETE ON device_registrations    TO sbci_api, sbci_app;
GRANT DELETE ON api_tokens              TO sbci_api, sbci_app;
GRANT DELETE ON browser_sessions        TO sbci_api, sbci_app;
GRANT DELETE ON pop_replay              TO sbci_api, sbci_app;
GRANT DELETE ON step_up_authorizations  TO sbci_api, sbci_app;
GRANT DELETE ON entitlements            TO sbci_api, sbci_app;
GRANT DELETE ON usage_cycles            TO sbci_api, sbci_app;
GRANT DELETE ON usage_reservations      TO sbci_api, sbci_app;
GRANT DELETE ON account_plans           TO sbci_api, sbci_app;
GRANT DELETE ON cloud_projects          TO sbci_api, sbci_app;
GRANT DELETE ON cloud_sessions          TO sbci_api, sbci_app;
GRANT DELETE ON evidence_objects        TO sbci_api, sbci_app;
GRANT DELETE ON analysis_jobs           TO sbci_api, sbci_app;
-- Already-deleted-by-skeleton targets, re-granted for a single authoritative
-- list (idempotent; these were granted in earlier migrations).
GRANT DELETE ON evidence_blobs          TO sbci_api, sbci_app;
GRANT DELETE ON structural_snapshots    TO sbci_api, sbci_app;
GRANT DELETE ON structural_account_days TO sbci_api, sbci_app;
GRANT DELETE ON portal_consent_choices  TO sbci_api, sbci_app;
