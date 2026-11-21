-- 0141_account_deletion_followups_rls.sql - row-level security on the account
-- deletion follow-ups (docs/audits/fable-review-2026-11-17.md FR-12; lane
-- fix/fr-deletion).
--
-- step: expand
--
-- account_deletion_followups (0120) had no row-level security: sbci_api held
-- INSERT on it, so any API-role defect that inserted one row could name an
-- arbitrary account and personal org, and the worker would remove that
-- account's memberships and purge that org with no window. Now:
--
--   sbci_api    INSERT only a row of the account in context
--               (account_id = sbci_current_account(); the account deletion
--               transaction runs under WithAccount, store.deletionCompleteTx).
--   sbci_worker SELECT and UPDATE every row (the deletion driver runs with no
--               tenant context); before it acts on a row it also checks it
--               against deletion_requests and the personal org's creator and
--               kind (0140 sbci_deletion_followup_check).
--   sbci_staff  SELECT every row (its 0120 column grant still hides subs).
--   sbci_app    every row (operator paths, the dev/test single role), as
--               before.
--
-- A policy step of its own (internal/migcheck), after 0140; the grants are
-- 0120's and unchanged. The table becomes FORCE ROW LEVEL SECURITY, so a role
-- with no policy here reaches no row (fail closed).

SET LOCAL lock_timeout = '5s';

ALTER TABLE account_deletion_followups ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_deletion_followups FORCE ROW LEVEL SECURITY;

CREATE POLICY account_deletion_followups_api_insert ON account_deletion_followups
    FOR INSERT
    TO sbci_api
    WITH CHECK (account_id = sbci_current_account());

CREATE POLICY account_deletion_followups_worker_select ON account_deletion_followups
    FOR SELECT
    TO sbci_worker
    USING (true);

CREATE POLICY account_deletion_followups_worker_update ON account_deletion_followups
    FOR UPDATE
    TO sbci_worker
    USING (true)
    WITH CHECK (true);

CREATE POLICY account_deletion_followups_staff_select ON account_deletion_followups
    FOR SELECT
    TO sbci_staff
    USING (true);

CREATE POLICY account_deletion_followups_app ON account_deletion_followups
    TO sbci_app
    USING (true)
    WITH CHECK (true);
