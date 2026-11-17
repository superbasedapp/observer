-- 0075_account_verified_emails_policy.sql - row-level security on the table
-- 0074 created (managed-SaaS plan 07, operator item A4).
--
-- step: expand
--
-- The tenant policy of account_profiles (0033): a row is visible to, and
-- writable by, only the account it belongs to. FORCE applies it to the table
-- owner too. A step of its own (migcheck: policy and row-level-security
-- changes).

SET LOCAL lock_timeout = '5s';

ALTER TABLE account_verified_emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_verified_emails FORCE ROW LEVEL SECURITY;
CREATE POLICY account_verified_emails_tenant ON account_verified_emails
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());
