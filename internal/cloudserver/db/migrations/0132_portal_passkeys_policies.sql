-- 0132_portal_passkeys_policies.sql - row-level security for 0131's three
-- account-keyed tables (C2 portal second factor; wave 17 portal-guardrails).
--
-- step: expand
--
-- Each table is readable and writable only in its own account's context
-- (sbci_current_account()), the account_verified_emails pattern (0075).

SET LOCAL lock_timeout = '5s';

ALTER TABLE portal_passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_passkeys FORCE ROW LEVEL SECURITY;
CREATE POLICY portal_passkeys_tenant ON portal_passkeys
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

ALTER TABLE portal_passkey_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_passkey_ceremonies FORCE ROW LEVEL SECURITY;
CREATE POLICY portal_passkey_ceremonies_tenant ON portal_passkey_ceremonies
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

ALTER TABLE portal_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_recovery_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY portal_recovery_codes_tenant ON portal_recovery_codes
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());
