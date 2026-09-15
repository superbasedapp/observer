-- 0011_auth_transactions_cascade.sql — let an account be deleted while a
-- step-up auth transaction is still live (W1 adversarial review, F13).
--
-- 0009 gave auth_transactions a nullable `account_id uuid REFERENCES
-- accounts(account_id)` with the default NO ACTION semantics. That binding is
-- correct — a step_up transaction MUST name the account it re-authenticates —
-- but the default referential action makes it a BLOCKER on the one path that
-- matters most: account purge. A user who starts a deletion step-up and then
-- has their account purged (by the deletion pipeline, or by an operator acting
-- on a WorkOS lifecycle event) leaves a row that refuses the DELETE with a
-- foreign-key violation, and the purge fails on a 10-minute-lived pre-auth row.
--
-- ON DELETE CASCADE is the right action here precisely BECAUSE these rows are
-- not account data. Per the rev-4 F6 classification (0009's header) an
-- auth_transactions row is pre-auth, excluded from account export, and not part
-- of the deletion matrix: it expires globally on expires_at and exists only to
-- carry one OAuth round-trip. Dropping it with the account destroys nothing
-- anyone is entitled to, and a transaction whose account no longer exists could
-- never complete anyway (the callback resolves the identity back to an account
-- that is gone).
--
-- The step_up_authorizations FK is deliberately NOT changed here: those rows ARE
-- account-scoped data (RLS, and the 0009 header says they purge with the
-- account), so how they are removed is the deletion pipeline's decision to make
-- explicitly, not a cascade this migration should silently install.
--
-- The constraint is dropped and re-added rather than altered: PostgreSQL has no
-- ALTER CONSTRAINT for referential actions on a foreign key. The name is
-- Postgres's own default for the 0009 column definition
-- (<table>_<column>_fkey); the IF EXISTS makes re-application safe.

ALTER TABLE auth_transactions
    DROP CONSTRAINT IF EXISTS auth_transactions_account_id_fkey;

ALTER TABLE auth_transactions
    ADD CONSTRAINT auth_transactions_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE;
