-- 0034_paddle_trial_management_urls.sql — Paddle production go-live gaps 1.11
-- (trial handling) and 1.4 (customer-portal management links), from the
-- 2026-09-12 Paddle-to-production-live register
-- (docs/handovers/next-session-kickoff-2026-09-12-paddle-signin-production.md
-- §1.11 / §1.4).
--
-- OPERATOR RULING (2026-09-11): a 7-day Paddle-side trial ships on the launch
-- price. The plan is unchanged — 'plus_beta' v1, no new plan row — but our
-- side must persist the 'trialing' status HONESTLY rather than folding it
-- into 'active' the way the pre-arc code did (store/paddle.go's old
-- upsertSubscriptionTx always wrote "active", so the portal could never show
-- "trial ends in N days" — kickoff gap 1.11). Trialing is LIVE paid access —
-- it stays OUT of the paddle_subscriptions_one_live exclusion list, the same
-- way 'active'/'past_due'/'paused' already are; only the TERMINAL states
-- ('canceled'/'refunded'/'charged_back', migration 0030) are excluded.
--
-- management_update_url / management_cancel_url close gap 1.4: Paddle's
-- subscription payload can carry `management_urls.{update_payment_method,
-- cancel}` — hosted-Paddle links the portal surfaces directly instead of
-- telling the user "the management link is not wired into this portal yet".
-- Stored ONLY when they parse as https URLs on paddle.com (or a
-- *.paddle.com subdomain) — see store/paddle.go's validatePaddleManagementURL
-- — because a webhook body is attacker-shaped input until the signature is
-- verified, and even verified we never persist (let alone render) an
-- arbitrary URL taken from it.

ALTER TABLE paddle_subscriptions DROP CONSTRAINT paddle_subscriptions_status_check;
ALTER TABLE paddle_subscriptions
    ADD CONSTRAINT paddle_subscriptions_status_check
    CHECK (status IN ('active','trialing','canceled','past_due','paused','refunded','charged_back'));

-- trialing is LIVE access — the "one live subscription per account" partial
-- unique index is recreated verbatim (its predicate does not change: only
-- canceled/refunded/charged_back were ever excluded) so the migration is
-- self-contained and the invariant is documented at the point of change,
-- matching the migration 0030 precedent.
DROP INDEX paddle_subscriptions_one_live;
CREATE UNIQUE INDEX paddle_subscriptions_one_live
    ON paddle_subscriptions (account_id)
    WHERE status NOT IN ('canceled','refunded','charged_back');

ALTER TABLE paddle_subscriptions
    ADD COLUMN trial_ends_at         timestamptz,
    ADD COLUMN management_update_url text,
    ADD COLUMN management_cancel_url text;

COMMENT ON COLUMN paddle_subscriptions.trial_ends_at IS
    'Set only while status=''trialing'': current_billing_period.ends_at (fallback next_billed_at) from the webhook payload. Cleared the moment the row resolves to any other status (upsertSubscriptionTx''s CASE).';
COMMENT ON COLUMN paddle_subscriptions.management_update_url IS
    'Paddle-hosted payment-method-update link (data.management_urls.update_payment_method). Stored only when it parses as an https URL on paddle.com/*.paddle.com — see validatePaddleManagementURL.';
COMMENT ON COLUMN paddle_subscriptions.management_cancel_url IS
    'Paddle-hosted cancellation link (data.management_urls.cancel). Same https+paddle.com acceptance rule as management_update_url.';

-- No new grants needed: paddle_subscriptions' existing table-level GRANTs
-- (migration 0024, GRANT ... ON paddle_subscriptions TO sbci_api/sbci_app)
-- already cover every column on the table, including these three — Postgres
-- table-level GRANTs are not column-scoped, so a plain ADD COLUMN needs no
-- companion GRANT (confirmed against 0015/0019/0032, which only ever narrow
-- grants for NEW tables or NEW functions, never re-grant an existing table
-- for an added column).
