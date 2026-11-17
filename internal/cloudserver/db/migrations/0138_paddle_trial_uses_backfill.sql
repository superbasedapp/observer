-- 0138_paddle_trial_uses_backfill.sql - paddle_trial_uses for the
-- subscriptions that already trialed before 0137 (Fable review 2026-11-17
-- FR-10; docs/security.md BILL-FR10).
--
-- step: data
--
-- A subscription has trialed when it is trialing now or still carries a
-- trial end (trial_ends_at is cleared when a row leaves trialing, so a row
-- that trialed and then converted is not visible here; production has run
-- with SBCI_PADDLE_TRIAL_DAYS=0, so none should exist). The earliest such
-- row per scope wins; ON CONFLICT keeps a row the webhook already wrote.
--
-- One statement, transactional (the cloud runner keeps no progress table);
-- re-running it changes nothing.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

INSERT INTO paddle_trial_uses (account_id, org_id, paddle_subscription_id, first_trial_at)
SELECT DISTINCT ON (ps.account_id, ps.org_id)
       ps.account_id, ps.org_id, ps.paddle_subscription_id, ps.created_at
  FROM paddle_subscriptions ps
 WHERE ps.status = 'trialing' OR ps.trial_ends_at IS NOT NULL
 ORDER BY ps.account_id, ps.org_id, ps.created_at
ON CONFLICT DO NOTHING;
