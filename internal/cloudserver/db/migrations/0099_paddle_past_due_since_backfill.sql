-- 0099_paddle_past_due_since_backfill.sql - past_due_since for the rows
-- already past_due when 0098 ran (managed-SaaS plan 07 wave 16 lane
-- control-plane; lead decision W16-D5).
--
-- step: data
--
-- A row that was past_due before 0098 has past_due_since NULL. Its window
-- starts at its last Paddle event (last_event_at, the F3 ordering guard's
-- occurrence time, which for a past_due row is no earlier than its entry
-- into past_due), else its updated_at. The 0098 trigger keeps an explicit
-- value on a row that stays past_due, so this UPDATE is what lands.
--
-- One statement, transactional: the cloud runner keeps no progress table
-- (migcheck's data-step rule), and the table is small (production has no
-- live Paddle yet, L-114). Re-running it changes nothing (the WHERE).

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

UPDATE paddle_subscriptions
   SET past_due_since = COALESCE(last_event_at, updated_at)
 WHERE status = 'past_due'
   AND past_due_since IS NULL;
