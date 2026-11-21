-- 0137_paddle_trial_uses_and_seat_quantity.sql - one free trial per account
-- and per org, and the seat quantity a subscription pays for (Fable review
-- 2026-11-17 FR-10 and FR-22; docs/security.md BILL-FR10, BILL-FR22).
--
-- step: expand
--
-- paddle_trial_uses (FR-10). Nothing recorded that an account or org had
-- already had a trial, so "start a trial, cancel on day 6, repeat" worked
-- for ever once SBCI_PADDLE_TRIAL_DAYS is raised above 0. The webhook writes
-- a row the first time a subscription lands as trialing (one per account
-- scope, org_id NULL; one per org), and the checkout refuses to mint a new
-- intent for a scope that has used its trial while the deployment advertises
-- one. account_id is the paying account (an FK, cascading with the account
-- row's tombstone sweep); org_id is opaque (no FK: an org id is never reused,
-- and the record must outlive an org's deletion so a deleted-and-recreated
-- scope is a new id anyway). 0138 backfills it from paddle_subscriptions.
-- Class S: the webhook (sbci_api) writes it, the checkout (sbci_api) reads
-- it, sbci_app mirrors; no UPDATE or DELETE for any role.
--
-- paddle_subscriptions.seat_quantity (FR-22). The quantity Paddle bills the
-- subscription's first item for (data.items[0].quantity), stored as each
-- delivery that carries items reports it. Nullable: rows written before this
-- step, and events with no items, leave it unknown.

SET LOCAL lock_timeout = '5s';

CREATE TABLE paddle_trial_uses (
    trial_use_id           uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id             uuid        NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
    org_id                 uuid,
    paddle_subscription_id text        NOT NULL CHECK (paddle_subscription_id <> ''),
    first_trial_at         timestamptz NOT NULL,
    recorded_at            timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX paddle_trial_uses_account ON paddle_trial_uses (account_id) WHERE org_id IS NULL;
CREATE UNIQUE INDEX paddle_trial_uses_org ON paddle_trial_uses (org_id) WHERE org_id IS NOT NULL;

COMMENT ON TABLE paddle_trial_uses IS
    'FR-10: the first free trial of an account scope (org_id NULL) or of an org; the checkout refuses a second trial. Class S, ids and a time only.';

GRANT SELECT, INSERT ON paddle_trial_uses TO sbci_api;
GRANT SELECT, INSERT ON paddle_trial_uses TO sbci_app;

ALTER TABLE paddle_subscriptions ADD COLUMN seat_quantity integer;

COMMENT ON COLUMN paddle_subscriptions.seat_quantity IS
    'FR-22: the quantity Paddle bills the first item for (data.items[0].quantity), as last reported; NULL when unknown.';
