-- 0030_paddle_refund_checkout_binding.sql — Stream 5 (arc2 production-gap
-- register G2-08 + the code half of G2-07). Two additions on top of the W9
-- Paddle billing state machine (migrations 0024/0025):
--
--   (G2-07 / F2 core) SERVER-INITIATED CHECKOUT BINDING. Before this, the
--   webhook trusted `data.custom_data.account_id` alone to bind a subscription
--   to an account — a user who initiates their OWN Paddle checkout can set
--   custom_data to any account id, so a signed delivery could bind (or grant a
--   plan to) a victim account. `checkout_intents` is the server-side proof: the
--   portal mints a single-use nonce for the AUTHENTICATED account, stores its
--   sha256 (never the raw value), and puts the raw nonce in the checkout's
--   custom_data. The webhook only binds a subscription→account when the event's
--   custom_data.checkout_nonce matches a live (unconsumed, unexpired) intent for
--   the claimed account — the untrusted account id alone no longer binds.
--   SYSTEM table (like billing_events / exchange_nonces): content-free (a hash +
--   an account id + a price id), read/written by the front-door role directly,
--   no RLS. ON DELETE CASCADE keeps the retention sweep's `DELETE FROM accounts`
--   FK-safe and purges the ephemeral rows with the account; the TTL expires them
--   long before that.
--
--   (G2-08) REFUND / CHARGEBACK RESOLUTION. Refunds and chargebacks arrive as
--   `adjustment.*` events that carry NO custom_data — only a subscription_id.
--   `sbci_paddle_account_for_subscription` is the SECURITY DEFINER resolver
--   (owner sbci_defs, BYPASSRLS) that maps a bound subscription id back to its
--   account without tenant context, so an adjustment can be attributed to the
--   account that already owns the subscription (the TRUSTED linkage, never
--   custom_data). It returns only the account id — an identifier, no content.
--   A full refund / chargeback revokes paid access; the subscription row records
--   the honest terminal state, so `status` gains 'refunded' and 'charged_back'.

-- ===========================================================================
-- checkout_intents — server-minted, single-use checkout nonce (SYSTEM).
-- ===========================================================================
CREATE TABLE checkout_intents (
    intent_id    uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The AUTHENTICATED account the portal minted this intent for. ON DELETE
    -- CASCADE: the row is ephemeral account-scoped pre-checkout state (like
    -- exchange_nonces), so it dies with the account and never blocks the
    -- retention sweep's DELETE FROM accounts.
    account_id   uuid NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    -- sha256 of the server-minted nonce. The raw nonce is returned to the
    -- authenticated browser ONCE (it travels in the checkout custom_data) and is
    -- never stored — exactly the exchange_nonces / auth_transactions discipline.
    nonce_hash   bytea NOT NULL,
    -- The Paddle price this checkout is for (audit / cross-check only; the plan
    -- grant is still resolved from the price map at webhook time).
    price_id     text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- TTL: a nonce is only bindable while now() < expires_at.
    expires_at   timestamptz NOT NULL,
    -- Single-use: set when a webhook consumes this intent to bind a subscription.
    consumed_at              timestamptz,
    consumed_subscription_id text,
    UNIQUE (nonce_hash)
);

CREATE INDEX checkout_intents_account ON checkout_intents (account_id);
CREATE INDEX checkout_intents_expiry  ON checkout_intents (expires_at);

COMMENT ON TABLE checkout_intents IS
    'G2-07/F2 server-initiated checkout binding: single-use, TTL''d, sha256-hashed nonce minted for an authenticated account. SYSTEM data, content-free; the webhook requires a matching live intent before binding a subscription to an account.';

GRANT SELECT, INSERT, UPDATE, DELETE ON checkout_intents TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON checkout_intents TO sbci_app;

-- ===========================================================================
-- sbci_paddle_account_for_subscription — resolve a bound subscription's account
-- without tenant context (SECURITY DEFINER, owner sbci_defs = BYPASSRLS).
-- Adjustment events carry no custom_data, so attribution goes through the
-- already-bound paddle_subscriptions linkage (trusted), never custom_data.
-- Returns ONLY the account id (an identifier, no content), same DEFINER
-- hardening as the W5 community functions.
-- ===========================================================================
CREATE OR REPLACE FUNCTION sbci_paddle_account_for_subscription(p_subscription_id text)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT ps.account_id
      FROM public.paddle_subscriptions ps
     WHERE ps.paddle_subscription_id = p_subscription_id
     LIMIT 1;
$$;

ALTER FUNCTION sbci_paddle_account_for_subscription(text) OWNER TO sbci_defs;
REVOKE ALL  ON FUNCTION sbci_paddle_account_for_subscription(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_paddle_account_for_subscription(text) TO sbci_api;
GRANT EXECUTE ON FUNCTION sbci_paddle_account_for_subscription(text) TO sbci_app;
-- The DEFINER owner needs the base table privilege (BYPASSRLS bypasses ROW
-- policies, not table GRANTs) — same as the W5 community DEFINER functions.
GRANT SELECT ON paddle_subscriptions TO sbci_defs;

-- ===========================================================================
-- paddle_subscriptions.status — record the refund/chargeback terminal states.
-- 'refunded' (a full, approved refund revoked paid access) and 'charged_back'
-- (a chargeback reversed the payment) are honest terminal states the portal
-- Billing surface shows; a chargeback_reverse restores the row to 'active'.
-- ===========================================================================
ALTER TABLE paddle_subscriptions DROP CONSTRAINT paddle_subscriptions_status_check;
ALTER TABLE paddle_subscriptions
    ADD CONSTRAINT paddle_subscriptions_status_check
    CHECK (status IN ('active','canceled','past_due','paused','refunded','charged_back'));

-- The "one live subscription per account" guard must treat refunded/charged_back
-- as NOT-live (a revoked subscription no longer occupies the live slot), the same
-- way 'canceled' is excluded. Recreate the partial unique index accordingly.
DROP INDEX paddle_subscriptions_one_live;
CREATE UNIQUE INDEX paddle_subscriptions_one_live
    ON paddle_subscriptions (account_id)
    WHERE status NOT IN ('canceled','refunded','charged_back');
