-- 0135_paddle_binding_refusals.sql - a durable record of every Paddle
-- delivery's outcome, and of every refused subscription binding (Fable review
-- 2026-11-17 FR-2; docs/security.md BILL-FR2).
--
-- step: expand
--
-- WHY. A refused binding used to be acked 200 and forgotten: the outcome lived
-- only in a security_audit_events action name, and the sweeper deleted the
-- checkout intent. A customer whose first webhook was refused (for example a
-- checkout completed after the old 30-minute intent window) was charged and
-- got no plan, and nothing an operator could query said so.
--
--   billing_events.outcome   the intake outcome of the delivery (applied,
--                            binding_refused, terminal_pending, ...), stamped
--                            with processed_at. NULL on rows written before
--                            this step and on an unfinished delivery.
--
--   paddle_binding_refusals  one row per refused binding delivery: the Paddle
--                            ids an operator needs to find the payment in
--                            Paddle (subscription, customer, price), whether
--                            the price is one this deployment sells (a known
--                            price means a paying customer), the machine
--                            reason, and resolved_at, stamped when a later
--                            delivery for the same subscription binds it.
--
-- WHAT IS NOT HERE. No account id: the custom_data account id is untrusted on
-- a refusal (it may name no account, or someone else's), so it is not kept.
-- No card or payment data. CLASS S (no row-level security), like
-- billing_events and checkout_intents: the webhook (sbci_api) writes it and
-- the operator (sbci_app) reads it; no DELETE for any role.

SET LOCAL lock_timeout = '5s';

ALTER TABLE billing_events ADD COLUMN outcome text;

COMMENT ON COLUMN billing_events.outcome IS
    'FR-2: the intake outcome stamped with processed_at (applied, binding_refused, terminal_pending, terminal_kept, ...). NULL before 0135 and while a delivery is unfinished.';

CREATE TABLE paddle_binding_refusals (
    event_id               text        NOT NULL PRIMARY KEY CHECK (event_id <> ''),
    event_type             text        NOT NULL CHECK (event_type <> ''),
    paddle_subscription_id text        NOT NULL CHECK (paddle_subscription_id <> ''),
    paddle_customer_id     text,
    price_id               text,
    -- true when price_id maps to a plan this deployment sells: the refusal
    -- concerns a paying customer and is an alert, not noise.
    price_known            boolean     NOT NULL,
    reason                 text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 64),
    note                   text        CHECK (note IS NULL OR char_length(note) <= 500),
    occurred_at            timestamptz,
    recorded_at            timestamptz NOT NULL DEFAULT now(),
    -- Set when a later delivery binds this subscription after all.
    resolved_at            timestamptz
);

CREATE INDEX paddle_binding_refusals_subscription ON paddle_binding_refusals (paddle_subscription_id);
CREATE INDEX paddle_binding_refusals_open ON paddle_binding_refusals (recorded_at) WHERE resolved_at IS NULL;

COMMENT ON TABLE paddle_binding_refusals IS
    'FR-2: one row per refused Paddle subscription binding (Paddle ids, price, machine reason, resolved_at). Class S, content-free, no account id.';

GRANT SELECT, INSERT, UPDATE ON paddle_binding_refusals TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON paddle_binding_refusals TO sbci_app;
