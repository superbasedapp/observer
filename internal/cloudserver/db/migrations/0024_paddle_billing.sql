-- 0024_paddle_billing.sql — W9 Paddle billing (cloud-intelligence divergence
-- remediation plan §3 "W9"; operator ruling R4 "a real Paddle billing system is
-- COMMITTED as W9"; closes D6). Paddle is the billing event source / merchant of
-- record; this migration adds the two pieces of durable state W9 needs, built ON
-- TOP OF W4's plan machinery (plans / account_plans) so billing is NEVER a
-- competing entitlement source — a paid subscription resolves to a W4 plan
-- assignment (plan 'plus_beta'), and the caps/pools still come from `plans`.
--
--   billing_events — SYSTEM idempotency + audit log of Paddle webhook
--                    deliveries (mirrors workos_events exactly: a provider
--                    webhook log keyed by the provider's event id, content-free
--                    beyond ids/type/timestamps + a resolved account_id). It is
--                    NOT user content: the W6d deletion matrix classifies it
--                    `excluded`, same as workos_events. Idempotency is a DATABASE
--                    constraint (event_id PRIMARY KEY): a redelivery inserts
--                    nothing and replays. processed_at gates retry-safety — a
--                    delivery recorded but not finished (crash) has processed_at
--                    NULL and MUST re-run on redelivery.
--
--   paddle_subscriptions — TENANT (RLS ENABLE + FORCE): the account's live
--                    subscription linkage {paddle customer/subscription ids,
--                    the plan it grants, status, current period end}. This is
--                    account data: the W6d deletion matrix classifies it `purge`
--                    (removed on account deletion; the Paddle-side billing
--                    lifecycle is the operator's/ Paddle's concern, never the
--                    node's). One live subscription per account (partial unique).
--
-- Billing state NEVER lives in an access token as sole authority (plan §3 W9):
-- entitlement is always resolved from account_plans/plans, which this only
-- feeds. Cancellation removes FUTURE paid allowance at period end (an
-- account_plans reassignment to 'free' effective at current_period_end, floored
-- by W4's downgrade-at-cycle-end rule) and NEVER touches the local node or
-- deletes results.

-- ===========================================================================
-- billing_events — provider webhook idempotency + audit log (SYSTEM).
-- ===========================================================================
CREATE TABLE billing_events (
    -- Paddle's own notification id (evt_...). PRIMARY KEY = idempotency: a
    -- redelivery of the same event inserts nothing.
    event_id     text NOT NULL PRIMARY KEY CHECK (event_id <> ''),
    event_type   text NOT NULL CHECK (event_type <> ''),
    -- The account this event resolved to, once known (from Paddle custom_data).
    -- NULL when an event could not be attributed (logged, not acted on).
    account_id   uuid REFERENCES accounts(account_id),
    -- When Paddle says the event occurred (provider clock), for ordering/audit.
    occurred_at  timestamptz,
    received_at  timestamptz NOT NULL DEFAULT now(),
    -- NULL until handling COMPLETES. A row with processed_at NULL is an
    -- in-flight/failed delivery a redelivery must re-run (retry-safety).
    processed_at timestamptz
);

CREATE INDEX billing_events_account ON billing_events (account_id) WHERE account_id IS NOT NULL;

COMMENT ON TABLE billing_events IS
    'W9 Paddle webhook idempotency + audit log (mirrors workos_events). SYSTEM data, not user content; deletion matrix = excluded. event_id PK = idempotency; processed_at NULL = retry-safe redelivery.';

-- ===========================================================================
-- paddle_subscriptions — the account's live subscription linkage (TENANT).
-- ===========================================================================
CREATE TABLE paddle_subscriptions (
    account_id            uuid NOT NULL REFERENCES accounts(account_id),
    paddle_customer_id     text NOT NULL CHECK (paddle_customer_id <> ''),
    paddle_subscription_id text NOT NULL CHECK (paddle_subscription_id <> ''),
    -- The W4 plan this subscription grants (name+version → plans).
    plan_name             text NOT NULL CHECK (plan_name <> ''),
    plan_version          int  NOT NULL CHECK (plan_version >= 1),
    -- Paddle subscription status: active | canceled | past_due | paused.
    status                text NOT NULL CHECK (status IN ('active','canceled','past_due','paused')),
    -- End of the paid period. On cancellation the paid allowance is removed at
    -- THIS instant (not immediately) — the account keeps what it paid for.
    current_period_end    timestamptz,
    canceled_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, paddle_subscription_id),
    UNIQUE (paddle_subscription_id)
);

-- One LIVE (non-canceled) subscription per account.
CREATE UNIQUE INDEX paddle_subscriptions_one_live
    ON paddle_subscriptions (account_id)
    WHERE status <> 'canceled';

ALTER TABLE paddle_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE paddle_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY paddle_subscriptions_tenant ON paddle_subscriptions
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- ===========================================================================
-- Grants. The webhook + portal Billing surfaces are front-door (serve) paths, so
-- sbci_api owns the DML; sbci_app mirrors for dev/single-process + tests. The
-- worker never touches billing.
-- ===========================================================================
GRANT SELECT, INSERT, UPDATE         ON billing_events        TO sbci_api;
GRANT SELECT, INSERT, UPDATE         ON billing_events        TO sbci_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON paddle_subscriptions  TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON paddle_subscriptions  TO sbci_app;
