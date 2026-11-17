-- 0136_paddle_pending_terminals.sql - a terminal Paddle event for a
-- subscription that is not bound yet is kept, by subscription id, until the
-- binding arrives (Fable review 2026-11-17 FR-8; docs/security.md BILL-FR8).
--
-- step: expand
--
-- WHY. After an outage Paddle may deliver subscription.canceled (or a full
-- refund / chargeback adjustment) before the subscription.created or
-- transaction.completed that binds the subscription. The terminal event used
-- to be acked and dropped as unattributed, so the later bind granted a plan
-- nothing would ever revoke.
--
-- RULE (store/paddle.go recordPendingTerminal, bindPendingTerminalTx): the
-- webhook records the terminal state here instead of dropping it; the binding
-- delivery reads it under the same per-subscription advisory lock and binds
-- the row in that terminal state with no plan, unless the binding delivery is
-- itself a paid transaction.completed that occurred after the terminal event
-- (the FR-7 re-activation rule). Recording, not a 5xx: a refused binding
-- would otherwise make Paddle retry the terminal event until it gave up.
--
-- CLASS S (no row-level security): Paddle ids, a status and two times; no
-- account id (none is known yet), no content. sbci_api writes it, sbci_app
-- mirrors for dev and tests; no DELETE for any role.

SET LOCAL lock_timeout = '5s';

CREATE TABLE paddle_pending_terminals (
    paddle_subscription_id text        NOT NULL PRIMARY KEY CHECK (paddle_subscription_id <> ''),
    status                 text        NOT NULL CHECK (status IN ('canceled', 'refunded', 'charged_back')),
    event_id               text        NOT NULL CHECK (event_id <> ''),
    occurred_at            timestamptz NOT NULL,
    current_period_end     timestamptz,
    recorded_at            timestamptz NOT NULL DEFAULT now(),
    -- Set when the binding delivery read it (bound terminal, or superseded by
    -- a later paid transaction).
    applied_at             timestamptz
);

COMMENT ON TABLE paddle_pending_terminals IS
    'FR-8: a terminal Paddle state (canceled, refunded, charged_back) seen for a subscription before it was bound; read at bind. Class S, content-free.';

GRANT SELECT, INSERT, UPDATE ON paddle_pending_terminals TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON paddle_pending_terminals TO sbci_app;
