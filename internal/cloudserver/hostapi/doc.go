// Package hostapi is the pure core of the control plane's client of the
// tenant host API (/platform/v1; managed-SaaS plan 07 row M6.4, plan 06
// section 5.8.2, design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md
// sections 3.3 and 4.6). The wire contract is internal/platformcontract; the
// host's side is internal/orgserver/hostapi. This package holds no transport,
// no SQL and no keys; the I/O composition (signing, mTLS, the outbox store,
// the dispatcher and reconciler loops) is the hostclient subpackage.
//
// What lives here, each a data table walked top-down with one test per row:
//
//   - intents (intent.go): the five mutating verbs as outbox intents, with
//     deterministic idempotency keys, so the control-plane change and its
//     intent commit in one transaction and a duplicate enqueue is one row;
//   - the verb table (verbs.go): how a queued intent becomes a contract
//     request (method, path from platformcontract, body), and how a VERIFIED
//     success body is judged per verb; plus the two read probes the
//     reconciler sends (route-check and health);
//   - the answer rules (judge.go): what the dispatcher does with an answer.
//     Success is decided by the SIGNED body only, never by the HTTP status
//     (the status is not covered by the response signature). An answer that
//     did not verify is never a success. A verified refusal of class 409
//     (replayed, idempotency_in_progress) is retried as a new request: a new
//     nonce, the same idempotency key; a 5xx class (unavailable, internal) is
//     retried; a create the host put on its capacity waitlist
//     (capacity_waitlist, 503, lead decision W14-D4) stays open with that
//     error class and is retried no sooner than WaitlistMinDelay; every other
//     refusal parks the intent for an operator and is never resent blind;
//   - the retry schedule (backoff.go): exponential with injected jitter, a
//     one-hour cap;
//   - the reconciliation rules (reconcile.go): desired state (the orgs row)
//     against what the host reports (route-check, health), yielding findings
//     and at most one correction intent, which goes through the same outbox;
//   - the usage pull (usage.go; M6.0 Q11): the usage request per receipt
//     day, the reading of a verified report (with its body digest) and the
//     rules that decide which tenant entries are stored (only an org the
//     control plane placed on the reporting host, once per report).
//
// Imports are pinned by imports_test.go: platformcontract and a closed
// standard-library list only, no net/http, no database/sql, no store.
package hostapi
