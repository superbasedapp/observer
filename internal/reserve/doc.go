// Package reserve is the one reserve-and-settle decision core (plan 07 row
// M7a.5, plan 06 section 17 "Ledgers"). Every reservation DECISION a ledger
// makes goes through it: whether a hold fits under its caps, which cap
// refused it and in what unit, what a settle, release, expiry or
// reconciliation books against the windows, whether a request key that was
// seen before is a replay, and which window bucket an instant falls in.
//
// The package is pure. It imports no database/sql, pgx, net/http or fsnotify
// (imports_test.go pins it). A caller keeps its own STORAGE: it locks and
// reads its counter rows in its own canonical order, hands the values to
// this package, and writes back what the returned decision says. The SQL,
// the lock order and the error vocabulary a caller's API maps to stay in the
// caller; the arithmetic does not.
//
// The decisions are rule tables walked top-down, first match wins, one test
// row per rule:
//
//   - limitRules decide one Limit: invalid input fails closed, then the
//     at-cap and over-cap boundaries.
//   - requestRules decide a whole Request: an estimate the caller cannot
//     compute in a capped unit refuses, an uncapped request whose estimate
//     is unknown refuses when the caller asks, then each cap Group in order
//     (the leading unit of a group is the one that exhausts first; a soft
//     group warns, a hard one refuses).
//   - settleRules decide how a hold closes: an already-final hold is an
//     idempotent no-op, a settle books its actual (an overrun is recorded,
//     never clamped; an underrun refunds the rest), a settle that cannot say
//     what it cost keeps the worst case, a release or expiry refunds all of
//     it, a reconciliation books the worst case.
//   - replayRules decide a request key seen before: fresh, rejoin the open
//     hold, or refuse as a replay or as in flight.
//   - windowRules key an instant into a daily, monthly or live bucket in a
//     given location.
//
// How the two ledgers differ is DATA on these types, never a second code
// path: the cloud service counts units (Unit Count) against daily, monthly,
// concurrency and budget-pool caps, one Group each, and checks its USD
// spend ceilings at the AtCap boundary because a job's cost is unknown
// before the call; the AI gateway counts USD and tokens against one Group
// per cap row, with soft or hard enforcement and the unpriced-model rule
// expressed as an unknown USD estimate.
package reserve
