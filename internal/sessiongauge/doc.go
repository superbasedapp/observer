// Package sessiongauge is the ONE pure derivation behind the session detail's
// two "how much room is left" gauges, shared by the node's session endpoints
// (internal/intelligence/dashboard) and the org session drawer's rollup
// (internal/orgserver/rollup), so the two dashboards cannot drift through two
// implementations of the same arithmetic (the node-session-detail trickle-up
// rule; see internal/sessionmsg for the message-bucketing precedent).
//
//   - Context: the context-window gauge. Used tokens are the running cache
//     prefix (the newest non-zero cache_read over the session's counted turn
//     rows, the rows sessionmsg.DeriveVerdicts keeps); the ceiling is the
//     first known value of an ordered ladder (the session's own reported
//     context budget, then the model's context window from the pricing
//     catalog). No ceiling means the ratio is unknown, never 0%.
//   - Limit: the subscription rate-limit gauge ladder (an audited
//     no-local-source registry finding, then the newest proxy-captured
//     window, then the tool's own transcript-captured window, then the named
//     "needs proxy" / "no window" absences).
//
// Pure: no database/sql, no net/http, no fsnotify (pinned by imports_test.go).
// Every caller loads its own rows with its own SQL and passes plain values in.
package sessiongauge
