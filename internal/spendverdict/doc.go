// Package spendverdict is the node's ONE owner of the stored proxy/transcript
// dedup verdicts (agent migration 143: spend_verdict_token,
// spend_verdict_proxy, spend_verdict_dirty, spend_verdict_state) - the node
// mirror of the org's rollup/spenddedup.go.
//
// A session's spend follows one rule, internal/sessionmsg.Derive. Surfaces
// that read ONE session (the session header, the Messages tab, the
// predictor's shape, the sub-agent / task drill-downs, the cloud evidence)
// run it live over that session's rows, loaded by LoadSession. Surfaces that
// sum api_turns ∪ token_usage across a WINDOW of many sessions (the cost
// engine, the guard's budget windows, the predictor's cross-session prior)
// cannot run it per row in SQL, so Derive's per-row decisions are stored
// here and those surfaces apply them with the SQL fragments in sql.go
// (CountedTokenRow, ProxyVerdictJoin, CountedProxyRow, ProxyOutput, ...)
// and sum the ordinary way. A session's windowed sum therefore equals its
// header by construction, whatever window cuts through it.
//
// Refresh is the only writer. Triggers on api_turns, token_usage and
// sessions queue a changed session in spend_verdict_dirty; Refresh
// re-derives every queued session, each inside a write transaction that also
// clears its queue entry. A windowed reader calls Refresh first, and the
// daemon runs it on a ticker so a reader rarely finds work to do.
//
// The package reads and writes SQL (it is a store seam, not a pure package);
// the derivation itself stays in internal/sessionmsg, and the capability
// flags come from internal/integration by capability shape, never by tool
// name (CapsFor).
package spendverdict
