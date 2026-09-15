// Package quiesce is the node's bounded-drain primitive: the substrate an
// in-place binary update needs in order to stop serving, wait for what is
// already in flight, and — always — start serving again.
//
// It exists because of ruling R9/R13 of
// docs/plans/enterprise-update-management-plan-2026-09-07.md. CLAUDE.md's
// "don't stop/restart the daemon while the proxy route is active" exists
// because a restart hands a live proxied session ConnectionRefused, and
// scripts/restart-daemon.sh states the safe sequence as
// "route OFF -> restart daemon -> route ON". A node cannot flip its client's
// base URL, so the closest honest equivalent of "route OFF" is a retryable
// refusal: 503 with Retry-After. And a point-in-time "is anything in flight?"
// check is strictly weaker than the rule it cites — it races the request that
// arrives during the restart window. So this is a DRAIN, not a sample.
//
// Two types, both pure:
//
//   - Gate is one admission point plus its in-flight counter. internal/proxy
//     holds one, injected as an interface on its Options so the proxy never
//     imports this package and no type leaks past that seam (CLAUDE.md #2).
//   - Quiescence composes a Gate with any number of named "live work"
//     counters — dashboard PTY sessions, a running backfill — and performs
//     the bounded drain over all of them.
//
// The one guarantee this package makes, and the reason Resume is a defer and
// not a happy-path statement: EVERY drain either completes and proceeds, or
// times out, RESTORES normal admission, and reports a failure. There is no
// state in which a node is left refusing traffic because an apply gave up
// (ruling R13). A half-drained daemon is worse than the update it was serving.
//
// Purity: no database/sql, no net/http, no os/exec, no fsnotify — pinned by
// imports_test.go. This package counts and waits; it does not know what a
// request is, what a PTY is, or what an update is.
package quiesce
