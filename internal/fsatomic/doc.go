// Package fsatomic writes a file atomically: a same-directory temp file,
// 0600, an optional fsync, then a rename.
//
// It exists because three copies of this sequence had already accumulated
// (internal/orgclient/policy.go, internal/orgclient/policyresource.go,
// internal/intelligence/dashboard/guardpolicy.go) and Phase 1b's governance
// sidecar would have been the fourth. The two orgclient copies were NOT the
// same function — one fsyncs and one does not (review m3) — so the switch is
// EXPLICIT here rather than assumed.
//
// A deliberate non-goal: this package carries no doc comment about
// transaction fences. policyresource.go's fsyncing copy ties its ordering
// guarantee to being called inside store.WithPolicyResourceFence; that is a
// property of THAT CALL SITE, not of the write, and carrying the claim onto
// a daemon-loop caller that holds no fence would be a false guarantee.
package fsatomic
