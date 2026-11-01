// Package deliverysvc is the delivery poll loop and the "Check now" path of
// the commit to PR to merge tracking arc
// (docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md, sections 7.2 and
// 12). It decides WHEN to reach a code host or a mirror and WHAT to ask;
// every network or git operation goes through internal/deliverynet (the
// only egress package), every row goes through a narrow injected Store
// interface (internal/store satisfies it), and the landing evaluation is an
// injected func (internal/landingscan owns the local evidence). The package
// itself imports neither os/exec nor a git helper.
//
// Zero egress by default: with no provider link and no project opted into a
// mirror, Run makes no call at all, and the OS keychain is not opened until a
// token link is connected, tested or used.
//
// Cadence and backoff are one ordered table (rules.go, the planlimits.NextRun
// shape): success polls again after the configured interval, a rate limit
// waits for the reset GitHub announced, an auth failure stops the link until
// the user reconnects or tests it, and transient failures back off 2, 4, 8 up
// to 60 minutes.
package deliverysvc
