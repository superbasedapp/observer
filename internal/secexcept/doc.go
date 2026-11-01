// Package secexcept is the pure core of the security pillar's local
// finding exceptions and baselines (security pillar plan
// docs/plans/security-pillar-plan-2026-10-19.md sections 4.5.2, 5.12 and
// 6.3; Phase C, lane sec-c3).
//
// An exception is "this is not a real problem" for ONE finding: it is
// scoped to the finding's location-free lifecycle key in one project, it
// always expires (1 day, 7 days, 30 days, or until the file changes), and
// it is granted only by a local owner (the CLI or the dashboard), never by
// a repository file or an agent. It is never rule-wide, so it can never
// lower a rule for a project (adversarial case X8): the rule keeps firing
// everywhere else, and the same finding comes back when the exception
// ends.
//
// The package holds the closed pickers (Reasons, Expiries), the grant
// refusal table (Plan) and the lifecycle table (Judge), and the baseline
// commit check (CheckBaselineCommit). It does no I/O: the store, the file
// fingerprint and git are the caller's (internal/secsvc and cmd/observer).
//
// It belongs to the `security` module root; only build-tagged callers
// import it, so a build with sbo_omit_security links none of it.
package secexcept
