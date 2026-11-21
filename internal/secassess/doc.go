// Package secassess is the pure core of the agent-run security assessments
// module (docs/plans/security-assessments-module-plan-2026-11-13.md): the
// closed table of assessment kinds (threat model, local pen test and red team
// of the developer's own app, read-only cloud posture review, instrumented
// tests, and the honest "not agent-shaped" runtime-protection row), the
// eligibility rules a launch must pass, the prompt an agent is handed, the
// result-file contract, the preparation of the agent's SARIF report for the
// existing SARIF import, the read-only cloud-command classifier and the
// derived state of a run.
//
// It is pure: standard library only, no database, network, subprocess,
// filesystem or file watcher, and no other observer package
// (imports_test.go). In particular it imports nothing from the security
// component or from security.dast, so the component fence and the omit-tag
// builds are untouched. The dashboard routes and the service package
// (internal/secassesssvc) pass plain values in and out; nothing here is
// trusted from a client, and every string that came from a repository, a
// scanner or an agent is cleaned before it is used.
//
// Ownership: all work on this module is done by a Sonnet 5.5 subagent at xhigh
// effort (CLAUDE.md "Agent-run security assessments module: ownership rule").
package secassess
