// Package secciwf is the security pillar's native CI workflow rules for
// GitHub Actions, S-771 to S-778 (security pillar plan
// docs/plans/security-pillar-plan-2026-10-19.md section 5.6; built in
// Phase C because the CI verify-lite step, F1, runs them: it is the
// ci_workflow row of internal/secverify's detector table).
//
// One closed rule table, one test case per row:
//
//	S-771 pull_request_target (or workflow_run) that checks out the PR head
//	S-772 ${{ github.event.* }} or github.head_ref interpolated into run:
//	S-773 the same interpolated into an AI agent step's prompt
//	S-774 a third-party action pinned by tag or branch, not a commit SHA
//	S-775 permissions: write-all (workflow or job)
//	S-776 no permissions block at all (flag only: the effective
//	      permission comes from an org or repository default the file
//	      does not show)
//	S-777 secrets exposed to a job that runs untrusted code (a
//	      pull_request_target job that checks out the PR head and reads a
//	      secret)
//	S-778 an AI agent step with a permission-bypass flag
//
// S-779 is reserved. The input is untrusted repository text: the parser
// reads at most MaxWorkflowBytes, findings carry a rule, a line and a
// fixed message (never repository text), and nothing is executed.
//
// The package is pure: no SQL, no HTTP, no process, no filesystem.
package secciwf
