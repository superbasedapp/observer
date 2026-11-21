// Package secciwf is the security pillar's native CI workflow rules for
// GitHub Actions, S-771 to S-784 (security pillar plan
// docs/plans/security-pillar-plan-2026-10-19.md section 5.6 and OS and CI
// vulnerability scanning plan
// docs/plans/os-and-ci-vulnerability-scanning-plan-2026-11-04.md section 5;
// built in Phase C because the CI verify-lite step, F1, runs them: it is the
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
//	S-779 a uses: action whose version has a known advisory in OSV's
//	      GitHub Actions ecosystem. Check never emits it: matching needs
//	      the OSV database, so the dependency scan child matches
//	      ActionRefs (actions.go) and raises the finding with the
//	      advisory's own severity. The row exists so the rule id, ceiling
//	      severity and message are known to policy and feedback code.
//	S-780 run: installs OS packages with no version (flag only)
//	S-781 run: installs language packages with no version or lock (flag
//	      only)
//	S-782 run: pipes remote content into an interpreter
//	S-783 runs-on names a moving runner label such as ubuntu-latest (flag
//	      only; one finding per file, at the first such label)
//	S-784 a job container, a service image or a docker:// step not pinned
//	      by an @sha256: digest
//
// S-780 to S-782 are decided by internal/secshellrisk, the one owner of
// the three script classifications (shared with the Dockerfile rules); the
// run: text is parsed in the step's shell dialect (shell:, else
// defaults.run.shell of the job, else of the workflow, else PowerShell on a
// windows-* runner and POSIX otherwise).
//
// The input is untrusted repository text: the parser reads at most
// MaxWorkflowBytes, findings carry a rule, a line and a fixed message
// (never repository text), and nothing is executed.
//
// The package is pure: no SQL, no HTTP, no process, no filesystem.
package secciwf
