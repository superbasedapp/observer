// Package secverify is the pure core of `observer security verify`, the CI
// verify-lite check (security pillar plan section 7.9, phase F1; joint
// roadmap lane sec-f1).
//
// It judges one pull request diff, read as DATA, never executed:
//
//   - ParseDiff (with ParseNameStatus) turns the bytes of `git diff
//     --name-status -z` and `git diff -U0` (fetched by the cmd layer through
//     gitview's read-only envelope) into ChangedFile rows, under caps.
//   - Detectors() is the closed native detector table. Each row is a pure
//     function over the changed files; a row whose detector lives in a later
//     phase (CI workflow rules and test tampering in phase C, repository
//     trust in phase B, the install index in phase D1) is listed with no
//     function and reports "not in this build", never clean.
//   - Policy is the hermetic policy: it comes only from a file the caller
//     names outside the repository under test (the required workflow's own
//     protected checkout), from the BASE commit as a labelled advisory
//     fallback, or from the built-in defaults. The PR head's policy, the
//     project config and the environment are never read (the package reads
//     nothing at all; the cmd layer never calls config.Load for verify).
//   - Verify walks the detectors and decides the verdict from the ordered
//     rule table verdictTable in verify.go: an error, a truncated diff or a
//     required detector that did not finish is `unknown` (exit 2, fail
//     closed); a finding whose action is deny under mode enforce is `fail`
//     (exit 1), and so is a commit with no verified AI change record when
//     the policy's provenance floor is "fail"; otherwise `pass` (exit 0).
//   - checkProvenance (provenance.go, lane SEC-F2A) checks each commit's
//     signed AI change records (internal/secchange) offline against a keys
//     file the caller names outside the repository under test; a commit
//     with none verified is unknown_provenance, a review label by default.
//   - WriteSARIF renders SARIF 2.1.0 that GitHub code scanning accepts.
//     Locations are project-relative URIs only (an absolute file:// prefix
//     under the root is stripped, anything outside the root is refused),
//     no result ever carries a snippet, message text comes from templates
//     and never from repository text, and an empty result list is never
//     presented as clean: the run's invocation records whether the
//     execution finished and every detector's coverage is a notification
//     (security plan 4.5.3 as amended by JSP-8 and JSP-12).
//   - RenderWorkflow renders the required-workflow template the setup guide
//     ships (docs/security-verify.md), with the binary pinned by version,
//     SHA-256 and vendor signature.
//
// No LLM, no network, no database, no process: the package imports no
// os, os/exec, net, database/sql or fsnotify (imports_test.go).
package secverify
