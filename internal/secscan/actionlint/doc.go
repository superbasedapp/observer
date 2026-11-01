// Package actionlint is the `security.scan.actionlint` driver (security
// pillar plan docs/plans/security-pillar-plan-2026-10-19.md sections 4.4
// "actionlint as a linked driver", 5.6 and 8.7; Phase G, lane SEC-G5): the
// MIT-licensed github.com/rhysd/actionlint linked in process behind this
// facade, under its own omit tag and compiled only in the managed and full
// distros.
//
// actionlint runs shellcheck and pyflakes from PATH when it is told their
// names; this facade never tells it, so neither rule exists and no process
// starts (a test puts a fake shellcheck first on PATH and proves it never
// runs). It lints bytes the caller read (only .github/workflows/*.y*ml,
// under the CI rule caps) under a virtual path that does not exist, so
// actionlint never finds a project: it reads no repository config
// (.github/actionlint.yaml), no local action metadata and no local
// reusable workflow from disk. Its library API disclaims semantic-version
// stability, so the version is pinned (PinnedVersion) and a compatibility
// test checks the build carries exactly it.
//
// Findings are ci_config, low severity, medium confidence, flag only; the
// rule id is "actionlint/<kind>" and the message is templated, never
// actionlint's own text (section 9 T8).
package actionlint
