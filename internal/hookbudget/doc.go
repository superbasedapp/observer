// Package hookbudget is the hook budget harness's pure core (joint security
// and sandbox roadmap docs/plans/security-and-sandbox-joint-roadmap-2026-10-20.md,
// piece F0-3; security pillar plan
// docs/plans/security-pillar-plan-2026-10-19.md sections 4.7, 4.8 and 6.4;
// roadmap spike JSP-2 for the relay).
//
// It holds the one budget table (a whole hook launch cold and warm, the
// hook context seam's own cost, the three hook-side security budgets of
// sections 4.7 and 4.8, and a slot for the sandbox relay's overhead), the
// sample statistics, the verdict rules and the report rendering. It
// measures nothing itself: the launch harness in tests/hookbudget runs the
// real `observer hook` command and feeds samples in, and a later phase
// that builds a sidecar reader, a detector set, a quick scan or the relay
// registers a probe for its row. A row with no probe reports "not built",
// never a number.
//
// Pure: no SQL, HTTP, fsnotify or process execution (imports_test.go).
// See docs/hook-budget-harness.md for how to run it.
package hookbudget
