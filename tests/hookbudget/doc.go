// Package hookbudget is the hook budget launch harness (joint roadmap piece
// F0-3): it times the real `observer hook` command, process start to exit,
// cold and warm, on testdata payloads, adds the hook context seam's own
// cost, and reports every row of internal/hookbudget's budget table. It is
// report-only and runs only when SBO_HOOK_BUDGET=1; see
// docs/hook-budget-harness.md.
package hookbudget
