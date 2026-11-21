// Package codequality is the pure core of the Projects page's quality
// metrics (docs/projects-page.md "Quality metrics"; plan
// docs/plans/os-and-ci-vulnerability-scanning-plan-2026-11-04.md section
// 14.10, item 8, phases M3L-2 and M3L-4): line coverage read from the
// report files a project's own test runs already wrote, duplication rolled
// up from code intelligence's body near-clone index, complexity rolled up
// from the per-function cyclomatic complexity code intelligence counts at
// index time, and the per-project daily trend of all three.
//
// It is PURE (CLAUDE.md module rule 1, pinned by imports_test.go): no
// database/sql, net/http, os/exec, fsnotify, and no os file reads. The
// caller hands in report bytes and index rows; the I/O boundary is
// internal/codequalitysvc (report discovery on disk) and the store seam
// internal/store/codequality*.go (the codeintel read and the
// project_quality_daily table).
//
// What lives here:
//
//   - coverage.go: the four report parsers (lcov, Cobertura XML, JaCoCo
//     XML, Go coverprofile) behind one sniff table. Every format is reduced
//     to LINES: a Go statement block marks each line it spans.
//   - discover.go: the closed table of report locations a project is
//     probed at, and the read caps.
//   - combine.go: folding the reports found into one project figure (the
//     same-run rule that drops a second format of one test run).
//   - duplication.go: the near-clone roll-up (shared MinHash LSH bands,
//     union-find into clone groups, line union per file).
//   - complexity.go: the complexity roll-up (functions over the threshold,
//     percentiles, per language, the most complex functions) and its state
//     table.
//   - state.go: the ordered state tables that decide every honest
//     "not measured" answer and its reason.
//   - measure.go: composing one measurement, the stored daily point
//     (numbers and states only) and a metric's change over the history.
//
// Nothing here runs a project's tests or any tool: a project with no
// report reads "no coverage report found", never zero coverage, and a
// project whose files have no complexity counter reads
// "no_supported_files", never zero complexity.
package codequality
