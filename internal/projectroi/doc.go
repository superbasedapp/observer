// Package projectroi computes, per project, whether AI spend is turning
// into shipped work: it links AI-authored edits to the prompts that
// caused them and the commits that later carried them, attributes spend
// across that chain, and derives a small set of honestly-captioned ROI
// proxies from the result.
//
// It is a PURE package per CLAUDE.md module-boundary rule #1: no
// database/sql, no net/http, no fsnotify, no os/exec, and no imports of
// internal/store or internal/commitlog. All I/O — loading prompts,
// edits, commits, turns, tasks and sessions — happens at the store seam
// (internal/store/projectroi.go); this package only receives plain row
// slices and returns plain results. Purity is pinned by imports_test.go.
//
// Three entry points, used in order by the dashboard handler:
//
//  1. Link implements the ordered attribution rule from
//     docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md
//     §2 R4: which prompt an AI edit belongs to, which (prompt, file)
//     pairs are superseded by a later prompt's edit to the same file,
//     and which surviving pairs a later commit carries.
//
//  2. AttributeSpend splits each prompt's session-turn spend across the
//     commits its files reached, weighted by the prompt's own
//     file-count share of those commits. Turns that precede the first
//     prompt in a session are orphaned; a linked prompt's spend that
//     reaches no commit stays unattributed rather than being dropped.
//
//  3. Proxies turns a Linkage and a Spend into a fixed, honestly-labeled
//     set of ROI tiles (R10): every metric that cannot be computed from
//     the given inputs reports Available=false and says why, rather
//     than a fabricated or misleading number.
//
// Everything here operates on data the caller has already loaded and
// windowed; this package does no filtering by date range or project ID
// itself, and it does no I/O of any kind.
package projectroi
