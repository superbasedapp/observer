// Package delivery is the pure core of commit to PR to merge tracking
// (docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md): the closed
// vocabularies and row shapes (types.go), remote URL parsing and provider
// classification, the GitHub status mapping table, the ordered landing
// rule table, and the funnel and metric math the Projects page and the org
// wire share.
//
// PURE (CLAUDE.md module-boundary rule 1): no database/sql, net/http,
// os/exec or fsnotify; every input arrives as plain values. Pinned by
// imports_test.go.
package delivery
