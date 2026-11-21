// Package explorerview is the Plane A explorer's saved views and live tail
// dialect (W5-4, lane C9), shared by the org server (internal/orgserver/
// obsviews, rollup) and the machine (internal/obs/store, internal/obs/
// httpapi): the saved view model with its closed vocabularies and
// validation, the read:content redaction a shared view needs (rulings D23 and
// D25: end user, trace tag, metadata and content search are raw customer
// text), and the live tail bounds, cursors and rate limiter.
//
// It sits outside internal/obs on purpose: the org server may not import
// internal/obs (tests/invariant/obs_boundary_test.go), and one dialect must
// not be defined twice (plan of record principle 2, CLAUDE.md rule 4).
//
// Pure (CLAUDE.md rule 1): no database/sql, net/http or fsnotify. Pinned by
// imports_test.go.
package explorerview
