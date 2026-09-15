// Package tagtaxonomy is the canonical, curated session-tag vocabulary shared
// across the product: the local dashboard's tag picker (mirrored in
// web/src/lib/tagTaxonomy.ts), the cloud Luna enrichment's controlled
// taxonomy_tags output (internal/cloudserver/jobs), and any node-side tag
// normalization that wants a definition for a standard tag.
//
// It is PURE DATA — no SQL, no HTTP, no fsnotify — so every surface can import
// it without coupling. Tags are SUGGESTIONS with definitions, never a hard
// enum on the node side (session_tags stays free-form; custom tags + custom
// definitions live in tag_definitions). The ONE place the taxonomy is enforced
// as a closed set is the cloud enrichment's strict json_schema, so the model's
// taxonomy_tags are standardized to this vocabulary; free-form model guesses go
// in suggested_tags instead.
//
// The TypeScript mirror (web/src/lib/tagTaxonomy.ts) MUST be kept in lockstep
// with Standard() — a divergence test (tagtaxonomy_mirror_test.go) fails if the
// slug set drifts.
package tagtaxonomy
