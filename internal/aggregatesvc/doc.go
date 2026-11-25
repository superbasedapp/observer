//go:build !sbo_omit_egress_aggregate_share

// Package aggregatesvc is the node-side COLLECTOR for the opt-in aggregate
// rail (G25 design §6, Phase 4). It is the SINGLE seam that assembles a
// finalized month's coarsened aggregate from the node's local tables and
// drives the gated submission lifecycle — consent gate -> node-local ledger ->
// hardened egress -> mark — so the lifecycle lives in exactly one place.
//
// Both the `observer aggregate` CLI (preview/status/submit) and (Phase 5) the
// daemon's monthly auto-submit tick call this collector. SubmitDue is the
// clean Phase-5 hook: it resolves the most-recently-finalized month and submits
// it iff consent is valid, staying inert (nothing built, nothing sent) when the
// rail is off, not consented, or the month is already submitted.
//
// Impurity is CONCENTRATED at seams, never written here: the payload assembly
// is an injected Builder (the real one wraps internal/aggregatesource + the
// cost engine in cmd), the node-local ledger + consent receipt come from
// internal/store, and egress goes ONLY through internal/aggregateclient — whose
// unforgeable Gate makes an unconsented send structurally impossible. This
// package writes no raw I/O of its own: no database/sql, no net/http, no
// fsnotify — pinned by imports_test.go.
package aggregatesvc
