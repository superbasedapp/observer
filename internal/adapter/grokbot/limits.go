package grokbot

// NoLimitSource is the operator-facing reason Grok Bot never produces a
// usage/quota gauge (docs/cost-predictor.md's 5h/weekly limit gauge).
//
// Investigated live 2026-09-22 against the real
// sand-client-persistence store: every ".blob" filename decoded from its
// base32-encoded dotted key (see blobname.go), and every decoded slice's
// plaintext-JSON content grepped for plan/tier/quota/usage/limit/billing/
// credit/subscription — zero structured hits. The slices present are
// ui-layout, client-meta.account-slot (just an auth0 user id),
// account.<id>.transcript.replicas.* (real saved conversations —
// incidental natural-language PROSE about usage limits can appear inside
// these if a transcript happens to discuss the topic, which is not a
// structured account-quota field), composer-drafts, roster.last-roster,
// selection.last-agent, send-journal, and sidebar.last-sections.
//
// This is a structural absence, not a parsing gap: Grok Bot's agent runs
// in a remote sandbox VM (same TokenTier finding in
// internal/integration's "grokbot" registry row — tokens/model/cost are
// honestly absent for the identical reason), so there is no local
// process on this machine that could ever carry subscription/quota
// state, in principle, not just in this snapshot.
//
// Kept byte-identical to internal/integration's "grokbot" registry row
// Limit.Note (registry_coverage_test.go cross-checks the two never
// drift); the registry canNOT import this package without breaking its
// deliberate zero-internal-import purity (internal/integration currently
// imports nothing but "sort" — see internal/integration/imports_test.go),
// so the two live as independent literals instead of one being derived
// from the other.
const NoLimitSource = "Grok Bot runs its agent in a remote sandbox - no local file or process on this machine carries usage/quota data. Check the Grok Bot app's own account panel."
