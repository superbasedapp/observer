// Package pricingfeedgate is the EGRESS SEAM for the standalone-node public
// pricing feed (docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md
// §C.3). It is the node's ONLY importer of the network lane
// (internal/pricingfeed/client), mirroring the role internal/cloudgateway plays
// for the cloud lane.
//
// WHY A SEAM AT ALL. The zero-egress-by-default invariant (D3) is structural,
// not a promise: tests/invariant/pricing_feed_egress_test.go pins that the
// always-on daemon packages (internal/watcher, internal/proxy, internal/store,
// internal/hook) AND the org push loop (internal/orgclient) transitively import
// NONE of the network lane, and that the lane is reachable only through THIS
// package. cmd/observer reaches the network exclusively by composing this gate,
// so no command — and no future background path — can obtain a network client
// without going through the one auditable entry point.
//
// WHAT THE GATE ADDS over the raw lane: it binds the TRUST check to the fetch.
// A 200 body is decoded by the lane and then VERIFIED here (pricingfeed.Verify
// against the compiled vendor key set) before it is returned, so a caller can
// never act on an unsigned, mis-signed, tampered, or wrong-schema body — the
// gate returns a typed verification error and the caller keeps its cached
// prices. Replay/version reasoning (is this feed_version newer than what we
// already applied?) stays with the caller, because only the caller holds the
// node's cache.
package pricingfeedgate
