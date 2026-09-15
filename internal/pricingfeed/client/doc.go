// Package client is the NETWORK LANE of the standalone-node pricing feed
// (docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §C.3).
//
// It is the one place a node makes an outbound HTTP request for the PUBLIC
// pricing feed, and it is IMPORT-ISOLATED exactly like internal/cloudclient:
// the always-on daemon packages (internal/watcher, internal/proxy,
// internal/store, internal/hook) and the org push loop (internal/orgclient)
// must NEVER transitively link it, and only internal/pricingfeedgate — the
// egress seam reached from cmd/observer — may import it. That isolation is
// pinned structurally by tests/invariant/pricing_feed_egress_test.go (the
// sibling of TestCloudClientIsolatedToConsentGateway), which is what keeps "an
// individual node makes no network call by default" (D3) true by construction
// rather than by discipline.
//
// The lane does TRANSPORT only — GET with If-None-Match, a bounded body, a
// JSON decode, and typed errors. It performs NO signature verification and NO
// replay/version reasoning: the offline trust check (pricingfeed.Verify against
// the compiled vendor key) and the cache-replay guard are the gate's and the
// sync command's jobs, so the one network-touching package stays as small and
// as auditable as possible.
package client
