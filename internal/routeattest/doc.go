// Package routeattest classifies every registered adapter's proxy-route
// posture into a full-coverage matrix of attestations — never a matrix of
// gaps (Plane B dual-mode gateway RBAC/IA design
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §3.3,
// tracker item "Full-coverage attestation (HG1)").
//
// The package dispatches on the integration registry's RouteKind capability
// SHAPE (internal/integration.RouteKind), never on tool name (CLAUDE.md
// "Module Boundaries & Anti-Spaghetti Discipline" rule 3), so a future
// adapter that lands with a known RouteKind automatically inherits that
// kind's inspector, and a tool whose route posture cannot be read from
// config falls back to a traffic-observed attestation rather than being
// silently unobserved.
//
// Three attestation methods, in dispatch order:
//
//   - Exempt: the registry marks the tool RouteStatusNativeExempt (or its
//     Hook mechanism is HookBrowserExtension) — the tool has no routable
//     proxy surface by design and is shown as exempt, never as "unattested".
//   - Config: the tool's RouteKind has a grounded, tool-identity-aware
//     config reader (today: RouteEnvSettings for claude-code via
//     internal/proxyroute.InspectClaudeRouteWithGateways, RouteConfigFile
//     for codex via InspectCodexRouteWithGateways) that can actually read
//     ITS OWN config surface.
//   - Traffic: everything else — RouteKinds whose config surface isn't yet
//     readable (RouteProviderJSON, RouteVSCodeSettings, RouteLauncher,
//     RouteManual, or a tool sharing a kind with no per-tool reader, e.g.
//     qwen-code/kimi-code sharing RouteConfigFile with codex) — attested by
//     comparing native session-activity counts against proxied/gateway turn
//     counts via the caller-injected TrafficSource.
//
// The package is pure logic: no database/sql, net/http, or fsnotify import
// (enforced by imports_test.go). internal/proxyroute's file-reading
// inspectors are injected as plain function values, and traffic counts
// arrive through the TrafficSource interface — the caller (the observer
// daemon / server rollup) owns all I/O.
//
// AttestAll(homeDir, gateways, traffic) is the single entry point; its
// []RouteAttestation result is what a server-side rollup or the web2
// dashboard's per-node route-attestation matrix would consume directly —
// this package does no aggregation or persistence of its own.
package routeattest
