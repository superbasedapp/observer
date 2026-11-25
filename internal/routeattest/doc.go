// Package routeattest judges every registered adapter's proxy-route posture
// into a full-coverage matrix of attestations — never a matrix of gaps
// (Plane B dual-mode gateway RBAC/IA design
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §3.3,
// tracker item "Full-coverage attestation (HG1)"; the per-surface judgement
// is surface-gap arc Wave 0.3,
// docs/plans/surface-gap-wave-0-design-2026-10-25.md section 5).
//
// AttestSurfaces is the entry point. It judges each observed session group
// (tool, capture surface kind, surface host) from the session counts the
// caller's store query supplies, against the registry facts a SurfacePolicy
// returns (RegistrySurfacePolicy reads them from internal/integration),
// through one ordered rule table. WithDeclaredSurfaces adds a zero-count
// group for every surface the registry declares for a tool that has run, so
// a declared surface with no session reads "unobserved" instead of
// vanishing. IsExempt names the registry rows that have no routable proxy
// surface by design. The facts come from the registry's capability shape,
// never a tool name (CLAUDE.md "Module Boundaries & Anti-Spaghetti
// Discipline" rule 3).
//
// Callers: the node's doctor (route.observed) and dashboard capture pill
// share ObservedWindow and WithDeclaredSurfaces; the org server's route
// matrix and budget coverage rollups fold the verdicts per tool.
//
// The package is pure logic: no database/sql, net/http, or fsnotify import
// (enforced by imports_test.go). Traffic counts arrive as plain values — the
// caller (the observer daemon / server rollup) owns all I/O — and this
// package does no aggregation or persistence of its own. A config-lane
// attestation, if one is wanted later, belongs on
// proxyroute.InspectRoutesWith, the one table-driven route inspector.
package routeattest
