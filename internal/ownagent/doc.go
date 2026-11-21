// Package ownagent resolves the identity of a developer's OWN agent (one
// built on a raw provider API or SDK, not a registered coding tool) from the
// two optional proxy request headers, X-Superbased-Agent and X-Session-Id,
// into plain normalized data: an agent name token, a capture session id and
// whether this process has already seen that session (P-228, design
// docs/plans/discovery-sdk-2026-11-03.md section 4.1, phase 1).
//
// It is pure (CLAUDE.md "Module Boundaries" rule 1): no SQL, no HTTP, no
// fsnotify. The proxy reads the header values and hands this package plain
// strings; the store writes the session row; the org push seam asks
// WireSurfaceHost how the agent name may cross to an org.
//
// The agent name is stored in sessions.surface_host as "agent:<name>" so
// every surface that already reads the capture surface (Sessions filters,
// session detail, the org drawer) can group by it with no new column. The
// org wire ships the raw name only under ShareOptions.shipsRawContent() and
// otherwise a hash ("agent#<16 hex>"), decided by WireSurfaceHost.
package ownagent
