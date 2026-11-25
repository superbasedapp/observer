// SPDX-License-Identifier: BUSL-1.1
//
// Copyright (c) 2026 Marmut App

package main

// proxy_fallback.go — the pure, table-driven launch-time decision every tool
// launcher (`observer claude`, `observer codex`) consults before a bare launch
// to answer ONE question honestly: given the user's routing intent, whether the
// observer proxy is reachable, and whether the TOOL'S OWN persistent config
// bakes in a proxy route, should this launch (a) proceed routed through the
// proxy, (b) launch bypassing the proxy, or (c) refuse?
//
// Why this exists (resilient-attach scenario 4/5 + codex-parity):
// Claude Code's settings.json `env` block OVERRIDES the process environment
// (docs "How scopes interact" + the `env` description "Set a variable to `""` to
// override a shell export"; empirically confirmed 2026-07-20). Codex 0.130+
// likewise reads $CODEX_HOME/config.toml and silently drops the wrapper's argv
// `-c openai_base_url` override (V6-2). So when `observer init` bakes a proxy
// route into the tool's OWN persistent config, the launcher CANNOT neutralize it
// by touching the process env / argv — the tool reads its own config and keeps
// routing to the observer proxy. If that proxy is DOWN (the daemon-unreachable
// attach fallback, or a plain launch with the daemon stopped), every API call
// hits a dead proxy and the session is silently broken — the exact operator
// report the "notice + bare launch" fallback failed to honor.
//
// The decision is a pure function of THREE capability-shaped facts (never the
// tool name — CLAUDE.md #3): the user's no-proxy-route intent, proxy
// reachability, and whether the tool's persistent config routes to the proxy.
// Detection of the persistent route is per-tool I/O performed at the boundary
// (claudeConfigRoutesToProxy reads settings.json; codexConfigsRoutingToProxy
// reads config.toml) and injected here as a plain bool, so this function does no
// I/O and is exhaustively table-tested (CLAUDE.md #1/#5).

// proxyFallbackAction is what the launcher should do with the launch.
type proxyFallbackAction int

const (
	// proxyRouteProceed: route the launch through the observer proxy as normal
	// (the proxy is reachable and the user did not opt out). The happy path.
	proxyRouteProceed proxyFallbackAction = iota
	// proxyNeutralize: launch bypassing the observer proxy. Safe ONLY because no
	// persistent config route exists, so the launcher's own env/argv override
	// (or the tool's provider default) actually reaches the provider directly.
	// Carries a reason so the caller prints the honest "not captured" notice.
	proxyNeutralize
	// proxyFailClosed: refuse to launch. Either the user asked for no routing but
	// a persistent config route would keep routing anyway (the escape hatch is a
	// lie), or a routed launch would hit an UNREACHABLE proxy baked into config
	// that the launcher cannot neutralize. A broken-looking tool that silently
	// can't call its API is worse than an honest refusal; the caller prints
	// actionable copy naming the exact fix and returns a non-zero exit.
	proxyFailClosed
)

// proxyFallbackReason names WHY a verdict was reached so the caller can print
// the matching honest copy. Distinct values (rather than a bool per action)
// keep every row's notice/error message legible and unit-testable.
type proxyFallbackReason int

const (
	// reasonRouteHealthy: proxy reachable, routed launch — proceed.
	reasonRouteHealthy proxyFallbackReason = iota
	// reasonNoProxyRouteClean: --no-proxy-route with NO persistent config route —
	// the launcher's own bypass is sufficient; neutralize + "not captured" notice.
	reasonNoProxyRouteClean
	// reasonNoProxyRouteConflict: --no-proxy-route BUT the tool's persistent
	// config still routes to the proxy (settings.json env / config.toml), which
	// the tool applies over the launcher's bypass — the flag's "not captured"
	// promise would be false. Fail closed (mirrors codex B3-1).
	reasonNoProxyRouteConflict
	// reasonProxyDownClean: routed launch, proxy UNreachable, NO persistent route
	// — bypass to the provider default so the tool actually works (the honest
	// daemon-down bare fallback: notice + working launch). Turns are not captured
	// until the daemon is back.
	reasonProxyDownClean
	// reasonProxyDownConflict: routed launch, proxy UNreachable, AND a persistent
	// config route points at that dead proxy — the tool would send every API call
	// into the dead proxy and the launcher cannot neutralize the baked-in route.
	// Fail closed with copy naming the fix (start the daemon, or remove the
	// baked-in route). This is the resilient-attach scenario-4/5 break.
	reasonProxyDownConflict
	// reasonProxyDownOrgRoute: routed launch, proxy UNreachable, nothing pins
	// the route, but this is a MANAGED node whose organization owns the AI
	// tools' proxy routes (route posture maintain). A working bypass would
	// skip the proxy-resident controls the organization requires, so refuse
	// and name the fix (lane launcher-proxy-down, 2026-11-24).
	reasonProxyDownOrgRoute
)

// proxyFallbackInputs are the injected capability facts decideProxyFallback
// walks. No I/O happens here — the persistent-route detection and the proxy dial
// run in the caller and are passed as plain bools.
type proxyFallbackInputs struct {
	// noProxyRoute is the user's `--no-proxy-route` / `--no-proxy` intent: launch
	// WITHOUT routing through the observer proxy (turns not captured).
	noProxyRoute bool
	// proxyReachable reports whether a fresh dial of the observer proxy succeeded.
	// Consulted ONLY on the routed rows (it is irrelevant to a no-proxy-route
	// launch, whose verdict turns solely on the persistent route), so the caller
	// may skip the dial entirely when noProxyRoute is set.
	proxyReachable bool
	// persistentRoute reports whether the tool's OWN persistent config
	// (settings.json env.ANTHROPIC_BASE_URL for claude; config.toml
	// openai_base_url / model_provider for codex) routes to the observer proxy.
	persistentRoute bool
	// canNeutralizePersistent reports whether the launcher has a mechanism that
	// OVERRIDES that persistent config route so it can bypass the proxy anyway —
	// e.g. claude's CLI-scope `--settings` override, which the docs rank above
	// user-scope settings.json and which the 2026-07-20 probe confirmed WINS.
	// Consulted ONLY when persistentRoute is true. It is a launcher CAPABILITY
	// resolved at the boundary (never a tool-name branch): true for claude unless
	// the operator already passed their own `--settings` (unsafe to stack), false
	// for codex (config.toml wins and codex 0.130+ drops the argv `-c` override,
	// so there is no CLI-scope lever). When false, an un-overridable persistent
	// route forces the honest fail-closed; when true, the launch neutralizes via
	// the override instead of refusing (honoring operator decision #2).
	canNeutralizePersistent bool
	// orgRequiresRoute reports a MANAGED node whose organization owns the AI
	// tools' proxy routes (govern route posture maintain: the admin pinned
	// proxy.maintain_routes ON, or left it unset while governing a
	// proxy-resident enforcement point). Consulted ONLY on the routed,
	// proxy-down row: a bypass there would skip the organization's proxy-
	// resident controls, so it fails closed instead of neutralizing. The env
	// launchers resolve it (envLauncherProxyGate); claude and codex leave it
	// false today, so their verdicts are unchanged.
	orgRequiresRoute bool
}

// proxyFallbackDecision is decideProxyFallback's verdict: the action plus the
// reason that produced it (for the caller's honest copy).
type proxyFallbackDecision struct {
	action proxyFallbackAction
	reason proxyFallbackReason
}

// decideProxyFallback is the pure, table-driven launch-time routing decision.
// The pivotal fact is `blocking`: a persistent config route the launcher CANNOT
// override (persistentRoute && !canNeutralizePersistent). A blocking route is
// the only thing that forces a fail-closed; a route the launcher CAN override
// (or the absence of a route) always neutralizes or proceeds. Rows walked
// top-down; first match wins:
//
//  1. --no-proxy-route  &&  blocking route         → FAIL CLOSED  (escape-hatch lie, can't override)
//  2. --no-proxy-route  && !blocking               → neutralize   (bypass; override the route if any)
//  3. routed            &&  proxy reachable         → proceed      (happy path)
//  4. routed && !reachable &&  blocking route       → FAIL CLOSED  (dead baked-in proxy, can't override)
//  5. routed && !reachable &&  org owns the route   → FAIL CLOSED  (managed node: a bypass skips org controls)
//  6. routed && !reachable && !blocking             → neutralize   (working daemon-down fallback)
//
// Row 1 is FIRST and independent of proxy reachability: an un-overridable route
// the tool applies over the launcher's bypass makes the `--no-proxy-route`
// promise false whether the proxy is up (turns captured against the user's wish)
// or down (dead-proxy break) — the honest move is to refuse and name the fix,
// exactly like codex's B3-1 guard. Rows 4-6 are the routed daemon-down split:
// refuse when a baked-in route the launcher can't override would silently send
// API calls into a dead proxy (row 4), refuse on a managed node whose
// organization owns the routes even with nothing pinned (row 5: a bypass would
// skip the organization's proxy-resident controls), else neutralize (operator
// decision #2 — notice + working launch). When canNeutralizePersistent is true
// (claude's `--settings` override lever), `blocking` collapses to false, so a
// claude launch with a baked-in route NEUTRALIZES via the override instead of
// refusing; codex passes canNeutralizePersistent=false, so its
// persistent-route rows stay fail-closed.
func decideProxyFallback(in proxyFallbackInputs) proxyFallbackDecision {
	blocking := in.persistentRoute && !in.canNeutralizePersistent
	switch {
	case in.noProxyRoute && blocking:
		return proxyFallbackDecision{proxyFailClosed, reasonNoProxyRouteConflict}
	case in.noProxyRoute:
		return proxyFallbackDecision{proxyNeutralize, reasonNoProxyRouteClean}
	case in.proxyReachable:
		return proxyFallbackDecision{proxyRouteProceed, reasonRouteHealthy}
	case blocking:
		return proxyFallbackDecision{proxyFailClosed, reasonProxyDownConflict}
	case in.orgRequiresRoute:
		return proxyFallbackDecision{proxyFailClosed, reasonProxyDownOrgRoute}
	default:
		return proxyFallbackDecision{proxyNeutralize, reasonProxyDownClean}
	}
}
