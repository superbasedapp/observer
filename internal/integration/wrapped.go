package integration

// This file is the WRAPPED-LAUNCH vocabulary: what "run this tool with the
// observer prefix" means for every launchable row, CLI and GUI alike, and
// what a wrapped IDE / desktop-app launch honestly does for each agent it
// hosts. It is the answer to backlog item 8 ("is IDE traffic proxied when the
// IDE is wrapped with the observer prefix?") and the seam backlog item 7 (a
// Settings option that swaps a tool's command for its wrapped form) calls.
//
// Everything here is DATA derived from existing registry fields (Proxy,
// Routability, GUI.Wrap, Handoff.Launch) — no product-name branch anywhere
// (CLAUDE.md #3/#5). A wrapped GUI launch is executed by `observer ide <id>`
// (cmd/observer/ide.go) and by the dashboard's GUI launch; both compose the
// argv/env through internal/guilaunch.Compose.

// GUILaunchVerb is the `observer <verb>` subcommand that launches a GUI row
// wrapped: `observer ide <gui-id> [project-dir] [-- app-args...]`. ONE owner:
// the cobra command registers under this spelling and WrappedCommandFor
// composes it, so the two can never drift. It must never collide with a
// registry Handoff.Launch.Subcommand (pinned by
// TestGUILaunchVerbDisjointFromToolVerbs).
const GUILaunchVerb = "ide"

// HostedRoute is the honest answer to "when this IDE / desktop app is
// launched wrapped, does THIS hosted agent's model traffic reach the observer
// proxy?" — one value per (GUI row, hosted adapter) pair. The zero value is
// "unclassified", never an assumed route.
type HostedRoute string

const (
	// HostedRouteUnclassified: the hosted adapter's Routability is not
	// classified, so nothing can be claimed. Zero value.
	HostedRouteUnclassified HostedRoute = ""
	// HostedRoutePersisted: the adapter's route lives in its OWN config file,
	// which `observer init` writes (claude-code settings.json env, codex
	// config.toml, qwen/kimi/crush/pi/hermes/cline-cli provider config). It
	// applies however the host was started — wrapped or not — once init has
	// written it. The route is live-verified for the adapter's own CLI; an
	// IDE-embedded run of the same agent reads the same file.
	HostedRoutePersisted HostedRoute = "persisted_config"
	// HostedRouteLaunchEnv: the wrapped launch exports exactly the base-URL
	// variable (name AND suffix) this adapter's launcher route reads. It
	// reaches the agent only if the agent is spawned by the host and inherits
	// the host's environment, and only on a cold start of a single-instance
	// host — plumbing-verified, never traffic-verified unless the row's
	// WrapSpec.TrafficProof says so.
	HostedRouteLaunchEnv HostedRoute = "launch_env"
	// HostedRouteLauncherOnly: the adapter has a verified route, but only
	// through its own `observer <verb>` launcher — the variable it reads is
	// not one this host launch exports (it would need a sibling selector such
	// as a provider type or a BYOK key the launcher never sets).
	HostedRouteLauncherOnly HostedRoute = "launcher_only"
	// HostedRouteManual: a base-URL knob exists (Routability routable_now)
	// but Observer has no writer for it — the VS Code extensions (Cline,
	// legacy Kilo Code) keep it in the editor's live state.vscdb, so the
	// operator pastes the proxy URL into the extension UI once.
	HostedRouteManual HostedRoute = "manual"
	// HostedRouteUnproven: a BYOK / base-URL path is documented or suspected
	// but not live-proven (Routability probe_required), or needs proxy work
	// first (after_upstream / after_bridge). Launch works; routing is not
	// claimed.
	HostedRouteUnproven HostedRoute = "unproven"
	// HostedRouteNotRoutable: the agent talks only to its vendor's own
	// backend with no base-URL knob (Routability native_exempt) — vendor-
	// hosted inference. No launch wrapper can change that.
	HostedRouteNotRoutable HostedRoute = "not_routable"
)

// persistedRouteKinds are the RouteKinds whose route survives in the tool's
// own config file (written by `observer init` / the launcher), as opposed to
// an env var that exists only for one exec.
var persistedRouteKinds = map[RouteKind]bool{
	RouteEnvSettings:  true,
	RouteConfigFile:   true,
	RouteProviderJSON: true,
}

// manualRouteKinds are the RouteKinds Observer never writes: the route is a
// setting the operator pastes into the client's own UI.
var manualRouteKinds = map[RouteKind]bool{
	RouteVSCodeSettings: true,
	RouteManual:         true,
}

// AllRouteKinds is the closed RouteKind vocabulary, for coverage sweeps that
// must prove every kind has a defined behaviour.
func AllRouteKinds() []RouteKind {
	return []RouteKind{
		RouteLauncher, RouteEnvSettings, RouteConfigFile, RouteProviderJSON,
		RouteVSCodeSettings, RouteManual,
	}
}

// HostedRouteInput is what the classifier sees for one (GUI row, hosted
// adapter) pair.
type HostedRouteInput struct {
	// Cap is the hosted adapter's registry row.
	Cap Capability
	// Wrap is the GUI row's routing-injection contract.
	Wrap WrapSpec
	// OwnProduct is true when the hosted adapter is the adapter CARRYING the
	// GUI row (the GUI is that adapter's own product: cursor-ide on cursor,
	// cline-desktop on cline-cli). For such a pair a WrapNone Reason is the
	// grounded negative about the GUI product itself, and it outranks the
	// adapter's CLI route.
	OwnProduct bool
}

// hostedRouteRule is one row of the ordered classification table: the first
// match wins, one test case per row (CLAUDE.md #5).
type hostedRouteRule struct {
	outcome HostedRoute
	match   func(in HostedRouteInput) bool
}

var hostedRouteRules = []hostedRouteRule{
	{HostedRouteLauncherOnly, func(in HostedRouteInput) bool {
		// The GUI product's own row says nothing can be injected, yet its
		// adapter's CLI has a verified route: that route is reachable only
		// through the CLI launcher (cline-desktop routes through Cline's
		// hosted gateway, not the providers.json `observer cline-cli`
		// writes).
		return in.OwnProduct && in.Wrap.Kind == WrapNone && in.Cap.Proxy != nil
	}},
	{HostedRoutePersisted, func(in HostedRouteInput) bool {
		return in.Cap.Proxy != nil && persistedRouteKinds[in.Cap.Proxy.Kind]
	}},
	{HostedRouteLaunchEnv, func(in HostedRouteInput) bool {
		// Only a LAUNCHER route is read from the process environment; a
		// persisted or UI-pasted route is not, whatever variable it names.
		p := in.Cap.Proxy
		return p != nil && p.Kind == RouteLauncher && p.EnvVar != "" && in.Wrap.exports(p.EnvVar, p.Suffix)
	}},
	{HostedRouteManual, func(in HostedRouteInput) bool {
		if in.Cap.Proxy != nil {
			return manualRouteKinds[in.Cap.Proxy.Kind]
		}
		// A knob exists (routable_now) but no route is driven: the pending
		// writer / paste-by-hand state the RouteStatus doc describes.
		return in.Cap.Routability == RouteStatusRoutableNow
	}},
	{HostedRouteLauncherOnly, func(in HostedRouteInput) bool {
		return in.Cap.Proxy != nil
	}},
	{HostedRouteUnproven, func(in HostedRouteInput) bool {
		switch in.Cap.Routability {
		case RouteStatusProbeRequired, RouteStatusAfterUpstream, RouteStatusAfterBridge:
			return true
		}
		return false
	}},
	{HostedRouteNotRoutable, func(in HostedRouteInput) bool {
		return in.Cap.Routability == RouteStatusNativeExempt
	}},
}

// exports reports whether a WrapChildEnv spec injects name with exactly this
// suffix. A matching name with a different suffix is NOT an export of the
// route (it would point the agent at the wrong endpoint).
func (w WrapSpec) exports(name, suffix string) bool {
	if w.Kind != WrapChildEnv {
		return false
	}
	for _, v := range w.Env {
		if v.Name == name && v.Suffix == suffix {
			return true
		}
	}
	return false
}

// ClassifyHostedRoute walks the ordered rule table for one hosted adapter
// under one GUI wrap. Unclassified when no rule fires.
func ClassifyHostedRoute(in HostedRouteInput) HostedRoute {
	for _, r := range hostedRouteRules {
		if r.match(in) {
			return r.outcome
		}
	}
	return HostedRouteUnclassified
}

// HostedRouteRow is one hosted adapter's wrapped-launch outcome.
type HostedRouteRow struct {
	// Tool is the hosted adapter's registry key.
	Tool string
	// Outcome is the classified route.
	Outcome HostedRoute
	// Routability echoes the adapter's RouteStatus (for rendering the
	// unproven / not-routable reasons).
	Routability RouteStatus
	// Launcher is the adapter's own `observer <verb>` route, when it has one
	// ("" otherwise) — the concrete next step for launcher_only.
	Launcher string
}

// HostedRoutes returns the per-hosted-adapter outcome of launching g wrapped,
// in the row's Hosts order. A host listed in Hosts is a registry tool
// (pinned by TestGUILaunchHostsAreRegistryTools).
func HostedRoutes(g GUILaunchable) []HostedRouteRow {
	out := make([]HostedRouteRow, 0, len(g.Spec.Hosts))
	for _, tool := range g.Spec.Hosts {
		c, _ := For(tool)
		row := HostedRouteRow{
			Tool:        tool,
			Outcome:     ClassifyHostedRoute(HostedRouteInput{Cap: c, Wrap: g.Spec.Wrap, OwnProduct: tool == g.Adapter}),
			Routability: c.Routability,
		}
		if c.Proxy != nil {
			row.Launcher = c.Proxy.Launcher
		}
		out = append(out, row)
	}
	return out
}

// WrappedCommand is the observer-prefixed form of one launchable tool or GUI
// row: what `claude` becomes (`observer claude`), what `code` becomes
// (`observer ide vscode`). It is the seam a "replace the command with its
// wrapped form" setting reads (backlog item 7) — it never has to know whether
// the id is a CLI adapter or an IDE.
type WrappedCommand struct {
	// ID is the registry tool key or GUI launch id that was resolved.
	ID string
	// Kind is the launch shape: LaunchKindTerminal for a CLI launcher,
	// LaunchKindGUI for a detached IDE / desktop app.
	Kind LaunchKind
	// Args is the argv AFTER the observer executable, e.g. ["claude"] or
	// ["ide", "vscode"]. Operator arguments follow a "--" (CLI) or the
	// project dir then "--" (GUI).
	Args []string
	// Replaces is the vendor's own executable spellings the wrapped form
	// stands in for (the row's grounded BinaryNames).
	Replaces BinaryNames
	// Routes reports whether the wrapped form changes routing at all: a CLI
	// row with a verified Proxy route, or a GUI row whose wrap injects
	// environment. False means the wrap launches the same thing (capture
	// still rides the product's own store) — a Settings UI must say so
	// rather than imply metering.
	Routes bool
	// TrafficProven reports whether a live turn through THIS wrapped form has
	// landed an api_turns row. CLI rows with a Proxy route are proven by
	// definition (the registry flips Proxy only after that proof); a GUI row
	// is proven only when its WrapSpec.TrafficProof is set.
	TrafficProven bool
}

// WrappedCommandFor resolves a registry tool key or GUI launch id to its
// observer-prefixed command. Tool keys are consulted first; the two id
// spaces are disjoint (TestGUILaunchIDsAreDisjointFromToolIDs). ok=false for
// an unknown id or a row that is not advertised / not launchable.
func WrappedCommandFor(id string) (WrappedCommand, bool) {
	if c, ok := registry[id]; ok {
		if !TerminalLaunchable(c) {
			return WrappedCommand{}, false
		}
		w := WrappedCommand{
			ID:            id,
			Kind:          LaunchKindTerminal,
			Args:          []string{c.Handoff.Launch.Subcommand},
			Routes:        c.Proxy != nil,
			TrafficProven: c.Proxy != nil,
		}
		if c.Binary != nil {
			w.Replaces = c.Binary.Names
		}
		return w, true
	}
	g, ok := GUILaunchFor(id)
	if !ok || !g.Advertised() {
		return WrappedCommand{}, false
	}
	return WrappedCommand{
		ID:            id,
		Kind:          LaunchKindGUI,
		Args:          []string{GUILaunchVerb, id},
		Replaces:      g.Spec.Binary.Names,
		Routes:        g.Spec.Wrap.Kind == WrapChildEnv,
		TrafficProven: g.Spec.Wrap.Kind == WrapChildEnv && g.Spec.Wrap.TrafficProof != "",
	}, true
}

// GUIRowForID resolves a GUI launch id, or a registry tool key whose adapter
// carries a GUI row (so `observer ide cursor` finds `cursor-ide`). ok=false
// for anything else.
func GUIRowForID(id string) (GUILaunchable, bool) {
	if g, ok := GUILaunchFor(id); ok {
		return g, true
	}
	if c, ok := registry[id]; ok && c.GUI != nil {
		return GUILaunchFor(c.GUI.ID)
	}
	return GUILaunchable{}, false
}
