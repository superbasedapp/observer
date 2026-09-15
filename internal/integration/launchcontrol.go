package integration

// This file holds the LAUNCH-ADMISSION vocabulary: the two questions a budget
// admission boundary asks about an invocation it is about to start, answered
// as registry DATA rather than as a tool-name branch (CLAUDE.md #3):
//
//  1. Does the route this launcher applies PROVE which backend the request
//     reaches?  (RouteProof, carried on ProxyRoute.)
//  2. Can a process cutoff bind to the SURFACE being started at all?
//     (LaunchSurfaceClass / GUILaunchSurfaceClass, over the intervention
//     surface declarations.)
//
// Both are honest-zero: an undeclared row answers "not proven" and "not
// classified", which every consumer must treat as the fail-closed direction.

// RouteProof states how much a launcher's applied proxy route establishes
// about the invocation's final backend. It is deliberately separate from
// BudgetAdmissionChannel: the channel says a route EXISTS for the tool, this
// says that applying it on THIS invocation settles the question.
type RouteProof string

const (
	// RouteProofUnproven is the safe zero value: the route can be applied, but
	// the effective provider is still selected somewhere the launcher does not
	// own — an ambient provider variable (goose's GOOSE_PROVIDER), a stored
	// auth selection (gemini's OAuth / Vertex), or a per-model backend switch
	// (aider). An invocation of such a tool is never admitted as proxy-routed
	// on the base URL alone.
	RouteProofUnproven RouteProof = ""
	// RouteProofLauncherRoute means the route the launcher applies — the
	// injected base-URL environment, or the config file it writes — is the
	// ONLY thing that selects the backend for this product, so an invocation
	// that carries the applied route intact reaches the Observer proxy. A row
	// may still name SelectorArguments that take the proof away for one
	// invocation.
	RouteProofLauncherRoute RouteProof = "launcher_route"
)

// RouteProven reports whether this capability's launcher-applied proxy route
// settles the invocation's backend. False for a nil Proxy row, so an
// un-routable adapter can never read as proven.
func (c Capability) RouteProven() bool {
	return c.Proxy != nil && c.Proxy.Proof == RouteProofLauncherRoute
}

// RouteSelectorArguments returns the product-specific argv keys that outrank
// this capability's proxy route. Nil for a row with no proxy route or no
// grounded selectors; the caller composes its own cross-vendor set on top.
func (c Capability) RouteSelectorArguments() []string {
	if c.Proxy == nil {
		return nil
	}
	return append([]string(nil), c.Proxy.SelectorArguments...)
}

// LaunchSurfaceClass returns the intervention class of the surface a bare
// `observer <tool>` launch starts: the tool's own dedicated CLI process when
// it declares one, otherwise the class the registry does declare (a shared
// IDE/desktop host, remote execution, or unclassified).
//
// It is the ONE owner of the question "could a process cutoff bind to what
// this launch starts?" — an admission boundary reads this instead of deciding
// per tool. An unknown tool is SurfaceUnclassified with ok=false, which is the
// fail-closed answer.
func LaunchSurfaceClass(tool string) (InterventionSurfaceClass, bool) {
	surfaces, ok := InterventionFor(tool)
	if !ok || len(surfaces) == 0 {
		return SurfaceUnclassified, false
	}
	for _, surface := range surfaces {
		if surface.Class == SurfaceDedicatedProcess {
			return SurfaceDedicatedProcess, true
		}
	}
	return surfaces[0].Class, true
}

// GUILaunchSurfaceClass returns the intervention class of the surface a GUI
// launch row starts.
//
// Every GUI row is a shared host by construction: this table launches IDEs and
// desktop apps, and an extension is never a launch row (the host is — see
// GUILaunchSpec). The lookup still goes through the adapter's own intervention
// declaration where one exists, so a product that ever declares an isolated
// GUI worker reclassifies here automatically rather than silently inheriting
// the shared answer. ok=false for an unknown launch id.
func GUILaunchSurfaceClass(id string) (InterventionSurfaceClass, bool) {
	row, ok := GUILaunchFor(id)
	if !ok {
		return SurfaceUnclassified, false
	}
	if row.Adapter != "" {
		if surfaces, found := InterventionFor(row.Adapter); found {
			want := row.Adapter + "/" + row.Spec.Surface
			for _, surface := range surfaces {
				if surface.ID == want {
					return surface.Class, true
				}
			}
		}
	}
	// A pure editor host (VS Code, the JetBrains IDEs) has no adapter row of
	// its own; the host process contains unrelated editor work by definition.
	return SurfaceSharedHost, true
}
