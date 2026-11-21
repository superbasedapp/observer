package controlcoverage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// surfaceposture.go is the per-capture-surface half of the control-coverage
// row (surface-gap arc Wave 3, findings OBS-4, CX-1, W-5, CC-1a, CC-3 and
// W-2b). A tool's Row answers once per tool, but a product ships several
// surfaces (models.Surface*) and the levers do not reach all of them: the
// Claude Code proxy route reaches the CLI and not Claude Desktop's Code tab,
// and the Codex hook gate runs in the CLI and not in Codex Desktop or the
// IDE-embedded cores. Everything here is derived from the registry's
// per-surface rows (Capability.RouteSurfaces, HookSpec.Surfaces), never from
// a tool name.

// SurfaceGate is how far one lever (the tool-call gate, or the proxy route)
// reaches one capture surface. Closed vocabulary.
type SurfaceGate string

const (
	// SurfaceGateNone: the tool has no such lever on any surface (no wired
	// tool gate, or no proxy route).
	SurfaceGateNone SurfaceGate = ""
	// SurfaceGated: the lever acts on the surface (a wired gate whose hooks
	// run there, or a proven route the surface honours).
	SurfaceGated SurfaceGate = "gated"
	// SurfaceUngated: grounded negative, the lever does not reach the
	// surface (its hooks are skipped there, or the surface ignores the
	// route).
	SurfaceUngated SurfaceGate = "ungated"
	// SurfaceUnproven: a route exists for the surface but an override the
	// launcher does not own can escape it, or it is not live-verified.
	SurfaceUnproven SurfaceGate = "unproven"
	// SurfaceGateUnknown: whether the lever reaches the surface is not
	// grounded (a pending live check).
	SurfaceGateUnknown SurfaceGate = "unknown"
)

// SurfacePosture is one capture surface's control posture for one tool.
type SurfacePosture struct {
	// Kind is a models.Surface* kind; Host refines it ("" = every host).
	Kind string
	Host string
	// ToolGate is how far the tool-call gate reaches the surface.
	ToolGate SurfaceGate
	// Route is how far the proxy route reaches the surface.
	Route SurfaceGate
	// RouteProof is the surface's RouteProofState (RouteProofFor).
	RouteProof RouteProofState
}

// surfaceKindOrder orders surfaces the way people read them.
var surfaceKindOrder = map[string]int{
	models.SurfaceCLI:     0,
	models.SurfaceIDE:     1,
	models.SurfaceDesktop: 2,
	models.SurfaceSDK:     3,
	models.SurfaceWeb:     4,
	models.SurfaceMobile:  5,
}

// RouteProofFor is the route proof of one capture surface of c: none when c
// has no proxy route; proven only when the launcher's route is proven
// (Capability.RouteProven) AND a declared row for the surface is routable
// now (Capability.RouteSurfaceFor matched a row, effective routable_now).
// A surface with no row of its own on a tool that declares surfaces is not
// a routed surface, so it is unproven, never borrowed from the CLI (OBS-4).
//
// An empty kind asks about an unstamped session: it is judged by the tool's
// Unstamped row when one is declared, else by the tool-level answer
// (toolRouteProof).
func RouteProofFor(c integration.Capability, kind, host string) RouteProofState {
	if c.Proxy == nil {
		return RouteProofStateNone
	}
	if kind == "" {
		u, ok := c.UnstampedSurface()
		if !ok {
			return toolRouteProof(c)
		}
		kind, host = u.Kind, u.Host
	}
	row, match := c.RouteSurfaceFor(kind, host)
	declared := match != integration.SurfaceMatchTool || len(c.RouteSurfaces) == 0
	if c.RouteProven() && declared && row.EffectiveRoutability(c) == integration.RouteStatusRoutableNow {
		return RouteProofStateProven
	}
	return RouteProofStateUnproven
}

// toolRouteProof is the registry-only tool-level route proof
// (toolRouteProofSeen with no node observations).
func toolRouteProof(c integration.Capability) RouteProofState {
	state, _ := toolRouteProofSeen(c, nil)
	return state
}

// SurfaceSeen reports whether a declared surface row of a tool produced
// sessions on the node. nil means a registry-only view (no node): a row is
// then seen unless no adapter can produce it (SurfaceRoute.NoProducer).
type SurfaceSeen func(row integration.SurfaceRoute) bool

// registrySeen is the registry-only SurfaceSeen.
func registrySeen(row integration.SurfaceRoute) bool { return !row.NoProducer }

// toolRouteProofSeen is the tool-level route proof: proven only when the
// route is proven AND every declared surface that produces sessions is
// routable now, so a tool one of whose USED surfaces ignores or may escape
// the route is never "proven" as a whole (OBS-4: Claude Desktop falsified
// claude-code's tool-wide claim). A surface with no observed session is
// skipped, neither proven nor unproven (AW-48), and returned so the caller
// names it; once one of its sessions is observed it counts again.
func toolRouteProofSeen(c integration.Capability, seen SurfaceSeen) (RouteProofState, []string) {
	if c.Proxy == nil {
		return RouteProofStateNone, nil
	}
	if seen == nil {
		seen = registrySeen
	}
	var skipped []string
	unproven := !c.RouteProven()
	for _, r := range c.RouteSurfaces {
		if !seen(r) {
			skipped = append(skipped, surfaceLabel(r.Kind, r.Host))
			continue
		}
		if r.EffectiveRoutability(c) != integration.RouteStatusRoutableNow {
			unproven = true
		}
	}
	if unproven {
		return RouteProofStateUnproven, skipped
	}
	return RouteProofStateProven, skipped
}

// surfaceLabel renders a surface as "kind" or "kind/host".
func surfaceLabel(kind, host string) string {
	if host == "" {
		return kind
	}
	return kind + "/" + host
}

// SurfaceSession is one observed session group of a tool on a node: the
// sessions' capture surface (models.Surface* kind, "" when unstamped) and
// host, and how many there are (store.LoadSurfaceCounts).
type SurfaceSession struct {
	Kind, Host string
	Sessions   int64
}

// RouteProofBasis says what a row's tool-wide RouteProof was computed from.
// Closed.
type RouteProofBasis string

const (
	// RouteBasisRegistry: a registry-only view (no node): the proof skips
	// only the surfaces no adapter can produce yet (SurfaceRoute.NoProducer).
	RouteBasisRegistry RouteProofBasis = "registry"
	// RouteBasisObserved: the node's own sessions: the proof skips every
	// declared surface with no session on the node.
	RouteBasisObserved RouteProofBasis = "observed"
	// RouteBasisRegistryFallback: a node view that holds no evidence it can
	// judge (no session of the tool at all, or sessions on no declared
	// surface), so the row shows the registry proof instead of claiming
	// anything on the strength of nothing. RouteBasisNote says which.
	RouteBasisRegistryFallback RouteProofBasis = "registry_fallback"
)

// sessionEvidence is a node's session groups of one tool placed on the
// tool's declared surface rows.
type sessionEvidence struct {
	seen     SurfaceSeen
	placed   int64 // sessions on a declared surface row
	unplaced int64 // sessions with no row to put them on
}

// placeSessions maps a node's session groups of c onto c's declared surface
// rows: a stamped group marks the row RouteSurfaceFor matches (an exact or a
// kind row); an unstamped group marks the tool's Unstamped row. A group with
// no row to go on (unstamped on a tool with no Unstamped row, or a surface
// the tool declares no row for) is counted as unplaced, never dropped: it
// could be any surface, including one the route does not reach.
func placeSessions(c integration.Capability, groups []SurfaceSession) sessionEvidence {
	seen := map[[2]string]bool{}
	var ev sessionEvidence
	for _, g := range groups {
		if g.Sessions <= 0 {
			continue
		}
		kind, host := g.Kind, g.Host
		if kind == "" {
			u, ok := c.UnstampedSurface()
			if !ok {
				ev.unplaced += g.Sessions
				continue
			}
			kind, host = u.Kind, u.Host
		}
		row, match := c.RouteSurfaceFor(kind, host)
		if match == integration.SurfaceMatchTool {
			ev.unplaced += g.Sessions
			continue
		}
		seen[[2]string{row.Kind, row.Host}] = true
		ev.placed += g.Sessions
	}
	ev.seen = func(r integration.SurfaceRoute) bool { return seen[[2]string{r.Kind, r.Host}] }
	return ev
}

// observedBasisRules is the ordered table ForObserved walks: the first rule
// that holds sends the row to the registry proof with its note; when none
// holds, the observed proof stands. One test case per row
// (TestObservedBasisRules).
var observedBasisRules = []struct {
	name string
	hit  func(c integration.Capability, ev sessionEvidence) (string, bool)
}{
	{"no route surfaces declared", func(c integration.Capability, _ sessionEvidence) (string, bool) {
		// Nothing per surface to observe: the registry proof is the whole
		// answer, not a fallback, so no note (ForObserved keeps the plain
		// registry basis).
		return "", len(c.RouteSurfaces) == 0
	}},
	{"no session observed", func(_ integration.Capability, ev sessionEvidence) (string, bool) {
		return "no session of this tool on this node", ev.placed == 0 && ev.unplaced == 0
	}},
	{"sessions on no declared surface", func(_ integration.Capability, ev sessionEvidence) (string, bool) {
		return fmt.Sprintf("%d session(s) carry no surface stamp or a surface the tool declares no row for, so they could be on any surface", ev.unplaced), ev.unplaced > 0
	}},
}

// routeGateByProof maps a surface's route proof onto the posture gate; a
// non-routable surface reads ungated when the registry says the route can
// never reach it (settings ignored, exempt) and unproven otherwise.
func routeGateFor(c integration.Capability, kind, host string) SurfaceGate {
	if c.Proxy == nil {
		return SurfaceGateNone
	}
	if RouteProofFor(c, kind, host) == RouteProofStateProven {
		return SurfaceGated
	}
	row, _ := c.RouteSurfaceFor(kind, host)
	switch row.EffectiveRoutability(c) {
	case integration.RouteStatusSettingsIgnored, integration.RouteStatusNativeExempt:
		return SurfaceUngated
	}
	return SurfaceUnproven
}

// hookGateByRun maps a declared hook surface row onto the posture gate.
var hookGateByRun = map[integration.HookSurfaceRun]SurfaceGate{
	integration.HookSurfaceRuns:    SurfaceGated,
	integration.HookSurfaceSkipped: SurfaceUngated,
	integration.HookSurfaceUnknown: SurfaceGateUnknown,
}

// hasWiredToolGate reports whether any tool-gate binding is wired.
func hasWiredToolGate(c integration.Capability) bool {
	for _, b := range c.Hook.Bindings {
		if b.Cap == integration.HookCapToolGate && b.Wired {
			return true
		}
	}
	return false
}

// toolGateFor is how far the tool-call gate reaches one surface: none
// without a wired gate; from the surface's hook row when declared; else the
// tool-level answer (gated: the hooks run wherever the tool runs them).
func toolGateFor(c integration.Capability, kind, host string) SurfaceGate {
	if !hasWiredToolGate(c) {
		return SurfaceGateNone
	}
	row, match := c.Hook.SurfaceFor(kind, host)
	if match == integration.SurfaceMatchTool {
		return SurfaceGated
	}
	return hookGateByRun[row.Runs]
}

// SurfacePostures lists the control posture of every capture surface c
// declares a route or hook row for, in reading order (cli, ide, desktop,
// sdk, web; then host). Empty when c declares no surface.
func SurfacePostures(c integration.Capability) []SurfacePosture {
	seen := map[[2]string]bool{}
	var keys [][2]string
	add := func(kind, host string) {
		k := [2]string{kind, host}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for _, r := range c.RouteSurfaces {
		add(r.Kind, r.Host)
	}
	for _, r := range c.Hook.Surfaces {
		add(r.Kind, r.Host)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return surfaceKindOrder[keys[i][0]] < surfaceKindOrder[keys[j][0]]
		}
		return keys[i][1] < keys[j][1]
	})
	out := make([]SurfacePosture, 0, len(keys))
	for _, k := range keys {
		out = append(out, SurfacePosture{
			Kind: k[0], Host: k[1],
			ToolGate:   toolGateFor(c, k[0], k[1]),
			Route:      routeGateFor(c, k[0], k[1]),
			RouteProof: RouteProofFor(c, k[0], k[1]),
		})
	}
	return out
}

// replayedVia lists, sorted and de-duplicated, the tools whose own hook
// registration a wired binding of c rides (HookBinding.ReplayedVia): the
// gate runs only where that tool's Observer hooks are registered (W-2b). A
// replay that only stands in for c's own registered gate
// (HookSpec.ReplayFallback) rides nothing.
func replayedVia(c integration.Capability) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range c.Hook.Bindings {
		if b.Wired && b.ReplayedVia != "" && !c.Hook.ReplayFallback(b) && !seen[b.ReplayedVia] {
			seen[b.ReplayedVia] = true
			out = append(out, b.ReplayedVia)
		}
	}
	sort.Strings(out)
	return out
}

// PostureText renders a row's per-surface posture for people, one clause
// per lever that exists on some surface: "tool gate: cli gated, desktop
// ungated; proxy route: cli gated, desktop ungated". It names the tools a
// replayed gate rides. "" when the row declares no surface and rides no
// other tool's registration.
func (r Row) PostureText() string {
	var clauses []string
	for _, lever := range []struct {
		label string
		gate  func(SurfacePosture) SurfaceGate
	}{
		{"tool gate", func(p SurfacePosture) SurfaceGate { return p.ToolGate }},
		{"proxy route", func(p SurfacePosture) SurfaceGate { return p.Route }},
	} {
		var entries []postureEntry
		for _, p := range r.Surfaces {
			g := lever.gate(p)
			if g == SurfaceGateNone {
				continue
			}
			entries = append(entries, postureEntry{kind: p.Kind, host: p.Host, gate: g})
		}
		parts := collapseHostFamilies(entries)
		if len(parts) > 0 {
			clauses = append(clauses, lever.label+": "+strings.Join(parts, ", "))
		}
	}
	if len(r.ReplayedVia) > 0 {
		clauses = append(clauses, "gates ride the "+strings.Join(r.ReplayedVia, ", ")+" hook registration")
	}
	if r.RouteProofBasis == RouteBasisRegistryFallback && r.RouteBasisNote != "" {
		clauses = append(clauses, "route proof from the registry: "+r.RouteBasisNote)
	}
	if len(r.RouteNotObserved) > 0 {
		clauses = append(clauses, "route proof skips "+strings.Join(r.RouteNotObserved, ", ")+": "+skipReason[r.RouteProofBasis])
	}
	return strings.Join(clauses, "; ")
}

// skipReason words a RouteNotObserved skip per view: a registry view skips
// a surface because no adapter captures it yet; an observed node view
// because the node holds no session of it.
var skipReason = map[RouteProofBasis]string{
	RouteBasisRegistry:         "no adapter captures it yet",
	RouteBasisRegistryFallback: "no adapter captures it yet",
	RouteBasisObserved:         "no sessions observed on this node",
}

// postureEntry is one surface's gate for one lever, before rendering.
type postureEntry struct {
	kind, host string
	gate       SurfaceGate
}

// hostFamilyMin is how many hosts of one family must share a kind and a gate
// before PostureText names the family once ("ide/jetbrains-* ungated")
// instead of every product host.
const hostFamilyMin = 3

// hostFamily is the family of a host token: the text before its first '-'
// ("jetbrains" for "jetbrains-idea"), "" for a host with no '-'.
func hostFamily(host string) string {
	if i := strings.IndexByte(host, '-'); i > 0 {
		return host[:i]
	}
	return ""
}

// collapseHostFamilies renders entries in order, naming a run of
// hostFamilyMin or more hosts of one family with the same kind and gate once,
// at the place of its first member.
func collapseHostFamilies(entries []postureEntry) []string {
	type famKey struct {
		kind, family string
		gate         SurfaceGate
	}
	count := map[famKey]int{}
	for _, e := range entries {
		if f := hostFamily(e.host); f != "" {
			count[famKey{e.kind, f, e.gate}]++
		}
	}
	done := map[famKey]bool{}
	var parts []string
	for _, e := range entries {
		name := e.kind
		if e.host != "" {
			name += "/" + e.host
		}
		if f := hostFamily(e.host); f != "" {
			k := famKey{e.kind, f, e.gate}
			if count[k] >= hostFamilyMin {
				if done[k] {
					continue
				}
				done[k] = true
				name = e.kind + "/" + f + "-*"
			}
		}
		parts = append(parts, name+" "+string(e.gate))
	}
	return parts
}
