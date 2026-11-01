package routeattest

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// surfaceattest.go judges proxy-route traffic per capture surface (surface-
// gap arc Wave 0.3; docs/plans/surface-gap-wave-0-design-2026-10-25.md
// section 5). AttestByTraffic answers once per tool and only "some" or
// "none", so one proxied CLI session attests a tool whose desktop sessions
// never touch the proxy. AttestSurfaces answers per (tool, surface kind,
// surface host) session group, from session counts the caller's store query
// supplies, through one ordered rule table.

// SurfaceTraffic is one observed session group. Both counts are SESSIONS,
// never API turns: ProxiedSessions is the number of the group's sessions
// with at least one api_turns row. A caller that counts turns would make
// ProxiedSessions exceed Sessions, which the rule table refuses.
type SurfaceTraffic struct {
	Tool string
	// Kind is the sessions.surface value (a models.Surface* kind, or ""
	// for a session no adapter stamped).
	Kind string
	// Host is the sessions.surface_host value ("" when unstamped).
	Host            string
	Sessions        int
	ProxiedSessions int
}

// SurfaceState is the classified traffic state of one session group.
type SurfaceState string

// The closed SurfaceState vocabulary, in rule-table order.
const (
	// SurfaceInvalidInput: a negative count, or more proxied sessions than
	// sessions (the caller counted turns). Never a verdict about the tool.
	SurfaceInvalidInput SurfaceState = "invalid_input"
	// SurfaceUnknownSurface: the group's sessions carry no known surface
	// kind, so no per-surface fact applies. An unstamped group with no
	// proxied session and no stamped sibling that speaks for the tool is
	// judged at tool level instead (applyToolLevelFallback, P-172).
	SurfaceUnknownSurface SurfaceState = "unknown_surface"
	// SurfaceExempt: the surface has no routable proxy surface by design.
	SurfaceExempt SurfaceState = "exempt"
	// SurfaceUnobserved: no session of the surface in the window.
	SurfaceUnobserved SurfaceState = "unobserved"
	// SurfaceUnknownMeasurability: sessions exist, but whether a proxied
	// turn of this surface joins back to its session is not grounded, so
	// zero proxied sessions is not evidence of a bypass.
	SurfaceUnknownMeasurability SurfaceState = "unknown_measurability"
	// SurfaceNotMeasurable: grounded negative, the surface's proxied turns
	// cannot be joined to its sessions.
	SurfaceNotMeasurable SurfaceState = "not_measurable"
	// SurfaceBypassSuspect: sessions exist and none was proxied.
	SurfaceBypassSuspect SurfaceState = "bypass_suspect"
	// SurfacePartial: some, not all, sessions were proxied.
	SurfacePartial SurfaceState = "partial"
	// SurfaceAttested: every session was proxied.
	SurfaceAttested SurfaceState = "attested"
)

// SurfaceFacts are the registry facts one session group is judged against.
type SurfaceFacts struct {
	// Exempt: the surface has no routable proxy surface by design.
	Exempt bool
	// Routable: the surface's effective routability is routable_now. Only
	// a routable surface's bypass can block Gateway-Mode activation
	// (SurfaceVerdict.ObservedBypass).
	Routable bool
	// Correlation says whether the surface's proxied turns join back to its
	// sessions.
	Correlation integration.CorrelationMode
	// UnstampedAs is the surface kind an unstamped session group (Kind "")
	// was judged as (integration.SurfaceRoute.Unstamped); "" when the group
	// is stamped or the tool declares no such row, in which case an
	// unstamped group reads unknown_surface.
	UnstampedAs string
}

// SurfacePolicy resolves SurfaceFacts for one session group. Injected so a
// server rollup or a test can supply its own; RegistrySurfacePolicy is the
// default.
type SurfacePolicy func(tool, kind, host string) SurfaceFacts

// SurfaceVerdict is one session group's judgement.
type SurfaceVerdict struct {
	SurfaceTraffic
	Facts  SurfaceFacts
	State  SurfaceState
	Reason string
}

// ObservedBypass reports whether the verdict is an observed bypass of a
// routable surface: bypass_suspect, or partial where every proxied turn
// carries its session id (CorrelationMode.JoinsEveryTurn), on a surface
// whose effective routability is routable_now. It is the Gateway-Mode
// activation gate input (review decision D11); exempt, unobserved,
// not-measurable and not-yet-routable surfaces never count. A partial
// window on a process-bridge surface does not count either: that bridge
// misses the first turns and one-shot runs, so partial is its expected
// reading, and only a window with no joined session is a bypass (the
// evidence the pre-arc tool-level gate used; surface-gap Wave 3).
func (v SurfaceVerdict) ObservedBypass() bool {
	if !v.Facts.Routable {
		return false
	}
	switch v.State {
	case SurfaceBypassSuspect:
		return true
	case SurfacePartial:
		return v.Facts.Correlation.JoinsEveryTurn()
	}
	return false
}

// surfaceRule is one row of the rule table: the first row whose when holds
// decides the state.
type surfaceRule struct {
	state  SurfaceState
	when   func(r SurfaceTraffic, f SurfaceFacts) bool
	reason func(r SurfaceTraffic, f SurfaceFacts) string
}

// surfaceRules is the ordered rule table AttestSurfaces walks top-down (one
// test row per rule). Unobserved runs before the correlation checks so a
// surface with no sessions reads "unobserved" whatever its correlation.
var surfaceRules = []surfaceRule{
	{
		state: SurfaceInvalidInput,
		when: func(r SurfaceTraffic, _ SurfaceFacts) bool {
			return r.Sessions < 0 || r.ProxiedSessions < 0 || r.ProxiedSessions > r.Sessions
		},
		reason: func(r SurfaceTraffic, _ SurfaceFacts) string {
			return fmt.Sprintf("invalid counts: %d proxied of %d sessions (counts must be sessions, never API turns)", r.ProxiedSessions, r.Sessions)
		},
	},
	{
		state: SurfaceUnknownSurface,
		when: func(r SurfaceTraffic, f SurfaceFacts) bool {
			return !models.KnownSurface(r.Kind) && (r.Kind != "" || f.UnstampedAs == "")
		},
		reason: func(r SurfaceTraffic, _ SurfaceFacts) string {
			if r.Kind == "" {
				return "the sessions carry no surface stamp"
			}
			return fmt.Sprintf("surface kind %q is not in the closed vocabulary", r.Kind)
		},
	},
	{
		state:  SurfaceExempt,
		when:   func(_ SurfaceTraffic, f SurfaceFacts) bool { return f.Exempt },
		reason: func(SurfaceTraffic, SurfaceFacts) string { return "no routable proxy surface by design" },
	},
	{
		state:  SurfaceUnobserved,
		when:   func(r SurfaceTraffic, _ SurfaceFacts) bool { return r.Sessions == 0 },
		reason: func(SurfaceTraffic, SurfaceFacts) string { return "no session of this surface in the window" },
	},
	{
		state: SurfaceUnknownMeasurability,
		when: func(_ SurfaceTraffic, f SurfaceFacts) bool {
			return !f.Correlation.Measurable() && f.Correlation != integration.CorrelationUnavailable
		},
		reason: func(r SurfaceTraffic, _ SurfaceFacts) string {
			return fmt.Sprintf("%d proxied of %d sessions, but whether this surface's proxied turns join back to its sessions is not grounded", r.ProxiedSessions, r.Sessions)
		},
	},
	{
		state: SurfaceNotMeasurable,
		when: func(_ SurfaceTraffic, f SurfaceFacts) bool {
			return f.Correlation == integration.CorrelationUnavailable
		},
		reason: func(SurfaceTraffic, SurfaceFacts) string {
			return "this surface's proxied turns cannot be joined to its sessions"
		},
	},
	{
		state: SurfaceBypassSuspect,
		when:  func(r SurfaceTraffic, _ SurfaceFacts) bool { return r.ProxiedSessions == 0 },
		reason: func(r SurfaceTraffic, _ SurfaceFacts) string {
			return fmt.Sprintf("none of %d sessions was proxied", r.Sessions)
		},
	},
	{
		state: SurfacePartial,
		when:  func(r SurfaceTraffic, _ SurfaceFacts) bool { return r.ProxiedSessions < r.Sessions },
		reason: func(r SurfaceTraffic, f SurfaceFacts) string {
			if !f.Correlation.JoinsEveryTurn() {
				return fmt.Sprintf("%d of %d sessions joined a proxied turn; the process bridge misses first turns and one-shot runs, so this is not counted as a bypass", r.ProxiedSessions, r.Sessions)
			}
			return fmt.Sprintf("%d of %d sessions proxied", r.ProxiedSessions, r.Sessions)
		},
	},
	{
		state: SurfaceAttested,
		when:  func(SurfaceTraffic, SurfaceFacts) bool { return true },
		reason: func(r SurfaceTraffic, _ SurfaceFacts) string {
			return fmt.Sprintf("all %d sessions proxied", r.Sessions)
		},
	},
}

// AttestSurfaces judges each session group, in input order. A nil policy
// uses RegistrySurfacePolicy.
func AttestSurfaces(rows []SurfaceTraffic, policy SurfacePolicy) []SurfaceVerdict {
	if policy == nil {
		policy = RegistrySurfacePolicy
	}
	out := make([]SurfaceVerdict, 0, len(rows))
	for _, r := range rows {
		f := policy(r.Tool, r.Kind, r.Host)
		for _, rule := range surfaceRules {
			if rule.when(r, f) {
				reason := rule.reason(r, f)
				if r.Kind == "" && f.UnstampedAs != "" && rule.state != SurfaceInvalidInput {
					reason = "unstamped sessions judged as " + f.UnstampedAs + " (the adapter stamps no surface): " + reason
				}
				out = append(out, SurfaceVerdict{SurfaceTraffic: r, Facts: f, State: rule.state, Reason: reason})
				break
			}
		}
	}
	applyToolLevelFallback(out)
	return out
}

// applyToolLevelFallback is the DEC-4 addendum (orchestrator ruling P-172:
// the gate is never weaker than before the arc; audit finding 1 of the Waves
// 1-3 hand-back). An unstamped group of a tool that declares no Unstamped
// row reads unknown_surface, which never blocks on its own, so a multi-
// surface tool whose unstamped sessions all went direct (a pre-139 agent, a
// vendor token the adapter does not map) read clean, where the pre-arc
// per (user, tool) AttestByTraffic blocked it. Such a group is judged at
// tool level as bypass_suspect when it has sessions and none was proxied and
// no stamped routable group of the same tool in this batch can speak for
// it. A stamped group speaks when it is routable, has sessions, and either
// had a proxied session (the route reaches the tool, as the pre-arc reading
// attested) or has a measurable correlation (it judges itself, and blocks
// if it was bypassed). Only a group whose tool-level facts are routable is
// judged so (and then blocks, ObservedBypass): a tool that is exempt or not
// routable_now keeps unknown_surface, as D11 never blocks on a surface that
// is not routable. The facts come from the registry rows through the
// policy, never a tool name. Callers pass one user's (one node's)
// groups per batch, so siblings are that user's own.
func applyToolLevelFallback(out []SurfaceVerdict) {
	speaks := map[string]bool{}
	for _, v := range out {
		if models.KnownSurface(v.Kind) && v.State != SurfaceInvalidInput && v.Facts.Routable && v.Sessions > 0 &&
			(v.ProxiedSessions > 0 || v.Facts.Correlation.Measurable()) {
			speaks[v.Tool] = true
		}
	}
	for i, v := range out {
		if v.State != SurfaceUnknownSurface || v.Kind != "" || v.Facts.UnstampedAs != "" || !v.Facts.Routable ||
			v.Sessions == 0 || v.ProxiedSessions != 0 || speaks[v.Tool] {
			continue
		}
		out[i].State = SurfaceBypassSuspect
		out[i].Reason = fmt.Sprintf("tool-level reading (P-172): the sessions carry no surface stamp, none of %d was proxied, "+
			"and no stamped routable surface of this tool speaks for them", v.Sessions)
	}
}

// RegistrySurfacePolicy resolves SurfaceFacts from the integration registry:
// the surface's route row (Capability.RouteSurfaceFor) gives its effective
// routability and correlation, and exemption is IsExempt judged on that
// effective routability, so a surface row can refine a tool-level verdict.
// A tool with no registry row yields zero facts (not exempt, not routable,
// correlation unknown), never a guess.
func RegistrySurfacePolicy(tool, kind, host string) SurfaceFacts {
	c, _ := integration.For(tool)
	return surfaceFactsFor(c, kind, host)
}

// surfaceFactsFor is RegistrySurfacePolicy for one Capability.
//
// An unstamped group (kind "") is judged by the tool's Unstamped row when it
// declares one (an adapter that stamps no surface); otherwise it keeps the
// tool fallback and the rule table reads it unknown_surface.
func surfaceFactsFor(c integration.Capability, kind, host string) SurfaceFacts {
	var unstampedAs string
	row, _ := c.RouteSurfaceFor(kind, host)
	if kind == "" {
		if u, ok := c.UnstampedSurface(); ok {
			row, unstampedAs = u, u.Kind
		}
	}
	surface := c
	surface.Routability = row.EffectiveRoutability(c)
	exempt, _ := IsExempt(surface)
	return SurfaceFacts{
		Exempt: exempt,
		// An exempt surface is never routable, whatever its row says.
		Routable:    !exempt && surface.Routability == integration.RouteStatusRoutableNow,
		Correlation: row.CorrelationMode,
		UnstampedAs: unstampedAs,
	}
}
