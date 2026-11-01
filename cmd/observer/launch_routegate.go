// launch_routegate.go — the launcher boundary for a CONDITIONAL proxy route
// (integration.ProxyRoute.Gate).
//
// A gated route only works when the developer configured the vendor's own
// bring-your-own-key lane. This file resolves one launch's environment and
// argv into the gate's boolean inputs, walks integration.EvaluateRouteGate,
// and returns a plain verdict the launcher acts on: apply the route, launch
// unrouted with a one-line notice, or refuse with a visible message. It reads
// env var PRESENCE only; no credential value is ever printed, logged or
// copied anywhere. Shared code: it dispatches on the registry row's Gate
// shape, never on the tool name (CLAUDE.md #3).

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// gatedRoute is the launcher-facing verdict for one launch.
type gatedRoute struct {
	// routed: apply the route's env (base URL and its non-secret companions).
	routed bool
	// notice is the one line to print when the launch is NOT routed; "" when
	// routed (runEnvLauncher prints the routing line itself).
	notice string
	// err, when non-nil, refuses the launch. It is a visible launcher error,
	// so the message reaches a dashboard terminal too.
	err error
	// caveat is the one line printed after the "routing via" line of a ROUTED
	// launch whose gate names a lane it cannot see (RouteGate.RoutedCaveat);
	// "" otherwise.
	caveat string
}

// resolveGatedRoute decides whether tool's launcher route applies to this
// launch. label is the stderr prefix ("observer <label>: ..."), proxyURL the
// resolved proxy base URL, launcherModel the launcher's own --model value,
// args the argv forwarded to the product, environ the launch environment.
// A tool with no route or an ungated route always routes.
func resolveGatedRoute(tool, label, proxyURL, launcherModel string, args, environ []string) gatedRoute {
	capab, _ := integration.For(tool)
	p := capab.Proxy
	if p == nil || p.Gate == nil {
		return gatedRoute{routed: true}
	}
	lookup := func(k string) (string, bool) { return lookupEnvValue(environ, k) }

	// The developer already set the route's base-URL variable themselves. If it
	// points at the proxy they configured the lane by hand and the vendor
	// enforces its own requirements; otherwise it is their own endpoint and it
	// is left alone.
	var in integration.RouteGateInput
	if p.EnvVar != "" {
		if v, ok := lookup(p.EnvVar); ok && strings.TrimSpace(v) != "" {
			if urlRoutesToProxy(v, proxyURL) {
				return gatedRoute{routed: true, caveat: routedCaveat(label, p.Gate)}
			}
			in.OwnEndpoint = true
		}
	}
	in.CredentialPresent = p.Gate.CredentialPresent(lookup)
	in.ModelPresent = p.Gate.ModelPresent(lookup, args, launcherModel)
	in.ForeignProvider = p.Gate.ProviderTypeForeign(lookup, args)
	pins := gateAuthPins(p.Gate, lookup)
	in.AuthPinned = len(pins) > 0

	prefix := "observer " + label + ": "
	switch integration.EvaluateRouteGate(p.Gate, in) {
	case integration.RouteGateRoutedAuthPinned:
		return gatedRoute{routed: true, caveat: authPinnedCaveat(label, pins)}
	case integration.RouteGateOwnEndpoint:
		return gatedRoute{notice: prefix + "not routed through the proxy: " + p.EnvVar +
			" is already set to your own endpoint, so it is left alone"}
	case integration.RouteGateNoCredential:
		because := strings.TrimSpace(p.Gate.UnroutedBecause)
		if because == "" {
			because = "no provider key is set"
		}
		return gatedRoute{notice: prefix + "not routed through the proxy: " + because +
			"; set " + firstOr(p.Gate.CredentialEnv, "a provider key") + modelHint(p.Gate) + " to route it"}
	case integration.RouteGateForeignProvider:
		// Name the variable and the types the route speaks, never its value
		// beyond what the developer typed into it (a provider name).
		return gatedRoute{notice: prefix + "not routed through the proxy: " + p.Gate.ProviderTypeEnv +
			" selects a provider this route cannot carry (it speaks " + strings.Join(p.Gate.RoutableProviderTypes, ", ") +
			"), so your provider key is not sent through it; unset " + p.Gate.ProviderTypeEnv +
			" or set it to " + firstOr(p.Gate.RoutableProviderTypes, "a supported type") + " to route it"}
	case integration.RouteGateModelRequired:
		cred := firstSet(p.Gate.CredentialEnv, lookup)
		msg := prefix + cred + " is set, so this launch routes your own provider through the proxy, " +
			"and that needs an explicit model: pass --model <id>" + modelEnvHint(p.Gate) +
			". Unset " + cred + " to launch on your own sign-in instead."
		return gatedRoute{err: newVisibleLauncherError(errors.New(msg), msg)}
	default:
		return gatedRoute{routed: true, caveat: routedCaveat(label, p.Gate)}
	}
}

// routedCaveat renders the gate's RoutedCaveat as one launcher line, "" when
// the gate carries none.
func routedCaveat(label string, g *integration.RouteGate) string {
	c := strings.TrimSpace(g.RoutedCaveat)
	if c == "" {
		return ""
	}
	return "observer " + label + ": note: " + c
}

// modelHint is the " and a model (--model)" tail of the no-credential notice,
// empty when the lane needs no explicit model.
func modelHint(g *integration.RouteGate) string {
	if !g.RequiresModel() {
		return ""
	}
	return " and a model (--model)"
}

// modelEnvHint names the first documented model env var, if any.
func modelEnvHint(g *integration.RouteGate) string {
	if len(g.ModelEnv) == 0 {
		return ""
	}
	return fmt.Sprintf(" or set %s", g.ModelEnv[0])
}

func firstOr(xs []string, fallback string) string {
	if len(xs) > 0 && xs[0] != "" {
		return xs[0]
	}
	return fallback
}

// firstSet returns the NAME of the first key in keys that is set; never a value.
func firstSet(keys []string, lookup func(string) (string, bool)) string {
	for _, k := range keys {
		if v, ok := lookup(k); ok && strings.TrimSpace(v) != "" {
			return k
		}
	}
	return firstOr(keys, "a provider key")
}
