package integration

import "strings"

// This file holds the CONDITIONAL-ROUTE vocabulary: a launcher route that
// only works when the developer has configured the vendor's own
// bring-your-own-key lane. The canonical case is GitHub Copilot CLI: its
// COPILOT_PROVIDER_* lane reaches any OpenAI-compatible endpoint (so the
// proxy), but a developer signed in with a GitHub Copilot subscription has no
// provider key, and pointing COPILOT_PROVIDER_BASE_URL at the proxy switches
// Copilot into BYOK mode, which then refuses to run without a key and a model.
// Setting the route in that case turns a working tool into a broken one.
//
// The gate is DATA on the registry row (ProxyRoute.Gate); EvaluateRouteGate is
// the one ordered rule table every launcher walks. It reads env var PRESENCE
// only, never a credential value (the caller passes a lookup that answers "is
// it set"); the single value it compares is ProviderTypeEnv, a provider name.

// RouteGate is the precondition set for applying a conditional launcher route.
// Every field names env vars or argv keys, except RoutableProviderTypes, which
// lists provider names (never a credential).
type RouteGate struct {
	// CredentialEnv lists the vendor's provider-credential env vars. The route
	// applies only when at least one is present and non-empty; with none
	// present the launcher starts the product unrouted on its own sign-in.
	CredentialEnv []string
	// ModelEnv lists the vendor env vars that select an explicit model for the
	// gated lane. Together with ModelArguments and the launcher's own model
	// flag, at least one must be set when the route applies, or the vendor
	// refuses to run; the launcher then refuses with a clear message instead.
	// Empty ModelEnv and ModelArguments = the lane needs no explicit model.
	ModelEnv []string
	// ModelArguments are the product's own argv keys that select a model
	// (compared on the token before any '='; a value must follow).
	ModelArguments []string
	// UnroutedBecause completes the sentence "not routed through the proxy:"
	// for the closed-gate case, naming what the product uses instead, e.g.
	// "Copilot is using your GitHub sign-in".
	UnroutedBecause string
	// RoutedCaveat, when set, is printed after the "routing via" line of a
	// ROUTED launch: a lane the presence-only gate cannot see (a choice saved
	// in the product's own settings) that still bypasses the proxy, so the
	// routing line never over-claims. Empty = the routed outcome is exact.
	RoutedCaveat string
	// ProviderTypeEnv names the vendor env var that selects the BYOK lane's
	// provider protocol (COPILOT_PROVIDER_TYPE). Empty = the lane has no such
	// switch. It is the one env var whose VALUE the gate reads: it is a
	// provider name, never a credential.
	ProviderTypeEnv string
	// RoutableProviderTypes are the ProviderTypeEnv values the proxy route
	// can carry (case-insensitive). An unset or empty ProviderTypeEnv counts
	// as routable, because the launcher then sets it to the route's own type.
	// Any other value selects a provider the route's endpoint does not speak,
	// and routing it would send that provider's credential to the wrong
	// upstream (pass-2 review C156-19: an Anthropic key on the OpenAI lane).
	RoutableProviderTypes []string
	// ProviderTypeArguments are the product's argv keys that select the same
	// provider type (compared on the token before any '='; a value must
	// follow). Read like ProviderTypeEnv.
	ProviderTypeArguments []string
	// AuthSettingKeys are settings keys whose PRESENCE means the product has
	// a saved sign-in choice that can pin its vendor's own host whatever
	// base URL the launcher sets (surface-gap CLI-6: Gemini CLI's
	// security.auth.selectedType, an administrator's enforcedType). The
	// launcher reads key presence only and says which key may override the
	// route; the doctor classes the saved mode (agentconfig
	// gemini-cli/security.auth.selectedType).
	AuthSettingKeys []AuthSettingKey
	// DotenvKeys are variables a .env file the product loads can set to
	// switch its sign-in mode (GOOGLE_GENAI_USE_GCA); DotenvFiles are the
	// files it loads, "~/" the home and "<project>/" the launch directory.
	// Key presence only, never a value.
	DotenvKeys  []string
	DotenvFiles []string
}

// RouteGateOutcome is the closed result of EvaluateRouteGate.
type RouteGateOutcome string

const (
	// RouteGateRouted: apply the launcher route.
	RouteGateRouted RouteGateOutcome = "routed"
	// RouteGateOwnEndpoint: the developer already pointed the route's base-URL
	// variable at their own endpoint; leave it alone and launch unrouted.
	RouteGateOwnEndpoint RouteGateOutcome = "own_endpoint"
	// RouteGateNoCredential: no provider credential is configured; the product
	// runs on its own sign-in, which the proxy cannot carry. Launch unrouted.
	RouteGateNoCredential RouteGateOutcome = "no_credential" //nolint:gosec // G101 false positive: an outcome label, not a credential

	// RouteGateModelRequired: a credential is configured (the developer chose
	// the BYOK lane) but no explicit model is, and the vendor refuses BYOK
	// without one. Refuse the launch with a message naming the fix.
	RouteGateModelRequired RouteGateOutcome = "model_required"

	// RouteGateForeignProvider: the developer's BYOK lane names a provider
	// type the route cannot carry (RoutableProviderTypes). Launch unrouted on
	// their own provider settings rather than send that provider's credential
	// to the route's upstream.
	RouteGateForeignProvider RouteGateOutcome = "foreign_provider"

	// RouteGateRoutedAuthPinned: apply the route, and say which saved
	// sign-in setting (AuthSettingKeys, DotenvKeys) may still send the
	// product to its vendor's own host (CLI-6). The route is never refused
	// for it: the saved choice may be the API-key mode the route carries.
	RouteGateRoutedAuthPinned RouteGateOutcome = "routed_auth_pinned"
)

// RouteGateInput is the resolved, boolean view of one launch, computed at the
// launcher boundary so the rule table stays pure.
type RouteGateInput struct {
	// OwnEndpoint: the route's base-URL env var is already set to an endpoint
	// that is not the Observer proxy.
	OwnEndpoint bool
	// CredentialPresent: at least one RouteGate.CredentialEnv var is set.
	CredentialPresent bool
	// ModelPresent: an explicit model is set through ModelEnv, ModelArguments
	// or the launcher's own model flag.
	ModelPresent bool
	// ForeignProvider: RouteGate.ProviderTypeEnv is set to a value outside
	// RoutableProviderTypes.
	ForeignProvider bool
	// AuthPinned: an AuthSettingKeys key or a DotenvKeys variable is
	// present, so a saved sign-in choice may override the route.
	AuthPinned bool
}

// routeGateRule is one row of the ordered gate table: first match wins, one
// test case per row (CLAUDE.md #5).
type routeGateRule struct {
	outcome RouteGateOutcome
	match   func(g RouteGate, in RouteGateInput) bool
}

var routeGateRules = []routeGateRule{
	// 1. The developer's own endpoint wins: never overwrite it, never claim it.
	{RouteGateOwnEndpoint, func(_ RouteGate, in RouteGateInput) bool { return in.OwnEndpoint }},
	// 2. No provider credential: the product's own sign-in is in charge.
	{RouteGateNoCredential, func(g RouteGate, in RouteGateInput) bool {
		return len(g.CredentialEnv) > 0 && !in.CredentialPresent
	}},
	// 3. The BYOK lane names a provider the route cannot carry: its
	// credential must not reach the route's upstream.
	{RouteGateForeignProvider, func(_ RouteGate, in RouteGateInput) bool { return in.ForeignProvider }},
	// 4. The BYOK lane is chosen but has no explicit model.
	{RouteGateModelRequired, func(g RouteGate, in RouteGateInput) bool {
		return g.RequiresModel() && !in.ModelPresent
	}},
	// 5. A saved sign-in choice may outrank the route: route, and say so.
	{RouteGateRoutedAuthPinned, func(_ RouteGate, in RouteGateInput) bool { return in.AuthPinned }},
	// 6. Everything the lane needs is present.
	{RouteGateRouted, func(RouteGate, RouteGateInput) bool { return true }},
}

// EvaluateRouteGate walks the gate table for one launch. A nil gate always
// routes (the route is unconditional).
func EvaluateRouteGate(g *RouteGate, in RouteGateInput) RouteGateOutcome {
	if g == nil {
		return RouteGateRouted
	}
	for _, r := range routeGateRules {
		if r.match(*g, in) {
			return r.outcome
		}
	}
	return RouteGateRouted
}

// RequiresModel reports whether the gated lane needs an explicit model.
func (g RouteGate) RequiresModel() bool {
	return len(g.ModelEnv) > 0 || len(g.ModelArguments) > 0
}

// CredentialPresent reports whether any CredentialEnv var is set to a
// non-empty value. lookup answers env presence (os.LookupEnv shape); the value
// is compared to "" only and never returned or retained.
func (g RouteGate) CredentialPresent(lookup func(string) (string, bool)) bool {
	return anyEnvSet(g.CredentialEnv, lookup)
}

// ModelPresent reports whether an explicit model is set: the launcher's own
// model flag value, any ModelEnv var, or a ModelArguments key in args carrying
// a non-empty value (`--model x` or `--model=x`).
func (g RouteGate) ModelPresent(lookup func(string) (string, bool), args []string, launcherModel string) bool {
	if strings.TrimSpace(launcherModel) != "" || anyEnvSet(g.ModelEnv, lookup) {
		return true
	}
	for i, tok := range args {
		if tok == "--" {
			// Everything after a bare "--" is the product's positional data.
			return false
		}
		for _, key := range g.ModelArguments {
			if tok == key && i+1 < len(args) && strings.TrimSpace(args[i+1]) != "" {
				return true
			}
			if v, ok := strings.CutPrefix(tok, key+"="); ok && strings.TrimSpace(v) != "" {
				return true
			}
		}
	}
	return false
}

// ProviderTypeForeign reports whether ProviderTypeEnv, or a
// ProviderTypeArguments key in args, selects a provider type outside
// RoutableProviderTypes. Unset or empty is not foreign. The values read are
// provider names only.
func (g RouteGate) ProviderTypeForeign(lookup func(string) (string, bool), args []string) bool {
	var vals []string
	if g.ProviderTypeEnv != "" && lookup != nil {
		if v, ok := lookup(g.ProviderTypeEnv); ok {
			vals = append(vals, v)
		}
	}
	for i, tok := range args {
		if tok == "--" {
			break // the product's positional data
		}
		for _, key := range g.ProviderTypeArguments {
			if tok == key && i+1 < len(args) {
				vals = append(vals, args[i+1])
			}
			if v, ok := strings.CutPrefix(tok, key+"="); ok {
				vals = append(vals, v)
			}
		}
	}
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" && !g.routableType(v) {
			return true
		}
	}
	return false
}

func (g RouteGate) routableType(v string) bool {
	for _, t := range g.RoutableProviderTypes {
		if strings.EqualFold(v, t) {
			return true
		}
	}
	return false
}

// GateEnvNames returns every env var NAME the gate decision reads (credential,
// model, provider type, and the route's own base-URL variable), so a launch
// handed to the daemon can forward exactly those and the daemon-spawned
// launcher decides on the caller's environment. Nil for an ungated or nil
// route.
func (p *ProxyRoute) GateEnvNames() []string {
	if p == nil || p.Gate == nil {
		return nil
	}
	out := make([]string, 0, len(p.Gate.CredentialEnv)+len(p.Gate.ModelEnv)+2)
	out = append(out, p.Gate.CredentialEnv...)
	out = append(out, p.Gate.ModelEnv...)
	if p.Gate.ProviderTypeEnv != "" {
		out = append(out, p.Gate.ProviderTypeEnv)
	}
	if p.EnvVar != "" {
		out = append(out, p.EnvVar)
	}
	return out
}

func anyEnvSet(keys []string, lookup func(string) (string, bool)) bool {
	if lookup == nil {
		return false
	}
	for _, k := range keys {
		if v, ok := lookup(k); ok && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}
