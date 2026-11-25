package routingconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/routing"
)

// OrgBodyMode extracts the [routing].mode token from an org-distributed
// routing body ("" when absent or unparseable). ComposeOrgPolicy structurally
// IGNORES this mode on the individual plane (§R23: no remote enforce toggle).
// The Arc 4 P3b managed-enforce lift is the SOLE consumer: cmd/observer honors
// this mode only for a managed node that holds the enforce.routing authority,
// leaving every non-managed node's routing posture entirely node-owned.
func OrgBodyMode(orgBody string) string {
	// Prefer the [routing] header form (the shape the org actually distributes);
	// toml does not error on an unrelated top-level key, so a bare fragment
	// leaves org.Routing.Mode empty and we fall through to the bare parse.
	var org struct {
		Routing config.RoutingConfig `toml:"routing"`
	}
	if err := toml.Unmarshal([]byte(orgBody), &org); err == nil {
		if m := strings.TrimSpace(org.Routing.Mode); m != "" {
			return m
		}
	}
	var bare config.RoutingConfig
	if err := toml.Unmarshal([]byte(orgBody), &bare); err == nil {
		return strings.TrimSpace(bare.Mode)
	}
	return ""
}

// Spec mirrors the [routing] config section into the routing package's
// compiler input.
func Spec(rc config.RoutingConfig) routing.PolicySpec {
	spec := routing.PolicySpec{
		Policy:                  rc.Policy,
		MinTurnsBetweenSwitches: rc.Stickiness.MinTurnsBetweenSwitches,
		RespectCache:            rc.Stickiness.RespectCache,
		PathClasses:             rc.PathClasses,
		RateLimitEnabled:        rc.RateLimitWindow.Enabled,
		RateLimitHeadroomPct:    rc.RateLimitWindow.HeadroomPct,
		Fallbacks:               rc.Reliability.Fallbacks,
	}
	for _, pr := range rc.Privacy.Rules {
		spec.PrivacyRules = append(spec.PrivacyRules, routing.PrivacyRuleSpec{
			Project:        pr.Project,
			PathClass:      pr.PathClass,
			LocalOnly:      pr.LocalOnly,
			DenyProviders:  pr.DenyProviders,
			AllowProviders: pr.AllowProviders,
		})
	}
	for _, bs := range rc.Budget.Scopes {
		spec.BudgetScopes = append(spec.BudgetScopes, routing.BudgetScopeSpec{
			Scope:     bs.Scope,
			LimitUSD:  bs.LimitUSD,
			Window:    bs.Window,
			Bands:     bs.Bands,
			Exhausted: bs.Exhausted,
		})
	}
	for _, r := range rc.Rules {
		spec.Rules = append(spec.Rules, routing.RuleSpec{
			Name: r.Name,
			When: routing.WhenSpec{
				TurnKind:           r.When.TurnKind,
				TurnKinds:          r.When.TurnKinds,
				Phase:              r.When.Phase,
				TierAtLeast:        r.When.TierAtLeast,
				Model:              r.When.Model,
				Project:            r.When.Project,
				PathClass:          r.When.PathClass,
				SessionAgeTurnsMin: r.When.SessionAgeTurnsMin,
				SessionAgeTurnsMax: r.When.SessionAgeTurnsMax,
				Sidechain:          r.When.Sidechain,
				MaxTools:           r.When.MaxTools,
				MinPromptTokens:    r.When.MinPromptTokens,
				MaxPromptTokens:    r.When.MaxPromptTokens,
				BudgetBandAtLeast:  r.When.BudgetBandAtLeast,
				Entitlement:        r.When.Entitlement,
			},
			Action: routing.ActionSpec{
				RouteToTier:      r.Action.RouteToTier,
				RouteToModel:     r.Action.RouteToModel,
				PinTier:          r.Action.PinTier,
				NoRoute:          r.Action.NoRoute,
				SetEffort:        r.Action.SetEffort,
				SetFallbackChain: r.Action.SetFallbackChain,
				DenyProviders:    r.Action.DenyProviders,
				AllowProviders:   r.Action.AllowProviders,
				Reason:           r.Action.Reason,
			},
		})
	}
	return spec
}

// TierOverrides converts the [routing.tiers] map for
// routing.TierResolver.Reload. Nil when no overrides are configured.
func TierOverrides(rc config.RoutingConfig) map[string]routing.Tier {
	if len(rc.Tiers) == 0 {
		return nil
	}
	out := make(map[string]routing.Tier, len(rc.Tiers))
	for model, tier := range rc.Tiers {
		out[model] = routing.Tier(tier)
	}
	return out
}

// ResolvedTierOverrides composes the §R7.3 benchmark imports with the
// user's explicit [routing.tiers] map (explicit wins) and returns the
// merged overrides plus per-file provenance strings. A file that
// fails to read or parse is reported in errs and SKIPPED — a bad
// benchmark file degrades to the seed table, never a failed start.
func ResolvedTierOverrides(rc config.RoutingConfig) (overrides map[string]routing.Tier, provenance []string, errs []error) {
	bench := map[string]routing.Tier{}
	for _, path := range rc.BenchmarkFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("benchmark file %s: %w", path, err))
			continue
		}
		imp, err := routing.ImportBenchmarks(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("benchmark file %s: %w", path, err))
			continue
		}
		for model, tier := range imp.Overrides {
			bench[model] = tier
		}
		provenance = append(provenance, imp.Provenance())
	}
	merged := routing.MergeTierOverrides(bench, TierOverrides(rc))
	if len(merged) == 0 {
		return nil, provenance, errs
	}
	return merged, provenance, errs
}

// LocalUpstreamRouting derives the §R11.7 routing inputs from the
// [[routing.local_upstreams]] declarations:
//
//   - tierOverrides places every declared model in TierLocal;
//   - reps installs the OpenAI-shape TierLocal representative (the
//     first declared model) — local inference servers speak the OpenAI
//     wire shape, so only OpenAI-shape requests can route locally
//     until cross-provider translation ships (§R11.4); an
//     Anthropic-shape privacy hold stays a loud privacy_hold row;
//   - routes maps each model to its endpoint base URL for the proxy.
func LocalUpstreamRouting(rc config.RoutingConfig) (tierOverrides map[string]routing.Tier, reps map[routing.ProviderShape]string, routes map[string]string) {
	if len(rc.LocalUpstreams) == 0 {
		return nil, nil, nil
	}
	tierOverrides = map[string]routing.Tier{}
	routes = map[string]string{}
	for _, lu := range rc.LocalUpstreams {
		for _, model := range lu.Models {
			tierOverrides[model] = routing.TierLocal
			routes[model] = lu.BaseURL
			if reps == nil {
				reps = map[routing.ProviderShape]string{routing.ShapeOpenAI: model}
			}
		}
	}
	return tierOverrides, reps, routes
}

// ComposeOrgPolicy composes an org-distributed policy body (§R19.1)
// with the node's local spec. Composition semantics:
//
//   - org HARD constraints — privacy rules, budget ceilings, path
//     classes — compose by INTERSECTION, so they cannot be relaxed
//     locally: org privacy rules append to the filter set (filters
//     intersect); org budget scopes add ceilings (the engine acts on
//     the WORST-burning matching scope); org path classes merge in
//     (local definitions win name collisions for local rules' own
//     references).
//   - org SOFT preferences — [[routing.rules]] rows — append AFTER the
//     local rules: first-match-wins means they rank UNDER local.
//   - enabled / mode / policy keys in the org body are STRUCTURALLY
//     IGNORED: this function never reads them — enforcement is
//     node-side opt-in by design (§R23: no remote enforce toggle).
//
// A body that fails to parse degrades to the local spec unchanged with
// the error returned for logging (fail-open; a broken org policy must
// not take the node's routing down).
func ComposeOrgPolicy(local routing.PolicySpec, orgBody string) (routing.PolicySpec, error) {
	var org struct {
		Routing config.RoutingConfig `toml:"routing"`
	}
	if err := toml.Unmarshal([]byte(orgBody), &org); err != nil {
		// Also accept a bare fragment without the [routing] header.
		if err2 := toml.Unmarshal([]byte(orgBody), &org.Routing); err2 != nil {
			return local, fmt.Errorf("routingconfig.ComposeOrgPolicy: %w", err)
		}
	}
	orgSpec := Spec(org.Routing)

	out := local
	// Hard constraints intersect (cannot be relaxed locally).
	out.PrivacyRules = append(append([]routing.PrivacyRuleSpec{}, orgSpec.PrivacyRules...), local.PrivacyRules...)
	out.BudgetScopes = append(append([]routing.BudgetScopeSpec{}, local.BudgetScopes...), orgSpec.BudgetScopes...)
	if len(orgSpec.PathClasses) > 0 {
		merged := map[string][]string{}
		for name, globs := range orgSpec.PathClasses {
			merged[name] = globs
		}
		for name, globs := range local.PathClasses {
			merged[name] = globs // local definitions win collisions
		}
		out.PathClasses = merged
	}
	// Soft preferences rank UNDER local (appended after).
	out.Rules = append(append([]routing.RuleSpec{}, local.Rules...), orgSpec.Rules...)
	return out, nil
}
