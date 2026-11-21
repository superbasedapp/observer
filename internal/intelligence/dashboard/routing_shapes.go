package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/routingcore"
)

// Routing shape editors (dashboard CLI parity plan, section 9 follow-up):
// the Settings > Routing cards for the non-secret [routing] shapes that used
// to be config-file-only - tier overrides, path classes, budget scopes,
// privacy rules, local upstreams and model fallbacks.
//
// One writer, as for [[routing.rules]]: the shapes ride the routing section
// save (PUT /api/config/section/routing, settings.go case "routing") through
// optional Set* fields. Their JSON names are DISTINCT from the GET payload's
// Go field names (Tiers, PathClasses, ...), so the section form, which
// spreads the GET payload into its body, can never replace a shape by
// accident:
//
//   - field absent (or JSON null): the shape is kept exactly as the file has it;
//   - field present: the shape is replaced wholesale, an empty value clears it.
//
// A replacement passes three gates before anything is written, and a problem
// at any of them refuses the save with the file untouched:
//
//  1. the dashboard's own row checks (routingShapes below): what the loader
//     does not check but an editor must (a tier name outside the vocabulary,
//     an invalid glob, a dangling path-class reference, a base URL with a
//     user name in it, a model served by two upstreams);
//  2. the loader's [routing] checks over the WHOLE next section
//     (config.ValidateRouting, the same function config.Load runs), so the
//     next daemon start loads what this save writes;
//  3. the compiler's error-severity lint (newRoutingLintErrors,
//     routingpolicy.go), counting only the findings this save introduces.
//
// key_pool has no Set* field and never will: it holds API keys, and secret
// keys are never readable or writable over HTTP (decision P-4).

// routingShapeEdits are the optional replace fields of the routing section
// body. nil = keep the file's value; non-nil = replace (an empty map or list
// clears the shape).
type routingShapeEdits struct {
	SetTiers          *map[string]string                   `json:"SetTiers"`
	SetPathClasses    *map[string][]string                 `json:"SetPathClasses"`
	SetBudgetScopes   *[]config.RoutingBudgetScopeConfig   `json:"SetBudgetScopes"`
	SetPrivacyRules   *[]config.RoutingPrivacyRuleConfig   `json:"SetPrivacyRules"`
	SetLocalUpstreams *[]config.RoutingLocalUpstreamConfig `json:"SetLocalUpstreams"`
	SetFallbacks      *map[string][]string                 `json:"SetFallbacks"`
}

// routingShapeRule is one ordered dashboard check of a shape. check sees the
// next section (the replacement applied) and base (the section before this
// save's shapes) and returns one problem per offending row.
type routingShapeRule struct {
	id    string
	check func(next, base config.RoutingConfig) []string
}

// routingShape is one Set* field: the card label every problem is prefixed
// with, the exact JSON field name, where it decodes, how a present value
// replaces the shape, and the shape's ordered checks.
type routingShape struct {
	label  string
	field  string
	target func(e *routingShapeEdits) any
	// apply replaces the shape on rc when the edit carries it and reports
	// whether it did.
	apply func(e routingShapeEdits, rc *config.RoutingConfig) bool
	rules []routingShapeRule
}

// routingShapes is the shape table, in the order the cards render.
var routingShapes = []routingShape{
	{
		label:  "Tier overrides",
		field:  "SetTiers",
		target: func(e *routingShapeEdits) any { return &e.SetTiers },
		apply: func(e routingShapeEdits, rc *config.RoutingConfig) bool {
			if e.SetTiers == nil {
				return false
			}
			rc.Tiers = nilIfEmptyMap(*e.SetTiers)
			return true
		},
		rules: []routingShapeRule{
			{"tiers_model_named", func(next, _ config.RoutingConfig) []string {
				var out []string
				for _, model := range routingSortedKeys(next.Tiers) {
					if p := routingTextProblem("model", model); p != "" {
						out = append(out, p)
					}
				}
				return out
			}},
			{"tiers_known_tier", func(next, _ config.RoutingConfig) []string {
				var out []string
				for _, model := range routingSortedKeys(next.Tiers) {
					if tier := next.Tiers[model]; !routingKnownTier(tier) {
						out = append(out, fmt.Sprintf("model %q: tier %q is not one of %s", model, tier, routingTierList()))
					}
				}
				return out
			}},
			// The privacy basis treats the local tier as "on this machine"
			// (internal/routing/bases.go providerClassForCandidate), so a
			// cloud model placed there would pass a local-only privacy rule
			// while its requests still go to its provider. Only a model a
			// local upstream serves may sit in the local tier.
			{"tiers_local_needs_upstream", func(next, _ config.RoutingConfig) []string {
				var out []string
				served := routingUpstreamModels(next.LocalUpstreams)
				for _, model := range routingSortedKeys(next.Tiers) {
					if next.Tiers[model] == string(routingcore.TierLocal) && !served[model] {
						out = append(out, fmt.Sprintf("model %q: only a model a local upstream serves can be in the local tier (privacy rules treat that tier as this machine); add it under Local upstreams instead", model))
					}
				}
				return out
			}},
		},
	},
	{
		label:  "Path classes",
		field:  "SetPathClasses",
		target: func(e *routingShapeEdits) any { return &e.SetPathClasses },
		apply: func(e routingShapeEdits, rc *config.RoutingConfig) bool {
			if e.SetPathClasses == nil {
				return false
			}
			rc.PathClasses = nilIfEmptyMap(*e.SetPathClasses)
			return true
		},
		rules: []routingShapeRule{
			{"path_class_named", func(next, _ config.RoutingConfig) []string {
				var out []string
				for _, name := range routingSortedKeys(next.PathClasses) {
					if p := routingTextProblem("class name", name); p != "" {
						out = append(out, p)
					}
				}
				return out
			}},
			{"path_class_has_patterns", func(next, _ config.RoutingConfig) []string {
				var out []string
				for _, name := range routingSortedKeys(next.PathClasses) {
					if len(next.PathClasses[name]) == 0 {
						out = append(out, fmt.Sprintf("class %q has no path patterns; add one or remove the class", name))
					}
				}
				return out
			}},
			{"path_class_valid_globs", func(next, _ config.RoutingConfig) []string {
				var out []string
				for _, name := range routingSortedKeys(next.PathClasses) {
					for _, pat := range next.PathClasses[name] {
						if p := routingTextProblem("pattern", pat); p != "" {
							out = append(out, fmt.Sprintf("class %q: %s", name, p))
							continue
						}
						if !routingGlobValid(pat) {
							out = append(out, fmt.Sprintf("class %q: pattern %q is not a valid glob (check its [ ] brackets and \\ escapes)", name, pat))
						}
					}
				}
				return out
			}},
			{"path_class_still_used", func(next, base config.RoutingConfig) []string {
				var out []string
				for _, name := range routingSortedKeys(base.PathClasses) {
					if _, kept := next.PathClasses[name]; kept {
						continue
					}
					for i, pr := range next.Privacy.Rules {
						if pr.PathClass == name {
							out = append(out, fmt.Sprintf("class %q is still used by privacy rule %d; change or remove that rule first", name, i+1))
						}
					}
					for _, r := range next.Rules {
						if r.When.PathClass == name {
							out = append(out, fmt.Sprintf("class %q is still used by custom rule %q; change or remove that rule first", name, r.Name))
						}
					}
				}
				return out
			}},
		},
	},
	{
		label:  "Budget scopes",
		field:  "SetBudgetScopes",
		target: func(e *routingShapeEdits) any { return &e.SetBudgetScopes },
		apply: func(e routingShapeEdits, rc *config.RoutingConfig) bool {
			if e.SetBudgetScopes == nil {
				return false
			}
			var scopes []config.RoutingBudgetScopeConfig
			for _, sc := range *e.SetBudgetScopes {
				sc.Bands = nilIfEmptySlice(sc.Bands)
				scopes = append(scopes, sc)
			}
			rc.Budget.Scopes = scopes
			return true
		},
		rules: []routingShapeRule{
			{"budget_scope_target_trimmed", func(next, _ config.RoutingConfig) []string {
				var out []string
				for i, sc := range next.Budget.Scopes {
					if kind, target, ok := strings.Cut(sc.Scope, ":"); ok && target != strings.TrimSpace(target) {
						out = append(out, fmt.Sprintf("row %d: the %s name in %q has spaces at the start or end", i+1, kind, sc.Scope))
					}
				}
				return out
			}},
			{"budget_scope_known_tier", func(next, _ config.RoutingConfig) []string {
				var out []string
				for i, sc := range next.Budget.Scopes {
					if tier, ok := strings.CutPrefix(sc.Scope, "tier:"); ok && tier != "" && !routingKnownTier(tier) {
						out = append(out, fmt.Sprintf("row %d: tier %q is not one of %s", i+1, tier, routingTierList()))
					}
				}
				return out
			}},
			{"budget_scope_unique", func(next, _ config.RoutingConfig) []string {
				var out []string
				seen := map[string]int{}
				for i, sc := range next.Budget.Scopes {
					key := sc.Scope + "\x00" + sc.Window
					if first, dup := seen[key]; dup {
						out = append(out, fmt.Sprintf("row %d repeats row %d (%s over a %s); remove one", i+1, first, sc.Scope, sc.Window))
						continue
					}
					seen[key] = i + 1
				}
				return out
			}},
		},
	},
	{
		label:  "Privacy rules",
		field:  "SetPrivacyRules",
		target: func(e *routingShapeEdits) any { return &e.SetPrivacyRules },
		apply: func(e routingShapeEdits, rc *config.RoutingConfig) bool {
			if e.SetPrivacyRules == nil {
				return false
			}
			var rules []config.RoutingPrivacyRuleConfig
			for _, pr := range *e.SetPrivacyRules {
				pr.DenyProviders = nilIfEmptySlice(pr.DenyProviders)
				pr.AllowProviders = nilIfEmptySlice(pr.AllowProviders)
				rules = append(rules, pr)
			}
			rc.Privacy.Rules = rules
			return true
		},
		rules: []routingShapeRule{
			{"privacy_selectors_trimmed", func(next, _ config.RoutingConfig) []string {
				var out []string
				for i, pr := range next.Privacy.Rules {
					for _, f := range []struct{ what, v string }{{"project", pr.Project}, {"path class", pr.PathClass}} {
						if f.v != "" && f.v != strings.TrimSpace(f.v) {
							out = append(out, fmt.Sprintf("rule %d: %s %q has spaces at the start or end", i+1, f.what, f.v))
						}
					}
				}
				return out
			}},
			{"privacy_path_class_defined", func(next, _ config.RoutingConfig) []string {
				var out []string
				for i, pr := range next.Privacy.Rules {
					if pr.PathClass == "" {
						continue
					}
					if _, ok := next.PathClasses[pr.PathClass]; !ok {
						out = append(out, fmt.Sprintf("rule %d: path class %q is not defined; add it under Path classes first", i+1, pr.PathClass))
					}
				}
				return out
			}},
			{"privacy_provider_names", func(next, _ config.RoutingConfig) []string {
				var out []string
				for i, pr := range next.Privacy.Rules {
					for _, f := range []struct {
						list      string
						names     []string
						allowStar bool
					}{{"deny", pr.DenyProviders, true}, {"allow", pr.AllowProviders, false}} {
						for _, name := range f.names {
							if p := routingProviderProblem(name, f.allowStar); p != "" {
								out = append(out, fmt.Sprintf("rule %d, %s list: %s", i+1, f.list, p))
							}
						}
					}
				}
				return out
			}},
		},
	},
	{
		label:  "Local upstreams",
		field:  "SetLocalUpstreams",
		target: func(e *routingShapeEdits) any { return &e.SetLocalUpstreams },
		apply: func(e routingShapeEdits, rc *config.RoutingConfig) bool {
			if e.SetLocalUpstreams == nil {
				return false
			}
			var ups []config.RoutingLocalUpstreamConfig
			for _, lu := range *e.SetLocalUpstreams {
				lu.Models = nilIfEmptySlice(lu.Models)
				ups = append(ups, lu)
			}
			rc.LocalUpstreams = ups
			return true
		},
		rules: []routingShapeRule{
			{"upstream_named_once", func(next, _ config.RoutingConfig) []string {
				var out []string
				seen := map[string]bool{}
				for i, lu := range next.LocalUpstreams {
					if p := routingTextProblem("name", lu.Name); p != "" {
						out = append(out, fmt.Sprintf("row %d: %s", i+1, p))
						continue
					}
					if seen[lu.Name] {
						out = append(out, fmt.Sprintf("%q is listed twice; give each endpoint its own name", lu.Name))
					}
					seen[lu.Name] = true
				}
				return out
			}},
			{"upstream_base_url", func(next, _ config.RoutingConfig) []string {
				var out []string
				for i, lu := range next.LocalUpstreams {
					if p := routingBaseURLProblem(lu.BaseURL); p != "" {
						out = append(out, fmt.Sprintf("row %d (%s): %s", i+1, lu.Name, p))
					}
				}
				return out
			}},
			{"upstream_models_once", func(next, _ config.RoutingConfig) []string {
				var out []string
				servedBy := map[string]string{}
				for i, lu := range next.LocalUpstreams {
					for _, model := range lu.Models {
						if p := routingTextProblem("model", model); p != "" {
							out = append(out, fmt.Sprintf("row %d (%s): %s", i+1, lu.Name, p))
							continue
						}
						if prev, dup := servedBy[model]; dup {
							out = append(out, fmt.Sprintf("model %q is served by both %q and %q; keep it on one endpoint", model, prev, lu.Name))
							continue
						}
						servedBy[model] = lu.Name
					}
				}
				return out
			}},
			// The other half of tiers_local_needs_upstream: removing the
			// endpoint of a model pinned to the local tier would leave a
			// cloud model that local-only privacy rules let through.
			{"upstream_keeps_local_tier_pins", func(next, base config.RoutingConfig) []string {
				var out []string
				was := routingUpstreamModels(base.LocalUpstreams)
				now := routingUpstreamModels(next.LocalUpstreams)
				for _, model := range routingSortedKeys(next.Tiers) {
					if next.Tiers[model] == string(routingcore.TierLocal) && was[model] && !now[model] {
						out = append(out, fmt.Sprintf("model %q is set to the local tier under Tier overrides; change that override first", model))
					}
				}
				return out
			}},
		},
	},
	{
		label:  "Model fallbacks",
		field:  "SetFallbacks",
		target: func(e *routingShapeEdits) any { return &e.SetFallbacks },
		apply: func(e routingShapeEdits, rc *config.RoutingConfig) bool {
			if e.SetFallbacks == nil {
				return false
			}
			rc.Reliability.Fallbacks = nilIfEmptyMap(*e.SetFallbacks)
			return true
		},
		rules: []routingShapeRule{
			{"fallback_from_named", func(next, _ config.RoutingConfig) []string {
				var out []string
				for _, from := range routingSortedKeys(next.Reliability.Fallbacks) {
					if p := routingTextProblem("model or tier", from); p != "" {
						out = append(out, p)
					}
				}
				return out
			}},
			{"fallback_chain", func(next, _ config.RoutingConfig) []string {
				var out []string
				for _, from := range routingSortedKeys(next.Reliability.Fallbacks) {
					chain := next.Reliability.Fallbacks[from]
					if len(chain) == 0 {
						out = append(out, fmt.Sprintf("%q has no fallback models; add one or remove the row", from))
						continue
					}
					seen := map[string]bool{}
					for _, model := range chain {
						text := routingTextProblem("fallback model", model)
						switch {
						case text != "":
							out = append(out, fmt.Sprintf("%q: %s", from, text))
						case model == from:
							out = append(out, fmt.Sprintf("%q falls back to itself; remove it from its own chain", from))
						case seen[model]:
							out = append(out, fmt.Sprintf("%q lists %q twice", from, model))
						}
						seen[model] = true
					}
				}
				return out
			}},
		},
	},
}

// applyRoutingShapes is the routing section's gate for the Set* fields
// (settings.go case "routing"). next is the section about to be saved, with
// the form's knobs applied and the shapes as the file has them; on success
// it carries every replaced shape. Problems refuse the save, and next is
// left untouched.
func applyRoutingShapes(next *config.RoutingConfig, body []byte) []string {
	edits, problems := decodeRoutingShapeEdits(body)
	if len(problems) > 0 {
		return problems
	}
	base := *next
	candidate := base
	var present []routingShape
	for _, sh := range routingShapes {
		if sh.apply(edits, &candidate) {
			present = append(present, sh)
		}
	}
	if len(present) == 0 {
		return nil
	}
	for _, sh := range present {
		for _, rule := range sh.rules {
			for _, p := range rule.check(candidate, base) {
				problems = append(problems, sh.label+": "+p)
			}
		}
	}
	if len(problems) > 0 {
		return problems
	}
	// The loader's own [routing] checks over the whole section: exactly what
	// the next daemon start runs (config.Load -> validateRouting).
	if err := config.ValidateRouting(candidate); err != nil {
		return []string{err.Error()}
	}
	if problems := newRoutingLintErrors(base, candidate); len(problems) > 0 {
		return problems
	}
	*next = candidate
	return nil
}

// decodeRoutingShapeEdits reads the Set* fields of a routing section body.
// Each present field is decoded on its own and strictly: a row carrying a
// field the shape does not have is refused instead of silently dropped. The
// names match exactly (a differently cased key is not a Set* field).
func decodeRoutingShapeEdits(body []byte) (routingShapeEdits, []string) {
	var edits routingShapeEdits
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return edits, []string{fmt.Sprintf("decode routing shapes: %v", err)}
	}
	var problems []string
	for _, sh := range routingShapes {
		raw, ok := fields[sh.field]
		if !ok {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(sh.target(&edits)); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", sh.label, err))
		}
	}
	return edits, problems
}

// routingTextProblem reports an empty name or one with spaces at either end
// ("" when the text is fine). Lookups are exact, so " ollama" never matches
// "ollama": the editors trim, and the save refuses what they would not send.
func routingTextProblem(what, s string) string {
	switch {
	case strings.TrimSpace(s) == "":
		return "a " + what + " is empty"
	case s != strings.TrimSpace(s):
		return fmt.Sprintf("%s %q has spaces at the start or end", what, s)
	}
	return ""
}

// routingKnownTier reports whether tier is in the shipped tier vocabulary.
func routingKnownTier(tier string) bool { return routingcore.Tier(tier).Known() }

// routingTierList names the tier vocabulary for a refusal message.
func routingTierList() string {
	var names []string
	for _, t := range routingcore.AllTiers() {
		names = append(names, string(t))
	}
	return strings.Join(names, ", ")
}

// routingGlobValid mirrors the path-class matcher
// (internal/store/routingsnap.go pathClassMatch): a "**/" prefix and a
// "/**" suffix are its own forms, the rest goes to path.Match, whose only
// error is a malformed pattern. path.Match checks the whole pattern even when
// the name does not match, so matching against "" is a syntax check.
func routingGlobValid(pat string) bool {
	pat = strings.TrimPrefix(filepath.ToSlash(pat), "**/")
	if strings.HasSuffix(pat, "/**") {
		return true // matched as a literal directory prefix
	}
	_, err := path.Match(pat, "")
	return err == nil
}

// routingProviderProblem checks one privacy-rule provider name against the
// provider-class vocabulary the privacy basis compares with
// (internal/routing/bases.go providerClassForCandidate): lowercase classes
// such as anthropic, openai, google, local or a router prefix such as
// openrouter. "*" means "every provider not allowed" and only in a deny list.
func routingProviderProblem(name string, allowStar bool) string {
	if p := routingTextProblem("provider name", name); p != "" {
		return p
	}
	if name == "*" {
		if allowStar {
			return ""
		}
		return `"*" only works in the deny list (deny every provider not allowed)`
	}
	if name != strings.ToLower(name) {
		return fmt.Sprintf("provider %q never matches: provider names are lowercase (%q)", name, strings.ToLower(name))
	}
	return ""
}

// routingBaseURLProblem checks a local upstream's base URL beyond the
// loader's http(s) prefix check: it must parse, name a host, carry no user
// name or password (the message never echoes such a URL) and no query or
// fragment, because the proxy appends the API path to it. Any host is
// allowed, loopback or not: pointing routing at another machine is the
// feature.
func routingBaseURLProblem(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "a base URL is empty"
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "the base URL does not parse; use the form http://localhost:11434/v1"
	}
	// No message quotes the URL: one that fails here may carry a credential
	// (a user name, a password, a key in the query).
	switch {
	case u.User != nil:
		return "the base URL must not carry a user name or password"
	case trimmed != raw:
		return "the base URL has spaces at the start or end"
	case u.Scheme != "http" && u.Scheme != "https":
		return "the base URL must start with http:// or https://"
	case u.Host == "":
		return "the base URL names no host; use the form http://localhost:11434/v1"
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return "the base URL must not have a ?query or #fragment"
	}
	return ""
}

// routingUpstreamModels is the set of model ids the local upstreams serve.
func routingUpstreamModels(ups []config.RoutingLocalUpstreamConfig) map[string]bool {
	out := map[string]bool{}
	for _, lu := range ups {
		for _, m := range lu.Models {
			out[m] = true
		}
	}
	return out
}

// routingSortedKeys returns m's keys sorted, so problems come out in a
// stable order.
func routingSortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// nilIfEmptyMap keeps a cleared table out of the file instead of writing an
// empty header.
func nilIfEmptyMap[V any](m map[string]V) map[string]V {
	if len(m) == 0 {
		return nil
	}
	return m
}

// nilIfEmptySlice keeps an empty list out of the file (an empty bands list
// and an absent one both mean the defaults).
func nilIfEmptySlice[T any](s []T) []T {
	if len(s) == 0 {
		return nil
	}
	return s
}
