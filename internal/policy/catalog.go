package policy

// Catalog introspection accessors for the guard composition layer and
// the CLI/doc surfaces (G5 `observer guard rules`, G8 rule-doc
// generation). Read-only summaries — matcher functions never leave
// this package (§17.2: policy internals don't cross the seam).

// RuleInfo is a read-only summary of one rule table row.
type RuleInfo struct {
	// ID is the public catalog ID; multi-row IDs appear once per row.
	ID string
	// Category groups the rule for reporting.
	Category Category
	// Severity is the rule's grade.
	Severity Severity
	// Observe and Enforce are the catalog's mode-decision pair.
	Observe Decision
	// Enforce is the enforce-mode decision.
	Enforce Decision
	// Doc is the catalog one-liner.
	Doc string
	// Advice is the remediation hint the rule carries on its
	// verdicts ("Use --force-with-lease ..."). Empty when the rule
	// defines none.
	Advice string
	// Source is the policy layer the row came from ("builtin" when
	// the rule carries no explicit layer).
	Source string
	// Enforced reports per-rule enforcement (§4.1): the enforce-mode
	// decision applies even in observe mode.
	Enforced bool
	// Overridable reports the org-granted override grant
	// (Rule.Overridable). Always false on an individual node.
	Overridable bool
}

// Catalog returns summaries of the BUILT-IN rule rows in table order.
// The guard layer uses it as the §4.6 layering reference (what
// decision does each rule currently carry, so a lower-trust override
// that would relax it can be rejected); CLI surfaces render it.
func Catalog() []RuleInfo {
	return ruleInfos(builtinRules())
}

// RuleInfos returns summaries of THIS engine's effective rule rows —
// built-ins plus extra layers, with overrides applied and disabled
// rules removed. Powers `observer guard rules --effective`.
func (e *Engine) RuleInfos() []RuleInfo {
	return ruleInfos(e.rules)
}

// ruleInfos maps rule rows to their read-only summaries.
func ruleInfos(rules []Rule) []RuleInfo {
	out := make([]RuleInfo, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		source := r.Source
		if source == "" {
			source = SourceBuiltin
		}
		out = append(out, RuleInfo{
			ID: r.ID, Category: r.Category, Severity: r.Severity,
			Observe: r.Observe, Enforce: r.Enforce, Doc: r.Doc,
			Advice: r.Advice, Source: source, Enforced: r.Enforced,
			Overridable: r.Overridable,
		})
	}
	return out
}

// IsBuiltinRuleID reports whether id names a built-in catalog rule.
// The guard policy loader uses it to reject user [[rule]] entries that
// collide with built-in IDs (overrides are the way to tune built-ins).
func IsBuiltinRuleID(id string) bool {
	for _, r := range builtinRules() {
		if r.ID == id {
			return true
		}
	}
	return false
}

// SensitiveResolvedPath reports whether an already-resolved path (a
// MatchContext.Path value) falls in the R-152 sensitive set, returning
// the human-readable description on a hit. Exported for the user-rule
// `path_sensitive` matcher (§4.4) so the sensitive vocabulary stays in
// ONE place (rules_boundary.go's table).
func SensitiveResolvedPath(path, home string) (string, bool) {
	if path == "" {
		return "", false
	}
	return pathPatternMatch(path, home, sensitivePathPatterns)
}

// MatchAnyPathGlob reports whether the resolved path matches any of
// the gitignore-style glob patterns ("~/"-anchored and absolute forms,
// `**` segments — the same semantics the built-in path tables use),
// returning the matching pattern. Exported for the user-rule
// `path_glob` / `path_not` matchers (§4.4) so user globs behave
// byte-identically to built-in ones.
func MatchAnyPathGlob(patterns []string, path, home string) (string, bool) {
	if path == "" || len(patterns) == 0 {
		return "", false
	}
	pats := make([]pathPattern, 0, len(patterns))
	for _, g := range patterns {
		pats = append(pats, pathPattern{glob: g, desc: g})
	}
	return pathPatternMatch(path, home, pats)
}

// OutsideProjectPath reports whether the event's resolved path lies
// outside its project root, IGNORING read/write direction (the
// user-rule `path_outside_project` matcher — direction is the rule
// author's job via applies_to / action choice). Unknown (unresolved
// path, missing root, cross-flavor) is never a hit — the R-150
// convention.
func OutsideProjectPath(ctx *MatchContext) (bool, string) {
	p, pr := ctx.Path, ctx.Event.ProjectRoot
	if p == "" || pr == "" || !comparableFlavors(p, pr) || isUnder(p, pr) {
		return false, ""
	}
	return true, "path " + ctx.Event.Target + " is outside the project root"
}

// OutsideProjectWrite reports whether the event is a WRITE landing
// outside its project root (the user-rule `sink =
// "out_of_project_write"` condition). desc is the hit description.
func OutsideProjectWrite(ctx *MatchContext, desc string) (bool, string) {
	hit, _ := matchOutsideProject(true)(ctx)
	if !hit {
		return false, ""
	}
	return true, desc
}
