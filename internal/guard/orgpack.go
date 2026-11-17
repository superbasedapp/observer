package guard

import (
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// orgLintPack is the rule pack the ORG layer is linted against: every
// security pillar row this build carries, with every component on.
//
// An org bundle is authored for a fleet, not for the host that lints it.
// The org server never runs Code security, and a node may have it off
// while its peers have it on, so linting the org layer against the host's
// own (usually empty) pack refused every `[[override]]` on an S-7xx rule
// at publish AND at a node's accept (audit CG-1). Against the full pack an
// override on any rule some node can evaluate gets the same one-way checks
// a built-in gets (a relaxation is still refused), and an id no row of
// this build carries is still refused. A node whose module is off records
// the usual "not loaded" note at engine build and applies the override
// once the module turns on.
//
// The node's engine build does NOT use this: it composes only the active
// components (Options.PackRules, from the cmd layer). This is the static
// authoring vocabulary, the same in every build that carries the security
// component. It is defined in orgpack_security.go (the security pillar's
// feature-owned file, tagged !sbo_omit_security) and orgpack_omit.go (a
// build without the security component, which carries no pack rows and so
// lints the org layer exactly as before CG-1). Keeping the secrules import
// in a tagged file is what lets the security component leave the binary
// with its tag (tests/invariant TestComponentsPackageFence and
// TestComponentsL1PackageAbsence).

// OrgRuleCatalog is every rule a node can evaluate, one summary per table
// row: the built-in catalog (policy.Catalog) and then every row of the full
// security pillar pack. It is the one "all rule ids" list the org side reads
// (the guard exemption's rule facts, the TS catalog mirror test), so a rule
// the node evaluates is never an unknown rule to the org (audit CG-4).
func OrgRuleCatalog() []policy.RuleInfo {
	out := policy.Catalog()
	for _, r := range orgLintPack() {
		source := r.Source
		if source == "" {
			source = policy.SourceBuiltin
		}
		out = append(out, policy.RuleInfo{
			ID: r.ID, Category: r.Category, Severity: r.Severity,
			Observe: r.Observe, Enforce: r.Enforce, Doc: r.Doc,
			Advice: r.Advice, Source: source, Enforced: r.Enforced,
		})
	}
	return out
}
