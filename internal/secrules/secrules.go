package secrules

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// PackVersion is the rule pack version the composition records.
const PackVersion = "2026.10.1"

// packRow is one pillar child's slice of the S-7xx range (section 4.7
// item 5) and its constructor.
type packRow struct {
	// component is the catalog id that owns the rows; they are composed
	// only while it is active.
	component string
	// lo and hi bound the rule numbers the row may use.
	lo, hi int
	rules  func() []policy.Rule
}

// packTable is the pillar's rule table, one row per child. Phase A ships
// the table and its validation; the rows' rules are written by the
// phases that own them (B: trust, C: secrets and the commit gate, D1:
// packages, the code phases: code), each adding its component's catalog
// row in the same change.
var packTable = []packRow{
	{component: "security.trust", lo: 701, hi: 719, rules: TrustRules},
	{component: "security.secrets", lo: 721, hi: 739, rules: SecretRules},
	{component: "security.deps", lo: 741, hi: 759, rules: DepsRules},
	{component: "security.code", lo: 761, hi: 789, rules: CodeRules},
	{component: "security", lo: 791, hi: 799, rules: GateRules},
}

// CodeRules are the code, CI and regression rules (S-761 to S-789).
func CodeRules() []policy.Rule { return nil }

// idOwner records the child, category and severity of the first rule
// composed under an id.
type idOwner struct {
	component string
	category  policy.Category
	severity  policy.Severity
}

// Composition is a validated pack, ready for guard.Options.PackRules.
type Composition struct {
	Rules []policy.Rule
	// Components are the children whose rows were composed.
	Components  []string
	PackVersion string
}

// WiredComponentIDs returns every component id the pack table names that
// has at least one rule, for the catalog pin (a misspelt id must fail the
// build, never silently turn a pack on or off).
func WiredComponentIDs() []string {
	var out []string
	for _, r := range packTable {
		if len(r.rules()) > 0 {
			out = append(out, r.component)
		}
	}
	return out
}

// Compose returns the rules of every active child, validated: every id is
// in its child's S-7xx range and appears once, none collides with a
// built-in rule, each row carries Source policy.SourcePackSecurity and a
// pillar category. active is the shared optional-module predicate
// (componentstate.Snapshot.ModuleActive), so an unknown id is inactive.
// Any violation refuses the whole pack: a broken pack is a build defect,
// and guard then runs without it.
func Compose(active func(id string) bool) (Composition, error) {
	return compose(packTable, active)
}

func compose(table []packRow, active func(string) bool) (Composition, error) {
	c := Composition{PackVersion: PackVersion}
	if active == nil {
		return c, nil
	}
	builtin := map[string]bool{}
	for _, info := range policy.Catalog() {
		builtin[info.ID] = true
	}
	seen := map[string]idOwner{}
	for _, row := range table {
		if !active(row.component) {
			continue
		}
		rules := row.rules()
		if len(rules) == 0 {
			continue
		}
		for _, r := range rules {
			if err := validateRule(r, row, builtin); err != nil {
				return Composition{PackVersion: PackVersion}, err
			}
			// One id may carry several variants inside its own child (S-721
			// denies a secret write and asks for one in a fixture path), as
			// the built-in rules do; every variant keeps the first one's
			// category and severity, and no id crosses children.
			if prev, dup := seen[r.ID]; dup && (prev.component != row.component || prev.category != r.Category || prev.severity != r.Severity) {
				return Composition{PackVersion: PackVersion}, fmt.Errorf("secrules.Compose: %s appears twice (%s and %s)", r.ID, prev.component, row.component)
			}
			if _, dup := seen[r.ID]; !dup {
				seen[r.ID] = idOwner{component: row.component, category: r.Category, severity: r.Severity}
			}
			c.Rules = append(c.Rules, inPack(r, row.component))
		}
		c.Components = append(c.Components, row.component)
	}
	sort.Strings(c.Components)
	return c, nil
}

// inPack wraps a composed rule so it fires only while its child is in the
// event's active pack set (Event.Security.Packs, the set signed into the
// project's posture). This is the one place pack membership is enforced:
// the hook composes every pillar row while the module is active, so a
// child that is off must be gated here, not in each rule's matcher. An
// event without Security facts never matches.
func inPack(r policy.Rule, component string) policy.Rule {
	if m := r.Match; m != nil {
		r.Match = func(ctx *policy.MatchContext) (bool, string) {
			if !packActive(ctx, component) {
				return false, ""
			}
			return m(ctx)
		}
	}
	if m := r.MatchCmd; m != nil {
		r.MatchCmd = func(ctx *policy.MatchContext, cmd *policy.Command) (bool, string) {
			if !packActive(ctx, component) {
				return false, ""
			}
			return m(ctx, cmd)
		}
	}
	return r
}

// packActive reports whether component is in the event's active pack set.
func packActive(ctx *policy.MatchContext, component string) bool {
	if ctx == nil || ctx.Event == nil || ctx.Event.Security == nil {
		return false
	}
	return slices.Contains(ctx.Event.Security.Packs, component)
}

// validateRule checks one row against its child's range.
func validateRule(r policy.Rule, row packRow, builtin map[string]bool) error {
	n, ok := ruleNumber(r.ID)
	switch {
	case !ok:
		return fmt.Errorf("secrules.Compose: %q is not an S-7xx id", r.ID)
	case n < row.lo || n > row.hi:
		return fmt.Errorf("secrules.Compose: %s is outside %s's range S-%d to S-%d", r.ID, row.component, row.lo, row.hi)
	case builtin[r.ID]:
		return fmt.Errorf("secrules.Compose: %s collides with a built-in rule", r.ID)
	case r.Source != policy.SourcePackSecurity:
		return fmt.Errorf("secrules.Compose: %s has source %q, want %q", r.ID, r.Source, policy.SourcePackSecurity)
	case r.Category != policy.CategoryCodeSecurity && r.Category != policy.CategorySecrets:
		return fmt.Errorf("secrules.Compose: %s has category %q, want %s or %s", r.ID, r.Category, policy.CategoryCodeSecurity, policy.CategorySecrets)
	case strings.TrimSpace(r.Doc) == "":
		return fmt.Errorf("secrules.Compose: %s has no Doc", r.ID)
	case (r.Match == nil) == (r.MatchCmd == nil):
		return fmt.Errorf("secrules.Compose: %s must set exactly one of Match and MatchCmd", r.ID)
	}
	return nil
}

// ruleNumber parses "S-7NN" into 7NN.
func ruleNumber(id string) (int, bool) {
	rest, ok := strings.CutPrefix(id, "S-")
	if !ok || len(rest) != 3 || !strings.HasPrefix(id, policy.SecurityRuleIDPrefix) {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}
