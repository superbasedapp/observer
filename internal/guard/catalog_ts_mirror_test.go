//go:build !sbo_omit_security

package guard

import (
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// guardCatalogTS is the one TypeScript copy of the guard catalog: the org
// Guard form's rule select, the grant dialog's picker and the node
// dashboard's rule editor all read it.
const guardCatalogTS = "../../shared/lib/guardCatalog.ts"

// tsCatalogRowRe is one GUARD_RULE_CATALOG row, up to the end of its line.
var tsCatalogRowRe = regexp.MustCompile(`(?m)^\s*\{ id: "([A-Z]-\d{3})", category: "([a-z_]+)", severity: "([a-z]+)", observe: "([a-z]+)", enforce: "([a-z]+)"(.*)$`)

// catalogTSExclusions are the rule ids the node evaluates that the TS
// catalog deliberately leaves out, each with its reason. Empty today: every
// rule a node can evaluate is one an org can name.
var catalogTSExclusions = map[string]string{}

// goRuleStance is the reduction of every Go row for one id.
type goRuleStance struct {
	category, severity string
	observe, enforce   policy.Decision
	pack               bool
}

// TestGuardCatalogTSCoversEveryRule pins shared/lib/guardCatalog.ts to every
// rule a node can evaluate (OrgRuleCatalog: the built-in catalog and the
// full security pillar pack, the vocabulary the org lint checks against). Each id must have a TS row whose category, severity and
// observe/enforce pair equal the Go rows (the stricter of all rows for a
// split id, the reduction mergeLayers seeds its reference with, so the
// escalate-only floor the org form offers is the one publish enforces), or
// sit in catalogTSExclusions with a reason. A pack row must name its module
// and a built-in row must not; a TS row no Go row carries is an orphan.
// Audit CG-2 (29 ids missing) and CG-3 (R-157 enforce ask vs deny).
func TestGuardCatalogTSCoversEveryRule(t *testing.T) {
	raw, err := os.ReadFile(guardCatalogTS)
	if err != nil {
		t.Fatalf("read %s: %v", guardCatalogTS, err)
	}
	ts := map[string][]string{}
	for _, m := range tsCatalogRowRe.FindAllStringSubmatch(string(raw), -1) {
		if _, dup := ts[m[1]]; dup {
			t.Errorf("%s: %s has two GUARD_RULE_CATALOG rows", guardCatalogTS, m[1])
		}
		ts[m[1]] = m[2:]
	}
	if len(ts) < 40 {
		t.Fatalf("%s: parsed only %d catalog rows; the row regexp no longer matches the file", guardCatalogTS, len(ts))
	}

	goRows := map[string]*goRuleStance{}
	add := func(id string, c policy.Category, s policy.Severity, o, e policy.Decision, pack bool) {
		if g := goRows[id]; g != nil {
			g.observe = policy.StricterOf(g.observe, o)
			g.enforce = policy.StricterOf(g.enforce, e)
			return
		}
		goRows[id] = &goRuleStance{category: string(c), severity: s.String(), observe: o, enforce: e, pack: pack}
	}
	packRows := 0
	for _, info := range OrgRuleCatalog() {
		pack := info.Source == policy.SourcePackSecurity
		if pack {
			packRows++
		}
		add(info.ID, info.Category, info.Severity, info.Observe, info.Enforce, pack)
	}
	if packRows == 0 {
		t.Fatal("OrgRuleCatalog carries no security pillar rows")
	}

	ids := make([]string, 0, len(goRows))
	for id := range goRows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		g := goRows[id]
		row, ok := ts[id]
		if reason, excluded := catalogTSExclusions[id]; excluded {
			if ok {
				t.Errorf("%s is excluded (%s) but has a TS row", id, reason)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: rule %s has no GUARD_RULE_CATALOG row (category %s, severity %s, observe %s, enforce %s)",
				guardCatalogTS, id, g.category, g.severity, g.observe, g.enforce)
			continue
		}
		want := []string{g.category, g.severity, g.observe.String(), g.enforce.String()}
		if got := row[:4]; !slices.Equal(got, want) {
			t.Errorf("%s: %s row (category, severity, observe, enforce) = %v, Go rows = %v", guardCatalogTS, id, got, want)
		}
		if hasModule := strings.Contains(row[4], `module: "Code security"`); hasModule != g.pack {
			t.Errorf("%s: %s row names the Code security module = %v, want %v (a pack rule must say it needs the module)", guardCatalogTS, id, hasModule, g.pack)
		}
	}
	for id := range ts {
		if goRows[id] == nil {
			t.Errorf("%s: %s has a GUARD_RULE_CATALOG row but no Go rule carries it", guardCatalogTS, id)
		}
	}
	for id := range catalogTSExclusions {
		if goRows[id] == nil {
			t.Errorf("exclusion %s names no Go rule", id)
		}
	}
}
