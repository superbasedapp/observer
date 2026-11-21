package policy

import (
	"os"
	"regexp"
	"slices"
	"sort"
	"testing"
)

// guardCatalogTS is the one TypeScript copy of the guard catalog, read by
// the node dashboard's rule editor (web/src/pages/security/RuleEditor.tsx)
// and the org guard form.
const guardCatalogTS = "../../shared/lib/guardCatalog.ts"

var (
	// tsIntegrityFn is the body of isGuardIntegrityRuleId.
	tsIntegrityFn = regexp.MustCompile(`(?s)export function isGuardIntegrityRuleId\(id: string\): boolean \{(.*?)\n\}`)
	// tsRuleID is a quoted rule id inside that body.
	tsRuleID = regexp.MustCompile(`"([A-Z]-\d{3})"`)
	// tsCatalogRow is one GUARD_RULE_CATALOG row's id and decision fields.
	tsCatalogRow = regexp.MustCompile(`\{ id: "([A-Z]-\d{3})", category: "([a-z]+)", severity: "([a-z]+)", observe: "([a-z]+)", enforce: "([a-z]+)"`)
)

// TestIntegritySetTypeScriptMirror pins shared/lib/guardCatalog.ts's
// isGuardIntegrityRuleId to IsIntegrityRuleID (CF1-A1, F-016). The Go side
// is not a second hand-kept list: it is IsIntegrityRuleID asked about every
// built-in rule id, so a rule added to the Go set and missed in the TS copy
// (the R-167 drift CF1's audit found) fails here. Each integrity id must
// also have a TS catalog row whose category, severity and observe/enforce
// pair match the Go rows (stricter of all rows for the id, the reduction
// the TS catalog's header comment names), so the dashboard's escalate-only
// floor for it is the engine's.
func TestIntegritySetTypeScriptMirror(t *testing.T) {
	raw, err := os.ReadFile(guardCatalogTS)
	if err != nil {
		t.Fatalf("read %s: %v", guardCatalogTS, err)
	}
	src := string(raw)

	fn := tsIntegrityFn.FindStringSubmatch(src)
	if fn == nil {
		t.Fatalf("%s: isGuardIntegrityRuleId not found", guardCatalogTS)
	}
	var tsSet []string
	for _, m := range tsRuleID.FindAllStringSubmatch(fn[1], -1) {
		tsSet = append(tsSet, m[1])
	}
	sort.Strings(tsSet)

	goRows := map[string][]RuleInfo{}
	for _, info := range Catalog() {
		if IsIntegrityRuleID(info.ID) {
			goRows[info.ID] = append(goRows[info.ID], info)
		}
	}
	goSet := make([]string, 0, len(goRows))
	for id := range goRows {
		goSet = append(goSet, id)
	}
	sort.Strings(goSet)

	if len(goSet) == 0 {
		t.Fatal("no built-in rule is an integrity rule; the test cannot pin anything")
	}
	if !slices.Equal(tsSet, goSet) {
		t.Fatalf("isGuardIntegrityRuleId in %s = %v, IsIntegrityRuleID over the built-in catalog = %v", guardCatalogTS, tsSet, goSet)
	}

	tsRows := map[string][]string{}
	for _, m := range tsCatalogRow.FindAllStringSubmatch(src, -1) {
		tsRows[m[1]] = m[2:]
	}
	for _, id := range goSet {
		got, ok := tsRows[id]
		if !ok {
			t.Errorf("%s: integrity rule %s has no GUARD_RULE_CATALOG row", guardCatalogTS, id)
			continue
		}
		rows := goRows[id]
		observe, enforce := rows[0].Observe, rows[0].Enforce
		for _, r := range rows[1:] {
			observe = StricterOf(observe, r.Observe)
			enforce = StricterOf(enforce, r.Enforce)
		}
		want := []string{string(rows[0].Category), rows[0].Severity.String(), observe.String(), enforce.String()}
		if !slices.Equal(got, want) {
			t.Errorf("%s: %s catalog row (category, severity, observe, enforce) = %v, Go rows = %v", guardCatalogTS, id, got, want)
		}
	}
}
