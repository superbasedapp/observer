package entitlements

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

// TestCatalogTemplatesAreValid: every row passes the template rules.
func TestCatalogTemplatesAreValid(t *testing.T) {
	t.Parallel()
	for _, b := range Plans() {
		if err := b.CheckTemplate(); err != nil {
			t.Errorf("%s v%d: %v", b.Plan.Name, b.Plan.Version, err)
		}
	}
}

// TestCatalogPlansAreUnique: (name, version) is a key, and a name keeps one
// kind across versions.
func TestCatalogPlansAreUnique(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	kindOf := map[string]Kind{}
	for _, b := range Plans() {
		k := fmt.Sprintf("%s v%d", b.Plan.Name, b.Plan.Version)
		if seen[k] {
			t.Errorf("%s appears twice", k)
		}
		seen[k] = true
		if prev, ok := kindOf[b.Plan.Name]; ok && prev != b.Kind {
			t.Errorf("%s changes kind from %s to %s", b.Plan.Name, prev, b.Kind)
		}
		kindOf[b.Plan.Name] = b.Kind
	}
}

// TestOneFloorPerKind: exactly one floor per kind, and it sets every cap and
// term that applies to its kind (so an absent document cap always falls
// back to a stated value).
func TestOneFloorPerKind(t *testing.T) {
	t.Parallel()
	count := map[Kind]int{}
	for _, d := range planDefs() {
		if d.floor {
			count[d.body.Kind]++
		}
	}
	for _, k := range Kinds() {
		if count[k] != 1 {
			t.Errorf("kind %s has %d floors, want 1", k, count[k])
			continue
		}
		f, ok := Floor(k)
		if !ok {
			t.Fatalf("Floor(%s) missing", k)
		}
		for _, n := range capsFor(k) {
			if _, ok := f.Caps[n]; !ok {
				t.Errorf("floor %s (%s) does not set cap %s", f.Plan.Name, k, n)
			}
		}
		for _, r := range termRules() {
			if slices.Contains(r.kinds, k) {
				if _, ok := f.Terms[r.name]; !ok {
					t.Errorf("floor %s (%s) does not set term %s", f.Plan.Name, k, r.name)
				}
			}
		}
	}
	if _, ok := Floor("no_such_kind"); ok {
		t.Error("Floor of an unknown kind exists")
	}
}

// TestEveryCatalogPlanIsInTheVocabulary: the plan-name lint knows every
// catalog name (this package owns the vocabulary).
func TestEveryCatalogPlanIsInTheVocabulary(t *testing.T) {
	t.Parallel()
	for _, b := range Plans() {
		if got, _ := PlanName(b.Plan.Name); got != b.Plan.Name {
			t.Errorf("catalog plan %s is not in PlanWords", b.Plan.Name)
		}
	}
}

// TestPlanWords: one case per vocabulary row (spelled with spaces and upper
// case), plus a non-word.
func TestPlanWords(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, w := range PlanWords() {
		if seen[w.Word] {
			t.Errorf("%s listed twice", w.Word)
		}
		seen[w.Word] = true
		got, anywhere := PlanName(" " + uppercase(w.Word) + " ")
		if got != w.Word || anywhere != w.Anywhere {
			t.Errorf("PlanName(%s) = %q, %v; want %q, %v", w.Word, got, anywhere, w.Word, w.Anywhere)
		}
	}
	if got, _ := PlanName("teams"); got != "" {
		t.Errorf("PlanName(teams) = %q", got)
	}
}

func uppercase(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c == '_':
			b[i] = ' '
		case c >= 'a' && c <= 'z':
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// TestPlanLookup: a version, the highest version, and a miss.
func TestPlanLookup(t *testing.T) {
	t.Parallel()
	if b, ok := Plan("free", 5); !ok || b.Plan.Version != 5 {
		t.Fatalf("Plan(free, 5) = %+v, %v", b.Plan, ok)
	}
	if b, ok := Plan("team", 0); !ok || b.Plan.Name != "team" {
		t.Fatalf("Plan(team, latest) = %+v, %v", b.Plan, ok)
	}
	if _, ok := Plan("free", 4); ok {
		t.Fatal("free v4 is migration history, not a catalog row")
	}
	if _, ok := Plan("nope", 0); ok {
		t.Fatal("unknown plan found")
	}
	if len(PlansOfKind(KindAccount)) != 2 {
		t.Fatalf("PlansOfKind(account) = %d rows", len(PlansOfKind(KindAccount)))
	}
}

// TestPlansAreFreshCopies: mutating a returned template never reaches the
// catalog (no shared package state).
func TestPlansAreFreshCopies(t *testing.T) {
	t.Parallel()
	b, _ := Plan("business", 1)
	b.Caps[CapSeatsMin] = 999
	b.Capabilities[0] = "mutated"
	again, _ := Plan("business", 1)
	if again.Caps[CapSeatsMin] == 999 || again.Capabilities[0] == "mutated" {
		t.Fatal("a returned template shares state with the catalog")
	}
}

// TestNoCatalogPlanNarrowsItsFloor is the floor property: evaluating any
// catalog plan as a document never yields less than the floor of its kind.
func TestNoCatalogPlanNarrowsItsFloor(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	for _, b := range Plans() {
		doc := mustDoc(t, b, "org-1")
		with := Evaluate(b.Kind, &doc, now)
		floor := Evaluate(b.Kind, nil, now)
		for _, id := range floor.Capabilities() {
			if !with.Has(id) {
				t.Errorf("%s drops floor capability %s", b.Plan.Name, id)
			}
		}
		for _, n := range capsFor(b.Kind) {
			f, w := floor.Cap(n), with.Cap(n)
			if !w.Set || (f.Unlimited && !w.Unlimited) || (!w.Unlimited && w.N < f.N) {
				t.Errorf("%s narrows cap %s: floor %+v, with %+v", b.Plan.Name, n, f, w)
			}
		}
	}
}

// TestComposeIssuesFromTheCatalog: a composed body is issuable, names the
// org and the window, and refuses an unknown plan or a bad org.
func TestComposeIssuesFromTheCatalog(t *testing.T) {
	t.Parallel()
	b, err := Compose("business", 1, "org-42", 100, 100, 200)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if b.Org != "org-42" || b.IssuedAt != 100 || b.NotAfter != 200 || b.Kind != KindTeam {
		t.Fatalf("Compose = %+v", b)
	}
	if _, err := Compose("nope", 1, "org-42", 1, 0, 0); err == nil {
		t.Error("Compose of an unknown plan succeeded")
	}
	if _, err := Compose("team", 1, "", 1, 0, 0); err == nil {
		t.Error("Compose without an org succeeded")
	}
	if _, err := Compose("team", 1, "org-1", 0, 0, 0); err == nil {
		t.Error("Compose without an issue time succeeded")
	}
}

// TestOwnIdPCatalogMapping pins W16-D8's provisional catalog (L-124
// C3.ENTL-gates): Business and every plan above it hold org.own_idp, Team
// and the personal plans do not, and a floor that grants every plan-gated
// capability (the self-hosted community floor) keeps a single-org server
// unchanged. One row per catalog plan; a new plan fails until it is placed.
func TestOwnIdPCatalogMapping(t *testing.T) {
	t.Parallel()
	want := map[string]bool{
		"free":             false,
		"plus_beta":        false,
		"personal_free":    false,
		"personal_pro":     false,
		"team_lapsed":      false,
		"team":             false,
		"business":         true,
		"dedicated_lapsed": false,
		"dedicated":        true,
		"community":        true,
		"self_hosted":      true,
	}
	seen := map[string]bool{}
	for _, b := range Plans() {
		seen[b.Plan.Name] = true
		w, ok := want[b.Plan.Name]
		if !ok {
			t.Errorf("catalog plan %s v%d is not placed in this table: decide whether it holds %s", b.Plan.Name, b.Plan.Version, CapabilityOwnIdP)
			continue
		}
		if got := slices.Contains(b.Capabilities, CapabilityOwnIdP); got != w {
			t.Errorf("%s v%d lists %s = %v, want %v", b.Plan.Name, b.Plan.Version, CapabilityOwnIdP, got, w)
		}
		if err := b.CheckTemplate(); err != nil {
			t.Errorf("%s v%d: %v", b.Plan.Name, b.Plan.Version, err)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("table row %s names no catalog plan", name)
		}
	}
	// The effective entitlement follows the document: a Team document leaves
	// the capability out, a Business one grants it, and the self-hosted
	// floor grants it with no document at all.
	now := time.Unix(1, 0)
	for _, c := range []struct {
		kind Kind
		plan string
		want bool
	}{
		{KindTeam, "", false},
		{KindTeam, "team", false},
		{KindTeam, "business", true},
		{KindPersonal, "personal_pro", false},
		{KindSelfHosted, "", true},
		{KindDedicated, "dedicated", true},
	} {
		var doc *Document
		if c.plan != "" {
			body, err := Compose(c.plan, 0, "org-1", 1, 0, 0)
			if err != nil {
				t.Fatalf("Compose(%s): %v", c.plan, err)
			}
			doc = &Document{Body: body}
		}
		if got := Evaluate(c.kind, doc, now).Has(CapabilityOwnIdP); got != c.want {
			t.Errorf("Evaluate(%s, %q).Has(%s) = %v, want %v", c.kind, c.plan, CapabilityOwnIdP, got, c.want)
		}
	}
}

// TestCurrentCarriesForward: one case per carry rule. A version marked
// carries replaces the one below it for every holder; the walk stops at a
// version that is not marked (Business v2 and v3 move by their price, so a
// Business v1 holder stays on v1); an unknown plan is not found.
func TestCurrentCarriesForward(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		version int
		want    int
		ok      bool
	}{
		{"personal_pro", 1, 3, true},
		{"personal_pro", 2, 3, true},
		{"personal_pro", 3, 3, true},
		{"personal_free", 1, 3, true},
		{"personal_free", 2, 3, true},
		{"team_lapsed", 1, 2, true},
		{"business", 1, 1, true},
		{"business", 2, 2, true},
		{"business", 3, 3, true},
		{"team", 1, 1, true},
		{"personal_pro", 0, 3, true},
		{"personal_pro", 9, 0, false},
		{"nope", 1, 0, false},
	}
	for _, tc := range cases {
		b, ok := Current(tc.name, tc.version)
		if ok != tc.ok || (ok && b.Plan.Version != tc.want) {
			t.Errorf("Current(%s, %d) = v%d, %v; want v%d, %v", tc.name, tc.version, b.Plan.Version, ok, tc.want, tc.ok)
		}
	}
}

// TestCarriedVersionsNeverNarrow: a version that carries its holders
// forward is never less than the version it replaces (every capability
// kept, every cap at least as high, same kind), so moving a holder is
// never a downgrade.
func TestCarriedVersionsNeverNarrow(t *testing.T) {
	t.Parallel()
	for _, d := range planDefs() {
		if !d.carries {
			continue
		}
		prev, ok := Plan(d.body.Plan.Name, d.body.Plan.Version-1)
		if !ok {
			t.Errorf("%s v%d carries, but there is no v%d", d.body.Plan.Name, d.body.Plan.Version, d.body.Plan.Version-1)
			continue
		}
		next := d.body.Normalized()
		if prev.Kind != next.Kind {
			t.Errorf("%s v%d changes kind", next.Plan.Name, next.Plan.Version)
		}
		for _, id := range prev.Capabilities {
			if !slices.Contains(next.Capabilities, id) {
				t.Errorf("%s v%d drops %s", next.Plan.Name, next.Plan.Version, id)
			}
		}
		for n, v := range prev.Caps {
			w, ok := next.Caps[n]
			if !ok || (v == Unlimited && w != Unlimited) || (w != Unlimited && w < v) {
				t.Errorf("%s v%d narrows %s: %d -> %d", next.Plan.Name, next.Plan.Version, n, v, w)
			}
		}
	}
}

// TestGrantingPlans names, per kind, the newest plans that sell the AI Apps
// gateway: what a refusal offers, read from the catalog.
func TestGrantingPlans(t *testing.T) {
	t.Parallel()
	names := func(k Kind) []string {
		var out []string
		for _, b := range GrantingPlans(k, CapabilityPlaneAGateway) {
			out = append(out, fmt.Sprintf("%s:%d", b.Plan.Name, b.Plan.Version))
		}
		return out
	}
	cases := []struct {
		kind Kind
		want []string
	}{
		{KindPersonal, []string{"personal_free:3", "personal_pro:3"}},
		{KindTeam, []string{"business:3"}},
		{KindAccount, nil},
	}
	for _, tc := range cases {
		if got := names(tc.kind); !slices.Equal(got, tc.want) {
			t.Errorf("GrantingPlans(%s) = %v, want %v", tc.kind, got, tc.want)
		}
	}
}

// TestAccountPairs pins L-167: the Plus account plan pairs with Personal Pro
// (its newest version), every pair joins an account plan to a personal one,
// and only the personal kind is reachable through a pair.
func TestAccountPairs(t *testing.T) {
	t.Parallel()
	for _, p := range accountPairs() {
		a, okA := Plan(p.account, 0)
		b, okB := Plan(p.personal, 0)
		if !okA || !okB || a.Kind != KindAccount || b.Kind != KindPersonal {
			t.Errorf("pair %s -> %s: %v/%v kinds %s/%s", p.account, p.personal, okA, okB, a.Kind, b.Kind)
		}
	}
	if b, ok := PairedPersonalPlan("plus_beta"); !ok || b.Plan.Name != "personal_pro" || b.Plan.Version != 3 {
		t.Fatalf("PairedPersonalPlan(plus_beta) = %+v, %v", b.Plan, ok)
	}
	if _, ok := PairedPersonalPlan("free"); ok {
		t.Fatal("the free account plan pairs with a personal plan")
	}
	for _, k := range Kinds() {
		if got, want := AccountPlansPairInto(k), k == KindPersonal; got != want {
			t.Errorf("AccountPlansPairInto(%s) = %v, want %v", k, got, want)
		}
	}
}
