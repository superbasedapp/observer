package secassess

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func thr(id, title, cat string, el Element, l, i int) Threat {
	r := Rating{Likelihood: l, Impact: i}
	return Threat{ID: id, Title: title, Framework: FrameworkSTRIDE, Category: cat, Element: el, Rating: r, Band: BandOf(r), Score: r.Score()}
}

var (
	elAPI = Element{Kind: "component", ID: "api"}
	elDB  = Element{Kind: "component", ID: "db"}
)

func tmOf(ts ...Threat) *ThreatModelDoc { return &ThreatModelDoc{Threats: ts} }

// tmSys is a model whose system names one component per (id, name) pair, so a
// threat's element resolves to a name.
func tmSys(comps map[string]string, ts ...Threat) *ThreatModelDoc {
	doc := &ThreatModelDoc{Threats: ts}
	ids := make([]string, 0, len(comps))
	for id := range comps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		doc.System.Components = append(doc.System.Components, Component{ID: id, Name: comps[id], Type: "service"})
	}
	return doc
}

func elComp(id string) Element { return Element{Kind: "component", ID: id} }

func itemIDs(items []DiffItem) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.ID)
	}
	return out
}

func TestDiffModels(t *testing.T) {
	cases := []struct {
		name                     string
		prev, cur                *ThreatModelDoc
		added, removed           []string
		changed                  int
		unchanged, byID, byTitle int
	}{
		{
			"identical", tmOf(thr("T-1", "SQL injection", "tampering", elAPI, 4, 4), thr("T-2", "Leaked token", "information_disclosure", elAPI, 3, 4)),
			tmOf(thr("T-1", "SQL injection", "tampering", elAPI, 4, 4), thr("T-2", "Leaked token", "information_disclosure", elAPI, 3, 4)),
			nil, nil, 0, 2, 2, 0,
		},
		{
			"three of five the same",
			tmOf(thr("T-1", "A one", "tampering", elAPI, 4, 4), thr("T-2", "B two", "spoofing", elAPI, 4, 4), thr("T-3", "C three", "repudiation", elDB, 2, 2), thr("T-4", "D four", "tampering", elDB, 3, 3), thr("T-5", "E five", "spoofing", elDB, 1, 1)),
			tmOf(thr("T-1", "A one", "tampering", elAPI, 4, 4), thr("T-2", "B two", "spoofing", elAPI, 4, 4), thr("T-3", "C three", "repudiation", elDB, 2, 2), thr("T-9", "F six", "tampering", elAPI, 5, 5), thr("T-10", "G seven", "spoofing", elAPI, 2, 2)),
			[]string{"T-9", "T-10"},
			[]string{"T-4", "T-5"},
			0, 3, 3, 0,
		},
		{
			"band delta is a change",
			tmOf(thr("T-1", "A one", "tampering", elAPI, 2, 2)),
			tmOf(thr("T-1", "A one", "tampering", elAPI, 5, 5)),
			nil, nil, 1, 0, 1, 0,
		},
		{
			"same id, other element: not matched by id",
			tmOf(thr("T-1", "A one", "tampering", elAPI, 3, 3)),
			tmOf(thr("T-1", "Something else", "tampering", elDB, 3, 3)),
			[]string{"T-1"},
			[]string{"T-1"},
			0, 0, 0, 0,
		},
		{
			"same id, other category: not matched by id",
			tmOf(thr("T-1", "A one", "tampering", elAPI, 3, 3)),
			tmOf(thr("T-1", "A one", "spoofing", elAPI, 3, 3)),
			[]string{"T-1"},
			[]string{"T-1"},
			0, 0, 0, 0,
		},
		{
			"renumbered ids match by title",
			tmOf(thr("T-1", "SQL injection in search", "tampering", elAPI, 4, 4), thr("T-2", "Weak session cookie", "spoofing", elAPI, 3, 3)),
			tmOf(thr("X-7", "sql injection  in SEARCH!", "tampering", elAPI, 4, 4), thr("X-8", "Weak session cookie", "spoofing", elAPI, 3, 3)),
			nil, nil, 0, 2, 0, 2,
		},
		{
			"renamed title with the same id is a change, not an add",
			tmOf(thr("T-1", "A one", "tampering", elAPI, 4, 4)),
			tmOf(thr("T-1", "A one, reworded", "tampering", elAPI, 4, 4)),
			nil, nil, 1, 0, 1, 0,
		},
		{
			"renamed and renumbered shows as removed plus added",
			tmOf(thr("T-1", "A one", "tampering", elAPI, 4, 4)),
			tmOf(thr("Q-1", "Entirely different words", "tampering", elAPI, 4, 4)),
			[]string{"Q-1"},
			[]string{"T-1"},
			0, 0, 0, 0,
		},
		{
			"previous copy missing: everything is added", nil,
			tmOf(thr("T-1", "A one", "tampering", elAPI, 4, 4)),
			[]string{"T-1"},
			nil, 0, 0, 0, 0,
		},
		{
			"new model missing: everything is removed",
			tmOf(thr("T-1", "A one", "tampering", elAPI, 4, 4)), nil,
			nil,
			[]string{"T-1"},
			0, 0, 0, 0,
		},
		{"both missing", nil, nil, nil, nil, 0, 0, 0, 0},
		{
			"duplicate ids in the earlier model pair once",
			tmOf(thr("T-1", "A one", "tampering", elAPI, 4, 4), thr("T-1", "A one", "tampering", elAPI, 4, 4)),
			tmOf(thr("T-1", "A one", "tampering", elAPI, 4, 4)),
			nil,
			[]string{"T-1"},
			0, 1, 1, 0,
		},
		{
			// The reviewer's first probe: two threats of one element and
			// category, numbered the other way round in the second run, with
			// the same titles. Nothing changed, so nothing may be reported.
			"ids swapped between two threats of one cell with the same titles",
			tmOf(thr("T1", "Forged login form", "spoofing", elAPI, 2, 2), thr("T2", "Stolen session cookie", "spoofing", elAPI, 5, 5)),
			tmOf(thr("T2", "Forged login form", "spoofing", elAPI, 2, 2), thr("T1", "Stolen session cookie", "spoofing", elAPI, 5, 5)),
			nil, nil, 0, 2, 0, 2,
		},
		{
			// The reviewer's second probe: the same threat, the component's id
			// chosen afresh by the agent, its name the same.
			"a component renumbered between runs is the same element",
			tmSys(map[string]string{"c1": "API"}, thr("T-1", "Forged login form", "spoofing", elComp("c1"), 3, 3)),
			tmSys(map[string]string{"comp-api": "api"}, thr("T-1", "Forged login form", "spoofing", elComp("comp-api"), 3, 3)),
			nil, nil, 0, 1, 1, 0,
		},
		{
			"a renumbered component and a renumbered threat still match by title",
			tmSys(map[string]string{"c1": "API"}, thr("T-1", "Forged login form", "spoofing", elComp("c1"), 3, 3)),
			tmSys(map[string]string{"comp-api": "API"}, thr("X-5", "forged login FORM", "spoofing", elComp("comp-api"), 3, 3)),
			nil, nil, 0, 1, 0, 1,
		},
		{
			"a re-worded threat under a renumbered component matches by id",
			tmSys(map[string]string{"c1": "API"}, thr("T-1", "Forged login form", "spoofing", elComp("c1"), 3, 3)),
			tmSys(map[string]string{"comp-api": "API"}, thr("T-1", "Login forgery", "spoofing", elComp("comp-api"), 3, 3)),
			nil, nil, 1, 0, 1, 0,
		},
		{
			// A component id reused for another component is another element.
			"the same component id for a different component is not the same element",
			tmSys(map[string]string{"c1": "API"}, thr("T-1", "Forged login form", "spoofing", elComp("c1"), 3, 3)),
			tmSys(map[string]string{"c1": "Billing"}, thr("T-1", "Forged login form", "spoofing", elComp("c1"), 3, 3)),
			[]string{"T-1"},
			[]string{"T-1"},
			0, 0, 0, 0,
		},
		{
			// Names are compared only when both models give some; a model with
			// no system (an older or hand-made copy) leaves the ids to compare.
			"one model without a system: the ids are compared",
			tmOf(thr("T-1", "Forged login form", "spoofing", elComp("api"), 3, 3)),
			tmSys(map[string]string{"api": "API"}, thr("T-1", "Forged login form", "spoofing", elComp("api"), 3, 3)),
			nil, nil, 0, 1, 1, 0,
		},
		{
			"one model without a system and another id: not the same element",
			tmOf(thr("T-1", "Forged login form", "spoofing", elComp("api"), 3, 3)),
			tmSys(map[string]string{"comp-api": "API"}, thr("T-1", "Forged login form", "spoofing", elComp("comp-api"), 3, 3)),
			[]string{"T-1"},
			[]string{"T-1"},
			0, 0, 0, 0,
		},
		{
			"an id that names nothing in the system keeps its id as its name",
			tmSys(map[string]string{"c1": "API"}, thr("T-1", "A one", "spoofing", elComp("gone"), 3, 3)),
			tmSys(map[string]string{"c1": "API"}, thr("T-1", "A one", "spoofing", elComp("gone"), 3, 3)),
			nil, nil, 0, 1, 1, 0,
		},
		{
			// Two threats a diff cannot tell apart pair by their own ids first.
			"two threats of one title swap their order: they pair by id",
			tmOf(thr("T-1", "Same words", "spoofing", elAPI, 2, 2), thr("T-2", "Same words", "spoofing", elAPI, 5, 5)),
			tmOf(thr("T-2", "Same words", "spoofing", elAPI, 5, 5), thr("T-1", "Same words", "spoofing", elAPI, 2, 2)),
			nil, nil, 0, 2, 2, 0,
		},
		{
			"two threats of one title with ids that match nothing pair in order",
			tmOf(thr("T-1", "Same words", "spoofing", elAPI, 2, 2), thr("T-2", "Same words", "spoofing", elAPI, 2, 2)),
			tmOf(thr("Q-8", "Same words", "spoofing", elAPI, 2, 2), thr("Q-9", "Same words", "spoofing", elAPI, 2, 2)),
			nil, nil, 0, 2, 0, 2,
		},
		{
			"a threat matched by title is never then matched again by id",
			tmOf(thr("T-1", "A one", "spoofing", elAPI, 2, 2), thr("T-2", "B two", "spoofing", elAPI, 2, 2)),
			tmOf(thr("T-2", "A one", "spoofing", elAPI, 2, 2), thr("T-3", "C three", "spoofing", elAPI, 2, 2)),
			[]string{"T-3"},
			[]string{"T-2"},
			0, 1, 0, 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := DiffModels(tc.prev, tc.cur)
			if got := itemIDs(d.Added); !reflect.DeepEqual(got, tc.added) {
				t.Errorf("added %v, want %v", got, tc.added)
			}
			if got := itemIDs(d.Removed); !reflect.DeepEqual(got, tc.removed) {
				t.Errorf("removed %v, want %v", got, tc.removed)
			}
			if len(d.Changed) != tc.changed {
				t.Errorf("changed %d, want %d: %+v", len(d.Changed), tc.changed, d.Changed)
			}
			if d.Unchanged != tc.unchanged || d.MatchedByID != tc.byID || d.MatchedByTitle != tc.byTitle {
				t.Errorf("unchanged %d byID %d byTitle %d, want %d %d %d", d.Unchanged, d.MatchedByID, d.MatchedByTitle, tc.unchanged, tc.byID, tc.byTitle)
			}
			if d.Note != DiffNote || !strings.Contains(d.Note, "renamed") {
				t.Error("the diff does not carry its limit note")
			}
		})
	}
}

func TestDiffModelsChangeDetail(t *testing.T) {
	p := thr("T-1", "A one", "tampering", elAPI, 2, 2)
	p.Status = "identified"
	p.Missing = []Missing{{Text: "x"}}
	c := thr("T-1", "A one", "tampering", elAPI, 5, 5)
	c.Status = "partial"
	c.Missing = []Missing{{Text: "x"}, {Text: "y"}}
	c.Existing = []Mitigation{{Text: "z"}}
	d := DiffModels(tmOf(p), tmOf(c))
	if len(d.Changed) != 1 {
		t.Fatalf("changed: %+v", d.Changed)
	}
	ch := d.Changed[0]
	if ch.FromBand != BandLow || ch.ToBand != BandCritical || ch.FromScore != 4 || ch.ToScore != 25 {
		t.Errorf("band delta: %+v", ch)
	}
	if ch.FromStatus != "identified" || ch.ToStatus != "partial" || ch.MissingFrom != 1 || ch.MissingTo != 2 || ch.ExistingFrom != 0 || ch.ExistingTo != 1 {
		t.Errorf("detail: %+v", ch)
	}
	if ch.Match != MatchByID || ch.TitleChanged {
		t.Errorf("match: %+v", ch)
	}
}

func TestDiffModelsOrder(t *testing.T) {
	cur := tmOf(thr("a", "one", "tampering", elAPI, 1, 1), thr("b", "two", "spoofing", elAPI, 5, 5), thr("c", "three", "spoofing", elDB, 5, 5))
	d := DiffModels(nil, cur)
	if got := itemIDs(d.Added); !reflect.DeepEqual(got, []string{"b", "c", "a"}) {
		t.Errorf("added order %v: highest score first, then id", got)
	}
	if !reflect.DeepEqual(d, DiffModels(nil, cur)) {
		t.Error("the diff is not deterministic")
	}
}

func TestDiffSystem(t *testing.T) {
	mk := func(comps []Component, flows []Flow, zones ...string) *ThreatModelDoc {
		doc := &ThreatModelDoc{System: System{Components: comps, Flows: flows, Actors: []Actor{{ID: "u", Name: "User", Kind: "end_user"}}}}
		for _, z := range zones {
			doc.System.Zones = append(doc.System.Zones, Zone{ID: z, Name: z})
		}
		return doc
	}
	prev := mk([]Component{{ID: "c1", Name: "API", Type: "service"}, {ID: "c2", Name: "Cache", Type: "datastore"}},
		[]Flow{{ID: "f1", From: "u", To: "c1"}}, "dmz")
	cur := mk([]Component{{ID: "x9", Name: "api", Type: "service"}, {ID: "x8", Name: "Queue", Type: "service"}},
		[]Flow{{ID: "g1", From: "u", To: "x9"}, {ID: "g2", From: "x9", To: "x8"}}, "dmz", "internal")
	d := DiffModels(prev, cur).System
	if !reflect.DeepEqual(d.Components, NameDiff{Added: []string{"Queue"}, Removed: []string{"Cache"}}) {
		t.Errorf("components %+v (renumbered ids and a case change are not change)", d.Components)
	}
	if !reflect.DeepEqual(d.Zones, NameDiff{Added: []string{"internal"}}) {
		t.Errorf("zones %+v", d.Zones)
	}
	if !reflect.DeepEqual(d.Flows, NameDiff{Added: []string{"api to Queue"}}) {
		t.Errorf("flows %+v", d.Flows)
	}
}

func TestDiffEmpty(t *testing.T) {
	m := tmOf(thr("T-1", "A one", "tampering", elAPI, 4, 4))
	if !DiffModels(m, m).Empty() {
		t.Error("a model compared with itself is not empty")
	}
	if DiffModels(nil, m).Empty() {
		t.Error("an added threat reads as empty")
	}
}

// TestDiffElementNameRows holds the name table: one row per element kind of the
// closed list, and a name that is the same in two runs whatever the ids.
func TestDiffElementNameRows(t *testing.T) {
	sys := func(prefix string) System {
		return System{
			Components:  []Component{{ID: prefix + "c", Name: "API Gateway", Type: "service"}},
			Actors:      []Actor{{ID: prefix + "a", Name: "Customer", Kind: "end_user"}},
			Assets:      []Asset{{ID: prefix + "s", Name: "Card numbers", Sensitivity: "restricted"}},
			Flows:       []Flow{{ID: prefix + "f", From: prefix + "a", To: prefix + "c"}},
			EntryPoints: []EntryPoint{{ID: prefix + "e", Component: prefix + "c", Kind: "http_route"}},
		}
	}
	one, two := newNameIndex(sys("x-")), newNameIndex(sys("y-"))
	for _, tc := range []struct{ kind, suffix, wantName string }{
		{"component", "c", "api gateway"},
		{"actor", "a", "customer"},
		{"asset", "s", "card numbers"},
		{"flow", "f", "customer to api gateway"},
		{"entry_point", "e", "api gateway http route"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			a, b := one.elementKey(Element{Kind: tc.kind, ID: "x-" + tc.suffix}, true), two.elementKey(Element{Kind: tc.kind, ID: "y-" + tc.suffix}, true)
			if a != b {
				t.Errorf("the same element under two id schemes reads %q and %q", a, b)
			}
			if !strings.Contains(a, "n:"+tc.wantName) {
				t.Errorf("key %q does not carry the name %q", a, tc.wantName)
			}
		})
	}
	// Every kind of the closed list has a row.
	have := map[string]bool{}
	for _, r := range elementNameRows {
		have[r.kind] = true
	}
	for _, k := range EnumElementKind {
		if !have[k] {
			t.Errorf("element kind %q has no name row", k)
		}
	}
	// An id nothing in the system names is its own name, and never equals a name.
	if got := one.elementKey(Element{Kind: "component", ID: "gone"}, true); got != "component\x00i:gone" {
		t.Errorf("unresolved key %q", got)
	}
	if one.elementKey(Element{Kind: "component", ID: "api gateway"}, true) == one.elementKey(Element{Kind: "component", ID: "x-c"}, true) {
		t.Error("an id that spells a name must not equal the element that has the name")
	}
}

// TestDiffPassesAreOrdered: the strongest evidence first, one row each.
func TestDiffPassesAreOrdered(t *testing.T) {
	if len(diffPasses) != 4 {
		t.Fatalf("%d passes", len(diffPasses))
	}
	// The scored pass (row 3) sits above the id-only row: an id is the order the
	// agent wrote its threats in, a cited place says what a threat is about.
	want := []string{MatchByID, MatchByTitle, MatchBySimilarity, MatchByID}
	for i, p := range diffPasses {
		if p.match != want[i] || p.scored != (want[i] == MatchBySimilarity) || (p.key == nil) != p.scored {
			t.Errorf("pass %d: match %q scored %v key %v, want %q", i, p.match, p.scored, p.key != nil, want[i])
		}
	}
	// Row 1 is stricter than row 2 and row 2 is the title evidence: for a
	// threat both keys differ from the id-only key of row 4.
	th := thr("T-1", "A one", "spoofing", elAPI, 3, 3)
	k0, k1, k2 := diffPasses[0].key(th, "e"), diffPasses[1].key(th, "e"), diffPasses[3].key(th, "e")
	if k0 == k1 || k1 == k2 || !strings.HasPrefix(k0, k1) {
		t.Errorf("keys %q %q %q", k0, k1, k2)
	}
}

// TestPromptInputCarriesNothingFromAnEarlierRun (review W3-9, D24): nothing from
// an earlier run reaches the agent through the prompt, because PromptInput has no
// field that could carry it: not an earlier run's id, its model or the
// comparison with it. The comparison is made by Observer after the new model is
// checked and kept with the new copy. Adding such a field must fail this test,
// so it is a decision somebody makes and justifies, never an accident.
func TestPromptInputCarriesNothingFromAnEarlierRun(t *testing.T) {
	banned := []string{"previous", "earlier", "prior", "diff", "compare", "compared", "last_run", "lastrun", "history"}
	modelTypes := map[reflect.Type]string{
		reflect.TypeOf(ThreatModelDoc{}): "ThreatModelDoc",
		reflect.TypeOf(ModelDiff{}):      "ModelDiff",
		reflect.TypeOf(Result{}):         "Result",
		reflect.TypeOf(Threat{}):         "Threat",
	}
	var carries func(typ reflect.Type) string
	carries = func(typ reflect.Type) string {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		return modelTypes[typ]
	}
	typ := reflect.TypeOf(PromptInput{})
	if typ.NumField() < 10 {
		t.Fatalf("PromptInput has %d fields: the reflection is not reading it", typ.NumField())
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.ToLower(f.Name)
		for _, b := range banned {
			if strings.Contains(name, b) {
				t.Errorf("PromptInput.%s: a field that could carry an earlier run (%q). An earlier model must never reach the agent (D24); justify the field in the plan before adding it", f.Name, b)
			}
		}
		if mt := carries(f.Type); mt != "" {
			t.Errorf("PromptInput.%s has type %s, which carries a model; an earlier run's model must not reach the prompt (D24)", f.Name, mt)
		}
	}
}
