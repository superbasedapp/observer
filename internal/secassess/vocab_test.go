package secassess

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestStrideTable(t *testing.T) {
	letters := map[string]bool{}
	for _, c := range StrideCategories {
		if c.ID == "" || c.Letter == "" || c.Name == "" || c.Question == "" {
			t.Errorf("incomplete row %+v", c)
		}
		if letters[c.Letter] {
			t.Errorf("duplicate letter %s", c.Letter)
		}
		letters[c.Letter] = true
		got, ok := StrideCategoryByID(c.ID)
		if !ok || got != c {
			t.Errorf("lookup of %s: %+v", c.ID, got)
		}
	}
	if len(StrideCategories) != 6 || strings.Join(keysOf(letters), "") != "DEIRST" {
		t.Fatalf("STRIDE must have the six letters, has %v", keysOf(letters))
	}
	if _, ok := StrideCategoryByID("nope"); ok {
		t.Fatal("unknown category found")
	}
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestApplicableStride(t *testing.T) {
	cases := []struct {
		class DFDClass
		logs  bool
		want  string
	}{
		{ClassExternalEntity, false, "spoofing,repudiation"},
		{ClassProcess, false, "spoofing,tampering,repudiation,information_disclosure,denial_of_service,elevation_of_privilege"},
		{ClassDataStore, false, "tampering,information_disclosure,denial_of_service"},
		{ClassDataStore, true, "tampering,repudiation,information_disclosure,denial_of_service"},
		{ClassDataFlow, false, "tampering,information_disclosure,denial_of_service"},
		{ClassDataFlow, true, "tampering,information_disclosure,denial_of_service"},
		{ClassProcess, true, "spoofing,tampering,repudiation,information_disclosure,denial_of_service,elevation_of_privilege"},
		{"nonsense", false, ""},
	}
	for _, c := range cases {
		if got := strings.Join(ApplicableStride(c.class, c.logs), ","); got != c.want {
			t.Errorf("%s logs=%v: %s, want %s", c.class, c.logs, got, c.want)
		}
	}
	// Every cell of the chart names a real category.
	for class, ids := range strideChart {
		for _, id := range ids {
			if _, ok := StrideCategoryByID(id); !ok {
				t.Errorf("chart cell %s/%s names no category", class, id)
			}
		}
	}
}

func TestComponentTypes(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range ComponentTypes {
		if c.ID == "" || c.Name == "" || seen[c.ID] {
			t.Errorf("bad or duplicate row %+v", c)
		}
		seen[c.ID] = true
		if _, ok := strideChart[c.Class]; !ok {
			t.Errorf("%s: class %s is not in the chart", c.ID, c.Class)
		}
		if c.HoldsLogs && c.Class != ClassDataStore {
			t.Errorf("%s: only a data store holds logs", c.ID)
		}
		if got, ok := ComponentTypeByID(c.ID); !ok || got != c {
			t.Errorf("lookup of %s", c.ID)
		}
	}
	if _, ok := ComponentTypeByID("nope"); ok {
		t.Fatal("unknown type found")
	}
}

func TestLinddunTable(t *testing.T) {
	if len(LinddunCategories) != 7 {
		t.Fatalf("%d categories", len(LinddunCategories))
	}
	seen := map[string]bool{}
	for _, c := range LinddunCategories {
		if c.ID == "" || c.Name == "" || c.Question == "" || seen[c.ID] {
			t.Errorf("bad or duplicate row %+v", c)
		}
		seen[c.ID] = true
		if got, ok := LinddunCategoryByID(c.ID); !ok || got != c {
			t.Errorf("lookup of %s", c.ID)
		}
		if _, ok := StrideCategoryByID(c.ID); ok {
			t.Errorf("%s is also a STRIDE id", c.ID)
		}
	}
}

func TestWSTGTable(t *testing.T) {
	want := "INFO CONF IDNT ATHN ATHZ SESS INPV ERRH CRYP BUSL CLNT APIT"
	var ids []string
	facts := map[string]bool{}
	for _, f := range GroundingFacts {
		facts[f] = true
	}
	for _, c := range WSTGCategories {
		ids = append(ids, c.ID)
		if len(c.ID) != 4 || c.Title == "" || c.Intent == "" || len(c.CWEFamilies) == 0 {
			t.Errorf("incomplete row %+v", c)
		}
		if !facts[c.AppliesWhen] {
			t.Errorf("%s: fact %q is not in the closed list", c.ID, c.AppliesWhen)
		}
		seen := map[string]bool{}
		for _, w := range c.CWEFamilies {
			if !ValidCWE(w) || seen[w] {
				t.Errorf("%s: bad or duplicate CWE %q", c.ID, w)
			}
			seen[w] = true
		}
		if got, ok := WSTGCategoryByID(c.ID); !ok || !reflect.DeepEqual(got, c) {
			t.Errorf("lookup of %s", c.ID)
		}
		if !isWSTG(c.ID) {
			t.Errorf("isWSTG(%s)", c.ID)
		}
	}
	if got := strings.Join(ids, " "); got != want {
		t.Fatalf("categories = %s", got)
	}
	if isWSTG("ZZZZ") || isWSTG("") {
		t.Fatal("isWSTG accepts an unknown id")
	}
}

func TestPTESPhases(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range PTESPhases {
		if p.ID == "" || p.Name == "" || p.Bound == "" || seen[p.ID] {
			t.Errorf("bad or duplicate phase %+v", p)
		}
		seen[p.ID] = true
	}
	if len(PTESPhases) != 7 || PTESPhases[5].ID != "post_exploitation" || !strings.Contains(PTESPhases[5].Bound, "Stay inside") {
		t.Fatalf("phases = %+v", PTESPhases)
	}
}

func TestStandardIDShapes(t *testing.T) {
	cases := []struct {
		fn   func(string) bool
		in   string
		want bool
	}{
		{ValidCWE, "CWE-89", true},
		{ValidCWE, "CWE-12345", true},
		{ValidCWE, "CWE-123456", false},
		{ValidCWE, "CWE-0", false},
		{ValidCWE, "CWE-089", false},
		{ValidCWE, "cwe-89", false},
		{ValidCWE, "CWE-", false},
		{ValidCWE, "CWE-8a", false},
		{ValidCWE, "", false},
		{ValidCAPEC, "CAPEC-66", true},
		{ValidCAPEC, "CAPEC-1000", true},
		{ValidCAPEC, "CAPEC-10000", false},
		{ValidCAPEC, "CAPEC-0", false},
		{ValidCAPEC, "CAPEC", false},
		{ValidASVS, "V2.1.1", true},
		{ValidASVS, "V14.2.10", true},
		{ValidASVS, "V2.1", false},
		{ValidASVS, "V2.1.1.1", false},
		{ValidASVS, "V200.1.1", false},
		{ValidASVS, "2.1.1", false},
		{ValidASVS, "V2..1", false},
		{ValidASVS, "V", false},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("%q: %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAIFrameworks(t *testing.T) {
	for _, f := range AIFrameworks {
		if f.ID == "" || f.Name == "" || f.SecframeworkID == "" || f.IDPrefix == "" {
			t.Errorf("incomplete row %+v", f)
		}
		if got, ok := AIFrameworkByID(f.ID); !ok || got != f {
			t.Errorf("lookup of %s", f.ID)
		}
	}
	cases := []struct {
		fw, cat string
		want    bool
	}{
		{FrameworkOWASPLLM, "LLM01", true},
		{FrameworkOWASPLLM, "LLM10", true},
		{FrameworkOWASPLLM, "LLM00", false},
		{FrameworkOWASPLLM, "LLM11", false},
		{FrameworkOWASPLLM, "ASI01", false},
		{FrameworkOWASPAgentic, "ASI04", true},
		{FrameworkOWASPAgentic, "ASI4", false},
		{FrameworkOWASPAgentic, "ASIxx", false},
		{"nope", "LLM01", false},
		{FrameworkOWASPLLM, "", false},
	}
	for _, c := range cases {
		if got := ValidAICategory(c.fw, c.cat); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.fw, c.cat, got, c.want)
		}
	}
}

func TestFrameworkOfCategory(t *testing.T) {
	cases := map[string]string{
		"spoofing": FrameworkSTRIDE, "elevation_of_privilege": FrameworkSTRIDE, "linkability": FrameworkLINDDUN,
		"non_compliance": FrameworkLINDDUN, "LLM03": FrameworkOWASPLLM, "ASI05": FrameworkOWASPAgentic, "chaos": "", "": "",
	}
	for cat, want := range cases {
		if got := frameworkOfCategory(cat); got != want {
			t.Errorf("%q: %q, want %q", cat, got, want)
		}
	}
	// The ids of the four frameworks never overlap, so a no_threat row's
	// category names exactly one framework.
	for _, s := range StrideCategories {
		if _, clash := LinddunCategoryByID(s.ID); clash {
			t.Errorf("%s is in both STRIDE and LINDDUN", s.ID)
		}
	}
}

func TestEnums(t *testing.T) {
	enums := map[string]Enum{
		"sensitivity": EnumSensitivity, "actor": EnumActorKind, "entry": EnumEntryKind, "authn": EnumAuthn, "exposure": EnumExposure,
		"encrypted": EnumEncrypted, "threat state": EnumThreatState, "effort": EnumEffort, "element": EnumElementKind, "op": EnumTreeOp,
		"coverage": EnumCoverageStatus, "basis": EnumBasis, "finding state": EnumFindingState,
	}
	for name, e := range enums {
		seen := map[string]bool{}
		if len(e) == 0 {
			t.Errorf("%s is empty", name)
		}
		for _, v := range e {
			if v == "" || seen[v] {
				t.Errorf("%s: bad or duplicate %q", name, v)
			}
			seen[v] = true
			if !e.Has(v) {
				t.Errorf("%s: Has(%q)", name, v)
			}
		}
		if e.Has("") || e.Has("zzz") {
			t.Errorf("%s accepts an unknown word", name)
		}
	}
}

func TestBands(t *testing.T) {
	// Every likelihood and impact pair, against the written boundaries.
	for l := 1; l <= 5; l++ {
		for i := 1; i <= 5; i++ {
			s := l * i
			want := BandCritical
			switch {
			case s <= 6:
				want = BandLow
			case s <= 12:
				want = BandMedium
			case s <= 19:
				want = BandHigh
			}
			if got := BandOf(Rating{l, i}); got != want {
				t.Errorf("%dx%d=%d: %s, want %s", l, i, s, got, want)
			}
		}
	}
	for _, r := range []Rating{{0, 3}, {3, 0}, {6, 1}, {1, 6}, {-1, 2}, {}} {
		if BandOf(r) != "" || r.Score() != 0 || ValidRating(r) {
			t.Errorf("%+v is accepted", r)
		}
	}
	if BandRank(BandLow) != 1 || BandRank(BandCritical) != 4 || BandRank("") != 0 || BandRank("x") != 0 {
		t.Fatal("BandRank")
	}
	for i := 1; i < len(Bands); i++ {
		if BandRank(Bands[i]) <= BandRank(Bands[i-1]) {
			t.Fatal("Bands are not ordered")
		}
	}
}

func TestPresets(t *testing.T) {
	cases := []struct {
		name    string
		list    []Preset
		valid   func(string) bool
		must    string // a preset that must hold every valid member
		mustAll int
	}{
		{"frameworks", FrameworkPresets, func(s string) bool { return frameworkEnum.Has(s) }, "all", 4},
		{"extras", MethodExtraPresets, func(s string) bool { return s == ExtraAbuseCases || s == ExtraAttackTrees }, "both", 2},
		{"categories", CategoryPresets, isWSTG, "all", 12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ids := map[string]bool{}
			for _, p := range c.list {
				if p.ID == "" || p.Name == "" || ids[p.ID] {
					t.Errorf("bad or duplicate preset %+v", p)
				}
				ids[p.ID] = true
				seen := map[string]bool{}
				for _, m := range p.Members {
					if !c.valid(m) || seen[m] {
						t.Errorf("%s: bad or duplicate member %q", p.ID, m)
					}
					seen[m] = true
				}
				if c.name == "frameworks" && (len(p.Members) == 0 || p.Members[0] != FrameworkSTRIDE) {
					t.Errorf("%s does not start with STRIDE", p.ID)
				}
				if c.name == "categories" && len(p.Members) == 0 {
					t.Errorf("%s is empty", p.ID)
				}
			}
			got, ok := ResolvePreset(c.list, c.must)
			if !ok || len(got) != c.mustAll {
				t.Fatalf("%s: %v %v", c.must, got, ok)
			}
			got[0] = "changed"
			if again, _ := ResolvePreset(c.list, c.must); again[0] == "changed" {
				t.Fatal("ResolvePreset returned the table's own slice")
			}
			if _, ok := ResolvePreset(c.list, "nope"); ok {
				t.Fatal("unknown preset resolved")
			}
		})
	}
	if m, ok := ResolvePreset(MethodExtraPresets, "neither"); !ok || len(m) != 0 {
		t.Fatalf("neither = %v %v", m, ok)
	}
}

func TestValidItemID(t *testing.T) {
	cases := map[string]bool{
		"a": true, "T-12": true, "svc.api_v2": true, "0abc": true, strings.Repeat("a", 48): true,
		"": false, strings.Repeat("a", 49): false, "-a": false, ".a": false, "_a": false, "a b": false, "a/b": false,
		"a\n": false, "\xc3\xa9": false, "a;b": false,
	}
	for in, want := range cases {
		if got := ValidItemID(in); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}
