package secreach

import "testing"

// TestSymbolRules has one case per symbolRules row, in table order (RG-0
// rules 1 to 4, rule 2 split in two, and the "not reported" row).
func TestSymbolRules(t *testing.T) {
	full := SymbolFacts{ListsImports: true, ListsSymbols: true, Analysed: true}
	with := func(f func(*SymbolFacts)) SymbolFacts { c := full; f(&c); return c }
	cases := []struct {
		row   string
		facts SymbolFacts
		want  SymbolVerdict
	}{
		{"run failed", with(func(f *SymbolFacts) { f.Failed = ReasonStripped; f.SymbolTrace = true }), VerdictUnknown},
		{"no function list", with(func(f *SymbolFacts) { f.ListsImports = false; f.ListsSymbols = false; f.SymbolTrace = true }), VerdictNone},
		{"no function list", with(func(f *SymbolFacts) { f.ListsSymbols = false; f.PackageWithoutSymbols = true; f.SymbolTrace = true }), VerdictNone},
		{"symbol trace", with(func(f *SymbolFacts) { f.SymbolTrace = true; f.PackageWithoutSymbols = true }), VerdictCalled},
		{"package without symbols", with(func(f *SymbolFacts) { f.PackageWithoutSymbols = true }), VerdictNone},
		{"not reported", with(func(f *SymbolFacts) { f.Analysed = false }), VerdictNone},
		{"analysed, no trace", full, VerdictNotCalled},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.row] = true
		if got := DecideSymbol(tc.facts); got != tc.want {
			t.Errorf("%s: DecideSymbol(%+v) = %q, want %q", tc.row, tc.facts, got, tc.want)
		}
	}
	for _, r := range symbolRules {
		if !seen[r.Name] {
			t.Errorf("symbolRules row %q has no test case", r.Name)
		}
	}
}

var (
	runCalled = SymbolRun{Source: SourceGovulncheckBinary, Target: "bin/a", Records: []SymbolRecord{
		{ID: "GO-1", Module: "example.com/m", Version: "v1.0.0", Verdict: VerdictCalled, Symbol: "m.Bad"},
	}}
	runNot = SymbolRun{Source: SourceGovulncheckBinary, Target: "bin/b", Records: []SymbolRecord{
		{ID: "GO-1", Module: "example.com/m", Version: "v1.0.0", Verdict: VerdictNotCalled},
	}}
	runStripped = SymbolRun{Source: SourceGovulncheckBinary, Target: "bin/c", Reason: ReasonStripped}
	runTimedOut = SymbolRun{Source: SourceGovulncheckBinary, Target: "bin/c", Reason: ReasonTimedOut}
	base        = Tier{Level: Imported, Source: SourceGoImports, Match: "example.com/m"}
	// versionMatch is a binary's embedded standard library matched by its
	// Go release only (item 4 Go stdlib).
	versionMatch = Tier{Level: PotentiallyAffected, Source: SourceGoBuildinfo}
)

func q(paths ...string) SymbolQuery {
	return SymbolQuery{Module: "example.com/m", Version: "v1.0.0", IDs: []string{"GHSA-x", "GO-1"}, Paths: paths, PathsKnown: true}
}

// TestApplyRules has one case per applyRules row, in table order, plus the
// edges that keep a result to the build it covered.
func TestApplyRules(t *testing.T) {
	cases := []struct {
		row  string
		q    SymbolQuery
		runs []SymbolRun
		want Tier
		base *Tier // nil: base
	}{
		{"called somewhere covered", q("bin/a", "go.mod"), []SymbolRun{runCalled}, Tier{Level: Called, Source: SourceGovulncheckBinary, Target: "bin/a", Match: "m.Bad"}, nil},
		{"called somewhere covered", q("bin/b", "bin/a"), []SymbolRun{runNot, runCalled}, Tier{Level: Called, Source: SourceGovulncheckBinary, Target: "bin/a", Match: "m.Bad"}, nil},
		{"not called everywhere it was seen", q("bin/b"), []SymbolRun{runNot}, Tier{Level: NotCalled, Source: SourceGovulncheckBinary, Target: "bin/b"}, nil},
		{"stripped binary keeps a version match unknown", q("bin/c"), []SymbolRun{runStripped}, UnknownTier(ReasonStripped), &versionMatch},
		{"stripped binary keeps a version match unknown", q("bin/c"), []SymbolRun{runStripped}, func() Tier { b := base; b.SymbolNote = ReasonStripped; return b }(), nil},
		{"a covering check could not decide", q("bin/c"), []SymbolRun{runTimedOut}, func() Tier { b := base; b.SymbolNote = ReasonTimedOut; return b }(), nil},
		{"a covering check could not decide", q("bin/c"), []SymbolRun{runTimedOut}, func() Tier { b := versionMatch; b.SymbolNote = ReasonTimedOut; return b }(), &versionMatch},
		{"no claim", q("bin/b", "go.mod"), []SymbolRun{runNot}, base, nil},
		{"no claim", q("bin/z"), []SymbolRun{runNot}, base, nil},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.row] = true
		b := base
		if tc.base != nil {
			b = *tc.base
		}
		if got := ApplySymbol(b, tc.q, tc.runs); got != tc.want {
			t.Errorf("%s: ApplySymbol = %+v, want %+v", tc.row, got, tc.want)
		}
	}
	for _, r := range applyRules {
		if !seen[r.Name] {
			t.Errorf("applyRules row %q has no test case", r.Name)
		}
	}
}

// TestApplySymbolScopes: a result applies only to the finding it covered.
func TestApplySymbolScopes(t *testing.T) {
	cases := []struct {
		name string
		q    SymbolQuery
	}{
		{"other version", func() SymbolQuery { x := q("bin/b"); x.Version = "v1.1.0"; return x }()},
		{"other module", func() SymbolQuery { x := q("bin/b"); x.Module = "example.com/other"; return x }()},
		{"other advisory", func() SymbolQuery { x := q("bin/b"); x.IDs = []string{"GO-9"}; return x }()},
		{"sightings unknown", func() SymbolQuery { x := q("bin/b"); x.PathsKnown = false; return x }()},
		{"no module", func() SymbolQuery { x := q("bin/b"); x.Module = ""; return x }()},
	}
	for _, tc := range cases {
		if got := ApplySymbol(base, tc.q, []SymbolRun{runNot}); got != base {
			t.Errorf("%s: ApplySymbol = %+v, want the 3a tier unchanged", tc.name, got)
		}
	}
	if got := ApplySymbol(base, q("bin/b"), nil); got != base {
		t.Errorf("no runs: %+v", got)
	}
}

func TestNotCalledNeverReadsUnreachable(t *testing.T) {
	for _, tr := range []Tier{{Level: NotCalled, Source: SourceGovulncheckBinary, Target: "bin/a"}, {Level: NotImportedDirectly}} {
		if l := tr.Label(); contains(l, "unreachable") || contains(l, "safe") {
			t.Errorf("%q reads as unreachable", l)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestApplySymbolAssumedGo: a source-mode stdlib answer carries the Go
// release it assumed onto the tier and its label.
func TestApplySymbolAssumedGo(t *testing.T) {
	run := SymbolRun{Source: SourceGovulncheckSource, Target: "go.mod", Records: []SymbolRecord{
		{ID: "GO-9", Module: "stdlib", Version: "1.27.0", Verdict: VerdictNotCalled, AssumedGo: "1.27.0"},
	}}
	q := SymbolQuery{Module: "stdlib", Version: "1.27.0", IDs: []string{"GO-9"}, Paths: []string{"go.mod"}, PathsKnown: true}
	got := ApplySymbol(UnknownTier(ReasonNotALibrary), q, []SymbolRun{run})
	if got.Level != NotCalled || got.AssumedGo != "1.27.0" {
		t.Fatalf("tier = %+v", got)
	}
	if want := "not called (govulncheck-source, go.mod); stdlib at go1.27.0 from the go.mod, not the Go that builds it"; got.Label() != want {
		t.Errorf("label = %q, want %q", got.Label(), want)
	}
	// Another go.mod's answer never applies.
	q.Paths = []string{"tools/go.mod"}
	if got := ApplySymbol(UnknownTier(ReasonNotALibrary), q, []SymbolRun{run}); got.Level != Unknown {
		t.Errorf("another go.mod's run applied: %+v", got)
	}
}
