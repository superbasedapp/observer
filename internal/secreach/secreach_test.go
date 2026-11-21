package secreach

import "testing"

func goSet(complete bool, uses map[string]Use, modules ...string) map[string]ImportSet {
	return map[string]ImportSet{LangGo: {Source: SourceGoImports, Complete: complete, Uses: uses, Modules: modules}}
}

var (
	prod = Use{NonTest: true}
	test = Use{Test: true}
	both = Use{NonTest: true, Test: true}
)

// TestGoRecordRules has one case per goRecordRules row (and the decided /
// incomplete outcomes of each), in table order.
func TestGoRecordRules(t *testing.T) {
	cases := []struct {
		name    string
		adv     Advisory
		imports map[string]ImportSet
		want    Tier
	}{
		// Row 1: toolchain.
		{
			name:    "toolchain is not a library",
			adv:     Advisory{Ecosystem: "Go", Package: "toolchain", Records: []Record{{ID: "GO-1"}}},
			imports: goSet(true, map[string]Use{"fmt": prod}),
			want:    Tier{Level: Unknown, Reason: ReasonNotALibrary},
		},
		// Row 2: listed import paths.
		{
			name:    "listed path imported by production code",
			adv:     Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{{ID: "GO-2", ImportPaths: []string{"golang.org/x/net/html"}}}},
			imports: goSet(true, map[string]Use{"golang.org/x/net/html": both}),
			want:    Tier{Level: Imported, Source: SourceGoImports, Match: "golang.org/x/net/html"},
		},
		{
			name:    "listed path imported by tests only",
			adv:     Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{{ID: "GO-2", ImportPaths: []string{"golang.org/x/net/html"}}}},
			imports: goSet(true, map[string]Use{"golang.org/x/net/html": test}),
			want:    Tier{Level: Imported, Source: SourceGoImports, TestsOnly: true, Match: "golang.org/x/net/html"},
		},
		{
			name: "production use wins over a tests-only use of another listed path",
			adv: Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{{
				ID:          "GO-2",
				ImportPaths: []string{"golang.org/x/net/html", "golang.org/x/net/http2"},
			}}},
			imports: goSet(true, map[string]Use{"golang.org/x/net/html": test, "golang.org/x/net/http2": prod}),
			want:    Tier{Level: Imported, Source: SourceGoImports, Match: "golang.org/x/net/http2"},
		},
		{
			name:    "a subpackage of a listed path is another package",
			adv:     Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{{ID: "GO-2", ImportPaths: []string{"golang.org/x/net/html"}}}},
			imports: goSet(true, map[string]Use{"golang.org/x/net/html/atom": prod, "golang.org/x/net/proxy": prod}),
			want:    Tier{Level: NotImportedDirectly, Source: SourceGoImports},
		},
		{
			name:    "listed stdlib path matches exactly",
			adv:     Advisory{Ecosystem: "Go", Package: "stdlib", Records: []Record{{ID: "GO-3", ImportPaths: []string{"net/http"}}}},
			imports: goSet(true, map[string]Use{"net/http": prod}),
			want:    Tier{Level: Imported, Source: SourceGoImports, Match: "net/http"},
		},
		{
			name:    "listed stdlib path not imported",
			adv:     Advisory{Ecosystem: "Go", Package: "stdlib", Records: []Record{{ID: "GO-3", ImportPaths: []string{"net/smtp"}}}},
			imports: goSet(true, map[string]Use{"net/http": prod}),
			want:    Tier{Level: NotImportedDirectly, Source: SourceGoImports},
		},
		{
			name:    "an incomplete list proves nothing absent",
			adv:     Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{{ID: "GO-2", ImportPaths: []string{"golang.org/x/net/html"}}}},
			imports: goSet(false, map[string]Use{"fmt": prod}),
			want:    Tier{Level: Unknown, Reason: ReasonIncomplete},
		},
		{
			name:    "an incomplete list still proves a present import",
			adv:     Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{{ID: "GO-2", ImportPaths: []string{"golang.org/x/net/html"}}}},
			imports: goSet(false, map[string]Use{"golang.org/x/net/html": prod}),
			want:    Tier{Level: Imported, Source: SourceGoImports, Match: "golang.org/x/net/html"},
		},
		// Row 3: whole standard library.
		{
			name:    "stdlib record without paths and a stdlib import",
			adv:     Advisory{Ecosystem: "Go", Package: "stdlib", Records: []Record{{ID: "GO-4"}}},
			imports: goSet(true, map[string]Use{"C": prod, "example.com/x": prod, "fmt": test, "os": prod}),
			want:    Tier{Level: Imported, Source: SourceGoImports, Match: "os"},
		},
		{
			name:    "stdlib record without paths and no stdlib import",
			adv:     Advisory{Ecosystem: "Go", Package: "stdlib", Records: []Record{{ID: "GO-4"}}},
			imports: goSet(true, map[string]Use{"C": prod, "example.com/x": prod}),
			want:    Tier{Level: NotImportedDirectly, Source: SourceGoImports},
		},
		// Row 4: module path.
		{
			name:    "module record: the module root package",
			adv:     Advisory{Ecosystem: "Go", Package: "github.com/a/b", Records: []Record{{ID: "GO-5"}}},
			imports: goSet(true, map[string]Use{"github.com/a/b": prod}),
			want:    Tier{Level: Imported, Source: SourceGoImports, Match: "github.com/a/b"},
		},
		{
			name:    "module record: a package under the module",
			adv:     Advisory{Ecosystem: "Go", Package: "github.com/a/b", Records: []Record{{ID: "GO-5"}}},
			imports: goSet(true, map[string]Use{"github.com/a/b/c/d": test}),
			want:    Tier{Level: Imported, Source: SourceGoImports, TestsOnly: true, Match: "github.com/a/b/c/d"},
		},
		{
			name:    "module record: a name-prefix sibling is not under it",
			adv:     Advisory{Ecosystem: "Go", Package: "github.com/a/b", Records: []Record{{ID: "GO-5"}}},
			imports: goSet(true, map[string]Use{"github.com/a/bc": prod}),
			want:    Tier{Level: NotImportedDirectly, Source: SourceGoImports},
		},
		{
			name:    "module record: /v2 is another module",
			adv:     Advisory{Ecosystem: "Go", Package: "github.com/a/b", Records: []Record{{ID: "GO-5"}}},
			imports: goSet(true, map[string]Use{"github.com/a/b/v2/c": prod}),
			want:    Tier{Level: NotImportedDirectly, Source: SourceGoImports},
		},
		{
			name:    "module record: the /v2 module itself",
			adv:     Advisory{Ecosystem: "Go", Package: "github.com/a/b/v2", Records: []Record{{ID: "GO-5"}}},
			imports: goSet(true, map[string]Use{"github.com/a/b/v2/c": prod}),
			want:    Tier{Level: Imported, Source: SourceGoImports, Match: "github.com/a/b/v2/c"},
		},
		{
			name:    "module record: a nested module of the build graph is another module",
			adv:     Advisory{Ecosystem: "Go", Package: "github.com/aws/sdk", Records: []Record{{ID: "GO-6"}}},
			imports: goSet(true, map[string]Use{"github.com/aws/sdk/service/s3": prod}, "github.com/aws/sdk", "github.com/aws/sdk/service/s3"),
			want:    Tier{Level: NotImportedDirectly, Source: SourceGoImports},
		},
		{
			name:    "module record: a package of the module beside a nested module",
			adv:     Advisory{Ecosystem: "Go", Package: "github.com/aws/sdk", Records: []Record{{ID: "GO-6"}}},
			imports: goSet(true, map[string]Use{"github.com/aws/sdk/aws": prod, "github.com/aws/sdk/service/s3": prod}, "github.com/aws/sdk", "github.com/aws/sdk/service/s3"),
			want:    Tier{Level: Imported, Source: SourceGoImports, Match: "github.com/aws/sdk/aws"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.adv, tc.imports); got != tc.want {
				t.Fatalf("Classify = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestClassify covers the ecosystem table, the missing inputs and the
// combination of several records.
func TestClassify(t *testing.T) {
	html := Record{ID: "GO-A", ImportPaths: []string{"golang.org/x/net/html"}}
	http2 := Record{ID: "GO-B", ImportPaths: []string{"golang.org/x/net/http2"}}
	cases := []struct {
		name    string
		adv     Advisory
		imports map[string]ImportSet
		want    Tier
	}{
		{
			name:    "an ecosystem without a mapping",
			adv:     Advisory{Ecosystem: "Maven", Package: "org.example:lib", Records: []Record{{ID: "GHSA-1"}}},
			imports: goSet(true, map[string]Use{"org.example:lib": prod}),
			want:    Tier{Level: Unknown, Reason: ReasonNoMapping},
		},
		{
			name:    "no advisory record",
			adv:     Advisory{Ecosystem: "Go", Package: "golang.org/x/net"},
			imports: goSet(true, map[string]Use{"golang.org/x/net/html": prod}),
			want:    Tier{Level: Unknown, Reason: ReasonNoAdvisory},
		},
		{
			name:    "no import list for the language",
			adv:     Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{html}},
			imports: nil,
			want:    Tier{Level: Unknown, Reason: ReasonNoImportData},
		},
		{
			name:    "the strongest record wins",
			adv:     Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{html, http2}},
			imports: goSet(true, map[string]Use{"golang.org/x/net/http2": prod}),
			want:    Tier{Level: Imported, Source: SourceGoImports, Match: "golang.org/x/net/http2"},
		},
		{
			name: "one undecidable record keeps the finding unknown, not 'not imported'",
			adv: Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{
				html,
				{ID: "GO-C", ImportPaths: []string{"golang.org/x/net/idna"}},
			}},
			imports: map[string]ImportSet{LangGo: {Source: SourceCodeIntel, Complete: false, Uses: map[string]Use{}}},
			want:    Tier{Level: Unknown, Reason: ReasonIncomplete},
		},
		{
			name:    "codeintel source carries through",
			adv:     Advisory{Ecosystem: "Go", Package: "golang.org/x/net", Records: []Record{html}},
			imports: map[string]ImportSet{LangGo: {Source: SourceCodeIntel, Complete: true, Uses: map[string]Use{}}},
			want:    Tier{Level: NotImportedDirectly, Source: SourceCodeIntel},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.adv, tc.imports); got != tc.want {
				t.Fatalf("Classify = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLabelAndRank(t *testing.T) {
	cases := []struct {
		tier  Tier
		label string
		rank  int
	}{
		{Tier{Level: Called, Source: SourceGovulncheckBinary, Target: "bin/app", Match: "jwt.Parse"}, "called: jwt.Parse (govulncheck-binary, bin/app)", 7},
		{Tier{Level: Called, Source: SourceGovulncheckSource, Target: "go.mod"}, "called (govulncheck-source, go.mod)", 7},
		{Tier{Level: Imported, Source: SourceGoImports, SymbolNote: ReasonStripped}, "imported (go imports); symbol check unknown: stripped binary", 6},
		{Tier{Level: NotCalled, Source: SourceGovulncheckBinary, Target: "bin/app"}, "not called (govulncheck-binary, bin/app)", 1},
		{Tier{Level: Called, Source: SourceRustCallSite, Approximate: true}, "called, approximate (codeintel-rust-callsite)", 7},
		{Tier{Level: Imported, Source: SourceGoImports}, "imported (go imports)", 6},
		{Tier{Level: Called, Source: SourceRustCallSite, Approximate: true, TestsOnly: true}, "called, tests only, approximate (codeintel-rust-callsite)", 5},
		{Tier{Level: Imported, Source: SourceCodeIntel, Approximate: true}, "imported, approximate (codeintel)", 6},
		{Tier{Level: Imported, Source: SourceCodeIntel, TestsOnly: true}, "imported, tests only (codeintel)", 4},
		{Tier{Level: PotentiallyAffected, Source: SourceGoBuildinfo}, "potentially affected (go-buildinfo)", 3},
		{Tier{Level: NotImportedDirectly, Source: SourceGoImports}, "not imported directly (go imports)", 0},
		{UnknownTier(ReasonIncomplete), "unknown (import list incomplete)", 2},
		{UnknownTier(ReasonNoMapping), "unknown (no import mapping for this ecosystem)", 2},
		{UnknownTier(ReasonNoAdvisory), "unknown (advisory not in the local database)", 2},
		{UnknownTier(ReasonNoImportData), "unknown (no import data)", 2},
		{UnknownTier(ReasonNotALibrary), "unknown (the Go toolchain, not an import)", 2},
		{UnknownTier(ReasonStripped), "unknown (stripped binary)", 2},
		{UnknownTier(ReasonNoArtifactMapping), "unknown (no rule for this kind of build artifact)", 2},
		{UnknownTier(ReasonNoCodeIntel), "unknown (no code intelligence index for this language)", 2},
		{UnknownTier(ReasonNoNameMapping), "unknown (import name of this distribution not known)", 2},
		{UnknownTier(ReasonUseOnly), "unknown (crate in no use declaration; other paths are not indexed)", 2},
		{Tier{}, "unknown", 2},
	}
	for _, tc := range cases {
		if got := tc.tier.Label(); got != tc.label {
			t.Errorf("Label(%+v) = %q, want %q", tc.tier, got, tc.label)
		}
		if got := tc.tier.SortRank(); got != tc.rank {
			t.Errorf("SortRank(%+v) = %d, want %d", tc.tier, got, tc.rank)
		}
	}
}

func TestEveryReasonHasText(t *testing.T) {
	for _, r := range []Reason{ReasonNoImportData, ReasonNoMapping, ReasonNoAdvisory, ReasonIncomplete, ReasonNotALibrary, ReasonStripped, ReasonNoArtifactMapping, ReasonNoCodeIntel, ReasonNoNameMapping, ReasonUseOnly, ReasonPending, ReasonSymbolCheckFailed, ReasonOutOfMemory, ReasonTimedOut, ReasonNoToolchain, ReasonUnsupportedBinary, ReasonBinaryCap} {
		if reasonText[r] == "" {
			t.Errorf("reason %q has no label text", r)
		}
	}
}

func TestLanguageFor(t *testing.T) {
	for eco, want := range map[string]string{"Go": LangGo, "npm": LangJS, "PyPI": LangPython, "crates.io": LangRust} {
		if l, ok := LanguageFor(eco); !ok || l != want {
			t.Fatalf("LanguageFor(%s) = %q, %v; want %q", eco, l, ok, want)
		}
	}
	for _, eco := range []string{"Maven", "NuGet", "RubyGems", "go", "pypi", ""} {
		if _, ok := LanguageFor(eco); ok {
			t.Errorf("LanguageFor(%q) mapped, want no mapping", eco)
		}
	}
	if !NeedsRecords("Go") || NeedsRecords("npm") || NeedsRecords("PyPI") || NeedsRecords("crates.io") || NeedsRecords("Maven") {
		t.Error("NeedsRecords: only Go reads the records to decide")
	}
}

func TestIsMajorSuffix(t *testing.T) {
	cases := map[string]bool{"v2": true, "v10": true, "v1": false, "v0": false, "v02": false, "v": false, "vx": false, "v2a": false, "x2": false, "": false}
	for in, want := range cases {
		if got := isMajorSuffix(in); got != want {
			t.Errorf("isMajorSuffix(%q) = %v, want %v", in, got, want)
		}
	}
}
