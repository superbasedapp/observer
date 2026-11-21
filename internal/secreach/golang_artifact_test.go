package secreach

import "testing"

// TestGoArtifactRules: one case per row of goArtifactRules (item 4 Go
// stdlib, ruling 2026-11-05 (b) to (d)), then the record fold and the
// ecosystem dispatch.
func TestGoArtifactRules(t *testing.T) {
	stdlib := func(recs ...Record) Advisory {
		return Advisory{Ecosystem: "Go", Package: "stdlib", Artifact: true, Records: recs}
	}
	potentially := Tier{Level: PotentiallyAffected, Source: SourceGoBuildinfo}
	cases := []struct {
		name string
		adv  Advisory
		ev   BinaryEvidence
		want Tier
	}{
		{
			name: "release match is potentially affected (the default)",
			adv:  stdlib(Record{ID: "GO-1", ImportPaths: []string{"net/http"}}),
			want: potentially,
		},
		{
			name: "release match, a record that lists no package",
			adv:  stdlib(Record{ID: "GO-2"}),
			want: potentially,
		},
		{
			name: "toolchain is never a property of a binary",
			adv:  Advisory{Ecosystem: "Go", Package: "toolchain", Artifact: true, Records: []Record{{ID: "GO-3", ImportPaths: []string{"cmd/go"}}}},
			want: UnknownTier(ReasonNotALibrary),
		},
		{
			name: "toolchain stays unknown whatever the symbols say",
			adv:  Advisory{Ecosystem: "Go", Package: "toolchain", Artifact: true, Records: []Record{{ID: "GO-3"}}},
			ev:   BinaryEvidence{Symbols: SymbolsStripped},
			want: UnknownTier(ReasonNotALibrary),
		},
		{
			name: "a stripped binary stays unknown",
			adv:  stdlib(Record{ID: "GO-4", ImportPaths: []string{"crypto/tls"}}),
			ev:   BinaryEvidence{Symbols: SymbolsStripped},
			want: UnknownTier(ReasonStripped),
		},
		{
			name: "collected-but-empty evidence changes nothing",
			adv:  stdlib(Record{ID: "GO-5", ImportPaths: []string{"crypto/tls"}}),
			ev:   BinaryEvidence{Symbols: SymbolsNotCollected},
			want: potentially,
		},
		{
			name: "a flaw of the go command only is not in a compiled program",
			adv:  stdlib(Record{ID: "GO-6", ImportPaths: []string{"cmd/go", "cmd/compile"}}),
			want: UnknownTier(ReasonNotALibrary),
		},
		{
			name: "cmd and a library package together stay potentially affected",
			adv:  stdlib(Record{ID: "GO-7", ImportPaths: []string{"cmd/go", "net/http"}}),
			want: potentially,
		},
		{
			name: "a path that merely starts with cmd is a library",
			adv:  stdlib(Record{ID: "GO-8", ImportPaths: []string{"cmdline/x"}}),
			want: potentially,
		},
		{
			name: "the strongest record wins: one affected record keeps it potentially affected",
			adv: stdlib(
				Record{ID: "GO-9", ImportPaths: []string{"cmd/go"}},
				Record{ID: "GO-10", ImportPaths: []string{"net/http"}}),
			want: potentially,
		},
		{
			name: "no advisory record",
			adv:  stdlib(),
			want: UnknownTier(ReasonNoAdvisory),
		},
		{
			name: "an ecosystem with no artifact rule",
			adv:  Advisory{Ecosystem: "PyPI", Package: "requests", Artifact: true, Records: []Record{{ID: "PYSEC-1"}}},
			want: UnknownTier(ReasonNoArtifactMapping),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyArtifact(tc.adv, tc.ev); got != tc.want {
				t.Fatalf("ClassifyArtifact = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestPotentiallyAffectedRanksBetweenImportedAndNotImported pins the rank
// order: every import the project's code makes outranks a version-only
// binary match, which outranks unknown and not-imported.
func TestPotentiallyAffectedRanksBetweenImportedAndNotImported(t *testing.T) {
	order := []Tier{
		{Level: Imported, Source: SourceGoImports},
		{Level: Imported, Source: SourceGoImports, TestsOnly: true},
		{Level: PotentiallyAffected, Source: SourceGoBuildinfo},
		UnknownTier(ReasonNoImportData),
		{Level: NotImportedDirectly, Source: SourceGoImports},
	}
	for i := 1; i < len(order); i++ {
		if order[i-1].SortRank() <= order[i].SortRank() {
			t.Errorf("%s (rank %d) must outrank %s (rank %d)", order[i-1].Label(), order[i-1].SortRank(), order[i].Label(), order[i].SortRank())
		}
	}
}
