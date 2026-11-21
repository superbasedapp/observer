package secrank

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secreach"
)

func dep(kev bool, reach secreach.Tier, epss int) Key {
	return Key{Dependency: true, Exploit: secexploit.Rank{KEV: kev, EPSSMilli: epss}, Reach: reach.SortRank()}
}

var (
	imported    = secreach.Tier{Level: secreach.Imported, Source: secreach.SourceGoImports}
	testsOnly   = secreach.Tier{Level: secreach.Imported, TestsOnly: true}
	unknown     = secreach.UnknownTier(secreach.ReasonNoMapping)
	notImported = secreach.Tier{Level: secreach.NotImportedDirectly}
	potentially = secreach.Tier{Level: secreach.PotentiallyAffected, Source: secreach.SourceGoBuildinfo}
)

// TestRuleTable is one case per row of the ranking table: each row decides
// a pair the rows above it tie, and the full tie keeps the caller's order.
func TestRuleTable(t *testing.T) {
	cases := []struct {
		rule        string
		first, then Key
	}{
		{"kev", dep(true, notImported, -1), dep(false, imported, 990)},
		{"reach", dep(false, imported, 1), dep(false, unknown, 990)},
		{"reach", dep(false, testsOnly, -1), dep(false, unknown, 990)},
		{"reach", dep(false, testsOnly, -1), dep(false, potentially, 990)},
		{"reach", dep(false, potentially, -1), dep(false, unknown, 990)},
		{"reach", dep(false, unknown, -1), dep(false, notImported, 990)},
		{"epss", dep(true, imported, 500), dep(true, imported, 20)},
		{"epss", dep(false, unknown, 0), dep(false, unknown, -1)},
	}
	names := map[string]bool{}
	for _, r := range rules {
		names[r.Name] = true
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		if !names[tc.rule] {
			t.Fatalf("no rule %q", tc.rule)
		}
		covered[tc.rule] = true
		if c := Compare(tc.first, tc.then); c >= 0 {
			t.Errorf("%s: %+v must sort before %+v (got %d)", tc.rule, tc.first, tc.then, c)
		}
		if c := Compare(tc.then, tc.first); c <= 0 {
			t.Errorf("%s: reversed pair compares %d", tc.rule, c)
		}
		// Every rule above this one ties the pair.
		for _, r := range rules {
			if r.Name == tc.rule {
				break
			}
			if r.Compare(tc.first, tc.then) != 0 {
				t.Errorf("%s: an earlier rule %s decides the pair", tc.rule, r.Name)
			}
		}
	}
	for n := range names {
		if !covered[n] {
			t.Errorf("rule %s has no test case", n)
		}
	}
	if c := Compare(dep(false, unknown, 3), dep(false, unknown, 3)); c != 0 {
		t.Fatalf("a full tie compares %d", c)
	}
}

func TestOrderMovesOnlyDependencyFindings(t *testing.T) {
	other := Key{}
	keys := []Key{
		other,                       // 0: a critical secret, stays first
		dep(false, notImported, -1), // 1: critical dependency, nothing known
		other,                       // 2: a high code finding, stays third
		dep(false, imported, 100),   // 3
		dep(true, unknown, -1),      // 4: KEV-listed, low severity
		NoSignal(),                  // 5
		dep(false, imported, 100),   // 6: ties 3, keeps the caller's order
	}
	got := Order(keys)
	want := []int{0, 4, 2, 3, 6, 5, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	items := []string{"secret", "dep-crit", "code", "dep-a", "dep-kev", "dep-none", "dep-b"}
	ranked := Apply(items, func(s string) Key {
		for i, it := range items {
			if it == s {
				return keys[i]
			}
		}
		return Key{}
	})
	if !reflect.DeepEqual(ranked, []string{"secret", "dep-kev", "code", "dep-a", "dep-b", "dep-none", "dep-crit"}) {
		t.Fatalf("apply %v", ranked)
	}
	if items[1] != "dep-crit" {
		t.Fatal("Apply changed its input")
	}
}

func TestUnavailableExploitDataGainsNoRank(t *testing.T) {
	// Exploit data unavailable: no listing and no score, the same key as a
	// finding the data does not list. Never a claim, never a demotion below
	// a finding with no signal.
	if got := KeyOf(unknown, secexploit.Exploit{}); got != NoSignal() {
		t.Fatalf("unavailable %+v, want %+v", got, NoSignal())
	}
}

func TestReachTokens(t *testing.T) {
	cases := []struct {
		tier  secreach.Tier
		token string
	}{
		{secreach.Tier{Level: secreach.Called, Source: secreach.SourceGovulncheckBinary}, "called"},
		{imported, "imported"},
		{testsOnly, "imported_tests_only"},
		{potentially, "potentially_affected"},
		{secreach.Tier{Level: secreach.NotCalled, Source: secreach.SourceGovulncheckBinary}, "not_called"},
		{notImported, "not_imported_directly"},
		{unknown, "unknown"},
		{secreach.Tier{}, "unknown"},
		{secreach.Tier{Level: secreach.Called}, "called"},
		{secreach.Tier{Level: secreach.Called, TestsOnly: true}, "called_tests_only"},
		{secreach.Tier{Level: secreach.Called, Approximate: true}, "called_approximate"},
		{secreach.Tier{Level: secreach.Called, Approximate: true, TestsOnly: true}, "called_approximate_tests_only"},
		{secreach.Tier{Level: secreach.Imported, Approximate: true}, "imported_approximate"},
		{secreach.Tier{Level: secreach.Imported, Approximate: true, TestsOnly: true}, "imported_approximate_tests_only"},
		{secreach.Tier{Level: secreach.NotImportedDirectly, Approximate: true}, "not_imported_directly"},
	}
	for _, tc := range cases {
		if got := ReachToken(tc.tier); got != tc.token {
			t.Errorf("%+v: token %q, want %q", tc.tier, got, tc.token)
		}
		if got := ReachRankOfToken(tc.token); tc.tier.Level != "" && got != tc.tier.SortRank() {
			t.Errorf("%q: rank %d, want %d", tc.token, got, tc.tier.SortRank())
		}
	}
	for _, r := range reachTokens {
		if len(r.Token) > 32 {
			t.Errorf("token %q is longer than the MCP answer keeps (32 bytes)", r.Token)
		}
	}
	if ReachRankOfToken("called_approximate") <= ReachRankOfToken("imported") {
		t.Error("a called tier must rank above an imported one")
	}
	if ReachRankOfToken("reachable!") != unknown.SortRank() || ReachRankOfToken("") != unknown.SortRank() {
		t.Fatal("a token outside the vocabulary must rank as unknown")
	}
}
