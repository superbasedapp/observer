package secrank

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// Key is one finding's rank inputs.
type Key struct {
	// Dependency marks a dependency finding: only those are reordered.
	Dependency bool
	// Exploit is the KEV listing and EPSS score as data
	// (secexploit.RankOf; EPSSMilli -1 when there is no score).
	Exploit secexploit.Rank
	// Reach is the reachability tier's rank (secreach.Tier.SortRank, higher
	// first).
	Reach int
}

// NoSignal is the key of a dependency finding with no signal at all: no
// KEV listing, an unknown tier and no score.
func NoSignal() Key {
	return Key{Dependency: true, Exploit: secexploit.Rank{EPSSMilli: -1}, Reach: secreach.UnknownTier("").SortRank()}
}

// KeyOf is a dependency finding's key from its tier and exploit answer.
func KeyOf(t secreach.Tier, x secexploit.Exploit) Key {
	return Key{Dependency: true, Exploit: secexploit.RankOf(x), Reach: t.SortRank()}
}

// rule is one row of the ranking table: Compare is negative when a sorts
// before b, 0 when this rule ties them.
type rule struct {
	Name    string
	Compare func(a, b Key) int
}

// rules is THE ranking table, walked top down; the first rule that does
// not tie decides. A full tie keeps the caller's order (stable).
var rules = []rule{
	{"kev", func(a, b Key) int { return secexploit.CompareKEV(a.Exploit, b.Exploit) }},
	{"reach", func(a, b Key) int {
		switch {
		case a.Reach > b.Reach:
			return -1
		case a.Reach < b.Reach:
			return 1
		}
		return 0
	}},
	{"epss", func(a, b Key) int { return secexploit.CompareEPSS(a.Exploit, b.Exploit) }},
}

// Compare orders two dependency findings' keys by the ranking table:
// negative when a sorts first, 0 when every rule ties them.
func Compare(a, b Key) int {
	for _, r := range rules {
		if c := r.Compare(a, b); c != 0 {
			return c
		}
	}
	return 0
}

// Order returns the ranked order of keys as indexes into keys: every
// non-dependency key keeps its position, and the dependency keys fill the
// positions dependency keys held, sorted stably by Compare (so the caller's
// order, the existing severity order, breaks a full tie).
func Order(keys []Key) []int {
	out := make([]int, len(keys))
	var slots, deps []int
	for i, k := range keys {
		out[i] = i
		if k.Dependency {
			slots = append(slots, i)
			deps = append(deps, i)
		}
	}
	sort.SliceStable(deps, func(i, j int) bool { return Compare(keys[deps[i]], keys[deps[j]]) < 0 })
	for n, slot := range slots {
		out[slot] = deps[n]
	}
	return out
}

// Apply returns a copy of items in Order over their keys; items itself is
// not changed.
func Apply[T any](items []T, key func(T) Key) []T {
	keys := make([]Key, len(items))
	for i, it := range items {
		keys[i] = key(it)
	}
	out := make([]T, len(items))
	for i, j := range Order(keys) {
		out[i] = items[j]
	}
	return out
}

// reachTokens is the reach tier's token vocabulary on an agent-facing
// answer (get_security_findings' "reach"), one row per tier shape.
var reachTokens = []struct {
	Token       string
	Level       secreach.Level
	TestsOnly   bool
	Approximate bool
}{
	{"called", secreach.Called, false, false},
	{"called_tests_only", secreach.Called, true, false},
	{"called_approximate", secreach.Called, false, true},
	{"called_approximate_tests_only", secreach.Called, true, true},
	{"imported", secreach.Imported, false, false},
	{"imported_tests_only", secreach.Imported, true, false},
	{"imported_approximate", secreach.Imported, false, true},
	{"imported_approximate_tests_only", secreach.Imported, true, true},
	{"potentially_affected", secreach.PotentiallyAffected, false, false},
	{"not_called", secreach.NotCalled, false, false},
	{"not_imported_directly", secreach.NotImportedDirectly, false, false},
	{"unknown", secreach.Unknown, false, false},
}

// ReachToken is a tier's token ("called_approximate", "imported",
// "imported_tests_only", "imported_approximate", "potentially_affected",
// "not_called", "not_imported_directly", "unknown", ...; reachTokens).
func ReachToken(t secreach.Tier) string {
	decided := t.Level == secreach.Imported || t.Level == secreach.Called
	for _, r := range reachTokens {
		if r.Level == t.Level && r.TestsOnly == (t.TestsOnly && decided) && r.Approximate == (t.Approximate && decided) {
			return r.Token
		}
	}
	return "unknown"
}

// ReachRankOfToken is a token's tier rank; a token that is not in the
// vocabulary (or "") ranks as unknown.
func ReachRankOfToken(token string) int {
	for _, r := range reachTokens {
		if r.Token == token {
			return secreach.Tier{Level: r.Level, TestsOnly: r.TestsOnly, Approximate: r.Approximate}.SortRank()
		}
	}
	return secreach.UnknownTier("").SortRank()
}
