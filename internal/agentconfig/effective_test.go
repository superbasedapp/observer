package agentconfig

import (
	"errors"
	"reflect"
	"testing"
)

// Synthetic sources for the policy table: four files and two runtime layers,
// each with its own rank (the injected rank function stands in for
// DefaultRank, so the policies are tested apart from the real catalogue).
var (
	srcUser    = SourceRef{FileID: "t/user"}
	srcProject = SourceRef{FileID: "t/project"}
	srcLocal   = SourceRef{FileID: "t/local"}
	srcManaged = SourceRef{FileID: "t/managed"}
	srcFlag    = SourceRef{Runtime: RuntimeCLIFlag}
	srcLaunch  = SourceRef{Runtime: RuntimeLaunchEnv}
)

func testRank(s SourceRef) (int, bool) {
	r, ok := map[SourceRef]int{srcUser: 20, srcProject: 30, srcLocal: 40, srcFlag: 50, srcManaged: 100, srcLaunch: 1000}[s]
	return r, ok
}

func fam(p Policy) Family {
	return Family{
		ID: "t/fam", Tool: "t", Shape: "t/settings", Key: KeyPath{"k"}, Policy: p,
		Classes:      []string{"a", "b", "deny", "allow", "with_observer", "without_observer", "empty", "observer_entry", "other_entry"},
		RuntimeRanks: map[RuntimeLayer]int{RuntimeCLIFlag: 50, RuntimeLaunchEnv: 1000},
		DenyClass:    "deny", KeepClass: "with_observer",
	}
}

func ob(s SourceRef, class string) Observation {
	return Observation{Source: s, Key: KeyPath{"k"}, Present: true, Class: class, Active: true}
}

func obKey(s SourceRef, key KeyPath, class string) Observation {
	o := ob(s, class)
	o.Key = key
	return o
}

func inactive(o Observation) Observation {
	o.Active, o.InactiveReason = false, "untrusted project"
	return o
}

// TestEvaluatePolicies has rows for each of the eight policies, plus the
// shared behaviour (override, inactive and absent sources, no observation).
func TestEvaluatePolicies(t *testing.T) {
	withOverride := func(f Family) Family { f.Override = []RuntimeLayer{RuntimeLaunchEnv}; return f }
	cases := []struct {
		name string
		f    Family
		obs  []Observation
		want []EffectiveResult
	}{
		// highest_wins
		{
			"highest_wins single source", fam(PolicyHighestWins),
			[]Observation{ob(srcUser, "a")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "a", Winning: srcUser, Reason: ReasonSingleSource}},
		},
		{
			"highest_wins: project over user", fam(PolicyHighestWins),
			[]Observation{ob(srcUser, "a"), ob(srcProject, "b")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "b", Winning: srcProject, Shadowed: []SourceRef{srcUser}, Reason: ReasonOutranked}},
		},
		{
			"highest_wins: an inactive higher source never wins", fam(PolicyHighestWins),
			[]Observation{ob(srcUser, "a"), inactive(ob(srcLocal, "b"))},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "a", Winning: srcUser, Inactive: []SourceRef{srcLocal}, Reason: ReasonSingleSource}},
		},
		{
			"highest_wins: only inactive sources", fam(PolicyHighestWins),
			[]Observation{inactive(ob(srcLocal, "b"))},
			[]EffectiveResult{{Key: KeyPath{"k"}, Inactive: []SourceRef{srcLocal}, Reason: ReasonNoObservation}},
		},
		{
			"highest_wins: an absent source is ignored", fam(PolicyHighestWins),
			[]Observation{ob(srcUser, "a"), {Source: srcManaged, Key: KeyPath{"k"}, Active: true}},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "a", Winning: srcUser, Reason: ReasonSingleSource}},
		},
		{
			"highest_wins: nothing observed", fam(PolicyHighestWins), nil,
			[]EffectiveResult{{Key: KeyPath{"k"}, Reason: ReasonNoObservation}},
		},
		{
			"highest_wins: a CLI flag sits between local and managed", fam(PolicyHighestWins),
			[]Observation{ob(srcLocal, "a"), ob(srcFlag, "b")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "b", Winning: srcFlag, Shadowed: []SourceRef{srcLocal}, Reason: ReasonOutranked}},
		},
		// runtime_override
		{
			"runtime_override: launch env beats managed", withOverride(fam(PolicyRuntimeOverride)),
			[]Observation{ob(srcManaged, "a"), ob(srcLaunch, "b")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "b", Winning: srcLaunch, Shadowed: []SourceRef{srcManaged}, Reason: ReasonRuntimeOverride}},
		},
		{
			"runtime_override: no override set falls back to highest", withOverride(fam(PolicyRuntimeOverride)),
			[]Observation{ob(srcUser, "a"), ob(srcManaged, "b")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "b", Winning: srcManaged, Shadowed: []SourceRef{srcUser}, Reason: ReasonOutranked}},
		},
		// map_merge
		{"map_merge decides each key on its own", withOverride(fam(PolicyMapMerge)), []Observation{
			obKey(srcUser, KeyPath{"k", "A"}, "a"), obKey(srcLocal, KeyPath{"k", "A"}, "b"),
			obKey(srcUser, KeyPath{"k", "B"}, "a"), obKey(srcLaunch, KeyPath{"k", "C"}, "b"), obKey(srcManaged, KeyPath{"k", "C"}, "a"),
		}, []EffectiveResult{
			{Key: KeyPath{"k", "A"}, EffectiveClass: "b", Winning: srcLocal, Shadowed: []SourceRef{srcUser}, Reason: ReasonOutranked},
			{Key: KeyPath{"k", "B"}, EffectiveClass: "a", Winning: srcUser, Reason: ReasonSingleSource},
			{Key: KeyPath{"k", "C"}, EffectiveClass: "b", Winning: srcLaunch, Shadowed: []SourceRef{srcManaged}, Reason: ReasonRuntimeOverride},
		}},
		{"map_merge: nothing observed is no result", fam(PolicyMapMerge), nil, []EffectiveResult{}},
		// deny_wins
		{
			"deny_wins: a lower deny beats a higher allow", fam(PolicyDenyWins),
			[]Observation{ob(srcUser, "deny"), ob(srcManaged, "allow")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "deny", Winning: srcUser, Shadowed: []SourceRef{srcManaged}, Reason: ReasonDenyPresent}},
		},
		{
			"deny_wins: a deny beats the override too", withOverride(fam(PolicyDenyWins)),
			[]Observation{ob(srcUser, "deny"), ob(srcLaunch, "allow")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "deny", Winning: srcUser, Shadowed: []SourceRef{srcLaunch}, Reason: ReasonDenyPresent}},
		},
		{
			"deny_wins: no deny is highest wins", fam(PolicyDenyWins),
			[]Observation{ob(srcUser, "allow"), ob(srcProject, "allow")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "allow", Winning: srcProject, Shadowed: []SourceRef{srcUser}, Reason: ReasonOutranked}},
		},
		{
			"deny_wins: an inactive deny does not count", fam(PolicyDenyWins),
			[]Observation{inactive(ob(srcProject, "deny")), ob(srcUser, "allow")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "allow", Winning: srcUser, Inactive: []SourceRef{srcProject}, Reason: ReasonSingleSource}},
		},
		// array_replace
		{
			"array_replace: an empty higher array drops Observer's", fam(PolicyArrayReplace),
			[]Observation{ob(srcUser, "with_observer"), ob(srcProject, "empty")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "empty", Winning: srcProject, Shadowed: []SourceRef{srcUser}, Reason: ReasonArrayReplaced}},
		},
		// array_concat
		{
			"array_concat keeps Observer's entry from a lower source", fam(PolicyArrayConcat),
			[]Observation{ob(srcUser, "with_observer"), ob(srcProject, "without_observer")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "with_observer", Winning: srcUser, Shadowed: []SourceRef{srcProject}, Reason: ReasonMerged}},
		},
		{
			"array_concat: no source has it", fam(PolicyArrayConcat),
			[]Observation{ob(srcUser, "without_observer"), ob(srcProject, "empty")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "empty", Winning: srcProject, Shadowed: []SourceRef{srcUser}, Reason: ReasonMerged}},
		},
		{
			"array_concat single source", fam(PolicyArrayConcat),
			[]Observation{ob(srcUser, "with_observer")},
			[]EffectiveResult{{Key: KeyPath{"k"}, EffectiveClass: "with_observer", Winning: srcUser, Reason: ReasonSingleSource}},
		},
		// same_name_replace
		{"same_name_replace: a project entry of the same name replaces Observer's", fam(PolicySameNameReplace), []Observation{
			obKey(srcUser, KeyPath{"k", "superbased-observer"}, "observer_entry"), obKey(srcProject, KeyPath{"k", "superbased-observer"}, "other_entry"),
		}, []EffectiveResult{{Key: KeyPath{"k", "superbased-observer"}, EffectiveClass: "other_entry", Winning: srcProject, Shadowed: []SourceRef{srcUser}, Reason: ReasonSameNameReplaced}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(tc.f, tc.obs, testRank)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// TestEveryPolicyIsTested keeps the policy table closed and covered.
func TestEveryPolicyIsTested(t *testing.T) {
	all := []Policy{PolicyHighestWins, PolicyDenyWins, PolicyMapMerge, PolicyArrayReplace, PolicyArrayConcat, PolicySameNameReplace, PolicyRuntimeOverride, PolicyFirstFileWins}
	if len(policies) != len(all) {
		t.Errorf("policies has %d entries; update this test and TestEvaluatePolicies", len(policies))
	}
	for _, p := range all {
		if policies[p].eval == nil {
			t.Errorf("policy %q has no evaluator", p)
		}
	}
}

// TestEvaluateErrors: each table or caller bug is an error, never a verdict.
func TestEvaluateErrors(t *testing.T) {
	good := fam(PolicyHighestWins)
	cases := []struct {
		name string
		f    Family
		obs  []Observation
		want error
	}{
		{"unknown policy", func() Family { f := good; f.Policy = "made_up"; return f }(), nil, ErrBadFamily},
		{"no classes", func() Family { f := good; f.Classes = nil; return f }(), nil, ErrBadFamily},
		{"deny_wins without a deny class", func() Family { f := fam(PolicyDenyWins); f.DenyClass = "missing"; return f }(), nil, ErrBadFamily},
		{"array_concat without a keep class", func() Family { f := fam(PolicyArrayConcat); f.KeepClass = ""; return f }(), nil, ErrBadFamily},
		{"runtime_override without an override", fam(PolicyRuntimeOverride), nil, ErrBadFamily},
		{"override layer with no rank", func() Family { f := good; f.Override = []RuntimeLayer{"host_env"}; return f }(), nil, ErrBadFamily},
		{"source outside the family", good, []Observation{ob(SourceRef{FileID: "other/file"}, "a")}, ErrBadObservation},
		{"source names both a file and a layer", good, []Observation{ob(SourceRef{FileID: "t/user", Runtime: RuntimeCLIFlag}, "a")}, ErrBadObservation},
		{"source names neither", good, []Observation{ob(SourceRef{}, "a")}, ErrBadObservation},
		{"class outside the family", good, []Observation{ob(srcUser, "made_up")}, ErrBadObservation},
		{"key outside an exact family", good, []Observation{obKey(srcUser, KeyPath{"k", "sub"}, "a")}, ErrBadObservation},
		{"key at a map family's own key", fam(PolicyMapMerge), []Observation{ob(srcUser, "a")}, ErrBadObservation},
		{"key outside a map family", fam(PolicyMapMerge), []Observation{obKey(srcUser, KeyPath{"other", "A"}, "a")}, ErrBadObservation},
		{"same source twice", good, []Observation{ob(srcUser, "a"), ob(srcUser, "b")}, ErrBadObservation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Evaluate(tc.f, tc.obs, testRank); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	tied := func(s SourceRef) (int, bool) { return 20, true }
	if _, err := Evaluate(good, []Observation{ob(srcUser, "a"), ob(srcProject, "b")}, tied); !errors.Is(err, ErrAmbiguousRank) {
		t.Errorf("tied ranks: err = %v, want ErrAmbiguousRank", err)
	}
}

// TestClaudeEnvFamilyOnTheRealCatalogue runs the seeded family through
// DefaultRank and the real Claude Code rows: the review's OBS-9 fixture (a
// project-local settings file sending ANTHROPIC_BASE_URL to the vendor
// shadows the user file's loopback route) and the original trigger (the
// launch environment beats every settings file, managed included).
func TestClaudeEnvFamilyOnTheRealCatalogue(t *testing.T) {
	f, ok := FamilyByID("claude-code/env")
	if !ok {
		t.Fatal("no claude-code/env family")
	}
	baseURL := KeyPath{"env", "ANTHROPIC_BASE_URL"}
	user := SourceRef{FileID: "claude-code/user-settings"}
	local := SourceRef{FileID: "claude-code/project-local-settings"}
	managed := SourceRef{FileID: "claude-code/managed-settings"}
	launch := SourceRef{Runtime: RuntimeLaunchEnv}
	at := func(s SourceRef, class string) Observation {
		return Observation{Source: s, Key: baseURL, Present: true, Class: class, Active: true}
	}

	got, err := Evaluate(f, []Observation{at(user, "loopback"), at(local, "vendor_host")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []EffectiveResult{{Key: baseURL, EffectiveClass: "vendor_host", Winning: local, Shadowed: []SourceRef{user}, Reason: ReasonOutranked}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("OBS-9 fixture: got %+v, want %+v", got, want)
	}

	got, err = Evaluate(f, []Observation{at(user, "loopback"), at(managed, "loopback"), at(launch, "vendor_host")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want = []EffectiveResult{{Key: baseURL, EffectiveClass: "vendor_host", Winning: launch, Shadowed: []SourceRef{managed, user}, Reason: ReasonRuntimeOverride}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("launch env: got %+v, want %+v", got, want)
	}

	if _, err := Evaluate(f, []Observation{at(SourceRef{FileID: "codex/user-config"}, "loopback")}, nil); !errors.Is(err, ErrBadObservation) {
		t.Errorf("another tool's file: err = %v, want ErrBadObservation", err)
	}
	if _, err := Evaluate(f, []Observation{at(SourceRef{FileID: "claude-code/global-config"}, "loopback")}, nil); !errors.Is(err, ErrBadObservation) {
		t.Errorf("another shape of the same tool: err = %v, want ErrBadObservation", err)
	}
}

// TestFamiliesWellFormed checks the real family table: each family is valid,
// names a shape the catalogue has for its tool, its effective file ranks
// (FileRanks over FileRow.Precedence) never tie, its runtime ranks never tie
// a file of that shape, and it has a classifier whose classes are its own.
func TestFamiliesWellFormed(t *testing.T) {
	seenID := map[string]bool{}
	concerns := map[Concern]bool{}
	for _, r := range layerFindingRules {
		concerns[r.concern] = true
	}
	for _, f := range Families() {
		if seenID[f.ID] {
			t.Errorf("duplicate family %s", f.ID)
		}
		seenID[f.ID] = true
		if err := validateFamily(f); err != nil {
			t.Errorf("%s: %v", f.ID, err)
		}
		if f.Grounding.Kind == "" || f.Grounding.Source == "" || f.Grounding.Date == "" {
			t.Errorf("%s: incomplete grounding", f.ID)
		}
		if familyClassifiers[f.ID] == nil {
			t.Errorf("%s: no classifier in familyClassifiers", f.ID)
		}
		if !concerns[f.Concern] {
			t.Errorf("%s: concern %q has no layerFindingRules row", f.ID, f.Concern)
		}
		rank := DefaultRank(f)
		ranks := map[int]string{}
		of := map[string]bool{}
		for _, row := range Files() {
			if row.Tool == f.Tool && row.Shape == f.Shape {
				of[row.ID] = true
				r, _ := rank(SourceRef{FileID: row.ID})
				if other, dup := ranks[r]; dup {
					t.Errorf("%s: %s and %s share rank %d", f.ID, other, row.ID, r)
				}
				ranks[r] = row.ID
			}
		}
		if len(ranks) == 0 {
			t.Errorf("%s: no catalogued file of %s / %s", f.ID, f.Tool, f.Shape)
		}
		for id := range f.FileRanks {
			if !of[id] {
				t.Errorf("%s: FileRanks names %s, not a file of %s / %s", f.ID, id, f.Tool, f.Shape)
			}
		}
		for l, r := range f.RuntimeRanks {
			if other, dup := ranks[r]; dup {
				t.Errorf("%s: runtime %s ties file %s at %d", f.ID, l, other, r)
			}
		}
		if f.Concern == ConcernLayerDrop && (f.OffClass == "" || len(f.DropScopes) == 0) {
			t.Errorf("%s: a layer-drop family needs an OffClass and DropScopes", f.ID)
		}
	}
	for id := range familyClassifiers {
		if !seenID[id] {
			t.Errorf("familyClassifiers has %s, which is no family", id)
		}
	}
}
