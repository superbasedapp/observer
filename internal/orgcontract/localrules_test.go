package orgcontract

import (
	"strings"
	"testing"
)

const testProjectHash = "9c09f8055a26c27736ddcc04b4e693afbffd826da1d5a8e76081fdc9244e4c09"

// TestLocalRuleChangeValid pins the gen9 closed shape, one row per rule.
func TestLocalRuleChangeValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		c    LocalRuleChange
		want bool
	}{
		{"machine disable", LocalRuleChange{RuleID: "S-791", Layer: LocalRuleLayerMachine, Kind: LocalRuleKindDisable, Loosens: true}, true},
		{"user override", LocalRuleChange{RuleID: "R-101", Layer: LocalRuleLayerUserFile, Kind: LocalRuleKindOverride, Observe: "allow", Enforce: "allow"}, true},
		{"trusted disable with hash", LocalRuleChange{RuleID: "R-103", Layer: LocalRuleLayerTrustedProject, Kind: LocalRuleKindDisable, ProjectRootHash: testProjectHash}, true},
		{"project layer without hash", LocalRuleChange{RuleID: "R-103", Layer: LocalRuleLayerProjectFile, Kind: LocalRuleKindOverride}, false},
		{"machine layer with hash", LocalRuleChange{RuleID: "R-103", Layer: LocalRuleLayerMachine, Kind: LocalRuleKindDisable, ProjectRootHash: testProjectHash}, false},
		{"path as hash", LocalRuleChange{RuleID: "R-103", Layer: LocalRuleLayerProjectFile, Kind: LocalRuleKindOverride, ProjectRootHash: "/home/acme"}, false},
		{"free text id", LocalRuleChange{RuleID: "acme secret project", Layer: LocalRuleLayerUserFile, Kind: LocalRuleKindRule}, false},
		{"unknown decision", LocalRuleChange{RuleID: "R-101", Layer: LocalRuleLayerUserFile, Kind: LocalRuleKindOverride, Observe: "maybe"}, false},
		{"disable with a decision", LocalRuleChange{RuleID: "R-101", Layer: LocalRuleLayerMachine, Kind: LocalRuleKindDisable, Observe: "allow"}, false},
		{"disable in the user file", LocalRuleChange{RuleID: "R-101", Layer: LocalRuleLayerUserFile, Kind: LocalRuleKindDisable}, false},
	}
	for _, tc := range cases {
		if got := tc.c.Valid(); got != tc.want {
			t.Errorf("%s: Valid = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestLocalGuardWeakeningsGen9: a local loosening, applied or refused, is a
// guard.rules weakening; a tightening is not.
func TestLocalGuardWeakeningsGen9(t *testing.T) {
	t.Parallel()
	p := &LocalGuardPosture{Enabled: true, Mode: "enforce", PromptEnabled: true, PromptMode: "ask-once"}
	if got := LocalGuardWeakenings(p, nil); len(got) != 0 {
		t.Fatalf("baseline weakenings = %v", got)
	}
	p.RuleChanges = []LocalRuleChange{{RuleID: "R-103", Layer: LocalRuleLayerUserFile, Kind: LocalRuleKindOverride, Observe: "deny", Enforce: "deny", Applied: true}}
	if got := LocalGuardWeakenings(p, nil); len(got) != 0 {
		t.Fatalf("a tightening is not a weakening: %v", got)
	}
	p.RuleChanges = append(p.RuleChanges, LocalRuleChange{RuleID: "S-791", Layer: LocalRuleLayerMachine, Kind: LocalRuleKindDisable, Loosens: true})
	if got := strings.Join(LocalGuardWeakenings(p, nil), ","); got != LocalGuardKeyRules {
		t.Fatalf("weakenings = %q, want %q", got, LocalGuardKeyRules)
	}
	s := StripLocalRuleReport(p)
	if s.RuleChanges != nil || len(p.RuleChanges) != 2 {
		t.Fatalf("StripLocalRuleReport must clear the copy only")
	}
}

// TestLocalNodePostureValid pins the node posture's closed shape.
func TestLocalNodePostureValid(t *testing.T) {
	t.Parallel()
	ok := LocalNodePosture{BudgetWindow: LocalListDefault, DefaultWorkspace: LocalListCustom, SandboxBackends: []string{"bwrap"}, Share: map[string]bool{"obs.summary": true}, RoutingMode: "advise"}
	if !ok.Valid() {
		t.Fatal("a well-formed posture must validate")
	}
	for name, edit := range map[string]func(n *LocalNodePosture){
		"path as a backend":    func(n *LocalNodePosture) { n.SandboxBackends = []string{"/usr/bin/bwrap"} },
		"text as a mode":       func(n *LocalNodePosture) { n.RoutingMode = "route everything to acme" },
		"unknown window shape": func(n *LocalNodePosture) { n.BudgetWindow = "none" },
		"workspace path":       func(n *LocalNodePosture) { n.DefaultWorkspace = "/home/dev" },
		"negative count":       func(n *LocalNodePosture) { n.LaunchAllowedTools = -1 },
		"free text share key":  func(n *LocalNodePosture) { n.Share = map[string]bool{"My Key": true} },
	} {
		n := ok
		edit(&n)
		if n.Valid() {
			t.Errorf("%s: validated", name)
		}
	}
	if !(&LocalGuardPosture{Node: &ok}).Node.Valid() || ValidLocalRuleReport(&LocalGuardPosture{Node: &LocalNodePosture{}}) {
		t.Error("ValidLocalRuleReport must check the node posture")
	}
}

// TestValidLocalRuleReport pins the bounds and the removed-disables pairing.
func TestValidLocalRuleReport(t *testing.T) {
	t.Parallel()
	ok := &LocalGuardPosture{RemovedDisables: []string{"S-791"}, RemovedDisablesAt: "2026-11-12T10:00:00Z"}
	if !ValidLocalRuleReport(ok) || !ValidLocalRuleReport(nil) {
		t.Fatal("a well-formed report must validate")
	}
	for name, p := range map[string]*LocalGuardPosture{
		"time without ids":  {RemovedDisablesAt: "2026-11-12T10:00:00Z"},
		"ids without time":  {RemovedDisables: []string{"S-791"}},
		"bad time":          {RemovedDisables: []string{"S-791"}, RemovedDisablesAt: "yesterday"},
		"free text removed": {RemovedDisables: []string{"a b"}, RemovedDisablesAt: "2026-11-12T10:00:00Z"},
		"too many changes":  {RuleChanges: make([]LocalRuleChange, MaxLocalRuleChanges+1)},
	} {
		if ValidLocalRuleReport(p) {
			t.Errorf("%s: validated", name)
		}
	}
}
