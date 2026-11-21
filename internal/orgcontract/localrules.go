package orgcontract

import (
	"regexp"
	"time"
)

// Local rule changes (gen9 of the guard policy-state row, 2026-11-12
// operator ruling: "Enterprise has absolute visibility, so any changes that
// are happening, especially on the policy front, have to be available to the
// org").
//
// A machine's effective guard rules are the built-in catalog, the org
// bundle, and the layers the machine sets for itself: the `[guard.rules]
// disable` list in its config, the user policy file, each repository's
// project policy file and the trusted per-project layer the node dashboard
// writes. Before gen9 none of the local layers reached the organization.
// LocalGuardPosture now carries them as ids, closed enums and project
// identity hashes only: never a matcher, a regex, a path, a doc line or any
// other text from the files.

// Local rule layers: the closed vocabulary of LocalRuleChange.Layer.
const (
	// LocalRuleLayerMachine is the node config's `[guard.rules] disable`
	// list ("This machine's settings").
	LocalRuleLayerMachine = "machine_settings"
	// LocalRuleLayerUserFile is the user policy file and its applied recipe.
	LocalRuleLayerUserFile = "user_file"
	// LocalRuleLayerProjectFile is a repository's in-repo project policy
	// file (escalate-only: a relaxation in it never applies).
	LocalRuleLayerProjectFile = "project_file"
	// LocalRuleLayerTrustedProject is the daemon-local trusted per-project
	// layer the node dashboard writes, and its applied recipe.
	LocalRuleLayerTrustedProject = "trusted_project"
)

// Local rule change kinds: the closed vocabulary of LocalRuleChange.Kind.
const (
	// LocalRuleKindDisable turns a rule off.
	LocalRuleKindDisable = "disable"
	// LocalRuleKindOverride changes an existing rule's decision or
	// enforcement.
	LocalRuleKindOverride = "override"
	// LocalRuleKindRule defines a rule of the layer's own.
	LocalRuleKindRule = "rule"
)

// MaxLocalRuleChanges bounds LocalGuardPosture.RuleChanges. A node with more
// reports the first MaxLocalRuleChanges (in its stable order) and sets
// RuleChangesTruncated.
const MaxLocalRuleChanges = 4000

// MaxRemovedDisables bounds LocalGuardPosture.RemovedDisables.
const MaxRemovedDisables = 200

// localRuleIDRe is the reportable shape of a rule id. Built-in, pack and
// org ids all fit it; a locally defined rule whose id does not is left out
// of the report and the list is marked truncated, so free text can never
// ride the id field.
var localRuleIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// projectHashRe is a project identity hash: the lowercase sha256 hex the
// push wire ships as project_root_hash.
var projectHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// localRuleDecisions is the closed decision vocabulary ("" = not set).
var localRuleDecisions = map[string]bool{"": true, "allow": true, "flag": true, "ask": true, "deny": true}

var localRuleLayers = map[string]bool{
	LocalRuleLayerMachine: true, LocalRuleLayerUserFile: true,
	LocalRuleLayerProjectFile: true, LocalRuleLayerTrustedProject: true,
}

var localRuleKinds = map[string]bool{
	LocalRuleKindDisable: true, LocalRuleKindOverride: true, LocalRuleKindRule: true,
}

// LocalRuleChange is one rule change a machine makes for itself.
type LocalRuleChange struct {
	// RuleID is the rule the change names.
	RuleID string `json:"rule_id"`
	// Layer is where the change is written (LocalRuleLayer*).
	Layer string `json:"layer"`
	// Kind is what the change does (LocalRuleKind*).
	Kind string `json:"kind"`
	// Observe and Enforce are the decisions the change sets while observing
	// and when enforcing ("" when it sets none: a disable, or an override
	// that only changes enforcement).
	Observe string `json:"observe,omitempty"`
	Enforce string `json:"enforce,omitempty"`
	// Enforced: the change makes the rule apply its enforcing decision even
	// while observing.
	Enforced bool `json:"enforced,omitempty"`
	// EnforceOff: the change caps the rule at flag (`enforce = false`).
	EnforceOff bool `json:"enforce_off,omitempty"`
	// Loosens: the change makes the rule weaker than its built-in decision
	// (a disable always does).
	Loosens bool `json:"loosens,omitempty"`
	// Applied: the machine runs the change. False when a stronger layer
	// refuses it: the organization's policy sets the rule, the organization
	// manages every rule on this machine and did not allow a local change,
	// the rule is one of the guard's own integrity rules, or a project file
	// tried to relax a rule (project files may only tighten).
	Applied bool `json:"applied"`
	// ProjectRootHash names the project for a project_file or
	// trusted_project change: the same identity hash the push wire ships as
	// project_root_hash. Empty for the machine-wide layers.
	ProjectRootHash string `json:"project_root_hash,omitempty"`
}

// ReportableLocalRuleID reports whether id may travel as a LocalRuleChange
// rule id (or a removed disable).
func ReportableLocalRuleID(id string) bool { return localRuleIDRe.MatchString(id) }

// Valid reports whether c carries only closed values: a reportable rule id,
// a known layer and kind, decisions from the closed set, and a project hash
// exactly where the layer is per project.
func (c LocalRuleChange) Valid() bool {
	if !ReportableLocalRuleID(c.RuleID) || !localRuleLayers[c.Layer] || !localRuleKinds[c.Kind] {
		return false
	}
	if !localRuleDecisions[c.Observe] || !localRuleDecisions[c.Enforce] {
		return false
	}
	perProject := c.Layer == LocalRuleLayerProjectFile || c.Layer == LocalRuleLayerTrustedProject
	if perProject != (c.ProjectRootHash != "") {
		return false
	}
	if c.ProjectRootHash != "" && !projectHashRe.MatchString(c.ProjectRootHash) {
		return false
	}
	// A disable sets no decision, and only the machine settings list and the
	// trusted project layer can disable a rule.
	if c.Kind == LocalRuleKindDisable {
		if c.Observe != "" || c.Enforce != "" {
			return false
		}
		if c.Layer != LocalRuleLayerMachine && c.Layer != LocalRuleLayerTrustedProject {
			return false
		}
	}
	return true
}

// ValidLocalRuleReport reports whether the gen9 fields of p are well formed:
// every change Valid and within MaxLocalRuleChanges, every removed disable a
// reportable id within MaxRemovedDisables, and RemovedDisablesAt an RFC3339
// time exactly when RemovedDisables is set. A nil p is valid.
func ValidLocalRuleReport(p *LocalGuardPosture) bool {
	if p == nil {
		return true
	}
	if len(p.RuleChanges) > MaxLocalRuleChanges || len(p.RemovedDisables) > MaxRemovedDisables {
		return false
	}
	if !p.Inputs.Valid() || !p.Node.Valid() {
		return false
	}
	for _, c := range p.RuleChanges {
		if !c.Valid() {
			return false
		}
	}
	for _, id := range p.RemovedDisables {
		if !ReportableLocalRuleID(id) {
			return false
		}
	}
	if (len(p.RemovedDisables) > 0) != (p.RemovedDisablesAt != "") {
		return false
	}
	if p.RemovedDisablesAt != "" {
		if _, err := time.Parse(time.RFC3339, p.RemovedDisablesAt); err != nil {
			return false
		}
	}
	return true
}

// LocalRuleLoosenings returns the changes that make a rule weaker than its
// built-in decision, applied or not (a refused loosening is an attempt the
// organization still sees).
func LocalRuleLoosenings(p *LocalGuardPosture) []LocalRuleChange {
	if p == nil {
		return nil
	}
	var out []LocalRuleChange
	for _, c := range p.RuleChanges {
		if c.Loosens {
			out = append(out, c)
		}
	}
	return out
}

// StripLocalRuleReport returns a copy of p without the gen9 fields, the
// shape a gen8 server validates. nil in, nil out; p is not modified.
func StripLocalRuleReport(p *LocalGuardPosture) *LocalGuardPosture {
	if p == nil {
		return nil
	}
	cp := *p
	cp.RuleChanges = nil
	cp.RuleChangesTruncated = false
	cp.RemovedDisables = nil
	cp.RemovedDisablesAt = ""
	cp.Inputs = nil
	cp.Node = nil
	return &cp
}

// List shapes for LocalGuardInputs (a closed enum: what the list holds, never
// its entries).
const (
	// LocalListDefault: the key is unset, so the built-in list applies.
	LocalListDefault = "default"
	// LocalListCustom: the machine sets its own non-empty list.
	LocalListCustom = "custom"
	// LocalListNone: the machine sets an explicitly empty list.
	LocalListNone = "none"
)

// MaxLocalGuardInputCount bounds every count in LocalGuardInputs.
const MaxLocalGuardInputCount = 100000

// LocalGuardInputs is the gen9 summary of the machine's guard engine inputs
// (managed policy visibility audit 2026-11-12, item 11): the lists and
// switches every rule engine on the machine, the organization's included, is
// built with. Shapes, counts, closed enums and bools only: no path, host,
// branch name or pattern travels.
type LocalGuardInputs struct {
	// BoundaryAllowPaths is the shape of [guard.boundary].allow_paths (paths
	// outside the project an agent may write); BoundaryAllowCount its length.
	BoundaryAllowPaths string `json:"boundary_allow_paths"`
	BoundaryAllowCount int    `json:"boundary_allow_count"`
	// ProtectedBranches is the shape of [guard.boundary].protected_branches.
	ProtectedBranches string `json:"protected_branches"`
	// NetworkAllowCount / NetworkDenyCount count the [guard.network] hosts.
	NetworkAllowCount int `json:"network_allow_count"`
	NetworkDenyCount  int `json:"network_deny_count"`
	// DatabaseProdPatternCount counts [guard.database].prod_patterns.
	DatabaseProdPatternCount int `json:"database_prod_pattern_count"`
	// EgressScan, EgressAction (flag|mask|deny), EgressAllowCount,
	// ResponseScan and InjectionHeuristics are [guard.proxy].
	EgressScan          bool   `json:"egress_scan"`
	EgressAction        string `json:"egress_action"`
	EgressAllowCount    int    `json:"egress_allow_count"`
	ResponseScan        bool   `json:"response_scan"`
	InjectionHeuristics bool   `json:"injection_heuristics"`
	// TaintEnabled is [guard.taint].enabled.
	TaintEnabled bool `json:"taint_enabled"`
	// MCPPinning and MCPPoisoningHeuristics are [guard.mcp].
	MCPPinning             bool `json:"mcp_pinning"`
	MCPPoisoningHeuristics bool `json:"mcp_poisoning_heuristics"`
}

var localListShapes = map[string]bool{LocalListDefault: true, LocalListCustom: true, LocalListNone: true}

var localEgressActions = map[string]bool{"flag": true, "mask": true, "deny": true}

// Valid reports whether in carries only closed values and bounded counts. A
// nil in is valid.
func (in *LocalGuardInputs) Valid() bool {
	if in == nil {
		return true
	}
	if !localListShapes[in.BoundaryAllowPaths] || !localListShapes[in.ProtectedBranches] || !localEgressActions[in.EgressAction] {
		return false
	}
	for _, n := range []int{in.BoundaryAllowCount, in.NetworkAllowCount, in.NetworkDenyCount, in.DatabaseProdPatternCount, in.EgressAllowCount} {
		if n < 0 || n > MaxLocalGuardInputCount {
			return false
		}
	}
	return true
}

// LocalGuardInputWeakenings returns, in table order, the input keys on which
// in is weaker than the shipped defaults: extra allowed paths, no protected
// branch, a switched-off scan or heuristic, an egress action that only
// flags, or an egress allow-list. A nil in reports nothing.
func LocalGuardInputWeakenings(in *LocalGuardInputs) []string {
	if in == nil {
		return nil
	}
	checks := []struct {
		key  string
		weak bool
	}{
		{"guard.boundary.allow_paths", in.BoundaryAllowPaths == LocalListCustom},
		{"guard.boundary.protected_branches", in.ProtectedBranches == LocalListNone},
		{"guard.proxy.egress_scan", !in.EgressScan},
		{"guard.proxy.egress_action", in.EgressAction == "flag"},
		{"guard.proxy.egress_allow", in.EgressAllowCount > 0},
		{"guard.proxy.response_scan", !in.ResponseScan},
		{"guard.proxy.injection_heuristics", !in.InjectionHeuristics},
		{"guard.taint.enabled", !in.TaintEnabled},
		{"guard.mcp.pinning", !in.MCPPinning},
		{"guard.mcp.poisoning_heuristics", !in.MCPPoisoningHeuristics},
	}
	var out []string
	for _, c := range checks {
		if c.weak {
			out = append(out, c.key)
		}
	}
	return out
}
