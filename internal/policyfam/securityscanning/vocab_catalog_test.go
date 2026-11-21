package securityscanning

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/postureop"
)

// notChildren are the security catalog rows that are deliberately not
// family children, each with its reason.
var notChildren = map[string]string{
	"security":            "the module itself, not a child",
	"security.githooks":   "the org never installs git hooks, on managed nodes too (PR11)",
	"security.feedback":   "feedback to the agent (lane SEC-H) is the managed pull's feedback key, not a floor section",
	"security.provenance": "the signed AI change record (lane SEC-F2A) is opt-in only (Q9, securityOptIn) and writes into a repository only on a person's per-repository consent (Q8, Q12), so no floor may require it",
	"security.dast":       "the passive dev-server check (M3L-5) is opt-in only and runs only when the developer starts `observer security dast <url>` after their own one-time accept (never an agent, R-165), so no floor may require it",
	// The OS-CI-VULN arc's image and reach rows (2026-11-06). Making any of
	// them requirable is a change to the signed managed-pull vocabulary
	// (orgcontract.SecurityManagedComponents), which older nodes validate as
	// a closed list, so it is a deliberate later lane, not a merge fix.
	"security.scan.os":          "image OS package scanning is manual only (`observer security scan image`) and needs the developer's own OS database accept (R-165); not in the managed pull vocabulary yet, so no floor may require it",
	"security.scan.image.trivy": "Trivy's image driver needs the developer's own Trivy database accept (R-165), and a managed node's org mirror does not serve that database yet, so no floor may require it",
	"security.reach.go":         "Go symbol reachability ranks and labels findings only (it never closes or hides one), and its source mode runs per project on the developer's own opt-in, so a floor requiring it would enforce nothing",
}

// TestChildrenArePinnedToTheCatalog (SEC-E merge audit item 10): every node
// security row of the component catalog is a child or has a reason not to
// be, every child names a real catalog row, and every driver's component is
// a real row or none.
func TestChildrenArePinnedToTheCatalog(t *testing.T) {
	inChildren := map[string]bool{}
	for _, c := range Children {
		inChildren[c.Component] = true
		if c.Component != "security."+c.ID {
			t.Errorf("child %s: component %s, want security.%s", c.ID, c.Component, c.ID)
		}
		if comp, ok := components.Get(c.Component); !ok || comp.Binary != components.BinaryNode {
			t.Errorf("child %s names %s, which is not a node catalog row", c.ID, c.Component)
		}
	}
	for _, comp := range components.ForBinary(components.BinaryNode) {
		if comp.ID != "security" && !strings.HasPrefix(comp.ID, "security.") {
			continue
		}
		if _, skip := notChildren[comp.ID]; skip {
			if inChildren[comp.ID] {
				t.Errorf("%s is both a child and excluded", comp.ID)
			}
			continue
		}
		if !inChildren[comp.ID] {
			t.Errorf("catalog row %s is not a security.scanning child; add it to Children (with its process and egress columns reviewed) or to notChildren with a reason", comp.ID)
		}
	}
	for _, d := range Drivers {
		if d.Component == "" {
			continue
		}
		if !inChildren[d.Component] {
			t.Errorf("driver %s names %s, which is not a child component", d.ID, d.Component)
		}
	}
}

// TestEvaluateWithTheModuleOff (SEC-E merge audit item 11): with the
// security module inactive every key is not_applicable: module_inactive and
// nothing merges.
func TestEvaluateWithTheModuleOff(t *testing.T) {
	s := mustCompile(t, `{"require":{"prelaunch_trust":"refuse","components":["security.deps"]}}`)
	local := postureop.Posture{AxisPrelaunchTrust: {S: "warn"}}
	f := NodeFacts{Active: allActive(), Local: local, ModuleOff: true}
	for _, k := range Evaluate(s, f) {
		if k.State != StateNotApplicable || k.Reason != ReasonModuleInactive {
			t.Fatalf("key %s, want not_applicable: module_inactive", k)
		}
	}
	eff, err := Effective(&s, f)
	if err != nil || eff[AxisPrelaunchTrust].S != "warn" {
		t.Fatalf("effective %v %v, want the node's own value", eff, err)
	}
	// The control is a managed node: the trust floor is managed only
	// (P-125, audit SEC-P4 F4).
	f.ModuleOff, f.Managed = false, true
	if eff, _ := Effective(&s, f); eff[AxisPrelaunchTrust].S != "refuse" {
		t.Fatalf("control: with the module the floor applies, got %v", eff)
	}
}

// TestHistoryScanOnEnrolNeedsTheSuperAdmin (SEC-E merge audit item 12): a
// floor that starts git on enrolment is the super admin's.
func TestHistoryScanOnEnrolNeedsTheSuperAdmin(t *testing.T) {
	if why, need := SuperAdminReason(mustCompile(t, `{"require":{"history_scan_on_enrol":true}}`)); !need || len(why) == 0 {
		t.Fatal("history_scan_on_enrol = true must need the super admin")
	}
	if _, need := SuperAdminReason(mustCompile(t, `{"require":{"history_scan_on_enrol":false}}`)); need {
		t.Fatal("history_scan_on_enrol = false needs no super admin")
	}
}
