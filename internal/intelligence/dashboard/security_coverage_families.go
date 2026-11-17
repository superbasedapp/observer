//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"context"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// security_coverage_families.go adds the Coverage tab's "what is checked"
// rows (security coverage gaps plan
// docs/plans/security-coverage-gaps-plan-2026-11-13.md section 2,
// recommendation 5.1 of the gap analysis): one row per checking family
// with its components and its state from the component snapshot, so a
// family that is not selected is visible rather than absent.

// The family states, one closed vocabulary.
const (
	familyOn          = "on"
	familyOff         = "off"
	familyNotSelected = "not_selected"
	familyNotInBuild  = "not_in_build"
)

// securityCheckFamilyJS is one row of GET /api/security/coverage's
// families.
type securityCheckFamilyJS struct {
	Family     string   `json:"family"`
	Label      string   `json:"label"`
	Components []string `json:"components"`
	State      string   `json:"state"`
	Note       string   `json:"note,omitempty"`
}

// familyFacts are what the rows read beyond the component snapshot: the
// licence policy, the provenance setting and the DAST accept.
type familyFacts struct {
	// LicencePolicy: [security.licenses] names a deny or allow list, or
	// flags unknown licences.
	LicencePolicy bool
	// ProvenanceOff: [security.deps] provenance = "off".
	ProvenanceOff bool
	// DASTAccepted: the DAST checker's accept is recorded (nil: unknown).
	DASTAccepted *bool
}

// familyComponentState reads one component: compiled, blocked, selected.
type familyComponentState struct {
	Compiled func(id string) bool
	Blocked  func(id string) bool
	Selected func(id string) bool
}

// securityFamilyRow is one family of the table: its components (the
// family is on when any of them is on) and an optional refinement of an on
// row from the config.
type securityFamilyRow struct {
	family, label string
	components    []string
	refine        func(f familyFacts) (state, note string)
}

// securityFamilyRows is the family table, in the Coverage tab's order.
var securityFamilyRows = []securityFamilyRow{
	{family: "dependency_vulnerabilities", label: "Dependency vulnerabilities", components: []string{"security.scan.scalibr", "security.scan.osv"}},
	{family: "secrets", label: "Secrets", components: []string{"security.secrets"}},
	{family: "code_rules", label: "Code rules", components: []string{"security.scan.opengrep"}},
	{family: "iac", label: "Infrastructure as code", components: []string{"security.scan.trivy", "security.scan.kics"}},
	{family: "workflow_lint", label: "Workflow lint", components: []string{"security.scan.actionlint"}},
	{family: "passive_dast", label: "Passive DAST", components: []string{"security.dast"}, refine: func(f familyFacts) (string, string) {
		if f.DASTAccepted != nil && !*f.DASTAccepted {
			return familyOn, "selected; the one accept is not recorded yet (Scanners > Passive DAST)"
		}
		return familyOn, ""
	}},
	{family: "licences", label: "Licences", components: []string{"security.deps"}, refine: func(f familyFacts) (string, string) {
		if !f.LicencePolicy {
			return familyOn, "licences are reported; no [security.licenses] policy is set, so none is flagged"
		}
		return familyOn, "[security.licenses] policy set"
	}},
	{family: "package_provenance", label: "Package provenance", components: []string{"security.deps"}, refine: func(f familyFacts) (string, string) {
		if f.ProvenanceOff {
			return familyOff, `[security.deps] provenance = "off"`
		}
		return familyOn, ""
	}},
}

// componentFamilyState is one component's state, walked top-down.
func componentFamilyState(cs familyComponentState, id string) string {
	switch {
	case cs.Compiled != nil && !cs.Compiled(id):
		return familyNotInBuild
	case cs.Blocked != nil && cs.Blocked(id):
		return familyOff
	case cs.Selected != nil && cs.Selected(id):
		return familyOn
	}
	return familyNotSelected
}

// familyStateRank orders the combined state: the best state of any
// component is the family's.
var familyStateRank = []string{familyOn, familyOff, familyNotSelected, familyNotInBuild}

// securityCheckFamilies builds the rows from the component states and the
// facts.
func securityCheckFamilies(cs familyComponentState, f familyFacts) []securityCheckFamilyJS {
	out := make([]securityCheckFamilyJS, 0, len(securityFamilyRows))
	for _, row := range securityFamilyRows {
		best := len(familyStateRank) - 1
		for _, id := range row.components {
			if i := slices.Index(familyStateRank, componentFamilyState(cs, id)); i < best {
				best = i
			}
		}
		js := securityCheckFamilyJS{Family: row.family, Label: row.label, Components: append([]string{}, row.components...), State: familyStateRank[best]}
		if js.State == familyOn && row.refine != nil {
			js.State, js.Note = row.refine(f)
		}
		out = append(out, js)
	}
	return out
}

// securityCoverageFamilies reads the live snapshot, the config and the
// DAST accept for the rows. With no snapshot every opt-in reads not
// selected (the opt-in rule fails closed).
func (s *Server) securityCoverageFamilies(ctx context.Context) []securityCheckFamilyJS {
	snap, ok := s.comps.live(ctx)
	sel := s.opts.SecuritySelected
	cs := familyComponentState{
		Compiled: func(id string) bool {
			if !ok {
				return true
			}
			if d, found := snap.Decision(id); found {
				return d.State != components.StateAbsent && d.State != components.StateRequiredMissing
			}
			return len(snap.Compiled) == 0 || slices.Contains(snap.Compiled, id)
		},
		Blocked: func(id string) bool {
			d, found := snap.Decision(id)
			return ok && found && d.State == components.StateBlocked
		},
		Selected: func(id string) bool { return ok && sel != nil && sel(snap, id) },
	}
	var facts familyFacts
	resolved, _ := config.ResolveGlobalPath(s.opts.ConfigPath)
	if cfg, err := loadConfigForDashboard(resolved); err == nil {
		lic := cfg.Security.Licenses
		facts.LicencePolicy = len(lic.Deny) > 0 || len(lic.Allow) > 0 || lic.Unknown == "flag"
		facts.ProvenanceOff = cfg.Security.Deps.Provenance == "off"
	}
	if d := s.opts.SecurityDAST; d != nil && d.State != nil && cs.Selected("security.dast") {
		accepted := d.State(ctx).Accepted
		facts.DASTAccepted = &accepted
	}
	return securityCheckFamilies(cs, facts)
}
