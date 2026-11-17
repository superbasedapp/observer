//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
)

// familySet is a component-state stand-in over three id sets.
func familySet(compiled, blocked, selected []string) familyComponentState {
	return familyComponentState{
		Compiled: func(id string) bool { return slices.Contains(compiled, id) },
		Blocked:  func(id string) bool { return slices.Contains(blocked, id) },
		Selected: func(id string) bool { return slices.Contains(selected, id) },
	}
}

// TestSecurityCheckFamilies: one case per family row, each walking the
// states the row can take.
func TestSecurityCheckFamilies(t *testing.T) {
	no, yes := false, true
	cases := []struct {
		family                      string
		compiled, blocked, selected []string
		facts                       familyFacts
		state, note                 string
	}{
		{"dependency_vulnerabilities", []string{"security.scan.osv"}, nil, []string{"security.scan.osv"}, familyFacts{}, familyOn, ""},
		{"dependency_vulnerabilities", []string{"security.scan.scalibr", "security.scan.osv"}, nil, nil, familyFacts{}, familyNotSelected, ""},
		{"dependency_vulnerabilities", nil, nil, nil, familyFacts{}, familyNotInBuild, ""},
		{"secrets", []string{"security.secrets"}, []string{"security.secrets"}, nil, familyFacts{}, familyOff, ""},
		{"secrets", []string{"security.secrets"}, nil, []string{"security.secrets"}, familyFacts{}, familyOn, ""},
		{"code_rules", []string{"security.scan.opengrep"}, nil, nil, familyFacts{}, familyNotSelected, ""},
		{"iac", []string{"security.scan.trivy", "security.scan.kics"}, nil, []string{"security.scan.kics"}, familyFacts{}, familyOn, ""},
		{"iac", nil, nil, nil, familyFacts{}, familyNotInBuild, ""},
		{"workflow_lint", []string{"security.scan.actionlint"}, nil, []string{"security.scan.actionlint"}, familyFacts{}, familyOn, ""},
		{"passive_dast", []string{"security.dast"}, nil, []string{"security.dast"}, familyFacts{DASTAccepted: &no}, familyOn, "accept is not recorded"},
		{"passive_dast", []string{"security.dast"}, nil, []string{"security.dast"}, familyFacts{DASTAccepted: &yes}, familyOn, ""},
		{"passive_dast", []string{"security.dast"}, nil, nil, familyFacts{}, familyNotSelected, ""},
		{"licences", []string{"security.deps"}, nil, []string{"security.deps"}, familyFacts{}, familyOn, "no [security.licenses] policy"},
		{"licences", []string{"security.deps"}, nil, []string{"security.deps"}, familyFacts{LicencePolicy: true}, familyOn, "policy set"},
		{"licences", []string{"security.deps"}, nil, nil, familyFacts{LicencePolicy: true}, familyNotSelected, ""},
		{"package_provenance", []string{"security.deps"}, nil, []string{"security.deps"}, familyFacts{}, familyOn, ""},
		{"package_provenance", []string{"security.deps"}, nil, []string{"security.deps"}, familyFacts{ProvenanceOff: true}, familyOff, `provenance = "off"`},
		{"package_provenance", nil, nil, nil, familyFacts{}, familyNotInBuild, ""},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.family] = true
		rows := securityCheckFamilies(familySet(c.compiled, c.blocked, c.selected), c.facts)
		if len(rows) != len(securityFamilyRows) {
			t.Fatalf("rows %d, want %d", len(rows), len(securityFamilyRows))
		}
		i := slices.IndexFunc(rows, func(r securityCheckFamilyJS) bool { return r.Family == c.family })
		if i < 0 {
			t.Fatalf("no row %s", c.family)
		}
		r := rows[i]
		if r.State != c.state || (c.note == "" && r.Note != "") || !strings.Contains(r.Note, c.note) || len(r.Components) == 0 {
			t.Errorf("%s %v/%v/%v: state %q note %q, want %q %q", c.family, c.compiled, c.blocked, c.selected, r.State, r.Note, c.state, c.note)
		}
	}
	for _, row := range securityFamilyRows {
		if !seen[row.family] {
			t.Errorf("family %s has no test case", row.family)
		}
	}
}

// TestSecurityCoverageCarriesFamilies: the coverage read carries every
// family; with the opt-in rule naming none, every family reads not
// selected (or not in this build), never on.
func TestSecurityCoverageCarriesFamilies(t *testing.T) {
	s, _ := newTestServer(t)
	s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	s.opts.SecuritySelected = scannerRule()
	w := httptest.NewRecorder()
	s.handleSecurityCoverage(w, httptest.NewRequest(http.MethodGet, "/api/security/coverage", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, row := range securityFamilyRows {
		if !strings.Contains(w.Body.String(), `"family":"`+row.family+`"`) {
			t.Errorf("no family %s in %s", row.family, w.Body)
		}
	}
	if strings.Contains(w.Body.String(), `"state":"on"`) {
		t.Errorf("a family reads on with nothing selected: %s", w.Body)
	}
}
