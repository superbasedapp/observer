package securityscanning

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func spec(t *testing.T, raw string) PolicySpec {
	t.Helper()
	s, _, err := CompileBody([]byte(raw), 0)
	if err != nil {
		t.Fatalf("compile %s: %v", raw, err)
	}
	return s
}

// TestMergeProjectSections is one row per merge operator (lane sec-p3): a
// project section only raises over the org-wide floor, several sections take
// the strictest, and a section that cannot merge is skipped with the floor
// in force kept.
func TestMergeProjectSections(t *testing.T) {
	rows := []struct {
		name     string
		base     string // "" = no org-wide floor
		sections []string
		want     string // canonical body of the merged floor
		refused  []int  // indexes of sections that must not apply
	}{
		{"section alone", "", []string{`{"require":{"max_advisory_db_age_h":24}}`}, `{"require":{"max_advisory_db_age_h":24}}`, nil},
		{"enum raises", `{"require":{"prelaunch_trust":"ask"}}`, []string{`{"require":{"prelaunch_trust":"refuse"}}`}, `{"require":{"prelaunch_trust":"refuse"}}`, nil},
		{"enum never lowers", `{"require":{"prelaunch_trust":"refuse"}}`, []string{`{"require":{"prelaunch_trust":"warn"}}`}, `{"require":{"prelaunch_trust":"refuse"}}`, nil},
		{"lower is stronger", `{"require":{"max_advisory_db_age_h":72}}`, []string{`{"require":{"max_advisory_db_age_h":168}}`, `{"require":{"max_advisory_db_age_h":24}}`}, `{"require":{"max_advisory_db_age_h":24}}`, nil},
		{"higher is stronger", `{"require":{"quick_scan_budget_s":10}}`, []string{`{"require":{"quick_scan_budget_s":5}}`}, `{"require":{"quick_scan_budget_s":10}}`, nil},
		{"retention lengthens, forever wins", `{"require":{"finding_retention_days":0}}`, []string{`{"require":{"finding_retention_days":90}}`}, `{"require":{"finding_retention_days":0}}`, nil},
		{"retention raise", `{"require":{"finding_retention_days":90}}`, []string{`{"require":{"finding_retention_days":365}}`}, `{"require":{"finding_retention_days":365}}`, nil},
		{"required components union", `{"require":{"components":["security.trust"]}}`, []string{`{"require":{"components":["security.secrets"]}}`}, `{"require":{"components":["security.secrets","security.trust"]}}`, nil},
		{"allow-sets intersect", `{"allow":{"scanner_sources":["org_mirror","vendor_release"]}}`, []string{`{"allow":{"scanner_sources":["org_mirror","user_installed"]}}`}, `{"allow":{"scanner_sources":["org_mirror"]}}`, nil},
		{"empty intersection refused, floor kept", `{"allow":{"scanner_sources":["vendor_release"]}}`, []string{`{"allow":{"scanner_sources":["org_mirror"]}}`}, `{"allow":{"scanner_sources":["vendor_release"]}}`, []int{0}},
		{"privacy floor forbids", `{"allow":{"online_checks":"allowed"}}`, []string{`{"allow":{"online_checks":"forbidden"}}`}, `{"allow":{"online_checks":"forbidden"}}`, nil},
		{"required and forbidden contradict", `{"require":{"online_checks":"required"}}`, []string{`{"allow":{"online_checks":"forbidden"}}`}, `{"require":{"online_checks":"required"}}`, []int{0}},
		{"version newer wins", `{"rule_pack":{"min_version":"2026.10.1"}}`, []string{`{"rule_pack":{"min_version":"2026.11.1"}}`}, `{"rule_pack":{"min_version":"2026.11.1"}}`, nil},
		{"strictest of two projects", "", []string{`{"require":{"min_blocking_severity":"medium"}}`, `{"require":{"min_blocking_severity":"low"}}`}, `{"require":{"min_blocking_severity":"low"}}`, nil},
		{"sections union", `{"sections":{"deps":{"capability":"security.deps.v1"}}}`, []string{`{"sections":{"trust":{"capability":"security.trust.v1"}}}`}, `{"sections":{"deps":{"capability":"security.deps.v1"},"trust":{"capability":"security.trust.v1"}}}`, nil},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var base *PolicySpec
			if r.base != "" {
				b := spec(t, r.base)
				base = &b
			}
			var secs []ProjectSection
			for i, s := range r.sections {
				secs = append(secs, ProjectSection{Project: fmt.Sprintf("P%d", i), Version: 1, Spec: spec(t, s)})
			}
			got, outcomes := MergeProjectSections(base, secs)
			want := spec(t, r.want)
			if got == nil || !SpecsEqual(got, &want) {
				t.Fatalf("merged = %+v, want %+v", got, want.Body)
			}
			var refused []int
			for i, o := range outcomes {
				if !o.Applied {
					if !errors.Is(o.Err, ErrSectionConflict) {
						t.Fatalf("section %d: %v, want ErrSectionConflict", i, o.Err)
					}
					refused = append(refused, i)
				}
			}
			if !reflect.DeepEqual(refused, r.refused) {
				t.Fatalf("refused = %v, want %v", refused, r.refused)
			}
		})
	}
	if got, _ := MergeProjectSections(nil, nil); got != nil {
		t.Fatalf("no floor and no section = %+v, want nil", got)
	}
}

// TestMergeProjectSectionsPerAxis is SEC-P3 merge finding 2 (orchestrator
// ruling): a section that conflicts on one axis is refused on THAT axis only
// and its other raises still apply; the result does not depend on the order
// the sections arrive in (every row runs in both orders); the refused axis is
// named with its project.
func TestMergeProjectSectionsPerAxis(t *testing.T) {
	type sec struct{ project, body string }
	rows := []struct {
		name     string
		base     string
		sections []sec
		want     string
		// partial and refused are per project: the refused axes, and whether
		// the section still applies something else.
		refused map[string][]string
		partial map[string]bool
	}{
		{
			"allow-set conflicts with the org-wide floor: that axis only",
			`{"allow":{"scanner_sources":["vendor_release"]}}`,
			[]sec{{"X", `{"allow":{"scanner_sources":["org_mirror"],"online_checks":"forbidden"}}`}},
			`{"allow":{"scanner_sources":["vendor_release"],"online_checks":"forbidden"}}`,
			map[string][]string{"X": {AxisAllowScannerSources}},
			map[string]bool{"X": true},
		},
		{
			"contradicts the org-wide floor: that axis only",
			`{"require":{"online_checks":"required"}}`,
			[]sec{{"X", `{"allow":{"online_checks":"forbidden"},"require":{"finding_retention_days":730}}`}},
			`{"require":{"online_checks":"required","finding_retention_days":730}}`,
			map[string][]string{"X": {AxisAllowOnlineChecks}},
			map[string]bool{"X": true},
		},
		{
			"two projects contradict: the privacy floor is kept",
			"",
			[]sec{{"A", `{"require":{"online_checks":"required","max_advisory_db_age_h":24}}`}, {"B", `{"allow":{"online_checks":"forbidden"}}`}},
			`{"allow":{"online_checks":"forbidden"},"require":{"max_advisory_db_age_h":24}}`,
			map[string][]string{"A": {AxisOnlineChecks}},
			map[string]bool{"A": true},
		},
		{
			"two projects' allow-sets leave nothing: the earlier project id stands",
			"",
			[]sec{{"A", `{"allow":{"scanner_sources":["org_mirror"]}}`}, {"B", `{"allow":{"scanner_sources":["vendor_release"]},"require":{"finding_retention_days":730}}`}},
			`{"allow":{"scanner_sources":["org_mirror"]},"require":{"finding_retention_days":730}}`,
			map[string][]string{"B": {AxisAllowScannerSources}},
			map[string]bool{"B": true},
		},
		{
			"two projects, strictest per field",
			`{"require":{"max_advisory_db_age_h":72}}`,
			[]sec{{"A", `{"require":{"max_advisory_db_age_h":24,"min_blocking_severity":"high"}}`}, {"B", `{"require":{"max_advisory_db_age_h":48,"min_blocking_severity":"low"}}`}},
			`{"require":{"max_advisory_db_age_h":24,"min_blocking_severity":"low"}}`,
			nil, nil,
		},
		{
			"a section whose only axis conflicts is refused whole",
			`{"allow":{"scanner_sources":["vendor_release"]}}`,
			[]sec{{"X", `{"allow":{"scanner_sources":["org_mirror"]}}`}},
			`{"allow":{"scanner_sources":["vendor_release"]}}`,
			map[string][]string{"X": {AxisAllowScannerSources}},
			map[string]bool{},
		},
	}
	for _, r := range rows {
		for _, reverse := range []bool{false, true} {
			name := r.name + " (given order)"
			if reverse {
				name = r.name + " (reversed)"
			}
			t.Run(name, func(t *testing.T) {
				var base *PolicySpec
				if r.base != "" {
					b := spec(t, r.base)
					base = &b
				}
				var in []ProjectSection
				for i := range r.sections {
					s := r.sections[i]
					if reverse {
						s = r.sections[len(r.sections)-1-i]
					}
					in = append(in, ProjectSection{Project: s.project, Version: 1, Spec: spec(t, s.body)})
				}
				got, outcomes := MergeProjectSections(base, in)
				want := spec(t, r.want)
				if got == nil || !SpecsEqual(got, &want) {
					t.Fatalf("merged = %+v, want %+v", got, want.Body)
				}
				for i, o := range outcomes {
					p := in[i].Project
					if !reflect.DeepEqual(o.RefusedAxes(), r.refused[p]) {
						t.Fatalf("project %s refused %v, want %v", p, o.RefusedAxes(), r.refused[p])
					}
					if o.Partial != r.partial[p] || o.Applied != (len(r.refused[p]) == 0) {
						t.Fatalf("project %s applied=%v partial=%v", p, o.Applied, o.Partial)
					}
					if len(r.refused[p]) > 0 && (!errors.Is(o.Err, ErrSectionConflict) || !strings.Contains(o.Err.Error(), r.refused[p][0])) {
						t.Fatalf("project %s err = %v, want a conflict naming the axis", p, o.Err)
					}
				}
			})
		}
	}
}

// TestMergeSpecsWritesEveryAxis pins that every axis has a writer, so a new
// axis cannot be silently dropped by a merge.
func TestMergeSpecsWritesEveryAxis(t *testing.T) {
	for _, ax := range Axes {
		if _, ok := floorWriters[ax.Name]; !ok {
			t.Errorf("axis %s has no floor writer", ax.Name)
		}
		if _, ok := floorReaders[ax.Name]; !ok {
			t.Errorf("axis %s has no floor reader", ax.Name)
		}
	}
}
