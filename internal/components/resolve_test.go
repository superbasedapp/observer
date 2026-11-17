package components

import (
	"strings"
	"testing"
)

// TestResolveTable is one row per resolver property (plan 3.1) and per rule
// of resolveRules, against the real catalog.
func TestResolveTable(t *testing.T) {
	type want struct {
		id      string
		state   State
		reason  Reason
		because string
	}
	cases := []struct {
		name    string
		in      ResolveInput
		want    []want
		wantErr string
	}{
		{
			name: "core is always active",
			in:   ResolveInput{Binary: BinaryNode, Compiled: []string{"core", "org.client"}},
			want: []want{{"core", StateActive, ReasonCore, ""}},
		},
		{
			name: "not selected is available",
			in:   ResolveInput{Binary: BinaryNode},
			want: []want{{"codeintel", StateAvailable, ReasonNotSelected, ""}},
		},
		{
			name: "selected is active",
			in:   ResolveInput{Binary: BinaryNode, Selected: []string{"codeintel"}},
			want: []want{{"codeintel", StateActive, ReasonSelected, ""}},
		},
		{
			name: "requires is transitive and selects what it needs",
			in:   ResolveInput{Binary: BinaryNode, Selected: []string{"proxy.routing"}},
			want: []want{
				{"proxy.routing", StateActive, ReasonSelected, ""},
				{"capture.proxy", StateActive, ReasonRequiredBy, "proxy.routing"},
			},
		},
		{
			name: "requires is transitive across two hops",
			in:   ResolveInput{Binary: BinaryNode, Selected: []string{"benchmark"}},
			want: []want{{"terminals", StateActive, ReasonRequiredBy, "benchmark"}},
		},
		{
			name: "an adapter requires the adapter whose parser it wraps",
			in:   ResolveInput{Binary: BinaryNode, Selected: []string{"adapter.kilo-code"}},
			want: []want{{"adapter.cline", StateActive, ReasonRequiredBy, "adapter.kilo-code"}},
		},
		{
			name: "not compiled is absent",
			in:   ResolveInput{Binary: BinaryNode, Compiled: InDistro(DistroMinimal)},
			want: []want{{"codeintel", StateAbsent, ReasonNotCompiled, ""}},
		},
		{
			name:    "selecting an absent component names the distros that have it",
			in:      ResolveInput{Binary: BinaryNode, Compiled: InDistro(DistroMinimal), Selected: []string{"terminals"}},
			want:    []want{{"terminals", StateAbsent, ReasonNotCompiled, ""}},
			wantErr: "terminals: not in this build; builds that include it: developer, managed, full",
		},
		{
			name:    "a missing requirement is reported against the selected component",
			in:      ResolveInput{Binary: BinaryNode, Compiled: without(InDistro(DistroFull), "capture.proxy"), Selected: []string{"proxy.routing"}},
			want:    []want{{"proxy.routing", StateBlocked, ReasonRequiresNotCompiled, "capture.proxy"}},
			wantErr: "proxy.routing: needs capture.proxy, which is not in this build",
		},
		{
			name: "requires_compiled needs the code, not the activity",
			in:   ResolveInput{Binary: BinaryNode, Compiled: InDistro(DistroFull), Selected: []string{"projects.alignment-judge"}},
			want: []want{
				{"projects.alignment-judge", StateActive, ReasonSelected, ""},
				{"judge.client", StateAvailable, ReasonNotSelected, ""},
			},
		},
		{
			name: "requires_compiled missing blocks",
			in:   ResolveInput{Binary: BinaryNode, Compiled: without(InDistro(DistroFull), "judge.client")},
			want: []want{{"projects.alignment-judge", StateBlocked, ReasonRequiresNotCompiled, "judge.client"}},
		},
		{
			name:    "denied is blocked",
			in:      ResolveInput{Binary: BinaryNode, Selected: []string{"remote"}, Denied: []string{"remote"}},
			want:    []want{{"remote", StateBlocked, ReasonDenied, ""}},
			wantErr: "remote: denied",
		},
		{
			name: "denying a requirement blocks the dependant and says so",
			in:   ResolveInput{Binary: BinaryNode, Selected: []string{"org.update"}, Denied: []string{"org.client"}},
			want: []want{
				{"org.client", StateBlocked, ReasonDenied, ""},
				{"org.update", StateBlocked, ReasonDeniedDependency, "org.client"},
			},
			wantErr: "org.update: requires org.client, which is denied",
		},
		{
			name: "denial propagates transitively",
			in:   ResolveInput{Binary: BinaryNode, Denied: []string{"terminals"}},
			want: []want{{"benchmark", StateBlocked, ReasonDeniedDependency, "terminals"}},
		},
		{
			name:    "unknown selection is an error",
			in:      ResolveInput{Binary: BinaryNode, Selected: []string{"nope"}},
			wantErr: "nope: unknown node component",
		},
		{
			name: "server binary resolves its own rows",
			in:   ResolveInput{Binary: BinaryOrg, Compiled: InImage(ImageCore), Selected: []string{"org.digest"}},
			want: []want{
				{"org.core", StateActive, ReasonCore, ""},
				{"org.digest", StateAbsent, ReasonNotCompiled, ""},
			},
			wantErr: "org.digest: not in this build",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Resolve(tc.in)
			for _, w := range tc.want {
				d, ok := res.Decision(w.id)
				if !ok {
					t.Fatalf("%s: no decision", w.id)
				}
				if d.State != w.state || d.Reason != w.reason || d.Because != w.because {
					t.Errorf("%s: got %s/%s/%q, want %s/%s/%q", w.id, d.State, d.Reason, d.Because, w.state, w.reason, w.because)
				}
			}
			errs := strings.Join(res.Errors, "\n")
			if tc.wantErr == "" && errs != "" {
				t.Errorf("unexpected errors:\n%s", errs)
			}
			if tc.wantErr != "" && !strings.Contains(errs, tc.wantErr) {
				t.Errorf("want an error containing %q, got:\n%s", tc.wantErr, errs)
			}
		})
	}
}

// TestResolveCoversEveryRule fails when a rule of resolveRules has no row
// in TestResolveTable that exercises its reason.
func TestResolveCoversEveryRule(t *testing.T) {
	covered := map[Reason]bool{
		ReasonCore: true, ReasonNotSelected: true, ReasonSelected: true, ReasonRequiredBy: true,
		ReasonNotCompiled: true, ReasonRequiresNotCompiled: true, ReasonDenied: true, ReasonDeniedDependency: true,
		// Managed-policy rows: TestResolveGovernanceTable.
		ReasonAboveCeiling: true, ReasonPolicyDenied: true, ReasonPolicyUnlisted: true,
		ReasonPolicyRequired: true, ReasonGranted: true,
		// Availability rows: TestResolveAvailabilityRows.
		ReasonNotAvailable: true, ReasonNotEntitled: true,
	}
	for _, r := range resolveRules {
		if !covered[r.reason] {
			t.Errorf("rule %q (reason %s) has no table row", r.name, r.reason)
		}
	}
}

func TestResolveDefaultsPerDistro(t *testing.T) {
	for _, d := range Distros() {
		res := Resolve(ResolveInput{Binary: BinaryNode, Compiled: InDistro(d), Selected: DefaultActive(d)})
		if len(res.Errors) != 0 {
			t.Errorf("%s defaults do not resolve cleanly:\n%s", d, strings.Join(res.Errors, "\n"))
		}
	}
}

func without(ids []string, drop string) []string {
	var out []string
	for _, id := range ids {
		if id != drop {
			out = append(out, id)
		}
	}
	return out
}
