package openshellorg

import "testing"

// TestProbeLadder: one case per row, each the first failing row over a
// passing base, plus the all-pass case.
func TestProbeLadder(t *testing.T) {
	pass := ProbeFacts{Offered: true, ComponentActive: true, Listed: true, PlatformOK: true, HomeRelayOK: true, LaptopRelay: true, OrgLaptopRelay: LaptopRelayAllowed, SignedIn: true}
	cases := []struct {
		name   string
		change func(*ProbeFacts)
		row    string
		want   string
	}{
		{"all pass", func(*ProbeFacts) {}, "", ""},
		{"R0 not offered", func(f *ProbeFacts) { f.Offered = false; f.Listed = false }, "R0", VerdictNotOffered},
		{"R1 component", func(f *ProbeFacts) { f.ComponentActive = false }, "R1", VerdictComponentInactive},
		{"R1 not listed", func(f *ProbeFacts) { f.Listed = false }, "R1", VerdictNotInBackends},
		{"R2 platform", func(f *ProbeFacts) { f.PlatformOK = false }, "R2", VerdictUnsupportedPlatfm},
		{"R2 custody", func(f *ProbeFacts) { f.Custody = "in_box_api_key" }, "R2", VerdictCustodyNotOffered},
		{"R2 home relay custody explicit", func(f *ProbeFacts) { f.Custody = "home_relay" }, "", ""},
		{"R2 home relay", func(f *ProbeFacts) { f.HomeRelayOK = false }, "R2", VerdictHomeRelayMissing},
		{"R2b forbidden wins over not opted in", func(f *ProbeFacts) { f.OrgLaptopRelay = LaptopRelayForbidden; f.LaptopRelay = false }, "R2b", VerdictLaptopRelayForbid},
		{"R2b not opted in", func(f *ProbeFacts) { f.LaptopRelay = false }, "R2b", VerdictLaptopRelayNoOptIn},
		{"R3 not signed in", func(f *ProbeFacts) { f.SignedIn = false }, "R3", VerdictSigninRequired},
		{"R3 expired", func(f *ProbeFacts) { f.SignInExpired = true }, "R3", VerdictSigninExpired},
	}
	for _, tc := range cases {
		f := pass
		tc.change(&f)
		row, v, why := Probe(f)
		if row != tc.row || v != tc.want || (v != "" && why == "") {
			t.Errorf("%s: %s %s %q", tc.name, row, v, why)
		}
	}
}
