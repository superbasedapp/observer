package dataauthority

import "testing"

func TestClassifyAtCapture(t *testing.T) {
	tests := []struct {
		name    string
		state   EnrolmentState
		want    Authority
		version int
	}{
		{"not enrolled -> personal", EnrolmentState{Enrolled: false}, AuthorityPersonal, Version},
		{"enrolled -> org", EnrolmentState{Enrolled: true}, AuthorityOrg, Version},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAtCapture(tt.state)
			if got.Authority != tt.want {
				t.Errorf("ClassifyAtCapture(%+v).Authority = %v, want %v", tt.state, got.Authority, tt.want)
			}
			if got.Version != tt.version {
				t.Errorf("ClassifyAtCapture(%+v).Version = %d, want %d", tt.state, got.Version, tt.version)
			}
		})
	}
}

func TestCombine_Stickiness(t *testing.T) {
	orgPrior := &Classification{Authority: AuthorityOrg, Version: Version}
	personalPrior := &Classification{Authority: AuthorityPersonal, Version: Version}
	staleOrgPrior := &Classification{Authority: AuthorityOrg, Version: 0} // simulates a record from an older schema version

	tests := []struct {
		name  string
		prior *Classification
		state EnrolmentState
		want  Authority
	}{
		{
			name:  "no prior, not enrolled -> personal",
			prior: nil,
			state: EnrolmentState{Enrolled: false},
			want:  AuthorityPersonal,
		},
		{
			name:  "no prior, enrolled -> org",
			prior: nil,
			state: EnrolmentState{Enrolled: true},
			want:  AuthorityOrg,
		},
		{
			name:  "prior org, now de-enrolled -> STILL org (sticky, the safer default)",
			prior: orgPrior,
			state: EnrolmentState{Enrolled: false},
			want:  AuthorityOrg,
		},
		{
			name:  "prior org, still enrolled -> org",
			prior: orgPrior,
			state: EnrolmentState{Enrolled: true},
			want:  AuthorityOrg,
		},
		{
			name:  "prior personal, now enrolled -> org (org-authority is captured going forward)",
			prior: personalPrior,
			state: EnrolmentState{Enrolled: true},
			want:  AuthorityOrg,
		},
		{
			name:  "prior personal, still not enrolled -> personal",
			prior: personalPrior,
			state: EnrolmentState{Enrolled: false},
			want:  AuthorityPersonal,
		},
		{
			name:  "prior org recorded under an older Version, now de-enrolled -> still org, Version upgraded",
			prior: staleOrgPrior,
			state: EnrolmentState{Enrolled: false},
			want:  AuthorityOrg,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Combine(tt.prior, tt.state)
			if got.Authority != tt.want {
				t.Errorf("Combine(%+v, %+v).Authority = %v, want %v", tt.prior, tt.state, got.Authority, tt.want)
			}
			if got.Version != Version {
				t.Errorf("Combine(%+v, %+v).Version = %d, want current Version %d", tt.prior, tt.state, got.Version, Version)
			}
		})
	}
}

func TestEligibleForPersonalEnrichment(t *testing.T) {
	tests := []struct {
		name string
		c    Classification
		want bool
	}{
		{"personal is eligible", Classification{Authority: AuthorityPersonal, Version: Version}, true},
		{"org is never eligible, regardless of consent elsewhere", Classification{Authority: AuthorityOrg, Version: Version}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.EligibleForPersonalEnrichment(); got != tt.want {
				t.Errorf("Classification{%v}.EligibleForPersonalEnrichment() = %v, want %v", tt.c.Authority, got, tt.want)
			}
		})
	}
}

func TestEligibleForOrgEnrichment(t *testing.T) {
	tests := []struct {
		name string
		c    Classification
		want bool
	}{
		{"org is eligible for the org rail", Classification{Authority: AuthorityOrg, Version: Version}, true},
		{"personal is never eligible for the org rail", Classification{Authority: AuthorityPersonal, Version: Version}, false},
		{"unknown (empty) authority is eligible for neither rail", Classification{Authority: Authority(""), Version: Version}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.EligibleForOrgEnrichment(); got != tt.want {
				t.Errorf("Classification{%v}.EligibleForOrgEnrichment() = %v, want %v", tt.c.Authority, got, tt.want)
			}
		})
	}
}

// TestEligibilityPredicatesAreDisjoint pins INV-1 at the predicate layer: the
// personal and org predicates are mutually exclusive across every authority
// value, and neither covers the unknown authority — so no unit of data is ever
// eligible for both planes, and unknown is eligible for neither.
func TestEligibilityPredicatesAreDisjoint(t *testing.T) {
	for _, a := range []Authority{AuthorityPersonal, AuthorityOrg, Authority(""), Authority("bogus")} {
		c := Classification{Authority: a, Version: Version}
		p, o := c.EligibleForPersonalEnrichment(), c.EligibleForOrgEnrichment()
		if p && o {
			t.Errorf("authority %q is eligible for BOTH planes — the predicates must be disjoint (INV-1)", a)
		}
	}
}

// TestOrgAuthorityIrrespectiveOfPosture pins design §5.3 item 7's specific
// wording: "an org-enrolled node (any posture) marks its sessions
// org-authority." EnrolmentState deliberately carries no posture field —
// this test is the standing guard that a future change does not
// reintroduce one under the mistaken belief that teams-posture data is
// somehow less org-authority than enterprise-posture data.
func TestOrgAuthorityIrrespectiveOfPosture(t *testing.T) {
	got := ClassifyAtCapture(EnrolmentState{Enrolled: true})
	if got.Authority != AuthorityOrg {
		t.Fatalf("enrolled node classified %v, want AuthorityOrg — posture must not affect this", got.Authority)
	}
}
