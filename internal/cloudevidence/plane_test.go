package cloudevidence

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// TestBuildEnvelopePlaneAuthorityMatrix is the INV-1 pin at the builder layer:
// the closed {personal, org, unknown} × {personal plane, org plane} matrix has
// exactly two accepting cells (personal→personal, org→org) and four refusing
// cells. It drives BuildEnvelope over all six and asserts each outcome, so the
// planeEligibility table cannot be quietly widened. INV-10 (an enterprise node
// never dual-submits — the personal builder still refuses org authority) falls
// out of the {org, personal-plane} = refuse cell.
func TestBuildEnvelopePlaneAuthorityMatrix(t *testing.T) {
	authorities := map[string]dataauthority.Classification{
		"personal": {Authority: dataauthority.AuthorityPersonal, Version: dataauthority.Version},
		"org":      {Authority: dataauthority.AuthorityOrg, Version: dataauthority.Version},
		// "unknown" is any authority that is neither personal nor org — a NULL /
		// pre-096 row / fail-closed enrolment read. The empty zero value is the
		// canonical unknown.
		"unknown": {Authority: dataauthority.Authority(""), Version: dataauthority.Version},
	}

	for _, tc := range []struct {
		authority  string
		plane      cloudcontract.Plane
		wantAccept bool
	}{
		{"personal", cloudcontract.PlanePersonal, true},
		{"org", cloudcontract.PlanePersonal, false},
		{"unknown", cloudcontract.PlanePersonal, false},
		{"personal", cloudcontract.PlaneOrg, false},
		{"org", cloudcontract.PlaneOrg, true},
		{"unknown", cloudcontract.PlaneOrg, false},
	} {
		name := tc.authority + "_authority/" + string(tc.plane) + "_plane"
		t.Run(name, func(t *testing.T) {
			in := baseInput()
			in.Authority = authorities[tc.authority]
			env, err := BuildEnvelope(in, tc.plane, structuralOpts())
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("want accept, got refusal: %v", err)
				}
				if env == nil {
					t.Fatal("want accept, got nil envelope")
				}
				return
			}
			if err == nil {
				t.Fatalf("want refusal for %s authority on the %q plane, got a built envelope", tc.authority, tc.plane)
			}
			if env != nil {
				t.Fatalf("a refused build must return a nil envelope, got %+v", env)
			}
		})
	}

	// The empty zero-value plane matches no row and must be refused even for
	// otherwise-eligible personal data — the plane is a required input.
	t.Run("empty_plane_is_refused", func(t *testing.T) {
		if _, err := BuildEnvelope(baseInput(), cloudcontract.Plane(""), structuralOpts()); err == nil {
			t.Fatal("an empty plane must be refused (plane is required)")
		}
	})
}

// TestPlaneTableMatchesAuthorityPredicates cross-checks the builder's
// planeEligibility table against dataauthority's two predicates so they cannot
// drift: the personal-plane column must equal EligibleForPersonalEnrichment and
// the org-plane column must equal EligibleForOrgEnrichment for every authority.
func TestPlaneTableMatchesAuthorityPredicates(t *testing.T) {
	for _, c := range []dataauthority.Classification{
		{Authority: dataauthority.AuthorityPersonal},
		{Authority: dataauthority.AuthorityOrg},
		{Authority: dataauthority.Authority("")},
		{Authority: dataauthority.Authority("bogus")},
	} {
		if got, want := eligibleForPlane(cloudcontract.PlanePersonal, c), c.EligibleForPersonalEnrichment(); got != want {
			t.Errorf("personal plane for authority %q: table=%v predicate=%v", c.Authority, got, want)
		}
		if got, want := eligibleForPlane(cloudcontract.PlaneOrg, c), c.EligibleForOrgEnrichment(); got != want {
			t.Errorf("org plane for authority %q: table=%v predicate=%v", c.Authority, got, want)
		}
	}
}
