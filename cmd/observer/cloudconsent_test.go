package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
)

// TestStandingTermsAreCommunitySpecific is the "binding-terms-are-community"
// regression for Sol review F2: a community standing grant used to record and
// display the STRUCTURAL rail's endpoint, schema version, data-dictionary
// digest and source-window rule, because cloudStandingTermsByPurpose (or its
// predecessor) fell back to hardcoded structural values regardless of which
// purpose was being granted. This asserts the community entry's every wire
// term is its OWN, and none of them collide with the structural entry's —
// collision would mean the fallback bug is back.
func TestStandingTermsAreCommunitySpecific(t *testing.T) {
	structural, ok := cloudStandingTermsByPurpose[cloudcontract.PurposeStructuralInsights]
	if !ok {
		t.Fatalf("no term set wired up for %q", cloudcontract.PurposeStructuralInsights)
	}
	community, ok := cloudStandingTermsByPurpose[cloudcontract.PurposeCohortBenchmarking]
	if !ok {
		t.Fatalf("no term set wired up for %q", cloudcontract.PurposeCohortBenchmarking)
	}

	if community.envelopeSchemaVersion != cloudcontract.CommunityContributionSchemaVersion {
		t.Errorf("community envelopeSchemaVersion = %q, want %q",
			community.envelopeSchemaVersion, cloudcontract.CommunityContributionSchemaVersion)
	}
	if community.envelopeSchemaVersion == structural.envelopeSchemaVersion {
		t.Errorf("community envelopeSchemaVersion (%q) must not equal the structural rail's (%q)",
			community.envelopeSchemaVersion, structural.envelopeSchemaVersion)
	}

	if got, want := community.dataDictionaryDigest(), cloudcontract.CommunityDataDictionaryDigest(); got != want {
		t.Errorf("community dataDictionaryDigest() = %q, want %q", got, want)
	}
	if community.dataDictionaryDigest() == structural.dataDictionaryDigest() {
		t.Errorf("community dataDictionaryDigest() must not equal the structural rail's digest")
	}

	if community.sourceWindowRule != cloudCommunitySourceWindowRule {
		t.Errorf("community sourceWindowRule = %q, want %q", community.sourceWindowRule, cloudCommunitySourceWindowRule)
	}
	if community.sourceWindowRule == structural.sourceWindowRule {
		t.Errorf("community sourceWindowRule (%q) must not equal the structural rail's (%q)",
			community.sourceWindowRule, structural.sourceWindowRule)
	}

	// The endpoint FUNCTION must be the community rail's own accessor, not the
	// structural one — proven behaviorally: point a gateway at a base URL and
	// confirm the two purposes' terms resolve to two DIFFERENT, purpose-correct
	// endpoints (the community one carrying the community path, never the
	// structural path, and vice versa).
	dir := t.TempDir()
	gw, err := cloudgateway.Open(cloudgateway.Options{
		BaseURL: "https://cloud.example.test",
		CredDir: dir,
	})
	if err != nil {
		t.Fatalf("open gateway: %v", err)
	}

	structuralEndpoint, err := structural.endpoint(gw)
	if err != nil {
		t.Fatalf("structural.endpoint: %v", err)
	}
	communityEndpoint, err := community.endpoint(gw)
	if err != nil {
		t.Fatalf("community.endpoint: %v", err)
	}
	wantStructural, err := gw.StructuralEndpoint()
	if err != nil {
		t.Fatalf("gw.StructuralEndpoint: %v", err)
	}
	wantCommunity, err := gw.CommunityEndpoint()
	if err != nil {
		t.Fatalf("gw.CommunityEndpoint: %v", err)
	}

	if structuralEndpoint != wantStructural {
		t.Errorf("structural.endpoint(gw) = %q, want the gateway's StructuralEndpoint %q", structuralEndpoint, wantStructural)
	}
	if communityEndpoint != wantCommunity {
		t.Errorf("community.endpoint(gw) = %q, want the gateway's CommunityEndpoint %q", communityEndpoint, wantCommunity)
	}
	if communityEndpoint == structuralEndpoint {
		t.Fatalf("community and structural endpoints must differ (both resolved to %q) — a community grant would bind the wrong rail's endpoint", communityEndpoint)
	}

	// Field classes are recorded too — same fallback-bug shape (Sol review F2
	// named this same table), so pin them alongside the rest of the binding.
	if len(community.fieldClasses) == 0 {
		t.Errorf("community fieldClasses must not be empty")
	}
}

// TestCloudStandingFieldClassesJSON pins cloudStandingFieldClassesJSON's two
// observable behaviors: it renders each wired purpose's OWN field classes (not
// a purpose-name string masquerading as one — the placeholder this function
// used to fall back to), and it fails closed to "[]" for a purpose with no
// term set wired up rather than reusing another purpose's classes.
func TestCloudStandingFieldClassesJSON(t *testing.T) {
	cases := []struct {
		name    string
		purpose cloudcontract.Purpose
		want    string
	}{
		{"structural", cloudcontract.PurposeStructuralInsights, `["structural_metrics"]`},
		{"community", cloudcontract.PurposeCohortBenchmarking, `["structural_metrics"]`},
		{"unwired purpose fails closed", cloudcontract.Purpose("no_such_purpose"), `[]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cloudStandingFieldClassesJSON(tc.purpose)
			if got != tc.want {
				t.Errorf("cloudStandingFieldClassesJSON(%q) = %s, want %s", tc.purpose, got, tc.want)
			}
		})
	}
}
