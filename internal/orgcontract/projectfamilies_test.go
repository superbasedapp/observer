package orgcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// TestProjectFamiliesSigning pins the families signing message (lane
// sec-p3): an envelope with members is signed under its own domain over the
// families digest, so it never verifies once the members or the digest are
// changed, and an envelope with none signs exactly as in P1.
func TestProjectFamiliesSigning(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"require":{"max_advisory_db_age_h":24},"version":1}`
	m := ProjectFamilyMember{Family: "security.scanning", Version: 3, Projects: []string{"X", "Y"}, Body: body, BodyHash: ProjectFamilyBodyHash(body)}
	bind := ProjectBinding{OrgID: "org", Subject: "u-dana", OrgProjectID: "X", Epoch: 2}
	plain := PolicyBundleV3SigningMessage(7, []byte("# t\n"), bind)
	bind.FamiliesDigest = ProjectFamiliesDigest([]ProjectFamilyMember{m})
	withFam := PolicyBundleV3SigningMessage(7, []byte("# t\n"), bind)
	if string(plain[:len(policyBundleSigningV3Domain)]) != policyBundleSigningV3Domain ||
		string(withFam[:len(policyBundleSigningV3FamiliesDomain)]) != policyBundleSigningV3FamiliesDomain {
		t.Fatal("the two forms must open with their own domains")
	}
	if ProjectFamiliesDigest(nil) != "" {
		t.Fatal("no member must digest to empty (P1 message unchanged)")
	}

	env := PolicyBundle{
		Version: 7, BundleTOML: "# t\n", ProjectBinding: &bind, Families: []ProjectFamilyMember{m},
		PublicKey: base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
	}
	env.Signature = SignPolicyBundleEnvelope(priv, env)
	if _, err := VerifyPolicyBundle(env); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := CheckProjectFamilies(env); err != nil {
		t.Fatalf("check: %v", err)
	}
	stripped := env
	sb := *env.ProjectBinding
	sb.FamiliesDigest = ""
	stripped.ProjectBinding, stripped.Families = &sb, nil
	if _, err := VerifyPolicyBundle(stripped); err == nil {
		t.Fatal("an envelope with its members and digest stripped verified")
	}

	rows := []struct {
		name   string
		mutate func(e *PolicyBundle)
	}{
		{"body swapped", func(e *PolicyBundle) { e.Families[0].Body = `{"version":1}` }},
		{"version zero", func(e *PolicyBundle) { e.Families[0].Version = 0 }},
		{"no family", func(e *PolicyBundle) { e.Families[0].Family = "" }},
		{"project not in the audience", func(e *PolicyBundle) { e.Families[0].Projects = []string{"Y"} }},
		{"listed twice", func(e *PolicyBundle) { e.Families = append(e.Families, e.Families[0]) }},
		{"digest with no member", func(e *PolicyBundle) { e.Families = nil }},
		{"members on the composed bundle", func(e *PolicyBundle) {
			b := *e.ProjectBinding
			b.OrgProjectID = ""
			e.ProjectBinding = &b
		}},
		{"capability added", func(e *PolicyBundle) { e.Families[0].RequiredCapabilities = []string{"security.deps.v1"} }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e := env
			e.Families = append([]ProjectFamilyMember(nil), env.Families...)
			r.mutate(&e)
			if err := CheckProjectFamilies(e); !errors.Is(err, ErrProjectFamilies) {
				t.Fatalf("err = %v, want ErrProjectFamilies", err)
			}
		})
	}
}

// TestValidProjectFamilyStatus: the closed vocabulary, one row per refusal.
func TestValidProjectFamilyStatus(t *testing.T) {
	ok := ProjectFamilySectionState{OrgProjectID: "p1", Family: "security.scanning", Version: 2, Status: ProjectFamilyRefused}
	if !ValidProjectFamilyStatus(nil) || !ValidProjectFamilyStatus([]ProjectFamilySectionState{ok}) {
		t.Fatal("a valid list was refused")
	}
	for name, e := range map[string]ProjectFamilySectionState{
		"empty project": {Family: "security.scanning", Version: 2, Status: ProjectFamilyApplied},
		"space in id":   {OrgProjectID: "p 1", Family: "security.scanning", Version: 2, Status: ProjectFamilyApplied},
		"other family":  {OrgProjectID: "p1", Family: "node.features", Version: 2, Status: ProjectFamilyApplied},
		"no version":    {OrgProjectID: "p1", Family: "security.scanning", Status: ProjectFamilyApplied},
		"bad status":    {OrgProjectID: "p1", Family: "security.scanning", Version: 2, Status: "fine"},
		// SEC-P3 merge finding 2: the refused axes of a partial section.
		"partial without axes":   {OrgProjectID: "p1", Family: "security.scanning", Version: 2, Status: ProjectFamilyPartial},
		"axes on an applied one": {OrgProjectID: "p1", Family: "security.scanning", Version: 2, Status: ProjectFamilyApplied, RefusedAxes: []string{"allow.online_checks"}},
		"axis not axis-shaped":   {OrgProjectID: "p1", Family: "security.scanning", Version: 2, Status: ProjectFamilyPartial, RefusedAxes: []string{"Allow online"}},
		"axes not sorted":        {OrgProjectID: "p1", Family: "security.scanning", Version: 2, Status: ProjectFamilyPartial, RefusedAxes: []string{"require.online_checks", "allow.online_checks"}},
		"axis listed twice":      {OrgProjectID: "p1", Family: "security.scanning", Version: 2, Status: ProjectFamilyPartial, RefusedAxes: []string{"allow.online_checks", "allow.online_checks"}},
	} {
		if ValidProjectFamilyStatus([]ProjectFamilySectionState{e}) {
			t.Errorf("%s was accepted", name)
		}
	}
	partial := ProjectFamilySectionState{OrgProjectID: "p1", Family: "security.scanning", Version: 3, Status: ProjectFamilyPartial, RefusedAxes: []string{"allow.online_checks", "require.online_checks"}}
	if !ValidProjectFamilyStatus([]ProjectFamilySectionState{partial}) {
		t.Error("a partial section naming its axes was refused")
	}
	if ValidProjectFamilyStatus([]ProjectFamilySectionState{ok, ok}) {
		t.Error("a section listed twice was accepted")
	}
	for s, acked := range map[string]bool{ProjectFamilyApplied: true, ProjectFamilyNotMatched: true, ProjectFamilyUnknown: false, ProjectFamilyNotDelivered: false, ProjectFamilyRefused: false, ProjectFamilyInert: false, ProjectFamilyPartial: false, "x": false} {
		if ProjectFamilyAcked(s) != acked {
			t.Errorf("%s acked = %v", s, !acked)
		}
	}
}
