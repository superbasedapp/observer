package orgcontract

import (
	"encoding/base64"
	"strings"
	"testing"
)

func servedApprovals() []SecurityBaselineApproval {
	return []SecurityBaselineApproval{
		{Project: "proj-b", RefKind: "commit", Ref: "abc123", ApprovedAt: "2026-10-24T10:00:00Z"},
		{Project: "proj-a", RefKind: "ci_result", Ref: "run-9", ApprovedAt: "2026-10-23T10:00:00Z"},
	}
}

// TestComposeSecurityServedOlderNodeGetsTheAuthoredBody: a caller that
// advertised no served capability (an older node) is served the authored
// body byte for byte, so its closed decoder never sees a field it lacks.
func TestComposeSecurityServedOlderNodeGetsTheAuthoredBody(t *testing.T) {
	authored := []byte(`{"version":1,"finding_share":"findings"}`)
	key := &SecurityOrgDedupe{Version: 1, Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	for _, caps := range [][]string{nil, {SandboxCapabilitySkipRepoScan}} {
		got, err := ComposeSecurityServed(authored, caps, SecurityServedInput{Approvals: servedApprovals(), Dedupe: key})
		if err != nil || string(got) != string(authored) {
			t.Fatalf("caps %v: got %s, %v; want the authored body unchanged", caps, got, err)
		}
	}
	// Nothing to serve: unchanged too, even for a caller that asked.
	got, err := ComposeSecurityServed(authored, []string{SecurityCapabilityBaselineApprovals}, SecurityServedInput{})
	if err != nil || string(got) != string(authored) {
		t.Fatalf("nothing to serve: %s, %v", got, err)
	}
	// An empty authored body stays the signed "none" when nothing is served.
	if got, _ := ComposeSecurityServed(nil, []string{SecurityCapabilityBaselineApprovals}, SecurityServedInput{}); got != nil {
		t.Fatalf("empty body: %s", got)
	}
}

// TestComposeSecurityServedApprovals: a caller that advertised the
// capability gets its approvals in the canonical order; the body decodes
// with this build's closed decoder and keeps the authored fields.
func TestComposeSecurityServedApprovals(t *testing.T) {
	authored := []byte(`{"version":1,"finding_share":"findings"}`)
	got, err := ComposeSecurityServed(authored, []string{SecurityCapabilityBaselineApprovals}, SecurityServedInput{Approvals: servedApprovals()})
	if err != nil {
		t.Fatal(err)
	}
	p, ok, err := DecodeSecurityManagedPolicy(got)
	if err != nil || !ok {
		t.Fatalf("decode: %v %v (%s)", ok, err, got)
	}
	if p.FindingShare != "findings" || len(p.ApprovedBaselines) != 2 || p.ApprovedBaselines[0].Project != "proj-a" || p.OrgDedupe != nil {
		t.Fatalf("composed: %+v", p)
	}
	// From an org that authored nothing: version 1 with the approvals only.
	got, err = ComposeSecurityServed(nil, []string{SecurityCapabilityBaselineApprovals}, SecurityServedInput{Approvals: servedApprovals()})
	if err != nil || !strings.Contains(string(got), `"version":1`) {
		t.Fatalf("from none: %s, %v", got, err)
	}
	if enables := SecurityManagedPolicyEnables(p); len(enables) != 0 {
		t.Fatalf("served fields switch nothing on: %v", enables)
	}
}

// TestValidateSecurityServedRefusals: every malformed served field is
// refused by the closed decoder.
func TestValidateSecurityServedRefusals(t *testing.T) {
	bad := []string{
		`{"version":1,"approved_baselines":[]}`,
		`{"version":1,"approved_baselines":[{"project":"p","ref_kind":"tag","ref":"r","approved_at":"2026-10-24T10:00:00Z"}]}`,
		`{"version":1,"approved_baselines":[{"project":"p/../x","ref_kind":"commit","ref":"r","approved_at":"2026-10-24T10:00:00Z"}]}`,
		`{"version":1,"approved_baselines":[{"project":"p","ref_kind":"commit","ref":"r","approved_at":"yesterday"}]}`,
		`{"version":1,"approved_baselines":[{"project":"p","ref_kind":"commit","ref":"r","approved_at":"2026-10-24T10:00:00Z"},{"project":"p","ref_kind":"commit","ref":"r","approved_at":"2026-10-24T11:00:00Z"}]}`,
		`{"version":1,"org_dedupe":{"version":0,"key":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}}`,
		`{"version":1,"org_dedupe":{"version":1,"key":"` + base64.StdEncoding.EncodeToString(make([]byte, 16)) + `"}}`,
		`{"version":1,"org_dedupe":{"version":1,"key":"not base64!"}}`,
	}
	for _, raw := range bad {
		if _, _, err := DecodeSecurityManagedPolicy([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if got := SecurityServedFields(SecurityManagedPolicyV1{ApprovedBaselines: servedApprovals(), OrgDedupe: &SecurityOrgDedupe{}}); strings.Join(got, ",") != "approved_baselines,org_dedupe" {
		t.Errorf("served fields = %v", got)
	}
}

// TestComposeSecurityServedCapsApprovals: past the cap the newest stay.
func TestComposeSecurityServedCapsApprovals(t *testing.T) {
	var list []SecurityBaselineApproval
	for i := 0; i < MaxSecurityApprovedBaselines+5; i++ {
		ref := "r" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		at := "2026-10-" + []string{"01", "02", "03"}[i%3] + "T10:00:00Z"
		list = append(list, SecurityBaselineApproval{Project: "p", RefKind: "commit", Ref: ref, ApprovedAt: at})
	}
	got, err := ComposeSecurityServed(nil, []string{SecurityCapabilityBaselineApprovals}, SecurityServedInput{Approvals: list})
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := DecodeSecurityManagedPolicy(got)
	if err != nil || len(p.ApprovedBaselines) != MaxSecurityApprovedBaselines {
		t.Fatalf("capped: %d, %v", len(p.ApprovedBaselines), err)
	}
}
