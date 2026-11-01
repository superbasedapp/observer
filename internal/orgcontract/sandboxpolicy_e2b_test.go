package orgcontract

import (
	"strings"
	"testing"
)

// TestSandboxHostedE2BField (lane SBX-UPD, SBX-GOV-2): the org-published
// E2B endpoint validates as an https origin with an optional pin and
// template, rides the closed body, and is served only to a caller that
// advertised the capability (an older node is served no field).
func TestSandboxHostedE2BField(t *testing.T) {
	good := `{"schema":"sbo-sandbox-managed-v1","hosted_e2b":{"origin":"https://api.e2b.corp.example:8443","spki_sha256":"` + strings.Repeat("a", 64) + `","template":"corp-base"}}`
	p, err := DecodeSandboxManagedPolicy([]byte(good))
	if err != nil || p.HostedE2B == nil || p.HostedE2B.Template != "corp-base" {
		t.Fatalf("decode = %+v %v", p, err)
	}
	for _, bad := range []string{
		`{"schema":"sbo-sandbox-managed-v1","hosted_e2b":{"origin":"http://api.e2b.corp.example"}}`,
		`{"schema":"sbo-sandbox-managed-v1","hosted_e2b":{"origin":"https://api.e2b.corp.example/v2"}}`,
		`{"schema":"sbo-sandbox-managed-v1","hosted_e2b":{"origin":"https://u:p@api.e2b.corp.example"}}`,
		`{"schema":"sbo-sandbox-managed-v1","hosted_e2b":{"origin":"https://api.e2b.corp.example","spki_sha256":"xyz"}}`,
		`{"schema":"sbo-sandbox-managed-v1","hosted_e2b":{"origin":"https://api.e2b.corp.example","template":"a b"}}`,
		`{"schema":"sbo-sandbox-managed-v1","hosted_e2b":{"origin":"https://api.e2b.corp.example","api_key":"k"}}`,
		`{"schema":"sbo-sandbox-managed-v1","hosted_e2b":{"origin":"https://api.e2b.corp.example","enabled":true}}`,
	} {
		if _, err := DecodeSandboxManagedPolicy([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if got := SandboxE2BForCaller(p, nil); got.HostedE2B != nil {
		t.Fatal("served hosted_e2b to a caller that did not advertise it")
	}
	if got := SandboxE2BForCaller(p, []string{SandboxCapabilitySkipRepoScan, SandboxCapabilityE2BEndpoint}); got.HostedE2B == nil {
		t.Fatal("withheld hosted_e2b from a caller that advertised it")
	}
	// A body without the field is the body of before (an older server).
	old := `{"schema":"sbo-sandbox-managed-v1","enabled":true}`
	if q, err := DecodeSandboxManagedPolicy([]byte(old)); err != nil || q.HostedE2B != nil {
		t.Fatalf("an older body: %+v %v", q, err)
	}
}
