package orgcontract

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHashObsIdentity(t *testing.T) {
	a := HashObsIdentity(ObsIdentityEndUser, "org-1", "alice")
	if len(a) != 64 || a == "alice" {
		t.Fatalf("hash = %q", a)
	}
	if a == HashObsIdentity(ObsIdentityEndUser, "org-2", "alice") {
		t.Error("hash must be org-bound")
	}
	if a == HashObsIdentity(ObsIdentityTenant, "org-1", "alice") {
		t.Error("hash must be kind-separated")
	}
	if HashObsIdentity(ObsIdentityEndUser, "org-1", "") != "" {
		t.Error("empty value must hash to empty")
	}
}

func TestObsTraceRowPrepareForWire(t *testing.T) {
	full := ObsTraceRow{
		TraceID: "t", ProjectRoot: "/p", EndUser: "alice", Tenant: "acme",
		Tags: []string{"x"}, Metadata: map[string]string{"k": "v"}, Service: "svc", Environment: "prod", Release: "1",
	}
	gated := full
	gated.PrepareForWire("org-1", "dev@x", false)
	if gated.OrgID != "org-1" || gated.UserEmail != "dev@x" {
		t.Errorf("attribution = %+v", gated)
	}
	b, _ := json.Marshal(gated)
	for _, leak := range []string{"/p", "alice", "acme", `"x"`, `"k"`, "end_user_hash", "tenant_hash"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("gated row leaks %s: %s", leak, b)
		}
	}
	if gated.EndUserHash != "" || gated.TenantHash != "" {
		t.Errorf("identity hashes ship metadata-only (D23): %+v", gated)
	}
	if gated.Service != "svc" || gated.Environment != "prod" || gated.Release != "1" {
		t.Errorf("always-ship fields missing: %+v", gated)
	}
	raw := full
	raw.PrepareForWire("org-1", "dev@x", true)
	if raw.EndUser != "alice" || raw.Tenant != "acme" || raw.ProjectRoot != "/p" || raw.Metadata["k"] != "v" {
		t.Errorf("raw row stripped: %+v", raw)
	}
	if raw.EndUserHash != HashObsIdentity(ObsIdentityEndUser, "org-1", "alice") || raw.TenantHash != HashObsIdentity(ObsIdentityTenant, "org-1", "acme") {
		t.Errorf("raw row hashes = %q / %q", raw.EndUserHash, raw.TenantHash)
	}
	// A hash a store already set is also stripped metadata-only.
	pre := ObsTraceRow{EndUserHash: "h", TenantHash: "h2"}
	pre.PrepareForWire("org-1", "dev@x", false)
	if pre.EndUserHash != "" || pre.TenantHash != "" {
		t.Errorf("preset hashes survived the gate: %+v", pre)
	}
}

// TestObsSummaryRowPrimaryOmitted: a nil primary count is absent on the wire
// (so a new server can tell a pre-F17 agent), a zero one is present.
func TestObsSummaryRowPrimaryOmitted(t *testing.T) {
	b, _ := json.Marshal(ObsSummaryRow{Day: "d"})
	if strings.Contains(string(b), "traces_primary") {
		t.Errorf("nil primary on the wire: %s", b)
	}
	zero := int64(0)
	b, _ = json.Marshal(ObsSummaryRow{Day: "d", TracesPrimary: &zero})
	if !strings.Contains(string(b), `"traces_primary":0`) {
		t.Errorf("zero primary missing: %s", b)
	}
}
