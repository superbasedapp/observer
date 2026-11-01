package orgcontract

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestDecodeSandboxManagedPolicy walks the body's accept and refuse rows.
func TestDecodeSandboxManagedPolicy(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"schema only", `{"schema":"sbo-sandbox-managed-v1"}`, ""},
		{"every key", `{"schema":"sbo-sandbox-managed-v1","enabled":true,"backends":["bwrap"],"default_on":true,
			"egress":"proxy_only","egress_allow_cidrs":["10.20.0.0/16"],"allow_tool_config_writes":false,
			"allow_remote_clone":true,"remote_allowed_hosts":["github.com"],"workspace_retention_days":7,
			"mask_paths":["/mnt/c"],"prep_timeout_seconds":600,
			"node":{"extra_ro_binds":["/opt/tools"],"extra_rw_binds":["/srv/cache"]}}`, ""},
		{"empty backends enables nothing", `{"schema":"sbo-sandbox-managed-v1","backends":[]}`, ""},
		{"wrong schema", `{"schema":"sbo-security-managed-v1"}`, "schema"},
		{"missing schema", `{"enabled":true}`, "schema"},
		{"unknown key", `{"schema":"sbo-sandbox-managed-v1","home_mode":"readonly"}`, "unknown field"},
		{"egress none", `{"schema":"sbo-sandbox-managed-v1","egress":"none"}`, "loses capture"},
		{"egress unknown", `{"schema":"sbo-sandbox-managed-v1","egress":"open"}`, "egress"},
		{"bad backend id", `{"schema":"sbo-sandbox-managed-v1","backends":["Bwrap"]}`, "backends"},
		{"duplicate backend", `{"schema":"sbo-sandbox-managed-v1","backends":["bwrap","bwrap"]}`, "twice"},
		{"non-canonical cidr", `{"schema":"sbo-sandbox-managed-v1","egress_allow_cidrs":["10.20.1.0/16"]}`, "egress_allow_cidrs"},
		{"host with credential", `{"schema":"sbo-sandbox-managed-v1","remote_allowed_hosts":["user:pw@github.com"]}`, "remote_allowed_hosts"},
		{"retention negative", `{"schema":"sbo-sandbox-managed-v1","workspace_retention_days":-1}`, "workspace_retention_days"},
		{"prep below bound", `{"schema":"sbo-sandbox-managed-v1","prep_timeout_seconds":5}`, "prep_timeout_seconds"},
		{"relative mask", `{"schema":"sbo-sandbox-managed-v1","mask_paths":["mnt/c"]}`, "mask_paths"},
		{"unclean node path", `{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["/srv/../etc"]}}`, "extra_rw_binds"},
		{"trailing data", `{"schema":"sbo-sandbox-managed-v1"}{}`, "after top-level value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeSandboxManagedPolicy([]byte(tc.body))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want accepted: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrSandboxManagedBody) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want refused with %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestSandboxManagedNeverEnablesCaptureLosingModes: allow_reduced_capture and
// provider key injection are refused by name, at any level and any case.
func TestSandboxManagedNeverEnablesCaptureLosingModes(t *testing.T) {
	for _, body := range []string{
		`{"schema":"sbo-sandbox-managed-v1","allow_reduced_capture":true}`,
		`{"schema":"sbo-sandbox-managed-v1","Allow_Reduced_Capture":true}`,
		`{"schema":"sbo-sandbox-managed-v1","provider_injected":true}`,
		`{"schema":"sbo-sandbox-managed-v1","key_custody":"provider_injected"}`,
		`{"schema":"sbo-sandbox-managed-v1","node":{"provider_key_injection":"allowed"}}`,
	} {
		_, err := DecodeSandboxManagedPolicy([]byte(body))
		if err == nil || !strings.Contains(err.Error(), string(SandboxRefusedCaptureLosing)) {
			t.Errorf("%s: want a capture_losing_mode refusal, got %v", body, err)
		}
	}
}

// TestSandboxManagedNeverCarriesACredential: credential-shaped keys are
// refused by name wherever they appear.
func TestSandboxManagedNeverCarriesACredential(t *testing.T) {
	for _, body := range []string{
		`{"schema":"sbo-sandbox-managed-v1","token":"x"}`,
		`{"schema":"sbo-sandbox-managed-v1","node":{"credential":{"value":"x"}}}`,
		`{"schema":"sbo-sandbox-managed-v1","node":{"api_key":"sk-test"}}`,
		`{"schema":"sbo-sandbox-managed-v1","kubeconfig":"apiVersion: v1"}`,
	} {
		_, err := DecodeSandboxManagedPolicy([]byte(body))
		if err == nil || !strings.Contains(err.Error(), string(SandboxRefusedCredentialValue)) {
			t.Errorf("%s: want a credential_value refusal, got %v", body, err)
		}
	}
}

// TestMarshalSandboxManagedPolicyRoundTrip: the canonical encoding decodes
// back to the same body, and an invalid body is never encoded.
func TestMarshalSandboxManagedPolicyRoundTrip(t *testing.T) {
	on, days := true, 3
	backends := []string{"bwrap"}
	p := SandboxManagedPolicyV1{Schema: SandboxManagedSchema, Enabled: &on, Backends: &backends, WorkspaceRetentionDays: &days}
	raw, err := MarshalSandboxManagedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSandboxManagedPolicy(raw)
	if err != nil || *got.Enabled != true || (*got.Backends)[0] != "bwrap" || *got.WorkspaceRetentionDays != 3 {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	none := "none"
	if _, err := MarshalSandboxManagedPolicy(SandboxManagedPolicyV1{Schema: SandboxManagedSchema, Egress: &none}); err == nil {
		t.Fatal("an invalid body must not be encoded")
	}
	if rail, ok := LookupManagedPullRail("sandbox"); !ok || rail.Domain != SandboxManagedSchema {
		t.Fatalf("the schema must equal the rail's domain: %+v", rail)
	}
}

// TestSandboxSkipRepoScan (ruling P-060, ledger SBX-GOV-3): skip_repo_scan
// is a parallel list whose every entry equals an extra_rw_binds entry; one
// that names no write bind is refused by name.
func TestSandboxSkipRepoScan(t *testing.T) {
	ok := `{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["/srv/cache","/srv/work"],"skip_repo_scan":["/srv/cache"]}}`
	p, err := DecodeSandboxManagedPolicy([]byte(ok))
	if err != nil {
		t.Fatalf("a skip entry naming a write bind: %v", err)
	}
	if p.Node == nil || p.Node.SkipRepoScan == nil || (*p.Node.SkipRepoScan)[0] != "/srv/cache" {
		t.Fatalf("decoded node %+v", p.Node)
	}
	for name, body := range map[string]string{
		"not a bind":       `{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["/srv/cache"],"skip_repo_scan":["/srv/other"]}}`,
		"no binds":         `{"schema":"sbo-sandbox-managed-v1","node":{"skip_repo_scan":["/srv/cache"]}}`,
		"a read bind":      `{"schema":"sbo-sandbox-managed-v1","node":{"extra_ro_binds":["/srv/cache"],"skip_repo_scan":["/srv/cache"]}}`,
		"twice":            `{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["/srv/cache"],"skip_repo_scan":["/srv/cache","/srv/cache"]}}`,
		"relative":         `{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["/srv/cache"],"skip_repo_scan":["srv/cache"]}}`,
		"another spelling": `{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["/srv/cache"],"skip_repo_scan":["/srv/cache/"]}}`,
	} {
		_, err := DecodeSandboxManagedPolicy([]byte(body))
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err = DecodeSandboxManagedPolicy([]byte(`{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["/srv/cache"],"skip_repo_scan":["/srv/x"]}}`))
	if err == nil || !strings.Contains(err.Error(), string(SandboxRefusedSkipScanNotABind)) || !strings.Contains(err.Error(), "/srv/x") {
		t.Fatalf("refusal does not name the entry and reason: %v", err)
	}
}

// TestSandboxSkipRepoScanForCaller: the server serves skip_repo_scan only
// to a caller that advertised the capability; otherwise the field is gone
// and, when nothing else is left, the node part too.
func TestSandboxSkipRepoScanForCaller(t *testing.T) {
	rw := []string{"/srv/cache"}
	skip := []string{"/srv/cache"}
	n := &SandboxManagedNodeV1{ExtraRWBinds: &rw, SkipRepoScan: &skip}
	if got := SandboxSkipRepoScanForCaller(n, []string{"other", SandboxCapabilitySkipRepoScan}); got != n {
		t.Fatalf("a capable caller lost the field: %+v", got)
	}
	got := SandboxSkipRepoScanForCaller(n, nil)
	if got == nil || got.SkipRepoScan != nil || got.ExtraRWBinds == nil {
		t.Fatalf("an older caller: %+v", got)
	}
	if n.SkipRepoScan == nil {
		t.Fatal("the stored node was changed")
	}
	if got := SandboxSkipRepoScanForCaller(&SandboxManagedNodeV1{SkipRepoScan: &skip}, nil); got != nil {
		t.Fatalf("a node part with only the field: %+v", got)
	}
	if SandboxSkipRepoScanForCaller(nil, nil) != nil {
		t.Fatal("nil in, not nil out")
	}
}

// TestParseManagedPullCapabilities pins the header's reading.
func TestParseManagedPullCapabilities(t *testing.T) {
	got := ParseManagedPullCapabilities(" sandbox.skip_repo_scan, ,x,x," + strings.Repeat("y", 65))
	if len(got) != 2 || got[0] != SandboxCapabilitySkipRepoScan || got[1] != "x" {
		t.Fatalf("parsed %q", got)
	}
	if ParseManagedPullCapabilities("") != nil {
		t.Fatal("an empty header has tokens")
	}
}

// TestSandboxOlderDecoderRefusesSkipRepoScan pins why the field is served
// only by capability: a closed decoder without the field (an older node)
// refuses a body carrying it.
func TestSandboxOlderDecoderRefusesSkipRepoScan(t *testing.T) {
	type olderNode struct {
		ExtraROBinds *[]string `json:"extra_ro_binds,omitempty"`
		ExtraRWBinds *[]string `json:"extra_rw_binds,omitempty"`
	}
	dec := json.NewDecoder(strings.NewReader(`{"extra_rw_binds":["/srv/cache"],"skip_repo_scan":["/srv/cache"]}`))
	dec.DisallowUnknownFields()
	var n olderNode
	if err := dec.Decode(&n); err == nil {
		t.Fatal("an older closed decoder accepted skip_repo_scan")
	}
}
