package orgcontract

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func goodOrgOpenShell() *SandboxManagedOrgOpenShellV1 {
	return &SandboxManagedOrgOpenShellV1{
		FrontURL: "https://sandbox.example.com", GatewayID: "gw-1",
		Issuer: "https://org.example.com/sandbox-idp", Version: "0.1.6",
		Image:    "registry.example.com/box@sha256:" + strings.Repeat("a", 64),
		IsoClass: "container", Tiers: []string{"none", "proxy_only"},
		BlockedCIDRs: []string{"10.0.0.0/8"}, CloneRepositories: []string{"https://git.example.com/org/repo"},
		BoxBinary: "upload", LaptopRelay: "allowed", HoldPolicy: "on_disconnect",
		MaxHoldHours: 24, ReturnToNode: true, MaxRunMinutes: 120,
		QuotaSummary: SandboxOrgOpenShellQuotaV1{MaxConcurrentPerMember: 2, MaxBoxesPerMember: 3},
	}
}

func TestOrgOpenShellRoundTrip(t *testing.T) {
	p := SandboxManagedPolicyV1{Schema: SandboxManagedSchema, OrgOpenShell: goodOrgOpenShell()}
	raw, err := MarshalSandboxManagedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSandboxManagedPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(p.OrgOpenShell)
	b, _ := json.Marshal(got.OrgOpenShell)
	if string(a) != string(b) {
		t.Fatalf("round trip changed the field:\n%s\n%s", a, b)
	}
}

// An older body (no field) decodes on a new node and offers nothing.
func TestOrgOpenShellOlderBody(t *testing.T) {
	got, err := DecodeSandboxManagedPolicy([]byte(`{"schema":"` + SandboxManagedSchema + `"}`))
	if err != nil || got.OrgOpenShell != nil {
		t.Fatalf("older body: %+v %v", got.OrgOpenShell, err)
	}
}

// A newer body reaches a caller that did not advertise the capability without
// the field: an older node's closed decoder would refuse the whole body.
func TestOrgOpenShellForCaller(t *testing.T) {
	p := SandboxManagedPolicyV1{Schema: SandboxManagedSchema, OrgOpenShell: goodOrgOpenShell()}
	if SandboxOrgOpenShellForCaller(p, []string{SandboxCapabilityE2BEndpoint}).OrgOpenShell != nil {
		t.Fatal("field served without the capability")
	}
	if SandboxOrgOpenShellForCaller(p, []string{SandboxCapabilityOrgOpenShell}).OrgOpenShell == nil {
		t.Fatal("field withheld from a capable caller")
	}
	raw, _ := MarshalSandboxManagedPolicy(SandboxOrgOpenShellForCaller(p, nil))
	if strings.Contains(string(raw), "org_openshell") {
		t.Fatalf("stripped body still names the field: %s", raw)
	}
	// What an older node sees if a server forgot to strip: its closed
	// decoder refuses the whole body (why the server filters per caller).
	type olderBody struct {
		Schema string `json:"schema"`
	}
	full, _ := MarshalSandboxManagedPolicy(p)
	dec := json.NewDecoder(strings.NewReader(string(full)))
	dec.DisallowUnknownFields()
	var o olderBody
	if dec.Decode(&o) == nil {
		t.Fatal("an older closed decoder accepted the new field")
	}
}

func TestOrgOpenShellValidate(t *testing.T) {
	cases := []struct {
		name string
		mut  func(o *SandboxManagedOrgOpenShellV1)
	}{
		{"front url with path", func(o *SandboxManagedOrgOpenShellV1) { o.FrontURL = "https://x.example.com/p" }},
		{"front url http", func(o *SandboxManagedOrgOpenShellV1) { o.FrontURL = "http://x.example.com" }},
		{"bad pin", func(o *SandboxManagedOrgOpenShellV1) { o.FrontTLSSPKISHA256 = "zz" }},
		{"bad gateway id", func(o *SandboxManagedOrgOpenShellV1) { o.GatewayID = "GW" }},
		{"issuer http", func(o *SandboxManagedOrgOpenShellV1) { o.Issuer = "http://o/sandbox-idp" }},
		{"version", func(o *SandboxManagedOrgOpenShellV1) { o.Version = "latest" }},
		{"image by tag", func(o *SandboxManagedOrgOpenShellV1) { o.Image = "registry.example.com/box:latest" }},
		{"iso class", func(o *SandboxManagedOrgOpenShellV1) { o.IsoClass = "microvm" }},
		{"tier host", func(o *SandboxManagedOrgOpenShellV1) { o.Tiers = []string{"host"} }},
		{"no tiers", func(o *SandboxManagedOrgOpenShellV1) { o.Tiers = nil }},
		{"cidr unmasked", func(o *SandboxManagedOrgOpenShellV1) { o.BlockedCIDRs = []string{"10.0.0.1/8"} }},
		{"host with scheme", func(o *SandboxManagedOrgOpenShellV1) { o.EgressAllowHosts = []string{"https://pypi.org"} }},
		{"clone repo helper", func(o *SandboxManagedOrgOpenShellV1) { o.CloneRepositories = []string{"ext::sh"} }},
		{"box binary", func(o *SandboxManagedOrgOpenShellV1) { o.BoxBinary = "copy" }},
		{"laptop relay required", func(o *SandboxManagedOrgOpenShellV1) { o.LaptopRelay = "required" }},
		{"hold policy", func(o *SandboxManagedOrgOpenShellV1) { o.HoldPolicy = "always" }},
		{"hold hours", func(o *SandboxManagedOrgOpenShellV1) { o.MaxHoldHours = 169 }},
		{"run minutes", func(o *SandboxManagedOrgOpenShellV1) { o.MaxRunMinutes = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := goodOrgOpenShell()
			tc.mut(o)
			err := SandboxManagedPolicyV1{Schema: SandboxManagedSchema, OrgOpenShell: o}.Validate()
			if !errors.Is(err, ErrSandboxManagedBody) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if err := (SandboxManagedPolicyV1{Schema: SandboxManagedSchema, OrgOpenShell: goodOrgOpenShell()}).Validate(); err != nil {
		t.Fatal(err)
	}
}
