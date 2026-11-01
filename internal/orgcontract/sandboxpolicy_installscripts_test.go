package orgcontract

import (
	"strings"
	"testing"
)

// TestSandboxManagedInstallScripts (lane LEFT-SBX, ruling P-136): the
// optional install_scripts floor validates, is served only to a node that
// advertised the capability (an older node's closed decoder would refuse
// the whole body), and an older body without it decodes unchanged.
func TestSandboxManagedInstallScripts(t *testing.T) {
	h := strings.Repeat("a", 64)
	good := SandboxManagedPolicyV1{Schema: SandboxManagedSchema, InstallScripts: &SandboxManagedInstallScriptsV1{
		Mode: "none", Tools: []string{"claude-code"}, Pins: []SandboxManagedScriptPinV1{{Tool: "claude-code", Version: "2.1.310", SHA256: h}},
	}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := MarshalSandboxManagedPolicy(good)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeSandboxManagedPolicy(b)
	if err != nil || back.InstallScripts == nil || back.InstallScripts.Pins[0].SHA256 != h {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	if old, err := DecodeSandboxManagedPolicy([]byte(`{"schema":"` + SandboxManagedSchema + `","enabled":true}`)); err != nil || old.InstallScripts != nil {
		t.Fatalf("an older body: %+v %v", old, err)
	}
	if got := SandboxInstallScriptsForCaller(good, nil); got.InstallScripts != nil {
		t.Fatal("served to a caller without the capability")
	}
	if got := SandboxInstallScriptsForCaller(good, []string{SandboxCapabilityInstallScripts}); got.InstallScripts == nil {
		t.Fatal("withheld from a caller with the capability")
	}
	bad := []func(s *SandboxManagedInstallScriptsV1){
		func(s *SandboxManagedInstallScriptsV1) { s.Mode = "always" },
		func(s *SandboxManagedInstallScriptsV1) { s.Tools = []string{"Not A Tool"} },
		func(s *SandboxManagedInstallScriptsV1) { s.Pins[0].SHA256 = "x" },
		func(s *SandboxManagedInstallScriptsV1) { s.Pins[0].Version = "latest" },
		func(s *SandboxManagedInstallScriptsV1) { s.Pins[0].Note = "a\nb" },
	}
	for i, edit := range bad {
		c := *good.InstallScripts
		c.Pins = append([]SandboxManagedScriptPinV1(nil), good.InstallScripts.Pins...)
		edit(&c)
		p := good
		p.InstallScripts = &c
		if err := p.Validate(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

// TestSandboxManagedScriptPinPackages (R-014): an org pin may carry the
// registry integrity of the packages its tool's script fetches; they round
// trip through the signed body and malformed ones are refused.
func TestSandboxManagedScriptPinPackages(t *testing.T) {
	integ := "sha512-" + strings.Repeat("A", 86) + "=="
	pin := SandboxManagedScriptPinV1{Tool: "opencode", Version: "1.20.0", SHA256: strings.Repeat("b", 64), Packages: []SandboxManagedPackagePinV1{
		{Name: "opencode-ai", Version: "1.20.0", Integrity: integ},
		{Name: "@opencode/linux-x64", Version: "1.20.0", Integrity: integ},
	}}
	good := SandboxManagedPolicyV1{Schema: SandboxManagedSchema, InstallScripts: &SandboxManagedInstallScriptsV1{Pins: []SandboxManagedScriptPinV1{pin}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := MarshalSandboxManagedPolicy(good)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeSandboxManagedPolicy(b)
	if err != nil || len(back.InstallScripts.Pins[0].Packages) != 2 || back.InstallScripts.Pins[0].Packages[1].Name != "@opencode/linux-x64" {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	for i, edit := range []func(p *SandboxManagedPackagePinV1){
		func(p *SandboxManagedPackagePinV1) { p.Integrity = "sha512-short==" },
		func(p *SandboxManagedPackagePinV1) { p.Integrity = "sha256-" + strings.Repeat("A", 43) + "=" },
		func(p *SandboxManagedPackagePinV1) { p.Name = "Not A Package" },
		func(p *SandboxManagedPackagePinV1) { p.Version = "latest" },
	} {
		c := pin
		c.Packages = append([]SandboxManagedPackagePinV1(nil), pin.Packages...)
		edit(&c.Packages[0])
		p := SandboxManagedPolicyV1{Schema: SandboxManagedSchema, InstallScripts: &SandboxManagedInstallScriptsV1{Pins: []SandboxManagedScriptPinV1{c}}}
		if err := p.Validate(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
