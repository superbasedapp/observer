//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// R-014 (P-136, P-142): user and org pins for a package-fetching tool carry
// the sha512 integrity of the main package and its platform packages into
// the node's script policy, where the same decision and guest check as the
// built-in pins apply; the consent line names them; a pin without integrity
// stays refused by name.
func TestOCIUserAndOrgPinsCarryPackageIntegrity(t *testing.T) {
	integ := func(c string) string { return "sha512-" + strings.Repeat(c, 86) + "==" }
	pkgs := []config.TerminalSandboxOCIPackagePin{
		{Name: "opencode-ai", Version: "1.20.0", Integrity: integ("A")},
		{Name: "opencode-linux-x64", Version: "1.20.0", Integrity: integ("B")},
	}
	userSHA, orgSHA := strings.Repeat("c", 64), strings.Repeat("d", 64)

	t.Run("user pin", func(t *testing.T) {
		cfg := config.TerminalSandboxOCIConfig{InstallScriptPins: []config.TerminalSandboxOCIScriptPin{{Tool: "opencode", Version: "1.20.0", SHA256: userSHA, Packages: pkgs}}}
		d, err := sandboxoci.DecideInstallScripts("opencode", "1.20.0", true, (&ociDriver{r: &sandboxRuntime{}, cfg: cfg}).ociScriptPolicy())
		if err != nil || len(d.Packages) != 2 || d.SHA256[0] != userSHA {
			t.Fatalf("decision %+v, %v; want the user pin with both packages", d, err)
		}
		line := ociScriptLine(d)
		for _, want := range []string{"(user)", "opencode-ai@1.20.0", "opencode-linux-x64@1.20.0", "sha512-AAAA"} {
			if !strings.Contains(line, want) {
				t.Errorf("consent line %q lacks %q", line, want)
			}
		}
	})
	t.Run("org pin", func(t *testing.T) {
		var dst config.TerminalSandboxConfig
		org := orgcontract.SandboxManagedInstallScriptsV1{Pins: []orgcontract.SandboxManagedScriptPinV1{{Tool: "opencode", Version: "1.20.0", SHA256: orgSHA, Packages: []orgcontract.SandboxManagedPackagePinV1{
			{Name: "opencode-ai", Version: "1.20.0", Integrity: integ("A")},
			{Name: "opencode-linux-x64", Version: "1.20.0", Integrity: integ("B")},
		}}}}
		sandboxManagedInstallScriptsFloor(&dst, org)
		d, err := sandboxoci.DecideInstallScripts("opencode", "1.20.0", true, (&ociDriver{r: &sandboxRuntime{}, cfg: dst.OCI}).ociScriptPolicy())
		if err != nil || len(d.Packages) != 2 || d.Pins[0].Source != sandboxoci.PinSourceOrg {
			t.Fatalf("decision %+v, %v; want the org pin with both packages", d, err)
		}
	})
	t.Run("user pin without integrity is refused by name", func(t *testing.T) {
		cfg := config.TerminalSandboxOCIConfig{InstallScriptPins: []config.TerminalSandboxOCIScriptPin{{Tool: "opencode", Version: "1.20.0", SHA256: userSHA}}}
		_, err := sandboxoci.DecideInstallScripts("opencode", "1.20.0", true, (&ociDriver{r: &sandboxRuntime{}, cfg: cfg}).ociScriptPolicy())
		if err == nil || !strings.Contains(err.Error(), sandboxoci.VerdictInstallScriptsUnpinned) || !strings.Contains(err.Error(), userSHA[:12]+" (user)") {
			t.Fatalf("err = %v, want %s naming the user pin", err, sandboxoci.VerdictInstallScriptsUnpinned)
		}
	})
}
