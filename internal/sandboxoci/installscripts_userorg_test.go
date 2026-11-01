package sandboxoci

import (
	"strings"
	"testing"
)

// R-014 (P-136, P-142): a user or org pin for a tool whose install script
// fetches more packages counts once it carries the registry integrity of the
// main package and its platform packages; one without integrity is refused
// by name, even beside a pin that has them for the same version.
func TestDecideInstallScriptsUserAndOrgPinsCarryIntegrity(t *testing.T) {
	t.Parallel()
	h, h2 := shaOf("script"), shaOf("other script")
	main := PackagePin{Name: "opencode-ai", Version: "1.20.0", Integrity: integrityOf("main")}
	plat := PackagePin{Name: "opencode-linux-x64", Version: "1.20.0", Integrity: integrityOf("plat")}
	user := ScriptPin{Tool: "opencode", Version: "1.20.0", SHA256: h, Source: PinSourceUser, Packages: []PackagePin{main, plat}}
	org := ScriptPin{Tool: "opencode", Version: "1.20.0", SHA256: h, Source: PinSourceOrg, Packages: []PackagePin{main, plat}}
	bareUser := ScriptPin{Tool: "opencode", Version: "1.20.0", SHA256: h2, Source: PinSourceUser}
	badOrg := ScriptPin{Tool: "opencode", Version: "1.20.0", SHA256: h2, Source: PinSourceOrg, Packages: []PackagePin{{Name: "opencode-ai", Version: "1.20.0", Integrity: "sha512-short=="}}}
	fetching := []string{"opencode"}
	cases := []struct {
		name     string
		pins     []ScriptPin
		wantErr  string // substring; "" = allowed
		wantSHAs []string
		wantPkgs int
	}{
		{"user pin with integrity", []ScriptPin{user}, "", []string{h}, 2},
		{"org pin with integrity", []ScriptPin{org}, "", []string{h}, 2},
		{"user pin without integrity is refused by name", []ScriptPin{bareUser}, h2[:12] + " (user)", nil, 0},
		{"org pin with a malformed integrity is refused by name", []ScriptPin{badOrg}, h2[:12] + " (org)", nil, 0},
		{"a bare pin never adds its script hash beside a pinned one", []ScriptPin{user, bareUser}, "", []string{h}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d, err := DecideInstallScripts("opencode", "1.20.0", true, ScriptPolicy{Pins: c.pins, Fetching: fetching})
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), VerdictInstallScriptsUnpinned) || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %s naming %q", err, VerdictInstallScriptsUnpinned, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want allowed", err)
			}
			if strings.Join(d.SHA256, ",") != strings.Join(c.wantSHAs, ",") || len(d.Packages) != c.wantPkgs {
				t.Fatalf("decision = %+v, want hashes %v and %d packages", d, c.wantSHAs, c.wantPkgs)
			}
		})
	}
}
