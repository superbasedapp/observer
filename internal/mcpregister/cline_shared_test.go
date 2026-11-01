//go:build !sbo_omit_agentaccess_relay

package mcpregister

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// The S-6 retarget: current Cline builds (the VS Code extension, the CLI and
// Cline for JetBrains) read ONE shared ~/.cline/data/settings/
// cline_mcp_settings.json. The VS Code globalStorage copy Observer used to
// write is migrated once by the extension and then never read, so every
// write there was dead. Each test below is red on the old registrar.

//nolint:gosec // G101: a fake fixture value, not a credential.
const clineFakeKey = "sk-test-not-real-cline"

func readServers(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var top struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return top.MCPServers
}

func TestClineMCPTargetsTheSharedFile(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		// want is the written file, relative to home unless abs.
		want func(home string) string
	}{
		{"default home", nil, func(home string) string {
			return filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json")
		}},
		{"CLINE_DATA_DIR", map[string]string{"CLINE_DATA_DIR": "<home>/alt-data"}, func(home string) string {
			return filepath.Join(home, "alt-data", "settings", "cline_mcp_settings.json")
		}},
		{"CLINE_DIR", map[string]string{"CLINE_DIR": "<home>/alt-cline"}, func(home string) string {
			return filepath.Join(home, "alt-cline", "data", "settings", "cline_mcp_settings.json")
		}},
		{"CLINE_MCP_SETTINGS_PATH", map[string]string{"CLINE_MCP_SETTINGS_PATH": "<home>/m/mcp.json", "CLINE_DIR": "<home>/alt-cline"}, func(home string) string {
			return filepath.Join(home, "m", "mcp.json")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			env := map[string]string{}
			for k, v := range tc.env {
				env[k] = strings.ReplaceAll(v, "<home>", home)
			}
			want := tc.want(home)
			// The install signal: the data dir the vendor creates at start.
			mustMkdir(t, testClineDataDir(home, runtime.GOOS, func(k string) string { return env[k] }))
			r, err := NewRegistrar(RegisterOptions{
				BinaryPath: "/usr/local/bin/observer", HomeDir: home,
				Getenv: func(k string) string { return env[k] },
			})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(r.Installed(), "cline") {
				t.Fatalf("Installed() = %v: a Cline with only the shared store is not detected", r.Installed())
			}
			res := r.Register("cline")
			if res.Error != nil || !res.Added || res.ConfigPath != want {
				t.Fatalf("Register = %+v, want Added at %s", res, want)
			}
			if _, ok := readServers(t, want)[ServerName]; !ok {
				t.Errorf("no %s entry in %s", ServerName, want)
			}
			legacy := locate.ClineLegacySettingsPath(home, runtime.GOOS)
			if _, err := os.Stat(legacy); err == nil {
				t.Errorf("the dead legacy file %s was written", legacy)
			}
		})
	}
}

// TestClineMCPPinnedHomeIgnoresTheProcessEnvironment: a caller that pinned
// HomeDir and passed no Getenv resolves under its own home even when the
// process carries CLINE_DIR (the sandbox posture).
func TestClineMCPPinnedHomeIgnoresTheProcessEnvironment(t *testing.T) {
	outside := t.TempDir()
	t.Setenv("CLINE_DIR", outside)
	r, home := newRegistrar(t, false)
	res := r.Register("cline")
	want := filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json")
	if res.Error != nil || res.ConfigPath != want {
		t.Fatalf("Register = %+v, want %s", res, want)
	}
	if _, err := os.Stat(filepath.Join(outside, "data")); err == nil {
		t.Error("a pinned-home registrar followed the process CLINE_DIR")
	}
}

// TestClineMCPUnregisterAlsoCleansTheLegacyFile: an uninstall removes the
// entry an older Observer build left in the legacy globalStorage file and
// keeps the user's other servers there byte for byte.
func TestClineMCPUnregisterAlsoCleansTheLegacyFile(t *testing.T) {
	// A provenance record says Observer created the shared file (MACUSER
	// merge M2: with no record a removal never deletes it).
	r, home := newProvenanceRegistrar(t)
	legacy := locate.ClineLegacySettingsPath(home, runtime.GOOS)
	mustMkdir(t, filepath.Dir(legacy))
	// A current install beside the legacy file (a legacy-only install is
	// not written at all: TestClineLegacyOnlyInstallIsNotWritten).
	mustMkdir(t, testClineDataDir(home, runtime.GOOS, nil))
	other := `{"command": "npx", "env": {"TOKEN": "` + clineFakeKey + `"}}`
	legacyBody := "{\n  \"mcpServers\": {\n    \"other\": " + other + ",\n    \"observer\": {\"command\": \"/usr/local/bin/observer\", \"args\": [\"serve\"]}\n  }\n}\n"
	if err := os.WriteFile(legacy, []byte(legacyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cline"); res.Error != nil || !res.Added {
		t.Fatalf("Register = %+v", res)
	}
	ures := r.Unregister("cline")
	if ures.Error != nil || !ures.Removed {
		t.Fatalf("Unregister = %+v", ures)
	}
	// The shared file held only Observer's entry, so it is gone.
	if _, err := os.Stat(ures.ConfigPath); err == nil {
		t.Error("observer's shared file left behind")
	}
	servers := readServers(t, legacy)
	if _, ok := servers[ServerName]; ok {
		t.Error("observer entry left in the legacy file")
	}
	var want, have any
	_ = json.Unmarshal([]byte(other), &want)
	_ = json.Unmarshal(servers["other"], &have)
	if !reflect.DeepEqual(want, have) {
		t.Errorf("the user's other server changed: %s", servers["other"])
	}
}

// TestClineLegacyOnlyInstallIsNotWritten (audit finding 8): when only the
// legacy VS Code globalStorage directory exists, the client has not run a
// current build, so neither the shared file nor the legacy one is written
// and the result says why. The old registrar created the shared file. A
// fresh home (neither store) and a current install still write the shared
// file. Red on the old code.
func TestClineLegacyOnlyInstallIsNotWritten(t *testing.T) {
	cases := []struct {
		name       string
		legacyDir  bool
		currentDir bool
		wantWrite  bool
	}{
		{"legacy only", true, false, false},
		{"legacy and current", true, true, true},
		{"current only", false, true, true},
		{"neither", false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, home := newRegistrar(t, false)
			legacy := locate.ClineLegacySettingsPath(home, runtime.GOOS)
			if tc.legacyDir {
				mustMkdir(t, filepath.Dir(legacy))
			}
			if tc.currentDir {
				mustMkdir(t, testClineDataDir(home, runtime.GOOS, nil))
			}
			shared := filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json")
			res := r.Register("cline")
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			_, statErr := os.Stat(shared)
			if tc.wantWrite {
				if !res.Added || statErr != nil {
					t.Fatalf("Register = %+v, want the shared file written", res)
				}
				return
			}
			if !res.Skipped || res.SkipReason == "" || res.Added {
				t.Fatalf("Register = %+v, want a reasoned skip", res)
			}
			if statErr == nil {
				t.Error("a legacy-only install had the shared file created")
			}
			if _, err := os.Stat(legacy); err == nil {
				t.Error("the legacy file was written")
			}
		})
	}
}

// TestUnregisterWalksDeclaredLegacyPaths (audit finding 4): Unregister
// removes Observer's entry from the legacy file a locate row declares
// (Location.LegacyPath), for every row that declares one, and for no other.
// The old Unregister reached the legacy file only through a tool-name branch.
// An older build wrote that file without a provenance record, so the file
// stays with its server object empty (MACUSER merge M2: no record, no
// delete).
func TestUnregisterWalksDeclaredLegacyPaths(t *testing.T) {
	entry := `{"mcpServers":{"observer":{"command":"/usr/local/bin/observer","args":["serve"]}}}`
	for _, loc := range locate.LocationsEnv("home", nil) {
		if loc.Format != locate.FormatMCPServersJSON {
			continue
		}
		t.Run(loc.Client, func(t *testing.T) {
			r, home := newRegistrar(t, false)
			got, ok := locate.ForClientEnv(loc.Client, home, nil)
			if !ok {
				t.Fatal("no location")
			}
			if got.LegacyPath == "" {
				// No declared legacy file: the result names only the file.
				res := r.Unregister(loc.Client)
				if res.Error != nil || res.Removed {
					t.Fatalf("Unregister = %+v", res)
				}
				return
			}
			mustMkdir(t, filepath.Dir(got.LegacyPath))
			if err := os.WriteFile(got.LegacyPath, []byte(entry), 0o600); err != nil {
				t.Fatal(err)
			}
			res := r.Unregister(loc.Client)
			if res.Error != nil || !res.Removed {
				t.Fatalf("Unregister = %+v, want the legacy entry removed", res)
			}
			servers := readServers(t, got.LegacyPath)
			if _, ok := servers[ServerName]; ok || len(servers) != 0 {
				t.Errorf("legacy file servers = %v, want observer's entry cut and the object empty", servers)
			}
		})
	}
	// The one declaring row today.
	if got, _ := locate.ForClientEnv("cline", "home", nil); got.LegacyPath == "" {
		t.Error("the cline row no longer declares its legacy file")
	}
}

// TestClineWindowsTargetsTheSharedFile: a WSL daemon writes the Windows
// home's shared store, detected by its data dir alone.
func TestClineWindowsTargetsTheSharedFile(t *testing.T) {
	winHome := t.TempDir()
	mustMkdir(t, filepath.Join(winHome, ".cline", "data"))
	forceMCPCrossmount(t, []crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}})
	r, err := NewRegistrar(RegisterOptions{BinaryPath: "/bin/observer", WSLDistro: "Ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(winHome, ".cline", "data", "settings", "cline_mcp_settings.json")
	if got := r.detectWindowsClineSettings(); got != want {
		t.Fatalf("detectWindowsClineSettings() = %q, want %q", got, want)
	}
	// The legacy-only layout is still detected (its first current-build
	// start migrates it), and the write still goes to the shared file.
	legacyOnly := t.TempDir()
	mustMkdir(t, filepath.Dir(locate.ClineLegacySettingsPath(legacyOnly, crossmount.OSWindows)))
	forceMCPCrossmount(t, []crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: legacyOnly}})
	if got, want := r.detectWindowsClineSettings(), filepath.Join(legacyOnly, ".cline", "data", "settings", "cline_mcp_settings.json"); got != want {
		t.Errorf("legacy-only detection = %q, want %q", got, want)
	}
	// Audit finding 8: detected, but never written while legacy-only.
	res := r.Register("cline-windows")
	if res.Error != nil || !res.Skipped || res.Added {
		t.Errorf("Register(cline-windows) on a legacy-only home = %+v, want a reasoned skip", res)
	}
	if _, err := os.Stat(filepath.Join(legacyOnly, ".cline")); err == nil {
		t.Error("a legacy-only Windows home had the shared store created")
	}
}

// TestUnregisterHasNoToolNameBranch pins audit finding 4: Unregister
// dispatches on the location's declared shape (its format, its legacy file,
// the registry's CrossOSBridge flag), never by comparing the tool name with
// a literal (CLAUDE.md rule 3). Red on the old `if tool == "cline"` code.
func TestUnregisterHasNoToolNameBranch(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "register.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Unregister" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			be, ok := n.(*ast.BinaryExpr)
			if !ok || (be.Op != token.EQL && be.Op != token.NEQ) {
				return true
			}
			for _, side := range []ast.Expr{be.X, be.Y} {
				if lit, ok := side.(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value != `""` {
					t.Errorf("%s: Unregister compares with the literal %s", fset.Position(be.Pos()), lit.Value)
				}
			}
			return true
		})
	}
}
