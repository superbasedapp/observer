package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestInstalledVSCodeExtensions reads a fixture home (FU-152): extension
// folders in VS Code's and Cursor's extensions dirs are reported by id with
// the first product that has them; a folder .obsolete lists, a plain file, a
// dotdir and a name with no version are not.
func TestInstalledVSCodeExtensions(t *testing.T) {
	home := t.TempDir()
	mk := func(rel string) {
		if err := os.MkdirAll(filepath.Join(home, filepath.FromSlash(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk(".vscode/extensions/block.vscode-goose-1.4.0")
	mk(".vscode/extensions/google.geminicodeassist-2.98.0")
	mk(".vscode/extensions/.hidden-1.0.0")
	mk(".vscode/extensions/noversion.name")
	mk(".cursor/extensions/block.vscode-goose-1.3.0")
	mk(".cursor/extensions/autohandai.vscode-autohand-0.2.0-darwin-arm64")
	if err := os.WriteFile(filepath.Join(home, ".vscode", "extensions", ".obsolete"), []byte(`{"google.geminicodeassist-2.98.0":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vscode", "extensions", "extensions.json"), []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := installedVSCodeExtensions(crossmount.HomeRoot{Path: home, OS: crossmount.OSLinux, Origin: "pinned"}, nil)
	want := map[string]string{"block.vscode-goose": "vscode", "autohandai.vscode-autohand": "cursor"}
	if len(got) != len(want) {
		t.Fatalf("installed = %v, want %v", got, want)
	}
	for id, host := range want {
		if got[id] != host {
			t.Errorf("%s: host %q, want %q (all: %v)", id, got[id], host, got)
		}
	}
	if len(installedVSCodeExtensions(crossmount.HomeRoot{Path: t.TempDir(), OS: crossmount.OSLinux, Origin: "pinned"}, nil)) != 0 {
		t.Error("an empty home reports extensions")
	}
}

// TestInstalledVSCodeExtensionsFollowsVSCodeExtensions (FU-170): with the
// doctor's VSCODE_EXTENSIONS set to an absolute directory, VS Code's
// extensions are read there and not at the default; a relative value reads
// none of VS Code's.
func TestInstalledVSCodeExtensionsFollowsVSCodeExtensions(t *testing.T) {
	home := t.TempDir()
	relocated := filepath.Join(t.TempDir(), "exts")
	for _, dir := range []string{
		filepath.Join(relocated, "block.vscode-goose-1.4.0"),
		filepath.Join(home, ".vscode", "extensions", "google.geminicodeassist-2.98.0"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h := crossmount.HomeRoot{Path: home, OS: crossmount.OSLinux, Origin: "native"}
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "VSCODE_EXTENSIONS" {
				return v
			}
			return ""
		}
	}
	got := installedVSCodeExtensions(h, env(relocated))
	if got["block.vscode-goose"] != "vscode" || got["google.geminicodeassist"] != "" {
		t.Errorf("relocated: %v, want only the relocated dir's extension, for vscode", got)
	}
	if got := installedVSCodeExtensions(h, env("exts")); len(got) != 0 {
		t.Errorf("relative VSCODE_EXTENSIONS: %v, want none", got)
	}
	if got := installedVSCodeExtensions(h, nil); got["google.geminicodeassist"] != "vscode" || got["block.vscode-goose"] != "" {
		t.Errorf("no environment: %v, want the default dir's extension", got)
	}
}

// TestSurfaceCoverageInstalledHere: a row whose Detect names an installed
// extension is marked "installed here" and its tool's row warns; the other
// tools' rows stay informational.
func TestSurfaceCoverageInstalledHere(t *testing.T) {
	checks := surfaceCoverageChecksWith(map[string]bool{"W": true, "M": true, "L": true}, map[string]string{"block.vscode-goose": "vscode"})
	var goose, other *Check
	for i := range checks {
		switch checks[i].Name {
		case "goose.surfaces":
			goose = &checks[i]
		case "kiro-cli.surfaces":
			other = &checks[i]
		}
	}
	if goose == nil || other == nil {
		t.Fatal("missing goose or kiro-cli surface rows")
	}
	if goose.Status != StatusWarn || !strings.Contains(goose.Message, "installed here") {
		t.Errorf("goose row %+v, want a warning naming an installed surface", *goose)
	}
	found := false
	for _, d := range goose.Details {
		found = found || strings.HasPrefix(d, "installed here (block.vscode-goose in vscode): ")
	}
	if !found {
		t.Errorf("goose details %q lack the installed-here line", goose.Details)
	}
	if other.Status != StatusOK {
		t.Errorf("kiro-cli row %+v, want informational", *other)
	}
}
