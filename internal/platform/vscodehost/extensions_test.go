package vscodehost

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestExtensionIDFromDir: one case per directory-name shape (FU-152).
func TestExtensionIDFromDir(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		ok         bool
	}{
		{"block.vscode-goose-1.2.3", "block.vscode-goose", true},
		{"ms-python.python-2024.1.0", "ms-python.python", true},
		{"GitHub.copilot-chat-0.20.0", "github.copilot-chat", true},
		{"anthropic.claude-code-2.1.0-linux-x64", "anthropic.claude-code", true},
		{".obsolete", "", false},
		{"extensions.json", "", false},
		{"noversion.name", "", false},
		{"nopublisher-1.0.0", "", false},
		{"", "", false},
	} {
		got, ok := ExtensionIDFromDir(tc.name)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ExtensionIDFromDir(%q) = %q,%v want %q,%v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// TestExtensionsDirs: the grounded products' extensions dirs sit under the
// home root on every OS; an ungrounded product (Kiro, Trae, Qoder, Devin
// Desktop) contributes none, and an unknown OS none at all.
func TestExtensionsDirs(t *testing.T) {
	home := filepath.Join("h", "u")
	for _, os := range []string{crossmount.OSLinux, crossmount.OSDarwin, crossmount.OSWindows} {
		refs := ExtensionsDirs(crossmount.HomeRoot{Path: home, OS: os, Origin: "pinned"}, nil)
		got := map[string]string{}
		for _, r := range refs {
			got[r.Product.Host] = r.Path
		}
		for host, rel := range map[string]string{
			"vscode": ".vscode/extensions", "vscode-insiders": ".vscode-insiders/extensions", "vscodium": ".vscode-oss/extensions",
			"cursor": ".cursor/extensions", "windsurf": ".windsurf/extensions",
			"vscode-remote": ".vscode-server/extensions", "cursor-remote": ".cursor-server/extensions",
		} {
			if got[host] != filepath.Join(home, filepath.FromSlash(rel)) {
				t.Errorf("%s: %s extensions dir %q", os, host, got[host])
			}
		}
		for _, host := range []string{"kiro", "trae", "qoder", "devin-desktop"} {
			if _, ok := got[host]; ok {
				t.Errorf("%s: ungrounded %s has an extensions dir", os, host)
			}
		}
	}
	if refs := ExtensionsDirs(crossmount.HomeRoot{Path: home, OS: "plan9"}, nil); len(refs) != 0 {
		t.Errorf("unknown OS: %v", refs)
	}
}

// TestExtensionsDirsFollowVSCodeExtensions (FU-170): an absolute
// VSCODE_EXTENSIONS moves VS Code's and VS Code Insiders' extensions dir
// (listed once, for VS Code), a relative one reads nothing for them, and
// every other product keeps its default.
func TestExtensionsDirsFollowVSCodeExtensions(t *testing.T) {
	home := t.TempDir()
	abs := filepath.Join(t.TempDir(), "exts")
	h := crossmount.HomeRoot{Path: home, OS: crossmount.OSLinux, Origin: "native"}
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == ExtensionsEnvVar {
				return v
			}
			return ""
		}
	}
	byHost := func(refs []UserDirRef) map[string]string {
		m := map[string]string{}
		for _, r := range refs {
			m[r.Product.Host] = r.Path
		}
		return m
	}
	got := byHost(ExtensionsDirs(h, env(abs)))
	if got["vscode"] != abs {
		t.Errorf("vscode extensions dir = %q, want %q", got["vscode"], abs)
	}
	if _, ok := got["vscode-insiders"]; ok {
		t.Errorf("the shared relocated dir is listed twice: %v", got)
	}
	for _, p := range Products() {
		if p.ExtensionsEnv || p.ExtensionsDir == "" {
			continue
		}
		if want := filepath.Join(home, filepath.FromSlash(p.ExtensionsDir)); got[p.Host] != want {
			t.Errorf("%s moved to %q, want its default %q", p.Host, got[p.Host], want)
		}
	}
	rel := byHost(ExtensionsDirs(h, env("relative/exts")))
	for _, p := range Products() {
		if _, ok := rel[p.Host]; ok && p.ExtensionsEnv {
			t.Errorf("a relative VSCODE_EXTENSIONS still read %s at %q", p.Host, rel[p.Host])
		}
	}
	if _, ok := rel["cursor"]; !ok {
		t.Error("a relative VSCODE_EXTENSIONS dropped a product it does not relocate")
	}
	unset := byHost(ExtensionsDirs(h, env("")))
	if unset["vscode"] != filepath.Join(home, ".vscode", "extensions") {
		t.Errorf("unset: vscode = %q", unset["vscode"])
	}
}
