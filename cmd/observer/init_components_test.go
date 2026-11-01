package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWireAIClientsSkipsInactiveComponents pins the init side of the gate:
// with integration.hooks and integration.mcp-server removed, a claude-code
// wire writes (here: would write) only the proxy route, and says why the
// other two were skipped. With the adapter itself removed nothing is wired.
func TestWireAIClientsSkipsInactiveComponents(t *testing.T) {
	requireAdapter(t, "claude-code")
	requireActiveAdapters(t, "claude-code")
	requireComponents(t, "integration.proxy-route")
	requireCompiled(t, "integration.mcp-server")
	cases := []struct {
		name, block string
		want, avoid []string
	}{
		{
			name:  "hooks and mcp removed",
			block: "[components]\nremove = [\"integration.hooks\", \"integration.mcp-server\"]\n",
			want:  []string{"skipped: the integration.hooks component is inactive", "skipped: the integration.mcp-server component is inactive", "route"},
			avoid: []string{"claude-code  hook", "claude-code  mcp"},
		},
		{
			name:  "adapter removed",
			block: "[components]\nremove = [\"adapter.claude-code\"]\n",
			want:  []string{"claude-code", "skipped: the adapter.claude-code component is inactive"},
			avoid: []string{"would register"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := interactiveHome(t)
			cfgPath := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(cfgPath, []byte(tc.block), 0o600); err != nil {
				t.Fatal(err)
			}
			lines, _, _, _, err := wireAIClients(WireAIClientsOptions{
				ConfigPath: cfgPath, ProxyPort: 18820, DryRun: true, HomeDir: home,
				OnlyClaudeCode: true, SkipExtension: true,
			})
			if err != nil {
				t.Fatalf("wireAIClients: %v", err)
			}
			text := strings.Join(lines, "\n")
			for _, w := range tc.want {
				if !strings.Contains(text, w) {
					t.Errorf("lines lack %q:\n%s", w, text)
				}
			}
			for _, a := range tc.avoid {
				if strings.Contains(text, a) {
					t.Errorf("lines contain %q:\n%s", a, text)
				}
			}
		})
	}
}

// TestWireAIClientsReadsTheDefaultConfig pins T-730 / T-742 (D-551): with no
// --config (the `observer init` and `observer enroll --wire-clients` default)
// the gate reads the DEFAULT config's [components] block, as the daemon does.
// Before the fix an empty path resolved the everything-active legacy
// snapshot, so a removed adapter was wired again (this case) and an adapter
// added on top of a distro base was skipped.
func TestWireAIClientsReadsTheDefaultConfig(t *testing.T) {
	requireAdapter(t, "claude-code")
	home := interactiveHome(t)
	cfgDir := filepath.Join(home, ".observer")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	block := "[components]\nremove = [\"adapter.claude-code\"]\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, _, _, _, err := wireAIClients(WireAIClientsOptions{
		ProxyPort: 18820, DryRun: true, HomeDir: home,
		OnlyClaudeCode: true, SkipExtension: true,
	})
	if err != nil {
		t.Fatalf("wireAIClients: %v", err)
	}
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, "skipped: the adapter.claude-code component is inactive") {
		t.Fatalf("a removed adapter was not skipped with no --config:\n%s", text)
	}
	if strings.Contains(text, "would register") {
		t.Fatalf("a removed adapter was wired with no --config:\n%s", text)
	}
}

// TestInitComponentFlagsWriteTheBlock pins --components/--without: the
// selection lands in [components] before any wiring, a dry run writes
// nothing, and an unknown id is refused while the rest applies.
func TestInitComponentFlagsWriteTheBlock(t *testing.T) {
	pinToolHomes(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("# keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	f := initComponentFlags{without: []string{"codeintel", "no-such-id"}}
	if err := f.apply(t.Context(), &out, cfgPath, true); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(cfgPath); string(body) != "# keep me\n" {
		t.Fatalf("dry run wrote: %q", body)
	}
	if !strings.Contains(out.String(), "would set [components]") || !strings.Contains(out.String(), "refused: no-such-id") {
		t.Fatalf("dry-run output: %s", out.String())
	}
	out.Reset()
	f = initComponentFlags{without: []string{"codeintel"}}
	if err := f.apply(t.Context(), &out, cfgPath, false); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), "# keep me") || !strings.Contains(string(body), "\"codeintel\"") {
		t.Fatalf("config after apply:\n%s", body)
	}
	if initGateFor(cfgPath).snap.Active("codeintel") {
		t.Fatal("codeintel still active after init --without codeintel")
	}
	// No --config is the default config under $HOME (T-730, D-551), which
	// holds no [components] block here: an unstamped build keeps everything.
	if unstampedBuild() && !compiledOut("codeintel") && !initGateFor("").snap.Active("codeintel") {
		t.Fatal("an unconfigured default config must keep everything active on an unstamped build")
	}
}
