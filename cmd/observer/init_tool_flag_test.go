package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestInitToolFlagSelectsCopilotCLI is the 2026-10-21 live proof gap: Copilot
// CLI was reachable from `observer init` only through --all. --tool selects it
// (and only it) by registry id.
func TestInitToolFlagSelectsCopilotCLI(t *testing.T) {
	if !autoInitSupported("copilot-cli") {
		t.Fatal("autoInitSupported(copilot-cli) = false: the registry no longer gives copilot-cli an init-writable capability")
	}
	installed := []string{"claude-code", "codex", "copilot-cli"}
	got := selectToolsForInit(false, []string{"copilot-cli"}, installed)
	if !slices.Equal(got, []string{"copilot-cli"}) {
		t.Errorf("--tool copilot-cli selected %v, want only copilot-cli", got)
	}
	// Combined with a classic alias flag, both are selected.
	got = selectToolsForInit(false, aliasTools([]bool{false, true}, []string{"copilot-cli"}), installed)
	slices.Sort(got)
	if !slices.Equal(got, []string{"codex", "copilot-cli"}) {
		t.Errorf("--codex --tool copilot-cli selected %v, want codex + copilot-cli", got)
	}
}

// TestInitToolAliasesMatchToolFlag: each per-product flag selects exactly
// what --tool with its id selects, cross-OS Windows union included, so the
// flags keep their behaviour as aliases; every alias names an init-wireable
// registry id and a flag `observer init` registers.
func TestInitToolAliasesMatchToolFlag(t *testing.T) {
	installed := []string{"claude-code", "claude-code-windows", "codex", "codex-windows", "cursor", "cline", "copilot-cli", "antigravity-cli", "antigravity-cli-windows"}
	seen := map[string]bool{}
	for i, a := range initToolAliases {
		if seen[a.flag] {
			t.Errorf("--%s is listed twice", a.flag)
		}
		seen[a.flag] = true
		if !autoInitSupported(a.tool) {
			t.Errorf("--%s aliases %s, which `observer init` cannot wire", a.flag, a.tool)
		}
		flags := make([]bool, len(initToolAliases))
		flags[i] = true
		alias := selectToolsForInit(false, aliasTools(flags, nil), installed)
		byID := selectToolsForInit(false, []string{a.tool}, installed)
		slices.Sort(alias)
		slices.Sort(byID)
		if !slices.Equal(alias, byID) {
			t.Errorf("--%s selected %v, --tool %s selected %v", a.flag, alias, a.tool, byID)
		}
		if !slices.Contains(alias, a.tool) {
			t.Errorf("--%s did not select %s: %v", a.flag, a.tool, alias)
		}
		if cmd := newInitCmd(); cmd.Flags().Lookup(a.flag) == nil {
			t.Errorf("the --%s flag is not registered", a.flag)
		}
	}
	// No selector at all still means "every detected tool".
	if got := selectToolsForInit(false, nil, installed); len(got) == 0 {
		t.Error("no selector selected nothing, want every detected tool")
	}
}

// TestInitAntigravityFlagCoversEveryAntigravityID (FU-174): every Antigravity
// registry id `observer init --all` can wire is reached by --antigravity
// alone, and nothing else is.
func TestInitAntigravityFlagCoversEveryAntigravityID(t *testing.T) {
	var ids []string
	for _, tool := range integration.Tools() {
		if strings.HasPrefix(tool, "antigravity") && autoInitSupported(tool) {
			ids = append(ids, tool)
		}
	}
	if len(ids) == 0 {
		t.Fatal("no Antigravity registry id is init-wireable; --antigravity would select nothing")
	}
	installed := append([]string{"claude-code", "codex", "cursor", "copilot-cli"}, ids...)
	all := selectToolsForInit(true, nil, installed)
	var want []string
	for _, tool := range all {
		if strings.HasPrefix(tool, "antigravity") {
			want = append(want, tool)
		}
	}
	got := selectToolsForInit(false, aliasTools(aliasOn(t, "antigravity"), nil), installed)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("--antigravity selected %v, want exactly the Antigravity ids --all selects %v", got, want)
	}
}

// aliasOn is the aliasTools switch slice with only the named flag on.
func aliasOn(t *testing.T, flag string) []bool {
	t.Helper()
	on := make([]bool, len(initToolAliases))
	for i, a := range initToolAliases {
		if a.flag == flag {
			on[i] = true
			return on
		}
	}
	t.Fatalf("no --%s alias in initToolAliases", flag)
	return nil
}

// TestInitAntigravityFlagThroughCobra (FU-174): `observer init --antigravity
// --dry-run` in an isolated home with Claude Code and the agy CLI both
// present plans only the Antigravity hooks file, and --help lists the flag.
func TestInitAntigravityFlagThroughCobra(t *testing.T) {
	// Registration runs only for active adapters; a stamped edition that
	// leaves them inactive by default (minimal, managed) registers nothing
	// (RB1 gate: these failed under the minimal edition's tag set).
	requireActiveAdapters(t, "antigravity-cli")
	home := t.TempDir()
	pinToolHomesAt(t, home)
	t.Setenv(crossmount.EnvDisableForeignHomes, "1")
	for _, dir := range []string{".claude", filepath.Join(".gemini", "antigravity-cli")} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(home, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newInitCmd()
	cmd.SetArgs([]string{"--antigravity", "--dry-run", "--skip-proxy-route", "--guard=false", "--skip-extension", "--config", cfg})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --antigravity: %v (%s)", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "antigravity-cli") {
		t.Fatalf("init --antigravity did not plan the antigravity-cli hooks:\n%s", got)
	}
	if strings.Contains(got, "claude-code") {
		t.Fatalf("init --antigravity also selected Claude Code:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".gemini", "config", "hooks.json")); !os.IsNotExist(err) {
		t.Fatalf("--dry-run wrote the hooks file (stat err %v)", err)
	}

	help := newInitCmd()
	var hb bytes.Buffer
	help.SetOut(&hb)
	help.SetArgs([]string{"--help"})
	if err := help.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hb.String(), "--antigravity") {
		t.Errorf("`observer init --help` does not list --antigravity")
	}
}

// TestResolveInitToolFlag pins --tool's validation table.
func TestResolveInitToolFlag(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr string
	}{
		{"empty", nil, nil, ""},
		{"one", []string{"copilot-cli"}, []string{"copilot-cli"}, ""},
		{"normalized-and-deduplicated", []string{" Copilot-CLI ", "copilot-cli", ""}, []string{"copilot-cli"}, ""},
		{"alias-id-accepted", []string{"codex"}, []string{"codex"}, ""},
		{"unknown", []string{"not-a-tool"}, nil, "choose from:"},
		{"no-init-capability", []string{"hermes"}, nil, "not a tool `observer init` can wire"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveInitToolFlag(c.in)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, c.wantErr)
				}
				if !strings.Contains(err.Error(), "copilot-cli") {
					t.Errorf("the refusal should list the selectable tools: %v", err)
				}
				return
			}
			if err != nil || !slices.Equal(got, c.want) {
				t.Fatalf("got %v, %v; want %v", got, err, c.want)
			}
		})
	}
}

// TestInitSelectableToolsAreRegistryDriven: the --tool vocabulary is exactly
// the registry tools with an init-writable capability, every one accepted by
// the flag and named in `observer init --help`.
func TestInitSelectableToolsAreRegistryDriven(t *testing.T) {
	sel := initSelectableTools()
	if !slices.IsSorted(sel) || !slices.Contains(sel, "copilot-cli") {
		t.Fatalf("initSelectableTools = %v, want a sorted list including copilot-cli", sel)
	}
	for _, tool := range integration.Tools() {
		if slices.Contains(sel, tool) != autoInitSupported(tool) {
			t.Errorf("%s: selectable=%v but autoInitSupported=%v", tool, slices.Contains(sel, tool), autoInitSupported(tool))
		}
	}
	if _, err := resolveInitToolFlag(sel); err != nil {
		t.Errorf("a selectable tool was refused: %v", err)
	}
	f := newInitCmd().Flags().Lookup("tool")
	if f == nil {
		t.Fatal("`observer init` has no --tool flag")
	}
	for _, tool := range sel {
		if !strings.Contains(f.Usage, tool) {
			t.Errorf("--tool help does not name %s", tool)
		}
	}
	if err := newInitCmd().Flags().Parse([]string{"--tool", "copilot-cli", "--tool", "gemini-cli,codex"}); err != nil {
		t.Errorf("--tool should be repeatable and comma-separable: %v", err)
	}
}
