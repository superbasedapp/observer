//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// registerObserverInto runs Observer's own registration writers into home
// the way `observer init` does: the hooks of every tool whose directory is
// there, the MCP entries, the Claude Code status line, and the Hermes
// plugin and MCP entry. bin is the observer binary the entries name.
func registerObserverInto(t *testing.T, home, bin string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(home, ".observer", "config.toml")
	reg, err := hook.NewRegistry(hook.Options{BinaryPath: bin, HomeDir: home, ConfigPath: cfg, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range reg.Installed() {
		if res := reg.Register(tool); res.Error != nil {
			t.Fatalf("register %s hooks: %v", tool, res.Error)
		}
	}
	if res := reg.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("status line: %v", res.Error)
	}
	mr, err := mcpregister.NewRegistrar(mcpregister.RegisterOptions{BinaryPath: bin, HomeDir: home, ConfigPath: cfg, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range mr.Installed() {
		if res := mr.Register(tool); res.Error != nil {
			t.Fatalf("register %s MCP: %v", tool, res.Error)
		}
	}
	hopts := hook.HermesOptions{HermesHome: filepath.Join(home, ".hermes"), BinaryPath: bin, ConfigPath: cfg}
	if _, err := hook.RegisterHermes(hopts); err != nil {
		t.Fatal(err)
	}
	if _, err := hook.RegisterHermesMCP(hopts); err != nil {
		t.Fatal(err)
	}
}

// TestRepoTrustUserBaselineIgnoresObserverOwn (plans decision log P-037
// finding 1): Observer's own hooks in ~/.claude, ~/.codex and Cursor, its
// MCP entries, its status line and ~/.hermes/plugins/superbased-observer/
// are not new items: `observer init` into a baselined home, and a release
// that rewrites every registration for another binary path, record zero
// findings. A foreign hook added next to them is still reported.
func TestRepoTrustUserBaselineIgnoresObserverOwn(t *testing.T) {
	ctx := context.Background()
	st := baselineTestStore(t)
	home := writeTrustRepo(t, nil)
	for _, d := range []string{".claude", ".codex", ".cursor", ".hermes", ".gemini", ".qwen", ".factory"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	paths := testUserPaths(home)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	pass := func(at time.Time) int {
		t.Helper()
		n, err := repoTrustUserBaselinePass(ctx, st, home, paths, at)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := pass(now); n != 0 {
		t.Fatalf("first pass recorded %d", n)
	}

	registerObserverInto(t, home, filepath.Join(home, "bin", "observer"))
	// The registration really wrote items the check reads, and every one is
	// recognised as Observer's.
	res, err := sectrust.Check(ctx, sectrust.OSFS(home), sectrust.Request{Paths: paths, Own: repoTrustObserverOwn(home, paths)})
	if err != nil {
		t.Fatal(err)
	}
	marked := 0
	for _, r := range res.Reasons {
		if r.Digest == "" {
			continue
		}
		if !r.Observer {
			t.Errorf("an Observer registration not recognised: %s %s %s %q", r.Code, r.File, r.Key, r.Excerpt)
		}
		marked++
	}
	if marked < 4 {
		t.Fatalf("only %d items read after registration: the writers wrote nothing the check reads", marked)
	}
	if n := pass(now.Add(time.Minute)); n != 0 {
		t.Fatalf("observer init recorded %d findings, want 0", n)
	}

	// A release that changes the registered hooks: every entry now names
	// another binary.
	registerObserverInto(t, home, filepath.Join(home, "opt", "observer-v2", "observer"))
	if n := pass(now.Add(2 * time.Minute)); n != 0 {
		t.Fatalf("a re-registration for a new binary recorded %d findings, want 0", n)
	}
	fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: repoTrustUserKey(home)})
	if err != nil || len(fs) != 0 {
		t.Fatalf("findings %+v %v", fs, err)
	}

	// A foreign hook beside Observer's is still new.
	writeHomeFile(t, home, ".cursor/hooks.json", `{"version":1,"hooks":{"stop":[{"command":"node ~/.cache/x/run.js"}]}}`)
	if n := pass(now.Add(3 * time.Minute)); n != 1 {
		t.Fatalf("a foreign hook recorded %d, want 1", n)
	}
}

// TestObserverMCPEntry: the MCP row of the Observer-entry table accepts
// Observer's own entry shapes naming a binary it owns, and nothing that
// merely carries its name or names another observer binary.
func TestObserverMCPEntry(t *testing.T) {
	cases := []struct {
		key, content string
		want         bool
	}{
		{"mcpServers.observer", "/usr/local/bin/observer serve", true},
		{"mcp_servers.observer", "/opt/My Tools/observer serve --config /home/u/My Config/config.toml", true},
		{"mcp_servers.superbased-observer", `C:\Users\u\observer.exe serve`, true},
		{"mcpServers.observer", "node evil.js serve", false},
		{"mcpServers.observer", "/usr/local/bin/observer serve TOKEN=x", false},
		{"mcpServers.other", "/usr/local/bin/observer serve", false},
		{"mcpServers.observer", "/usr/local/bin/observer", false},
	}
	owns := func(bin string) bool {
		return bin == "/usr/local/bin/observer" || bin == "/opt/My Tools/observer" || bin == `C:\Users\u\observer.exe`
	}
	cases = append(cases, struct {
		key, content string
		want         bool
	}{"mcpServers.observer", "/tmp/x/observer serve", false})
	for _, c := range cases {
		if got := observerMCPEntry(c.key, c.content, owns); got != c.want {
			t.Errorf("observerMCPEntry(%q, %q) = %v, want %v", c.key, c.content, got, c.want)
		}
	}
}
