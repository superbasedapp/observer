//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// TestSpawnGUIChecksTheProjectRoot (item 9): a dashboard GUI launch is
// checked in its own project root, never the daemon's working directory
// (daemonTrustSetup points that at an untrusted repository): an untrusted
// root refuses before anything resolves or spawns and names where to
// accept; a clean root passes the trust row.
func TestSpawnGUIChecksTheProjectRoot(t *testing.T) {
	cfgPath, _ := daemonTrustSetup(t, "enforce")
	row, ok := integration.GUILaunchFor("vscode")
	if !ok {
		t.Fatal("test premise: the vscode GUI row")
	}
	resolved := 0
	g := &guiLauncher{
		configPath: func() string { return cfgPath },
		resolveEnv: func() toolresolve.Env { resolved++; return toolresolve.Env{} },
		isWSL:      func() bool { return false },
	}
	untrusted := writeTrustRepo(t, untrustedHookRepo)
	_, err := g.SpawnGUI(termsvc.GUISpawnRequest{ID: "vscode", Spec: row.Spec, ProjectRoot: untrusted})
	if err == nil || !strings.Contains(err.Error(), "S-701") || !strings.Contains(err.Error(), "observer security trust accept --all --dir "+untrusted) {
		t.Fatalf("untrusted project root: %v, want the trust refusal", err)
	}
	if resolved != 0 {
		t.Fatal("the binary was resolved after a trust refusal")
	}
	clean := writeTrustRepo(t, map[string]string{"README.md": "# x\n"})
	_, err = g.SpawnGUI(termsvc.GUISpawnRequest{ID: "vscode", Spec: row.Spec, ProjectRoot: clean})
	if err != nil && strings.Contains(err.Error(), "repository trust") {
		t.Fatalf("clean project root refused by the trust row (the daemon's cwd was read?): %v", err)
	}
	if resolved == 0 {
		t.Fatal("a clean project root never reached resolution")
	}
}

// TestCheckedMarkerIsStrippedFromGUIChildren (item a): a marker the daemon
// inherited never reaches a GUI child; the launch's own marker does.
func TestCheckedMarkerIsStrippedFromGUIChildren(t *testing.T) {
	t.Setenv(repoTrustCheckedEnv, strings.Repeat("b", 64))
	for _, kv := range guiChildEnv(nil) {
		if strings.HasPrefix(kv, repoTrustCheckedEnv+"=") {
			t.Fatalf("GUI child inherited %s", kv)
		}
	}
	env := guiChildEnv([]string{repoTrustCheckedEnv + "=" + strings.Repeat("c", 64)})
	if env[len(env)-1] != repoTrustCheckedEnv+"="+strings.Repeat("c", 64) {
		t.Fatalf("the launch's own marker did not reach the GUI child: %v", env[len(env)-1])
	}
}
