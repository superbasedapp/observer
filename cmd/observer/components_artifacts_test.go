package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/artifactstate"
	"github.com/marmutapp/superbased-observer/internal/browserhost"
	"github.com/marmutapp/superbased-observer/internal/browserhost/hostfiles"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook/pluginshim"
)

func testArtifactProbes(t *testing.T) artifactProbes {
	t.Helper()
	home := t.TempDir()
	return artifactProbes{
		Home: home, ObserverDir: filepath.Join(home, ".observer"), GOOS: "linux", UID: 1000,
		BinaryVersion: "v1.36.0",
		Now:           func() time.Time { return time.UnixMilli(10_000_000_000) },
		Getenv:        func(string) string { return "" },
		BridgePath:    func() (string, error) { return "", os.ErrNotExist },
		PathExists:    func(string) bool { return false },
	}
}

func stateOf(t *testing.T, states []artifactstate.Status, id string) artifactstate.Status {
	t.Helper()
	for _, s := range states {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no state for %s", id)
	return artifactstate.Status{}
}

// TestCollectArtifactStatesEmptyMachine: a fresh home reports every
// artifact, none of them as installed, and nothing warns.
func TestCollectArtifactStatesEmptyMachine(t *testing.T) {
	p := testArtifactProbes(t)
	states := collectArtifactStates(p, componentstate.Legacy())
	want := map[string]artifactstate.State{
		"artifact.browser-extension":  artifactstate.StateNotDetected,
		"artifact.vscode-extension":   artifactstate.StateNotDetected,
		"artifact.plugin-shims":       artifactstate.StateAbsent,
		"artifact.antigravity-bridge": artifactstate.StateNotApplicable,
		"artifact.node-inspection":    artifactstate.StateAbsent,
	}
	if len(states) != len(want) {
		t.Fatalf("got %d states", len(states))
	}
	for id, st := range want {
		if got := stateOf(t, states, id); got.State != st || got.Leftover {
			t.Errorf("%s: %+v, want %s", id, got, st)
		}
	}
	for _, c := range componentsArtifactChecks(states) {
		if c.Status != diag.StatusOK {
			t.Errorf("%s warns on an empty machine: %s", c.Name, c.Message)
		}
	}
}

// TestCollectArtifactStatesInstalledMachine stages each artifact under a
// throwaway home and checks the report and the doctor rows.
func TestCollectArtifactStatesInstalledMachine(t *testing.T) {
	requireCompiled(t, "processobs")
	requireUnstampedBuild(t)
	p := testArtifactProbes(t)
	// Browser: host files installed, a current handshake recorded.
	hostDir, _ := browserhost.HostInstallDir(p.Home)
	if _, err := hostfiles.WriteHost(hostDir, hostfiles.Env{ObserverBin: "/usr/bin/observer"}); err != nil {
		t.Fatal(err)
	}
	if err := browserhost.RecordSeen(p.ObserverDir, browserhost.Hello{Protocol: 2, ExtensionVersion: "1.36.0"}, p.Now().UnixMilli()-60_000); err != nil {
		t.Fatal(err)
	}
	// VS Code: a current install and an old Cursor one.
	for _, d := range []string{".vscode/extensions/superbased.superbased-observer-1.36.0-linux-x64", ".cursor/extensions/superbased.superbased-observer-1.34.0-linux-x64", ".vscode/extensions/ms-python.python-1.0.0"} {
		if err := os.MkdirAll(filepath.Join(p.Home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Plugin shim: Observer's shim in the OpenCode plugin folder.
	h, _ := pluginshim.HostFor("opencode")
	dir, err := h.Dir(p.Home, p.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pluginshim.Write(dir, h, pluginshim.RenderOptions{Events: map[string]string{"tool.execute.before": "tool_gate"}, Bin: "observer"}); err != nil {
		t.Fatal(err)
	}
	// node-inspection broker socket present.
	p.PathExists = func(path string) bool { return strings.HasPrefix(path, "/run/observer-node-inspection/") }

	states := collectArtifactStates(p, componentstate.Legacy())
	if s := stateOf(t, states, "artifact.browser-extension"); s.State != artifactstate.StateConnected || s.Version != "1.36.0" {
		t.Errorf("browser: %+v", s)
	}
	if s := stateOf(t, states, "artifact.vscode-extension"); s.State != artifactstate.StateStale || len(s.Items) != 2 {
		t.Errorf("vscode: %+v", s)
	}
	if s := stateOf(t, states, "artifact.plugin-shims"); s.State != artifactstate.StateInstalled || s.Leftover {
		t.Errorf("shims: %+v", s)
	}
	// The node-inspection broker is a Linux Unix socket under /run; Windows
	// has no such artifact (Windows 11 Pro rerun 2026-10-25, D5 group 8).
	if s := stateOf(t, states, "artifact.node-inspection"); runtime.GOOS != "windows" && s.State != artifactstate.StateInstalled {
		t.Errorf("node-inspection: %+v", s)
	}
	warned := map[string]bool{}
	for _, c := range componentsArtifactChecks(states) {
		if c.Status == diag.StatusWarn {
			warned[c.Name] = true
		}
	}
	if !warned["components.artifact.vscode-extension"] || len(warned) != 1 {
		t.Errorf("only the stale VS Code install warns: %v", warned)
	}

	var buf bytes.Buffer
	renderArtifactStates(&buf, states)
	for _, want := range []string{"artifact.browser-extension", "connected", "1.36.0", "Observer registers no URL or protocol handler"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("rendered table lacks %q:\n%s", want, buf.String())
		}
	}
}

// TestArtifactLeftoversWhenComponentsInactive: with capture.browser and
// the adapter inactive, the host and the shim Observer left behind are
// leftovers naming their teardown, and the extension that still connects
// after the host is gone is host_removed.
func TestArtifactLeftoversWhenComponentsInactive(t *testing.T) {
	p := testArtifactProbes(t)
	h, _ := pluginshim.HostFor("opencode")
	dir, _ := h.Dir(p.Home, p.Getenv)
	if _, err := pluginshim.Write(dir, h, pluginshim.RenderOptions{Events: map[string]string{"tool.execute.before": "tool_gate"}, Bin: "observer"}); err != nil {
		t.Fatal(err)
	}
	if err := browserhost.RecordSeen(p.ObserverDir, browserhost.Hello{Protocol: 2, ExtensionVersion: "1.36.0"}, p.Now().UnixMilli()-60_000); err != nil {
		t.Fatal(err)
	}
	// The five *-web adapters require capture.browser, so removing it
	// alone would leave it active for them.
	snap := componentstate.Resolve(config.ComponentsConfig{Remove: []string{
		"capture.browser", "adapter.chatgpt-web", "adapter.claude-web", "adapter.perplexity-web",
		"adapter.gemini-web", "adapter.copilot-web", "adapter.opencode",
	}}, nil)
	if snap.Active("capture.browser") {
		t.Fatalf("capture.browser still active: %v", snap.Issues)
	}
	states := collectArtifactStates(p, snap)
	b := stateOf(t, states, "artifact.browser-extension")
	if b.State != artifactstate.StateHostRemoved || !b.Leftover || !strings.Contains(b.Remedy, "remove the extension in the browser") {
		t.Errorf("browser: %+v", b)
	}
	s := stateOf(t, states, "artifact.plugin-shims")
	if !s.Leftover || !strings.Contains(s.Remedy, "observer components teardown adapter.opencode") {
		t.Errorf("shims: %+v", s)
	}
}
