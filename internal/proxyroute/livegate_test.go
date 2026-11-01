package proxyroute

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// gateRouteTool gates target's route writer for one test.
func gateRouteTool(t *testing.T, target string, g integration.LiveGate) {
	t.Helper()
	prev := routeLiveGateFor
	routeLiveGateFor = func(tool string) integration.LiveGate {
		if tool == target {
			return g
		}
		return prev(tool)
	}
	t.Cleanup(func() { routeLiveGateFor = prev })
}

// TestRouteLiveGateRefusal pins the writer-side route gate (DEC-12): an
// absent file is the benign ConfigMissing skip, a present one is refused
// with the shared wording and is neither read nor changed, an ungated tool
// passes, and the test-only switch lets the real writer run.
func TestRouteLiveGateRefusal(t *testing.T) {
	home := t.TempDir()
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	gateRouteTool(t, "synthetic", "LC77")
	path := filepath.Join(home, "cfg.toml")

	res, gated := r.liveGateRefusal("synthetic", path)
	if !gated || !res.ConfigMissing || res.SkipReason != "" || res.Error != nil {
		t.Errorf("absent file: %+v gated=%v, want a benign ConfigMissing skip", res, gated)
	}
	body := []byte("api_key = \"secret\"\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	res, gated = r.liveGateRefusal("synthetic", path)
	if !gated || res.ConfigMissing || res.Error != nil || res.SkipReason != LiveGateSkipPrefix+"built, waiting on live check LC77" {
		t.Errorf("present file: %+v gated=%v, want the DEC-12 skip", res, gated)
	}
	if res.Added || res.AlreadySet {
		t.Errorf("a refusal claimed a route: %+v", res)
	}
	if got, _ := os.ReadFile(path); string(got) != string(body) {
		t.Error("the refusal changed the file")
	}
	if _, gated := r.liveGateRefusal("kimi-code", path); gated {
		t.Error("an ungated writer was refused")
	}
	runLiveGatedRouteWriters = true
	t.Cleanup(func() { runLiveGatedRouteWriters = false })
	if _, gated := r.liveGateRefusal("synthetic", path); gated {
		t.Error("the test-only switch did not let the writer run")
	}
}
