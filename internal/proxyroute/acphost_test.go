package proxyroute

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hostfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// zedHome lays out a home with Zed's settings.json (Linux catalogue path)
// holding a comment, a custom agent and a credential-like env value.
func zedHome(t *testing.T) (home, settings string) {
	t.Helper()
	prev := zedRouteGOOS
	zedRouteGOOS = func() string { return "linux" }
	t.Cleanup(func() { zedRouteGOOS = prev })
	home = t.TempDir()
	settings = filepath.Join(home, ".config", "zed", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "// Zed settings\n{\n  \"agent_servers\": {\n    \"my-agent\": { \"type\": \"custom\", \"command\": \"x\", \"env\": { \"API_KEY\": \"secret\" } },\n  },\n}\n"
	if err := os.WriteFile(settings, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, settings
}

func zedRegistrar(t *testing.T, home string) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestZedAgentRoutesComeFromCapabilities: every route row is an ACP agent
// whose tool's registry route has an env var, and Claude Agent's is
// ANTHROPIC_BASE_URL with no suffix.
func TestZedAgentRoutesComeFromCapabilities(t *testing.T) {
	rows := ZedAgentRoutes()
	if len(rows) == 0 {
		t.Fatal("no Zed agent routes")
	}
	for _, r := range rows {
		c, ok := integration.For(r.Tool)
		if !ok || c.Proxy == nil || c.Proxy.EnvVar != r.EnvVar || c.Proxy.Suffix != r.Suffix || c.Proxy.Gate != nil || c.Proxy.ConfigContentEnv != "" {
			t.Errorf("%+v does not match an unconditional single-variable %s registry route", r, r.Tool)
		}
	}
	// A conditional route (Copilot CLI's BYOK lane) or one that needs a
	// config-content variable too (OpenCode) is never a per-agent env row.
	for _, agent := range []string{"github-copilot", "github-copilot-cli", "opencode"} {
		if _, ok := zedAgentRoute(agent); ok {
			t.Errorf("%s has a Zed env route; its route needs more than one variable", agent)
		}
	}
	claude, ok := zedAgentRoute("claude-acp")
	if !ok || claude.EnvVar != "ANTHROPIC_BASE_URL" || zedRouteURL(8820, claude) != "http://127.0.0.1:8820" {
		t.Errorf("claude-acp route = %+v, %v", claude, ok)
	}
}

// TestZedAgentRouteGateClosedWritesNothing: with the LC27 gate closed the
// writer leaves the file byte for byte (Force too) and says why.
func TestZedAgentRouteGateClosedWritesNothing(t *testing.T) {
	if g := ZedAgentRouteGate(); !g.Waiting() || g.Text() != "built, waiting on live check LC27" {
		t.Fatalf("gate = %v (%q)", g, g.Text())
	}
	for _, force := range []bool{false, true} {
		home, settings := zedHome(t)
		before, _ := os.ReadFile(settings)
		r := zedRegistrar(t, home)
		r.opts.Force = force
		res := r.RegisterZedAgent("claude-acp")
		if res.Error != nil || res.Added || !strings.Contains(res.SkipReason, "built, waiting on live check LC27") {
			t.Errorf("force=%v: RegisterZedAgent = %+v", force, res)
		}
		if after, _ := os.ReadFile(settings); string(after) != string(before) {
			t.Errorf("force=%v: the gated writer changed settings.json", force)
		}
	}
}

// TestZedAgentRouteWhenSwitchedOn: switched on, an absent agent entry is
// created as a registry entry carrying the env route, an existing one gets
// only the env member, the rest of the JSONC survives, a foreign value is
// refused without Force, and Unregister gives back the entry it created.
func TestZedAgentRouteWhenSwitchedOn(t *testing.T) {
	runLiveGatedHostRoutes = true
	t.Cleanup(func() { runLiveGatedHostRoutes = false })
	home, settings := zedHome(t)
	r := zedRegistrar(t, home)
	res := r.RegisterZedAgent("claude-acp")
	if res.Error != nil || !res.Added || res.ConfigPath != settings {
		t.Fatalf("RegisterZedAgent = %+v", res)
	}
	got, _ := os.ReadFile(settings)
	for _, want := range []string{"// Zed settings", `"API_KEY": "secret"`, `"claude-acp"`, `"type": "registry"`, `"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820"`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("settings lack %q:\n%s", want, got)
		}
	}
	if again := r.RegisterZedAgent("claude-acp"); again.Error != nil || !again.AlreadySet {
		t.Errorf("re-run = %+v", again)
	}
	un := r.UnregisterZedAgent("claude-acp")
	if un.Error != nil || !un.Added {
		t.Fatalf("Unregister = %+v", un)
	}
	// Only the env member goes; the entry stays (no record says Observer
	// created it), the rest of the file is intact.
	if got, _ := os.ReadFile(settings); strings.Contains(string(got), "ANTHROPIC_BASE_URL") || !strings.Contains(string(got), "my-agent") || !strings.Contains(string(got), `"claude-acp"`) {
		t.Errorf("after Unregister:\n%s", got)
	}

	// A user's own local gateway on another port is left by Unregister,
	// kept by a plain Register (AlreadySet, reported as it is), and
	// repointed by --force.
	local := "{ \"agent_servers\": { \"claude-acp\": { \"type\": \"registry\", \"env\": { \"ANTHROPIC_BASE_URL\": \"http://localhost:4000\" } } } }\n"
	if err := os.WriteFile(settings, []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	if un := r.UnregisterZedAgent("claude-acp"); un.Added {
		t.Error("Unregister removed a local gateway on another port")
	}
	if kept := r.RegisterZedAgent("claude-acp"); !kept.AlreadySet || kept.BaseURL != "http://localhost:4000" {
		t.Errorf("Register over another loopback route = %+v", kept)
	}
	r.opts.Force = true
	if forced := r.RegisterZedAgent("claude-acp"); forced.Error != nil || !forced.Added {
		t.Errorf("--force did not repoint: %+v", forced)
	}
	r.opts.Force = false
	if got, _ := os.ReadFile(settings); !strings.Contains(string(got), "http://127.0.0.1:8820") {
		t.Errorf("after --force:\n%s", got)
	}

	// An existing entry with a foreign value is refused without Force.
	foreign := "// x\n{ \"agent_servers\": { \"claude-acp\": { \"type\": \"registry\", \"env\": { \"ANTHROPIC_BASE_URL\": \"https://gateway.example\" } } } }\n"
	if err := os.WriteFile(settings, []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := r.RegisterZedAgent("claude-acp"); c.Error == nil {
		t.Errorf("a foreign route was overwritten without --force: %+v", c)
	}
	if b, _ := os.ReadFile(settings); string(b) != foreign {
		t.Error("a refused write changed the file")
	}
	if un := r.UnregisterZedAgent("claude-acp"); un.Added {
		t.Error("Unregister removed a route Observer did not write")
	}
}

// TestZedAgentRouteNeedsZed: switched on, a home without Zed's directory
// gets nothing (a benign skip, no directory created); an unknown agent is
// an error.
func TestZedAgentRouteNeedsZed(t *testing.T) {
	runLiveGatedHostRoutes = true
	t.Cleanup(func() { runLiveGatedHostRoutes = false })
	prev := zedRouteGOOS
	zedRouteGOOS = func() string { return "linux" }
	t.Cleanup(func() { zedRouteGOOS = prev })
	home := t.TempDir()
	r := zedRegistrar(t, home)
	if res := r.RegisterZedAgent("claude-acp"); res.Error != nil || !res.ConfigMissing || res.Added {
		t.Errorf("no Zed: %+v", res)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Errorf("created %v", entries)
	}
	if res := r.RegisterZedAgent("no-such-agent"); res.Error == nil {
		t.Error("an unknown agent was accepted")
	}
}

// TestZedAgentRouteLinkNamesTheComponent (audit row 7, FU-198): a symbolic
// link at a middle directory of Zed's settings path is refused by Register
// and Unregister with a reason that carries the hostfile refusal naming the
// linked component, and the link's target is never written.
func TestZedAgentRouteLinkNamesTheComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privilege on windows")
	}
	runLiveGatedHostRoutes = true
	t.Cleanup(func() { runLiveGatedHostRoutes = false })
	home, settings := zedHome(t)
	body, _ := os.ReadFile(settings)
	// Move ~/.config/zed elsewhere and link it back in.
	real := filepath.Join(t.TempDir(), "zed")
	linked := filepath.Dir(settings)
	if err := os.Rename(linked, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, linked); err != nil {
		t.Fatal(err)
	}
	r := zedRegistrar(t, home)
	res := r.RegisterZedAgent("claude-acp")
	if res.Error != nil || res.Added || !res.ConfigMissing || !strings.Contains(res.SkipReason, linked) || !strings.Contains(res.SkipReason, hostfile.ErrLink.Error()) {
		t.Errorf("RegisterZedAgent through a linked directory = %+v", res)
	}
	un := r.UnregisterZedAgent("claude-acp")
	if un.Error != nil || un.Added || !un.ConfigMissing || !strings.Contains(un.SkipReason, linked) || !strings.Contains(un.SkipReason, hostfile.ErrLink.Error()) {
		t.Errorf("UnregisterZedAgent through a linked directory = %+v", un)
	}
	if got, _ := os.ReadFile(filepath.Join(real, "settings.json")); string(got) != string(body) {
		t.Errorf("the link's target was written:\n%s", got)
	}
}
