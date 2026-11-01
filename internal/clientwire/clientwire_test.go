package clientwire

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp"
)

const testBinary = "/opt/observer/bin/observer"

// TestPredicatesAreCapabilityShaped walks every registry row (and its
// cross-OS target) and pins the predicate relations the CLI and the
// dashboard both rely on: an auto-wired hook target is always removable, an
// unadvertised row is never offered, and a removable route is a persisted
// route.
func TestPredicatesAreCapabilityShaped(t *testing.T) {
	for _, c := range integration.Capabilities() {
		for _, tool := range []string{c.Tool, c.Tool + WindowsSuffix} {
			if HookSupported(tool) && !HookRemovable(tool) {
				t.Errorf("%s: hook-supported but not removable", tool)
			}
			if RouteRemovable(tool) && !RouteSupported(tool) {
				t.Errorf("%s: removable route that init never persists", tool)
			}
			if !c.Advertised() && (HookSupported(tool) || HookRemovable(tool) || MCPSupported(tool) || RouteSupported(tool)) {
				t.Errorf("%s: unadvertised (%s) row is still offered", tool, c.Lifecycle)
			}
			if MCPSupported(tool) && (c.MCP == nil || !mcpRegistrarFormats[c.MCP.Format]) {
				t.Errorf("%s: MCP offered for a format the registrar does not write", tool)
			}
		}
	}
	if HookSupported("no-such-tool") || MCPSupported("no-such-tool") || RouteSupported("no-such-tool") {
		t.Error("an unknown tool must never be offered")
	}
}

// TestRouteRemoversArePersistedRoutes: every route undo row names a tool whose
// registry row persists a route, so the table can never strip a route init
// did not write.
func TestRouteRemoversArePersistedRoutes(t *testing.T) {
	for tool := range routeRemovers {
		if !RouteSupported(tool) {
			t.Errorf("route remover for %s, which init does not persist a route for", tool)
		}
	}
}

// seedClaude registers Observer's hooks and MCP entry into a throwaway home
// next to a user-authored hook and a user MCP server, and returns the two
// file paths.
func seedClaude(t *testing.T, home string) (settings, claudeJSON string) {
	t.Helper()
	settings = filepath.Join(home, ".claude", "settings.json")
	claudeJSON = filepath.Join(home, ".claude.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	user := `{"permissions":{"allow":["Bash(/usr/local/bin/my-own-tool)"]}}`
	if err := os.WriteFile(settings, []byte(user), 0o600); err != nil {
		t.Fatal(err)
	}
	cred := `{"oauthAccount":{"emailAddress":"dev@example.test"},"mcpServers":{"mine":{"command":"/usr/bin/mine","args":[]}}}`
	if err := os.WriteFile(claudeJSON, []byte(cred), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := hook.NewRegistry(hook.Options{BinaryPath: testBinary, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("claude-code"); res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("seed hooks: %+v", res)
	}
	mreg, err := mcp.NewRegistrar(mcp.RegisterOptions{BinaryPath: testBinary, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if res := mreg.Register("claude-code"); res.Error != nil || !res.Added {
		t.Fatalf("seed mcp: %+v", res)
	}
	return settings, claudeJSON
}

// TestRemoverDryRunThenApply: a dry run reports exactly what would go and
// writes nothing; the apply removes only Observer's entries, keeps the
// user-authored hook and MCP server, and leaves the credential file's other
// keys untouched (the shared-credential-file exception: subtree-only edits).
func TestRemoverDryRunThenApply(t *testing.T) {
	home := t.TempDir()
	settings, claudeJSON := seedClaude(t, home)
	beforeSettings, _ := os.ReadFile(settings)
	beforeCred, _ := os.ReadFile(claudeJSON)

	dry, err := NewRemover(RemoveOptions{BinaryPath: testBinary, HomeDir: home, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	m := dry.Remove("claude-code", PartHooks, PartMCP)
	if m.Failed() || m.Hooks == nil || m.MCP == nil {
		t.Fatalf("dry run: %+v", m)
	}
	if len(m.Hooks.HooksRemoved) == 0 || !m.MCP.Removed {
		t.Fatalf("dry run reports nothing to remove: hooks=%+v mcp=%+v", *m.Hooks, *m.MCP)
	}
	if b, _ := os.ReadFile(settings); string(b) != string(beforeSettings) {
		t.Fatal("dry run wrote settings.json")
	}
	if b, _ := os.ReadFile(claudeJSON); string(b) != string(beforeCred) {
		t.Fatal("dry run wrote .claude.json")
	}

	live, err := NewRemover(RemoveOptions{BinaryPath: testBinary, HomeDir: home, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	m = live.Remove("claude-code", PartHooks, PartMCP)
	if m.Failed() {
		t.Fatalf("apply failed: hooks=%v mcp=%v", m.Hooks.Error, m.MCP.Error)
	}
	after, _ := os.ReadFile(settings)
	if strings.Contains(string(after), testBinary) {
		t.Errorf("observer hook entries survived: %s", after)
	}
	if !strings.Contains(string(after), "/usr/local/bin/my-own-tool") {
		t.Errorf("the user's own settings were removed: %s", after)
	}
	var cred map[string]json.RawMessage
	raw, _ := os.ReadFile(claudeJSON)
	if err := json.Unmarshal(raw, &cred); err != nil {
		t.Fatal(err)
	}
	if string(cred["oauthAccount"]) != `{"emailAddress":"dev@example.test"}` {
		t.Errorf("credential subtree changed: %s", cred["oauthAccount"])
	}
	if strings.Contains(string(cred["mcpServers"]), `"observer"`) || !strings.Contains(string(cred["mcpServers"]), `"mine"`) {
		t.Errorf("mcpServers after removal = %s", cred["mcpServers"])
	}
}

// TestRemoverSkipsInapplicableParts: asking for a part a tool does not have
// leaves that field nil, so "remove everything" is always safe to ask.
func TestRemoverSkipsInapplicableParts(t *testing.T) {
	r, err := NewRemover(RemoveOptions{BinaryPath: testBinary, HomeDir: t.TempDir(), DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if m := r.Remove("cursor", PartRoute); m.Route != nil || m.RouteErr != nil {
		t.Errorf("cursor has no removable route: %+v", m)
	}
	if m := r.Remove("no-such-tool", PartHooks, PartMCP, PartRoute); m.Hooks != nil || m.MCP != nil || m.Route != nil {
		t.Errorf("unknown tool removal touched something: %+v", m)
	}
	if _, err := NewRemover(RemoveOptions{}); err == nil {
		t.Error("NewRemover without a binary path must fail")
	}
}

// TestOfferedToolsHaveARegistryWriter pins T-421 item 2's other half: every
// tool the predicates offer (and so the dashboard renders a Set up step for)
// is one the registries actually write. A dry run into an empty home must
// never answer "not supported".
func TestOfferedToolsHaveARegistryWriter(t *testing.T) {
	home := t.TempDir()
	hooks, err := hook.NewRegistry(hook.Options{BinaryPath: testBinary, HomeDir: home, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	mcps, err := mcp.NewRegistrar(mcp.RegisterOptions{BinaryPath: testBinary, HomeDir: home, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range integration.Capabilities() {
		if HookSupported(c.Tool) {
			if res := hooks.Register(c.Tool); res.Error != nil && strings.Contains(res.Error.Error(), "not supported") {
				t.Errorf("%s: offered for hooks but the registry has no writer: %v", c.Tool, res.Error)
			}
		}
		if MCPSupported(c.Tool) {
			if res := mcps.Register(c.Tool); res.Error != nil && strings.Contains(res.Error.Error(), "not supported") {
				t.Errorf("%s: offered for MCP but the registrar has no writer: %v", c.Tool, res.Error)
			}
		}
	}
}

// TestXcodeTargetsAreHookTargetsOfTheirBase pins FU-145: an Xcode
// agent-home target answers for its base tool's hook capability (and only
// while it is switched on), resolves to its base for component gates, and
// is never an MCP, route or telemetry target.
func TestXcodeTargetsAreHookTargetsOfTheirBase(t *testing.T) {
	n := 0
	for _, base := range integration.Tools() {
		for _, target := range hook.XcodeTargetsFor(base) {
			n++
			_, gated := hook.LiveCheckGate(target)
			if HookSupported(target) == gated {
				t.Errorf("%s: HookSupported = %v with gated = %v", target, HookSupported(target), gated)
			}
			if HookSupported(target) && !HookSupported(base) {
				t.Errorf("%s: supported while its base %s is not", target, base)
			}
			if !HookRemovable(target) {
				t.Errorf("%s: not removable", target)
			}
			if MCPSupported(target) || RouteSupported(target) || TelemetrySupported(target) {
				t.Errorf("%s: an Xcode target is a hook target only", target)
			}
			if HookTargetBase(target) != base {
				t.Errorf("HookTargetBase(%s) = %q, want %q", target, HookTargetBase(target), base)
			}
			if c, ok := HookTargetCapability(target); !ok || c.Tool != base {
				t.Errorf("HookTargetCapability(%s) = %q, %v", target, c.Tool, ok)
			}
			if _, _, ok := AdvertisedCapability(target); ok {
				t.Errorf("AdvertisedCapability resolves %s; it must stay hook-only", target)
			}
		}
	}
	if n == 0 {
		t.Fatal("no Xcode agent-home target")
	}
	if HookTargetBase("codex-windows") != "codex" || HookTargetBase("cursor") != "cursor" {
		t.Error("HookTargetBase changed the -windows or the plain answer")
	}
}

// TestWSLTwinsAreHookTargetsOfTheirBase (FU-197): a "-wsl" twin is a hook
// target of its base tool for every caller, only while its live gate is off
// (today cursor-wsl), never an MCP, route or telemetry target; a gated twin
// stays refused with its gate reason.
func TestWSLTwinsAreHookTargetsOfTheirBase(t *testing.T) {
	n := 0
	for _, base := range integration.Tools() {
		for _, target := range hook.WSLTwinsFor(base) {
			n++
			gate, gated := hook.LiveCheckGate(target)
			if HookSupported(target) && (gated || !HookSupported(base)) {
				t.Errorf("%s: HookSupported with gated = %v, base supported = %v", target, gated, HookSupported(base))
			}
			if gated && gate == "" {
				t.Errorf("%s: gated without a reason", target)
			}
			if !gated && HookSupported(base) && !HookSupported(target) {
				t.Errorf("%s: switched on but not supported", target)
			}
			if HookRemovable(base) && !HookRemovable(target) {
				t.Errorf("%s: not removable while its base %s is", target, base)
			}
			if MCPSupported(target) || RouteSupported(target) || TelemetrySupported(target) {
				t.Errorf("%s: a WSL twin is a hook target only", target)
			}
			if HookTargetBase(target) != base {
				t.Errorf("HookTargetBase(%s) = %q, want %q", target, HookTargetBase(target), base)
			}
			if c, ok := HookTargetCapability(target); !ok || c.Tool != base {
				t.Errorf("HookTargetCapability(%s) = %q, %v", target, c.Tool, ok)
			}
		}
	}
	if n == 0 {
		t.Fatal("no WSL twin")
	}
	if !HookSupported("cursor-wsl") {
		t.Error("cursor-wsl (WSL-5 passed) is not a hook target")
	}
	if HookSupported("claude-code-wsl") {
		t.Error("claude-code-wsl waits on WSL-4 and must stay refused")
	}
}
