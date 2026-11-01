package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// TestCheckRoutePort is U9: a Claude Code / Codex route left on :8820 after
// [proxy].port moved to 18820 warns with the forced route rewrite for each
// tool; a matching port is ok.
func TestCheckRoutePort(t *testing.T) {
	home := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".claude/settings.json", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`)
	write(".codex/config.toml", "model_provider = \"openai-observer\"\n\n[model_providers.openai-observer]\nname = \"x\"\nbase_url = \"http://127.0.0.1:8820/v1\"\n")
	var cfg config.Config
	cfg.Proxy.Port = 18820
	c := checkRoutePort(home, cfg)
	if c.Status != StatusWarn {
		t.Fatalf("status %s, want warn: %q", c.Status, c.Message)
	}
	for _, want := range []string{
		"observer init --claude-code --skip-hooks --skip-mcp --proxy-port 18820 --force",
		"observer init --codex --skip-hooks --skip-mcp --proxy-port 18820 --force",
	} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q lacks %q", c.Message, want)
		}
	}
	cfg.Proxy.Port = 8820
	if c := checkRoutePort(home, cfg); c.Status != StatusOK {
		t.Fatalf("matching port: %s %q", c.Status, c.Message)
	}
}

// routeHostHome is an isolated home with every route reader's env override
// pointed inside it.
func routeHostHome(t *testing.T) (string, func(rel, body string)) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	t.Setenv("KIMI_CODE_HOME", "")
	t.Setenv("QWEN_HOME", "")
	return home, func(rel, body string) {
		t.Helper()
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

const qwenOnOpenRouter = `{"model":{"name":"qwen/qwen3-coder","baseUrl":"https://openrouter.ai/api/v1"},"modelProviders":{"openai":[{"id":"qwen/qwen3-coder","baseUrl":"https://openrouter.ai/api/v1","envKey":"OPENROUTER_API_KEY"}]}}`

// TestCheckRouteHost is T-903: a route at another host than an Observer
// proxy is a doctor row naming the tool (the admin already saw it as drift,
// the developer did not). A tool on its own provider a managed node would
// lane-route is OK unless this node keeps routes for its organization.
func TestCheckRouteHost(t *testing.T) {
	cases := []struct {
		name       string
		files      map[string]string
		maintained bool
		// sel is the node's component selection (zero: routing and every
		// tool selected).
		sel      proxyroute.Selection
		status   Status
		contains []string
		lacks    []string
	}{
		{
			// T-915 (D-770): an installed tool the policy did not select
			// is never routed by maintenance, so its host is not drift.
			name:       "qwen-code on another host, not selected by policy, this node keeps routes",
			files:      map[string]string{".qwen/settings.json": qwenOnOpenRouter, ".claude/settings.json": `{}`},
			maintained: true,
			sel:        proxyroute.Selection{Tool: func(tool string) bool { return tool != "qwen-code" }},
			status:     StatusOK,
			contains:   []string{"not selected by policy: qwen-code", "not route drift"},
			lacks:      []string{"sees this as route drift", "bypass it"},
		},
		{
			// D-771: the route writer component is not active, so no
			// route is drift wherever it points; the installed tools are
			// named.
			name: "routing switched off by policy, codex and qwen-code on other hosts",
			files: map[string]string{
				".qwen/settings.json":   qwenOnOpenRouter,
				".claude/settings.json": `{}`,
				".codex/config.toml":    "model_provider = \"other\"\n\n[model_providers.other]\nbase_url = \"https://llm.example.com/v1\"\n",
			},
			maintained: true,
			sel:        proxyroute.Selection{RoutingOff: true},
			status:     StatusOK,
			contains:   []string{"routing is switched off by policy", "no route is drift", "installed: claude-code, codex, qwen-code"},
			lacks:      []string{"sees this as route drift", "bypass it", "not selected by policy"},
		},
		{
			name: "codex bypass beside an unselected qwen-code",
			files: map[string]string{
				".qwen/settings.json":   qwenOnOpenRouter,
				".claude/settings.json": `{}`,
				".codex/config.toml":    "model_provider = \"other\"\n\n[model_providers.other]\nbase_url = \"https://llm.example.com/v1\"\n",
			},
			maintained: true,
			sel:        proxyroute.Selection{Tool: func(tool string) bool { return tool != "qwen-code" }},
			status:     StatusWarn,
			contains:   []string{"bypass it: codex", "sees this as route drift", "not selected by policy: qwen-code"},
			lacks:      []string{"bypass it: codex, qwen-code"},
		},
		{
			name:     "no route elsewhere",
			files:    map[string]string{".claude/settings.json": `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`},
			status:   StatusOK,
			contains: []string{"no tool routes to another host"},
		},
		{
			name:     "claude-code at another host",
			files:    map[string]string{".claude/settings.json": `{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}}`},
			status:   StatusWarn,
			contains: []string{"bypass it: claude-code", "observer init --claude-code --skip-hooks --skip-mcp --force"},
		},
		{
			name:     "qwen-code on its own provider, routes not kept here",
			files:    map[string]string{".qwen/settings.json": qwenOnOpenRouter},
			status:   StatusOK,
			contains: []string{"bypass it: qwen-code"},
		},
		{
			name:       "qwen-code on its own provider, this node keeps routes",
			files:      map[string]string{".qwen/settings.json": qwenOnOpenRouter, ".claude/settings.json": `{}`},
			maintained: true,
			status:     StatusWarn,
			contains:   []string{"bypass it: qwen-code", "sees this as route drift"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, write := routeHostHome(t)
			for rel, body := range tc.files {
				write(rel, body)
			}
			if tc.maintained {
				r, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: 8820, HomeDir: home, Writer: routeprov.WriterManaged})
				if err != nil {
					t.Fatal(err)
				}
				if res := r.RegisterClaudeCode(); res.Error != nil {
					t.Fatal(res.Error)
				}
			}
			c := checkRouteHost(home, tc.sel)
			if c.Status != tc.status {
				t.Fatalf("status %s, want %s: %q", c.Status, tc.status, c.Message)
			}
			for _, want := range tc.contains {
				if !strings.Contains(c.Message, want) {
					t.Errorf("message %q lacks %q", c.Message, want)
				}
			}
			for _, not := range tc.lacks {
				if strings.Contains(c.Message, not) {
					t.Errorf("message %q says %q", c.Message, not)
				}
			}
			if strings.Contains(c.Message, "https://") {
				t.Errorf("message quotes a configured URL: %q", c.Message)
			}
		})
	}
}

// TestCheckAdapterLaneNote is T-903: `observer doctor kimi-code` on a host
// whose kimi-code route is a provider lane prints the lane note, not the
// fixed route's [providers.openai] note.
func TestCheckAdapterLaneNote(t *testing.T) {
	home, write := routeHostHome(t)
	write(".kimi-code/config.toml", "default_model = \"flash\"\n\n[models.flash]\nprovider = \"baseten\"\nmodel = \"flash-1\"\n\n[providers.baseten]\ntype = \"openai\"\nbase_url = \"http://127.0.0.1:8820/up/route-inference-baseten-co/v1\"\napi_key = \"sk-test-not-real\"\n")
	c, ok := CheckAdapterIn("kimi-code", config.Config{}, home)
	if !ok {
		t.Fatal("kimi-code is not an adapter")
	}
	joined := strings.Join(c.Details, "\n")
	if !strings.Contains(joined, "routed through a proxy route lane to its own provider") {
		t.Fatalf("no lane note:\n%s", joined)
	}
	if strings.Contains(joined, "implicit host was api.openai.com") {
		t.Fatalf("the fixed route's note is still printed on a lane-routed host:\n%s", joined)
	}

	home2, write2 := routeHostHome(t)
	write2(".kimi-code/config.toml", "[providers.openai]\nbase_url = \"http://127.0.0.1:8820/v1\"\napi_key = \"sk-test-not-real\"\n")
	c, _ = CheckAdapterIn("kimi-code", config.Config{}, home2)
	if joined := strings.Join(c.Details, "\n"); !strings.Contains(joined, "[providers.openai]") {
		t.Fatalf("fixed route: the fixed note is missing:\n%s", joined)
	}
}
