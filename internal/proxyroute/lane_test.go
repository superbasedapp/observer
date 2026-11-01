package proxyroute

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// lane_test.go: the third-party-provider lane writers (lane P1).

func TestLaneTarget(t *testing.T) {
	cases := []struct {
		in             string
		id, root, path string
		ok             bool
	}{
		{"https://openrouter.ai/api/v1", "route-openrouter-ai", "https://openrouter.ai", "/api/v1", true},
		{"https://LLM.Example.com:8443/v1/", "route-llm-example-com-8443", "https://llm.example.com:8443", "/v1", true},
		{"https://api.example.com", "route-api-example-com", "https://api.example.com", "", true},
		{"http://llm.example.com/v1", "", "", "", false},           // not https
		{"https://user:pw@llm.example.com/v1", "", "", "", false},  // a credential in the URL
		{"https://llm.example.com/v1?key=abc", "", "", "", false},  // a query can carry a key
		{"https://llm.example.com/v1#frag", "", "", "", false},     // fragment
		{"http://127.0.0.1:8820/up/route-x/v1", "", "", "", false}, // already Observer
		{"", "", "", "", false},
	}
	for _, tc := range cases {
		id, root, path, ok := laneTarget(tc.in)
		if ok != tc.ok || id != tc.id || root != tc.root || path != tc.path {
			t.Errorf("laneTarget(%q) = %q %q %q %v, want %q %q %q %v", tc.in, id, root, path, ok, tc.id, tc.root, tc.path, tc.ok)
		}
	}
}

const kimiLaneFixture = `# my kimi settings
default_model = "mine-coder"

[models.mine-coder]
provider = "mine"
model = "coder-1"

[providers.mine]
type = "openai"
base_url = "https://llm.example.com/v1"
api_key = "sk-test-not-real"
`

// TestKimiCodeLaneWriteAndRestore: the active provider's base_url is
// rewritten to the lane URL (nothing else changes, the key is never touched),
// the lane and the original host are recorded, and removal puts the exact
// bytes back.
func TestKimiCodeLaneWriteAndRestore(t *testing.T) {
	home := maintainHome(t)
	writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml", kimiLaneFixture)
	st := statusFor(InspectRoutes(home), "kimi-code")
	if st.State != RouteDrifted || !st.LaneWritable {
		t.Fatalf("kimi-code before: %+v, want drifted + lane writable", st)
	}
	r := maintainRegistrar(t, home)
	installed := map[string]string{}
	got := resultFor(r.MaintainRoutes(MaintainOptions{
		Required: true, ProxyHealthy: always(true),
		InstallLane: func(id, root string) error { installed[id] = root; return nil },
	}), "kimi-code")
	if !got.Written || got.Error != nil || got.Decision.Reason != ReasonProviderLane {
		t.Fatalf("kimi-code: %+v, want a provider_lane write", got)
	}
	if installed["route-llm-example-com"] != "https://llm.example.com" {
		t.Fatalf("lane not installed before the write: %v", installed)
	}
	path := filepath.Join(home, ".kimi-code", "config.toml")
	after := readBytes(t, path)
	want := strings.Replace(kimiLaneFixture, `base_url = "https://llm.example.com/v1"`, `base_url = "http://127.0.0.1:8820/up/route-llm-example-com/v1"`, 1)
	if after != want {
		t.Fatalf("kimi-code after lane write:\n%s\nwant\n%s", after, want)
	}
	if s := statusFor(InspectRoutes(home), "kimi-code"); s.State != RouteOurs {
		t.Fatalf("kimi-code after: %q, want ours", s.State)
	}
	lanes, err := r.RouteLanes()
	if err != nil || !reflect.DeepEqual(lanes, map[string]string{"route-llm-example-com": "https://llm.example.com"}) {
		t.Fatalf("RouteLanes = %v, %v", lanes, err)
	}
	// Admin OFF: the original host comes back, byte for byte.
	out, err := r.ReleaseManagedRoutes(true)
	if err != nil || len(out) != 1 || !out[0].Removed {
		t.Fatalf("release = %+v, %v", out, err)
	}
	if b := readBytes(t, path); b != kimiLaneFixture {
		t.Fatalf("kimi-code after release:\n%s\nwant\n%s", b, kimiLaneFixture)
	}
	if lanes, _ := r.RouteLanes(); len(lanes) != 0 {
		t.Fatalf("lane record kept after release: %v", lanes)
	}
}

// TestLaneWriteNeedsAnInstalledLane: without a lane installer (or when the
// proxy cannot resolve it) nothing is written.
func TestLaneWriteNeedsAnInstalledLane(t *testing.T) {
	home := maintainHome(t)
	writeFile(t, filepath.Join(home, ".kimi-code"), "config.toml", kimiLaneFixture)
	r := maintainRegistrar(t, home)
	for _, install := range []func(string, string) error{nil, func(string, string) error { return errTestLane }} {
		got := resultFor(r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true), InstallLane: install}), "kimi-code")
		if got.Written || got.Decision.Reason != ReasonLaneUnavailable {
			t.Fatalf("kimi-code: %+v, want lane_unavailable", got)
		}
		if readBytes(t, filepath.Join(home, ".kimi-code", "config.toml")) != kimiLaneFixture {
			t.Fatal("a route was written toward a lane the proxy does not resolve")
		}
	}
}

type testLaneError struct{}

func (testLaneError) Error() string { return "lane refused" }

var errTestLane error = testLaneError{}

// TestLaneWriterRefusals: shapes the lane writers must not touch.
func TestLaneWriterRefusals(t *testing.T) {
	cases := []struct {
		name, dir, file, body string
		write                 func(*Registrar) RegistrationResult
	}{
		{
			"kimi: active provider of another type", ".kimi-code", "config.toml",
			"default_model = \"m\"\n[models.m]\nprovider = \"k\"\n[providers.k]\ntype = \"kimi\"\nbase_url = \"https://api.example.com/v1\"\n", (*Registrar).RegisterKimiCodeLane,
		},
		{
			"kimi: no base_url (implicit host not grounded)", ".kimi-code", "config.toml",
			"default_model = \"m\"\n[models.m]\nprovider = \"k\"\n[providers.k]\ntype = \"openai\"\napi_key = \"sk-test-not-real\"\n", (*Registrar).RegisterKimiCodeLane,
		},
		{
			"kimi: plain http host", ".kimi-code", "config.toml",
			"default_model = \"m\"\n[models.m]\nprovider = \"k\"\n[providers.k]\ntype = \"openai\"\nbase_url = \"http://llm.example.com/v1\"\n", (*Registrar).RegisterKimiCodeLane,
		},
		{
			"qwen: known default host is the fixed route", ".qwen", "settings.json",
			`{"model":{"name":"gpt-4o","baseUrl":"https://api.openai.com/v1"}}`, (*Registrar).RegisterQwenCodeLane,
		},
		{
			"qwen: active model resolves to a provider on another host", ".qwen", "settings.json",
			`{"model":{"name":"x","baseUrl":"https://openrouter.ai/api/v1"},"modelProviders":{"openai":[{"id":"x","baseUrl":"https://dashscope.example.com/v1","envKey":"K"}]}}`, (*Registrar).RegisterQwenCodeLane,
		},
		{
			"qwen: credential in the URL", ".qwen", "settings.json",
			`{"model":{"name":"x","baseUrl":"https://u:p@openrouter.ai/api/v1"}}`, (*Registrar).RegisterQwenCodeLane,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := maintainHome(t)
			writeFile(t, filepath.Join(home, tc.dir), tc.file, tc.body)
			r := maintainRegistrar(t, home)
			res := tc.write(r)
			if res.Error == nil || res.Added {
				t.Fatalf("result %+v, want a refusal", res)
			}
			if readBytes(t, filepath.Join(home, tc.dir, tc.file)) != tc.body {
				t.Fatal("a refused lane write changed the file")
			}
			if strings.Contains(res.Error.Error(), "sk-test") || strings.Contains(res.Error.Error(), "u:p@") {
				t.Fatalf("refusal quotes the file: %v", res.Error)
			}
		})
	}
}

// TestQwenCodeLaneRetargetsProvidersAndRestores: model.baseUrl and the
// openai-lane entries on the same host move to the lane URL (ids and envKeys
// kept); entries on other hosts are untouched; removal restores the host.
func TestQwenCodeLaneRetargetsProvidersAndRestores(t *testing.T) {
	home := maintainHome(t)
	const body = `{"model":{"name":"qwen/qwen3-coder","baseUrl":"https://openrouter.ai/api/v1"},"modelProviders":{"openai":[{"id":"qwen/qwen3-coder","baseUrl":"https://openrouter.ai/api/v1","envKey":"OPENROUTER_API_KEY"},{"id":"other","baseUrl":"https://dashscope.example.com/v1","envKey":"DASH"}]}}`
	writeFile(t, filepath.Join(home, ".qwen"), "settings.json", body)
	r := maintainRegistrar(t, home)
	got := resultFor(r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true), InstallLane: func(string, string) error { return nil }}), "qwen-code")
	if !got.Written || got.Error != nil {
		t.Fatalf("qwen-code: %+v", got)
	}
	path := filepath.Join(home, ".qwen", "settings.json")
	var doc struct {
		Model struct {
			BaseURL string `json:"baseUrl"`
		} `json:"model"`
		ModelProviders struct {
			OpenAI []map[string]string `json:"openai"`
		} `json:"modelProviders"`
	}
	if err := json.Unmarshal([]byte(readBytes(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	lane := "http://127.0.0.1:8820/up/route-openrouter-ai/api/v1"
	if doc.Model.BaseURL != lane || doc.ModelProviders.OpenAI[0]["baseUrl"] != lane ||
		doc.ModelProviders.OpenAI[0]["envKey"] != "OPENROUTER_API_KEY" || doc.ModelProviders.OpenAI[1]["baseUrl"] != "https://dashscope.example.com/v1" {
		t.Fatalf("qwen after lane write: %+v", doc)
	}
	if _, err := r.ReleaseManagedRoutes(true); err != nil {
		t.Fatal(err)
	}
	var before, after any
	_ = json.Unmarshal([]byte(body), &before)
	_ = json.Unmarshal([]byte(readBytes(t, path)), &after)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("qwen after release:\n%s\nwant\n%s", readBytes(t, path), body)
	}
}

// TestReleaseKeepsDeveloperRoutes: admin OFF removes the organization's
// routes (enrolment and managed) but never a route a developer set, and
// never an organization route the developer changed afterwards.
func TestReleaseKeepsDeveloperRoutes(t *testing.T) {
	home := maintainHome(t)
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", `{}`)
	writeFile(t, filepath.Join(home, ".codex"), "config.toml", "model = \"gpt-5\"\n")
	initReg, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Writer: routeprov.WriterInit})
	if err != nil {
		t.Fatal(err)
	}
	if res := initReg.RegisterCodex(); res.Error != nil {
		t.Fatal(res.Error)
	}
	codexBefore := readBytes(t, filepath.Join(home, ".codex", "config.toml"))
	r := maintainRegistrar(t, home)
	r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})
	if s := statusFor(InspectRoutes(home), "claude-code"); s.State != RouteOurs {
		t.Fatalf("claude-code not routed: %q", s.State)
	}
	out, err := r.ReleaseManagedRoutes(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, lr := range out {
		if lr.Tool == "codex" {
			t.Fatalf("release considered the developer's codex route: %+v", lr)
		}
	}
	if s := statusFor(InspectRoutes(home), "claude-code"); s.State != RouteAbsent {
		t.Fatalf("claude-code after release: %q, want absent", s.State)
	}
	if readBytes(t, filepath.Join(home, ".codex", "config.toml")) != codexBefore {
		t.Fatal("release changed the developer's codex route")
	}

	// A managed route the developer changed afterwards is kept.
	r.MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)})
	writeFile(t, filepath.Join(home, ".claude"), "settings.json", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:9999"}}`)
	out, _ = r.ReleaseManagedRoutes(true)
	if len(out) != 1 || out[0].Removed || out[0].Reason != routeprov.ReasonChangedAfterEnrol {
		t.Fatalf("release of a changed route = %+v, want kept", out)
	}
}
