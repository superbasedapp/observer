package proxyroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// secretMark is planted in every fixture; no result or error may carry it.
const secretMark = "sk-SECRET-do-not-leak"

// memberFixture is one tool's starting files (artifact id -> body).
type memberFixture map[string]string

func memberPath(t *testing.T, home, artifact string) string {
	t.Helper()
	p, err := routeArtifactPath("test", artifact, home, nil)
	if err != nil {
		t.Fatalf("%s: %v", artifact, err)
	}
	return p
}

func writeFixture(t *testing.T, home string, f memberFixture) {
	t.Helper()
	for artifact, body := range f {
		p := memberPath(t, home, artifact)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func runLiveGated(t *testing.T) {
	t.Helper()
	runLiveGatedRouteWriters = true
	t.Cleanup(func() { runLiveGatedRouteWriters = false })
}

func memberRegistrar(t *testing.T, home string, force bool) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Force: force})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func runMember(r *Registrar, spec memberRouteSpec) RegistrationResult {
	if spec.defaultProvider {
		return r.RegisterDefaultProvider(spec.tool)
	}
	return r.RegisterMemberRoute(spec.tool)
}

func noLeak(t *testing.T, res RegistrationResult) {
	t.Helper()
	if res.Error != nil && strings.Contains(res.Error.Error(), secretMark) {
		t.Errorf("an error quotes the file: %v", res.Error)
	}
	if strings.Contains(res.BaseURL+res.PriorBaseURL+res.PriorProvider, secretMark) {
		t.Errorf("a result carries a file value: %+v", res)
	}
}

// memberCases are the writable starting points, one per row, and what the
// primary member must read after the write.
var memberCases = []struct {
	tool            string
	defaultProvider bool
	ok              memberFixture
	want            string
}{
	{"open-interpreter", false, memberFixture{"open-interpreter/user-config": "# mine\napi_key = \"" + secretMark + "\"\n"}, "http://127.0.0.1:8820/v1"},
	{"stakpak", false, memberFixture{"stakpak/user-config": "[profiles.default]\napi_key = \"" + secretMark + "\"\n\n[profiles.default.providers.openai]\ntype = \"openai\"\n"}, "http://127.0.0.1:8820/v1"},
	{"poolside", false, memberFixture{"poolside/personal-settings": "# personal\nweb_search:\n  api_key: " + secretMark + "\npool:\n  default_agent_server: local\n"}, "http://127.0.0.1:8820/up/poolside/v1"},
	{"goose", true, memberFixture{"goose/user-config": "active_provider: openai\nOPENAI_API_KEY: " + secretMark + "\n"}, "http://127.0.0.1:8820"},
	{"hermes", true, memberFixture{"hermes/user-config": "model:\n  default: x\nproviders:\n  observer:\n    base_url: http://127.0.0.1:8820/up/openrouter/api/v1\n  other:\n    api_key: " + secretMark + "\n"}, "observer"},
	{"pi", true, memberFixture{"pi/user-settings": "{\n  \"defaultModel\": \"gpt-4o\"\n}\n", "pi/user-models": "{\"providers\": {\"observer\": {\"baseUrl\": \"http://127.0.0.1:8820/v1\"}, \"x\": {\"apiKey\": \"" + secretMark + "\"}}}"}, "observer"},
	{"prime-agent", true, memberFixture{"prime-agent/user-settings": "{\"defaultModel\": \"m\"}", "prime-agent/user-models": "{\"providers\": {\"observer\": {\"baseUrl\": \"http://127.0.0.1:8820/v1\", \"apiKey\": \"" + secretMark + "\"}}}"}, "observer"},
}

// TestMemberRouteWritersAreGatedByDefault: with the registry's gate in
// force, every writer refuses with the DEC-12 wording and leaves the file
// byte-identical, and an absent file stays the benign ConfigMissing skip.
func TestMemberRouteWritersAreGatedByDefault(t *testing.T) {
	for _, tc := range memberCases {
		t.Run(tc.tool, func(t *testing.T) {
			spec, _ := memberSpecFor(tc.tool, tc.defaultProvider)
			empty := t.TempDir()
			if res := runMember(memberRegistrar(t, empty, false), spec); !res.ConfigMissing || res.Error != nil {
				t.Errorf("absent file: %+v, want ConfigMissing", res)
			}
			home := t.TempDir()
			writeFixture(t, home, tc.ok)
			res := runMember(memberRegistrar(t, home, false), spec)
			if res.Error != nil || res.Added || !strings.HasPrefix(res.SkipReason, LiveGateSkipPrefix+"built, waiting on live check LC") {
				t.Fatalf("gated writer ran: %+v", res)
			}
			for artifact, body := range tc.ok {
				if got, _ := os.ReadFile(memberPath(t, home, artifact)); string(got) != body {
					t.Errorf("%s changed under the gate", artifact)
				}
			}
		})
	}
}

// TestMemberRouteWrite runs every writer past its gate: the route lands,
// every other byte (the planted secret included) survives, a second run is
// AlreadySet, a dry run writes nothing, and Leave's remover puts the file
// back byte for byte.
func TestMemberRouteWrite(t *testing.T) {
	runLiveGated(t)
	for _, tc := range memberCases {
		t.Run(tc.tool, func(t *testing.T) {
			spec, _ := memberSpecFor(tc.tool, tc.defaultProvider)
			home := t.TempDir()
			writeFixture(t, home, tc.ok)
			path := memberPath(t, home, spec.artifact)
			before, _ := os.ReadFile(path)

			dry, _ := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, DryRun: true})
			if res := runMember(dry, spec); !res.Added || res.Error != nil {
				t.Fatalf("dry run: %+v", res)
			}
			if got, _ := os.ReadFile(path); string(got) != string(before) {
				t.Fatal("the dry run wrote")
			}

			res := runMember(memberRegistrar(t, home, false), spec)
			noLeak(t, res)
			if res.Error != nil || !res.Added || res.BaseURL != tc.want {
				t.Fatalf("write: %+v", res)
			}
			after, _ := os.ReadFile(path)
			if !strings.Contains(string(after), tc.want) {
				t.Errorf("route value missing:\n%s", after)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(before)), "\n") {
				if !strings.Contains(string(after), strings.TrimSpace(line)) && !strings.HasPrefix(strings.TrimSpace(line), "{") {
					t.Errorf("lost line %q:\n%s", line, after)
				}
			}
			if strings.Contains(string(before), secretMark) && !strings.Contains(string(after), secretMark) {
				t.Error("the secret's bytes did not survive")
			}
			again := runMember(memberRegistrar(t, home, false), spec)
			if again.Error != nil || !again.AlreadySet || again.Added {
				t.Errorf("second run: %+v", again)
			}

			shape, ok := shapeFor(tc.tool)
			if !ok {
				t.Fatal("no Leave shape for the row")
			}
			got, present, err := shape.read(path, nil)
			if err != nil || !present || got != tc.want {
				t.Fatalf("Leave read = %q %v %v", got, present, err)
			}
			if err := removeMemberRouteFor(spec, portOf)(path, tc.want, res.PriorProvider); err != nil {
				t.Fatalf("remove: %v", err)
			}
			if back, _ := os.ReadFile(path); string(back) != string(before) {
				t.Errorf("write then remove is not byte-identical:\nbefore:\n%s\nafter:\n%s", before, back)
			}
		})
	}
}

// TestMemberRouteRefusals covers each refusal rule; none writes, none
// quotes the file.
func TestMemberRouteRefusals(t *testing.T) {
	runLiveGated(t)
	for _, tc := range []struct {
		name            string
		tool            string
		defaultProvider bool
		force           bool
		files           memberFixture
		wantErr         string
		wantAdded       bool
	}{
		{"oi reserved openai table", "open-interpreter", false, false, memberFixture{"open-interpreter/user-config": "[model_providers.openai]\nkey = \"" + secretMark + "\"\n"}, "reserved", false},
		{"oi another provider selected", "open-interpreter", false, false, memberFixture{"open-interpreter/user-config": "model_provider = \"azure\"\n"}, "selects another provider", false},
		{"oi another provider, forced", "open-interpreter", false, true, memberFixture{"open-interpreter/user-config": "model_provider = \"azure\"\n"}, "", true},
		{"oi foreign base_url", "open-interpreter", false, false, memberFixture{"open-interpreter/user-config": "[model_providers.openai-observer]\nbase_url = \"https://" + secretMark + ".example/v1\"\n"}, "non-observer URL", false},
		{"stakpak no provider", "stakpak", false, false, memberFixture{"stakpak/user-config": "[profiles.default]\napi_key = \"" + secretMark + "\"\n"}, "has no [profiles.default.providers.openai] provider", false},
		{"poolside foreign api_url", "poolside", false, false, memberFixture{"poolside/personal-settings": "pool:\n  api_url: https://" + secretMark + ".example\n"}, "non-observer URL", false},
		{"goose other provider", "goose", true, false, memberFixture{"goose/user-config": "active_provider: anthropic\n"}, "active_provider: openai or GOOSE_PROVIDER: openai", false},
		{"hermes no observer provider", "hermes", true, false, memberFixture{"hermes/user-config": "model:\n  provider: openrouter\n"}, "providers.observer", false},
		{"pi no models.json", "pi", true, false, memberFixture{"pi/user-settings": "{}"}, "observer pi", false},
		{"pi models.json without observer", "pi", true, false, memberFixture{"pi/user-settings": "{}", "pi/user-models": "{\"providers\": {\"x\": {\"apiKey\": \"" + secretMark + "\"}}}"}, "has no providers.observer", false},
		{"pi another default provider", "pi", true, false, memberFixture{"pi/user-settings": "{\"defaultProvider\": \"anthropic\"}", "pi/user-models": "{\"providers\": {\"observer\": {}}}"}, "selects another provider", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, _ := memberSpecFor(tc.tool, tc.defaultProvider)
			home := t.TempDir()
			writeFixture(t, home, tc.files)
			path := memberPath(t, home, spec.artifact)
			before, _ := os.ReadFile(path)
			res := runMember(memberRegistrar(t, home, tc.force), spec)
			noLeak(t, res)
			if tc.wantErr == "" {
				if res.Error != nil || res.Added != tc.wantAdded {
					t.Fatalf("res = %+v", res)
				}
				if res.PriorProvider != "azure" {
					t.Errorf("PriorProvider = %q, want azure", res.PriorProvider)
				}
				return
			}
			if res.Error == nil || !strings.Contains(res.Error.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", res.Error, tc.wantErr)
			}
			if got, _ := os.ReadFile(path); string(got) != string(before) {
				t.Error("a refusal wrote")
			}
		})
	}
}

// TestMemberRouteRefusesLayouts: a symbolic link at the route path is
// refused without writing (the FIFO case is memberroute_fifo_unix_test.go).
func TestMemberRouteRefusesLayouts(t *testing.T) {
	runLiveGated(t)
	spec, _ := memberSpecFor("poolside", false)
	home := t.TempDir()
	path := memberPath(t, home, spec.artifact)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(home, "real.yaml")
	if err := os.WriteFile(real, []byte("pool: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Skip("no symlinks here")
	}
	if res := runMember(memberRegistrar(t, home, false), spec); res.Error == nil || !strings.Contains(res.Error.Error(), "symbolic link") {
		t.Errorf("symlink: %+v", res)
	}
}

// TestMemberRouteRowsMatchTheRegistry pins both directions: every writer
// row's registry entry declares the credential-file exception and carries a
// live gate on the right field, and every gated ProxyProbe / PersistedDefault
// writer in the registry that names this package's member writer has a row.
func TestMemberRouteRowsMatchTheRegistry(t *testing.T) {
	for _, spec := range memberRouteSpecs {
		if !integration.RouteSharesCredentialFile(spec.tool) {
			t.Errorf("%s: no credential-file declaration", spec.tool)
		}
		g := integration.RouteLiveGate(spec.tool)
		if spec.defaultProvider {
			g = integration.DefaultProviderLiveGate(spec.tool)
		}
		if !g.Waiting() {
			t.Errorf("%s (default=%v): the writer is not gated", spec.tool, spec.defaultProvider)
		}
	}
	rows := map[string]bool{}
	for _, s := range memberRouteSpecs {
		rows[s.tool+map[bool]string{true: "/default", false: ""}[s.defaultProvider]] = true
	}
	for _, c := range integration.Capabilities() {
		if c.ProxyProbe != nil && strings.Contains(c.ProxyProbe.Note, "RegisterMemberRoute") && !rows[c.Tool] {
			t.Errorf("%s: the registry names RegisterMemberRoute but the table has no row", c.Tool)
		}
		for _, r := range []*integration.ProxyRoute{c.Proxy, c.ProxyProbe} {
			if r != nil && r.PersistedDefault != nil && !rows[c.Tool+"/default"] {
				t.Errorf("%s: PersistedDefault without a default-provider row", c.Tool)
			}
		}
	}
}
