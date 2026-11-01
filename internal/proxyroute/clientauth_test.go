package proxyroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

const testClientToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func clientAuthRegistrar(t *testing.T, home, token string) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, ClientToken: token})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	return r
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestClientAuthRouteForm walks claude-code and codex through the client
// token migration: plain route, token form, back to plain. The token is in
// the tool's config file and never in the result a caller prints.
func TestClientAuthRouteForm(t *testing.T) {
	t.Parallel()
	type tool struct {
		name     string
		register func(*Registrar) RegistrationResult
		file     func(home string) string
		plain    string
		token    string
	}
	tools := []tool{
		{
			"claude-code", (*Registrar).RegisterClaudeCode, func(h string) string { return filepath.Join(h, ".claude", "settings.json") },
			"http://127.0.0.1:8820", "http://127.0.0.1:8820/t/" + testClientToken,
		},
		{
			"codex", (*Registrar).RegisterCodex, func(h string) string { return filepath.Join(h, ".codex", "config.toml") },
			"http://127.0.0.1:8820/v1", "http://127.0.0.1:8820/t/" + testClientToken + "/v1",
		},
	}
	for _, tc := range tools {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Dir(tc.file(home)), 0o755); err != nil {
				t.Fatal(err)
			}
			// 1. Plain route, as today.
			res := tc.register(clientAuthRegistrar(t, home, ""))
			if res.Error != nil || !res.Added || res.ClientAuth {
				t.Fatalf("plain write: %+v", res)
			}
			if !strings.Contains(readFileString(t, tc.file(home)), tc.plain) {
				t.Fatalf("plain route not written")
			}
			// 2. The token form replaces our own plain route.
			res = tc.register(clientAuthRegistrar(t, home, testClientToken))
			if res.Error != nil || !res.Added || !res.ClientAuth {
				t.Fatalf("token write: %+v", res)
			}
			if strings.Contains(res.BaseURL, testClientToken) || !strings.Contains(res.BaseURL, "<redacted>") {
				t.Fatalf("result BaseURL %q must be redacted", res.BaseURL)
			}
			if !strings.Contains(readFileString(t, tc.file(home)), tc.token) {
				t.Fatalf("token route not written:\n%s", readFileString(t, tc.file(home)))
			}
			st := inspectorStatus(t, home, tc.name)
			if st.State != RouteOurs || !st.ClientAuth || !st.ClientAuthWritable {
				t.Fatalf("inspection of the token route: %+v", st)
			}
			// 3. Idempotent in the token form.
			res = tc.register(clientAuthRegistrar(t, home, testClientToken))
			if res.Error != nil || res.Added || !res.AlreadySet || !res.ClientAuth {
				t.Fatalf("token rewrite: %+v", res)
			}
			// 4. Token switched off: back to the plain form.
			res = tc.register(clientAuthRegistrar(t, home, ""))
			if res.Error != nil || !res.Added || res.ClientAuth {
				t.Fatalf("plain rewrite: %+v", res)
			}
			got := readFileString(t, tc.file(home))
			if strings.Contains(got, testClientToken) || !strings.Contains(got, tc.plain) {
				t.Fatalf("plain form not restored:\n%s", got)
			}
		})
	}
}

// TestClientAuthUnregisterRemovesTokenRoute: uninstall removes the token
// form of this install's route and never prints the token.
func TestClientAuthUnregisterRemovesTokenRoute(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	r := clientAuthRegistrar(t, home, testClientToken)
	for _, reg := range []func(*Registrar) RegistrationResult{(*Registrar).RegisterClaudeCode, (*Registrar).RegisterCodex} {
		if res := reg(r); res.Error != nil || !res.Added {
			t.Fatalf("register: %+v", res)
		}
	}
	plain := clientAuthRegistrar(t, home, "")
	for _, unreg := range []func(*Registrar) RegistrationResult{(*Registrar).UnregisterClaudeCode, (*Registrar).UnregisterCodex} {
		res := unreg(plain)
		if res.Error != nil || !res.Added {
			t.Fatalf("unregister: %+v", res)
		}
		if strings.Contains(res.BaseURL, testClientToken) {
			t.Fatalf("unregister result carries the token: %q", res.BaseURL)
		}
	}
	for _, p := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".codex", "config.toml")} {
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), testClientToken) {
			t.Fatalf("%s still carries the token route:\n%s", p, b)
		}
	}
}

func inspectorStatus(t *testing.T, home, tool string) RouteStatus {
	t.Helper()
	for _, st := range InspectRoutes(home) {
		if st.Tool == tool {
			return st
		}
	}
	t.Fatalf("no inspection row for %s", tool)
	return RouteStatus{}
}

// TestMaintainClientAuthFormKeepsPriors drives managed maintenance through a
// real route-provenance file (audit F3): an organization-written Codex route
// that replaced the developer's own model_provider is rewritten to the
// client token form, the record keeps what the first write replaced, and
// leaving the organization still puts that provider back.
func TestMaintainClientAuthFormKeepsPriors(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	cfgPath := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("model_provider = \"my-provider\"\n\n[model_providers.my-provider]\nname = \"mine\"\nbase_url = \"https://llm.example.test/v1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := func(token string) *Registrar {
		r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Force: true, Writer: routeprov.WriterManaged, ClientToken: token})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if res := managed("").RegisterCodex(); res.Error != nil || !res.Added {
		t.Fatalf("the organization's plain write: %+v", res)
	}
	got := resultFor(managed(testClientToken).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)}), "codex")
	if got.Error != nil || !got.Written || got.Repaired || got.Decision.Reason != ReasonClientAuthForm {
		t.Fatalf("maintenance: %+v", got)
	}
	if !strings.Contains(readFileString(t, cfgPath), "/t/"+testClientToken+"/v1") {
		t.Fatalf("the route is not in the token form:\n%s", readFileString(t, cfgPath))
	}
	f, err := loadProvenance(managed("").ProvenancePath())
	if err != nil {
		t.Fatal(err)
	}
	rec := f.Find("codex", cfgPath)
	if rec == nil || rec.PriorProvider != "my-provider" || !strings.Contains(rec.Value, testClientToken) || rec.Writer != routeprov.WriterManaged {
		t.Fatalf("provenance after the form change: %+v", rec)
	}
	// A second pass in the same form changes nothing.
	if again := resultFor(managed(testClientToken).MaintainRoutes(MaintainOptions{Required: true, ProxyHealthy: always(true)}), "codex"); again.Written {
		t.Fatalf("second pass rewrote: %+v", again)
	}
	// Leaving puts the developer's provider back.
	if _, err := managed(testClientToken).ReleaseManagedRoutes(true); err != nil {
		t.Fatal(err)
	}
	after := readFileString(t, cfgPath)
	if !strings.Contains(after, `model_provider = "my-provider"`) || strings.Contains(after, testClientToken) {
		t.Fatalf("release did not restore the developer's provider:\n%s", after)
	}
}
