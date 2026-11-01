package proxyroute

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// probeLeaveCase is one probe-lane tool's Leave round trip.
type probeLeaveCase struct {
	tool  string
	seed  string
	write func(t *testing.T, home, body string) string
	reg   func(r *Registrar) RegistrationResult
	// keep are fragments (incl. the fake credential) that must survive.
	keep []string
	// routed checks the route value after register.
	routed func(t *testing.T, raw []byte)
	// restored checks the file after Leave; routed is the file before it.
	restored func(t *testing.T, routed, raw []byte)
}

func probeLeaveCases() []probeLeaveCase {
	const proxy = "http://127.0.0.1:18644/v1"
	return []probeLeaveCase{
		{
			tool:  "kimi-code",
			seed:  kimiBaseConfig,
			write: writeKimiConfig,
			reg:   func(r *Registrar) RegistrationResult { return r.RegisterKimiCode() },
			keep:  []string{kimiKey, "[thinking]", "context = 128000"},
			routed: func(t *testing.T, raw []byte) {
				if got := kimiTOMLBaseURL(t, raw); got != proxy {
					t.Fatalf("kimi base_url after register = %q", got)
				}
			},
			restored: func(t *testing.T, routed, raw []byte) {
				if got := kimiTOMLBaseURL(t, raw); got != "" {
					t.Fatalf("kimi base_url after Leave = %q, want removed", got)
				}
				// Surgical: exactly the base_url line is gone, every other
				// byte the writer left is kept.
				var want []string
				for _, l := range strings.SplitAfter(string(routed), "\n") {
					if !strings.HasPrefix(strings.TrimSpace(l), "base_url") {
						want = append(want, l)
					}
				}
				if string(raw) != strings.Join(want, "") {
					t.Fatalf("Leave changed more than the base_url line:\n%s\nwant\n%s", raw, strings.Join(want, ""))
				}
			},
		},
		{
			tool:  "crush",
			seed:  crushBaseConfig,
			write: writeCrushConfig,
			reg:   func(r *Registrar) RegistrationResult { return r.RegisterCrush() },
			keep:  []string{crushKey, "anthropic-key-xyz", `"large"`},
			routed: func(t *testing.T, raw []byte) {
				if got := jsonPath(t, raw, "providers", "openai", "base_url"); got != proxy {
					t.Fatalf("crush base_url after register = %v", got)
				}
			},
			restored: func(t *testing.T, _, raw []byte) {
				if got := jsonPath(t, raw, "providers", "openai", "base_url"); got != nil {
					t.Fatalf("crush base_url after Leave = %v, want removed", got)
				}
			},
		},
		{
			tool:  "qwen-code",
			seed:  qwenConfigWithProviders("https://api.openai.com/v1"),
			write: writeQwenConfig,
			reg:   func(r *Registrar) RegistrationResult { return r.RegisterQwenCode() },
			keep:  []string{"QWEN_CUSTOM_OPENAI", "https://api.deepseek.com", `"theme"`},
			routed: func(t *testing.T, raw []byte) {
				if got := jsonPath(t, raw, "model", "baseUrl"); got != proxy {
					t.Fatalf("qwen model.baseUrl after register = %v", got)
				}
			},
			restored: func(t *testing.T, _, raw []byte) {
				if got := jsonPath(t, raw, "model", "baseUrl"); got != qwenDefaultBaseURL {
					t.Fatalf("qwen model.baseUrl after Leave = %v, want the default", got)
				}
				if strings.Contains(string(raw), proxy) {
					t.Fatalf("a modelProviders entry still points at the proxy:\n%s", raw)
				}
				var doc map[string]any
				_ = json.Unmarshal(raw, &doc)
				list := doc["modelProviders"].(map[string]any)["openai"].([]any)
				if e := list[0].(map[string]any); e["baseUrl"] != qwenDefaultBaseURL || e["envKey"] != "QWEN_CUSTOM_OPENAI" {
					t.Fatalf("openai provider after Leave = %v", e)
				}
			},
		},
	}
}

func kimiTOMLBaseURL(t *testing.T, raw []byte) string {
	t.Helper()
	root := map[string]any{}
	if err := toml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	p, _ := root["providers"].(map[string]any)
	o, _ := p["openai"].(map[string]any)
	s, _ := o["base_url"].(string)
	return s
}

func jsonPath(t *testing.T, raw []byte, path ...string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func probeEnv(t *testing.T) {
	t.Helper()
	t.Setenv("KIMI_CODE_HOME", "")
	t.Setenv("QWEN_HOME", "")
	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
}

// TestLeaveRemovesProbeRoutes pins T-156a: Leave removes the kimi-code,
// qwen-code and crush routes enrolment wrote, through each tool's own
// remover, changing only the route keys (the fake credentials, the other
// providers, comments and the file mode survive). Before T-156a they were
// recorded but kept with "remove it there by hand".
func TestLeaveRemovesProbeRoutes(t *testing.T) {
	for _, c := range probeLeaveCases() {
		t.Run(c.tool, func(t *testing.T) {
			probeEnv(t)
			home := t.TempDir()
			path := c.write(t, home, c.seed)
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			if res := c.reg(provReg(t, home, routeprov.WriterEnrolment)); !res.Added || res.Error != nil {
				t.Fatalf("register = %+v", res)
			}
			routed, _ := os.ReadFile(path)
			c.routed(t, routed)
			_ = os.Chmod(path, 0o640) // the writers write 0600; the remover must keep whatever it finds

			plan, err := provReg(t, home, "").LeaveRoutes(false)
			if err != nil {
				t.Fatal(err)
			}
			if d := onlyRoute(t, plan, c.tool); d.Action != routeprov.ActionRemove || d.Reason != routeprov.ReasonWrittenByEnrolment {
				t.Fatalf("plan = %+v, want remove / written_by_enrolment", d)
			}
			done, err := provReg(t, home, "").LeaveRoutes(true)
			if err != nil {
				t.Fatal(err)
			}
			if d := onlyRoute(t, done, c.tool); !d.Removed || d.Error != "" {
				t.Fatalf("leave = %+v", d)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			c.restored(t, routed, after)
			for _, k := range c.keep {
				if !strings.Contains(string(after), k) {
					t.Fatalf("Leave lost %q:\n%s", k, after)
				}
			}
			// POSIX-only: Windows has no mode bits (Perm reports 0666 or 0444).
			if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
				t.Fatalf("mode = %v, want 0640 kept", fi.Mode().Perm())
			}
			if f, _ := loadProvenance(provReg(t, home, "").ProvenancePath()); f.Find(c.tool, path) != nil {
				t.Fatal("the provenance record survived the removal")
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".tmp") {
					t.Fatalf("temp file left behind: %s", e.Name())
				}
			}
		})
	}
}

// TestLeaveKeepsChangedProbeRoute: a probe route changed after enrolment is
// kept (routeprov's rule, now reachable for these tools), and the file is not
// touched.
func TestLeaveKeepsChangedProbeRoute(t *testing.T) {
	probeEnv(t)
	home := t.TempDir()
	path := writeKimiConfig(t, home, kimiBaseConfig)
	if res := provReg(t, home, routeprov.WriterEnrolment).RegisterKimiCode(); !res.Added {
		t.Fatalf("register = %+v", res)
	}
	raw, _ := os.ReadFile(path)
	changed := strings.Replace(string(raw), "127.0.0.1:18644", "127.0.0.1:9999", 1)
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	done, err := provReg(t, home, "").LeaveRoutes(true)
	if err != nil {
		t.Fatal(err)
	}
	if d := onlyRoute(t, done, "kimi-code"); d.Removed || d.Reason != routeprov.ReasonChangedAfterEnrol {
		t.Fatalf("leave = %+v, want kept as changed_after_enrolment", d)
	}
	if after, _ := os.ReadFile(path); string(after) != changed {
		t.Fatalf("a kept route's file was touched:\n%s", after)
	}
}

// TestProbeRouteErrorsNeverQuoteTheFile: a credential-bearing file that does
// not parse yields an error that names the file but quotes nothing from it
// (D-268 / D-270).
func TestProbeRouteErrorsNeverQuoteTheFile(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name   string
		file   string
		body   string
		read   func(string) (string, bool, error)
		remove func(string, string, string) error
	}{
		{"kimi-code", "config.toml", "[providers.openai]\napi_key = \"sk-test-not-real\"\nbase_url = = broken\n", readKimiRouteAt, removeKimiRouteAt},
		{"crush", "crush.json", `{"providers":{"openai":{"api_key":"sk-test-not-real",,}}}`, readCrushRouteAt, removeCrushRouteAt},
		{"qwen-code", "settings.json", `{"model":{"apiKey":"sk-test-not-real","baseUrl": }`, readQwenRouteAt, removeQwenRouteAt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, c.name+"-"+c.file)
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, rerr := c.read(path)
			werr := c.remove(path, "http://127.0.0.1:18644/v1", "")
			for _, err := range []error{rerr, werr} {
				if err == nil {
					t.Fatal("a file that does not parse must be an error")
				}
				if strings.Contains(err.Error(), "sk-test-not-real") || strings.Contains(err.Error(), "broken") {
					t.Fatalf("error quotes the file: %v", err)
				}
			}
			if after, _ := os.ReadFile(path); string(after) != c.body {
				t.Fatal("a refused removal touched the file")
			}
		})
	}
}
