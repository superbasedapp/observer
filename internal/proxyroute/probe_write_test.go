package proxyroute

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// T-657: the kimi-code / qwen-code / crush route WRITERS follow the same
// credential-file discipline as their removers: surgical (comments and key
// order kept), no backup copy, mode kept, layouts they cannot own refused,
// and no error quotes the file.

// probeFakeKey is a fake credential: it must never appear in an error.
const probeFakeKey = "sk-test-not-real-0000"

type probeWriterCase struct {
	name     string
	file     func(home string) string
	register func(r *Registrar) RegistrationResult
	// seed is a valid routable config with a comment / unsorted keys the
	// writer must keep byte for byte.
	seed string
	// keep are fragments of seed that must survive, in this order.
	keep []string
	// added is the fragment the route write introduces.
	added string
	// foreign is a config whose route key points elsewhere.
	foreign    string
	foreignURL string
}

func probeWriterCases() []probeWriterCase {
	return []probeWriterCase{
		{
			name:     "kimi-code",
			file:     func(home string) string { return filepath.Join(home, ".kimi-code", "config.toml") },
			register: func(r *Registrar) RegistrationResult { return r.RegisterKimiCode() },
			seed: "# kimi config, hand-edited\n" +
				"zeta = 1\n" +
				"default_model = \"openai/gpt-4o\"\n\n" +
				"[providers.openai]\n" +
				"type = \"openai\" # provider kind\n" +
				"api_key = \"" + probeFakeKey + "\"\n\n" +
				"[alpha]\n" +
				"enabled = true\n",
			keep:       []string{"# kimi config, hand-edited\n", "zeta = 1\n", "type = \"openai\" # provider kind\n", "[alpha]\n"},
			added:      "base_url = \"http://127.0.0.1:8820/v1\"",
			foreign:    "[providers.openai]\napi_key = \"" + probeFakeKey + "\"\nbase_url = \"https://foreign.example.invalid/v1\"\n",
			foreignURL: "foreign.example.invalid",
		},
		{
			name:     "crush",
			file:     func(home string) string { return filepath.Join(home, ".config", "crush", "crush.json") },
			register: func(r *Registrar) RegistrationResult { return r.RegisterCrush() },
			seed: "{\n" +
				"    \"zeta\": 1,\n" +
				"    \"providers\": {\n" +
				"        \"openai\": {\"type\": \"openai\", \"api_key\": \"" + probeFakeKey + "\"}\n" +
				"    },\n" +
				"    \"alpha\": true\n" +
				"}\n",
			keep:       []string{"    \"zeta\": 1,\n", "\"api_key\": \"" + probeFakeKey + "\"", "    \"alpha\": true\n"},
			added:      "\"base_url\": \"http://127.0.0.1:8820/v1\"",
			foreign:    `{"providers":{"openai":{"api_key":"` + probeFakeKey + `","base_url":"https://foreign.example.invalid/v1"}}}`,
			foreignURL: "foreign.example.invalid",
		},
		{
			name:     "qwen-code",
			file:     func(home string) string { return filepath.Join(home, ".qwen", "settings.json") },
			register: func(r *Registrar) RegistrationResult { return r.RegisterQwenCode() },
			seed: "{\n" +
				"    \"zeta\": 1,\n" +
				"    \"model\": {\"name\": \"gpt-4o\", \"apiKey\": \"" + probeFakeKey + "\", \"baseUrl\": \"https://api.openai.com/v1\"},\n" +
				"    \"modelProviders\": {\"openai\": [{\"id\": \"gpt-4o\", \"envKey\": \"OPENAI_API_KEY\", \"baseUrl\": \"https://api.openai.com/v1\"}]},\n" +
				"    \"alpha\": true\n" +
				"}\n",
			keep:       []string{"    \"zeta\": 1,\n", "\"apiKey\": \"" + probeFakeKey + "\"", "    \"alpha\": true\n"},
			added:      "\"baseUrl\": \"http://127.0.0.1:8820/v1\"",
			foreign:    `{"model":{"apiKey":"` + probeFakeKey + `","baseUrl":"https://foreign.example.invalid/v1"}}`,
			foreignURL: "foreign.example.invalid",
		},
	}
}

func probeRegistrar(t *testing.T, home string) *Registrar {
	t.Helper()
	for _, k := range []string{"KIMI_CODE_HOME", "QWEN_HOME", "CRUSH_GLOBAL_CONFIG", "XDG_CONFIG_HOME"} {
		t.Setenv(k, "")
	}
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	return r
}

func seedProbeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// inOrder reports whether every fragment occurs in s, in order.
func inOrder(s string, frags []string) bool {
	at := 0
	for _, f := range frags {
		i := strings.Index(s[at:], f)
		if i < 0 {
			return false
		}
		at += i + len(f)
	}
	return true
}

func TestProbeRouteWritersAreSurgical(t *testing.T) {
	for _, tc := range probeWriterCases() {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := tc.file(home)
			seedProbeFile(t, path, tc.seed, 0o640)
			res := tc.register(probeRegistrar(t, home))
			if res.Error != nil || !res.Added {
				t.Fatalf("register: added=%v err=%v", res.Added, res.Error)
			}
			out, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !inOrder(string(out), tc.keep) {
				t.Errorf("the write did not keep the file's other bytes (comments, key order):\n%s", out)
			}
			if !strings.Contains(string(out), tc.added) {
				t.Errorf("route not written:\n%s", out)
			}
			if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
				t.Errorf("a .bak copy of the credential-bearing file was left behind")
			}
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			// POSIX-only: Windows has no mode bits (Perm reports 0666 or 0444).
			if got := fi.Mode().Perm(); runtime.GOOS != "windows" && got != 0o640 {
				t.Errorf("mode = %o, want 0640 kept", got)
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".tmp") {
					t.Errorf("temp file left behind: %s", e.Name())
				}
			}
		})
	}
}

func TestProbeRouteWritersNeverQuoteTheFile(t *testing.T) {
	for _, tc := range probeWriterCases() {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := tc.file(home)
			seedProbeFile(t, path, tc.foreign, 0o600)
			res := tc.register(probeRegistrar(t, home))
			if res.Error == nil {
				t.Fatal("expected a refusal on a foreign base URL")
			}
			msg := res.Error.Error()
			if strings.Contains(msg, tc.foreignURL) || strings.Contains(msg, probeFakeKey) {
				t.Errorf("error quotes a value read from the credential-bearing file: %s", msg)
			}
			if res.PriorBaseURL != "" {
				t.Errorf("PriorBaseURL carries a value read from the file: %q", res.PriorBaseURL)
			}
			if got, _ := os.ReadFile(path); string(got) != tc.foreign {
				t.Errorf("refusal mutated the file")
			}
		})
	}
}

func TestProbeRouteWritersRefuseASymlink(t *testing.T) {
	for _, tc := range probeWriterCases() {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := tc.file(home)
			real := filepath.Join(home, "dotfiles", filepath.Base(path))
			seedProbeFile(t, real, tc.seed, 0o600)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, path); err != nil {
				t.Skipf("symlink: %v", err)
			}
			res := tc.register(probeRegistrar(t, home))
			if res.Error == nil || res.Added {
				t.Fatalf("a symlinked config must be refused: added=%v err=%v", res.Added, res.Error)
			}
			if strings.Contains(res.Error.Error(), probeFakeKey) {
				t.Errorf("error quotes the file: %v", res.Error)
			}
			fi, err := os.Lstat(path)
			if err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("the symlink was replaced (err=%v)", err)
			}
			if got, _ := os.ReadFile(real); string(got) != tc.seed {
				t.Errorf("the link target was changed")
			}
		})
	}
}

func TestProbeRouteWritersRefuseLayoutsTheyCannotOwn(t *testing.T) {
	cases := []struct {
		name     string
		file     func(home string) string
		register func(r *Registrar) RegistrationResult
		body     string
	}{
		{
			name:     "kimi inline table",
			file:     func(home string) string { return filepath.Join(home, ".kimi-code", "config.toml") },
			register: func(r *Registrar) RegistrationResult { return r.RegisterKimiCode() },
			body:     "# keep\nproviders = { openai = { api_key = \"" + probeFakeKey + "\" } }\n",
		},
		{
			name:     "kimi base_url of another type",
			file:     func(home string) string { return filepath.Join(home, ".kimi-code", "config.toml") },
			register: func(r *Registrar) RegistrationResult { return r.RegisterKimiCode() },
			body:     "[providers.openai]\napi_key = \"" + probeFakeKey + "\"\nbase_url = 7\n",
		},
		{
			name:     "qwen modelProviders of another type",
			file:     func(home string) string { return filepath.Join(home, ".qwen", "settings.json") },
			register: func(r *Registrar) RegistrationResult { return r.RegisterQwenCode() },
			body:     `{"model":{"name":"m","apiKey":"` + probeFakeKey + `","baseUrl":"https://api.openai.com/v1"},"modelProviders":"see docs"}`,
		},
		{
			name:     "crush base_url of another type",
			file:     func(home string) string { return filepath.Join(home, ".config", "crush", "crush.json") },
			register: func(r *Registrar) RegistrationResult { return r.RegisterCrush() },
			body:     `{"providers":{"openai":{"api_key":"` + probeFakeKey + `","base_url":["x"]}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := tc.file(home)
			seedProbeFile(t, path, tc.body, 0o600)
			res := tc.register(probeRegistrar(t, home))
			if res.Error == nil || res.Added {
				t.Fatalf("want a refusal: added=%v err=%v", res.Added, res.Error)
			}
			if strings.Contains(res.Error.Error(), probeFakeKey) {
				t.Errorf("error quotes the file: %v", res.Error)
			}
			if got, _ := os.ReadFile(path); string(got) != tc.body {
				t.Errorf("refusal mutated the file:\n%s", got)
			}
		})
	}
}
