package proxyroute

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const crushKey = "routed-key-def"

func newCrushRegistrar(t *testing.T, home string) *Registrar {
	t.Helper()
	// Force homeDir/.config/crush resolution (no env override).
	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	return r
}

func writeCrushConfig(t *testing.T, home, body string) string {
	t.Helper()
	dir := filepath.Join(home, ".config", "crush")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "crush.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const crushBaseConfig = `{
  "providers": {
    "openai": {
      "api_key": "` + crushKey + `",
      "type": "openai"
    },
    "anthropic": {
      "api_key": "anthropic-key-xyz",
      "type": "anthropic"
    }
  },
  "models": {
    "large": {"model": "gpt-4o", "provider": "openai"}
  }
}`

func TestRegisterCrushAddsBaseURLWithoutBackup(t *testing.T) {
	home := t.TempDir()
	path := writeCrushConfig(t, home, crushBaseConfig)
	r := newCrushRegistrar(t, home)

	res := r.RegisterCrush()
	if res.Error != nil {
		t.Fatalf("RegisterCrush: %v", res.Error)
	}
	if !res.Added || res.ConfigMissing {
		t.Fatalf("want Added; got Added=%v ConfigMissing=%v", res.Added, res.ConfigMissing)
	}

	// T-657: no backup copy of a credential-bearing file.
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Errorf("the writer must leave no .bak copy of the file")
	}

	var doc map[string]any
	out, _ := os.ReadFile(path)
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	providers := doc["providers"].(map[string]any)
	openai := providers["openai"].(map[string]any)
	if openai["base_url"] != "http://127.0.0.1:8820/v1" {
		t.Errorf("base_url not added: %v", openai["base_url"])
	}
	if openai["api_key"] != crushKey {
		t.Errorf("api_key clobbered: %v", openai["api_key"])
	}
	// Unrelated provider + its key preserved byte-faithfully.
	anthropic := providers["anthropic"].(map[string]any)
	if anthropic["api_key"] != "anthropic-key-xyz" || anthropic["type"] != "anthropic" {
		t.Errorf("sibling provider mutated: %v", anthropic)
	}
	if _, ok := doc["models"]; !ok {
		t.Errorf("sibling models block lost")
	}
}

func TestRegisterCrushIdempotent(t *testing.T) {
	home := t.TempDir()
	writeCrushConfig(t, home, crushBaseConfig)
	r := newCrushRegistrar(t, home)
	if res := r.RegisterCrush(); res.Error != nil || !res.Added {
		t.Fatalf("first run: err=%v added=%v", res.Error, res.Added)
	}
	res := r.RegisterCrush()
	if res.Error != nil {
		t.Fatalf("second run err: %v", res.Error)
	}
	if !res.AlreadySet || res.Added {
		t.Errorf("re-run should be AlreadySet no-op, got Added=%v AlreadySet=%v", res.Added, res.AlreadySet)
	}
}

func TestRegisterCrushRefusesForeignURL(t *testing.T) {
	home := t.TempDir()
	cfg := `{"providers":{"openai":{"api_key":"` + crushKey + `","base_url":"https://gateway.example.com/v1"}}}`
	path := writeCrushConfig(t, home, cfg)
	r := newCrushRegistrar(t, home)
	res := r.RegisterCrush()
	if res.Error == nil {
		t.Fatal("expected refusal on a foreign base_url")
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Errorf("refusal must not write a .bak")
	}
	out, _ := os.ReadFile(path)
	if !strings.Contains(string(out), "gateway.example.com") {
		t.Errorf("refusal must not mutate the file")
	}
}

func TestRegisterCrushMissingConfigSkips(t *testing.T) {
	home := t.TempDir()
	r := newCrushRegistrar(t, home)
	res := r.RegisterCrush()
	if res.Error != nil {
		t.Fatalf("missing config should be benign skip: %v", res.Error)
	}
	if !res.ConfigMissing {
		t.Errorf("want ConfigMissing, got %+v", res)
	}
}

func TestRegisterCrushNoProviderErrors(t *testing.T) {
	home := t.TempDir()
	writeCrushConfig(t, home, `{"models":{"large":{"model":"gpt-4o"}}}`)
	r := newCrushRegistrar(t, home)
	if res := r.RegisterCrush(); res.Error == nil {
		t.Fatal("expected error when providers.openai absent")
	}
}
