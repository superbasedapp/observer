package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Part B item 1 (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §6.7): registration writers for Gemini CLI, Qwen Code, and Factory
// Droid — closing BLOCK-1's real-world gap (a receiver with nothing
// that ever registers it is inert). Gemini CLI and Qwen Code share the
// Claude-Code-shaped settings.json machinery (registerGenericSettingsHooks);
// Droid reuses the Codex hooks.json shape directly.

func genericSettingsRegistry(t *testing.T, subdir string) *Registry {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, subdir), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegisterGeminiCLI_FreshInstall(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".gemini")
	res := r.Register("gemini-cli")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "BeforeAgent" {
		t.Errorf("HooksAdded = %v, want [BeforeAgent]", res.HooksAdded)
	}
	wantPath := filepath.Join(r.opts.HomeDir, ".gemini", "settings.json")
	if res.ConfigPath != wantPath {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("settings.json not valid JSON: %v\n%s", err, body)
	}
	hooks, ok := got["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("settings.json missing top-level hooks block: %s", body)
	}
	groups, ok := hooks["BeforeAgent"].([]any)
	if !ok || len(groups) != 1 {
		t.Fatalf("BeforeAgent group missing/wrong shape: %s", body)
	}
	if !strings.Contains(string(body), "hook gemini-cli BeforeAgent") {
		t.Errorf("settings.json command does not name the gemini-cli receiver: %s", body)
	}
}

func TestRegisterGeminiCLI_Idempotent(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".gemini")
	if res := r.Register("gemini-cli"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("gemini-cli")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second register added %v, want none", res.HooksAdded)
	}
	if len(res.AlreadySet) != 1 || res.AlreadySet[0] != "BeforeAgent" {
		t.Errorf("AlreadySet = %v, want [BeforeAgent]", res.AlreadySet)
	}
}

func TestRegisterGeminiCLI_PreservesUnrelatedSettings(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".gemini")
	path := filepath.Join(r.opts.HomeDir, ".gemini", "settings.json")
	pre := `{"model": {"name": "gemini-2.5-pro"}, "mcpServers": {"foo": {"command": "bar"}}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("gemini-cli")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "gemini-2.5-pro") {
		t.Errorf("model config lost: %s", body)
	}
	if !strings.Contains(string(body), "mcpServers") {
		t.Errorf("mcpServers config lost: %s", body)
	}
}

func TestRegisterGeminiCLI_ConflictWithoutForce(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".gemini")
	path := filepath.Join(r.opts.HomeDir, ".gemini", "settings.json")
	pre := `{"hooks":{"BeforeAgent":[{"hooks":[{"type":"command","command":"/usr/local/bin/my-policy"}]}]}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("gemini-cli")
	if res.Error == nil {
		t.Fatalf("expected conflict error, got HooksAdded=%v", res.HooksAdded)
	}
	if !strings.Contains(res.Error.Error(), "non-observer hook") {
		t.Errorf("unexpected error: %v", res.Error)
	}
}

func TestUnregisterGeminiCLI_RoundTrip(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".gemini")
	path := filepath.Join(r.opts.HomeDir, ".gemini", "settings.json")
	pre := `{"model": {"name": "gemini-2.5-pro"}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("gemini-cli"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	res := r.Unregister("gemini-cli")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}
	body, _ := os.ReadFile(path)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("settings.json not valid JSON after unregister: %v\n%s", err, body)
	}
	if !strings.Contains(string(body), "gemini-2.5-pro") {
		t.Errorf("unregister lost unrelated config: %s", body)
	}
	if hooks, ok := got["hooks"].(map[string]any); ok {
		if _, has := hooks["BeforeAgent"]; has {
			t.Errorf("BeforeAgent group still present after unregister: %s", body)
		}
	}
}

func TestRegisterQwenCode_FreshInstall(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".qwen")
	res := r.Register("qwen-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "UserPromptSubmit" {
		t.Errorf("HooksAdded = %v, want [UserPromptSubmit]", res.HooksAdded)
	}
	wantPath := filepath.Join(r.opts.HomeDir, ".qwen", "settings.json")
	if res.ConfigPath != wantPath {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "hook qwen-code UserPromptSubmit") {
		t.Errorf("settings.json command does not name the qwen-code receiver: %s", body)
	}
}

func TestRegisterQwenCode_Idempotent(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".qwen")
	if res := r.Register("qwen-code"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("qwen-code")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.AlreadySet) != 1 {
		t.Errorf("AlreadySet = %v, want one entry", res.AlreadySet)
	}
}

func TestRegisterFactoryDroid_FreshInstall(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".factory")
	res := r.Register("droid")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "UserPromptSubmit" {
		t.Errorf("HooksAdded = %v, want [UserPromptSubmit]", res.HooksAdded)
	}
	wantPath := filepath.Join(r.opts.HomeDir, ".factory", "hooks.json")
	if res.ConfigPath != wantPath {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("hooks.json not valid JSON: %v\n%s", err, body)
	}
	hooks, ok := got["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks.json missing top-level hooks block: %s", body)
	}
	groups, ok := hooks["UserPromptSubmit"].([]any)
	if !ok || len(groups) != 1 {
		t.Fatalf("UserPromptSubmit group missing/wrong shape: %s", body)
	}
	if !strings.Contains(string(body), "hook droid UserPromptSubmit") {
		t.Errorf("hooks.json command does not name the droid receiver: %s", body)
	}
}

func TestRegisterFactoryDroid_Idempotent(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".factory")
	if res := r.Register("droid"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("droid")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second register added %v, want none", res.HooksAdded)
	}
	if len(res.AlreadySet) != 1 {
		t.Errorf("AlreadySet = %v, want one entry", res.AlreadySet)
	}
}

func TestRegisterFactoryDroid_ConflictWithoutForce(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".factory")
	path := filepath.Join(r.opts.HomeDir, ".factory", "hooks.json")
	pre := `{"hooks":{"UserPromptSubmit":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/my-policy"}]}]}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("droid")
	if res.Error == nil {
		t.Fatalf("expected conflict error, got HooksAdded=%v", res.HooksAdded)
	}
	if !strings.Contains(res.Error.Error(), "non-observer hook") {
		t.Errorf("unexpected error: %v", res.Error)
	}
}

func TestUnregisterFactoryDroid_RoundTrip(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".factory")
	if res := r.Register("droid"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	res := r.Unregister("droid")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}
	body, _ := os.ReadFile(filepath.Join(r.opts.HomeDir, ".factory", "hooks.json"))
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("hooks.json not valid JSON after unregister: %v\n%s", err, body)
	}
	if hooks, ok := got["hooks"].(map[string]any); ok {
		if _, has := hooks["UserPromptSubmit"]; has {
			t.Errorf("UserPromptSubmit group still present after unregister: %s", body)
		}
	}
}

// --- Part B item 2 (phase-3a, docs/plans/prompt-submit-intervention-
// exploration-2026-09-07.md §2.1b): registration writers for the
// documented long-tail vendors. Qoder shares the Claude-Code-shaped
// settings.json machinery exactly like Gemini CLI/Qwen Code above;
// Poolside is this repo's FIRST YAML-format writer; Devin/Cascade's
// hooks.json is its OWN flat shape (no matcher, no "type" field).
// zcode has no writer at all (deliberately — see
// internal/integration's zcode row) and commandcode's writer lives in
// its own test file (a go:embed'd TypeScript module, not a
// JSON/YAML config writer).

func TestRegisterQoder_FreshInstall(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".qoder")
	res := r.Register("qoder")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "UserPromptSubmit" {
		t.Errorf("HooksAdded = %v, want [UserPromptSubmit]", res.HooksAdded)
	}
	wantPath := filepath.Join(r.opts.HomeDir, ".qoder", "settings.json")
	if res.ConfigPath != wantPath {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "hook qoder UserPromptSubmit") {
		t.Errorf("settings.json command does not name the qoder receiver: %s", body)
	}
}

func TestRegisterQoder_Idempotent(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".qoder")
	if res := r.Register("qoder"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("qoder")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.AlreadySet) != 1 {
		t.Errorf("AlreadySet = %v, want one entry", res.AlreadySet)
	}
}

func TestUnregisterQoder_RoundTrip(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, ".qoder")
	if res := r.Register("qoder"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	res := r.Unregister("qoder")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}
}

func poolsideRegistry(t *testing.T) *Registry {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "poolside"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegisterPoolside_FreshInstall(t *testing.T) {
	t.Parallel()
	r := poolsideRegistry(t)
	res := r.Register("poolside")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "UserPromptSubmit" {
		t.Errorf("HooksAdded = %v, want [UserPromptSubmit]", res.HooksAdded)
	}
	wantPath := filepath.Join(r.opts.HomeDir, ".config", "poolside", "settings.yaml")
	if res.ConfigPath != wantPath {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("settings.yaml not valid YAML: %v\n%s", err, body)
	}
	if !strings.Contains(string(body), "hook poolside UserPromptSubmit") {
		t.Errorf("settings.yaml command does not name the poolside receiver: %s", body)
	}
	if doc["hooks"].(map[string]any)["UserPromptSubmit"].([]any)[0].(map[string]any)["matcher"] != "*" {
		t.Errorf(`settings.yaml missing matcher: "*" (documented as required for every event): %s`, body)
	}
}

func TestRegisterPoolside_Idempotent(t *testing.T) {
	t.Parallel()
	r := poolsideRegistry(t)
	if res := r.Register("poolside"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("poolside")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second register added %v, want none", res.HooksAdded)
	}
	if len(res.AlreadySet) != 1 {
		t.Errorf("AlreadySet = %v, want one entry", res.AlreadySet)
	}
}

func TestRegisterPoolside_PreservesUnrelatedSettings(t *testing.T) {
	t.Parallel()
	r := poolsideRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".config", "poolside", "settings.yaml")
	pre := "pool:\n  api_url: https://inference.poolside.ai\n"
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("poolside")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "inference.poolside.ai") {
		t.Errorf("pool.api_url config lost: %s", body)
	}
}

func TestRegisterPoolside_ConflictWithoutForce(t *testing.T) {
	t.Parallel()
	r := poolsideRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".config", "poolside", "settings.yaml")
	pre := "hooks:\n  UserPromptSubmit:\n    - name: my-policy\n      matcher: \"*\"\n      command: /usr/local/bin/my-policy\n"
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("poolside")
	if res.Error == nil {
		t.Fatalf("expected conflict error, got HooksAdded=%v", res.HooksAdded)
	}
	if !strings.Contains(res.Error.Error(), "non-observer hook") {
		t.Errorf("unexpected error: %v", res.Error)
	}
}

func TestUnregisterPoolside_RoundTrip(t *testing.T) {
	t.Parallel()
	r := poolsideRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".config", "poolside", "settings.yaml")
	pre := "pool:\n  api_url: https://inference.poolside.ai\n"
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("poolside"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	res := r.Unregister("poolside")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "inference.poolside.ai") {
		t.Errorf("unregister lost unrelated config: %s", body)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("settings.yaml not valid YAML after unregister: %v\n%s", err, body)
	}
	if _, has := doc["hooks"]; has {
		t.Errorf("hooks block still present after unregister: %s", body)
	}
}

// TestRegisterPoolside_HardenedLikeJSONWriters pins F8 (phase-3a
// review): registerPoolsideAt's YAML writer must carry the SAME three
// hardening steps every JSON settings writer already has —
// r.lockSettings (an advisory `.observer-lock` file left behind and
// released), pinWriteTarget (exercised on every write, verified
// separately by TestRegisterPoolside_RefusesRetargetedSymlink below),
// and r.recordChecksum (an entry lands in hook_checksums.json, exactly
// like TestRegisterClaudeCodeFreshInstall / every generic-settings
// writer test already checks for their own tool).
func TestRegisterPoolside_HardenedLikeJSONWriters(t *testing.T) {
	t.Parallel()
	r := poolsideRegistry(t)
	res := r.Register("poolside")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}

	// The checksum registry gained an entry for settings.yaml, keyed by
	// its absolute path — same shape recordChecksum writes for every
	// JSON writer.
	csPath := filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	csBody, err := os.ReadFile(csPath)
	if err != nil {
		t.Fatalf("checksum file not created: %v", err)
	}
	var checksums map[string]any
	if err := json.Unmarshal(csBody, &checksums); err != nil {
		t.Fatalf("hook_checksums.json not valid JSON: %v\n%s", err, csBody)
	}
	entry, ok := checksums[res.ConfigPath].(map[string]any)
	if !ok {
		t.Fatalf("no checksum entry for %q in %s", res.ConfigPath, csBody)
	}
	if entry["sha256"] == "" || entry["sha256"] == nil {
		t.Errorf("checksum entry missing sha256: %+v", entry)
	}

	// The advisory lock was taken and released — no stale
	// `.observer-lock` file left behind after a successful, non-dry
	// registration (mirrors how every other writer's lock file is
	// transient).
	lockPath := res.ConfigPath + settingsLockSuffix
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("settings lock file left behind at %s (err=%v)", lockPath, err)
	}

	// Unregister must ALSO be hardened the same way: the checksum entry
	// is removed (mirrors unregisterGenericSettingsHooks's
	// r.removeChecksum call). removeChecksum deletes the whole
	// checksums FILE once its last entry is gone (see
	// hook.removeChecksum) — poolside is the only entry this test ever
	// wrote, so "file no longer exists" is the expected shape here, not
	// "file exists with an empty object".
	if res := r.Unregister("poolside"); res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	csBody, err = os.ReadFile(csPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read checksum file after unregister: %v", err)
	}
	checksums = nil
	if err := json.Unmarshal(csBody, &checksums); err != nil {
		t.Fatalf("hook_checksums.json not valid JSON after unregister: %v\n%s", err, csBody)
	}
	if _, stillPresent := checksums[res.ConfigPath]; stillPresent {
		t.Errorf("checksum entry for %q still present after unregister: %s", res.ConfigPath, csBody)
	}
}

func cascadeRegistry(t *testing.T) *Registry {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codeium", "windsurf"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegisterCascade_FreshInstall(t *testing.T) {
	t.Parallel()
	r := cascadeRegistry(t)
	res := r.Register("devin")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "pre_user_prompt" {
		t.Errorf("HooksAdded = %v, want [pre_user_prompt]", res.HooksAdded)
	}
	wantPath := filepath.Join(r.opts.HomeDir, ".codeium", "windsurf", "hooks.json")
	if res.ConfigPath != wantPath {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var got cascadeHooksConfig
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("hooks.json not valid JSON: %v\n%s", err, body)
	}
	entries, ok := got.Hooks["pre_user_prompt"]
	if !ok || len(entries) != 1 {
		t.Fatalf("pre_user_prompt entry missing/wrong shape: %s", body)
	}
	if !strings.Contains(entries[0].Command, "hook devin pre_user_prompt") {
		t.Errorf("hooks.json command does not name the devin receiver: %s", body)
	}
}

func TestRegisterCascade_Idempotent(t *testing.T) {
	t.Parallel()
	r := cascadeRegistry(t)
	if res := r.Register("devin"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("devin")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second register added %v, want none", res.HooksAdded)
	}
	if len(res.AlreadySet) != 1 {
		t.Errorf("AlreadySet = %v, want one entry", res.AlreadySet)
	}
}

func TestRegisterCascade_ConflictWithoutForce(t *testing.T) {
	t.Parallel()
	r := cascadeRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".codeium", "windsurf", "hooks.json")
	pre := `{"hooks":{"pre_user_prompt":[{"command":"/usr/local/bin/my-policy"}]}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("devin")
	if res.Error == nil {
		t.Fatalf("expected conflict error, got HooksAdded=%v", res.HooksAdded)
	}
	if !strings.Contains(res.Error.Error(), "non-observer hook") {
		t.Errorf("unexpected error: %v", res.Error)
	}
}

func TestUnregisterCascade_RoundTrip(t *testing.T) {
	t.Parallel()
	r := cascadeRegistry(t)
	if res := r.Register("devin"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	res := r.Unregister("devin")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}
	body, _ := os.ReadFile(filepath.Join(r.opts.HomeDir, ".codeium", "windsurf", "hooks.json"))
	var got cascadeHooksConfig
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("hooks.json not valid JSON after unregister: %v\n%s", err, body)
	}
	if _, has := got.Hooks["pre_user_prompt"]; has {
		t.Errorf("pre_user_prompt entry still present after unregister: %s", body)
	}
}

func commandCodeRegistry(t *testing.T) *Registry {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".commandcode"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegisterCommandCode_FreshInstall(t *testing.T) {
	t.Parallel()
	r := commandCodeRegistry(t)
	res := r.Register("command-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "transformInput" {
		t.Errorf("HooksAdded = %v, want [transformInput]", res.HooksAdded)
	}
	wantPath := filepath.Join(r.opts.HomeDir, ".commandcode", "mods", "observer-guard.ts")
	if res.ConfigPath != wantPath {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "hook\", \"command-code\", \"transformInput\"") {
		t.Errorf("observer-guard.ts command does not name the command-code receiver: %s", body)
	}
}

func TestRegisterCommandCode_Idempotent(t *testing.T) {
	t.Parallel()
	r := commandCodeRegistry(t)
	if res := r.Register("command-code"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("command-code")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second register added %v, want none", res.HooksAdded)
	}
	if len(res.AlreadySet) != 1 {
		t.Errorf("AlreadySet = %v, want one entry", res.AlreadySet)
	}
}

func TestRegisterCommandCode_DryRunTouchesNothing(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".commandcode"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: home, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("command-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if _, err := os.Stat(filepath.Join(home, ".commandcode", "mods", "observer-guard.ts")); !os.IsNotExist(err) {
		t.Errorf("dry-run register wrote observer-guard.ts (err=%v)", err)
	}
}

func TestUnregisterCommandCode_RoundTrip(t *testing.T) {
	t.Parallel()
	r := commandCodeRegistry(t)
	if res := r.Register("command-code"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	res := r.Unregister("command-code")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}
	if _, err := os.Stat(filepath.Join(r.opts.HomeDir, ".commandcode", "mods", "observer-guard.ts")); !os.IsNotExist(err) {
		t.Errorf("unregister left observer-guard.ts behind (err=%v)", err)
	}
}

func TestUnregisterCommandCode_AbsentIsNoop(t *testing.T) {
	t.Parallel()
	r := commandCodeRegistry(t)
	res := r.Unregister("command-code")
	if res.Error != nil {
		t.Fatalf("Unregister on a fresh install: %v", res.Error)
	}
	if len(res.HooksRemoved) != 0 {
		t.Errorf("HooksRemoved = %v, want none", res.HooksRemoved)
	}
}

// TestRegisterCommandCode_BakesConfigPath pins FIX cluster item 5a:
// Options.ConfigPath (the operator's --config <path>) must survive
// into the written observer-guard.ts, the same way every other
// writer's configFlagSuffix bakes it into a shell command.
func TestRegisterCommandCode_BakesConfigPath(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".commandcode"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath: "/opt/observer/bin/observer",
		HomeDir:    home,
		ConfigPath: "/home/u/.observer/custom-config.toml",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("command-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `const OBSERVER_CONFIG_DEFAULT = "/home/u/.observer/custom-config.toml"`) {
		t.Errorf("observer-guard.ts missing baked --config path: %s", body)
	}
}

// TestRegisterCommandCode_ConflictWithoutForce pins FIX cluster item
// 5b: registerCommandCode used to unconditionally overwrite whatever
// was already at the mod path. A foreign (non-observer-written) file
// must now be refused without --force, and left byte-for-byte
// untouched.
func TestRegisterCommandCode_ConflictWithoutForce(t *testing.T) {
	t.Parallel()
	r := commandCodeRegistry(t)
	dir := filepath.Join(r.opts.HomeDir, ".commandcode", "mods")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "observer-guard.ts")
	foreign := "export default function (cmd) { /* some other mod, not observer's */ }"
	if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("command-code")
	if res.Error == nil {
		t.Fatalf("expected conflict error, got HooksAdded=%v", res.HooksAdded)
	}
	if !strings.Contains(res.Error.Error(), "--force") {
		t.Errorf("unexpected error: %v", res.Error)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != foreign {
		t.Errorf("foreign file was modified despite the refusal: %s", got)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Errorf("a .bak file was written even though the refusal means nothing was overwritten (err=%v)", err)
	}
}

// TestRegisterCommandCode_ForceOverwritesAndBacksUp pins FIX cluster
// item 5b's --force path: a foreign file is overwritten under
// --force, and a byte-for-byte backup of its PRE-overwrite content is
// left at path+".bak" (mirroring writeYAMLMap's backup discipline for
// a Poolside/Hermes settings.yaml takeover).
func TestRegisterCommandCode_ForceOverwritesAndBacksUp(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dir := filepath.Join(home, ".commandcode", "mods")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "observer-guard.ts")
	foreign := "export default function (cmd) { /* some other mod, not observer's */ }"
	if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: home, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("command-code")
	if res.Error != nil {
		t.Fatalf("Register with --force: %v", res.Error)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "cmd.hooks(") {
		t.Errorf("--force did not overwrite the foreign file with the observer mod: %s", got)
	}
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("expected a .bak file preserving the pre-overwrite content: %v", err)
	}
	if string(backup) != foreign {
		t.Errorf(".bak content = %q, want the original foreign content %q", backup, foreign)
	}
}

// TestRegisterCommandCode_ObserverOwnedFileNeedsNoForce pins that an
// existing observer-written copy (a normal reinstall/upgrade) is
// still refreshed silently without --force — the conflict guard only
// blocks a FOREIGN file, matching every other writer's own
// recognized-as-ours-refreshes-on-drift convention.
func TestRegisterCommandCode_ObserverOwnedFileNeedsNoForce(t *testing.T) {
	t.Parallel()
	r := commandCodeRegistry(t)
	if res := r.Register("command-code"); res.Error != nil {
		t.Fatalf("first register: %v", res.Error)
	}
	// Simulate a version upgrade: an observer-written copy that
	// predates today's template still carries the marker text.
	path := filepath.Join(r.opts.HomeDir, ".commandcode", "mods", "observer-guard.ts")
	if err := os.WriteFile(path, []byte("// SuperBased Observer prompt-submit guard bridge (old version)\nexport default function (cmd) {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("command-code")
	if res.Error != nil {
		t.Fatalf("re-register over an observer-owned file without --force: %v", res.Error)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "cmd.hooks(") {
		t.Errorf("re-register did not refresh the observer-owned file: %s", got)
	}
}

// TestUnregisterCommandCode_RefusesOnChecksumMismatch pins FIX
// cluster item 5c: unregisterCommandCode used to delete purely on
// commandcodemod.Installed's presence check. It must now refuse (like
// unregisterClaudeCode) when the on-disk file no longer matches the
// checksum recorded at install time, and succeed once --force is
// passed.
func TestUnregisterCommandCode_RefusesOnChecksumMismatch(t *testing.T) {
	t.Parallel()
	r := commandCodeRegistry(t)
	if res := r.Register("command-code"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	path := filepath.Join(r.opts.HomeDir, ".commandcode", "mods", "observer-guard.ts")
	if err := os.WriteFile(path, []byte("// modified out of band since install\nexport default function (cmd) {}"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.Unregister("command-code")
	if res.Error == nil {
		t.Fatal("expected a checksum-mismatch refusal, got success")
	}
	if !strings.Contains(res.Error.Error(), "--force") {
		t.Errorf("unexpected error: %v", res.Error)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("refused unregister must leave the file in place: %v", err)
	}

	forced, err := NewRegistry(Options{BinaryPath: r.opts.BinaryPath, HomeDir: r.opts.HomeDir, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	res = forced.Unregister("command-code")
	if res.Error != nil {
		t.Fatalf("--force unregister: %v", res.Error)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("--force unregister left the file behind (err=%v)", err)
	}
}

// TestUnregisterCommandCode_MatchingChecksumSucceeds is the
// checksum-matches counterpart of the mismatch test above: an
// unmodified, observer-written file removes cleanly with no --force.
func TestUnregisterCommandCode_MatchingChecksumSucceeds(t *testing.T) {
	t.Parallel()
	r := commandCodeRegistry(t)
	if res := r.Register("command-code"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	res := r.Unregister("command-code")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if !res.ChecksumMatch {
		t.Error("ChecksumMatch = false for an untouched, just-installed file")
	}
	path := filepath.Join(r.opts.HomeDir, ".commandcode", "mods", "observer-guard.ts")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("unregister left observer-guard.ts behind (err=%v)", err)
	}
}

// TestRegisterGenericSettingsHooks_DryRunTouchesNothing pins that
// Options.DryRun computes the result without writing any file — a gap
// the round-2 review caught (see the fix that added the missing
// `if r.opts.DryRun` guards to both new unregister writers).
func TestRegisterGenericSettingsHooks_DryRunTouchesNothing(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".gemini"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath: "/opt/observer/bin/observer",
		HomeDir:    home,
		DryRun:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("gemini-cli")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if !res.DryRun {
		t.Errorf("DryRun flag not carried on the result")
	}
	if _, err := os.Stat(filepath.Join(home, ".gemini", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("dry-run register wrote settings.json (err=%v)", err)
	}

	// A dry-run Unregister against a real prior registration (done via
	// a SEPARATE, non-dry-run registry) must also touch nothing.
	r2, err := NewRegistry(Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if res := r2.Register("gemini-cli"); res.Error != nil {
		t.Fatalf("seed register: %v", res.Error)
	}
	before, err := os.ReadFile(filepath.Join(home, ".gemini", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	r.opts.DryRun = true
	ures := r.Unregister("gemini-cli")
	if ures.Error != nil {
		t.Fatalf("Unregister: %v", ures.Error)
	}
	after, err := os.ReadFile(filepath.Join(home, ".gemini", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("dry-run unregister mutated settings.json:\nbefore=%s\nafter=%s", before, after)
	}
}
