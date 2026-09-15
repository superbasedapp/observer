package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// B5 (review finding): registerCascade/unregisterCascade,
// registerPoolsideAt/unregisterPoolsideAt, and
// registerClaudeCode/unregisterClaudeCode used to round-trip hooks.json
// / settings.yaml / settings.json through narrowly-typed Go structs
// (cascadeHooksConfig+cascadeHookEntry, the typed decodePoolsideHooks,
// claudeHookGroup+claudeHookCommand). Any content the typed shape
// didn't model — an unrelated top-level key, an unrelated event, or a
// sibling hook entry's undocumented-to-us field such as a per-entry
// "timeout" — was silently dropped the moment observer registered,
// refreshed, or removed its OWN entry in the same file. These tests
// pin the fix: every writer now preserves that content byte-for-byte
// (JSON) or field-for-field (YAML — see readYAMLMap/writeYAMLMap's own
// documented key-order/comment limitation, which B5 does not touch).

// --- Cascade (hooks.json): file-level (unknown top-level key, unknown
// event) AND entry-level (foreign entry's "timeout" field) in one seed,
// exactly as the review's acceptance criterion asks for.

func TestRegisterCascade_PreservesSiblingKeysEventsAndEntryFields(t *testing.T) {
	t.Parallel()
	r := cascadeRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".codeium", "windsurf", "hooks.json")
	r.opts.Force = true // a foreign pre_user_prompt entry already present would otherwise block without --force

	pre := `{
  "some_other_vendor_setting": {"foo": "bar"},
  "hooks": {
    "post_user_prompt": [{"command": "/usr/local/bin/other-event-hook"}],
    "pre_user_prompt": [{"command": "/usr/local/bin/my-policy", "timeout": 30}]
  }
}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.Register("devin")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "pre_user_prompt" {
		t.Fatalf("HooksAdded = %v, want [pre_user_prompt]", res.HooksAdded)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("hooks.json not valid JSON: %v\n%s", err, body)
	}

	// (a) unrelated top-level key byte-identical.
	other, ok := got["some_other_vendor_setting"].(map[string]any)
	if !ok || other["foo"] != "bar" {
		t.Errorf("some_other_vendor_setting lost or changed: %v", got["some_other_vendor_setting"])
	}

	hooks, ok := got["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks block missing/wrong shape: %s", body)
	}

	// (b) unrelated event list byte-identical.
	postEntries, ok := hooks["post_user_prompt"].([]any)
	if !ok || len(postEntries) != 1 {
		t.Fatalf("post_user_prompt lost: %v", hooks["post_user_prompt"])
	}
	if postEntries[0].(map[string]any)["command"] != "/usr/local/bin/other-event-hook" {
		t.Errorf("post_user_prompt entry changed: %v", postEntries[0])
	}

	// (c) the foreign pre_user_prompt entry's "timeout" field (and every
	// other field on it) survived, AND observer's own entry was added.
	preEntries, ok := hooks["pre_user_prompt"].([]any)
	if !ok || len(preEntries) != 2 {
		t.Fatalf("pre_user_prompt = %v, want 2 entries (foreign + observer)", hooks["pre_user_prompt"])
	}
	var sawForeignWithTimeout, sawObserver bool
	for _, e := range preEntries {
		m := e.(map[string]any)
		cmd, _ := m["command"].(string)
		if cmd == "/usr/local/bin/my-policy" {
			if m["timeout"] != float64(30) {
				t.Errorf("foreign entry lost its timeout field: %v", m)
			}
			sawForeignWithTimeout = true
		} else if isObserverAnyHookEntry(cmd, "devin") {
			sawObserver = true
		}
	}
	if !sawForeignWithTimeout {
		t.Errorf("foreign entry with timeout missing entirely: %v", preEntries)
	}
	if !sawObserver {
		t.Errorf("observer's own entry missing: %v", preEntries)
	}
}

func TestUnregisterCascade_PreservesSiblingKeysEventsAndEntryFields(t *testing.T) {
	t.Parallel()
	r := cascadeRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".codeium", "windsurf", "hooks.json")

	if res := r.Register("devin"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}

	// Hand-inject sibling content into the file observer just wrote —
	// content observer's own writer never put there, standing in for
	// whatever Cascade itself (or a human) added independently.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	doc["some_other_vendor_setting"] = map[string]any{"foo": "bar"}
	hooks := doc["hooks"].(map[string]any)
	hooks["post_user_prompt"] = []any{map[string]any{"command": "/usr/local/bin/other-event-hook"}}
	preEntries := hooks["pre_user_prompt"].([]any)
	preEntries = append(preEntries, map[string]any{"command": "/usr/local/bin/my-policy", "timeout": 30})
	hooks["pre_user_prompt"] = preEntries
	doc["hooks"] = hooks
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.Unregister("devin")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Fatalf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(after, &got); err != nil {
		t.Fatalf("hooks.json not valid JSON after unregister: %v\n%s", err, after)
	}
	other, ok := got["some_other_vendor_setting"].(map[string]any)
	if !ok || other["foo"] != "bar" {
		t.Errorf("some_other_vendor_setting lost: %v", got["some_other_vendor_setting"])
	}
	gotHooks, ok := got["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks block missing after unregister: %s", after)
	}
	postEntries, ok := gotHooks["post_user_prompt"].([]any)
	if !ok || len(postEntries) != 1 || postEntries[0].(map[string]any)["command"] != "/usr/local/bin/other-event-hook" {
		t.Errorf("post_user_prompt lost/changed: %v", gotHooks["post_user_prompt"])
	}
	gotPre, ok := gotHooks["pre_user_prompt"].([]any)
	if !ok || len(gotPre) != 1 {
		t.Fatalf("pre_user_prompt = %v, want exactly the surviving foreign entry", gotHooks["pre_user_prompt"])
	}
	survivor := gotPre[0].(map[string]any)
	if survivor["command"] != "/usr/local/bin/my-policy" || survivor["timeout"] != float64(30) {
		t.Errorf("surviving foreign entry changed: %v", survivor)
	}
}

// --- Poolside (settings.yaml): entry-level (foreign entry's "timeout"
// field), plus the already-covered file-level unrelated-key case
// folded in for the same combined-seed acceptance criterion.

func TestRegisterPoolside_PreservesSiblingKeyAndEntryFields(t *testing.T) {
	t.Parallel()
	r := poolsideRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".config", "poolside", "settings.yaml")
	r.opts.Force = true // a foreign UserPromptSubmit entry already present would otherwise block without --force

	pre := "pool:\n" +
		"  api_url: https://inference.poolside.ai\n" +
		"hooks:\n" +
		"  OtherEvent:\n" +
		"    - name: unrelated-event-hook\n" +
		"      matcher: \"*\"\n" +
		"      command: /usr/local/bin/other-event-hook\n" +
		"  UserPromptSubmit:\n" +
		"    - name: my-policy\n" +
		"      matcher: \"*\"\n" +
		"      command: /usr/local/bin/my-policy\n" +
		"      timeout: 30\n"
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.Register("poolside")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("settings.yaml not valid YAML: %v\n%s", err, body)
	}

	pool, ok := doc["pool"].(map[string]any)
	if !ok || pool["api_url"] != "https://inference.poolside.ai" {
		t.Errorf("pool.api_url lost/changed: %v", doc["pool"])
	}

	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks block missing/wrong shape: %s", body)
	}
	other, ok := hooks["OtherEvent"].([]any)
	if !ok || len(other) != 1 {
		t.Fatalf("OtherEvent lost: %v", hooks["OtherEvent"])
	}
	otherEntry := other[0].(map[string]any)
	if otherEntry["command"] != "/usr/local/bin/other-event-hook" || otherEntry["name"] != "unrelated-event-hook" {
		t.Errorf("OtherEvent entry changed: %v", otherEntry)
	}

	ups, ok := hooks["UserPromptSubmit"].([]any)
	if !ok || len(ups) != 2 {
		t.Fatalf("UserPromptSubmit = %v, want 2 entries (foreign + observer)", hooks["UserPromptSubmit"])
	}
	var sawForeignWithTimeout, sawObserver bool
	for _, e := range ups {
		m := e.(map[string]any)
		cmd, _ := m["command"].(string)
		if cmd == "/usr/local/bin/my-policy" {
			if m["timeout"] != 30 {
				t.Errorf("foreign entry lost its timeout field: %v", m)
			}
			sawForeignWithTimeout = true
		} else if isObserverAnyHookEntry(cmd, "poolside") {
			sawObserver = true
		}
	}
	if !sawForeignWithTimeout {
		t.Errorf("foreign entry with timeout missing entirely: %v", ups)
	}
	if !sawObserver {
		t.Errorf("observer's own entry missing: %v", ups)
	}
}

func TestUnregisterPoolside_PreservesSiblingKeyAndEntryFields(t *testing.T) {
	t.Parallel()
	r := poolsideRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".config", "poolside", "settings.yaml")

	if res := r.Register("poolside"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}

	// Hand-inject sibling content observer's own writer never put there.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	doc["pool"] = map[string]any{"api_url": "https://inference.poolside.ai"}
	hooks := doc["hooks"].(map[string]any)
	hooks["OtherEvent"] = []any{map[string]any{
		"name": "unrelated-event-hook", "matcher": "*", "command": "/usr/local/bin/other-event-hook",
	}}
	ups := hooks["UserPromptSubmit"].([]any)
	ups = append(ups, map[string]any{
		"name": "my-policy", "matcher": "*", "command": "/usr/local/bin/my-policy", "timeout": 30,
	})
	hooks["UserPromptSubmit"] = ups
	doc["hooks"] = hooks
	edited, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.Unregister("poolside")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Fatalf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(after, &got); err != nil {
		t.Fatalf("settings.yaml not valid YAML after unregister: %v\n%s", err, after)
	}
	pool, ok := got["pool"].(map[string]any)
	if !ok || pool["api_url"] != "https://inference.poolside.ai" {
		t.Errorf("pool.api_url lost: %v", got["pool"])
	}
	gotHooks, ok := got["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks block missing after unregister: %s", after)
	}
	other, ok := gotHooks["OtherEvent"].([]any)
	if !ok || len(other) != 1 {
		t.Errorf("OtherEvent lost: %v", gotHooks["OtherEvent"])
	}
	gotUPS, ok := gotHooks["UserPromptSubmit"].([]any)
	if !ok || len(gotUPS) != 1 {
		t.Fatalf("UserPromptSubmit = %v, want exactly the surviving foreign entry", gotHooks["UserPromptSubmit"])
	}
	survivor := gotUPS[0].(map[string]any)
	if survivor["command"] != "/usr/local/bin/my-policy" || survivor["timeout"] != 30 {
		t.Errorf("surviving foreign entry changed: %v", survivor)
	}
}

// --- Claude Code (settings.json): entry-level only — file-level
// unknown-top-level-key preservation is already pinned by
// TestRegisterClaudeCodePreservesOtherKeys / TestUnregisterClaudeCodeUserHookPreserved.

// TestRegisterClaudeCode_PreservesSiblingEntryTimeoutField seeds an
// event observer registers into (PreToolUse) with a pre-existing group
// on a NON-"*" matcher (so it doesn't trip the conflict guard) holding
// a foreign entry with a "timeout" field, plus an unrelated top-level
// key and an unrelated event. Registering must add observer's own
// group without disturbing any of that.
func TestRegisterClaudeCode_PreservesSiblingEntryTimeoutField(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")

	pre := `{
  "theme": "dark",
  "hooks": {
    "TeammateIdle": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/local/bin/my-other-hook"}]}
    ],
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/my-prehook", "timeout": 30}]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("settings.json not valid JSON: %v\n%s", err, body)
	}
	if got["theme"] != "dark" {
		t.Errorf("theme lost: %v", got["theme"])
	}
	hooks := got["hooks"].(map[string]any)

	teammateIdle, ok := hooks["TeammateIdle"].([]any)
	if !ok || len(teammateIdle) != 1 {
		t.Fatalf("TeammateIdle (unrelated event) lost: %v", hooks["TeammateIdle"])
	}

	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok || len(preToolUse) != 2 {
		t.Fatalf("PreToolUse = %v, want 2 groups (foreign Bash-matcher + observer's new *-matcher)", hooks["PreToolUse"])
	}
	var sawForeignWithTimeout, sawObserver bool
	for _, g := range preToolUse {
		group := g.(map[string]any)
		groupHooks := group["hooks"].([]any)
		for _, h := range groupHooks {
			entry := h.(map[string]any)
			cmd, _ := entry["command"].(string)
			if cmd == "/usr/local/bin/my-prehook" {
				if group["matcher"] != "Bash" {
					t.Errorf("foreign entry's group matcher changed: %v", group["matcher"])
				}
				if entry["timeout"] != float64(30) {
					t.Errorf("foreign entry lost its timeout field: %v", entry)
				}
				sawForeignWithTimeout = true
			} else if isObserverClaudeEntry(cmd) {
				sawObserver = true
			}
		}
	}
	if !sawForeignWithTimeout {
		t.Errorf("foreign PreToolUse entry with timeout missing entirely: %v", preToolUse)
	}
	if !sawObserver {
		t.Errorf("observer's own PreToolUse entry missing: %v", preToolUse)
	}
}

// TestUnregisterClaudeCode_PreservesSiblingEntryTimeoutFieldSameGroup
// hand-crafts a SINGLE PreToolUse group on the "*" matcher holding
// BOTH observer's own entry and a foreign entry carrying a "timeout"
// field — the exact B5 acceptance-criterion shape (a foreign entry in
// the SAME matcher group as observer's own). Unregistering must strip
// only observer's entry and leave the foreign entry, its timeout
// field, the unrelated top-level key, and the unrelated event intact.
func TestUnregisterClaudeCode_PreservesSiblingEntryTimeoutFieldSameGroup(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")

	mixed := `{
  "theme": "dark",
  "hooks": {
    "TeammateIdle": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/local/bin/my-other-hook"}]}
    ],
    "PreToolUse": [
      {"matcher": "*", "hooks": [
        {"type": "command", "command": "/opt/observer/bin/observer hook claude-code pre-tool"},
        {"type": "command", "command": "/usr/local/bin/my-prehook", "timeout": 30}
      ]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(mixed), 0o600); err != nil {
		t.Fatal(err)
	}
	// Seed checksum so unregister doesn't trip the drift guard (mirrors
	// TestUnregisterClaudeCodeMixedGroup's pattern for a hand-crafted file).
	if err := r.recordChecksum(path); err != nil {
		t.Fatal(err)
	}

	res := r.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("settings.json not valid JSON after unregister: %v\n%s", err, body)
	}
	if got["theme"] != "dark" {
		t.Errorf("theme lost: %v", got["theme"])
	}
	hooks := got["hooks"].(map[string]any)

	teammateIdle, ok := hooks["TeammateIdle"].([]any)
	if !ok || len(teammateIdle) != 1 {
		t.Fatalf("TeammateIdle (unrelated event) lost: %v", hooks["TeammateIdle"])
	}

	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok || len(preToolUse) != 1 {
		t.Fatalf("PreToolUse = %v, want exactly one surviving group", hooks["PreToolUse"])
	}
	group := preToolUse[0].(map[string]any)
	if group["matcher"] != "*" {
		t.Errorf("surviving group's matcher changed: %v", group["matcher"])
	}
	groupHooks := group["hooks"].([]any)
	if len(groupHooks) != 1 {
		t.Fatalf("groupHooks = %v, want exactly the surviving foreign entry", groupHooks)
	}
	survivor := groupHooks[0].(map[string]any)
	if strings.Contains(survivor["command"].(string), "/opt/observer/bin/observer") {
		t.Errorf("observer entry still present after unregister: %v", survivor)
	}
	if survivor["command"] != "/usr/local/bin/my-prehook" {
		t.Errorf("surviving entry's command changed: %v", survivor)
	}
	if survivor["timeout"] != float64(30) {
		t.Errorf("surviving foreign entry lost its timeout field: %v", survivor)
	}
}
