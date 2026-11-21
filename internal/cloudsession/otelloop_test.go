package cloudsession

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestValidOTelLoopbackAddr pins the loopback-only address rule of the
// in-sandbox receiver (lane CA-C7): a loopback IP literal and a port, never a
// name a resolver could point elsewhere.
func TestValidOTelLoopbackAddr(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"127.0.0.1:4318", "127.0.0.1:4318", true},
		{" 127.0.0.1:4318 ", "127.0.0.1:4318", true},
		{"127.0.0.2:9000", "127.0.0.2:9000", true},
		{"[::1]:4318", "[::1]:4318", true},
		{"localhost:4318", "", false},
		{"0.0.0.0:4318", "", false},
		{"10.0.0.1:4318", "", false},
		{"127.0.0.1", "", false},
		{"127.0.0.1:0", "", false},
		{"127.0.0.1:65536", "", false},
		{"127.0.0.1:http", "", false},
		{"", "", false},
	} {
		got, err := ValidOTelLoopbackAddr(tc.in)
		if tc.ok != (err == nil) || got != tc.want {
			t.Errorf("ValidOTelLoopbackAddr(%q) = %q, %v; want %q ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrOTelLoopbackAddr) {
			t.Errorf("ValidOTelLoopbackAddr(%q) error %v is not ErrOTelLoopbackAddr", tc.in, err)
		}
	}
}

// TestOTelLoopbackTable pins the loopback table: Claude Code only, every row
// agent exists and is supported, and the cloud-environment variables carry
// no credential (a loopback receiver needs none).
func TestOTelLoopbackTable(t *testing.T) {
	t.Parallel()
	if got := otelLoopbackAgents(); strings.Join(got, ",") != "claude-code" {
		t.Fatalf("loopback agents = %v; want [claude-code]", got)
	}
	for _, s := range otelLoopbackSpecs {
		a, err := AgentByID(s.Agent)
		if err != nil || !a.Supported() {
			t.Fatalf("%s: not a supported agent (%v)", s.Agent, err)
		}
		if len(s.Events) == 0 || s.Grounding == "" {
			t.Errorf("%s: row lacks events or grounding", s.Agent)
		}
		for _, kv := range s.Env(DefaultOTelLoopbackAddr) {
			if strings.Contains(kv[0], "HEADERS") || strings.Contains(strings.ToLower(kv[0]), "token") {
				t.Errorf("%s: loopback env carries a credential-shaped key %s", s.Agent, kv[0])
			}
		}
	}
	if _, err := OTelLoopbackFor("copilot"); err == nil {
		t.Error("copilot has a loopback row")
	}
}

// settingsHooks returns, per event, every hook command in a settings file.
func settingsHooks(t *testing.T, content string) map[string][]map[string]any {
	t.Helper()
	var doc struct {
		Hooks map[string][]struct {
			Hooks []map[string]any `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatalf("settings: %v", err)
	}
	out := map[string][]map[string]any{}
	for ev, groups := range doc.Hooks {
		for _, g := range groups {
			out[ev] = append(out[ev], g.Hooks...)
		}
	}
	return out
}

func ensureEntries(hooks map[string][]map[string]any, event string) []map[string]any {
	var out []map[string]any
	for _, h := range hooks[event] {
		if cmd, _ := h["command"].(string); strings.Contains(cmd, "otel-receiver") {
			out = append(out, h)
		}
	}
	return out
}

// TestAddOTelLoopback pins what `cloud-session init --otel-loopback` adds:
// one owned ensure entry on SessionStart and UserPromptSubmit, gated on the
// cloud marker, with the bounded timeout; the cloud-environment variables as
// a manual step; and nothing a later init without the option or `remove`
// does not take back out.
func TestAddOTelLoopback(t *testing.T) {
	t.Parallel()
	repo := memRepo{}
	opts := testOpts("claude-code")
	base, err := PlanInit(opts, repo.read)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := AddOTelLoopback(base, opts, "")
	if err != nil {
		t.Fatal(err)
	}
	var settings string
	for _, c := range plan.Changes {
		if c.Path == ClaudeSettingsPath {
			settings = c.After
		}
	}
	hooks := settingsHooks(t, settings)
	wantCmd := `[ "${CLAUDE_CODE_REMOTE:-}" = true ] && [ -x /usr/local/bin/observer ] && exec /usr/local/bin/observer cloud-session otel-receiver ensure --agent claude-code --addr 127.0.0.1:4318; exit 0 ` + OwnerTag
	for _, ev := range []string{"SessionStart", "UserPromptSubmit"} {
		got := ensureEntries(hooks, ev)
		if len(got) != 1 {
			t.Fatalf("%s: %d ensure entries; want 1", ev, len(got))
		}
		if got[0]["command"] != wantCmd {
			t.Errorf("%s command =\n%v\nwant\n%s", ev, got[0]["command"], wantCmd)
		}
		if got[0]["timeout"] != float64(OTelLoopbackHookTimeoutSeconds) {
			t.Errorf("%s timeout = %v", ev, got[0]["timeout"])
		}
	}
	for ev := range hooks {
		if ev != "SessionStart" && ev != "UserPromptSubmit" && len(ensureEntries(hooks, ev)) > 0 {
			t.Errorf("ensure entry on %s", ev)
		}
	}
	// The base plan's own entries are all still there.
	baseHooks := settingsHooks(t, func() string {
		for _, c := range base.Changes {
			if c.Path == ClaudeSettingsPath {
				return c.After
			}
		}
		return ""
	}())
	for ev, hs := range baseHooks {
		if len(hooks[ev]) != len(hs)+len(ensureEntries(hooks, ev)) {
			t.Errorf("%s: base entries changed", ev)
		}
	}
	manual := strings.Join(plan.Manual, "\n")
	for _, must := range []string{
		"CLAUDE_CODE_ENABLE_TELEMETRY=1", "OTEL_LOGS_EXPORTER=otlp",
		"OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf", "OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318",
		"none is a secret", "No network allowlist entry",
	} {
		if !strings.Contains(manual, must) {
			t.Errorf("manual steps lack %q:\n%s", must, manual)
		}
	}
	if strings.Contains(manual, "OTEL_EXPORTER_OTLP_HEADERS") {
		t.Error("the loopback route asks for a header (credential)")
	}
	if len(plan.Manual) != len(base.Manual)+2 {
		t.Errorf("manual steps = %d; want base %d + 2", len(plan.Manual), len(base.Manual))
	}

	// Apply, then: a second init with the option is idempotent, an init
	// without it drops the entries, and remove takes everything out.
	repo.apply(plan)
	again, err := PlanInit(opts, repo.read)
	if err != nil {
		t.Fatal(err)
	}
	again, err = AddOTelLoopback(again, opts, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range again.Changes {
		if c.Changed() {
			t.Errorf("re-init with --otel-loopback changes %s", c.Path)
		}
	}
	without, err := PlanInit(opts, repo.clone().read)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range without.Changes {
		if c.Path == ClaudeSettingsPath {
			h := settingsHooks(t, c.After)
			if n := len(ensureEntries(h, "SessionStart")) + len(ensureEntries(h, "UserPromptSubmit")); n != 0 {
				t.Errorf("init without --otel-loopback kept %d ensure entries", n)
			}
		}
	}
	rm, err := PlanRemove("claude-code", repo.read)
	if err != nil {
		t.Fatal(err)
	}
	repo.apply(rm)
	if _, ok := repo[ClaudeSettingsPath]; ok {
		t.Errorf("remove left %s:\n%s", ClaudeSettingsPath, repo[ClaudeSettingsPath])
	}
}

// TestAddOTelLoopbackRefusals: a non-loopback address and an agent without
// a loopback row are refused, and a custom loopback address is written.
func TestAddOTelLoopbackRefusals(t *testing.T) {
	t.Parallel()
	opts := testOpts("claude-code")
	base, err := PlanInit(opts, memRepo{}.read)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddOTelLoopback(base, opts, "10.1.2.3:4318"); !errors.Is(err, ErrOTelLoopbackAddr) {
		t.Errorf("non-loopback address: err = %v", err)
	}
	p, err := AddOTelLoopback(base, opts, "127.0.0.1:14318")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Manual, "\n"), "OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:14318") {
		t.Error("custom address not in the environment step")
	}
	cop, err := PlanInit(testOpts("copilot"), memRepo{}.read)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddOTelLoopback(cop, testOpts("copilot"), ""); err == nil {
		t.Error("copilot accepted")
	}
}
