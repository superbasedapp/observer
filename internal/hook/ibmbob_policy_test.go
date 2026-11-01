package hook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withBobPolicy replaces the host policy reader for one test.
func withBobPolicy(t *testing.T, p IBMBobPolicy) {
	t.Helper()
	prev := ibmBobPolicyReader
	ibmBobPolicyReader = func() IBMBobPolicy { return p }
	t.Cleanup(func() { ibmBobPolicyReader = prev })
}

func bobPolicyWith(t *testing.T, binary string) IBMBobPolicy {
	t.Helper()
	v, err := IBMBobEnforcedHooks(binary)
	if err != nil {
		t.Fatal(err)
	}
	return IBMBobPolicy{Source: "/etc/bob/policy.json", Found: true, EnforcedHooks: &v}
}

// The policy value and the per-node writer share one builder: the groups a
// per-node registration writes for a binary are byte-for-byte the groups
// IBMBobEnforcedHooks emits for it.
func TestIBMBobEnforcedHooksMatchesThePerNodeWriter(t *testing.T) {
	home := t.TempDir()
	reg, err := NewRegistry(Options{
		BinaryPath: "/usr/local/bin/observer", HomeDir: home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"), GOOS: "linux",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("ibm-bob"); res.Error != nil || res.Skipped {
		t.Fatalf("register: %+v", res)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".bob", "settings", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Hooks map[string][]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	v, err := IBMBobEnforcedHooks("/usr/local/bin/observer")
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string][]json.RawMessage
	if err := json.Unmarshal([]byte(v), &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy) != len(IBMBobHookEvents()) {
		t.Fatalf("policy events = %v, want %v", policy, IBMBobHookEvents())
	}
	for _, ev := range IBMBobHookEvents() {
		if len(policy[ev]) != 1 || len(file.Hooks[ev]) != 1 || !jsonEqual(policy[ev][0], file.Hooks[ev][0]) {
			t.Errorf("%s: policy %s != per-node %s", ev, policy[ev], file.Hooks[ev])
		}
	}
	// The default is a bare PATH-resolved command with no --config.
	bare, _ := IBMBobEnforcedHooks("")
	if !strings.Contains(bare, `"command":"observer hook ibm-bob PreToolUse"`) || strings.Contains(bare, "--config") || !strings.Contains(bare, `"timeout":30`) {
		t.Fatalf("bare value = %s", bare)
	}
	// A Windows install path is cmd.exe-quoted, as the per-node writer does.
	win, _ := IBMBobEnforcedHooks(`C:\Program Files\Observer\observer.exe`)
	if !strings.Contains(win, `\"C:\\Program Files\\Observer\\observer.exe\" hook ibm-bob`) {
		t.Fatalf("windows value = %s", win)
	}
	for _, b := range []string{"", "/usr/local/bin/observer", `C:\Program Files\Observer\observer.exe`} {
		p := bobPolicyWith(t, b)
		if c := p.Coverage(IBMBobHookEvents()); !c.Complete() {
			t.Errorf("%q: own value not complete: %+v", b, c)
		}
	}
}

func TestIBMBobEnforcedCoverage(t *testing.T) {
	events := []string{"PreToolUse", "UserPromptSubmit"}
	group := func(cmd string, extra string) string {
		return `[{"matcher":".*","hooks":[{"type":"command","command":` + mustQuote(cmd) + extra + `}]}]`
	}
	for _, tc := range []struct {
		name, value      string
		covered, problem string // covered events joined, problem substring
	}{
		{"both", `{"PreToolUse":` + group("observer hook ibm-bob PreToolUse", "") + `,"UserPromptSubmit":` + group("/opt/o/observer hook ibm-bob UserPromptSubmit", `,"timeout":30`) + `}`, "PreToolUse,UserPromptSubmit", ""},
		{"partial", `{"PreToolUse":` + group("observer hook ibm-bob PreToolUse", "") + `}`, "PreToolUse", ""},
		{"wrong_event_token", `{"PreToolUse":` + group("observer hook ibm-bob UserPromptSubmit", "") + `}`, "", ""},
		{"foreign", `{"PreToolUse":` + group("/opt/acme/audit hook ibm-bob PreToolUse", "") + `}`, "", ""},
		{"disabled", `{"PreToolUse":` + group("observer hook ibm-bob PreToolUse", `,"disabled":true`) + `}`, "", ""},
		{"wsl_bridge", `{"PreToolUse":` + group("wsl.exe -d Ubuntu -- /home/u/observer hook ibm-bob PreToolUse", "") + `}`, "PreToolUse", ""},
		{"windows_path", `{"PreToolUse":` + group(`"C:\Program Files\observer.exe" hook ibm-bob PreToolUse`, "") + `}`, "PreToolUse", ""},
		{"unknown_event", `{"Notification":[]}`, "", "outside Bob's hook schema"},
		{"extra_group_key", `{"PreToolUse":[{"hooks":[{"type":"command","command":"observer hook ibm-bob PreToolUse"}],"note":"x"}]}`, "", "does not match"},
		{"extra_handler_key", `{"PreToolUse":` + group("observer hook ibm-bob PreToolUse", `,"shell":"sh"`) + `}`, "", "does not match"},
		{"empty_hooks", `{"PreToolUse":[{"hooks":[]}]}`, "", "does not match"},
		{"not_json", `{`, "", "not a JSON object"},
		{"empty", ``, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := IBMBobEnforcedCoverage(tc.value, events)
			if got := strings.Join(c.Covered, ","); got != tc.covered {
				t.Errorf("covered = %q, want %q (%+v)", got, tc.covered, c)
			}
			if tc.problem == "" && c.Problem != "" || tc.problem != "" && !strings.Contains(c.Problem, tc.problem) {
				t.Errorf("problem = %q, want %q", c.Problem, tc.problem)
			}
			if len(c.Covered)+len(c.Missing) != len(events) {
				t.Errorf("covered+missing != events: %+v", c)
			}
		})
	}
}

func mustQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestParseIBMBobPolicyDocument(t *testing.T) {
	p := ParseIBMBobPolicyDocument("x", []byte(`{"EnforcedHooks":"{}","OtelConfiguration":"{\"OTEL_EXPORTER_OTLP_ENDPOINT\":\"http://127.0.0.1:4318\"}","EnableTelemetry":false}`))
	if p.EnforcedHooks == nil || *p.EnforcedHooks != "{}" || !p.OtelExport || p.EnableTelemetry == nil || *p.EnableTelemetry || p.Untrusted != "" {
		t.Fatalf("parsed = %+v", p)
	}
	q := ParseIBMBobPolicyDocument("x", []byte(`{"EnforcedHooks":{"PreToolUse":[]},"OtelConfiguration":"{\"OTEL_SERVICE_NAME\":\"b\"}","EnableTelemetry":"false"}`))
	if !q.EnforcedHooksWrongType || q.EnforcedHooks != nil || q.OtelExport || q.EnableTelemetry != nil {
		t.Fatalf("wrong types = %+v", q)
	}
	if c := q.Coverage(IBMBobHookEvents()); c.Problem == "" || c.Complete() {
		t.Fatalf("wrong-typed EnforcedHooks covered: %+v", c)
	}
	if r := ParseIBMBobPolicyDocument("x", []byte(`[1]`)); r.Untrusted == "" {
		t.Fatalf("array accepted: %+v", r)
	}
	// The test binary never reads the host's policy.
	if got := ReadIBMBobPolicy(); got.Found {
		t.Fatalf("test binary read a host policy: %+v", got)
	}
}

func TestRegisterIBMBobStandsDownUnderPolicy(t *testing.T) {
	settings := func(home string) string { return filepath.Join(home, ".bob", "settings", "settings.json") }

	t.Run("covered", func(t *testing.T) {
		withBobPolicy(t, bobPolicyWith(t, ""))
		home := t.TempDir()
		res := waveRegistry(t, home, "linux", nil, false).Register("ibm-bob")
		if !res.CoveredElsewhere() || res.SkipKind != SkipCovered || res.Error != nil ||
			!strings.Contains(res.SkipReason, "/etc/bob/policy.json") || !strings.Contains(res.SkipAdvice, "administrator policy") {
			t.Fatalf("res = %+v", res)
		}
		if _, err := os.Stat(settings(home)); !os.IsNotExist(err) {
			t.Fatalf("settings.json written under a covering policy: %v", err)
		}
	})

	t.Run("covered_but_binary_missing", func(t *testing.T) {
		withBobPolicy(t, bobPolicyWith(t, "/nonexistent/sbo-test/observer"))
		res := waveRegistry(t, t.TempDir(), "linux", nil, false).Register("ibm-bob")
		if !res.CoveredElsewhere() || !strings.Contains(res.SkipAdvice, "/nonexistent/sbo-test/observer does not resolve") {
			t.Fatalf("res = %+v", res)
		}
	})

	t.Run("covered_with_leftover_entries", func(t *testing.T) {
		home := t.TempDir()
		if res := waveRegistry(t, home, "linux", nil, false).Register("ibm-bob"); res.Error != nil {
			t.Fatal(res.Error)
		}
		before, _ := os.ReadFile(settings(home))
		withBobPolicy(t, bobPolicyWith(t, ""))
		res := waveRegistry(t, home, "linux", nil, false).Register("ibm-bob")
		if !res.CoveredElsewhere() || !strings.Contains(res.SkipAdvice, "PreToolUse") || !strings.Contains(res.SkipAdvice, "fire twice") {
			t.Fatalf("res = %+v", res)
		}
		after, _ := os.ReadFile(settings(home))
		if string(after) != string(before) {
			t.Fatal("a stand-down rewrote settings.json")
		}
	})

	t.Run("force_registers_and_warns", func(t *testing.T) {
		withBobPolicy(t, bobPolicyWith(t, ""))
		home := t.TempDir()
		reg := waveRegistry(t, home, "linux", nil, false)
		reg.opts.Force = true
		res := reg.Register("ibm-bob")
		if res.Skipped || res.Error != nil || len(res.HooksAdded) != len(IBMBobHookEvents()) || !strings.Contains(strings.Join(res.Warnings, " "), "fire twice") {
			t.Fatalf("res = %+v", res)
		}
	})

	t.Run("partial_registers_the_rest", func(t *testing.T) {
		v := `{"PreToolUse":[{"hooks":[{"type":"command","command":"observer hook ibm-bob PreToolUse"}]}]}`
		withBobPolicy(t, IBMBobPolicy{Source: "/etc/bob/policy.json", Found: true, EnforcedHooks: &v})
		home := t.TempDir()
		res := waveRegistry(t, home, "linux", nil, false).Register("ibm-bob")
		if res.Skipped || res.Error != nil || strings.Join(res.HooksAdded, ",") != "UserPromptSubmit" || len(res.Warnings) == 0 {
			t.Fatalf("res = %+v", res)
		}
		raw, _ := os.ReadFile(settings(home))
		if strings.Contains(string(raw), "PreToolUse") {
			t.Fatalf("the policy-covered event was written per node:\n%s", raw)
		}
	})

	t.Run("untrusted_never_stands_down", func(t *testing.T) {
		p := bobPolicyWith(t, "")
		p.Untrusted = "/etc/bob/policy.json is not owned by root"
		withBobPolicy(t, p)
		res := waveRegistry(t, t.TempDir(), "linux", nil, false).Register("ibm-bob")
		if res.Skipped || res.Error != nil || len(res.HooksAdded) == 0 || !strings.Contains(strings.Join(res.Warnings, " "), "not owned by root") {
			t.Fatalf("res = %+v", res)
		}
	})

	t.Run("no_enforced_hooks_is_unchanged", func(t *testing.T) {
		withBobPolicy(t, IBMBobPolicy{Source: "/etc/bob/policy.json", Found: true, OtelExport: true})
		res := waveRegistry(t, t.TempDir(), "linux", nil, false).Register("ibm-bob")
		if res.Skipped || res.Error != nil || len(res.HooksAdded) == 0 || len(res.Warnings) != 0 {
			t.Fatalf("res = %+v", res)
		}
	})

	t.Run("user_hook_events", func(t *testing.T) {
		home := t.TempDir()
		if ev, err := IBMBobUserHookEvents(home); err != nil || len(ev) != 0 {
			t.Fatalf("absent = %v %v", ev, err)
		}
		waveRegistry(t, home, "linux", nil, false).Register("ibm-bob")
		if ev, err := IBMBobUserHookEvents(home); err != nil || strings.Join(ev, ",") != "PreToolUse,UserPromptSubmit" {
			t.Fatalf("events = %v %v", ev, err)
		}
	})
}

func TestIBMBobVendorTelemetry(t *testing.T) {
	path := func(home string) string { return filepath.Join(home, ".bob", "settings", "settings.json") }
	write := func(t *testing.T, home, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path(home)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path(home), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(t *testing.T, home string) map[string]any {
		t.Helper()
		raw, err := os.ReadFile(path(home))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	t.Run("off_then_back", func(t *testing.T) {
		withBobPolicy(t, IBMBobPolicy{})
		home := t.TempDir()
		write(t, home, "{\n  \"theme\": \"dark\",\n  \"telemetry\": {\"excludePayload\": true}\n}\n")
		reg := waveRegistry(t, home, "linux", nil, false)
		if res := reg.IBMBobVendorTelemetry("ibm-bob", true); res.Error != nil || !res.Changed {
			t.Fatalf("disable = %+v", res)
		}
		m := read(t, home)
		tele, _ := m["telemetry"].(map[string]any)
		if m["theme"] != "dark" || tele["enabled"] != false || tele["excludePayload"] != true {
			t.Fatalf("after disable = %v", m)
		}
		if res := reg.IBMBobVendorTelemetry("ibm-bob", true); res.Error != nil || res.Changed {
			t.Fatalf("second disable changed: %+v", res)
		}
		if res := reg.IBMBobVendorTelemetry("ibm-bob", false); res.Error != nil || !res.Changed {
			t.Fatalf("undo = %+v", res)
		}
		m = read(t, home)
		tele, _ = m["telemetry"].(map[string]any)
		if _, ok := tele["enabled"]; ok || tele["excludePayload"] != true {
			t.Fatalf("after undo = %v", m)
		}
	})

	t.Run("fresh_file_and_dry_run", func(t *testing.T) {
		withBobPolicy(t, IBMBobPolicy{})
		home := t.TempDir()
		if res := waveRegistry(t, home, "linux", nil, true).IBMBobVendorTelemetry("ibm-bob", true); res.Error != nil || !res.Changed || !res.DryRun {
			t.Fatalf("dry run = %+v", res)
		}
		if _, err := os.Stat(path(home)); !os.IsNotExist(err) {
			t.Fatal("dry run wrote")
		}
		if res := waveRegistry(t, home, "linux", nil, false).IBMBobVendorTelemetry("ibm-bob", true); res.Error != nil || !res.Changed {
			t.Fatalf("fresh = %+v", res)
		}
		if tele, _ := read(t, home)["telemetry"].(map[string]any); tele["enabled"] != false {
			t.Fatalf("fresh file = %v", read(t, home))
		}
		// Undo leaves a true / absent value alone and drops an emptied object.
		if res := waveRegistry(t, home, "linux", nil, false).IBMBobVendorTelemetry("ibm-bob", false); res.Error != nil || !res.Changed {
			t.Fatalf("undo = %+v", res)
		}
		if _, ok := read(t, home)["telemetry"]; ok {
			t.Fatalf("empty telemetry object kept: %v", read(t, home))
		}
	})

	t.Run("refuses_under_policy_export", func(t *testing.T) {
		withBobPolicy(t, IBMBobPolicy{Source: "/etc/bob/policy.json", Found: true, OtelExport: true})
		home := t.TempDir()
		res := waveRegistry(t, home, "linux", nil, false).IBMBobVendorTelemetry("ibm-bob", true)
		if res.Error == nil || !strings.Contains(res.Error.Error(), "OtelConfiguration") {
			t.Fatalf("res = %+v", res)
		}
		if _, err := os.Stat(path(home)); !os.IsNotExist(err) {
			t.Fatal("refused call wrote")
		}
	})

	t.Run("policy_decides", func(t *testing.T) {
		off := false
		withBobPolicy(t, IBMBobPolicy{Source: "/etc/bob/policy.json", Found: true, OtelExport: true, EnableTelemetry: &off})
		res := waveRegistry(t, t.TempDir(), "linux", nil, false).IBMBobVendorTelemetry("ibm-bob", true)
		if !res.Skipped || res.Error != nil || !strings.Contains(res.Reason, "EnableTelemetry=false") {
			t.Fatalf("res = %+v", res)
		}
	})

	t.Run("env_export_warns", func(t *testing.T) {
		withBobPolicy(t, IBMBobPolicy{})
		home := t.TempDir()
		res := waveRegistry(t, home, "linux", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318"}, false).IBMBobVendorTelemetry("ibm-bob", true)
		if res.Error != nil || !res.Changed || len(res.Warnings) == 0 {
			t.Fatalf("res = %+v", res)
		}
	})

	t.Run("keeps_the_hook_checksum_current", func(t *testing.T) {
		withBobPolicy(t, IBMBobPolicy{})
		home := t.TempDir()
		reg := waveRegistry(t, home, "linux", nil, false)
		if res := reg.Register("ibm-bob"); res.Error != nil {
			t.Fatal(res.Error)
		}
		if res := reg.IBMBobVendorTelemetry("ibm-bob", true); res.Error != nil {
			t.Fatal(res.Error)
		}
		cs, err := os.ReadFile(filepath.Join(home, ".observer", "hook_checksums.json"))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path(home))
		if !strings.Contains(string(cs), sha256Hex(raw)) {
			t.Fatalf("checksum not refreshed:\n%s", cs)
		}
	})

	t.Run("unknown_target", func(t *testing.T) {
		if res := waveRegistry(t, t.TempDir(), "linux", nil, false).IBMBobVendorTelemetry("bob", true); res.Error == nil {
			t.Fatal("unknown target accepted")
		}
	})
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestParseIBMBobPolicyGatewayURL pins S-19: a deployed GatewayUrl is read
// (a locked route key the doctor names).
func TestParseIBMBobPolicyGatewayURL(t *testing.T) {
	p := ParseIBMBobPolicyDocument("/etc/bob/policy.json", []byte(`{"GatewayUrl":" https://bob.example.internal "}`))
	if p.GatewayURL != "https://bob.example.internal" {
		t.Errorf("GatewayURL = %q", p.GatewayURL)
	}
	if q := ParseIBMBobPolicyDocument("/etc/bob/policy.json", []byte(`{"GatewayUrl":42}`)); q.GatewayURL != "" {
		t.Errorf("a non-string GatewayUrl was read as %q", q.GatewayURL)
	}
}
