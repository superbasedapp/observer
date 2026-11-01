package hook

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookdisable"
)

// TestSurfaceTool: one case per sharedHookFileSurfaces row, plus the
// registered tool's own payload and the inputs no row may claim
// (surface-gap W-2c). Paths follow the vendor's app_data_dir table
// (antigravity.google/docs/hooks?tab=ide).
func TestSurfaceTool(t *testing.T) {
	for _, tc := range []struct {
		name       string
		registered string
		body       string
		want       string
		wantOK     bool
	}{
		{"app linux", "antigravity-cli", `{"conversationId":"c1","transcriptPath":"/home/u/.gemini/antigravity/brain/c1/.system_generated/logs/transcript.jsonl","toolCall":{"name":"run_command"}}`, "antigravity", true},
		{"app windows", "antigravity-cli", `{"conversationId":"c1","transcriptPath":"C:\\Users\\u\\.gemini\\antigravity\\brain\\c1\\.system_generated\\logs\\transcript.jsonl"}`, "antigravity", true},
		{"ide windows mixed case", "antigravity-cli", `{"conversationId":"c2","transcriptPath":"C:\\Users\\U\\.Gemini\\Antigravity-IDE\\brain\\c2\\.system_generated\\logs\\transcript.jsonl"}`, "antigravity", true},
		{"ide macos", "antigravity-cli", `{"conversationId":"c2","transcriptPath":"/Users/u/.gemini/antigravity-ide/brain/c2/.system_generated/logs/transcript.jsonl"}`, "antigravity", true},
		{"app under another gemini home", "antigravity-cli", `{"transcriptPath":"/srv/gem/antigravity/brain/c1/.system_generated/logs/transcript.jsonl"}`, "antigravity", true},
		{"cli own payload", "antigravity-cli", `{"conversationId":"c3","transcriptPath":"/home/u/.gemini/antigravity-cli/brain/c3/.system_generated/logs/transcript_full.jsonl"}`, "antigravity-cli", false},
		{"jetbrains acp agent stays cli", "antigravity-cli", `{"conversationId":"c4","transcriptPath":"/home/u/.gemini/antigravity-acp/brain/c4/.system_generated/logs/transcript.jsonl"}`, "antigravity-cli", false},
		{"no transcript path", "antigravity-cli", `{"conversationId":"c5","toolCall":{"name":"run_command"}}`, "antigravity-cli", false},
		{"data dir outside brain", "antigravity-cli", `{"transcriptPath":"/home/u/.gemini/antigravity/conversations/c6.pb"}`, "antigravity-cli", false},
		{"undecodable", "antigravity-cli", `{"transcriptPath":`, "antigravity-cli", false},
		{"other registered tool", "claude-code", `{"transcriptPath":"/home/u/.gemini/antigravity/brain/c1/x/transcript.jsonl"}`, "claude-code", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SurfaceTool(tc.registered, []byte(tc.body))
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("SurfaceTool = %q,%v want %q,%v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestCopilotRuntimeClaudePayload pins the copilot-cli signature row on the
// live check 12 capture (VS Code 1.143.1's local agent, the Copilot CLI
// runtime 1.0.100-1; anonymized): the Claude-compatible PreToolUse payload
// has no transcript_path and the hook process carries COPILOT_CLI and
// COPILOT_HOOK_DIR. One case per condition of the row, plus the inherited-
// environment case it must not claim (surface-gap IDE-7 / S-20).
func TestCopilotRuntimeClaudePayload(t *testing.T) {
	const lc12 = `{"hook_event_name":"PreToolUse","session_id":"a27ee083-0000-4000-8000-000000000001","timestamp":"2026-10-26T09:27:24.356Z","cwd":"d:\\work","tool_name":"Read","tool_input":{"path":"D:\\work\\notes.txt","view_range":[1,1]}}`
	both := map[string]string{"COPILOT_CLI": "1", "COPILOT_HOOK_DIR": "/h/.copilot/hooks"}
	for _, tc := range []struct {
		name    string
		body    string
		env     map[string]string
		foreign bool
	}{
		{"lc12 pre-tool from the copilot runtime", lc12, both, true},
		{"prompt from the copilot runtime", `{"hook_event_name":"UserPromptSubmit","session_id":"a27ee083-0000-4000-8000-000000000001","cwd":"d:\\work","prompt":"hi"}`, both, true},
		{"only COPILOT_CLI", lc12, map[string]string{"COPILOT_CLI": "1"}, false},
		{"only COPILOT_HOOK_DIR", lc12, map[string]string{"COPILOT_HOOK_DIR": "/h/.copilot/hooks"}, false},
		{"no environment", lc12, nil, false},
		{"claude code started from a copilot shell", `{"session_id":"s1","transcript_path":"/home/dev/.claude/projects/p/s1.jsonl","cwd":"/r","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`, both, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ClassifyClaudeHookPayloadHost([]byte(tc.body), ForeignHostEnv{
				Getenv:            func(k string) string { return tc.env[k] },
				OwnGateRegistered: func(string, string) bool { return true },
			})
			if !tc.foreign {
				if v.Foreign {
					t.Fatalf("classified foreign: %+v", v)
				}
				return
			}
			if !v.Foreign || v.Host != "copilot-cli" || v.Tool != "copilot-cli" || v.Action != ForeignNeutral || string(v.Reply) != "{}\n" {
				t.Fatalf("verdict %+v (reply %q), want a neutral copilot-cli answer", v, v.Reply)
			}
		})
	}
}

// TestCopilotRuntimeReplayNeutralOnlyWhileRegistered pins G2 (surface-gap
// Wave 5 audit finding 2): the copilot-cli row answers neutral only while
// Observer's own copilot-cli gate for the replayed step is registered; with
// it absent, or the probe missing, the replay is rerouted to copilot-cli.
// The probe is asked about the row's tool and the payload's step.
func TestCopilotRuntimeReplayNeutralOnlyWhileRegistered(t *testing.T) {
	const body = `{"hook_event_name":"PreToolUse","session_id":"a27ee083-0000-4000-8000-000000000001","cwd":"/r","tool_name":"Bash","tool_input":{"command":"rm -rf ~/"}}`
	getenv := func(k string) string {
		return map[string]string{"COPILOT_CLI": "1", "COPILOT_HOOK_DIR": "/h/.copilot/hooks"}[k]
	}
	for _, tc := range []struct {
		name  string
		probe func(tool, step string) bool
		want  ForeignAction
	}{
		{"registration present", func(tool, step string) bool { return tool == "copilot-cli" && step == "PreToolUse" }, ForeignNeutral},
		{"registration absent", func(string, string) bool { return false }, ForeignReroute},
		{"no probe", nil, ForeignReroute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ClassifyClaudeHookPayloadHost([]byte(body), ForeignHostEnv{Getenv: getenv, OwnGateRegistered: tc.probe})
			if !v.Foreign || v.Tool != "copilot-cli" || v.Action != tc.want || v.Step != "PreToolUse" || string(v.Reply) != "{}\n" {
				t.Fatalf("verdict %+v (reply %q), want %s for copilot-cli", v, v.Reply, tc.want)
			}
		})
	}
	// A row without an unregistered action never asks the probe.
	asked := false
	v := ClassifyClaudeHookPayloadHost([]byte(`{"session_id":"g","sessionId":"g","hook_event_name":"Stop","hookEventName":"stop"}`), ForeignHostEnv{
		OwnGateRegistered: func(string, string) bool { asked = true; return false },
	})
	if v.Action != ForeignDispatch || asked {
		t.Fatalf("grok verdict %+v (probe asked %v), want dispatch without a probe", v, asked)
	}
}

// TestProbeEntryEvents: one case per rule of the dry-run fallback reader.
func TestProbeEntryEvents(t *testing.T) {
	reg := []string{"PreToolUse", "UserPromptSubmit"}
	for _, tc := range []struct {
		name   string
		res    RegistrationResult
		want   []string
		wantOK bool
	}{
		{"failed registration is unknown", RegistrationResult{Error: os.ErrPermission}, nil, false},
		{"covered by the tool's own packaging", RegistrationResult{Skipped: true, SkipKind: SkipCovered}, reg, true},
		{"not applicable", RegistrationResult{Skipped: true, SkipKind: SkipNotApplicable}, nil, true},
		{"kept, dropped and rewritten entries", RegistrationResult{AlreadySet: []string{"a"}, HooksDropped: []string{"b"}, Rewrites: []Rewrite{{Event: "c"}}, HooksAdded: []string{"d"}}, []string{"a", "b", "c"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := probeEntryEvents(tc.res, reg)
			if ok != tc.wantOK || len(got) != len(tc.want) {
				t.Fatalf("probeEntryEvents = %v,%v want %v,%v", got, ok, tc.want, tc.wantOK)
			}
			for _, e := range tc.want {
				if !got[e] {
					t.Fatalf("probeEntryEvents = %v, lacks %s", got, e)
				}
			}
		})
	}
}

// TestOwnGateRegisteredReadsTheRegistration drives OwnGateRegistered
// against the registry's own copilot-cli target in a pinned home: absent
// before Register, present after it (tool gate for PreToolUse, prompt gate
// for UserPromptSubmit, every gate for a lifecycle step), absent again
// after Unregister. A tool with no registered gate is never registered.
func TestOwnGateRegisteredReadsTheRegistration(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".copilot"), 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{HomeDir: home, BinaryPath: "/usr/local/bin/observer"}
	probe := OwnGateRegistered(opts)
	steps := []string{"PreToolUse", "UserPromptSubmit", "SessionStart"}
	for _, step := range steps {
		if probe("copilot-cli", step) {
			t.Fatalf("%s: registered before any registration", step)
		}
	}
	reg, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("copilot-cli"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	for _, step := range steps {
		if !probe("copilot-cli", step) {
			t.Fatalf("%s: not registered after Register", step)
		}
	}
	// Another Observer binary path (an npm shim, a moved install) still
	// reads Observer's entry as registered.
	if !OwnGateRegistered(Options{HomeDir: home, BinaryPath: "/opt/elsewhere/observer"})("copilot-cli", "PreToolUse") {
		t.Fatal("an entry written by another Observer binary reads as absent")
	}
	if res := reg.Unregister("copilot-cli"); res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if probe("copilot-cli", "PreToolUse") {
		t.Fatal("PreToolUse: still registered after Unregister")
	}
	if probe("no-such-tool", "PreToolUse") {
		t.Fatal("an unknown tool reads as registered")
	}
}

// TestForeignHostToolsAreHookDisableReplayHosts: every host a signature row
// recognises is on hookdisable's Claude Code replay-host list, so the Claude
// Code hook-off switches report it as silenced too (surface-gap S-20: "a
// signature row plus a hookdisable host entry").
func TestForeignHostToolsAreHookDisableReplayHosts(t *testing.T) {
	hosts := append(hookdisable.ClaudeUserReplayHosts(), hookdisable.ClaudeProjectReplayHosts()...)
	tools := ForeignHostTools()
	for _, want := range []string{"cursor", "grok", "cortex-code", "kimchi", "copilot-cli", "deepseek"} {
		if !slices.Contains(tools, want) {
			t.Errorf("ForeignHostTools lacks %q: %v", want, tools)
		}
	}
	for _, tool := range tools {
		if !slices.Contains(hosts, tool) {
			t.Errorf("signature host %q is not a hookdisable Claude Code replay host (%v)", tool, hosts)
		}
	}
}
