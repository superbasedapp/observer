package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// cursorReplayPreTool is the payload cursor-agent's Agents window gives a
// Claude Code PreToolUse hook (FU-122, Mac round 4 row 2, anonymized): the
// Cursor field set, conversation_id, the Cursor step in hook_event_name and
// cursor_version.
const cursorReplayPreTool = `{"conversation_id":"c0c0c001-0000-4000-8000-0000000f0122","generation_id":"g-1","model":"default",` +
	`"tool_name":"Shell","tool_input":{"command":"echo mac-tool-deny"},"tool_use_id":"tu-1","cwd":"/Users/dev/proj",` +
	`"session_id":"c0c0c001-0000-4000-8000-0000000f0122","hook_event_name":"preToolUse","cursor_version":"3.4.1",` +
	`"workspace_roots":["/Users/dev/proj"],"user_email":null,"transcript_path":null}`

// TestCursorReplayNeutralOnlyWhileRegistered: one case per answer of the
// cursor rows (FU-122). While Observer's own cursor registration holds the
// replayed step the replay is answered neutral; absent (or unknown) it is
// rerouted to the cursor row. The probe is asked about the cursor tool and
// the payload's own step.
func TestCursorReplayNeutralOnlyWhileRegistered(t *testing.T) {
	prompt := `{"conversation_id":"c1","session_id":"c1","hook_event_name":"beforeSubmitPrompt","prompt":"hi","cursor_version":"3.4.1"}`
	noVersion := `{"conversation_id":"c1","session_id":"c1","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"ls"}}`
	for _, tc := range []struct {
		name      string
		body      string
		probe     func(tool, step string) bool
		want      ForeignAction
		wantStep  string
		wantReply string
	}{
		{"pre-tool, registration present", cursorReplayPreTool, func(tool, step string) bool { return tool == "cursor" && step == "preToolUse" }, ForeignNeutral, "preToolUse", "{}\n"},
		{"pre-tool, registration absent", cursorReplayPreTool, func(string, string) bool { return false }, ForeignReroute, "preToolUse", "{}\n"},
		{"pre-tool, no probe", cursorReplayPreTool, nil, ForeignReroute, "preToolUse", "{}\n"},
		{"prompt, registration present", prompt, func(tool, step string) bool { return tool == "cursor" && step == "beforeSubmitPrompt" }, ForeignNeutral, "beforeSubmitPrompt", "{\"continue\":true}\n"},
		{"prompt, registration absent", prompt, func(string, string) bool { return false }, ForeignReroute, "beforeSubmitPrompt", "{\"continue\":true}\n"},
		{"step name without version, registration present", noVersion, func(tool, _ string) bool { return tool == "cursor" }, ForeignNeutral, "preToolUse", "{}\n"},
		{"step name without version, registration absent", noVersion, func(string, string) bool { return false }, ForeignReroute, "preToolUse", "{}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ClassifyClaudeHookPayloadHost([]byte(tc.body), ForeignHostEnv{OwnGateRegistered: tc.probe})
			if !v.Foreign || v.Host != "cursor" || v.Tool != "cursor" || v.Action != tc.want || v.Step != tc.wantStep || string(v.Reply) != tc.wantReply {
				t.Fatalf("verdict %+v (reply %q), want %s for cursor step %s reply %q", v, v.Reply, tc.want, tc.wantStep, tc.wantReply)
			}
		})
	}
}

// TestOwnGateEventsHostStep: a replayed step that is the tool's own
// registered gate maps to that event alone (cursor), while the copilot-cli
// Claude-vocabulary mapping is unchanged.
func TestOwnGateEventsHostStep(t *testing.T) {
	for _, tc := range []struct {
		tool, step string
		want       []string
	}{
		{"cursor", "preToolUse", []string{"preToolUse"}},
		{"cursor", "beforeSubmitPrompt", []string{"beforeSubmitPrompt"}},
		{"copilot-cli", "PreToolUse", []string{"preToolUse"}},
		{"copilot-cli", "UserPromptSubmit", []string{"userPromptSubmitted"}},
	} {
		got := ownGateEvents(tc.tool, tc.step)
		if len(got) != len(tc.want) {
			t.Errorf("ownGateEvents(%s, %s) = %v, want %v", tc.tool, tc.step, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("ownGateEvents(%s, %s) = %v, want %v", tc.tool, tc.step, got, tc.want)
			}
		}
	}
	// A cursor lifecycle step maps to every registered cursor gate.
	if got := ownGateEvents("cursor", "sessionStart"); len(got) < 2 {
		t.Errorf("ownGateEvents(cursor, sessionStart) = %v, want every registered cursor gate", got)
	}
}

// TestOwnGateRegisteredReadsTheCursorRegistration drives the production
// probe against Observer's cursor registration in a pinned home: absent
// before Register, present after it for the replayed preToolUse and
// beforeSubmitPrompt steps (also when another Observer binary wrote the
// entry), absent again after Unregister.
func TestOwnGateRegisteredReadsTheCursorRegistration(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{HomeDir: home, BinaryPath: "/usr/local/bin/observer"}
	probe := OwnGateRegistered(opts)
	steps := []string{"preToolUse", "beforeSubmitPrompt"}
	for _, step := range steps {
		if probe("cursor", step) {
			t.Fatalf("%s: registered before any registration", step)
		}
	}
	reg, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("cursor"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	for _, step := range steps {
		if !probe("cursor", step) {
			t.Fatalf("%s: not registered after Register", step)
		}
	}
	if !OwnGateRegistered(Options{HomeDir: home, BinaryPath: "/opt/elsewhere/observer"})("cursor", "preToolUse") {
		t.Fatal("an entry written by another Observer binary reads as absent")
	}
	v := ClassifyClaudeHookPayloadHost([]byte(cursorReplayPreTool), ForeignHostEnv{OwnGateRegistered: probe})
	if v.Action != ForeignNeutral {
		t.Fatalf("verdict %+v with the cursor registration present, want neutral", v)
	}
	if res := reg.Unregister("cursor"); res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if probe("cursor", "preToolUse") {
		t.Fatal("preToolUse: still registered after Unregister")
	}
	v = ClassifyClaudeHookPayloadHost([]byte(cursorReplayPreTool), ForeignHostEnv{OwnGateRegistered: probe})
	if v.Action != ForeignReroute || v.Tool != "cursor" {
		t.Fatalf("verdict %+v with the cursor registration removed, want a reroute to cursor", v)
	}
}

// TestCursorObserverEventsCountsOnlyObserverCommands: one case per entry
// shape of the cursor registration reader.
func TestCursorObserverEventsCountsOnlyObserverCommands(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"observer, another install path", "/opt/x/observer hook cursor preToolUse --config /home/u/.observer/config.toml", true},
		{"wsl bridge", "wsl.exe -d Ubuntu -- /usr/local/bin/observer hook cursor preToolUse", true},
		{"observer for another tool", "/usr/local/bin/observer hook claude-code pre-tool", false},
		{"a user's own hook", "/opt/mine/audit.sh preToolUse", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, ".cursor")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			body := `{"version":1,"hooks":{"preToolUse":[{"command":` + strconvQuote(tc.command) + `}]}}`
			if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			got := OwnGateRegistered(Options{HomeDir: home, BinaryPath: "/usr/local/bin/observer"})("cursor", "preToolUse")
			if got != tc.want {
				t.Fatalf("OwnGateRegistered = %v, want %v", got, tc.want)
			}
		})
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
