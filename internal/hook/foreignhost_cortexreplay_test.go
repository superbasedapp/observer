package hook

import (
	"os"
	"path/filepath"
	"testing"
)

// cortexReplayPreTool is the Claude-shaped PreToolUse Cortex Code 1.2.18
// gives Observer's Claude Code hooks (transcript_path under the Cortex data
// home's conversations/, session_id the conversation id; anonymized).
const cortexReplayPreTool = `{"session_id":"a39b0000-0000-4000-8000-00000000f141","transcript_path":"/home/u/.snowflake/cortex/conversations/a39b0000-0000-4000-8000-00000000f141.json",` +
	`"cwd":"/home/u/repo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`

// TestCortexReplayNeutralOnlyWhileRegistered: one case per answer of the
// cortex-code row (FU-141). Rerouted to cortex-code unless the probe says
// Observer's own Cortex registration holds the replayed gate.
func TestCortexReplayNeutralOnlyWhileRegistered(t *testing.T) {
	prompt := `{"session_id":"c41","transcript_path":"C:\\Users\\u\\.snowflake\\cortex\\conversations\\c41.json","hook_event_name":"UserPromptSubmit","prompt":"hi"}`
	for _, tc := range []struct {
		name  string
		body  string
		probe func(tool, step string) bool
		want  ForeignAction
	}{
		{"pre-tool, registration present", cortexReplayPreTool, func(tool, step string) bool { return tool == "cortex-code" && step == "PreToolUse" }, ForeignNeutral},
		{"pre-tool, registration absent", cortexReplayPreTool, func(string, string) bool { return false }, ForeignReroute},
		{"pre-tool, no probe", cortexReplayPreTool, nil, ForeignReroute},
		{"prompt, registration present", prompt, func(tool, step string) bool { return tool == "cortex-code" && step == "UserPromptSubmit" }, ForeignNeutral},
		{"prompt, registration absent", prompt, func(string, string) bool { return false }, ForeignReroute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ClassifyClaudeHookPayloadHost([]byte(tc.body), ForeignHostEnv{OwnGateRegistered: tc.probe})
			if !v.Foreign || v.Tool != "cortex-code" || v.Action != tc.want || string(v.Reply) != "{}\n" {
				t.Fatalf("verdict %+v (reply %q), want %s for cortex-code", v, v.Reply, tc.want)
			}
		})
	}
}

// TestOwnGateRegisteredCortexIsOffWhileGated drives the production probe
// against Observer's Cortex registration: while the writer waits on LC18 it
// answers false even with Observer's entries in the file (the replay keeps
// judging); past the gate it answers true after Register and false again
// after Unregister; a Claude Code command a user put in Cortex's file never
// counts.
func TestOwnGateRegisteredCortexIsOffWhileGated(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".snowflake", "cortex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{HomeDir: home, BinaryPath: "/usr/local/bin/observer"}
	probe := OwnGateRegistered(opts)

	runLiveGatedHookWriters = true
	reg, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("cortex-code"); res.Error != nil || res.Skipped {
		runLiveGatedHookWriters = false
		t.Fatalf("Register past the gate = %+v", res)
	}
	for _, step := range []string{"PreToolUse", "UserPromptSubmit"} {
		if !probe("cortex-code", step) {
			t.Errorf("%s: not registered past the gate after Register", step)
		}
	}
	v := ClassifyClaudeHookPayloadHost([]byte(cortexReplayPreTool), ForeignHostEnv{OwnGateRegistered: probe})
	if v.Action != ForeignNeutral {
		t.Errorf("verdict %+v past the gate with the registration present, want neutral", v)
	}
	runLiveGatedHookWriters = false

	// The writer's gate is waiting again (production today): the file
	// holding Observer's entries does not count.
	if probe("cortex-code", "PreToolUse") {
		t.Fatal("a gated writer's registration reads as present")
	}
	v = ClassifyClaudeHookPayloadHost([]byte(cortexReplayPreTool), ForeignHostEnv{OwnGateRegistered: probe})
	if v.Action != ForeignReroute {
		t.Fatalf("verdict %+v while the writer is gated, want a reroute", v)
	}

	runLiveGatedHookWriters = true
	t.Cleanup(func() { runLiveGatedHookWriters = false })
	if res := reg.Unregister("cortex-code"); res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if probe("cortex-code", "PreToolUse") {
		t.Fatal("PreToolUse: still registered after Unregister")
	}
	claude := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/observer hook claude-code PreToolUse"}]}]}}`
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(claude), 0o600); err != nil {
		t.Fatal(err)
	}
	if probe("cortex-code", "PreToolUse") {
		t.Fatal("a Claude Code command in Cortex's hooks.json reads as Observer's Cortex registration")
	}
}
