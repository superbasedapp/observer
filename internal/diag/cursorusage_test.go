package diag

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

func TestCheckCursorUsage(t *testing.T) {
	database := routingGapDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	if _, err := database.Exec(`INSERT INTO projects (root_path, name, created_at) VALUES ('/p', 'p', ?)`, stamp); err != nil {
		t.Fatal(err)
	}
	if c := checkCursorUsage(ctx, database, cursorusage.HookWiringIncomplete); c.Status != StatusOK {
		t.Fatalf("empty db: %+v", c)
	}
	session := func(id string, started time.Time) {
		t.Helper()
		if _, err := database.Exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, 1, 'cursor', ?)`, id, started.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	action := func(sid, actionType, raw, eventID string) {
		t.Helper()
		if _, err := database.Exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, raw_tool_name, tool, source_file, source_event_id, success)
			VALUES (?, 1, ?, ?, ?, 'cursor', 'f', ?, 0)`, sid, stamp, actionType, raw, eventID); err != nil {
			t.Fatal(err)
		}
	}
	// node-1 shape: prompt + an unfinished turn from the CLI log.
	session("s-unfinished", now)
	action("s-unfinished", "user_prompt", "beforeSubmitPrompt", "g1:beforeSubmitPrompt")
	action("s-unfinished", "turn_aborted", cursorusage.RawToolTurnUnfinished, cursorusage.SourceEventTurnPrefix+"t1:unfinished")
	// prompt, no finish hook, no log evidence.
	session("s-nohook", now)
	action("s-nohook", "user_prompt", "beforeSubmitPrompt", "g2:beforeSubmitPrompt")
	// prompt + an afterAgentResponse row as the cursor hook writes it
	// (assistant_message, <generation>:afterAgentResponse).
	session("s-response", now)
	action("s-response", "user_prompt", "beforeSubmitPrompt", "g5:beforeSubmitPrompt")
	action("s-response", "assistant_message", "cursor.assistant_response", "g5"+cursorusage.SourceEventResponseHookSuffix)
	// has usage: never reported.
	session("s-ok", now)
	action("s-ok", "user_prompt", "beforeSubmitPrompt", "g3:beforeSubmitPrompt")
	if _, err := database.Exec(`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, source, reliability, source_file, source_event_id)
		VALUES ('s-ok', ?, 'cursor', 'm', 1, 1, 'hook', 'accurate', 'cursor:hook', 'g3:stop')`, stamp); err != nil {
		t.Fatal(err)
	}
	// outside the window: never reported.
	session("s-old", now.Add(-30*24*time.Hour))
	action("s-old", "user_prompt", "beforeSubmitPrompt", "g4:beforeSubmitPrompt")

	// Finish hooks NOT registered: re-registering is the advice.
	c := checkCursorUsage(ctx, database, cursorusage.HookWiringIncomplete)
	if c.Status != StatusWarn || !strings.Contains(c.Message, "3 Cursor session(s)") {
		t.Fatalf("check = %+v", c)
	}
	joined := strings.Join(c.Details, "\n")
	for _, want := range []string{"unfinished_turn: 1 session(s), e.g. s-unfinished", "finish_hooks_unregistered: 1 session(s), e.g. s-nohook", "response_without_usage: 1 session(s), e.g. s-response", "observer init --cursor"} {
		if !strings.Contains(joined, want) {
			t.Errorf("details missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "s-ok") || strings.Contains(joined, "s-old") {
		t.Errorf("sessions with usage / outside the window must not be reported:\n%s", joined)
	}

	// Live finding D4 (2026-09-28): finish hooks registered (doctor shows
	// every event wired) - the same session must NOT be told to run
	// `observer init --cursor`; the honest cause is a turn that never
	// finished or hooks that did not fire.
	c = checkCursorUsage(ctx, database, cursorusage.HookWiringComplete)
	joined = strings.Join(c.Details, "\n")
	if !strings.Contains(joined, "finish_hooks_silent: 1 session(s), e.g. s-nohook") {
		t.Errorf("wired details missing finish_hooks_silent:\n%s", joined)
	}
	if !strings.Contains(joined, "most likely never finished") {
		t.Errorf("wired details must name the likely cause:\n%s", joined)
	}
	for _, line := range c.Details {
		if strings.HasPrefix(line, "finish_hooks_silent") && strings.Contains(line, "- run `observer init --cursor`") {
			t.Errorf("wired remedy tells the user to re-run init:\n%s", line)
		}
	}
}

// TestCursorFinishHooksWiring pins the hooks.json -> wiring fold the doctor
// and the node dashboard share: both finish events canonically registered
// = complete; one missing, an orphaned HTTP entry, or no hooks.json at all =
// incomplete.
func TestCursorFinishHooksWiring(t *testing.T) {
	write := func(t *testing.T, events map[string]string) string {
		t.Helper()
		home := t.TempDir()
		if events == nil {
			return home
		}
		hooks := map[string][]map[string]string{}
		for ev, cmd := range events {
			hooks[ev] = []map[string]string{{"command": cmd}}
		}
		raw, err := json.Marshal(map[string]any{"version": 1, "hooks": hooks})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".cursor", "hooks.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return home
	}
	all := map[string]string{}
	for _, ev := range hook.CursorEvents() {
		all[ev] = "/usr/bin/observer hook cursor " + ev
	}
	noStop := map[string]string{}
	for ev, cmd := range all {
		if ev != "stop" {
			noStop[ev] = cmd
		}
	}
	orphaned := map[string]string{}
	for ev, cmd := range all {
		orphaned[ev] = cmd
	}
	orphaned["afterAgentResponse"] = `curl -s -X POST -H "X-Observer-Token: ` + strings.Repeat("ab", 32) + `" http://127.0.0.1:8830/api/cursor/hook/afterAgentResponse -d @-`
	if !hook.IsOrphanedObserverCursorHTTPHook(orphaned["afterAgentResponse"]) {
		t.Fatalf("fixture is not the orphaned HTTP shape: %s", orphaned["afterAgentResponse"])
	}
	for _, tc := range []struct {
		name   string
		events map[string]string
		want   cursorusage.HookWiring
	}{
		{"all_events_wired", all, cursorusage.HookWiringComplete},
		{"stop_missing", noStop, cursorusage.HookWiringIncomplete},
		{"no_hooks_json", nil, cursorusage.HookWiringIncomplete},
		{"orphaned_http_response_hook", orphaned, cursorusage.HookWiringIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CursorFinishHooksWiring(write(t, tc.events)); got != tc.want {
				t.Errorf("CursorFinishHooksWiring = %d, want %d", got, tc.want)
			}
		})
	}
}
