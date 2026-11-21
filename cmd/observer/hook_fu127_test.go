package main

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestSiblingGateMarkerDatedAfterPersist pins FU-127's window to the record,
// not to the firing's start. The first firing's persist can outlast
// siblingGateWindow (its first database open runs the whole migration chain:
// about 20 s under -race on a CI runner, release CI round 2), and the sibling
// firing that follows must still find a fresh marker and skip its record.
// With the marker dated before the persist, the sibling saw it as stale and
// both firings recorded.
func TestSiblingGateMarkerDatedAfterPersist(t *testing.T) {
	clock := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	prev := siblingGateNow
	siblingGateNow = func() time.Time { return clock }
	t.Cleanup(func() { siblingGateNow = prev })

	pre, ok := resolveHookBinding("devin", "PreToolUse")
	if !ok {
		t.Fatal("devin PreToolUse: no binding")
	}
	cascade, ok := resolveHookBinding("devin", "pre_run_command")
	if !ok {
		t.Fatal("devin pre_run_command: no binding")
	}
	if len(siblingGateEvents("devin", pre)) == 0 || len(siblingGateEvents("devin", cascade)) == 0 {
		t.Fatal("devin's two tool-gate dialects must be siblings of each other")
	}
	spool := filepath.Join(t.TempDir(), "guard-hookfail.jsonl")
	var v guard.ActionVerdict
	v.Input.Target = "rm -rf ~/"
	v.Verdict.RuleID = "R-101"

	records := 0
	slowFirst := recordSiblingGateOnce("devin", pre, spool, func(guard.ActionVerdict) {
		records++
		clock = clock.Add(siblingGateWindow + 10*time.Second) // a persist longer than the window
	})
	sibling := recordSiblingGateOnce("devin", cascade, spool, func(guard.ActionVerdict) { records++ })
	slowFirst(v)
	clock = clock.Add(time.Second) // the sibling process runs right after the record lands
	sibling(v)
	if records != 1 {
		t.Fatalf("records = %d, want 1: the sibling firing must skip a verdict recorded a second ago, however long its persist took", records)
	}
	// The window still bounds the pair: a sibling arriving a full window
	// after the record lands records again.
	slowFirst(v)
	clock = clock.Add(siblingGateWindow + time.Second)
	sibling(v)
	if records != 3 {
		t.Fatalf("records = %d, want 3: a sibling a full window after the record is a new call", records)
	}
}

// guardEventRowsAll returns "tool session rule decision" for every
// guard_events row in the database, in insert order.
func guardEventRowsAll(t *testing.T, dbPath string) []string {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT COALESCE(tool, ''), COALESCE(session_id, ''), COALESCE(rule_id, ''), COALESCE(decision, '') FROM guard_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tool, session, rule, decision string
		if err := rows.Scan(&tool, &session, &rule, &decision); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s %s %s %s", tool, session, rule, decision))
	}
	return out
}

// TestDevinDoubleFiringIsRecordedOnce pins FU-127's Devin half. Devin
// Desktop runs both Devin hook files Observer writes (Mac round 3: one shell
// call fired pre_user_prompt, a Claude-style PreToolUse and pre_run_command),
// so one call reaches `observer hook devin PreToolUse` (claude-json, from
// ~/.config/devin/config.json) AND `observer hook devin pre_run_command`
// (cascade, from ~/.codeium/windsurf/hooks.json). Each firing is judged and
// answered as before (both block), but the verdict is recorded once: the
// second firing of the pair finds the first's record marker and writes no
// second guard_events row. A host that fires one channel (Devin CLI:
// PreToolUse only; Windsurf: pre_run_command only) records every call, a
// repeated identical command included, and a dual-firing host's second call
// is recorded again.
//
// Payload shapes: PreToolUse as the Devin CLI documents it (hook_event_name,
// session_id, prompt_id, cwd, tool_name exec, tool_input); pre_run_command as
// the Cascade docs give it (agent_action_name, trajectory_id, execution_id,
// timestamp, tool_info.command_line / cwd). The two carry different session
// keys (session_id vs trajectory_id), so the pair is matched on the judged
// action, never on the session.
func TestDevinDoubleFiringIsRecordedOnce(t *testing.T) {
	claude := func(dir, sid string) string {
		return fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":%q,"prompt_id":"p1","cwd":%q,"tool_name":"exec","tool_input":{"command":"rm -rf ~/"}}`, sid, dir)
	}
	cascade := func(dir, sid string) string {
		return fmt.Sprintf(`{"agent_action_name":"pre_run_command","trajectory_id":%q,"execution_id":"e1","timestamp":"2026-10-28T10:30:00Z","tool_info":{"command_line":"rm -rf ~/","cwd":%q}}`, sid, dir)
	}
	type firing struct{ event, body string }
	for _, tc := range []struct {
		name     string
		firings  func(dir string) []firing
		wantRows int
	}{
		{"desktop: PreToolUse then pre_run_command", func(dir string) []firing {
			return []firing{{"PreToolUse", claude(dir, "devin-s1")}, {"pre_run_command", cascade(dir, "traj-1")}}
		}, 1},
		{"desktop: pre_run_command then PreToolUse", func(dir string) []firing {
			return []firing{{"pre_run_command", cascade(dir, "traj-1")}, {"PreToolUse", claude(dir, "devin-s1")}}
		}, 1},
		{"desktop: two calls, each fired twice", func(dir string) []firing {
			return []firing{
				{"PreToolUse", claude(dir, "devin-s1")},
				{"pre_run_command", cascade(dir, "traj-1")},
				{"PreToolUse", claude(dir, "devin-s1")},
				{"pre_run_command", cascade(dir, "traj-1")},
			}
		}, 2},
		{"devin cli: PreToolUse only, same command twice", func(dir string) []firing {
			return []firing{{"PreToolUse", claude(dir, "devin-s1")}, {"PreToolUse", claude(dir, "devin-s1")}}
		}, 2},
		{"windsurf: pre_run_command only, same command twice", func(dir string) []firing {
			return []firing{{"pre_run_command", cascade(dir, "traj-1")}, {"pre_run_command", cascade(dir, "traj-1")}}
		}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath, dbPath := enforcedGuardConfig(t)
			dir := filepath.Dir(configPath)
			for i, f := range tc.firings(dir) {
				h := newFailureHarness(t, resolveHookFailurePlan("devin", f.event, configPath))
				driveToolGateReceiver(t, "devin", f.event, f.body, configPath)
				// Every firing is still judged and blocks in its own dialect.
				if fc, _ := hook.BuildFailClosedReply(hook.ToolGateDialectCascade, "x"); f.event == "pre_run_command" {
					if codes := h.exitCodes(); len(codes) == 0 || codes[0] != fc.ExitCode {
						t.Fatalf("firing %d (%s): exits %v, want the cascade block exit %d", i, f.event, codes, fc.ExitCode)
					}
				} else if out := h.stdout.String(); !toolGateBlockWords.MatchString(out) {
					t.Fatalf("firing %d (%s): stdout %q, want the claude-json deny", i, f.event, out)
				}
			}
			if got := guardEventRowsAll(t, dbPath); len(got) != tc.wantRows {
				t.Fatalf("guard_events rows %q, want %d", got, tc.wantRows)
			}
		})
	}
}

// TestHookPayloadSessionIDPrecedence pins the failure and unclassified
// records' session key to the activity record's one rule (FU-127).
func TestHookPayloadSessionIDPrecedence(t *testing.T) {
	for body, want := range map[string]string{
		`{"conversationId":"agy-c1","transcriptPath":"/t/transcript_full.jsonl"}`: "agy-c1",
		`{"sessionId":"zc","session_id":"zs"}`:                                    "zs",
		`{"agent_action_name":"pre_run_command","trajectory_id":"traj-1"}`:        "traj-1",
		`{"session_id":"s1","prompt_id":"p1"}`:                                    "s1",
		`not json`:                                                                "",
	} {
		if got := hookPayloadSessionID([]byte(body)); got != want {
			t.Errorf("hookPayloadSessionID(%s) = %q, want %q", body, got, want)
		}
	}
}
