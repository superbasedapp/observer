package codebuddy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestMain isolates the package from the developer's own installs: no system
// npm roots are probed, and the log cache starts empty.
func TestMain(m *testing.M) {
	systemNodeModules = nil
	os.Exit(m.Run())
}

// The TestParseLive* tests run on REAL, anonymized transcripts written by the
// CLI during the 2026-10-21 hook probe: a loopback mock model scripted a
// Read -> Bash -> Edit sequence, so the record SHAPES (function_call,
// function_call_result, usage envelopes, hook-block message, permission
// denial, interrupted run) are real CLI output while the model text, token
// numbers (10 in / 5 out per generation) and call ids (call_probe_N) are mock
// values. What that does and does not prove is recorded in
// testdata/codebuddy/README.md and docs/codebuddy-adapter.md.

func TestParseLiveToolSession(t *testing.T) {
	const sid = "01a15e5d-65aa-751d-80c7-4e7ad26233b3"
	res, _ := stageFixture(t, "windows-tool-session.jsonl", sid)
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.Warnings)
	}
	got := countActions(res.ToolEvents)
	want := map[string]int{
		// A headless -p run writes no session-meta line: the first record
		// opens the session.
		models.ActionSessionStart:     1,
		models.ActionUserPrompt:       1,
		models.ActionReadFile:         1,
		models.ActionRunCommand:       1,
		models.ActionEditFile:         1,
		models.ActionAssistantMessage: 1,
	}
	if len(got) != len(want) {
		t.Errorf("action kinds = %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s = %d, want %d (all %v)", k, got[k], n, got)
		}
	}

	read := findByRaw(t, res.ToolEvents, "Read")
	if read.SourceEventID != "tool:call_probe_0" || !read.Success || read.OutcomePending {
		t.Errorf("read id=%q success=%v pending=%v", read.SourceEventID, read.Success, read.OutcomePending)
	}
	if !strings.HasSuffix(read.Target, "/project/notes.txt") || !strings.Contains(read.ToolOutput, "line one") {
		t.Errorf("read target=%q output=%q", read.Target, read.ToolOutput)
	}
	if read.Model != "hy3" || read.MessageID == "" || read.DurationMs <= 0 {
		t.Errorf("read model=%q msg=%q dur=%d", read.Model, read.MessageID, read.DurationMs)
	}
	bash := findByRaw(t, res.ToolEvents, "Bash")
	if !bash.Success || bash.Target != "echo probe" || !strings.Contains(bash.ToolOutput, "Stdout: probe") {
		t.Errorf("bash success=%v target=%q output=%q", bash.Success, bash.Target, bash.ToolOutput)
	}
	edit := findByRaw(t, res.ToolEvents, "Edit")
	if !edit.Success || edit.ContentBytes != int64(len("line one edited")) {
		t.Errorf("edit success=%v content bytes=%d", edit.Success, edit.ContentBytes)
	}
	if !strings.Contains(edit.RawToolInput, `"old_string"`) || !strings.Contains(edit.RawToolInput, `"new_string"`) {
		t.Errorf("edit input lost its old/new_string keys (internal/loc reads them): %q", edit.RawToolInput)
	}
	for _, ev := range res.ToolEvents {
		if ev.SessionID != sid || ev.Tool != models.ToolCodeBuddy {
			t.Fatalf("session/tool = %q/%q", ev.SessionID, ev.Tool)
		}
		if !strings.HasSuffix(strings.ToLower(strings.ReplaceAll(ev.ProjectRoot, `\`, "/")), "/project") {
			t.Errorf("%s project root = %q", ev.ActionType, ev.ProjectRoot)
		}
	}

	// One token row per model generation: the call, its result and the next
	// message share a messageId, and EVERY item of a generation carries the
	// same usage, so the field-wise MAX merge must yield four rows, not ten.
	if len(res.TokenEvents) != 4 {
		t.Fatalf("token events = %d, want 4 (one per generation)", len(res.TokenEvents))
	}
	seen := map[string]bool{}
	for i, tok := range res.TokenEvents {
		if seen[tok.SourceEventID] || !strings.HasPrefix(tok.SourceEventID, "tok:") {
			t.Errorf("token %d id %q duplicate or malformed", i, tok.SourceEventID)
		}
		seen[tok.SourceEventID] = true
		if tok.InputTokens != 10 || tok.OutputTokens != 5 || tok.CacheReadTokens != 0 ||
			tok.CacheCreationTokens != 0 || tok.ReasoningTokens != 0 {
			t.Errorf("token %d = in %d out %d cr %d cw %d rs %d, want the mock's 10/5/0/0/0",
				i, tok.InputTokens, tok.OutputTokens, tok.CacheReadTokens, tok.CacheCreationTokens, tok.ReasoningTokens)
		}
		if tok.Model != "hy3" || tok.SessionID != sid || tok.TurnID == "" || tok.MessageID == "" {
			t.Errorf("token %d model=%q session=%q turn=%q msg=%q", i, tok.Model, tok.SessionID, tok.TurnID, tok.MessageID)
		}
		if tok.Source != models.TokenSourceJSONL || tok.IsSidechain {
			t.Errorf("token %d source=%q sidechain=%v", i, tok.Source, tok.IsSidechain)
		}
		if tok.GenMs != 0 {
			t.Errorf("token %d GenMs = %d without a log, want 0 (never derived from timestamps)", i, tok.GenMs)
		}
	}
	if len(res.CacheObservations) != 4 {
		t.Errorf("cache observations = %d, want 4", len(res.CacheObservations))
	}
	// The call's own usage and its result's messageId join: the tool event
	// and the token row of one generation share the MessageID.
	if res.TokenEvents[0].MessageID != read.MessageID {
		t.Errorf("first token msg %q != read msg %q", res.TokenEvents[0].MessageID, read.MessageID)
	}
}

func TestParseLiveToolSessionWSL(t *testing.T) {
	const sid = "01a15e64-be14-7d7f-a266-9c5263c3ed56"
	res, _ := stageFixture(t, "wsl-tool-session.jsonl", sid)
	got := countActions(res.ToolEvents)
	if got[models.ActionReadFile] != 1 || got[models.ActionRunCommand] != 1 || got[models.ActionEditFile] != 1 ||
		got[models.ActionSessionStart] != 1 {
		t.Errorf("actions = %v", got)
	}
	for _, ev := range res.ToolEvents {
		if !strings.HasSuffix(filepath.ToSlash(ev.ProjectRoot), "/home/user/project") {
			t.Errorf("%s project root = %q, want the inline POSIX cwd", ev.ActionType, ev.ProjectRoot)
		}
	}
	if len(res.TokenEvents) != 4 {
		t.Errorf("token events = %d, want 4", len(res.TokenEvents))
	}
}

// TestParseLivePermissionDenied: headless -p without -y refuses Bash and Edit
// with a status:"incomplete" result whose providerData.toolResult.error holds
// the denial; Read still runs.
func TestParseLivePermissionDenied(t *testing.T) {
	res, _ := stageFixture(t, "windows-permission-denied-session.jsonl", "01a15e5d-0eef-7881-9133-a4d62eccfc18")
	read := findByRaw(t, res.ToolEvents, "Read")
	if !read.Success {
		t.Errorf("read success = false")
	}
	for _, name := range []string{"Bash", "Edit"} {
		ev := findByRaw(t, res.ToolEvents, name)
		if ev.Success || !strings.Contains(ev.ErrorMessage, "Permission to use "+name+" has been denied") {
			t.Errorf("%s success=%v err=%q, want a failed call carrying the denial", name, ev.Success, ev.ErrorMessage)
		}
		if ev.OutcomePending {
			t.Errorf("%s still pending although its result is in the file", name)
		}
		if ev.DurationMs <= 0 {
			t.Errorf("%s duration = %d", name, ev.DurationMs)
		}
	}
	if len(res.TokenEvents) != 4 {
		t.Errorf("token events = %d, want 4", len(res.TokenEvents))
	}
}

// TestParseLiveHookBlocked: a UserPromptSubmit hook exiting 2 blocks the turn
// before anything reaches the model. The only record persisted is the
// assistant-role block message (skipRun, hookStatus:"blocked").
func TestParseLiveHookBlocked(t *testing.T) {
	res, _ := stageFixture(t, "windows-hook-blocked-session.jsonl", "01a15e5b-cd73-7b3a-91eb-2d966849253e")
	got := countActions(res.ToolEvents)
	if got[models.ActionSessionStart] != 1 || got[models.ActionPermissionDenied] != 1 || len(got) != 2 {
		t.Fatalf("actions = %v, want one session_start + one permission_denied (and no assistant_message)", got)
	}
	ev := findByRaw(t, res.ToolEvents, models.ToolCodeBuddy+".hook_blocked")
	if ev.Success || ev.Target != "UserPromptSubmit" || ev.ErrorMessage != "PROBE-BLOCK-REASON-EXIT2: policy says no" {
		t.Errorf("hook block success=%v target=%q err=%q", ev.Success, ev.Target, ev.ErrorMessage)
	}
	if strings.Contains(ev.ErrorMessage, "capture.cjs") || strings.Contains(ev.RawToolInput, "capture.cjs") {
		t.Errorf("the hook command leaked into the row: %+v", ev)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("token events = %d, want 0 (no model call)", len(res.TokenEvents))
	}
}

// TestParseLiveInterrupted: a process killed mid-run leaves a Bash call with
// no result. It is flagged pending; the completed Read before it is not.
func TestParseLiveInterrupted(t *testing.T) {
	res, _ := stageFixture(t, "windows-interrupted-session.jsonl", "01a15e67-88b2-7f33-abf2-e9043f8e7550")
	bash := findByRaw(t, res.ToolEvents, "Bash")
	if !bash.OutcomePending {
		t.Errorf("unanswered Bash must be flagged OutcomePending")
	}
	read := findByRaw(t, res.ToolEvents, "Read")
	if read.OutcomePending || !read.Success {
		t.Errorf("answered Read pending=%v success=%v", read.OutcomePending, read.Success)
	}
	// The usage rode the two function_call lines: two generations, two rows.
	if len(res.TokenEvents) != 2 {
		t.Errorf("token events = %d, want 2", len(res.TokenEvents))
	}
}

// TestLiveFixturesAreAnonymized pins the fixture hygiene the README claims.
func TestLiveFixturesAreAnonymized(t *testing.T) {
	for _, name := range []string{
		"windows-tool-session.jsonl", "wsl-tool-session.jsonl", "windows-permission-denied-session.jsonl",
		"windows-hook-blocked-session.jsonl", "windows-interrupted-session.jsonl",
		"windows-auth-error-session.jsonl", "wsl-auth-error-session.jsonl", "synthetic-unobserved-shapes.jsonl",
	} {
		body, err := os.ReadFile(fixturePath(name))
		if err != nil {
			t.Fatal(err)
		}
		low := strings.ToLower(string(body))
		for _, bad := range []string{"marmu", "santosh", "programsx", "scratchpad", "sk-", "bearer", "api_key", "apikey"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
}

// TestParseAllLiveFixturesResumable re-parses every live fixture from each
// line boundary: the union of the two windows must equal the whole-file parse
// in event ids, so a poll tick landing anywhere loses and duplicates nothing.
func TestParseAllLiveFixturesResumable(t *testing.T) {
	for _, name := range []string{
		"windows-tool-session.jsonl", "windows-permission-denied-session.jsonl", "windows-interrupted-session.jsonl",
	} {
		body, err := os.ReadFile(fixturePath(name))
		if err != nil {
			t.Fatal(err)
		}
		p, a := stage(t, strings.TrimSuffix(name, ".jsonl"), string(body))
		whole, err := a.ParseSessionFile(context.Background(), p, 0)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitAfter(string(body), "\n")
		var cut int64
		for _, l := range lines[:4] {
			cut += int64(len(l))
		}
		if err := os.WriteFile(p, body[:cut], 0o600); err != nil {
			t.Fatal(err)
		}
		first, err := a.ParseSessionFile(context.Background(), p, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		second, err := a.ParseSessionFile(context.Background(), p, first.NewOffset)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]int{}
		for _, ev := range first.ToolEvents {
			ids[ev.SourceEventID]++
		}
		for _, ev := range second.ToolEvents {
			ids[ev.SourceEventID]++
		}
		for _, ev := range whole.ToolEvents {
			if ids[ev.SourceEventID] == 0 {
				t.Errorf("%s: event %q lost across the resume point", name, ev.SourceEventID)
			}
		}
	}
}
