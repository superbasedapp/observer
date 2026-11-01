package vtcode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	execSID  = "session-demo-exec-20261021T121537Z_320744-339386"
	probeSID = "session-demo-probe-20261021T124710Z_055429-24236"
	// patchCallID is the exec fixture's one apply_patch call that carried
	// arguments (denied by the exec-mode policy).
	patchCallID = "call_983295a21f2343748e168e0ff5fdddaf"
)

func execRoots(t *testing.T) (archive, store string) {
	return fx(t, "wsl", "state", "sessions"), fx(t, "wsl", "demo-exec", ".vtcode", "sessions")
}

// TestExecSession pins a real `vtcode exec` run (the --json ThreadEvent
// stream of the hook-probe session, re-enveloped): apply_patch LOC shape,
// archive reasoning, exec-mode phantom headers, thread.completed, and the
// pid seed from the session id.
func TestExecSession(t *testing.T) {
	archive, store := execRoots(t)
	a := NewWithOptions(nil, archive, store)
	path := filepath.Join(store, execSID, "events.jsonl")
	res := parse(t, a, path, 0)

	counts := map[string]int{
		models.ActionSessionStart: 1,
		models.ActionUserPrompt:   1,
		// 18 invocations: 9 real calls + 9 argument-less `call_function_*`
		// headers exec closes as failed/error (phantoms, no row).
		models.ActionRunCommand:  8,
		models.ActionEditFile:    1,
		models.ActionTurnAborted: 1,
		models.ActionSessionEnd:  1,
	}
	for action, want := range counts {
		if got := countAction(res, action); got != want {
			t.Errorf("%s count = %d, want %d", action, got, want)
		}
	}
	for _, e := range res.ToolEvents {
		if strings.Contains(e.SourceEventID, "call_function_") {
			t.Errorf("phantom header emitted: %s", e.SourceEventID)
		}
	}

	edit := eventsByAction(res, models.ActionEditFile)[0]
	if edit.SourceEventID != "tool:"+patchCallID || edit.Target != "scratch.txt" || edit.Success {
		t.Errorf("apply_patch row = id %q target %q success %v", edit.SourceEventID, edit.Target, edit.Success)
	}
	if !strings.HasPrefix(edit.RawToolInput, "*** Begin Patch\n*** Update File: scratch.txt") {
		t.Errorf("apply_patch RawToolInput = %q, want the bare patch envelope", edit.RawToolInput)
	}
	if edit.ContentBytes != int64(len("scratch edited2")) {
		t.Errorf("apply_patch ContentBytes = %d", edit.ContentBytes)
	}
	files := loc.Extract(loc.Input{RawToolInput: edit.RawToolInput, ActionType: edit.ActionType, Target: edit.Target, BeforeLines: -1})
	if len(files) != 1 || files[0].Shape != loc.ShapeCodexPatch || files[0].Path != "scratch.txt" {
		t.Errorf("loc.Extract = %+v, want one codex Begin-Patch file", files)
	}
	if !strings.HasPrefix(edit.PrecedingReasoning, "Now edit scratch.txt") {
		t.Errorf("apply_patch reasoning = %q, want the archive message's reasoning", edit.PrecedingReasoning)
	}
	var withReasoning int
	for _, e := range res.ToolEvents {
		if e.PrecedingReasoning != "" {
			withReasoning++
			if len(e.PrecedingReasoning) > reasoningCap {
				t.Errorf("reasoning not capped: %d", len(e.PrecedingReasoning))
			}
		}
	}
	// 4 archive Assistant messages carry reasoning, each issuing calls:
	// consumed once, by the message's first call.
	if withReasoning != 4 {
		t.Errorf("rows with reasoning = %d, want 4", withReasoning)
	}

	end := eventsByAction(res, models.ActionSessionEnd)[0]
	if end.Target != "error_during_execution" || end.Metadata == nil || end.Metadata.StopReason != "end_turn" {
		t.Errorf("session_end = %+v / %+v", end, end.Metadata)
	}
	if len(res.TokenEvents) != 1 || res.TokenEvents[0].InputTokens != 49467-44933 || res.TokenEvents[0].GenMs != 0 {
		t.Errorf("tokens = %+v, want one turn row, no GenMs without a trajectory", res.TokenEvents)
	}

	wantSeed := !isForeignOSPath(path)
	if got := len(res.SessionProcessSeeds) == 1; got != wantSeed {
		t.Fatalf("process seeds = %+v, want seeded=%v", res.SessionProcessSeeds, wantSeed)
	}
	if wantSeed {
		s := res.SessionProcessSeeds[0]
		if s.PID != 339386 || s.SessionID != execSID || s.Tool != models.ToolVTCode || s.ExecHint != "vtcode" {
			t.Errorf("seed = %+v", s)
		}
	}
	if len(res.SessionSurfaces) != 0 {
		t.Errorf("session-* ids must not be surface-stamped: %+v", res.SessionSurfaces)
	}
}

// TestAutoTaskSession: an `auto-task-<unix>` session dir (written by
// --full-auto) is a session file; its id comes from the dir, its primary
// actor from thread.started, and it is stamped cli/vtcode-auto.
func TestAutoTaskSession(t *testing.T) {
	_, store := execRoots(t)
	dir := t.TempDir()
	tmpStore := filepath.Join(dir, "ws", ".vtcode", "sessions")
	sid := "auto-task-1792584702"
	path := filepath.Join(tmpStore, sid, "events.jsonl")
	copyFile(t, filepath.Join(store, execSID, "events.jsonl"), path)
	writeFile(t, filepath.Join(tmpStore, sid, "manifest.json"), `{"session_id":"`+sid+`","created_at":"2026-10-21T12:11:42+00:00","status":"active"}`)

	a := NewWithOptions(nil, tmpStore)
	if !a.IsSessionFile(path) {
		t.Fatal("auto-task events.jsonl not claimed")
	}
	res := parse(t, a, path, 0)
	if countAction(res, models.ActionRunCommand) != 8 {
		t.Errorf("run_command = %d, want 8", countAction(res, models.ActionRunCommand))
	}
	for _, e := range res.ToolEvents {
		if e.SessionID != sid {
			t.Fatalf("SessionID = %q, want the dir name", e.SessionID)
		}
		if e.IsSidechain {
			t.Fatalf("primary-actor item marked sidechain: %+v", e)
		}
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceCLI || res.SessionSurfaces[0].SurfaceHost != "vtcode-auto" {
		t.Errorf("surfaces = %+v", res.SessionSurfaces)
	}
	if len(res.SessionProcessSeeds) != 0 {
		t.Errorf("auto-task ids carry no pid; seeds = %+v", res.SessionProcessSeeds)
	}
	if !isArchiveName(sid+".json") || !hasSessionIDPrefix("Auto-Task-1") || hasSessionIDPrefix("task-1") {
		t.Error("prefix helpers")
	}
}

// TestArchiveOnlyExec: the exec session's workspace was deleted after the
// probe; its archive alone yields the conversation, keyed so the tool rows
// dedupe against an events-mode parse of the same session.
func TestArchiveOnlyExec(t *testing.T) {
	archive, store := execRoots(t)
	a := NewWithOptions(nil, archive)
	archivePath := filepath.Join(archive, execSID+".json")
	res := parse(t, a, archivePath, 0)

	counts := map[string]int{
		models.ActionSessionStart:     1,
		models.ActionUserPrompt:       1, // exec marks nothing: the first User row is the task
		models.ActionRunCommand:       8,
		models.ActionEditFile:         1,
		models.ActionAssistantMessage: 5,
		models.ActionSessionEnd:       1,
	}
	for action, want := range counts {
		if got := countAction(res, action); got != want {
			t.Errorf("%s count = %d, want %d", action, got, want)
		}
	}
	if len(res.ToolEvents) != 17 || len(res.TokenEvents) != 0 {
		t.Errorf("rows = %d tool / %d token, want 17 / 0", len(res.ToolEvents), len(res.TokenEvents))
	}
	if p := eventsByAction(res, models.ActionUserPrompt)[0]; !strings.HasPrefix(p.Target, "Task: Exec Task") {
		t.Errorf("prompt = %q", p.Target)
	}

	direct := parse(t, NewWithOptions(nil, archive, store), filepath.Join(store, execSID, "events.jsonl"), 0)
	directIDs := map[string]bool{}
	for _, e := range direct.ToolEvents {
		directIDs[e.SourceEventID] = true
	}
	var prev time.Time
	for _, e := range res.ToolEvents {
		if filepath.Base(e.SourceFile) != "events.jsonl" || sessionIDFromEventsPath(e.SourceFile) != execSID {
			t.Errorf("SourceFile = %q, want the would-be event log", e.SourceFile)
		}
		if strings.HasPrefix(e.SourceEventID, "tool:") || strings.HasPrefix(e.SourceEventID, "session_") {
			if !directIDs[e.SourceEventID] {
				t.Errorf("archive-only id %q absent from the events-mode parse", e.SourceEventID)
			}
		}
		if e.Timestamp.Before(prev) {
			t.Errorf("rows out of order at %s", e.SourceEventID)
		}
		prev = e.Timestamp
	}
	edit := eventsByAction(res, models.ActionEditFile)[0]
	if edit.Success || !strings.Contains(edit.ErrorMessage, "denied") && !strings.Contains(edit.ErrorMessage, "Policy") {
		t.Errorf("apply_patch = success %v error %q, want the policy denial", edit.Success, edit.ErrorMessage)
	}
	if !strings.HasPrefix(edit.RawToolInput, "*** Begin Patch") || !strings.HasPrefix(edit.PrecedingReasoning, "Now edit scratch.txt") {
		t.Errorf("apply_patch input/reasoning = %q / %q", edit.RawToolInput, edit.PrecedingReasoning)
	}
	if len(res.SessionProcessSeeds) != 0 {
		t.Errorf("a gone workspace is no live process: %+v", res.SessionProcessSeeds)
	}
}

// TestArchiveOnlyTUI: a Windows TUI archive (prompts marked
// source=user_input with Unix-second timestamps, System rows, string and
// object tool errors).
func TestArchiveOnlyTUI(t *testing.T) {
	archive := fx(t, "win", "state", "sessions")
	a := NewWithOptions(nil, archive)
	res := parse(t, a, filepath.Join(archive, probeSID+".json"), 0)

	prompts := eventsByAction(res, models.ActionUserPrompt)
	if len(prompts) != 3 {
		t.Fatalf("prompts = %d, want 3", len(prompts))
	}
	if !prompts[0].Timestamp.Equal(time.Unix(1792586866, 0)) {
		t.Errorf("first prompt time = %s, want metadata.timestamp", prompts[0].Timestamp)
	}
	if prompts[0].Metadata == nil || prompts[0].Metadata.EffortLevel != "none" {
		t.Errorf("prompt metadata = %+v", prompts[0].Metadata)
	}
	runs := eventsByAction(res, models.ActionRunCommand)
	if len(runs) != 4 {
		t.Errorf("run_command = %d, want 4", len(runs))
	}
	for _, r := range runs {
		if r.Success {
			t.Errorf("run_command %q succeeded; every one was policy- or hook-denied", r.Target)
		}
	}
	if n := countAction(res, models.ActionSearchText); n != 15 {
		t.Errorf("search_text = %d, want 15", n)
	}
	var hookDenied int
	for _, r := range runs {
		if strings.Contains(r.ErrorMessage, "denied by PreToolUse hook") {
			hookDenied++
		}
	}
	if hookDenied != 2 {
		t.Errorf("hook-denied rows = %d, want 2 (string-shaped error)", hookDenied)
	}
	for _, e := range res.ToolEvents {
		if e.ActionType == models.ActionSessionStart || e.ActionType == models.ActionSessionEnd {
			continue
		}
		if e.Model != freeModel {
			t.Fatalf("%s model = %q, want the archive metadata model", e.ActionType, e.Model)
		}
	}
}

// TestTranscript covers the events-mode reader (with caps and full), the
// archive fallback, and an unknown session.
func TestTranscript(t *testing.T) {
	ctx := context.Background()
	archive, store := wslRoots(t)
	a := NewWithOptions(nil, archive, store)
	msgs, err := a.ReadTranscript(ctx, models.Session{ID: wslSID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var users, asst int
	var calls []models.ToolCallRef
	for _, m := range msgs {
		switch m.Role {
		case models.TranscriptUser:
			users++
		case models.TranscriptAssistant:
			asst++
			calls = append(calls, m.ToolCalls...)
		}
	}
	if users != 2 || asst == 0 || msgs[0].Text != "hi" || msgs[0].ID == "" {
		t.Errorf("users=%d assistants=%d first=%+v", users, asst, msgs[0])
	}
	if len(calls) != 8 {
		t.Errorf("tool calls = %d, want the 8 non-phantom calls", len(calls))
	}
	for _, c := range calls {
		if !c.Resolved || c.Name != "exec_command" {
			t.Errorf("call %+v", c)
		}
	}

	full, err := a.ReadTranscriptFull(ctx, models.Session{ID: wslSID}, []string{filepath.Join(store, wslSID, "events.jsonl")})
	if err != nil || len(full) != len(msgs) {
		t.Fatalf("full transcript: %d msgs, err %v", len(full), err)
	}

	// Exec session: the apply_patch call's input is the patch text.
	ea, es := execRoots(t)
	e := NewWithOptions(nil, ea, es)
	msgs, err = e.ReadTranscript(ctx, models.Session{ID: execSID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var patch bool
	for _, m := range msgs {
		for _, c := range m.ToolCalls {
			if strings.Contains(c.ID, "call_function_") {
				t.Errorf("phantom call in transcript: %s", c.ID)
			}
			if c.Name == "apply_patch" && strings.HasPrefix(c.InputExcerpt, "*** Begin Patch") {
				patch = true
			}
		}
	}
	if !patch {
		t.Error("apply_patch call missing from the exec transcript")
	}

	// Archive fallback: the Windows probe's workspace is gone.
	w := NewWithOptions(nil, fx(t, "win", "state", "sessions"))
	msgs, err = w.ReadTranscript(ctx, models.Session{ID: probeSID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	users = 0
	calls = nil
	for _, m := range msgs {
		if m.Role == models.TranscriptUser {
			users++
		}
		calls = append(calls, m.ToolCalls...)
	}
	if users != 3 || len(calls) != 19 {
		t.Errorf("archive transcript users=%d calls=%d, want 3/19", users, len(calls))
	}

	if _, err := w.ReadTranscript(ctx, models.Session{ID: "session-nope"}, nil); err == nil {
		t.Error("unknown session: want an error")
	}
}

func TestPidFromSessionID(t *testing.T) {
	tests := []struct {
		id   string
		want int
	}{
		{wslSID, 179245},
		{winSID, 33628},
		{"session-a_b-20261021T000000Z_12-3456", 3456},
		{"auto-task-1792584702", 0},
		{"session-x-20261021T000000Z_12-", 0},
		{"session-x-20261021T000000Z_12-1", 0},
		{"session-x-20261021T000000Z_ab-123", 0},
		{"session-x", 0},
	}
	for _, tc := range tests {
		if got := pidFromSessionID(tc.id); got != tc.want {
			t.Errorf("pidFromSessionID(%q) = %d, want %d", tc.id, got, tc.want)
		}
	}
	if got := processSeeds(wslSID, filepath.Join(t.TempDir(), "events.jsonl"), "/w", "completed"); got != nil {
		t.Errorf("completed session seeded: %+v", got)
	}
}

func TestResolveTerminalSession(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := filepath.Join(dir, "ws", ".vtcode", "sessions")
	sid := "session-ws-20261021T000000Z_77-4242"
	events := filepath.Join(store, sid, "events.jsonl")
	writeFile(t, events, `{"schema_version":"0.18.0","event":{"type":"thread.started","thread_id":"`+sid+`"}}`+"\n")
	lock := filepath.Join(store, sid, "session.lock")
	writeFile(t, lock, "")
	auto := filepath.Join(store, "auto-task-1792584702", "events.jsonl")
	writeFile(t, auto, `{"schema_version":"0.18.0","event":{"type":"thread.started","thread_id":"auto-task-1792584702"}}`+"\n")
	other := "session-ws-20261021T000001Z_78-4242"
	writeFile(t, filepath.Join(store, other, "events.jsonl"), `{"schema_version":"0.18.0","event":{"type":"thread.started","thread_id":"wrong"}}`+"\n")

	a := NewWithOptions(nil, store)
	f := func(path string, appendW bool) adapter.TerminalSessionFile {
		return adapter.TerminalSessionFile{Path: path, ReadPath: path, Append: appendW, Writable: appendW}
	}
	tests := []struct {
		name  string
		pid   int
		files []adapter.TerminalSessionFile
		want  string
	}{
		{"events held by the pid in the id", 4242, []adapter.TerminalSessionFile{f(events, true)}, sid},
		{"lock held", 4242, []adapter.TerminalSessionFile{f(lock, false)}, sid},
		{"another process", 4243, []adapter.TerminalSessionFile{f(events, true)}, ""},
		{"auto-task appended", 99, []adapter.TerminalSessionFile{f(auto, true)}, "auto-task-1792584702"},
		{"auto-task read-only", 99, []adapter.TerminalSessionFile{f(auto, false)}, ""},
		{"thread id disagrees", 4242, []adapter.TerminalSessionFile{f(filepath.Join(store, other, "events.jsonl"), true)}, ""},
		{"two sessions", 4242, []adapter.TerminalSessionFile{f(events, true), f(auto, true)}, ""},
		{"unrelated file", 4242, []adapter.TerminalSessionFile{f(filepath.Join(store, sid, "manifest.json"), true)}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.ResolveTerminalSession(ctx, adapter.TerminalProcess{PID: tc.pid, Files: tc.files})
			if err != nil {
				t.Fatal(err)
			}
			if got.SessionID != tc.want {
				t.Fatalf("SessionID = %q, want %q", got.SessionID, tc.want)
			}
			if tc.want != "" && filepath.Base(got.Evidence) != "events.jsonl" {
				t.Errorf("Evidence = %q", got.Evidence)
			}
		})
	}
}

// TestToolVersion: every session is stamped with the install-level
// last_seen_version of the install whose archive dir it belongs to.
func TestToolVersion(t *testing.T) {
	dir := t.TempDir()
	winState := filepath.Join(dir, "win", "AppData", "Roaming", "vinhnx", "vtcode", "state", "sessions")
	linState := filepath.Join(dir, "lin", ".local", "state", "vtcode", "sessions")
	if got := versionFileForStateRoot(winState); got != filepath.Join(dir, "win", "AppData", "Roaming", "vinhnx", "vtcode", "cache", updateCheckFileName) {
		t.Errorf("windows version file = %q", got)
	}
	if got := versionFileForStateRoot(linState); got != filepath.Join(dir, "lin", ".cache", "vtcode", updateCheckFileName) {
		t.Errorf("linux version file = %q", got)
	}
	if got := versionFileForStateRoot(filepath.Join(dir, "elsewhere", "sessions")); got != "" {
		t.Errorf("unknown layout = %q", got)
	}
	copyFile(t, fx(t, "last_update_check"), versionFileForStateRoot(linState))

	_, store := wslRoots(t)
	ws := filepath.Join(dir, "ws")
	tmpStore := filepath.Join(ws, ".vtcode", "sessions")
	events := filepath.Join(tmpStore, wslSID, "events.jsonl")
	copyFile(t, filepath.Join(store, wslSID, "events.jsonl"), events)
	writeArchive(t, filepath.Join(linState, wslSID+".json"), ws, freeModel, "medium")

	a := NewWithOptions(nil, winState, linState, tmpStore)
	res := parse(t, a, events, 0)
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "0.180.2" || res.SessionToolVersions[0].SessionID != wslSID {
		t.Fatalf("versions = %+v", res.SessionToolVersions)
	}
	// No archive (an auto-task run): the archive root sharing the longest
	// prefix with the event log is used.
	if got := a.stateRootFor(filepath.Join(dir, "lin", "proj", ".vtcode", "sessions", "auto-task-1", "events.jsonl"), ""); got != linState {
		t.Errorf("stateRootFor = %q, want %q", got, linState)
	}
	for v, want := range map[string]bool{"0.180.2": true, "1.2.3-rc.1": true, "": false, "v1.2": false, "1": false, "1.2 3": false} {
		if validVersion(v) != want {
			t.Errorf("validVersion(%q) != %v", v, want)
		}
	}
}

// TestGenMsNeedsFullCoverage: a trajectory missing one request of a turn
// leaves that turn's GenMs unset (never a partial sum); tokens unchanged.
func TestGenMsNeedsFullCoverage(t *testing.T) {
	_, store := wslRoots(t)
	ws := filepath.Join(t.TempDir(), "ws")
	tmpStore := filepath.Join(ws, ".vtcode", "sessions")
	events := filepath.Join(tmpStore, wslSID, "events.jsonl")
	copyFile(t, filepath.Join(store, wslSID, "events.jsonl"), events)
	traj, err := os.ReadFile(filepath.Join(filepath.Dir(store), "logs", "trajectory.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	dropped := false
	for _, l := range strings.Split(strings.TrimRight(string(traj), "\n"), "\n") {
		if !dropped && strings.Contains(l, `"prompt_cache_metrics"`) && strings.Contains(l, "aece74f3") {
			dropped = true
			continue
		}
		kept = append(kept, l)
	}
	writeFile(t, filepath.Join(ws, ".vtcode", "logs", "trajectory.jsonl"), strings.Join(kept, "\n")+"\n")

	res := parse(t, NewWithOptions(nil, tmpStore), events, 0)
	if len(res.TokenEvents) != 3 {
		t.Fatalf("token rows = %d", len(res.TokenEvents))
	}
	if res.TokenEvents[0].GenMs != 1576 || res.TokenEvents[1].GenMs != 0 || res.TokenEvents[2].GenMs != 6412 {
		t.Errorf("GenMs = %d/%d/%d, want 1576/0/6412", res.TokenEvents[0].GenMs, res.TokenEvents[1].GenMs, res.TokenEvents[2].GenMs)
	}
	if res.TokenEvents[1].InputTokens != 48946-41606 {
		t.Errorf("token counts changed with the trajectory: %+v", res.TokenEvents[1])
	}
	if len(res.CacheObservations) != 10 {
		t.Errorf("cache observations = %d, want 10", len(res.CacheObservations))
	}
}

// TestImagesAndPermissionDecisions: interjected.image_count rides onto the
// next user prompt; a non-allow permission decision is a denial row.
func TestImagesAndPermissionDecisions(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "ws", ".vtcode", "sessions")
	sid := "session-ws-20261021T000000Z_3-3"
	path := filepath.Join(store, sid, "events.jsonl")
	writeFile(t, path, strings.Join([]string{
		`{"schema_version":"0.18.0","event":{"type":"thread.started","thread_id":"` + sid + `"}}`,
		`{"schema_version":"0.18.0","event":{"type":"interjected","text":"look","source":"direct","image_count":2,"redirect_kind":"interjection"}}`,
		`{"schema_version":"0.18.0","event":{"type":"turn.started","context":{"turn_id":"t1","actor_id":"` + sid + `","origin":"user","timestamp":"2026-10-21T00:00:01+00:00","goal":"look"}}}`,
		`{"schema_version":"0.18.0","event":{"type":"permission.requested","tool_name":"exec_command"}}`,
		`{"schema_version":"0.18.0","event":{"type":"permission.resolved","tool_name":"exec_command","decision":"deny","wait_ms":900}}`,
		`{"schema_version":"0.18.0","event":{"type":"interjected","text":"/model","source":"direct","image_count":0}}`,
		`{"schema_version":"0.18.0","event":{"type":"turn.started","context":{"turn_id":"t2","actor_id":"` + sid + `","origin":"user","timestamp":"2026-10-21T00:00:05+00:00","goal":"again"}}}`,
	}, "\n")+"\n")
	res := parse(t, NewWithOptions(nil, store), path, 0)
	prompts := eventsByAction(res, models.ActionUserPrompt)
	if len(prompts) != 2 || len(prompts[0].UserAttachments) != 2 || prompts[0].UserAttachments[0].Kind != "image" || len(prompts[1].UserAttachments) != 0 {
		t.Fatalf("attachments = %+v", prompts)
	}
	denied := eventsByAction(res, models.ActionPermissionDenied)
	if len(denied) != 1 || denied[0].Success || denied[0].Target != "exec_command" || denied[0].DurationMs != 900 {
		t.Fatalf("denied = %+v", denied)
	}
}
