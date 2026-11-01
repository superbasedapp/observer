package vtcode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	fixtureRoot = "../../../testdata/vtcode"

	wslSID     = "session-demo-wsl-20261021T090440Z_077281-179245"
	wslOldSID  = "session-demo-wsl-20261021T071719Z_868051-135688"
	winSID     = "session-demo-win-20261021T090636Z_370151-33628"
	freeModel  = "minimax/minimax-m3.1-flash:free"
	startModel = "xiaomi/mimo-v2.6-pro"
)

// fx returns an absolute fixture path from slash-separated parts.
func fx(t *testing.T, parts ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(append([]string{fixtureRoot}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// wslRoots / winRoots return the archive dir and workspace store of a
// fixture OS tree.
func wslRoots(t *testing.T) (archive, store string) {
	return fx(t, "wsl", "state", "sessions"), fx(t, "wsl", "demo-wsl", ".vtcode", "sessions")
}

func winRoots(t *testing.T) (archive, store string) {
	return fx(t, "win", "state", "sessions"), fx(t, "win", "demo-win", ".vtcode", "sessions")
}

func parse(t *testing.T, a *Adapter, path string, from int64) adapter.ParseResult {
	t.Helper()
	res, err := a.ParseSessionFile(context.Background(), path, from)
	if err != nil {
		t.Fatalf("ParseSessionFile(%s, %d): %v", path, from, err)
	}
	return res
}

func countAction(res adapter.ParseResult, action string) int {
	n := 0
	for _, e := range res.ToolEvents {
		if e.ActionType == action {
			n++
		}
	}
	return n
}

func eventsByAction(res adapter.ParseResult, action string) []models.ToolEvent {
	var out []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.ActionType == action {
			out = append(out, e)
		}
	}
	return out
}

func TestIsSessionFile(t *testing.T) {
	archive, store := wslRoots(t)
	a := NewWithOptions(nil, archive, store)
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"workspace events log", filepath.Join(store, wslSID, "events.jsonl"), true},
		{"global archive json", filepath.Join(archive, wslSID+".json"), true},
		{"manifest sibling", filepath.Join(store, wslSID, "manifest.json"), false},
		{"turn index", filepath.Join(store, wslSID, "index", "turns.json"), false},
		{"trajectory log", filepath.Join(filepath.Dir(store), "logs", "trajectory.jsonl"), false},
		{"events not in a session dir", filepath.Join(store, "events.jsonl"), false},
		// VT Code copies a blocked turn's events into a forensics dir whose
		// name also starts with the session id — never a session file.
		{"blocker forensics copy", filepath.Join(filepath.Dir(store), "tasks", "blockers", wslSID+"-20261021T090830Z-x-forensics", "events.jsonl"), false},
		{"session-shaped json inside the workspace store", filepath.Join(store, wslSID+".json"), false},
		{"same shape outside every root", filepath.Join(t.TempDir(), "x", ".vtcode", "sessions", wslSID, "events.jsonl"), false},
		{"archive name, non-sessions dir", filepath.Join(filepath.Dir(archive), wslSID+".json"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Fatalf("IsSessionFile(%s) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestParseWSLSession(t *testing.T) {
	archive, store := wslRoots(t)
	a := NewWithOptions(nil, archive, store)
	path := filepath.Join(store, wslSID, "events.jsonl")
	res := parse(t, a, path, 0)

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != fi.Size() {
		t.Errorf("NewOffset = %d, want file size %d", res.NewOffset, fi.Size())
	}
	counts := map[string]int{
		models.ActionSessionStart:     1,
		models.ActionUserPrompt:       2, // the harness "continuation" turn is not a prompt
		models.ActionAssistantMessage: 3,
		models.ActionRunCommand:       8, // 15 invocations − 7 argument-less cancelled phantoms
		models.ActionTurnAborted:      2, // turn.failed once per turn (turn.blocked is not a second row)
		models.ActionSessionEnd:       1, // thread.completed
	}
	for action, want := range counts {
		if got := countAction(res, action); got != want {
			t.Errorf("%s count = %d, want %d", action, got, want)
		}
	}
	if len(res.ToolEvents) != 17 {
		t.Errorf("tool events = %d, want 17", len(res.ToolEvents))
	}

	for _, e := range res.ToolEvents {
		if e.SessionID != wslSID {
			t.Errorf("SessionID = %q, want %q", e.SessionID, wslSID)
		}
		if e.Tool != models.ToolVTCode || e.SourceFile != path {
			t.Errorf("Tool/SourceFile = %q/%q", e.Tool, e.SourceFile)
		}
		// The fixture workspace sits inside this repo, so git resolves it up
		// to the repo root; TestArchiveTrigger pins the non-git case.
		if e.ProjectRoot == "" {
			t.Errorf("ProjectRoot empty")
		}
	}

	start := eventsByAction(res, models.ActionSessionStart)[0]
	if got := start.Timestamp.Format("2006-01-02T15:04:05"); got != "2026-10-21T09:04:40" {
		t.Errorf("session_start timestamp = %s, want the manifest created_at", got)
	}

	prompts := eventsByAction(res, models.ActionUserPrompt)
	if prompts[0].Target != "hi" {
		t.Errorf("first prompt = %q, want hi", prompts[0].Target)
	}
	for _, p := range prompts {
		if p.Metadata == nil || p.Metadata.EffortLevel != "medium" {
			t.Errorf("prompt effort = %+v, want medium from the archive metadata", p.Metadata)
		}
		if p.Model != freeModel {
			t.Errorf("prompt model = %q, want %q", p.Model, freeModel)
		}
	}

	var ok, failed int
	for _, e := range eventsByAction(res, models.ActionRunCommand) {
		if e.RawToolName != "exec_command" || !strings.HasPrefix(e.SourceEventID, "tool:call_") {
			t.Errorf("run_command raw=%q id=%q", e.RawToolName, e.SourceEventID)
		}
		if e.Target == "" || e.Target == "exec_command" {
			t.Errorf("run_command target %q, want the cmd", e.Target)
		}
		if e.Success {
			ok++
		} else {
			failed++
			if !strings.Contains(e.ErrorMessage, "Blocked by policy") {
				t.Errorf("failed call error = %q, want the policy block output", e.ErrorMessage)
			}
		}
	}
	if ok != 6 || failed != 2 {
		t.Errorf("run_command success/failed = %d/%d, want 6/2", ok, failed)
	}
	first := eventsByAction(res, models.ActionRunCommand)[0]
	if first.Target != "ls -la" || first.DurationMs <= 0 {
		t.Errorf("first call target=%q duration=%d, want ls -la with a positive duration", first.Target, first.DurationMs)
	}

	type tok struct{ in, cache, out int64 }
	want := []tok{{4696 - 185, 185, 14}, {48946 - 41606, 41606, 448}, {16589 - 2544, 2544, 422}}
	if len(res.TokenEvents) != len(want) {
		t.Fatalf("token rows = %d, want %d (one per turn; failed+blocked deduped; thread total ignored)", len(res.TokenEvents), len(want))
	}
	for i, w := range want {
		te := res.TokenEvents[i]
		if te.InputTokens != w.in || te.CacheReadTokens != w.cache || te.OutputTokens != w.out {
			t.Errorf("token row %d = in %d cache %d out %d, want %+v", i, te.InputTokens, te.CacheReadTokens, te.OutputTokens, w)
		}
		if te.Model != freeModel || te.Source != models.TokenSourceJSONL || te.Reliability != models.ReliabilityApproximate {
			t.Errorf("token row %d model/source/reliability = %q/%q/%q", i, te.Model, te.Source, te.Reliability)
		}
		if te.TurnID == "" || te.MessageID != te.TurnID || te.SourceEventID != "tok:"+te.TurnID {
			t.Errorf("token row %d ids = msg %q turn %q src %q, want all keyed on the turn id", i, te.MessageID, te.TurnID, te.SourceEventID)
		}
		if te.ReasoningTokens != 0 || te.CacheCreationTokens != 0 {
			t.Errorf("token row %d reasoning/cache-creation = %d/%d, want 0/0", i, te.ReasoningTokens, te.CacheCreationTokens)
		}
	}

	// GenMs: the trajectory's per-request elapsed_ms, summed per turn, and
	// only because the requests sum exactly to each turn's usage.
	wantGen := []int64{1576, 1125 + 2186 + 1296 + 1214 + 2154 + 1546 + 1953 + 1922, 3013 + 3399}
	for i, g := range wantGen {
		te := res.TokenEvents[i]
		if te.GenMs != g || te.GenBasis != models.GenBasisNative || te.GenTimingV != genTimingVersion {
			t.Errorf("token row %d gen = %d/%q/v%d, want %d native", i, te.GenMs, te.GenBasis, te.GenTimingV, g)
		}
	}

	// One implicit-cache observation per trajectory request (1 + 8 + 2).
	if len(res.CacheObservations) != 11 {
		t.Fatalf("cache observations = %d, want 11", len(res.CacheObservations))
	}
	var obsRead int64
	for _, o := range res.CacheObservations {
		if !o.ImplicitCache || o.SessionID != wslSID || o.SourceFile != path || o.Model != freeModel || o.MessageID == "" {
			t.Errorf("cache observation = %+v", o)
		}
		obsRead += o.Usage.CacheReadTokens
	}
	if obsRead != 185+41606+2544 {
		t.Errorf("observed cache reads = %d, want the turns' total %d", obsRead, 185+41606+2544)
	}
	if o := res.CacheObservations[0]; o.Usage.NetInputTokens != 4696-185 || o.Usage.OutputTokens != 14 {
		t.Errorf("first observation usage = %+v", o.Usage)
	}

	end := eventsByAction(res, models.ActionSessionEnd)[0]
	if end.SourceEventID != "session_end:"+wslSID || end.Metadata == nil || end.Metadata.StopReason == "" {
		t.Errorf("session_end = %+v, want thread.completed with its stop reason", end)
	}
}

// TestParseWindowsSession pins the Windows layout and the model ladder: the
// archive's metadata.model is the model at session START (mimo), but the
// operator switched with /model before the first turn; the trajectory's
// per-turn record names the model that actually served it.
func TestParseWindowsSession(t *testing.T) {
	archive, store := winRoots(t)
	a := NewWithOptions(nil, archive, store)
	res := parse(t, a, filepath.Join(store, winSID, "events.jsonl"), 0)

	counts := map[string]int{
		models.ActionSessionStart:     1,
		models.ActionUserPrompt:       1,
		models.ActionAssistantMessage: 2,
		models.ActionRunCommand:       5,
		models.ActionSearchText:       2,
		models.ActionTurnAborted:      1,
		models.ActionSessionEnd:       1,
		// permission.resolved, all "allow" in the fixture (5 pairs).
		models.ActionPermissionRequest: 5,
	}
	for action, want := range counts {
		if got := countAction(res, action); got != want {
			t.Errorf("%s count = %d, want %d", action, got, want)
		}
	}
	for _, e := range eventsByAction(res, models.ActionRunCommand) {
		if e.Success {
			t.Errorf("run_command %q succeeded, want every fixture exec_command policy-blocked", e.Target)
		}
	}
	for _, e := range eventsByAction(res, models.ActionSearchText) {
		if !e.Success || e.RawToolName != "code_search" || e.Target == "" {
			t.Errorf("code_search row = %+v", e)
		}
	}
	if p := eventsByAction(res, models.ActionUserPrompt)[0]; p.Metadata == nil || p.Metadata.EffortLevel != "none" {
		t.Errorf("prompt effort = %+v, want none", p.Metadata)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token rows = %d, want 1", len(res.TokenEvents))
	}
	te := res.TokenEvents[0]
	if te.InputTokens != 268581-232079 || te.CacheReadTokens != 232079 || te.OutputTokens != 21506 {
		t.Errorf("token row = in %d cache %d out %d", te.InputTokens, te.CacheReadTokens, te.OutputTokens)
	}
	if te.Model != freeModel {
		t.Errorf("token model = %q, want the trajectory's served model %q (archive says %q)", te.Model, freeModel, startModel)
	}
	if te.ProjectRoot == "" {
		t.Errorf("ProjectRoot empty")
	}
	perms := eventsByAction(res, models.ActionPermissionRequest)
	if perms[0].Target != "exec_command" || perms[0].DurationMs != 4419 || !perms[0].Success {
		t.Errorf("first permission row = %+v, want exec_command allowed after 4419ms", perms[0])
	}
	end := eventsByAction(res, models.ActionSessionEnd)[0]
	if end.Target != "cancelled" || end.Metadata == nil || end.Metadata.StopReason != "tool_calls" || end.Metadata.TotalCostUSD != 0 {
		t.Errorf("session_end = %+v / %+v, want subtype cancelled, stop_reason tool_calls, no cost on a free model", end, end.Metadata)
	}
}

// TestModelLadder covers the rotated trajectory (the earlier session's
// records live in trajectory-<ts>.jsonl, found by history_projection_metrics
// only, its one request having failed) and the archive fallback when no
// trajectory names the turn.
func TestModelLadder(t *testing.T) {
	archive, store := wslRoots(t)
	a := NewWithOptions(nil, archive, store)
	res := parse(t, a, filepath.Join(store, wslOldSID, "events.jsonl"), 0)
	ab := eventsByAction(res, models.ActionTurnAborted)
	if len(ab) != 1 || ab[0].Model != startModel || ab[0].ErrorMessage != "turn aborted" {
		t.Fatalf("turn_aborted = %+v, want one row with model %q", ab, startModel)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("token rows = %d, want 0 (aborted turn without usage; zero thread total ignored)", len(res.TokenEvents))
	}

	// No trajectory at all: the archive's session-start model is the fallback.
	dir := t.TempDir()
	tmpStore := filepath.Join(dir, "ws", ".vtcode", "sessions")
	copyFile(t, filepath.Join(store, wslSID, "events.jsonl"), filepath.Join(tmpStore, wslSID, "events.jsonl"))
	tmpArchive := filepath.Join(dir, "state", "sessions")
	writeArchive(t, filepath.Join(tmpArchive, wslSID+".json"), filepath.Join(dir, "ws"), "some/fallback-model", "high")
	b := NewWithOptions(nil, tmpArchive, tmpStore)
	res = parse(t, b, filepath.Join(tmpStore, wslSID, "events.jsonl"), 0)
	for _, te := range res.TokenEvents {
		if te.Model != "some/fallback-model" {
			t.Errorf("fallback model = %q", te.Model)
		}
	}

	// Neither: the model stays honestly empty.
	c := NewWithOptions(nil, tmpStore)
	res = parse(t, c, filepath.Join(tmpStore, wslSID, "events.jsonl"), 0)
	for _, te := range res.TokenEvents {
		if te.Model != "" {
			t.Errorf("model with no trajectory and no archive = %q, want empty", te.Model)
		}
	}
	if p := eventsByAction(res, models.ActionUserPrompt); len(p) == 0 || p[0].Metadata != nil {
		t.Errorf("prompt metadata without an archive = %+v, want nil", p)
	}
}

// TestIncrementalParse splits the log at every line boundary and checks the
// two windows together emit exactly the full parse's rows, once each — tool
// calls whose invocation and output straddle the cut, and turn usage whose
// turn.started is behind the cursor, included. It runs on a temp copy
// (outside any git repo, so no per-parse git resolution) that is rewritten
// in place: truncated at the cut, parsed from 0, then restored and parsed
// from the cursor — exactly what the watcher does to an appended file.
func TestIncrementalParse(t *testing.T) {
	archive, store := wslRoots(t)
	src, err := os.ReadFile(filepath.Join(store, wslSID, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(t.TempDir(), "demo-wsl")
	tmpStore := filepath.Join(ws, ".vtcode", "sessions")
	path := filepath.Join(tmpStore, wslSID, "events.jsonl")
	copyFile(t, filepath.Join(store, wslSID, "manifest.json"), filepath.Join(tmpStore, wslSID, "manifest.json"))
	copyFile(t, filepath.Join(filepath.Dir(store), "logs", "trajectory.jsonl"), filepath.Join(ws, ".vtcode", "logs", "trajectory.jsonl"))
	writeFile(t, path, string(src))
	a := NewWithOptions(nil, archive, tmpStore)
	full := parse(t, a, path, 0)
	want := strings.Join(ids(full), ",")

	lines, _, err := readLines(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range lines[1:] {
		writeFile(t, path, string(src[:ln.off]))
		first := parse(t, a, path, 0)
		writeFile(t, path, string(src))
		second := parse(t, a, path, first.NewOffset)
		got := append(ids(first), ids(second)...)
		sort.Strings(got)
		if strings.Join(got, ",") != want {
			t.Fatalf("split at %d: got %d rows %v, want %d", ln.off, len(got), got, len(full.ToolEvents)+len(full.TokenEvents))
		}
	}
	if again := parse(t, a, path, full.NewOffset); len(again.ToolEvents)+len(again.TokenEvents) != 0 {
		t.Errorf("re-parse at EOF emitted %d rows, want 0", len(again.ToolEvents)+len(again.TokenEvents))
	}
}

// ids returns the sorted "kind:id" keys of a result.
func ids(res adapter.ParseResult) []string {
	var out []string
	for _, e := range res.ToolEvents {
		out = append(out, "tool|"+e.SourceEventID)
	}
	for _, e := range res.TokenEvents {
		out = append(out, "tok|"+e.SourceEventID)
	}
	sort.Strings(out)
	return out
}

// TestArchiveTrigger: the global archive JSON parses the archived
// workspace's event log in full, attributing rows to the EVENT LOG with the
// same ids a direct parse produces (so the two dedupe downstream).
func TestArchiveTrigger(t *testing.T) {
	_, store := wslRoots(t)
	dir := t.TempDir()
	ws := filepath.Join(dir, "demo-wsl")
	tmpStore := filepath.Join(ws, ".vtcode", "sessions")
	events := filepath.Join(tmpStore, wslSID, "events.jsonl")
	copyFile(t, filepath.Join(store, wslSID, "events.jsonl"), events)
	copyFile(t, filepath.Join(store, wslSID, "manifest.json"), filepath.Join(tmpStore, wslSID, "manifest.json"))
	copyFile(t, filepath.Join(filepath.Dir(store), "logs", "trajectory.jsonl"), filepath.Join(ws, ".vtcode", "logs", "trajectory.jsonl"))
	archive := filepath.Join(dir, "state", "sessions")
	archivePath := filepath.Join(archive, wslSID+".json")
	writeArchive(t, archivePath, ws, startModel, "medium")

	a := NewWithOptions(nil, archive, tmpStore)
	if !a.IsSessionFile(archivePath) {
		t.Fatal("archive JSON not claimed")
	}
	viaArchive := parse(t, a, archivePath, 0)
	direct := parse(t, a, events, 0)
	if strings.Join(ids(viaArchive), ",") != strings.Join(ids(direct), ",") {
		t.Fatalf("archive-triggered ids differ from the direct parse")
	}
	for _, e := range viaArchive.ToolEvents {
		if e.SourceFile != events {
			t.Fatalf("archive row SourceFile = %q, want the event log %q", e.SourceFile, events)
		}
		// Outside any git repo the workspace dir itself is the root.
		if filepath.Base(e.ProjectRoot) != "demo-wsl" {
			t.Fatalf("ProjectRoot = %q, want the workspace dir", e.ProjectRoot)
		}
	}
	fi, _ := os.Stat(archivePath)
	if viaArchive.NewOffset != fi.Size() {
		t.Errorf("archive NewOffset = %d, want its size %d", viaArchive.NewOffset, fi.Size())
	}
	if again := parse(t, a, archivePath, viaArchive.NewOffset); len(again.ToolEvents) != 0 {
		t.Errorf("unchanged archive re-emitted %d rows", len(again.ToolEvents))
	}

	// An archive whose workspace store is gone falls back to the archive's
	// own messages (TestArchiveOnly); a metadata-only archive yields none.
	gone := filepath.Join(archive, "session-gone-20261021T000000Z_1-1.json")
	writeArchive(t, gone, filepath.Join(dir, "nowhere"), "", "")
	res := parse(t, a, gone, 0)
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Errorf("metadata-only archive, missing workspace: rows=%d/%d", len(res.ToolEvents), len(res.TokenEvents))
	}
}

// TestPartialTrailingLineAndCRLF: a record still being written is not
// consumed, and CRLF terminators advance the cursor exactly.
func TestPartialTrailingLineAndCRLF(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "ws", ".vtcode", "sessions")
	sid := "session-ws-20261021T000000Z_1-1"
	path := filepath.Join(store, sid, "events.jsonl")
	lines := []string{
		`{"schema_version":"0.18.0","event":{"type":"thread.started","thread_id":"` + sid + `"}}`,
		``,
		`{"schema_version":"0.18.0","event":{"type":"turn.started","context":{"turn_id":"t1","actor_id":"` + sid + `","origin":"user","timestamp":"2026-10-21T00:00:01+00:00","goal":"hello"}}}`,
		`{"schema_version":"0.18.0","event":{"type":"turn.completed","completed_at":"2026-10-21T00:00:02+00:00","usage":{"input_tokens":10,"cached_input_tokens":4,"cache_creation_tokens":0,"output_tokens":2}}}`,
	}
	body := strings.Join(lines, "\r\n") + "\r\n"
	partial := `{"schema_version":"0.18.0","event":{"type":"turn.sta`
	writeFile(t, path, body+partial)

	a := NewWithOptions(nil, store)
	res := parse(t, a, path, 0)
	if res.NewOffset != int64(len(body)) {
		t.Fatalf("NewOffset = %d, want %d (end of the last complete CRLF line)", res.NewOffset, len(body))
	}
	if len(res.TokenEvents) != 1 || res.TokenEvents[0].InputTokens != 6 {
		t.Fatalf("tokens = %+v, want one row with net input 6", res.TokenEvents)
	}
	if countAction(res, models.ActionUserPrompt) != 1 {
		t.Errorf("prompt not parsed under CRLF")
	}

	// A malformed complete line warns and is skipped.
	writeFile(t, path, body+"{not json}\n")
	res = parse(t, a, path, int64(len(body)))
	if len(res.Warnings) != 1 || res.NewOffset != int64(len(body))+11 {
		t.Errorf("malformed line: warnings=%v offset=%d", res.Warnings, res.NewOffset)
	}

	// A cursor past EOF (file replaced) re-reads from the top.
	res = parse(t, a, path, 1<<20)
	if countAction(res, models.ActionSessionStart) != 1 {
		t.Errorf("cursor past EOF did not restart from 0")
	}
}

// TestSubagentActorIsSidechain: items whose actor_id is not the session id
// are attributed to a delegated subagent.
func TestSubagentActorIsSidechain(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "ws", ".vtcode", "sessions")
	sid := "session-ws-20261021T000000Z_2-2"
	path := filepath.Join(store, sid, "events.jsonl")
	ctx := func(actor string) string {
		return `"context":{"turn_id":"t1","actor_id":"` + actor + `","timestamp":"2026-10-21T00:00:01+00:00"}`
	}
	writeFile(t, path, strings.Join([]string{
		`{"event":{"type":"item.completed","item":{` + ctx(sid) + `,"id":"m1","type":"agent_message","text":"parent"}}}`,
		`{"event":{"type":"item.completed","item":{` + ctx("child-1") + `,"id":"m2","type":"agent_message","text":"child"}}}`,
	}, "\n")+"\n")
	res := parse(t, NewWithOptions(nil, store), path, 0)
	msgs := eventsByAction(res, models.ActionAssistantMessage)
	if len(msgs) != 2 || msgs[0].IsSidechain || !msgs[1].IsSidechain {
		t.Fatalf("sidechain flags = %+v", msgs)
	}
}

func TestCursorSemantics(t *testing.T) {
	archive, store := wslRoots(t)
	a := NewWithOptions(nil, archive, store)
	if k := a.CursorSemanticsFor(filepath.Join(archive, wslSID+".json")).Kind; k != adapter.CursorNoActions {
		t.Errorf("archive cursor kind = %v, want no_actions", k)
	}
	s := a.CursorSemanticsFor(filepath.Join(store, wslSID, "events.jsonl"))
	if s.Kind != adapter.CursorByteOffset || s.StreamsFromCursor {
		t.Errorf("events cursor = %+v, want byte offset, whole-file read", s)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dst, string(b))
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeArchive writes a minimal global archive JSON. workspace is
// json-marshalled so a Windows path survives.
func writeArchive(t *testing.T, path, workspace, model, effort string) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"metadata": map[string]string{
		"workspace_path": workspace, "model": model, "provider": "openrouter", "reasoning_effort": effort,
	}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b))
}
