package deepagents

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/handoffsvc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// The session-handoff reader contract, checked at compile time.
var (
	_ handoffsvc.TranscriptReader     = (*Adapter)(nil)
	_ handoffsvc.FullTranscriptReader = (*Adapter)(nil)
)

// The sub-agent run of thread E: the `task` call's LangGraph task id (also
// the child namespace `tools:<id>`) and the call that started it.
const (
	subagentID     = "08038a3d-55e4-ce10-cf39-555ebd6f4cce"
	subagentCallID = "call_function_t6lvs117ye8c_1"
)

func TestParseFixture_SubagentSidechain(t *testing.T) {
	res, _ := parseAll(t, 0)
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	var root, side []models.TokenEvent
	for _, tk := range tokensOf(res, threadE) {
		if tk.IsSidechain {
			side = append(side, tk)
		} else {
			root = append(root, tk)
		}
	}
	// Two parent calls, three sub-agent calls, no duplicate: the child's
	// forked copy of the parent prompt is never counted again.
	if len(root) != 2 || len(side) != 3 {
		t.Fatalf("thread E tokens root=%d side=%d want 2/3", len(root), len(side))
	}
	// The child's gross input equals dcode's own transfer record for the
	// run (`_session_cost_transfers` input_tokens 35723, cache_read 26316,
	// reasoning 131) — the usage the parse used to drop.
	var gross, cacheRead, reasoning int64
	for _, tk := range side {
		gross += tk.InputTokens + tk.CacheReadTokens + tk.CacheCreationTokens
		cacheRead += tk.CacheReadTokens
		reasoning += tk.ReasoningTokens
		if tk.GenMs != 0 {
			t.Errorf("sub-agent call %s carries GenMs %d (the channel is not written in a child namespace)", tk.SourceEventID, tk.GenMs)
		}
		if tk.TurnID == "" {
			t.Errorf("sub-agent call %s lost the parent turn id", tk.SourceEventID)
		}
	}
	if gross != 35723 || cacheRead != 26316 || reasoning != 131 {
		t.Errorf("sub-agent usage gross=%d cache_read=%d reasoning=%d want 35723/26316/131", gross, cacheRead, reasoning)
	}
	if first := tokenByID(t, side, "tokens:lc_run--01a15e60-3eb5-75cf-9d1a-6dd245ad8bea"); first.InputTokens != 9291 {
		t.Errorf("first sub-agent call net input=%d want 9291 (11771 - 2480)", first.InputTokens)
	}

	e := toolsOf(res, threadE)
	spawn := toolByID(t, e, "tool:"+subagentCallID)
	if spawn.ActionType != models.ActionSpawnSubagent || spawn.IsSidechain || spawn.Metadata == nil || spawn.Metadata.AgentID != subagentID {
		t.Errorf("spawn row = %+v meta=%+v", spawn, spawn.Metadata)
	}
	if spawn.DurationMs <= 0 || spawn.ToolOutput != "hello probe file" {
		t.Errorf("spawn duration/output = %d %q", spawn.DurationMs, spawn.ToolOutput)
	}
	stop := toolByID(t, e, "substop:"+subagentID)
	if stop.ActionType != models.ActionSubagentStop || stop.Target != "general-purpose" || !stop.IsSidechain ||
		stop.ToolOutput != "hello probe file" || stop.DurationMs != spawn.DurationMs || !stop.Timestamp.After(spawn.Timestamp) {
		t.Errorf("subagent_stop = %+v", stop)
	}
	var prompts, sidePrompts, sideCalls int
	for _, ev := range e {
		if ev.IsSidechain {
			if ev.Metadata == nil || ev.Metadata.AgentID != subagentID || !ev.Metadata.IsSubagent {
				t.Errorf("sidechain row %s lacks the sub-agent identity: %+v", ev.SourceEventID, ev.Metadata)
			}
			if ev.ActionType == models.ActionTaskComplete {
				t.Errorf("a sub-agent answer must not end the session turn: %s", ev.SourceEventID)
			}
		}
		switch {
		case ev.ActionType == models.ActionUserPrompt:
			prompts++
		case ev.ActionType == models.ActionPromptContext && ev.IsSidechain:
			sidePrompts++
			if !strings.Contains(ev.Target, "prior conversation") {
				t.Errorf("sub-agent prompt = %q", ev.Target)
			}
		case ev.IsSidechain && (ev.ActionType == models.ActionReadFile || ev.ActionType == models.ActionRunCommand):
			sideCalls++
		}
	}
	if prompts != 1 || sidePrompts != 1 || sideCalls != 2 {
		t.Errorf("E prompts=%d sub-agent prompts=%d sub-agent calls=%d want 1/1/2", prompts, sidePrompts, sideCalls)
	}
	for _, o := range res.CacheObservations {
		if o.SessionID == threadE && strings.Contains(o.MessageID, "gRqRuyQ") {
			t.Error("a sub-agent call fed the parent session's cache chain")
		}
	}
}

func TestParseFixture_GenMs(t *testing.T) {
	res, _ := parseAll(t, 0)
	// Grounded spans: request 12:11:59.717819 -> step checkpoint
	// 12:12:03.380956, and 12:12:24.042585 -> 12:12:25.415266.
	e := tokensOf(res, threadE)
	for id, want := range map[string]int64{
		"tokens:lc_run--01a15e60-1d6c-774b-ba79-59aa839a89ef": 3663,
		"tokens:lc_run--01a15e60-7c6d-7209-bdf7-3ae99c924169": 1372,
	} {
		tk := tokenByID(t, e, id)
		if tk.GenMs != want || tk.GenBasis != models.GenBasisNative || tk.GenTimingV != genTimingV {
			t.Errorf("%s gen=%d basis=%q v=%d want %d native", id, tk.GenMs, tk.GenBasis, tk.GenTimingV, want)
		}
	}
	timed := 0
	for _, tk := range tokensOf(res, threadD) {
		if tk.GenMs > 0 && tk.GenBasis == models.GenBasisNative {
			timed++
		}
	}
	if timed != 4 {
		t.Errorf("thread D timed calls=%d want 4", timed)
	}
	// Thread A carries no `_last_model_request_at` writes: never a guess.
	for _, tk := range tokensOf(res, threadA) {
		if tk.GenMs != 0 || tk.GenBasis != "" {
			t.Errorf("A %s has gen timing %d %q", tk.SourceEventID, tk.GenMs, tk.GenBasis)
		}
	}
}

func TestParseFixture_Surface(t *testing.T) {
	res, _ := parseAll(t, 0)
	got := map[string]models.SessionSurface{}
	for _, s := range res.SessionSurfaces {
		got[s.SessionID] = s
	}
	want := map[string]string{threadA: "dcode", threadD: "dcode-headless", threadE: "dcode-headless"}
	for id, host := range want {
		if s := got[id]; s.Surface != models.SurfaceCLI || s.SurfaceHost != host || s.Hosted {
			t.Errorf("surface %s = %+v want cli/%s", id, s, host)
		}
	}
	// Threads whose workspace config records no `interactive` flag get no
	// stamp (honest unknown).
	for _, id := range []string{threadB, threadC} {
		if s, ok := got[id]; ok {
			t.Errorf("thread %s stamped without evidence: %+v", id, s)
		}
	}
}

func TestParseFixture_WindowsReal(t *testing.T) {
	res, _ := parseAll(t, 0)
	d := toolsOf(res, threadD)
	if len(d) == 0 {
		t.Fatal("no thread D events")
	}
	if root := filepath.ToSlash(d[0].ProjectRoot); !strings.Contains(root, "sbo-hookprobe-deepagents") || strings.Contains(root, "superbased") {
		t.Errorf("windows project root = %q", d[0].ProjectRoot)
	}
	up := toolByID(t, d, "prompt:b065eece-6938-4404-9e89-5bcacd5a2925")
	// The PowerShell-piped prompt starts with a byte-order mark.
	if up.ActionType != models.ActionUserPrompt || !strings.HasPrefix(up.Target, "Run exactly this shell command") {
		t.Errorf("prompt target = %q", up.Target)
	}
	if up.TurnIndex != 1 || up.GitBranch != "main" {
		t.Errorf("prompt turn/branch = %d %q", up.TurnIndex, up.GitBranch)
	}
	blocked := toolByID(t, d, "tool:call_01a15e67469d729eadbdb359")
	if blocked.Success || !strings.Contains(blocked.ErrorMessage, "blocked by hook") || blocked.ActionType != models.ActionRunCommand {
		t.Errorf("hook-blocked execute = %+v", blocked)
	}
	for _, tk := range tokensOf(res, threadD) {
		if tk.TurnID != "3183e64e-6c27-4712-b624-3bb9b76709a0" {
			t.Errorf("D %s turn id = %q (headless: from checkpoint metadata)", tk.SourceEventID, tk.TurnID)
		}
	}
}

func TestParseFixture_TurnAbortedAndIndex(t *testing.T) {
	res, _ := parseAll(t, 0)
	a := toolsOf(res, threadA)
	ab := toolByID(t, a, "aborted:9ef7c20c-fbb8-4ff0-bc2d-8e6715bf6f31")
	if ab.ActionType != models.ActionTurnAborted || ab.TurnIndex != 1 {
		t.Errorf("aborted = %+v", ab)
	}
	n := 0
	for _, e := range a {
		if e.ActionType == models.ActionTurnAborted {
			n++
		}
	}
	if n != 1 {
		t.Errorf("turn_aborted rows=%d want 1 (only the interrupted first prompt)", n)
	}
	if w := toolByID(t, a, "tool:call_function_1i8z467cux1j_1"); w.TurnIndex != 3 {
		t.Errorf("third-turn tool call TurnIndex=%d want 3", w.TurnIndex)
	}
}

func TestParseFixture_Permissions(t *testing.T) {
	res, _ := parseAll(t, 0)
	e := toolsOf(res, threadE)
	root := toolByID(t, e, "perm:"+subagentCallID)
	if root.ActionType != models.ActionPermissionRequest || root.Target != "task" || root.IsSidechain ||
		!strings.Contains(root.RawToolInput, "general-purpose") {
		t.Errorf("task approval = %+v", root)
	}
	side := toolByID(t, e, "perm:call_function_aqfu84l44xq1_1")
	if side.Target != "execute" || !side.IsSidechain || side.Metadata == nil || side.Metadata.AgentID != subagentID {
		t.Errorf("sub-agent approval = %+v", side)
	}
	// Approved requests record no non-default approval kind and no denial;
	// the hook-protocol interrupts produce nothing.
	for _, ev := range e {
		switch ev.ActionType {
		case models.ActionPermissionDenied:
			t.Errorf("unexpected denial %s", ev.SourceEventID)
		case models.ActionPermissionRequest:
			if ev.Metadata != nil && ev.Metadata.PermissionApprovalKind != "" {
				t.Errorf("%s approval kind = %q", ev.SourceEventID, ev.Metadata.PermissionApprovalKind)
			}
		}
	}
	if n := countAction(e, models.ActionPermissionRequest); n != 2 {
		t.Errorf("E approvals=%d want 2", n)
	}
	if n := countAction(toolsOf(res, threadD), models.ActionPermissionRequest); n != 0 {
		t.Errorf("D approvals=%d want 0 (its interrupts are all hook invocations)", n)
	}
}

func countAction(evs []models.ToolEvent, action string) int {
	n := 0
	for _, e := range evs {
		if e.ActionType == action {
			n++
		}
	}
	return n
}

func TestAddPermissions_RejectAndEdit(t *testing.T) {
	cp := "1f1cd48a-16a0-6662-800e-c7c3cfc1bfa4"
	next := "1f1cd48a-20d1-6f15-8000-000000000000"
	shared := &threadShared{
		a:       NewWithOptions(nil, []string{t.TempDir()}),
		session: "s",
		tc: threadCheckpoints{
			byID: map[string]checkpointMeta{cp: {ApprovalMode: "manual"}},
			next: map[string]string{cp: next},
		},
	}
	calls := map[string][]rawToolCall{writeKey(cp, "t1"): {
		{ID: "c1", Name: "execute", Args: map[string]any{"command": "rm -rf build"}},
		{ID: "c2", Name: "execute", Args: map[string]any{"command": "ls"}},
	}}
	hitl := []hitlRequest{
		{CheckpointID: cp, TaskID: "t1", InterruptID: "i1", Index: 0, Name: "execute", Args: map[string]any{"command": "ls"}, Decision: "reject", Message: "not now"},
		{CheckpointID: cp, TaskID: "t1", InterruptID: "i1", Index: 1, Name: "execute", Args: map[string]any{"command": "rm -rf ./build"}, Decision: "edit"},
		{CheckpointID: cp, TaskID: "t9", InterruptID: "i2", Index: 0, Name: "write_file"},
	}
	b := newBuilder(shared, nil, calls, hitl)
	b.addPermissions()
	byID := map[string]models.ToolEvent{}
	for _, ev := range b.tools {
		byID[ev.SourceEventID] = ev
	}
	if len(b.tools) != 4 {
		t.Fatalf("rows=%d want 4 (3 requests + 1 denial): %+v", len(b.tools), b.tools)
	}
	// Exact args match pairs the first request with c2, the edited one
	// falls back to the remaining same-name call c1.
	req := byID["perm:c2"]
	if req.ActionType != models.ActionPermissionRequest || req.Metadata == nil || req.Metadata.PermissionApprovalKind != "reject" || req.Metadata.PermissionMode != "manual" {
		t.Errorf("rejected request = %+v", req)
	}
	deny := byID["permdeny:c2"]
	wantDeny, _ := uuidTime(next)
	if deny.ActionType != models.ActionPermissionDenied || deny.Success || deny.ErrorMessage != "not now" || !deny.Timestamp.Equal(wantDeny) {
		t.Errorf("denial = %+v", deny)
	}
	if ed := byID["perm:c1"]; ed.Metadata == nil || ed.Metadata.PermissionApprovalKind != "edit" {
		t.Errorf("edited request = %+v", ed)
	}
	if _, ok := byID["perm:i2:0"]; !ok {
		t.Error("an unmatched request must keep an interrupt-scoped id")
	}
}

func TestAgentIDOfAndPromptCleaning(t *testing.T) {
	for in, want := range map[string]string{
		"tools:abc":           "abc",
		"tools:abc|tools:def": "def",
		"plain":               "plain",
	} {
		if got := agentIDOf(in); got != want {
			t.Errorf("agentIDOf(%q)=%q want %q", in, got, want)
		}
	}
	if got := cleanPromptText(byteOrderMark + "\n\n  hello \n"); got != "hello" {
		t.Errorf("cleanPromptText=%q", got)
	}
	if got := clockMs("1f1cd489-dc1a-6846-800c-0bf6446bb453", "1f1cd48a-02c8-6c8f-800d-b6f10ebc5a50"); got != 4055 {
		t.Errorf("clockMs=%d want 4055", got)
	}
	if clockMs("x", "1f1cd48a-02c8-6c8f-800d-b6f10ebc5a50") != 0 || clockMs("1f1cd48a-02c8-6c8f-800d-b6f10ebc5a50", "1f1cd489-dc1a-6846-800c-0bf6446bb453") != 0 {
		t.Error("clockMs must be 0 for a missing clock or a negative span")
	}
}

func TestToolVersion_InstallFallback(t *testing.T) {
	dbPath, root := buildStore(t)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE checkpoints SET metadata = '{"cwd": "/x"}' WHERE thread_id = ?`, threadC); err != nil {
		t.Fatal(err)
	}
	db.Close()
	a := NewWithOptions(nil, []string{root})
	version := func() (string, bool) {
		res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range res.SessionToolVersions {
			if v.SessionID == threadC {
				return v.Version, true
			}
		}
		return "", false
	}
	if v, ok := version(); ok {
		t.Errorf("no per-session and no install version must emit nothing, got %q", v)
	}
	if err := os.WriteFile(filepath.Join(root, "update_state.json"),
		[]byte(`{"auto_update_default_acknowledged": true, "seen_version": "0.1.88", "seen_at": 1792561843.8}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, _ := version(); v != "0.1.88" {
		t.Errorf("install-level fallback = %q want 0.1.88", v)
	}
}

func TestReadTranscript(t *testing.T) {
	dbPath, root := buildStore(t)
	a := NewWithOptions(nil, []string{root})
	ctx := context.Background()
	msgs, err := a.ReadTranscript(ctx, models.Session{ID: threadE}, []string{dbPath + "-wal"})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].Role != models.TranscriptUser || msgs[1].Role != models.TranscriptAssistant {
		t.Fatalf("transcript shape = %+v", msgs)
	}
	if !strings.HasPrefix(msgs[0].Text, "Use the task tool") || msgs[0].ID != "35000a81-0367-4444-ae11-31fa2db0a529" {
		t.Errorf("user message = %+v", msgs[0])
	}
	asst := msgs[1]
	if len(asst.ToolCalls) != 2 || asst.ToolCalls[0].Name != "task" || !asst.ToolCalls[0].Resolved ||
		asst.ToolCalls[0].ResultExcerpt != "hello probe file" || !asst.ToolCalls[1].Resolved {
		t.Errorf("assistant calls = %+v", asst.ToolCalls)
	}
	if !strings.Contains(asst.Text, "hello probe file") || asst.Model != "minimax/minimax-m3.1-flash:free" || asst.Time.IsZero() {
		t.Errorf("assistant = %q model=%q", asst.Text, asst.Model)
	}
	// The sub-agent's own messages never enter the parent's transcript.
	for _, m := range msgs {
		if strings.Contains(m.Text, "prior conversation") {
			t.Error("sub-agent prompt leaked into the transcript")
		}
	}
	// Thread A: the interrupted first "hi" is kept, [SYSTEM] dropped,
	// literal text preferred; no hint resolves it through the watch root.
	am, err := a.ReadTranscript(ctx, models.Session{ID: threadA}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(am) < 4 || am[0].Text != "hi" || am[1].Text != "hi" || am[1].Role != models.TranscriptUser {
		t.Errorf("thread A transcript head = %+v", am[:min(len(am), 3)])
	}
	full, err := a.ReadTranscriptFull(ctx, models.Session{ID: threadD}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) == 0 || !strings.HasPrefix(full[0].Text, "Run exactly this shell command") {
		t.Errorf("full transcript = %+v", full)
	}
	if _, err := a.ReadTranscript(ctx, models.Session{ID: "01a00000-0000-7000-8000-0000000fffff"}, nil); err == nil {
		t.Error("an unknown thread must be an error")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := a.ReadTranscript(canceled, models.Session{ID: threadE}, nil); err == nil {
		t.Error("a canceled context must be an error")
	}
}
