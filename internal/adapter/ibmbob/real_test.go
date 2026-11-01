package ibmbob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// realID maps a live task id to its anonymized fixture id (the same
// sha256 scheme the exporter used for testdata/ibmbob/real.sql).
func realID(orig string) string {
	sum := sha256.Sum256([]byte("ibmbob-fixture:" + orig))
	return hex.EncodeToString(sum[:])[:32]
}

var (
	realWSLTask       = realID("e4afe5337fea884b2dddbbd57bbe5a2b") // 21 messages, write/edit/run/todo
	realCompactTask   = realID("0ad88777567c3274a2edb2ae3ad22fff") // /compact summary
	realWinTask       = realID("8078a21687333f0a38a092db61295bd9") // Windows, 29 messages
	realHookBlockTsk  = realID("c85a4e4f80c3ed9d444c9649eb01bf45") // hook-blocked prompt, no messages
	realHookBlockJSON = realID("923c26a87101b282115fc6599a0e17dc") // hook-blocked prompt via JSON decision
)

func parseReal(t *testing.T) adapter.ParseResult {
	t.Helper()
	a := NewWithOptions(nil, []string{realRoot})
	res, err := a.ParseSessionFile(context.Background(), realDB, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
	return res
}

func countBy(res adapter.ParseResult, session string) map[string]int {
	out := map[string]int{}
	for _, e := range res.ToolEvents {
		if e.SessionID == session {
			out[e.ActionType]++
		}
	}
	return out
}

func TestRealWSLTask(t *testing.T) {
	res := parseReal(t)
	want := map[string]int{
		models.ActionUserPrompt:       1,
		models.ActionAssistantMessage: 2,
		models.ActionTodoUpdate:       4,
		models.ActionWriteFile:        1,
		models.ActionEditFile:         1,
		models.ActionRunCommand:       3,
	}
	got := countBy(res, realWSLTask)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("action counts = %v, want %v", got, want)
	}
	var lastText, firstPrompt *models.ToolEvent
	for i := range res.ToolEvents {
		e := &res.ToolEvents[i]
		if e.SessionID != realWSLTask {
			continue
		}
		if e.Metadata == nil {
			t.Fatalf("%s has no Metadata", e.SourceEventID)
		}
		// approval_config {autoApprovalEnabled:true, allowed_permissions:
		// [read,todo,edit,execute]} + env.modeId "agent".
		if e.Metadata.PermissionMode != "auto:read+todo+edit+execute" {
			t.Errorf("%s PermissionMode = %q", e.SourceEventID, e.Metadata.PermissionMode)
		}
		if e.Metadata.CollaborationMode != "agent" {
			t.Errorf("%s CollaborationMode = %q", e.SourceEventID, e.Metadata.CollaborationMode)
		}
		if e.Metadata.IsSubagent || e.Metadata.ParentSessionID != "" {
			t.Errorf("%s flagged as a subagent: %+v", e.SourceEventID, e.Metadata)
		}
		if e.TurnIndex != 1 {
			t.Errorf("%s TurnIndex = %d, want 1 (single prompt)", e.SourceEventID, e.TurnIndex)
		}
		if e.ActionType == models.ActionUserPrompt {
			firstPrompt = e
		}
		if e.ActionType == models.ActionAssistantMessage && e.Metadata.StopReason != "" {
			lastText = e
		}
	}
	if firstPrompt == nil || len(firstPrompt.UserAttachments) != 0 {
		t.Errorf("prompt = %+v, want no attachments", firstPrompt)
	}
	if lastText == nil || lastText.Metadata.StopReason != "end_turn" {
		t.Errorf("no assistant_message carries StopReason end_turn: %+v", lastText)
	}
	// The write_file and search_and_replace rows keep native args (loc
	// and guard read RawToolInput) and the authored byte count.
	for _, e := range res.ToolEvents {
		if e.SessionID != realWSLTask {
			continue
		}
		switch e.RawToolName {
		case "write_file":
			if e.ContentBytes != int64(len("print(\"Hello, World!\")\n")) {
				t.Errorf("write_file ContentBytes = %d", e.ContentBytes)
			}
		case "search_and_replace":
			if e.ContentBytes != int64(len("print(\"Hello Bob\")")) {
				t.Errorf("search_and_replace ContentBytes = %d", e.ContentBytes)
			}
		}
	}
}

func TestRealWindowsTask(t *testing.T) {
	res := parseReal(t)
	got := countBy(res, realWinTask)
	if got[models.ActionUserPrompt] != 1 || got[models.ActionRunCommand] != 4 ||
		got[models.ActionTodoUpdate] != 7 || got[models.ActionWriteFile] != 1 || got[models.ActionEditFile] != 1 {
		t.Errorf("action counts = %v", got)
	}
	// This task's approval_config allows all four groups.
	for _, e := range res.ToolEvents {
		if e.SessionID == realWinTask && e.Metadata.PermissionMode != "auto:read+todo+edit+execute" {
			t.Errorf("%s PermissionMode = %q", e.SourceEventID, e.Metadata.PermissionMode)
		}
	}
}

func TestRealCompactionTask(t *testing.T) {
	res := parseReal(t)
	var compact []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.SessionID != realCompactTask {
			continue
		}
		if e.ActionType == models.ActionNotification {
			t.Errorf("compaction summary landed as a notification: %s", e.SourceEventID)
		}
		if e.ActionType == models.ActionContextCompacted {
			compact = append(compact, e)
		}
	}
	if len(compact) != 1 {
		t.Fatalf("context_compacted rows = %d, want 1", len(compact))
	}
	e := compact[0]
	if e.RawToolName != "ibm-bob.compact_summary" || !e.Success || e.ToolOutput != "" {
		t.Errorf("compaction row = %+v", e)
	}
	if e.RawToolInput == "" || e.Target == "" {
		t.Errorf("compaction row lost its size: %+v", e)
	}
}

func TestRealHookBlockedPrompt(t *testing.T) {
	res := parseReal(t)
	var rows []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.SessionID == realHookBlockTsk {
			rows = append(rows, e)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("hook-blocked task emitted %d rows, want exactly the error row", len(rows))
	}
	e := rows[0]
	if e.ActionType != models.ActionTurnAborted || e.Success {
		t.Errorf("ActionType/Success = %s/%v, want turn_aborted/false", e.ActionType, e.Success)
	}
	if e.Target != "UserPromptHookError" || e.ErrorMessage == "" || e.RawToolName != "ibm-bob.last_error" {
		t.Errorf("error row = %+v", e)
	}
	if e.Timestamp.IsZero() {
		t.Error("error row has no timestamp")
	}
	// Re-reading yields the same key (hash of the error JSON, not updated_at).
	again := parseReal(t)
	for _, r := range again.ToolEvents {
		if r.SessionID == realHookBlockTsk && r.SourceEventID != e.SourceEventID {
			t.Errorf("error key drifted: %q vs %q", r.SourceEventID, e.SourceEventID)
		}
	}
}

func TestRealToolVersionPerSession(t *testing.T) {
	res := parseReal(t)
	got := map[string]string{}
	for _, v := range res.SessionToolVersions {
		got[v.SessionID] = v.Version
	}
	want := []string{realWSLTask, realCompactTask, realWinTask, realHookBlockTsk, realHookBlockJSON}
	sort.Strings(want)
	var have []string
	for s := range got {
		have = append(have, s)
		if got[s] != "2.0.6" {
			t.Errorf("session %s version = %q, want 2.0.6 (install-level lastRunVersion)", s, got[s])
		}
	}
	sort.Strings(have)
	if fmt.Sprint(have) != fmt.Sprint(want) {
		t.Errorf("versioned sessions = %v, want %v", have, want)
	}
}

func TestRealNoTokenRows(t *testing.T) {
	res := parseReal(t)
	if len(res.TokenEvents) != 0 {
		t.Errorf("TokenEvents = %d, want 0 (Bob persists no token split)", len(res.TokenEvents))
	}
}

func TestReadTranscriptReal(t *testing.T) {
	a := NewWithOptions(nil, []string{realRoot})
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: realWSLTask}, []string{realDB + "-wal"})
	if err != nil {
		t.Fatalf("ReadTranscript: %v", err)
	}
	if len(msgs) == 0 || msgs[0].Role != models.TranscriptUser {
		t.Fatalf("transcript = %+v", msgs)
	}
	var calls, resolved int
	var last models.TranscriptMessage
	for i, m := range msgs {
		if m.Index != i {
			t.Errorf("message %d has Index %d", i, m.Index)
		}
		if m.ID == "" {
			t.Errorf("message %d has no id", i)
		}
		calls += len(m.ToolCalls)
		for _, c := range m.ToolCalls {
			if c.Resolved {
				resolved++
			}
		}
		last = m
	}
	if calls != 9 || resolved != 9 {
		t.Errorf("tool calls = %d (resolved %d), want 9/9", calls, resolved)
	}
	if last.Role != models.TranscriptAssistant || last.Text == "" {
		t.Errorf("last message = %+v, want the closing assistant summary", last)
	}
	// Without a usable hint the watch root is used.
	if msgs2, err := a.ReadTranscript(context.Background(), models.Session{ID: realWSLTask}, nil); err != nil || len(msgs2) != len(msgs) {
		t.Errorf("root fallback: %d msgs, err %v", len(msgs2), err)
	}
	// An unknown task reads as an empty transcript, not an error.
	if got, err := a.ReadTranscript(context.Background(), models.Session{ID: "nope"}, nil); err != nil || len(got) != 0 {
		t.Errorf("unknown task: %v, %v", got, err)
	}
}

func TestReadTranscriptNoStore(t *testing.T) {
	a := NewWithOptions(nil, []string{t.TempDir()})
	if _, err := a.ReadTranscript(context.Background(), models.Session{ID: "x"}, nil); err == nil {
		t.Error("expected an error when no bob.db exists")
	}
}

func TestReadTranscriptCompactionKeepsSummary(t *testing.T) {
	a := NewWithOptions(nil, []string{realRoot})
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: realCompactTask}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range msgs {
		if m.Role == models.TranscriptAssistant && strings.Contains(m.Text, "Previous conversation summary") {
			found = true
		}
	}
	if !found {
		t.Errorf("compaction summary missing from transcript: %+v", msgs)
	}
}
