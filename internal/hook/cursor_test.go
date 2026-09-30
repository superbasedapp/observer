package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

type fakeSink struct {
	called   []models.ToolEvent
	tokens   []models.TokenEvent
	outcomes []fakeOutcomeCall
	err      error
	delay    time.Duration
	// outcomeRows is what UpdateActionOutcome returns as RowsAffected.
	// Defaults to 1 (matched a row); tests that need to simulate the
	// "before-row didn't land" race set it to 0.
	outcomeRows int64
}

type fakeOutcomeCall struct {
	SourceFile    string
	SourceEventID string
	Success       bool
	ErrorMessage  string
	DurationMs    int64
	Output        string
	ToolName      string
	Target        string
}

func (f *fakeSink) Ingest(ctx context.Context, events []models.ToolEvent, tokens []models.TokenEvent, _ store.IngestOptions) (store.IngestResult, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return store.IngestResult{}, ctx.Err()
		}
	}
	if f.err != nil {
		return store.IngestResult{}, f.err
	}
	f.called = append(f.called, events...)
	f.tokens = append(f.tokens, tokens...)
	return store.IngestResult{ActionsInserted: len(events), TokensInserted: len(tokens)}, nil
}

func (f *fakeSink) UpdateActionOutcome(ctx context.Context, sourceFile, sourceEventID string, success bool, errorMessage string, durationMs int64, output, toolName, target string) (int64, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if f.err != nil {
		return 0, f.err
	}
	f.outcomes = append(f.outcomes, fakeOutcomeCall{
		SourceFile:    sourceFile,
		SourceEventID: sourceEventID,
		Success:       success,
		ErrorMessage:  errorMessage,
		DurationMs:    durationMs,
		Output:        output,
		ToolName:      toolName,
		Target:        target,
	})
	if f.outcomeRows > 0 {
		return f.outcomeRows, nil
	}
	return 1, nil
}

func TestHandleCursorEvent_HappyPath(t *testing.T) {
	body := `{
		"hook_event_name": "beforeShellExecution",
		"conversation_id": "c1",
		"generation_id": "g1",
		"workspace_roots": ["/repo"],
		"command": "go test"
	}`
	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	HandleCursorEvent(cursor.EventBeforeShellCommand, sink, scrub.New(),
		strings.NewReader(body), &stdout, &stderr, 250*time.Millisecond)

	var reply map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		t.Fatalf("reply: %v: %q", err, stdout.String())
	}
	if reply["permission"] != "allow" {
		t.Errorf("permission: %v", reply["permission"])
	}
	if continueVal, _ := reply["continue"].(bool); !continueVal {
		t.Errorf("continue: %v", reply["continue"])
	}

	if len(sink.called) != 1 {
		t.Fatalf("ingest call count: %d", len(sink.called))
	}
	if sink.called[0].Target != "go test" {
		t.Errorf("target: %s", sink.called[0].Target)
	}
}

func TestHandleCursorEvent_StopIngestsTokenUsage(t *testing.T) {
	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	dir := t.TempDir()
	transcript := filepath.Join(dir, "session.jsonl")
	if err := os.WriteFile(transcript, []byte(strings.Join([]string{
		`{"role":"user","message":{"content":[{"type":"text","text":"<user_query>Hello</user_query>"}]}}`,
		`{"role":"assistant","message":{"content":[{"type":"text","text":"Checking."},{"type":"tool_use","name":"ReadFile","input":{"path":"d:\\repo\\README.md"}}]}}`,
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	HandleCursorEvent(cursor.EventStop, sink, nil,
		strings.NewReader(`{
			"conversation_id":"c1","generation_id":"g1",
			"workspace_roots":["/r"],"model":"default",
			"input_tokens":123,"output_tokens":45,"cache_read_tokens":67,"cache_write_tokens":8,
			"transcript_path":"`+strings.ReplaceAll(transcript, `\`, `\\`)+`"
		}`),
		&stdout, &stderr, 250*time.Millisecond)
	if len(sink.tokens) != 1 {
		t.Fatalf("stop token ingest count: %d", len(sink.tokens))
	}
	// v1.4.49: BuildStopTranscriptEvents now also emits cursor.assistant_text
	// rows alongside the existing tool_use rows. Last assistant turn has one
	// text part ("Checking.") and one ReadFile tool_use → 2 events.
	if len(sink.called) != 2 {
		t.Fatalf("stop transcript events count = %d want 2; events = %+v", len(sink.called), sink.called)
	}
	if sink.called[0].RawToolName != "cursor.assistant_text" {
		t.Errorf("first transcript event RawToolName = %q want cursor.assistant_text", sink.called[0].RawToolName)
	}
	if sink.called[1].ActionType != models.ActionReadFile {
		t.Errorf("second transcript event = %+v (want ActionReadFile)", sink.called[1])
	}
	// InputTokens is NET non-cached: fixture's gross 123 with
	// cache_read_tokens=67 and cache_write_tokens=8 → 48 (both cache
	// buckets are inside Cursor's gross input). See cursor.buildTokenEvent.
	if sink.tokens[0].InputTokens != 48 || sink.tokens[0].Model != "default" || sink.tokens[0].MessageID != "g1" {
		t.Fatalf("unexpected token event: %+v (want InputTokens=48 net of 67 read + 8 written)", sink.tokens[0])
	}
	// Reply still emitted.
	if stdout.Len() == 0 {
		t.Error("no reply written for stop event")
	}
}

func TestHandleCursorEvent_DeadlineDoesNotPanic(t *testing.T) {
	// Sink takes 100ms but deadline is 5ms — ingest must time out cleanly,
	// reply still written, no panic.
	sink := &fakeSink{delay: 100 * time.Millisecond}
	var stdout, stderr bytes.Buffer
	HandleCursorEvent(cursor.EventBeforeShellCommand, sink, nil,
		strings.NewReader(`{
			"conversation_id":"c1","generation_id":"g1",
			"workspace_roots":["/r"],"command":"ls"
		}`),
		&stdout, &stderr, 5*time.Millisecond)
	if stdout.Len() == 0 {
		t.Error("reply not written")
	}
	if !strings.Contains(stderr.String(), "deadline") {
		t.Errorf("expected deadline note on stderr, got %q", stderr.String())
	}
}

func TestHandleCursorEvent_BadJSONStillReplies(t *testing.T) {
	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	HandleCursorEvent(cursor.EventBeforeShellCommand, sink, nil,
		strings.NewReader(`{not json`),
		&stdout, &stderr, 250*time.Millisecond)
	if stdout.Len() == 0 {
		t.Error("reply not written despite bad JSON")
	}
	if len(sink.called) != 0 {
		t.Errorf("should not ingest malformed payload")
	}
	if stderr.Len() == 0 {
		t.Error("expected stderr log")
	}
}

func TestHandleCursorEvent_StripsUTF8BOM(t *testing.T) {
	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	body := "\xEF\xBB\xBF" + `{
		"conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/r"],"command":"ls"
	}`
	HandleCursorEvent(cursor.EventBeforeShellCommand, sink, nil,
		strings.NewReader(body), &stdout, &stderr, 250*time.Millisecond)
	if stdout.Len() == 0 {
		t.Error("reply not written")
	}
	if len(sink.called) != 1 {
		t.Fatalf("expected one ingested event, got %d", len(sink.called))
	}
	if stderr.Len() != 0 {
		t.Errorf("unexpected stderr: %q", stderr.String())
	}
}

func TestHandleCursorEvent_IngestErrorLoggedNotReturned(t *testing.T) {
	sink := &fakeSink{err: errors.New("boom")}
	var stdout, stderr bytes.Buffer
	HandleCursorEvent(cursor.EventBeforeShellCommand, sink, nil,
		strings.NewReader(`{
			"conversation_id":"c1","generation_id":"g1",
			"workspace_roots":["/r"],"command":"ls"
		}`),
		&stdout, &stderr, 250*time.Millisecond)
	if stdout.Len() == 0 {
		t.Error("reply not written")
	}
	if !strings.Contains(stderr.String(), "boom") {
		t.Errorf("expected error log, got %q", stderr.String())
	}
}

// TestHandleCursorEvent_AfterShellExecution_RoutesToOutcomeUpdate
// pins that the dispatcher recognises afterShellExecution and routes
// it through cursor.BuildAfterOutcome → sink.UpdateActionOutcome
// instead of the default Ingest path. The sink's outcomes slice
// captures the call shape for verification.
func TestHandleCursorEvent_AfterShellExecution_RoutesToOutcomeUpdate(t *testing.T) {
	body := `{
		"hook_event_name":"afterShellExecution",
		"conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/r"],
		"command":"go test","exit_code":1,"error":"FAIL TestFoo","duration_ms":2500
	}`
	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	HandleCursorEvent(cursor.EventAfterShellExecution, sink, nil,
		strings.NewReader(body), &stdout, &stderr, 250*time.Millisecond)

	if stdout.Len() == 0 {
		t.Error("reply not written")
	}
	if len(sink.called) != 0 {
		t.Errorf("Ingest called %d times; expected 0 (after-event should route to UpdateActionOutcome)", len(sink.called))
	}
	if len(sink.outcomes) != 1 {
		t.Fatalf("outcomes recorded = %d; want 1", len(sink.outcomes))
	}
	got := sink.outcomes[0]
	if got.SourceFile != "cursor:hook" {
		t.Errorf("source_file=%q", got.SourceFile)
	}
	if got.Success {
		t.Errorf("success=true; exit_code=1 should fail-derive")
	}
	if got.ErrorMessage != "FAIL TestFoo" {
		t.Errorf("error=%q", got.ErrorMessage)
	}
	if got.DurationMs != 2500 {
		t.Errorf("duration_ms=%d", got.DurationMs)
	}
}

// TestHandleCursorEvent_AfterEvent_ZeroRowsLoggedNotFatal pins that
// when UpdateActionOutcome touches zero rows (the before-row hasn't
// landed yet, race condition), the dispatcher logs to stderr but
// doesn't surface a fatal error to the host tool — spec P1.
func TestHandleCursorEvent_AfterEvent_ZeroRowsLoggedNotFatal(t *testing.T) {
	body := `{
		"hook_event_name":"afterShellExecution",
		"conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/r"],
		"command":"go test","success":true
	}`
	zeroSink := &zeroRowsSink{}
	var stdout, stderr bytes.Buffer
	HandleCursorEvent(cursor.EventAfterShellExecution, zeroSink, nil,
		strings.NewReader(body), &stdout, &stderr, 250*time.Millisecond)
	if stdout.Len() == 0 {
		t.Error("reply not written despite zero-rows update")
	}
	if !strings.Contains(stderr.String(), "0 rows") {
		t.Errorf("stderr missing zero-rows note: %q", stderr.String())
	}
}

// zeroRowsSink simulates the race where UpdateActionOutcome's
// matching before-row hasn't landed yet — RowsAffected returns 0
// without an error.
type zeroRowsSink struct{ fakeSink }

func (z *zeroRowsSink) UpdateActionOutcome(_ context.Context, _, _ string, _ bool, _ string, _ int64, _, _, _ string) (int64, error) {
	return 0, nil
}
