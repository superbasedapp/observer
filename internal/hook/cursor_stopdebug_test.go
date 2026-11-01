//go:build !sbo_omit_adapter_cursor

package hook

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestSafeScalar(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		wantOK bool
		want   string // marshaled form of the returned value
	}{
		{"number", `123`, true, `123`},
		{"bool", `true`, true, `true`},
		{"short string", `"composer-2.5"`, true, `"composer-2.5"`},
		{"uuid", `"c1a2b3c4-0000-1111-2222-333344445555"`, true, `"c1a2b3c4-0000-1111-2222-333344445555"`},
		{"long string elided", `"` + strings.Repeat("x", 100) + `"`, true, `"string:100"`},
		{"object elided", `{"a":1}`, true, `"object"`},
		{"array elided", `[1,2,3]`, true, `"array"`},
		{"null skipped", `null`, false, ``},
		{"empty skipped", ``, false, ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := safeScalar(json.RawMessage(tt.raw))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			got, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("value = %s, want %s", got, tt.want)
			}
		})
	}
}

// readStopDebugRows parses every forensic row from the debug log under
// the test's overridden HOME.
func readStopDebugRows(t *testing.T) []cursorStopReject {
	t.Helper()
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".observer", "cursor-stop-debug.jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open debug log: %v", err)
	}
	defer f.Close()
	var rows []cursorStopReject
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var r cursorStopReject
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("row parse: %v (line %q)", err, sc.Text())
		}
		rows = append(rows, r)
	}
	return rows
}

// TestStopRejectDumpsRenamedTokenFields is the regression guard for the
// cursor zero-token blind spot: a stop payload whose usage fields were
// renamed (inputTokens vs input_tokens) must ingest no token row AND
// leave a content-safe forensic row revealing the real key set.
func TestStopRejectDumpsRenamedTokenFields(t *testing.T) {
	setTestHome(t, t.TempDir())

	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	body := `{
		"hook_event_name":"stop",
		"conversation_id":"c1","generation_id":"g1",
		"workspace_roots":["/r"],"model":"composer-2.5",
		"inputTokens":123,"outputTokens":45,
		"transcript_path":"` + strings.Repeat("d", 120) + `"
	}`
	HandleCursorEvent(cursor.EventStop, sink, nil,
		strings.NewReader(body), &stdout, &stderr, 250*time.Millisecond)

	if len(sink.tokens) != 0 {
		t.Fatalf("renamed-field payload should ingest no token, got %d", len(sink.tokens))
	}

	rows := readStopDebugRows(t)
	if len(rows) != 1 {
		t.Fatalf("debug row count = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.Reason != "no_usage_fields" {
		t.Errorf("reason = %q, want no_usage_fields", got.Reason)
	}
	// The whole point: the renamed camelCase keys are visible.
	if !containsAll(got.Keys, "inputTokens", "outputTokens", "generation_id", "model") {
		t.Errorf("keys missing renamed fields: %v", got.Keys)
	}
	// Content safety: the long transcript_path is elided, not echoed.
	if s, ok := got.Scalars["transcript_path"].(string); !ok || !strings.HasPrefix(s, "string:") {
		t.Errorf("transcript_path not elided: %v", got.Scalars["transcript_path"])
	}
	// Short scalars ARE echoed (this is what lets us read the rename).
	if scalarString(t, got.Scalars["model"]) != `"composer-2.5"` {
		t.Errorf("model scalar = %v, want composer-2.5", got.Scalars["model"])
	}
}

// TestStopRejectDumpsMissingRequiredField covers the error branch: a
// payload missing generation_id is rejected with an error, and the
// forensic row records which required field was absent.
func TestStopRejectDumpsMissingRequiredField(t *testing.T) {
	setTestHome(t, t.TempDir())

	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	body := `{"hook_event_name":"stop","conversation_id":"c1","model":"default","input_tokens":10,"output_tokens":2}`
	HandleCursorEvent(cursor.EventStop, sink, nil,
		strings.NewReader(body), &stdout, &stderr, 250*time.Millisecond)

	if len(sink.tokens) != 0 {
		t.Fatalf("payload missing generation_id should ingest no token, got %d", len(sink.tokens))
	}
	rows := readStopDebugRows(t)
	if len(rows) != 1 {
		t.Fatalf("debug row count = %d, want 1", len(rows))
	}
	if !strings.Contains(rows[0].Reason, "generation_id") {
		t.Errorf("reason = %q, want it to name generation_id", rows[0].Reason)
	}
}

func containsAll(hay []string, needles ...string) bool {
	set := make(map[string]struct{}, len(hay))
	for _, h := range hay {
		set[h] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; !ok {
			return false
		}
	}
	return true
}

// scalarString marshals a Scalars map value back to its JSON form for
// stable comparison (numbers/bools/strings round-trip predictably).
func scalarString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal scalar: %v", err)
	}
	return string(b)
}

// TestAfterAgentResponseIngestsTokens is the core Cursor-3.4+ token fix:
// afterAgentResponse (which fires INSTEAD of the retired `stop` hook)
// must now yield a token_usage event — net-of-cache input — alongside the
// assistant-message action row.
func TestAfterAgentResponseIngestsTokens(t *testing.T) {
	setTestHome(t, t.TempDir())
	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	body := `{
		"hook_event_name":"afterAgentResponse",
		"conversation_id":"conv-1","generation_id":"gen-1",
		"workspace_roots":["/repo"],"model":"composer-2.5","text":"done",
		"input_tokens":21268,"output_tokens":593,
		"cache_read_tokens":20992,"cache_write_tokens":0
	}`
	HandleCursorEvent(cursor.EventAfterAgentResponse, sink, nil,
		strings.NewReader(body), &stdout, &stderr, 250*time.Millisecond)

	if len(sink.called) != 1 {
		t.Fatalf("expected 1 assistant-message action, got %d", len(sink.called))
	}
	if len(sink.tokens) != 1 {
		t.Fatalf("expected 1 token event from afterAgentResponse, got %d", len(sink.tokens))
	}
	tk := sink.tokens[0]
	// net input = 21268 gross - 20992 cached = 276.
	if tk.InputTokens != 276 || tk.OutputTokens != 593 || tk.CacheReadTokens != 20992 {
		t.Errorf("usage mismatch: %+v (want net input 276)", tk)
	}
	if tk.SessionID != "conv-1" || tk.MessageID != "gen-1" || tk.Model != "composer-2.5" {
		t.Errorf("identity mismatch: %+v", tk)
	}
	if tk.Source != models.TokenSourceHook || tk.Reliability != models.ReliabilityAccurate {
		t.Errorf("source/reliability: %+v", tk)
	}
}

// TestAfterAgentResponseNoUsageDumps proves the forensic path fires on the
// event that actually occurs: an afterAgentResponse whose usage fields
// were renamed leaves no token but records a content-safe debug row (tagged
// with the event) exposing the new keys.
func TestAfterAgentResponseNoUsageDumps(t *testing.T) {
	setTestHome(t, t.TempDir())
	sink := &fakeSink{}
	var stdout, stderr bytes.Buffer
	body := `{
		"hook_event_name":"afterAgentResponse",
		"conversation_id":"conv-1","generation_id":"gen-1",
		"workspace_roots":["/repo"],"model":"composer-2.5","text":"hi",
		"inputTokens":10,"outputTokens":2
	}`
	HandleCursorEvent(cursor.EventAfterAgentResponse, sink, nil,
		strings.NewReader(body), &stdout, &stderr, 250*time.Millisecond)

	if len(sink.tokens) != 0 {
		t.Fatalf("renamed-field afterAgentResponse should ingest no token, got %d", len(sink.tokens))
	}
	rows := readStopDebugRows(t)
	if len(rows) != 1 || !strings.Contains(rows[0].Reason, "afterAgentResponse") {
		t.Fatalf("expected 1 afterAgentResponse forensic row, got %+v", rows)
	}
	if !containsAll(rows[0].Keys, "inputTokens", "outputTokens") {
		t.Errorf("debug row should expose the renamed keys: %v", rows[0].Keys)
	}
}

// TestStopRejectFollowsStateDir: the cursor stop-reject log follows the
// invocation's Observer home (SetStateDirResolver), not ~/.observer (live
// proof 2026-10-21).
func TestStopRejectFollowsStateDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(t.TempDir(), "observer-home")
	SetStateDirResolver(func() string { return dir })
	t.Cleanup(func() { SetStateDirResolver(nil) })

	dumpCursorStopReject([]byte(`{"hook_event_name":"stop"}`), "no_usage_fields")
	if _, err := os.Stat(filepath.Join(dir, "cursor-stop-debug.jsonl")); err != nil {
		t.Fatalf("cursor-stop-debug.jsonl not in the Observer home: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".observer", "cursor-stop-debug.jsonl")); !os.IsNotExist(err) {
		t.Errorf("cursor-stop-debug.jsonl also written under ~/.observer (err=%v)", err)
	}
}
