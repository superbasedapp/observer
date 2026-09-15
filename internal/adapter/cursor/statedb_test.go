package cursor

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// newTestStateDB creates a minimal state.vscdb fixture (ItemTable +
// cursorDiskKV, matching the real schema this reader queries) and
// returns its path.
func newTestStateDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.vscdb")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)`,
		`CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestMatchesStateDBShape(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{`/home/me/AppData/Roaming/Cursor/User/globalStorage/state.vscdb`, true},
		{`C:\Users\me\AppData\Roaming\Cursor\User\globalStorage\state.vscdb`, true},
		{`/home/me/.config/Cursor/User/globalStorage/state.vscdb`, true},
		{`/home/me/AppData/Roaming/Cursor/User/globalStorage/state.vscdb-wal`, false},
		{`/home/me/AppData/Roaming/Code/User/globalStorage/state.vscdb`, false},
		{`/home/me/.cursor/chats/abc/conv/store.db`, false},
	}
	for _, tc := range tests {
		if got := matchesStateDBShape(tc.path); got != tc.want {
			t.Errorf("matchesStateDBShape(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestParseStateDBFile_EmptyWindowSession(t *testing.T) {
	path := newTestStateDB(t)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	composerID := "11111111-1111-1111-1111-111111111111"
	if _, err := db.Exec(
		`INSERT INTO cursorDiskKV VALUES(?, ?)`,
		"composerData:"+composerID,
		[]byte(`{"name":"Untitled","createdAt":1735689600000,"unifiedMode":"agent","isAgentic":true,"modelConfig":[{"modelName":"claude-4-sonnet"}]}`),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO cursorDiskKV VALUES(?, ?)`,
		"bubbleId:"+composerID+":bubble-1",
		[]byte(`{"type":1,"text":"hello there","createdAt":1735689601000}`),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO cursorDiskKV VALUES(?, ?)`,
		"bubbleId:"+composerID+":bubble-2",
		[]byte(`{"type":2,"text":"hi, how can I help?","createdAt":1735689602000}`),
	); err != nil {
		t.Fatal(err)
	}
	db.Close()

	a := New()
	res, err := a.parseStateDBFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("parseStateDBFile: %v", err)
	}
	if res.NewOffset <= 0 {
		t.Errorf("NewOffset = %d, want > 0", res.NewOffset)
	}
	if len(res.ToolEvents) != 3 {
		t.Fatalf("got %d tool events, want 3 (session_start + user_prompt + assistant_message): %+v", len(res.ToolEvents), res.ToolEvents)
	}

	var sawStart, sawUser, sawAssistant bool
	for _, ev := range res.ToolEvents {
		if ev.SessionID != composerID {
			t.Errorf("event SessionID = %q, want %q", ev.SessionID, composerID)
		}
		switch ev.ActionType {
		case "session_start":
			sawStart = true
		case "user_prompt":
			sawUser = true
			if ev.RawToolInput != "hello there" {
				t.Errorf("user prompt RawToolInput = %q", ev.RawToolInput)
			}
		case "assistant_message":
			sawAssistant = true
		}
	}
	if !sawStart || !sawUser || !sawAssistant {
		t.Errorf("missing expected event types: start=%v user=%v assistant=%v", sawStart, sawUser, sawAssistant)
	}

	// Re-parsing from the returned watermark should yield no new events.
	res2, err := a.parseStateDBFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(res2.ToolEvents) != 0 {
		t.Errorf("re-parse from watermark produced %d events, want 0", len(res2.ToolEvents))
	}
}

// TestModelConfigDoc_TolerantShapes pins the object-OR-array decode of
// composerData.modelConfig. The `[]struct{ModelName string}` this field
// used to be made every v14/v15 document fail json.Unmarshal, which
// dropped the whole composerData row (IDE-02).
func TestModelConfigDoc_TolerantShapes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"v15 object", `{"modelConfig":{"modelName":"default","maxMode":false}}`, "default"},
		{
			"v14 object with selectedModels",
			`{"modelConfig":{"modelName":"claude-4-sonnet","maxMode":false,"selectedModels":[{"modelId":"gpt-5","parameters":[]}]}}`,
			"claude-4-sonnet", // modelName stays primary
		},
		{
			"object with empty modelName falls back to selectedModels",
			`{"modelConfig":{"modelName":"","selectedModels":[{"modelId":"composer-1","parameters":[]}]}}`,
			"composer-1",
		},
		{"legacy array", `{"modelConfig":[{"modelName":"claude-4-sonnet"}]}`, "claude-4-sonnet"},
		{"empty array", `{"modelConfig":[]}`, ""},
		{"null", `{"modelConfig":null}`, ""},
		{"absent", `{}`, ""},
		{"unknown scalar shape degrades, never errors", `{"modelConfig":"gpt-5"}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var doc composerDataDoc
			if err := json.Unmarshal([]byte(tc.raw), &doc); err != nil {
				t.Fatalf("Unmarshal(%s) = %v, want nil", tc.raw, err)
			}
			if doc.ModelConfig.ModelName != tc.want {
				t.Errorf("ModelName = %q, want %q", doc.ModelConfig.ModelName, tc.want)
			}
		})
	}
}

// TestFlexTime_TolerantShapes pins the int-ms-OR-ISO-string decode of
// createdAt. Every live bubbleId row carries the ISO form; the fixed
// int64 declaration made all of them fail json.Unmarshal (IDE-02).
func TestFlexTime_TolerantShapes(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantSet bool
		wantMs  int64
	}{
		{"unix ms number", `{"createdAt":1735689601000}`, true, 1735689601000},
		{"ISO with millis", `{"createdAt":"2025-01-01T00:00:01.000Z"}`, true, 1735689601000},
		{"ISO whole seconds", `{"createdAt":"2025-01-01T00:00:01Z"}`, true, 1735689601000},
		{"ISO with offset", `{"createdAt":"2025-01-01T01:00:01+01:00"}`, true, 1735689601000},
		{"quoted epoch ms", `{"createdAt":"1735689601000"}`, true, 1735689601000},
		{"null", `{"createdAt":null}`, false, 0},
		{"absent", `{}`, false, 0},
		{"empty string", `{"createdAt":""}`, false, 0},
		{"unparsable string degrades, never errors", `{"createdAt":"yesterday"}`, false, 0},
		{"zero ms is not a timestamp", `{"createdAt":0}`, false, 0},
		{"object shape degrades, never errors", `{"createdAt":{"seconds":1}}`, false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var doc bubbleDoc
			if err := json.Unmarshal([]byte(tc.raw), &doc); err != nil {
				t.Fatalf("Unmarshal(%s) = %v, want nil", tc.raw, err)
			}
			if doc.CreatedAt.Set != tc.wantSet {
				t.Fatalf("Set = %v, want %v", doc.CreatedAt.Set, tc.wantSet)
			}
			if tc.wantSet && doc.CreatedAt.Time.UnixMilli() != tc.wantMs {
				t.Errorf("Time = %s (%d ms), want %d ms",
					doc.CreatedAt.Time, doc.CreatedAt.Time.UnixMilli(), tc.wantMs)
			}
		})
	}
}

// TestParseStateDBFile_V14V15Shapes is the IDE-02 regression: a store
// written by a current Cursor build (object modelConfig + ISO
// createdAt, `name` sometimes null) must yield rows. Before the
// tolerant decode this fixture produced ZERO events — every document
// failed json.Unmarshal.
func TestParseStateDBFile_V14V15Shapes(t *testing.T) {
	path := newTestStateDB(t)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}

	// v15 composer: object modelConfig, no selectedModels, ISO createdAt.
	v15 := "33333333-3333-3333-3333-333333333333"
	// v14 composer: object modelConfig WITH selectedModels, null name.
	v14 := "44444444-4444-4444-4444-444444444444"
	rows := []struct{ key, value string }{
		{
			"composerData:" + v15,
			`{"name":"Explain the build","createdAt":"2026-08-30T11:04:07.318Z","unifiedMode":"agent","isAgentic":true,` +
				`"modelConfig":{"modelName":"default","maxMode":false},"_v":15}`,
		},
		{
			"bubbleId:" + v15 + ":bubble-iso",
			`{"type":1,"text":"why is the build slow?","createdAt":"2026-08-30T11:04:07.318Z"}`,
		},
		{
			"bubbleId:" + v15 + ":bubble-ms",
			`{"type":2,"text":"the link step dominates","createdAt":1735689602000}`,
		},
		{
			"composerData:" + v14,
			`{"name":null,"createdAt":"2026-08-29T09:00:00.000Z","unifiedMode":"ask","isAgentic":false,` +
				`"modelConfig":{"modelName":"","maxMode":false,"selectedModels":[{"modelId":"composer-1","parameters":[]}]},"_v":14}`,
		},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO cursorDiskKV VALUES(?, ?)`, r.key, []byte(r.value)); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	a := New()
	res, err := a.parseStateDBFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("parseStateDBFile: %v", err)
	}
	if len(res.ToolEvents) != 4 {
		t.Fatalf("got %d tool events, want 4 (2 session_start + 2 messages): %+v", len(res.ToolEvents), res.ToolEvents)
	}

	byKey := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		byKey[ev.SessionID+"|"+ev.ActionType] = ev
	}

	start15, ok := byKey[v15+"|session_start"]
	if !ok {
		t.Fatalf("no session_start for the v15 composer: %+v", res.ToolEvents)
	}
	if start15.Model != "default" {
		t.Errorf("v15 session_start Model = %q, want %q", start15.Model, "default")
	}
	if want := time.Date(2026, 8, 30, 11, 4, 7, 318000000, time.UTC); !start15.Timestamp.Equal(want) {
		t.Errorf("v15 session_start Timestamp = %s, want %s", start15.Timestamp, want)
	}

	start14, ok := byKey[v14+"|session_start"]
	if !ok {
		t.Fatalf("no session_start for the v14 composer: %+v", res.ToolEvents)
	}
	if start14.Model != "composer-1" {
		t.Errorf("v14 session_start Model = %q, want the selectedModels fallback %q", start14.Model, "composer-1")
	}
	if !strings.Contains(start14.RawToolInput, `name=""`) {
		t.Errorf("v14 session_start RawToolInput = %q, want a null name to degrade to an empty string", start14.RawToolInput)
	}

	user, ok := byKey[v15+"|user_prompt"]
	if !ok {
		t.Fatalf("no user_prompt for the ISO-createdAt bubble: %+v", res.ToolEvents)
	}
	if want := time.Date(2026, 8, 30, 11, 4, 7, 318000000, time.UTC); !user.Timestamp.Equal(want) {
		t.Errorf("ISO bubble Timestamp = %s, want %s", user.Timestamp, want)
	}
	assistant, ok := byKey[v15+"|assistant_message"]
	if !ok {
		t.Fatalf("no assistant_message for the int-ms bubble: %+v", res.ToolEvents)
	}
	if want := time.UnixMilli(1735689602000).UTC(); !assistant.Timestamp.Equal(want) {
		t.Errorf("int-ms bubble Timestamp = %s, want %s", assistant.Timestamp, want)
	}
}

func TestParseStateDBFile_SkipsSiblingCoveredSession(t *testing.T) {
	home := t.TempDir()
	composerID := "22222222-2222-2222-2222-222222222222"

	// Sibling agent-transcript exists for this composerID — the
	// conversation is already captured via the richer transcript path,
	// so state.vscdb rows for it must be suppressed.
	transcriptDir := filepath.Join(home, ".cursor", "projects", "some-slug", "agent-transcripts", composerID)
	if err := os.MkdirAll(transcriptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(transcriptDir, composerID+".jsonl"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	// crossmount.AllHomes()'s native-home resolution goes through
	// os.UserHomeDir, which reads $HOME on Linux/macOS and %USERPROFILE%
	// on Windows — pin BOTH so cursorSiblingExists globs the fixture
	// instead of the real host home on every OS the suite runs on.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	path := newTestStateDB(t)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO cursorDiskKV VALUES(?, ?)`,
		"composerData:"+composerID,
		[]byte(`{"name":"Covered","createdAt":1735689600000}`),
	); err != nil {
		t.Fatal(err)
	}
	db.Close()

	a := New()
	res, err := a.parseStateDBFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("parseStateDBFile: %v", err)
	}
	if len(res.ToolEvents) != 0 {
		t.Errorf("got %d tool events for a sibling-covered session, want 0: %+v", len(res.ToolEvents), res.ToolEvents)
	}
}
