package goose

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func TestNewAndWatchPaths(t *testing.T) {
	a := New()
	if a.scrubber == nil {
		t.Fatal("New() left a nil scrubber")
	}
	// WatchPaths returns the construction-time snapshot (may be empty on a
	// host with no resolvable homes, but must not panic).
	_ = a.WatchPaths()

	b := NewWithOptions(nil, nil)
	if b.scrubber == nil {
		t.Fatal("NewWithOptions(nil,nil) left a nil scrubber")
	}
}

func TestResolveDBPath(t *testing.T) {
	cases := map[string]string{
		"/x/sessions/sessions.db":     "/x/sessions/sessions.db",
		"/x/sessions/sessions.db-wal": "/x/sessions/sessions.db",
		"/x/sessions/sessions.db-shm": "/x/sessions/sessions.db",
	}
	for in, want := range cases {
		if got := resolveDBPath(in); got != want {
			t.Errorf("resolveDBPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsForeignMountPathAndMirror(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()

	foreignHome := t.TempDir()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/native", OS: crossmount.OSLinux, Origin: "native"},
			{Path: foreignHome, OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
		}
	}

	native := "/home/native/.local/share/goose/sessions/sessions.db"
	if isForeignMountPath(native) {
		t.Errorf("native path %q classified foreign", native)
	}
	srcDB := filepath.Join(foreignHome, "sessions", "sessions.db")
	if !isForeignMountPath(srcDB) {
		t.Fatalf("foreign path %q not classified foreign", srcDB)
	}

	// The mirror itself (filtered staging, reuse, refresh) is pinned by
	// mirror_filter_test.go and internal/adapter/mirrorbase.
}

func TestMissingMessagesTable(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sessions.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// A store with a sessions table but no messages table (a foreign or
	// partial schema) must degrade to an empty parse, not an error.
	if _, err := db.Exec(`CREATE TABLE sessions (id TEXT PRIMARY KEY, working_dir TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	a := NewWithOptions(nil, []string{dir})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile on messages-less store: %v", err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 || res.NewOffset != 0 {
		t.Errorf("expected empty parse, got %d tools / %d tokens / offset %d",
			len(res.ToolEvents), len(res.TokenEvents), res.NewOffset)
	}
}

func TestParseUTC(t *testing.T) {
	cases := []struct {
		in    string
		zero  bool
		wantY int
	}{
		{"2026-07-09 09:46:40", false, 2026},
		{"2026-07-09T09:46:40Z", false, 2026},
		{"", true, 0},
		{"not-a-time", true, 0},
	}
	for _, c := range cases {
		got := parseUTC(c.in)
		if c.zero {
			if !got.IsZero() {
				t.Errorf("parseUTC(%q)=%v want zero", c.in, got)
			}
			continue
		}
		if got.IsZero() || got.Year() != c.wantY || got.Location() != time.UTC {
			t.Errorf("parseUTC(%q)=%v want year %d UTC", c.in, got, c.wantY)
		}
	}
}

func TestModelNameAndMsgKey(t *testing.T) {
	if got := modelName(`{"model_name":"gpt-4o-mini"}`); got != "gpt-4o-mini" {
		t.Errorf("modelName valid = %q", got)
	}
	if got := modelName(""); got != "" {
		t.Errorf("modelName empty = %q want empty", got)
	}
	if got := modelName("{not json"); got != "" {
		t.Errorf("modelName malformed = %q want empty", got)
	}

	if got := msgKey(messageRow{MessageID: "abc", ID: 7}); got != "abc" {
		t.Errorf("msgKey with message_id = %q want abc", got)
	}
	if got := msgKey(messageRow{ID: 7}); got != "m7" {
		t.Errorf("msgKey fallback = %q want m7", got)
	}
}

func TestSecondsAndTruncate(t *testing.T) {
	if !secondsToTime(0).IsZero() || !secondsToTime(-5).IsZero() {
		t.Error("secondsToTime(<=0) should be zero time")
	}
	if secondsToTime(1783590471).IsZero() {
		t.Error("secondsToTime(positive) should be non-zero")
	}
	if got := truncate("abcdef", 3); got != "abc" {
		t.Errorf("truncate = %q want abc", got)
	}
	if got := truncate("ab", 5); got != "ab" {
		t.Errorf("truncate short = %q want ab", got)
	}
	if got := truncate("ab", 0); got != "ab" {
		t.Errorf("truncate n=0 = %q want ab (no-op)", got)
	}
}

func TestResultSuccess(t *testing.T) {
	if !resultSuccess(nil) {
		t.Error("nil result should default to success")
	}
	if resultSuccess(&toolResultEnv{Value: toolResultValue{IsError: true}}) {
		t.Error("isError=true should be failure")
	}
	if resultSuccess(&toolResultEnv{Status: "error"}) {
		t.Error("status=error should be failure")
	}
	if !resultSuccess(&toolResultEnv{Status: "success"}) {
		t.Error("status=success should be success")
	}
}

func TestErroredToolResultSurfacesFailure(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sessions.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE sessions (id TEXT PRIMARY KEY, working_dir TEXT NOT NULL,
  updated_at TIMESTAMP, provider_name TEXT, model_config_json TEXT,
  accumulated_input_tokens INTEGER, accumulated_output_tokens INTEGER,
  accumulated_cache_read_tokens INTEGER, accumulated_cache_write_tokens INTEGER,
  accumulated_total_tokens INTEGER, accumulated_cost REAL);
INSERT INTO sessions (id, working_dir, updated_at, model_config_json)
  VALUES ('s1','/home/user/proj','2026-07-09 10:00:00','{"model_name":"gpt-4o"}');
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT,
  session_id TEXT NOT NULL, role TEXT NOT NULL, content_json TEXT NOT NULL,
  created_timestamp INTEGER NOT NULL);
INSERT INTO messages (message_id, session_id, role, content_json, created_timestamp) VALUES
 ('a','s1','assistant','[{"type":"toolRequest","id":"c1","toolCall":{"status":"success","value":{"name":"shell","arguments":{"command":"false"}}}}]',1),
 ('b','s1','user','[{"type":"toolResponse","id":"c1","toolResult":{"status":"error","value":{"content":[{"type":"text","text":"command failed"}],"isError":true}}}]',2);
`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	a := NewWithOptions(nil, []string{dir})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range res.ToolEvents {
		if e.SourceEventID == "tool:c1" {
			found = true
			if e.Success {
				t.Error("errored tool call marked success")
			}
			if e.ErrorMessage == "" {
				t.Error("errored tool call has empty ErrorMessage")
			}
		}
	}
	if !found {
		t.Fatal("tool:c1 event not produced")
	}
}
