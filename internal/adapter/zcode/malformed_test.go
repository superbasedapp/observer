package zcode

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// TestParseSessionFile_MalformedRowIsSkippedAndCounted pins CAPTURE-02's
// json_valid half for zcode (an OpenCode fork with the same message/part
// tables). A message row and a part row whose data column is not valid
// JSON sit between good rows, plus a valid part under the malformed
// message. Without a json_valid guard json_extract raises "malformed
// JSON", the pass fails and the cursor never advances. With the guard the
// pass yields exactly the rows of the same store without the bad rows,
// the watermark is unchanged, and one warning names the count.
func TestParseSessionFile_MalformedRowIsSkippedAndCounted(t *testing.T) {
	clean := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, clean)
	want := parseZcodeResult(t, clean)

	dirty := filepath.Join(t.TempDir(), ".zcode", "cli", "db", "db.sqlite")
	setupZcodeDB(t, dirty)
	insertMalformedZcodeRows(t, dirty)
	a := NewWithOptions(nil, []string{filepath.Dir(dirty)})
	got, err := a.ParseSessionFile(context.Background(), dirty, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got.NewOffset != want.NewOffset {
		t.Fatalf("NewOffset = %d, want %d (the watermark must move past the bad rows)", got.NewOffset, want.NewOffset)
	}
	if g, w := eventKeys(got), eventKeys(want); !reflect.DeepEqual(g, w) {
		t.Fatalf("events = %v, want %v (the good rows must land, the bad ones not)", g, w)
	}
	if len(got.TokenEvents) != len(want.TokenEvents) {
		t.Fatalf("token events = %d, want %d", len(got.TokenEvents), len(want.TokenEvents))
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "skipped 2 row(s)") {
		t.Fatalf("warnings = %q, want one warning naming 2 skipped rows", got.Warnings)
	}

	// The next pass resumes past the bad rows: nothing new, no warning.
	again, err := a.ParseSessionFile(context.Background(), dirty, got.NewOffset)
	if err != nil {
		t.Fatalf("ParseSessionFile (resume): %v", err)
	}
	if len(again.ToolEvents) != 0 || len(again.Warnings) != 0 {
		t.Fatalf("resume pass: events=%d warnings=%q, want none", len(again.ToolEvents), again.Warnings)
	}
}

func parseZcodeResult(t *testing.T, dbPath string) adapter.ParseResult {
	t.Helper()
	a := NewWithOptions(nil, []string{filepath.Dir(dbPath)})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

// eventKeys lists each tool event's action type and source event id.
func eventKeys(res adapter.ParseResult) []string {
	out := make([]string, 0, len(res.ToolEvents))
	for _, ev := range res.ToolEvents {
		out = append(out, ev.ActionType+"|"+ev.SourceEventID)
	}
	return out
}

// insertMalformedZcodeRows adds one message and one part row whose data is
// truncated JSON, and one valid text part under the malformed message, all
// timestamped inside the window setupZcodeDB seeds.
func insertMalformedZcodeRows(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_bad', 'sess_a', 1500, 1500, '{"role":"assistant","finish":"st')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_bad', 'msg_asst', 'sess_a', 2250, 2250, '{"type":"tool","tool":"bash"'),
			('prt_of_bad_msg', 'msg_bad', 'sess_a', 1600, 1600, '{"type":"text","text":"orphan"}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}
