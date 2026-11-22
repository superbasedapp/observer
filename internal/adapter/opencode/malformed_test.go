package opencode

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestParseSessionFile_MalformedRowIsSkippedAndCounted pins CAPTURE-02's
// json_valid half: one message row and one part row whose data column is
// not valid JSON sit between good rows. Without a json_valid guard every
// json_extract over them raises "malformed JSON", the whole pass fails,
// the cursor never advances, and capture for the store stops for good.
// With the guard the good rows land, the watermark moves past the bad
// ones, and the skip is reported once as a warning carrying the count.
func TestParseSessionFile_MalformedRowIsSkippedAndCounted(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDB(t, path)
	insertMalformedV1Rows(t, path)

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != 3000 {
		t.Fatalf("NewOffset = %d, want 3000 (the watermark must move past the bad rows)", res.NewOffset)
	}
	var actions []string
	for _, ev := range res.ToolEvents {
		actions = append(actions, ev.ActionType)
	}
	want := []string{models.ActionUserPrompt, models.ActionRunCommand, models.ActionTaskComplete}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("tool events = %v, want %v (the good rows must land)", actions, want)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "skipped 2 row(s)") {
		t.Fatalf("warnings = %q, want one warning naming 2 skipped rows", res.Warnings)
	}

	// The next pass resumes past the bad rows: nothing new, no warning.
	again, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatalf("ParseSessionFile (resume): %v", err)
	}
	if len(again.ToolEvents) != 0 || len(again.Warnings) != 0 {
		t.Fatalf("resume pass: events=%d warnings=%q, want none", len(again.ToolEvents), again.Warnings)
	}
}

// insertMalformedV1Rows adds one message and one part row whose data is
// truncated JSON, timestamped between the good rows setupOpenCodeDB seeds.
func insertMalformedV1Rows(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_bad', 'ses_1', 1500, 1500, '{"role":"user","time":{"created":15')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_bad', 'msg_tool', 'ses_1', 2300, 2300, '{"type":"tool","tool":"bash"'),
			('prt_of_bad_msg', 'msg_bad', 'ses_1', 1600, 1600, '{"type":"text","text":"orphan"}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}
