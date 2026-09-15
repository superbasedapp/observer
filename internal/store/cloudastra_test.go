package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// cloudastra_test.go holds the store-side regressions for the 2026-09
// adversarial review of the cloud evidence lane.

// astraActionRow is one seeded action.
type astraActionRow struct {
	kind      string
	target    string
	rawInput  string
	errMsg    string
	success   bool
	sidechain bool
	second    int
}

// seedAstraStoreSession seeds an eligible session and its actions on `database`,
// returning the project id. It writes raw SQL so a test can express the
// is_sidechain shape the adapters produce.
func seedAstraStoreSession(t *testing.T, s *Store, database *sql.DB, sessionID string, rows []astraActionRow) {
	t.Helper()
	ctx := context.Background()
	seedEligibleSession(t, s, sessionID)
	var projectID int64
	if err := database.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id = ?`, sessionID).
		Scan(&projectID); err != nil {
		t.Fatalf("read project id: %v", err)
	}
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for i, r := range rows {
		ok, side := 1, 0
		if !r.success {
			ok = 0
		}
		if r.sidechain {
			side = 1
		}
		if _, err := database.ExecContext(ctx, `
			INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
			                     raw_tool_name, raw_tool_input, error_message, is_sidechain,
			                     source_file, source_event_id)
			VALUES (?, ?, ?, ?, 'claude-code', ?, ?, '', ?, ?, ?, 'f', ?)`,
			sessionID, projectID, base.Add(time.Duration(r.second)*time.Second).Format(time.RFC3339Nano),
			r.kind, ok, r.target, r.rawInput, r.errMsg, side,
			sessionID+"-"+strconv.Itoa(i)); err != nil {
			t.Fatalf("insert action %d: %v", i, err)
		}
	}
}

// TestCloudTextSubstrateExcludesSidechainRows is the A1 pin at the store seam:
// every CONTENT read is main-thread only.
//
// A Claude sub-agent shares its parent's session id, so its delegation brief is
// a `user_prompt` row and its reply an `assistant_message` row in the same
// table. Both are richer in incidental content than the developer's own text —
// a brief routinely quotes the record it wants analyzed — and both used to
// qualify as the developer's own words.
func TestCloudTextSubstrateExcludesSidechainRows(t *testing.T) {
	s, database := cloudTestStore(t)
	const secret = "customer_balance=12345"
	seedAstraStoreSession(t, s, database, "side-store", []astraActionRow{
		{kind: "user_prompt", target: "Analyze: " + secret, sidechain: true, success: true, second: 0},
		{kind: "user_prompt", target: "Wire the device auth flow", success: true, second: 1},
		{
			kind: "user_prompt", target: "Follow-up: " + secret, rawInput: "Follow-up: " + secret,
			sidechain: true, success: true, second: 2,
		},
		{
			kind: "tool_failure", target: "Bash", errMsg: "row dump " + secret + " permission denied",
			sidechain: true, second: 3,
		},
		{kind: "tool_failure", target: "Bash", errMsg: "no such file or directory", second: 4},
		{kind: "assistant_message", target: "Sub-agent says: " + secret, sidechain: true, success: true, second: 5},
		{kind: "assistant_message", target: "Done, the tests are green.", success: true, second: 6},
	})

	texts, err := s.LoadCloudSessionTexts(context.Background(), "side-store")
	if err != nil {
		t.Fatalf("LoadCloudSessionTexts: %v", err)
	}
	if len(texts.UserPrompts) != 1 || texts.UserPrompts[0] != "Wire the device auth flow" {
		t.Errorf("user prompts = %q, want only the MAIN-thread prompt", texts.UserPrompts)
	}
	if texts.FinalAssistantMessage != "Done, the tests are green." {
		t.Errorf("final assistant message = %q, want the main thread's", texts.FinalAssistantMessage)
	}
	for _, e := range texts.Errors {
		if strings.Contains(e, secret) {
			t.Errorf("a sub-agent failure message entered the error population: %q", e)
		}
	}
	if len(texts.Errors) != 1 {
		t.Errorf("errors = %q, want only the main thread's failure", texts.Errors)
	}
	// The structural facts deliberately KEEP sub-agent rows: a count carries no
	// content, and a sub-agent's work is the session's work. If this ever flips,
	// it must be a decision, not a side effect of the content filter.
	facts, ok, err := s.LoadCloudEvidenceFacts(context.Background(), "side-store", 256)
	if err != nil || !ok {
		t.Fatalf("LoadCloudEvidenceFacts: ok=%v err=%v", ok, err)
	}
	if facts.ActionCount != 7 {
		t.Errorf("ActionCount = %d, want all 7 rows — structural counts are not content", facts.ActionCount)
	}
}

// TestCloudEvidenceBundleReadsTextsInsideTheSnapshot is the A7 mutation proof.
//
// The structural facts already read from one pinned BEGIN DEFERRED snapshot, but
// the TEXT substrate was read afterwards, from the pool. So a prompt landing
// between the two reads changed the excerpts — the part of the envelope a
// consent receipt is most specifically about — while the digest the user
// previewed stayed the one they were shown.
//
// The test commits a write from a SECOND connection at exactly that moment, via
// the store's mid-read hook. It is designed to fail if the snapshot is removed:
// the hook fires AFTER the facts read has already established the snapshot, so
// only a text read on the same pinned, already-reading connection can miss the
// new row. A pool read would see it.
func TestCloudEvidenceBundleReadsTextsInsideTheSnapshot(t *testing.T) {
	s, database := cloudTestStore(t)
	seedAstraStoreSession(t, s, database, "snap1", []astraActionRow{
		{kind: "user_prompt", target: "the original prompt", success: true, second: 0},
		{kind: "run_command", target: "go test ./...", success: true, second: 1},
	})
	var projectID int64
	if err := database.QueryRowContext(context.Background(),
		`SELECT project_id FROM sessions WHERE id = ?`, "snap1").Scan(&projectID); err != nil {
		t.Fatalf("read project id: %v", err)
	}

	// A genuinely SEPARATE connection to the same file, so the write is not
	// simply invisible for want of a second writer.
	writer, err := db.Open(context.Background(), db.Options{Path: cloudTestDBPath(t, database)})
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	defer func() { _ = writer.Close() }()

	const injected = "the prompt that landed mid-read"
	fired := false
	cloudEvidenceMidReadHook = func() {
		fired = true
		if _, err := writer.ExecContext(context.Background(), `
			INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
			                     raw_tool_name, raw_tool_input, error_message, is_sidechain,
			                     source_file, source_event_id)
			VALUES (?, ?, '2026-08-01T00:00:30Z', 'user_prompt', 'claude-code', 1, ?, '', '', '', 0, 'f', 'snap1-mid')`,
			"snap1", projectID, injected); err != nil {
			t.Errorf("mid-read insert: %v", err)
		}
	}
	t.Cleanup(func() { cloudEvidenceMidReadHook = nil })

	bundle, ok, err := s.LoadCloudEvidenceBundle(context.Background(), "snap1", CloudEvidenceRequest{
		MaxActions: 256, IncludeTexts: true,
	})
	if err != nil || !ok {
		t.Fatalf("LoadCloudEvidenceBundle: ok=%v err=%v", ok, err)
	}
	if !fired {
		t.Fatal("the mid-read hook never fired — the test proves nothing")
	}
	for _, p := range bundle.Texts.UserPrompts {
		if strings.Contains(p, injected) {
			t.Fatalf("the text read saw a row committed AFTER the snapshot began: %q\n"+
				"prompts = %q\nThe excerpts must come from the same instant as the facts, or "+
				"a concurrent write silently changes what a preview said would be uploaded.",
				injected, bundle.Texts.UserPrompts)
		}
	}
	if len(bundle.Texts.UserPrompts) != 1 {
		t.Fatalf("prompts = %q, want exactly the one that existed when the snapshot opened",
			bundle.Texts.UserPrompts)
	}

	// The write really did land: without this the assertion above could pass
	// because nothing was ever inserted.
	cloudEvidenceMidReadHook = nil
	after, err := s.LoadCloudSessionTexts(context.Background(), "snap1")
	if err != nil {
		t.Fatalf("LoadCloudSessionTexts: %v", err)
	}
	if len(after.UserPrompts) != 2 {
		t.Fatalf("after the snapshot closed the store sees %q — the mid-read write did not commit, "+
			"so the snapshot assertion was vacuous", after.UserPrompts)
	}
}

// cloudTestDBPath recovers the file a test store was opened on, by asking SQLite.
func cloudTestDBPath(t *testing.T, database *sql.DB) string {
	t.Helper()
	var seq int
	var name, file sql.NullString
	rows, err := database.QueryContext(context.Background(), `PRAGMA database_list`)
	if err != nil {
		t.Fatalf("database_list: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := rows.Scan(&seq, &name, &file); err != nil {
			t.Fatalf("scan database_list: %v", err)
		}
		if name.String == "main" && file.String != "" {
			return file.String
		}
	}
	t.Fatal("could not resolve the test database path")
	return ""
}

// TestCloudOutcomeStreamCoversEveryRunCommand is the A5 pin at the store seam:
// the outcome population is a STREAM over every run_command row, so a session
// far past any window bound still reports its true last build. It also pins the
// target window, which must match the classifier's own scan bound.
func TestCloudOutcomeStreamCoversEveryRunCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a 60k-action session")
	}
	s, database := cloudTestStore(t)
	const (
		total    = 60000
		buildRow = 45000
	)
	seedStreamingCloudSession(t, s, database, "stream1", total, buildRow)

	var (
		seen      int
		lastBuild string
		longSeen  bool
	)
	if _, ok, err := s.LoadCloudEvidenceBundle(context.Background(), "stream1", CloudEvidenceRequest{
		MaxActions: 256,
		Commands: func(target string, _ bool) {
			seen++
			if strings.Contains(target, "go build") {
				lastBuild = target
			}
			if strings.Contains(target, "SBO_LONG_VALUE=") && strings.Contains(target, "go test") {
				longSeen = true
			}
		},
	}); err != nil || !ok {
		t.Fatalf("LoadCloudEvidenceBundle: ok=%v err=%v", ok, err)
	}
	if seen != 3 {
		t.Errorf("the stream saw %d run_command rows, want all 3 of them", seen)
	}
	if lastBuild == "" {
		t.Errorf("the build at row %d of %d never reached the stream — it sits inside the "+
			"window a head+tail read omits", buildRow, total)
	}
	if !longSeen {
		t.Errorf("the command behind a 600-byte inline env assignment was truncated away; "+
			"the target window (%d bytes) must be at least the classifier's own scan bound",
			cloudOutcomeTargetBytes)
	}
}

// seedStreamingCloudSession writes `total` actions, of which exactly three are
// run_command: a build in the MIDDLE and two tests at the end, one behind a long
// inline env assignment.
func seedStreamingCloudSession(t *testing.T, s *Store, database *sql.DB, sessionID string, total, buildRow int) {
	t.Helper()
	ctx := context.Background()
	seedEligibleSession(t, s, sessionID)
	var projectID int64
	if err := database.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id = ?`, sessionID).
		Scan(&projectID); err != nil {
		t.Fatalf("read project id: %v", err)
	}
	longEnv := "SBO_LONG_VALUE=" + strings.Repeat("x", 600) + " "
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
		                     raw_tool_name, raw_tool_input, error_message, is_sidechain, source_file, source_event_id)
		VALUES (?, ?, ?, ?, 'claude-code', ?, ?, '', '', '', 0, 'f', ?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < total; i++ {
		// edit_file, not read_file: the filler rows must be OUTCOME-BEARING, so
		// the kind-bounded head+tail population is genuinely 60k rows deep and
		// the build below genuinely falls in its omitted middle.
		kind, target, success := "edit_file", "/tmp/stream/f"+strconv.Itoa(i)+".go", 1
		switch i {
		case buildRow:
			kind, target, success = "run_command", "go build ./cmd/observer", 0
		case total - 2:
			kind, target = "run_command", "go test ./internal/store/..."
		case total - 1:
			kind, target = "run_command", longEnv+"go test ./cmd/..."
		}
		if _, err := stmt.ExecContext(ctx, sessionID, projectID,
			base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano),
			kind, success, target, sessionID+"-a"+strconv.Itoa(i)); err != nil {
			t.Fatalf("insert action %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatalf("close stmt: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
