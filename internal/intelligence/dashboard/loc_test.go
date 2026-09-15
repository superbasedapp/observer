package dashboard

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newLOCServer builds a Server over a throwaway database.
func newLOCServer(t *testing.T) (*Server, *sql.DB) {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, database
}

// ingestLOCEdit puts one AI edit into the database through the real
// ingest path, so the LOC rows are produced by the shipping seam and not
// by the test.
func ingestLOCEdit(t *testing.T, database *sql.DB, sessionID, root, target, raw, eventID string, at time.Time) {
	t.Helper()
	st := store.New(database)
	_, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SessionID:     sessionID,
		ProjectRoot:   root,
		Target:        target,
		ActionType:    models.ActionEditFile,
		RawToolInput:  raw,
		RawToolName:   "Edit",
		Tool:          models.ToolClaudeCode,
		SourceFile:    "/tmp/s.jsonl",
		SourceEventID: eventID,
		Timestamp:     at,
		Success:       true,
	}}, nil, store.IngestOptions{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
}

// TestSessionLOCEndpoint pins the session card's payload, including the
// honesty fields the UI is required to render.
func TestSessionLOCEndpoint(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/a.go",
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2\nb := 3"}`,
		"ev1", time.Now().UTC().Add(-time.Minute))

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/s1/loc", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var got SessionLOCResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rr.Body.String())
	}
	if got.SessionID != "s1" {
		t.Errorf("session_id = %q, want s1", got.SessionID)
	}
	if got.AIMain.CodeTouched != 2 {
		t.Errorf("ai_main.code_touched = %d, want 2 (1 modified + 1 added)", got.AIMain.CodeTouched)
	}
	if got.HumanCapture != "none" {
		t.Errorf("human_capture = %q, want none", got.HumanCapture)
	}
	// Honesty rule: the payload must hand the UI the wording, not leave
	// it to invent one — and must not imply a share it cannot compute.
	if !strings.Contains(got.CaptureNote, "no AI share is shown") {
		t.Errorf("capture_note = %q, want the no-share explanation", got.CaptureNote)
	}
	if got.ClassifierVersion != loc.Version {
		t.Errorf("classifier_version = %d, want %d", got.ClassifierVersion, loc.Version)
	}
}

// TestLOCSummaryOmitsShareWithoutHumanCapture is the single most
// important honesty assertion in this feature: with nothing measuring the
// developer's own typing, a share would be 100% by construction. The API
// must OMIT it rather than send 1.0.
func TestLOCSummaryOmitsShareWithoutHumanCapture(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/a.go",
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2"}`,
		"ev1", time.Now().UTC().Add(-time.Hour))

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/loc/summary?days=7", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	// Assert on the RAW JSON, not the struct: a nil *float64 and an
	// absent key look the same after decoding, and the contract with the
	// UI is that the key is absent.
	if bytes.Contains(rr.Body.Bytes(), []byte(`"ai_share"`)) {
		t.Errorf("ai_share is present with no human capture: %s", rr.Body.String())
	}
	var got LOCSummaryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.AICodeTouched != 1 {
		t.Errorf("ai_code_touched = %d, want 1", got.AICodeTouched)
	}
	if got.HumanCapture != "none" {
		t.Errorf("human_capture = %q, want none", got.HumanCapture)
	}
}

// postEditorChange issues an editor-change POST the way the extension
// does: no Origin header (a non-browser loopback client).
func postEditorChange(t *testing.T, s *Server, body EditorChangeRequest) (int, EditorChangeResponse) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/loc/editor-change", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	var out EditorChangeResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rr.Body.String())
		}
	}
	return rr.Code, out
}

// editorBody builds a well-formed request.
func editorBody(root, path string, human, system LOCStatsRequest, savedAt time.Time) EditorChangeRequest {
	return EditorChangeRequest{
		Path:              path,
		WorkspaceRoot:     root,
		Language:          "go",
		Category:          "code",
		Human:             human,
		System:            system,
		HumanConfidence:   "high",
		SystemConfidence:  "high",
		SavedAt:           savedAt.Format(time.RFC3339Nano),
		ClassifierVersion: loc.Version,
	}
}

// TestEditorChangeRecordsHumanAndSystemSeparately pins acceptance
// criterion 4(c): a format-on-save reflow is `system`, never folded into
// the developer's own line count.
func TestEditorChangeRecordsHumanAndSystemSeparately(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	now := time.Now().UTC()
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/other.go",
		`{"file_path":"/repo/other.go","old_string":"z := 1","new_string":"z := 2"}`,
		"ev1", now.Add(-2*time.Minute))

	code, res := postEditorChange(t, s, editorBody("/repo", "a.go",
		LOCStatsRequest{AddedCode: 3, Blank: 1},
		LOCStatsRequest{Whitespace: 12},
		now))
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if res.Recorded != 2 {
		t.Fatalf("recorded = %d, want 2 (one human row, one system row)", res.Recorded)
	}
	if res.Echo {
		t.Error("a save of a file no agent touched was called an echo")
	}
	if res.SessionID != "s1" {
		t.Errorf("session_id = %q, want s1 (a session was active 2 minutes ago)", res.SessionID)
	}

	got, err := store.New(database).LoadSessionLOC(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	var human, system loc.Stats
	for _, b := range got.Buckets {
		switch b.Actor {
		case store.LOCActorHuman:
			human.Add(b.Stats)
		case store.LOCActorSystem:
			system.Add(b.Stats)
		}
	}
	if human.AddedCode != 3 || human.Whitespace != 0 {
		t.Errorf("human = %+v, want 3 added code and NO whitespace (the reflow is the formatter's)", human)
	}
	if system.Whitespace != 12 || system.AddedCode != 0 {
		t.Errorf("system = %+v, want 12 whitespace only", system)
	}
	if got.HumanCapture != "vscode" {
		t.Errorf("human_capture = %q, want vscode once an editor has reported", got.HumanCapture)
	}
}

// TestEditorChangeEchoOfAnAIWriteIsNotHumanAuthorship pins acceptance
// criterion 4(a): the agent edited the file a second ago and the editor
// saved the reloaded buffer. Those lines are the agent's.
func TestEditorChangeEchoOfAnAIWriteIsNotHumanAuthorship(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	now := time.Now().UTC()
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/a.go",
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2\nb := 3\nc := 4"}`,
		"ev1", now.Add(-time.Second))

	code, res := postEditorChange(t, s, editorBody("/repo", "a.go",
		LOCStatsRequest{AddedCode: 2, ModifiedCode: 1}, LOCStatsRequest{}, now))
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !res.Echo {
		t.Fatal("a save one second after the agent wrote the same file was not recognised as an echo")
	}

	got, err := store.New(database).LoadSessionLOC(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range got.Buckets {
		if b.Actor == store.LOCActorHuman {
			t.Errorf("the echo was counted as human authorship: %+v", b)
		}
	}
}

// TestEditorChangeAfterAnOldAIEditCountsOnlyTheHumanDelta pins acceptance
// criterion 4(b): the agent touched the file five minutes ago, so this
// save is the developer's own work.
func TestEditorChangeAfterAnOldAIEditCountsOnlyTheHumanDelta(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	now := time.Now().UTC()
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/a.go",
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2"}`,
		"ev1", now.Add(-5*time.Minute))

	code, res := postEditorChange(t, s, editorBody("/repo", "a.go",
		LOCStatsRequest{AddedCode: 4}, LOCStatsRequest{}, now))
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if res.Echo {
		t.Error("a save five minutes after the agent's edit was called an echo")
	}
	got, err := store.New(database).LoadSessionLOC(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	var human loc.Stats
	for _, b := range got.Buckets {
		if b.Actor == store.LOCActorHuman {
			human.Add(b.Stats)
		}
	}
	if human.AddedCode != 4 {
		t.Errorf("human added_code = %d, want exactly the human delta of 4", human.AddedCode)
	}
}

// TestEditorChangeDeferredReconciliationRelabelsALateArrivingEcho pins
// the reason the reconciliation is DEFERRED: the extension reports the
// save immediately, but the transcript carrying the agent's action can be
// flushed seconds later. Reconciling only at save time would inflate the
// human number on every such race.
func TestEditorChangeDeferredReconciliationRelabelsALateArrivingEcho(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	now := time.Now().UTC()

	// A project must exist for the save to attach to.
	if _, err := store.New(database).UpsertProject(context.Background(), "/repo", ""); err != nil {
		t.Fatal(err)
	}
	// The save lands FIRST: nothing to reconcile against yet.
	code, res := postEditorChange(t, s, editorBody("/repo", "a.go",
		LOCStatsRequest{AddedCode: 2, ModifiedCode: 1}, LOCStatsRequest{}, now))
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if res.Echo {
		t.Fatal("the save was called an echo before the AI row existed")
	}

	// Now the agent's transcript flushes and its action lands.
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/a.go",
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2\nb := 3\nc := 4"}`,
		"ev1", now.Add(-time.Second))

	got, err := store.New(database).LoadLOCSummary(context.Background(), 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range got.Buckets {
		if b.Actor == store.LOCActorHuman {
			t.Errorf("the late-arriving AI row did not relabel the editor echo: %+v", b)
		}
	}
}

// TestEditorChangeRejectsOversizedAndBadBodies pins the body cap and the
// method guard. The endpoint accepts counts; there is no shape it accepts
// that could carry a file.
func TestEditorChangeRejectsOversizedAndBadBodies(t *testing.T) {
	t.Parallel()
	s, _ := newLOCServer(t)

	t.Run("oversized body", func(t *testing.T) {
		huge := bytes.Repeat([]byte("x"), locEditorMaxBody+1)
		req := httptest.NewRequest(http.MethodPost, "/api/loc/editor-change", bytes.NewReader(huge))
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", rr.Code)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/loc/editor-change",
			strings.NewReader("{not json"))
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("GET is not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/loc/editor-change", nil)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rr.Code)
		}
	})
}

// TestEditorChangeSkipsGeneratedFiles pins that saving a lockfile is not
// authorship, on the human side exactly as on the AI side.
func TestEditorChangeSkipsGeneratedFiles(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	if _, err := store.New(database).UpsertProject(context.Background(), "/repo", ""); err != nil {
		t.Fatal(err)
	}
	body := editorBody("/repo", "package-lock.json",
		LOCStatsRequest{AddedCode: 900}, LOCStatsRequest{}, time.Now().UTC())
	body.Category = "generated"
	body.Language = ""
	code, res := postEditorChange(t, s, body)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if res.Recorded != 0 {
		t.Errorf("recorded = %d, want 0 for a generated file", res.Recorded)
	}
	if !strings.Contains(res.Note, "skipped") {
		t.Errorf("note = %q, want an explanation of the skip", res.Note)
	}
}

// TestEditorChangeUnknownWorkspaceIsNotAnError pins that a save from a
// workspace no agent has run in records nothing and says so, rather than
// conjuring a project row from an editor event.
func TestEditorChangeUnknownWorkspaceIsNotAnError(t *testing.T) {
	t.Parallel()
	s, _ := newLOCServer(t)
	code, res := postEditorChange(t, s, editorBody("/never/seen", "a.go",
		LOCStatsRequest{AddedCode: 3}, LOCStatsRequest{}, time.Now().UTC()))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if res.Recorded != 0 {
		t.Errorf("recorded = %d, want 0", res.Recorded)
	}
	if !strings.Contains(res.Note, "not a known project") {
		t.Errorf("note = %q, want the unknown-workspace explanation", res.Note)
	}
}

// TestEditorChangeIsOwnerLocal pins that the loopback ingest is
// classified CapabilityLocal, so it is refused on every remotely-exposed
// bind before a principal is resolved. A remote viewer must never be able
// to write authorship counts into someone else's node.
func TestEditorChangeIsOwnerLocal(t *testing.T) {
	t.Parallel()
	s, _ := newLOCServer(t)
	_, capMap, _ := s.registerRoutes(nil)
	if got := capMap["/api/loc/editor-change"]; got != CapabilityLocal {
		t.Errorf("/api/loc/editor-change capability = %v, want %v", got, CapabilityLocal)
	}
	if got := capMap["/api/loc/summary"]; got != CapabilityView {
		t.Errorf("/api/loc/summary capability = %v, want %v", got, CapabilityView)
	}
}

// TestSessionsListCarriesAICodeLines pins the Sessions-table column: the
// list payload carries the per-session agent-authored code-line count,
// deduplicated the same way the detail card's read is, so the two
// surfaces cannot disagree about the same session.
func TestSessionsListCarriesAICodeLines(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/a.go",
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2\nb := 3\nc := 4"}`,
		"ev1", time.Now().UTC().Add(-time.Minute))

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var payload struct {
		Rows []struct {
			ID             string `json:"id"`
			AICodeLines    int    `json:"ai_code_lines"`
			HumanCodeLines int    `json:"human_code_lines"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v (%s)", err, rr.Body.String())
	}
	var found bool
	for _, row := range payload.Rows {
		if row.ID != "s1" {
			continue
		}
		found = true
		// 1 modified + 2 added = 3 code lines touched.
		if row.AICodeLines != 3 {
			t.Errorf("ai_code_lines = %d, want 3", row.AICodeLines)
		}
		if row.HumanCodeLines != 0 {
			t.Errorf("human_code_lines = %d, want 0 with no editor capture", row.HumanCodeLines)
		}
	}
	if !found {
		t.Fatalf("session s1 missing from the list: %s", rr.Body.String())
	}

	// The detail card must report the SAME number. If these ever diverge
	// the two dedup implementations have drifted.
	detail := httptest.NewRecorder()
	s.Handler().ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/api/session/s1/loc", nil))
	var card SessionLOCResponse
	if err := json.Unmarshal(detail.Body.Bytes(), &card); err != nil {
		t.Fatal(err)
	}
	if got := card.AIMain.CodeTouched + card.AISidechain.CodeTouched; got != 3 {
		t.Errorf("session card code_touched = %d, list said 3 — the list subquery and "+
			"locDedupCTE have drifted", got)
	}
}

// TestSessionsListOmitsLOCWhenNeverCounted pins that a corpus that has
// never run the backfill emits the byte-identical payload it did before
// this feature existed. A session that was never counted must not render
// as a session that wrote no code.
func TestSessionsListOmitsLOCWhenNeverCounted(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	// An action type LOC never counts, so no file_changes row exists.
	st := store.New(database)
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SessionID: "s1", ProjectRoot: "/repo", Target: "ls",
		ActionType: models.ActionRunCommand, RawToolInput: "ls",
		Tool: models.ToolClaudeCode, SourceFile: "/tmp/s.jsonl",
		SourceEventID: "ev1", Timestamp: time.Now().UTC(), Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil))
	if strings.Contains(rr.Body.String(), "ai_code_lines") {
		t.Errorf("ai_code_lines is present on an uncounted corpus — omitempty is not holding, "+
			"and the UI would render 0 where it should render 'not counted': %s", rr.Body.String())
	}
}

// TestSessionsSortByAICodeLines pins that the new sort key is accepted
// and actually orders by it.
func TestSessionsSortByAICodeLines(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	now := time.Now().UTC()
	ingestLOCEdit(t, database, "small", "/repo", "/repo/a.go",
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2"}`,
		"ev1", now.Add(-2*time.Minute))
	ingestLOCEdit(t, database, "big", "/repo", "/repo/b.go",
		`{"file_path":"/repo/b.go","old_string":"b := 1","new_string":"b := 2\nc := 3\nd := 4\ne := 5"}`,
		"ev2", now.Add(-time.Minute))

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/api/sessions?limit=10&sort_by=ai_code_lines&sort_dir=desc", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var payload struct {
		Rows []struct {
			ID          string `json:"id"`
			AICodeLines int    `json:"ai_code_lines"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Rows) < 2 {
		t.Fatalf("want 2 sessions, got %d", len(payload.Rows))
	}
	if payload.Rows[0].ID != "big" {
		t.Errorf("first row = %q (%d lines), want big — sort_by=ai_code_lines did not order",
			payload.Rows[0].ID, payload.Rows[0].AICodeLines)
	}
}

// ---------------------------------------------------------------------
// Review fixes (2026-09-07): M5, M7
// ---------------------------------------------------------------------

// TestSessionsListAndCardAgreeOnRepeatedHumanSaves is review finding M5.
//
// Editor rows carry NO input_digest (loc_editor.go never sets one), and
// locDedupCTE deliberately never collapses an empty digest — an absent
// fingerprint is not a shared one. The list subquery grouped them anyway
// and took the MAX, so three saves of one file adding 10, 20 and 30 lines
// showed 60 on the session card and 30 in the Sessions table.
func TestSessionsListAndCardAgreeOnRepeatedHumanSaves(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	now := time.Now().UTC()

	// A session for the saves to attach to.
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/other.go",
		`{"file_path":"/repo/other.go","old_string":"z := 1","new_string":"z := 2"}`,
		"ev1", now.Add(-20*time.Minute))

	// Three saves of the SAME file, ten minutes apart so none of them is
	// an echo of the AI edit above.
	for i, added := range []int{10, 20, 30} {
		code, res := postEditorChange(t, s, editorBody("/repo", "a.go",
			LOCStatsRequest{AddedCode: added}, LOCStatsRequest{},
			now.Add(time.Duration(i)*time.Second)))
		if code != http.StatusOK {
			t.Fatalf("save %d: status = %d", i, code)
		}
		if res.Recorded != 1 {
			t.Fatalf("save %d: recorded = %d, want 1 (note %q)", i, res.Recorded, res.Note)
		}
		if res.Echo {
			t.Fatalf("save %d was called an echo", i)
		}
	}

	// The card.
	detail := httptest.NewRecorder()
	s.Handler().ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/api/session/s1/loc", nil))
	var card SessionLOCResponse
	if err := json.Unmarshal(detail.Body.Bytes(), &card); err != nil {
		t.Fatalf("decode card: %v (%s)", err, detail.Body.String())
	}
	if card.Human.CodeTouched != 60 {
		t.Errorf("card human code_touched = %d, want 60 (10+20+30)", card.Human.CodeTouched)
	}

	// The list.
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil))
	var payload struct {
		Rows []struct {
			ID             string `json:"id"`
			HumanCodeLines int    `json:"human_code_lines"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list: %v (%s)", err, rr.Body.String())
	}
	var found bool
	for _, row := range payload.Rows {
		if row.ID != "s1" {
			continue
		}
		found = true
		if row.HumanCodeLines != 60 {
			t.Errorf("list human_code_lines = %d, card said %d — the list MAX-collapsed the "+
				"digest-less editor rows and reported only the largest single save",
				row.HumanCodeLines, card.Human.CodeTouched)
		}
	}
	if !found {
		t.Fatalf("session s1 missing from the list: %s", rr.Body.String())
	}
}

// TestSessionsListExcludesEditorEchoRows pins that the list obeys the
// same "kept, never counted" rule as the card and the org composer.
func TestSessionsListExcludesEditorEchoRows(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	now := time.Now().UTC()

	// An AI edit, then a save of the SAME file one second later — an echo.
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/a.go",
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2\nb := 3\nc := 4"}`,
		"ev1", now.Add(-time.Second))
	code, res := postEditorChange(t, s, editorBody("/repo", "a.go",
		LOCStatsRequest{AddedCode: 2, ModifiedCode: 1}, LOCStatsRequest{}, now))
	if code != http.StatusOK || !res.Echo {
		t.Fatalf("status = %d echo = %v, want 200/true", code, res.Echo)
	}

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil))
	var payload struct {
		Rows []struct {
			ID             string `json:"id"`
			AICodeLines    int    `json:"ai_code_lines"`
			HumanCodeLines int    `json:"human_code_lines"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, row := range payload.Rows {
		if row.ID != "s1" {
			continue
		}
		if row.HumanCodeLines != 0 {
			t.Errorf("list human_code_lines = %d, want 0 — the echo was counted", row.HumanCodeLines)
		}
		if row.AICodeLines != 3 {
			t.Errorf("list ai_code_lines = %d, want 3", row.AICodeLines)
		}
	}
}

// TestPossibleAgentSaveIsNotHumanAuthorship is review finding M7's daemon
// half.
//
// The extension's on-disk-reload safeguard only fires on a CLEAN
// document, but Copilot Chat agent mode, the Cline/Kilo extensions and
// Cursor apply their edits through a WorkspaceEdit, which dirties the
// buffer exactly like typing. Those lines were booked as the developer's.
// The extension now flags such a save; the daemon books it `unknown`.
func TestPossibleAgentSaveIsNotHumanAuthorship(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	now := time.Now().UTC()
	// A session, and an AI action far enough back that the echo rule
	// cannot be what makes this pass.
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/other.go",
		`{"file_path":"/repo/other.go","old_string":"z := 1","new_string":"z := 2"}`,
		"ev1", now.Add(-10*time.Minute))

	body := editorBody("/repo", "api.ts", LOCStatsRequest{AddedCode: 120}, LOCStatsRequest{}, now)
	body.Category = "code"
	body.Language = "typescript"
	body.PossibleAgent = true
	code, res := postEditorChange(t, s, body)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if res.Recorded != 1 {
		t.Fatalf("recorded = %d, want 1 (note %q)", res.Recorded, res.Note)
	}
	if res.Echo {
		t.Error("a possible-agent save is not an echo — no AI row exists for that file")
	}

	got, err := store.New(database).LoadSessionLOC(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range got.Buckets {
		if b.Actor == store.LOCActorHuman {
			t.Errorf("an in-editor agent's 120 lines were counted as human authorship: %+v", b)
		}
		if b.Actor == store.LOCActorAI && b.Stats.AddedCode == 120 {
			t.Errorf("the flagged save was ATTRIBUTED to an agent — Observer did not see which "+
				"agent wrote it and must not invent one: %+v", b)
		}
	}
	// Unknown, not dropped: the lines happened and the row records them.
	var unknown loc.Stats
	for _, b := range got.Buckets {
		if b.Actor == store.LOCActorUnknown {
			unknown.Add(b.Stats)
		}
	}
	if unknown.AddedCode != 120 {
		t.Errorf("unknown added_code = %d, want 120 — the row must be kept, just not credited",
			unknown.AddedCode)
	}
	// It is still editor evidence, so the card can say human capture
	// exists.
	if got.HumanCapture != "vscode" {
		t.Errorf("human_capture = %q, want vscode", got.HumanCapture)
	}

	// And the DEFAULT (an older extension that omits the field) is
	// unchanged: a plain save is still human.
	plain := editorBody("/repo", "typed.ts", LOCStatsRequest{AddedCode: 4}, LOCStatsRequest{},
		now.Add(time.Second))
	plain.Language = "typescript"
	if code, _ := postEditorChange(t, s, plain); code != http.StatusOK {
		t.Fatalf("plain save status = %d", code)
	}
	got, err = store.New(database).LoadSessionLOC(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	var human loc.Stats
	for _, b := range got.Buckets {
		if b.Actor == store.LOCActorHuman {
			human.Add(b.Stats)
		}
	}
	if human.AddedCode != 4 {
		t.Errorf("human added_code = %d, want 4 — an unflagged save must stay human",
			human.AddedCode)
	}
}

// TestSessionsListAndCardAgreeOnTheDedupRepresentative is the follow-up to
// M5: the two surfaces agreed on digest-LESS rows but still used two
// different rules for digest-CARRYING ones.
//
// The card sums each collapse group's MIN(id) representative (that is what
// locDedupCTE defines). The Sessions list used to take the group's MAX
// added+modified instead. Those agree only while both rows of a codex
// invocation/executor pair classify identically — and they need not: the
// executor's unified diff carries context lines the model's `*** Begin
// Patch` envelope does not, so the pair can land with different counts. When
// the executor's action id is the LOWER of the two, the card reported the
// executor's number and the list reported the invocation's.
//
// The fixture reproduces exactly that shape: one digest group whose lower id
// carries FEWER code lines than its twin.
func TestSessionsListAndCardAgreeOnTheDedupRepresentative(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// A real session + project for the pair to hang off. This edit is one
	// modified code line, counted by both surfaces.
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/other.go",
		`{"file_path":"/repo/other.go","old_string":"z := 1","new_string":"z := 2"}`,
		"ev1", now.Add(-20*time.Minute))

	st := store.New(database)
	pid, err := st.ProjectIDForRoot(ctx, "/repo")
	if err != nil || pid == 0 {
		t.Fatalf("ProjectIDForRoot(/repo) = %d, %v", pid, err)
	}

	// One collapse group, two renderings of ONE patch. Rows insert in slice
	// order, so the 10-line row takes the lower id: the representative the
	// card keeps is the SMALLER number, which is what makes a MAX-based list
	// disagree instead of coincidentally matching.
	dup := func(actionID int64, added int) store.FileChangeRow {
		return store.FileChangeRow{
			SessionID: "s1", ProjectID: pid, ActionID: actionID,
			FilePathHash: "fpair", InputDigest: "shared-digest",
			Language: string(loc.LangGo), Category: string(loc.CategoryCode),
			Actor: store.LOCActorAI, Confidence: string(loc.ConfidenceHigh),
			Source: store.LOCSourcePatch,
			Stats:  loc.Stats{AddedCode: added},
			// The two renderings arrive from the same action pair, so they
			// share the event time the transcript stamped them with.
			Version: loc.Version, SavedAt: now.Add(-10 * time.Minute),
		}
	}
	if _, err := st.InsertFileChanges(ctx, []store.FileChangeRow{dup(9001, 10), dup(9002, 40)}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	// The card.
	detail := httptest.NewRecorder()
	s.Handler().ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/api/session/s1/loc", nil))
	var card SessionLOCResponse
	if err := json.Unmarshal(detail.Body.Bytes(), &card); err != nil {
		t.Fatalf("decode card: %v (%s)", err, detail.Body.String())
	}
	cardAI := card.AIMain.CodeTouched + card.AISidechain.CodeTouched
	if cardAI != 11 {
		t.Fatalf("card ai code_touched = %d, want 11 (1 seeded edit + the 10-line representative)", cardAI)
	}

	// The list.
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil))
	var payload struct {
		Rows []struct {
			ID          string `json:"id"`
			AICodeLines int    `json:"ai_code_lines"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list: %v (%s)", err, rr.Body.String())
	}
	var found bool
	for _, row := range payload.Rows {
		if row.ID != "s1" {
			continue
		}
		found = true
		if row.AICodeLines != cardAI {
			t.Errorf("list ai_code_lines = %d, card said %d — the list took the digest group's "+
				"MAX (41) while the card sums its MIN(id) representative (11); one collapse rule, "+
				"or the two surfaces describe the same session differently",
				row.AICodeLines, cardAI)
		}
	}
	if !found {
		t.Fatalf("session s1 missing from the list: %s", rr.Body.String())
	}
}
