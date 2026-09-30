package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestLOCPayloadsCarryTheCodeCommentSplit pins the code-vs-comment split
// on the three node LOC payloads (operator ask 2026-09-28): the session
// card (ai_split + ai_sidechain_split), the window summary (ai_split) and
// the Sessions-list row (ai_split, omitempty). Each split's code_lines
// must equal the headline number the same surface already shows, and its
// comment_lines must equal the AI added-comment bucket - the server owns
// the arithmetic, so the web renders the split without computing it.
func TestLOCPayloadsCarryTheCodeCommentSplit(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	ingestLOCEdit(t, database, "s1", "/repo", "/repo/a.go",
		`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2\n// explain b\n// and c\nb := 3\n\nc := 4"}`,
		"ev1", time.Now().UTC().Add(-time.Minute))

	get := func(path string) []byte {
		t.Helper()
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, body %s", path, rr.Code, rr.Body.String())
		}
		return rr.Body.Bytes()
	}

	// Session card.
	cardRaw := get("/api/session/s1/loc")
	for _, key := range []string{`"ai_split"`, `"ai_sidechain_split"`} {
		if !bytes.Contains(cardRaw, []byte(key)) {
			t.Errorf("session payload lacks %s: %s", key, cardRaw)
		}
	}
	var card SessionLOCResponse
	if err := json.Unmarshal(cardRaw, &card); err != nil {
		t.Fatal(err)
	}
	if card.AIMain.AddedComment < 1 {
		t.Fatalf("fixture produced no comment lines (ai_main %+v); the test needs one", card.AIMain)
	}
	if got, want := card.AISplit.CodeLines, int64(card.AIMain.CodeTouched); got != want {
		t.Errorf("ai_split.code_lines = %d, want ai_main.code_touched %d", got, want)
	}
	if got, want := card.AISplit.CommentLines, int64(card.AIMain.AddedComment); got != want {
		t.Errorf("ai_split.comment_lines = %d, want ai_main.added_comment %d", got, want)
	}
	if card.AISplit.CommentShare == nil {
		t.Error("ai_split.comment_share absent although comment lines exist")
	}
	// No sidechain work: an empty split, with the share ABSENT (not 0).
	if card.AISidechainSplit.CodeLines != 0 || card.AISidechainSplit.CommentLines != 0 ||
		card.AISidechainSplit.CommentShare != nil {
		t.Errorf("ai_sidechain_split = %+v, want empty with no share", card.AISidechainSplit)
	}

	// Window summary.
	var sum LOCSummaryResponse
	if err := json.Unmarshal(get("/api/loc/summary?days=7"), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.AISplit.CodeLines != int64(sum.AICodeTouched) {
		t.Errorf("summary ai_split.code_lines = %d, want ai_code_touched %d",
			sum.AISplit.CodeLines, sum.AICodeTouched)
	}
	if sum.AISplit.CommentLines != card.AISplit.CommentLines {
		t.Errorf("summary ai_split.comment_lines = %d, want %d (the one session's comments)",
			sum.AISplit.CommentLines, card.AISplit.CommentLines)
	}

	// Sessions list row.
	listRaw := get("/api/sessions?limit=10")
	var payload struct {
		Rows []struct {
			ID          string         `json:"id"`
			AICodeLines int            `json:"ai_code_lines"`
			AISplit     *authoredSplit `json:"ai_split"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(listRaw, &payload); err != nil {
		t.Fatalf("decode: %v (%s)", err, listRaw)
	}
	var found bool
	for _, row := range payload.Rows {
		if row.ID != "s1" {
			continue
		}
		found = true
		if row.AISplit == nil {
			t.Fatalf("list row lacks ai_split: %s", listRaw)
		}
		if row.AISplit.CodeLines != int64(row.AICodeLines) {
			t.Errorf("list ai_split.code_lines = %d, want ai_code_lines %d",
				row.AISplit.CodeLines, row.AICodeLines)
		}
		if row.AISplit.CommentLines != card.AISplit.CommentLines {
			t.Errorf("list ai_split.comment_lines = %d, card said %d",
				row.AISplit.CommentLines, card.AISplit.CommentLines)
		}
	}
	if !found {
		t.Fatalf("session s1 missing from the list: %s", listRaw)
	}
}

// TestSessionsListOmitsSplitWhenNeverCounted pins the omitempty contract
// of the list row's ai_split: an uncounted session carries no split key,
// so a corpus that never ran the LOC backfill keeps its byte-identical
// payload.
func TestSessionsListOmitsSplitWhenNeverCounted(t *testing.T) {
	t.Parallel()
	s, database := newLOCServer(t)
	// An action type LOC never counts, so the session lists with no
	// file_changes row behind it.
	if _, err := store.New(database).Ingest(context.Background(), []models.ToolEvent{{
		SessionID: "s1", ProjectRoot: "/repo", Target: "ls",
		ActionType: models.ActionRunCommand, RawToolInput: "ls",
		Tool: models.ToolClaudeCode, SourceFile: "/tmp/s.jsonl",
		SourceEventID: "ev1", Timestamp: time.Now().UTC(), Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions?limit=10", nil))
	if !strings.Contains(rr.Body.String(), `"s1"`) {
		t.Fatalf("session s1 missing from the list: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "ai_split") {
		t.Errorf("ai_split present on an uncounted corpus: %s", rr.Body.String())
	}
}
