package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// readUserAttachments reads the actions.user_attachments column for a given
// (source_file, source_event_id) exactly as the messages read path does
// (COALESCE to ” → decode the JSON array). Returns (attachments, columnWasNull).
func readUserAttachments(t *testing.T, db *sql.DB, sourceFile, eventID string) ([]models.UserAttachment, bool) {
	t.Helper()
	var raw sql.NullString
	err := db.QueryRowContext(context.Background(),
		`SELECT user_attachments FROM actions WHERE source_file = ? AND source_event_id = ?`,
		sourceFile, eventID,
	).Scan(&raw)
	if err != nil {
		t.Fatalf("read user_attachments: %v", err)
	}
	if !raw.Valid || raw.String == "" {
		return nil, !raw.Valid
	}
	var atts []models.UserAttachment
	if err := json.Unmarshal([]byte(raw.String), &atts); err != nil {
		t.Fatalf("decode user_attachments %q: %v", raw.String, err)
	}
	return atts, false
}

func seedActionSession(t *testing.T, s *Store, sessionID string) int64 {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/att-"+sessionID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: sessionID, ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return pid
}

// TestUserAttachmentsRoundTrip pins Issue 1 (migration 126) at the store
// seam: an Action's UserAttachments persist to the actions.user_attachments
// JSON column and read back equal; an Action with none stores NULL and reads
// back empty.
func TestUserAttachmentsRoundTrip(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	pid := seedActionSession(t, s, "s-att")

	atts := []models.UserAttachment{
		{Kind: "image", MediaType: "image/png"},
		{Kind: "file", MediaType: "application/pdf"},
		{Kind: "image"}, // no media type
	}
	batch := []models.Action{
		{
			SessionID: "s-att", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionUserPrompt, Target: "look", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "att.jsonl", SourceEventID: "with",
			UserAttachments: atts,
		},
		{
			SessionID: "s-att", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionUserPrompt, Target: "plain", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "att.jsonl", SourceEventID: "without",
		},
	}
	if _, err := s.InsertActions(ctx, batch); err != nil {
		t.Fatal(err)
	}

	got, wasNull := readUserAttachments(t, db, "att.jsonl", "with")
	if wasNull {
		t.Fatal("attachments row stored NULL; want the JSON array")
	}
	if !reflect.DeepEqual(got, atts) {
		t.Errorf("round-trip = %+v; want %+v", got, atts)
	}

	none, wasNull := readUserAttachments(t, db, "att.jsonl", "without")
	if !wasNull {
		t.Errorf("no-attachments row: column = %+v; want NULL", none)
	}
	if len(none) != 0 {
		t.Errorf("no-attachments row read back %+v; want empty", none)
	}
}

// TestUserAttachmentsOnConflictFillWhenNull pins the ON CONFLICT rule: a
// re-emit fills the column only when it is currently NULL, and never
// regresses a captured value back to NULL.
func TestUserAttachmentsOnConflictFillWhenNull(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	pid := seedActionSession(t, s, "s-conf")

	withImg := []models.UserAttachment{{Kind: "image", MediaType: "image/png"}}
	base := func(eventID string, a []models.UserAttachment) models.Action {
		return models.Action{
			SessionID: "s-conf", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionUserPrompt, Target: "t", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "conf.jsonl", SourceEventID: eventID,
			UserAttachments: a,
		}
	}

	// (a) captured value must NOT regress: insert WITH attachments, re-emit
	// the same key WITHOUT → the captured value survives.
	if _, err := s.InsertActions(ctx, []models.Action{base("keep", withImg)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertActions(ctx, []models.Action{base("keep", nil)}); err != nil {
		t.Fatal(err)
	}
	got, _ := readUserAttachments(t, db, "conf.jsonl", "keep")
	if !reflect.DeepEqual(got, withImg) {
		t.Errorf("regression: after re-emit with none, attachments = %+v; want the original %+v", got, withImg)
	}

	// (b) NULL gets filled: insert with NONE, re-emit the same key WITH → the
	// column is filled.
	if _, err := s.InsertActions(ctx, []models.Action{base("fill", nil)}); err != nil {
		t.Fatal(err)
	}
	if pre, wasNull := readUserAttachments(t, db, "conf.jsonl", "fill"); !wasNull || len(pre) != 0 {
		t.Fatalf("precondition: first insert should be NULL, got %+v (null=%v)", pre, wasNull)
	}
	if _, err := s.InsertActions(ctx, []models.Action{base("fill", withImg)}); err != nil {
		t.Fatal(err)
	}
	filled, _ := readUserAttachments(t, db, "conf.jsonl", "fill")
	if !reflect.DeepEqual(filled, withImg) {
		t.Errorf("fill-when-null: after re-emit with attachments, got %+v; want %+v", filled, withImg)
	}
}
