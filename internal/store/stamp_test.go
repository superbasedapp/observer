package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/identity"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestIngestStampsOrgWhenEnrolled proves the WithStamper wiring persists
// org_id/user_email across all four insert paths when the agent is
// enrolled. The solo-local invariant suite proves the no-op case (NULL);
// this proves the bound columns are correct so a wrong bind can't hide
// behind always-NULL solo-local data.
func TestIngestStampsOrgWhenEnrolled(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "stamp.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO org_enrolment (id, org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id)
		 VALUES (1, 'org-x', 'X', 'https://x', 'u1', 'dev@x', '2026-05-25T00:00:00Z', 'kc')`); err != nil {
		t.Fatalf("seed enrolment: %v", err)
	}
	stmp, err := identity.NewStamper(ctx, database)
	if err != nil {
		t.Fatalf("NewStamper: %v", err)
	}
	if !stmp.IsEnrolled() {
		t.Fatal("stamper not enrolled after seeding org_enrolment")
	}

	st := New(database).WithStamper(stmp)
	ts := time.Now().UTC()
	if _, err := st.Ingest(ctx,
		[]models.ToolEvent{{
			SourceFile: "f", SourceEventID: "e1", SessionID: "s1", ProjectRoot: "/inv/p",
			Timestamp: ts, Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		}},
		[]models.TokenEvent{{
			SourceFile: "f", SourceEventID: "tok1", SessionID: "s1", ProjectRoot: "/inv/p",
			Timestamp: ts, Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
			InputTokens: 10, OutputTokens: 5, Source: "jsonl", Reliability: "unreliable",
		}},
		IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if _, err := st.InsertAPITurn(ctx, models.APITurn{
		SessionID: "s1", ProjectID: 1, Timestamp: ts, Provider: "anthropic",
		Model: "claude-opus-4-7", RequestID: "req1", InputTokens: 10, OutputTokens: 5,
	}); err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}

	// Every stamped table must carry the enrolled identity.
	checks := []struct {
		table, where string
	}{
		{"sessions", "id = 's1'"},
		{"actions", "source_event_id = 'e1'"},
		{"token_usage", "source_event_id = 'tok1'"},
		{"api_turns", "request_id = 'req1'"},
	}
	for _, c := range checks {
		var org, email string
		err := database.QueryRowContext(ctx,
			"SELECT org_id, user_email FROM "+c.table+" WHERE "+c.where).Scan(&org, &email)
		if err != nil {
			t.Fatalf("%s: scan org cols: %v", c.table, err)
		}
		if org != "org-x" || email != "dev@x" {
			t.Errorf("%s stamped (%q, %q), want (org-x, dev@x)", c.table, org, email)
		}
	}
}
