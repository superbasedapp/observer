package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestRawToolOutputCappedAtEveryWriter pins the store-side backstop for the
// 1 MiB actions.raw_tool_output contract (post-Agent-Access backlog item 9):
// an adapter that forgets contentcap must still not land a multi-megabyte
// build log or diff dump verbatim. One row per writer of the column.
func TestRawToolOutputCappedAtEveryWriter(t *testing.T) {
	t.Parallel()
	huge := strings.Repeat("x", 3*contentcap.DefaultMaxBytes)
	want := contentcap.Cap(huge, contentcap.DefaultMaxBytes)

	cases := []struct {
		name  string
		write func(ctx context.Context, s *Store, a models.Action) error
	}{
		{"InsertActions", func(ctx context.Context, s *Store, a models.Action) error {
			_, err := s.InsertActions(ctx, []models.Action{a})
			return err
		}},
		{"InsertActions upsert of an existing row", func(ctx context.Context, s *Store, a models.Action) error {
			small := a
			small.RawToolOutput = "short"
			if _, err := s.InsertActions(ctx, []models.Action{small}); err != nil {
				return err
			}
			_, err := s.InsertActions(ctx, []models.Action{a})
			return err
		}},
		{"insertSingleAction", func(ctx context.Context, s *Store, a models.Action) error {
			_, err := s.insertSingleAction(ctx, &a)
			return err
		}},
		{"UpdateActionOutcome", func(ctx context.Context, s *Store, a models.Action) error {
			body := a.RawToolOutput
			a.RawToolOutput = ""
			if _, err := s.InsertActions(ctx, []models.Action{a}); err != nil {
				return err
			}
			_, err := s.UpdateActionOutcome(ctx, a.SourceFile, a.SourceEventID, true, "", 10, body, "", "")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newTestStore(t)
			ctx := context.Background()
			pid, err := s.UpsertProject(ctx, "/tmp/p_toolcap", "")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertSession(ctx, models.Session{
				ID: "s_toolcap", ProjectID: pid, Tool: models.ToolOpenCode, StartedAt: time.Now().UTC(),
			}); err != nil {
				t.Fatal(err)
			}
			a := models.Action{
				SessionID: "s_toolcap", ProjectID: pid, Timestamp: time.Now().UTC(),
				ActionType: models.ActionRunCommand, Target: "npm run build", Success: true,
				Tool: models.ToolOpenCode, SourceFile: "opencode.db", SourceEventID: "part:big",
				RawToolOutput: huge,
			}
			if err := tc.write(ctx, s, a); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := s.db.QueryRowContext(ctx,
				`SELECT raw_tool_output FROM actions WHERE source_event_id = 'part:big'`).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("raw_tool_output = %d bytes, want the %d-byte capped body", len(got), len(want))
			}
		})
	}
}

// TestCapToolOutputIdempotent: re-capping an already-capped body must not
// grow or change it, so a row re-ingested through a second writer is stable.
func TestCapToolOutputIdempotent(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 10, contentcap.DefaultMaxBytes, contentcap.DefaultMaxBytes + 1, 2 * contentcap.DefaultMaxBytes} {
		once := capToolOutput(strings.Repeat("y", n))
		if twice := capToolOutput(once); twice != once {
			t.Errorf("n=%d: second cap changed the body (%d -> %d bytes)", n, len(once), len(twice))
		}
	}
}
