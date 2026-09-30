package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestTokensUnbilledNote(t *testing.T) {
	for _, tc := range []struct {
		name, tool string
		budget     int64
		ev         *cursorusage.Evidence
		want       []string
	}{
		{"non_cursor_unchanged", "codex", 0, nil, []string{"Token usage was not captured for this session."}},
		{"cursor_evidence_unavailable", "cursor", 0, nil, []string{"no prompt or turn record says why"}},
		{
			"cursor_node1_unfinished", "cursor", 12363, &cursorusage.Evidence{Prompts: 1, UnfinishedTurns: 1, LatestTurnDetail: "The session ended while Cursor was still retrying."},
			[]string{"1 turn never finished", "still retrying", "not billed usage"},
		},
		{
			"cursor_prompt_hooks_wired", "cursor", 0, &cursorusage.Evidence{Prompts: 1, FinishHooks: cursorusage.HookWiringComplete},
			[]string{"Both hooks are registered", "most likely never finished"},
		},
		{
			"cursor_prompt_hooks_missing", "cursor", 0, &cursorusage.Evidence{Prompts: 1, FinishHooks: cursorusage.HookWiringIncomplete},
			[]string{"not both registered", "observer init --cursor"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tokensUnbilledNote(tc.tool, tc.budget, tc.ev)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("note %q missing %q", got, w)
				}
			}
		})
	}
}

// TestAPISessionDetail_CursorNoteFollowsHookWiring pins live finding D4
// (2026-09-28) through the handler: a Cursor session with a prompt but no
// finish hook and no usage tells the user to run `observer init --cursor`
// ONLY when the finish hooks are not registered; with them registered it
// names the likely cause instead.
func TestAPISessionDetail_CursorNoteFollowsHookWiring(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if _, err := store.New(database).Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "g1:beforeSubmitPrompt", SessionID: "sHW",
		ProjectRoot: t.TempDir(), Timestamp: time.Now().UTC().Add(-time.Hour), Tool: models.ToolCursor,
		ActionType: models.ActionUserPrompt, Target: "hello", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	orig := cursorFinishHooksWiring
	t.Cleanup(func() { cursorFinishHooksWiring = orig })
	note := func(w cursorusage.HookWiring) string {
		t.Helper()
		cursorFinishHooksWiring = func() cursorusage.HookWiring { return w }
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/sHW", nil))
		if rr.Code != 200 {
			t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
		}
		var got struct {
			TokensNote string `json:"tokens_note"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got.TokensNote
	}
	wired := note(cursorusage.HookWiringComplete)
	if !strings.Contains(wired, "Both hooks are registered") || strings.Contains(wired, "observer init --cursor") {
		t.Errorf("hooks wired: note must name the likely cause and not advise init:\n%s", wired)
	}
	missing := note(cursorusage.HookWiringIncomplete)
	if !strings.Contains(missing, "run `observer init --cursor`") {
		t.Errorf("hooks missing: note must advise init:\n%s", missing)
	}
}
