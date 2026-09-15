package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestClaudeCodeHookDistinctOccurrencesArePreserved is the companion
// constraint to TestClaudeCodeHookDoubleFireIsIdempotent, and the
// regression pin for a silent data-loss bug it did not cover.
//
// THE BUG. baseToolEvent derives SourceEventID as
// "<session_id>:<event_name>" — CONSTANT for the whole session. Builders
// that never overrode it therefore produced ONE id per session, and
// actions' UNIQUE(source_file, source_event_id) (source_file is the
// constant "claude-code:hook") turned every later occurrence into an
// upsert of the first row. Measured on the live DB before the fix: all
// 515 hook-captured claude-code sessions had EXACTLY ONE user_prompt row
// each — while watcher/JSONL-captured sessions reached 406 — so every
// prompt after the first was lost. The same collapse truncated
// notification, cwd_change and stop_failure to one row per session.
//
// Downstream, the loss starved the cost predictor: LoadSessionShape
// derives its turns-per-message fan-out from user_prompt boundaries, so a
// hook-captured session could never report more than one observed
// message and always fell through to the prior/static tier.
//
// The two tests together pin the full contract:
//   - identical payload delivered twice (double-wired hooks) → 1 row
//     (TestClaudeCodeHookDoubleFireIsIdempotent)
//   - DIFFERENT payloads in one session → one row EACH (this test)
//
// Both are satisfied by a deterministic CONTENT hash. A timestamp or
// nonce would satisfy this test and break the other one.
func TestClaudeCodeHookDistinctOccurrencesArePreserved(t *testing.T) {
	cases := []struct {
		name string
		// bodies are distinct payloads from ONE session, in order.
		bodies []string
		build  claudeActionBuilder
	}{
		{
			// The reported defect: three real prompts from the live
			// session ccba252f, of which only the first was ever stored.
			name: "user_prompt_submit",
			bodies: []string{
				`{"session_id":"s1","cwd":"/repo","permission_mode":"default","prompt":"Can you list all the folders available in this project?"}`,
				`{"session_id":"s1","cwd":"/repo","permission_mode":"default","prompt":"what's in the .commandcode folder"}`,
				`{"session_id":"s1","cwd":"/repo","permission_mode":"default","prompt":"list the files here"}`,
			},
			build: buildClaudeUserPromptSubmitEvent,
		},
		{
			name: "notification",
			bodies: []string{
				`{"session_id":"s1","cwd":"/repo","notification_type":"idle_prompt","message":"waiting"}`,
				`{"session_id":"s1","cwd":"/repo","notification_type":"permission","message":"needs approval"}`,
			},
			build: buildClaudeNotificationEvent,
		},
		{
			name: "cwd_changed",
			bodies: []string{
				`{"session_id":"s1","cwd":"/repo","old_cwd":"/repo","new_cwd":"/repo/docs"}`,
				`{"session_id":"s1","cwd":"/repo","old_cwd":"/repo/docs","new_cwd":"/repo/src"}`,
			},
			build: buildClaudeCwdChangedEvent,
		},
		{
			name: "stop_failure",
			bodies: []string{
				`{"session_id":"s1","cwd":"/repo","error_type":"overloaded_error","error_message":"upstream busy"}`,
				`{"session_id":"s1","cwd":"/repo","error_type":"rate_limit_error","error_message":"slow down"}`,
			},
			build: buildClaudeStopFailureEvent,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer database.Close()
			st := store.New(database)

			seen := map[string]bool{}
			for i, body := range c.bodies {
				ev, ok := c.build([]byte(body))
				if !ok {
					t.Fatalf("body %d: builder rejected payload", i)
				}
				if seen[ev.SourceEventID] {
					t.Fatalf("body %d: SourceEventID %q collides with an earlier distinct occurrence — later events will be swallowed by UNIQUE(source_file, source_event_id)",
						i, ev.SourceEventID)
				}
				seen[ev.SourceEventID] = true
				if _, err := st.Ingest(ctx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
					t.Fatalf("body %d: ingest: %v", i, err)
				}
			}

			var n int
			if err := database.QueryRow(
				`SELECT COUNT(*) FROM actions WHERE session_id = 's1'`,
			).Scan(&n); err != nil {
				t.Fatalf("count: %v", err)
			}
			if n != len(c.bodies) {
				t.Errorf("stored %d rows for %d distinct occurrences, want %d",
					n, len(c.bodies), len(c.bodies))
			}
		})
	}
}

// TestUserPromptBoundariesFeedPredictor ties the hook fix to the symptom
// the operator actually saw: with prompts collapsing to one row, the
// predictor's fan-out ladder could only ever observe a single user
// message. Distinct ids per prompt are what let LoadSessionShape bucket
// turns across real message boundaries.
func TestUserPromptBoundariesFeedPredictor(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	st := store.New(database)

	prompts := []string{"first ask", "second ask", "third ask"}
	for _, p := range prompts {
		body := `{"session_id":"s1","cwd":"/repo","permission_mode":"default","prompt":"` + p + `"}`
		ev, ok := buildClaudeUserPromptSubmitEvent([]byte(body))
		if !ok {
			t.Fatalf("builder rejected %q", p)
		}
		if _, err := st.Ingest(ctx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
			t.Fatalf("ingest %q: %v", p, err)
		}
	}

	var boundaries int
	if err := database.QueryRow(
		`SELECT COUNT(*) FROM actions WHERE session_id='s1' AND action_type='user_prompt'`,
	).
		Scan(&boundaries); err != nil {
		t.Fatalf("count boundaries: %v", err)
	}
	if boundaries != len(prompts) {
		t.Fatalf("user_prompt boundaries = %d, want %d — the predictor's turns-per-message ladder reads exactly this count",
			boundaries, len(prompts))
	}
}
