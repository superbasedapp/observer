package stakpak

import (
	"context"
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestRealStore parses a REAL ~/.stakpak/data/local.db and logs the counts.
// It is skipped unless STAKPAK_REAL_DB points at a copy of the store, so CI
// and other developers' machines never touch a live store.
func TestRealStore(t *testing.T) {
	path := os.Getenv("STAKPAK_REAL_DB")
	if path == "" {
		t.Skip("set STAKPAK_REAL_DB to a copy of a stakpak local.db to run")
	}
	a := NewWithOptions(nil, []string{"."})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	sessions := map[string]bool{}
	actions := map[string]int{}
	for _, ev := range res.ToolEvents {
		sessions[ev.SessionID] = true
		actions[ev.ActionType]++
	}
	modelSet := map[string]bool{}
	var in, out int64
	for _, tk := range res.TokenEvents {
		sessions[tk.SessionID] = true
		modelSet[tk.Model] = true
		in += tk.InputTokens
		out += tk.OutputTokens
	}
	branches := map[string]bool{}
	var withMsgID int
	for _, ev := range res.ToolEvents {
		branches[ev.GitBranch] = true
		if ev.MessageID != "" {
			withMsgID++
		}
	}
	for id := range sessions {
		msgs, terr := a.ReadTranscript(context.Background(), models.Session{ID: id}, []string{path})
		t.Logf("transcript %s: %d messages, err=%v", id, len(msgs), terr)
	}
	t.Logf("tool_versions=%v git_branches=%v rows_with_message_id=%d/%d", res.SessionToolVersions, branches, withMsgID, len(res.ToolEvents))
	t.Logf("sessions=%d tool_events=%d (by action %v) token_rows=%d input=%d output=%d distinct_models=%v outcome_updates=%d warnings=%v watermark=%d",
		len(sessions), len(res.ToolEvents), actions, len(res.TokenEvents), in, out, modelSet, len(res.OutcomeUpdates), res.Warnings, res.NewOffset)
}
