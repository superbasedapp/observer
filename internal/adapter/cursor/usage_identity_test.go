package cursor

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// TestEvidenceRowsMatchTallyIdentity pins the writer to the reader: the
// rows this adapter emits must be counted by cursorusage.Tally from
// action_type + source_event_id alone (the only identity the org also
// receives), with raw_tool_name never consulted.
func TestEvidenceRowsMatchTallyIdentity(t *testing.T) {
	var rows []cursorusage.Row
	add := func(actionType, sourceEventID, detail string) {
		rows = append(rows, cursorusage.Row{ActionType: actionType, SourceEventID: sourceEventID, ErrorMessage: detail})
	}
	prompt, ok, err := BuildEvent(EventBeforeSubmitPrompt, []byte(`{"hook_event_name":"beforeSubmitPrompt","conversation_id":"conv-1","generation_id":"gen-1","workspace_roots":["/w"],"prompt":"hi"}`), scrub.New())
	if err != nil || !ok {
		t.Fatalf("prompt: %v %v", ok, err)
	}
	add(prompt.ActionType, prompt.SourceEventID, "")
	resp, ok, err := BuildEvent(EventAfterAgentResponse, []byte(`{"hook_event_name":"afterAgentResponse","conversation_id":"conv-1","generation_id":"gen-1","workspace_roots":["/w"],"text":"done"}`), scrub.New())
	if err != nil || !ok {
		t.Fatalf("response: %v %v", ok, err)
	}
	add(resp.ActionType, resp.SourceEventID, "")

	a, path := copyCLILog(t, readCLIFixture(t, fixtureCLIInteractive))
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range res.ToolEvents {
		add(ev.ActionType, ev.SourceEventID, ev.ErrorMessage)
	}
	got := cursorusage.Tally(rows)
	if got.Prompts != 1 || got.ResponseHooks != 1 || got.UnfinishedTurns != 1 || got.FailedTurns != 0 || got.FailedAttempts != 3 || got.LatestTurnDetail == "" {
		t.Fatalf("Tally over adapter rows = %+v", got)
	}
}
