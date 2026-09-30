package cursorusage

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// One case per rowKinds row, in table order, plus rows no kind claims.
func TestTallyRowKinds(t *testing.T) {
	unfinished := TurnSourceEventID("t1", RawToolTurnUnfinished)
	failed := TurnSourceEventID("t2", RawToolTurnFailedPrefix+"error")
	for _, tc := range []struct {
		name string
		row  Row
		want Evidence
	}{
		{"prompt", Row{ActionType: models.ActionUserPrompt, SourceEventID: "g1:beforeSubmitPrompt"}, Evidence{Prompts: 1}},
		{"response_hook", Row{ActionType: models.ActionAssistantMessage, SourceEventID: "g1:afterAgentResponse"}, Evidence{ResponseHooks: 1}},
		{"unfinished_turn", Row{ActionType: models.ActionTurnAborted, SourceEventID: unfinished, ErrorMessage: "d1"}, Evidence{UnfinishedTurns: 1, LatestTurnDetail: "d1"}},
		{"failed_turn", Row{ActionType: models.ActionTurnAborted, SourceEventID: failed, ErrorMessage: "d2"}, Evidence{FailedTurns: 1, LatestTurnDetail: "d2"}},
		{"failed_attempt", Row{ActionType: models.ActionAPIError, SourceEventID: SourceEventAttemptPrefix + "r1"}, Evidence{FailedAttempts: 1}},
		// Rows no kind claims: a transcript assistant row, a turn_aborted
		// from another source, an api_error that is not a CLI attempt.
		{"transcript_assistant", Row{ActionType: models.ActionAssistantMessage, SourceEventID: "c1:assistant:3"}, Evidence{}},
		{"foreign_turn_aborted", Row{ActionType: models.ActionTurnAborted, SourceEventID: "x:unfinished"}, Evidence{}},
		{"foreign_api_error", Row{ActionType: models.ActionAPIError, SourceEventID: "req-1"}, Evidence{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Tally([]Row{tc.row}); got != tc.want {
				t.Fatalf("Tally = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The latest turn row's detail wins, and hash-only rows (no
// error_message) keep the counts but drop the detail.
func TestTallyLatestDetailAndHashOnly(t *testing.T) {
	rows := []Row{
		{ActionType: models.ActionUserPrompt, SourceEventID: "g1:beforeSubmitPrompt"},
		{ActionType: models.ActionTurnAborted, SourceEventID: TurnSourceEventID("t1", RawToolTurnFailedPrefix+"error"), ErrorMessage: "older"},
		{ActionType: models.ActionTurnAborted, SourceEventID: TurnSourceEventID("t2", RawToolTurnUnfinished), ErrorMessage: "newer"},
	}
	got := Tally(rows)
	if got.LatestTurnDetail != "newer" || got.UnfinishedTurns != 1 || got.FailedTurns != 1 || got.Prompts != 1 {
		t.Fatalf("Tally = %+v", got)
	}
	for i := range rows {
		rows[i].ErrorMessage = ""
	}
	hashOnly := Tally(rows)
	if Classify(hashOnly) != Classify(got) {
		t.Fatalf("hash-only rows changed the reason: %s vs %s", Classify(hashOnly), Classify(got))
	}
	if hashOnly != got.WithoutDetail() {
		t.Fatalf("hash-only = %+v, want %+v", hashOnly, got.WithoutDetail())
	}
	if n := Explain(hashOnly, 0); strings.Contains(n, "newer") || !strings.Contains(n, "never finished") {
		t.Fatalf("hash-only note = %s", n)
	}
}

func TestTurnSourceEventIDSuffix(t *testing.T) {
	if id := TurnSourceEventID("abc", RawToolTurnUnfinished); !strings.HasSuffix(id, SourceEventUnfinishedSuffix) || !strings.HasPrefix(id, SourceEventTurnPrefix) {
		t.Fatalf("unfinished id %q", id)
	}
	if id := TurnSourceEventID("abc", RawToolTurnFailedPrefix+"error"); id != SourceEventTurnPrefix+"abc:error" {
		t.Fatalf("failed id %q", id)
	}
}
