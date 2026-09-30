package cursor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	fixtureCLIInteractive = "../../../testdata/cursor/cli-logs/session-2026-09-27T11-12-48-669Z-141379-1.log"
	fixtureCLIHeadless    = "../../../testdata/cursor/cli-logs/session-2026-09-21T19-53-18-627Z-55322-1.log"
	fixtureInteractiveSID = "c0c0c001-0000-4000-8000-000000000001"
	fixtureInteractiveGen = "c0c0c002-0000-4000-8000-000000000002"
)

// copyCLILog places a fixture under a cursor-agent-logs-* dir so the
// adapter's shape matcher claims it, and returns the adapter + path.
func copyCLILog(t *testing.T, body []byte) (*Adapter, string) {
	t.Helper()
	logs := filepath.Join(t.TempDir(), "cursor-agent-logs-test")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(logs, "session-2026-09-27T11-12-48-669Z-141379-1.log")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return NewWithOptions(nil, logs), path
}

func readCLIFixture(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCLITurnEvidence_NodeOneUnfinishedTurn replays the real node-1 shape:
// an interactive one-message ("hi") session on the Auto model whose only turn
// hit LostConnection three times and was quit mid-retry. Nothing reported
// usage, so the parse must emit NO token row, one api_error per failed
// attempt and one turn_unfinished row naming exactly what fired.
func TestCLITurnEvidence_NodeOneUnfinishedTurn(t *testing.T) {
	a, path := copyCLILog(t, readCLIFixture(t, fixtureCLIInteractive))
	if !a.IsSessionFile(path) {
		t.Fatal("fixture not claimed as a CLI log")
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TokenEvents) != 0 {
		t.Fatalf("an unfinished turn must never yield usage, got %+v", res.TokenEvents)
	}
	var attempts, turns []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.SessionID != fixtureInteractiveSID || ev.Tool != models.ToolCursor || ev.Success {
			t.Fatalf("bad evidence row: %+v", ev)
		}
		switch ev.ActionType {
		case models.ActionAPIError:
			attempts = append(attempts, ev)
		case models.ActionTurnAborted:
			turns = append(turns, ev)
		default:
			t.Fatalf("unexpected row: %+v", ev)
		}
	}
	if len(attempts) != 3 {
		t.Fatalf("attempt rows = %d, want 3", len(attempts))
	}
	for _, ev := range attempts {
		if ev.RawToolName != "LostConnection" || !strings.HasPrefix(ev.SourceEventID, cursorusage.SourceEventAttemptPrefix) {
			t.Fatalf("attempt row: %+v", ev)
		}
	}
	if len(turns) != 1 {
		t.Fatalf("turn rows = %d, want 1", len(turns))
	}
	turn := turns[0]
	if turn.RawToolName != cursorusage.RawToolTurnUnfinished || turn.MessageID != fixtureInteractiveGen {
		t.Fatalf("turn row identity: %+v", turn)
	}
	for _, want := range []string{
		"3 failed request attempts (LostConnection x3)",
		"session ended while Cursor was still retrying",
		"the stop and afterAgentResponse hooks",
		"hooks that fired: beforeSubmitPrompt, afterAgentThought x6, sessionEnd",
		"did not fire: stop, afterAgentResponse",
	} {
		if !strings.Contains(turn.ErrorMessage, want) {
			t.Errorf("detail missing %q:\n%s", want, turn.ErrorMessage)
		}
	}
	if strings.Contains(turn.ErrorMessage, "claude") {
		t.Errorf("Claude Code hooks cursor-agent also ran must not count as Cursor hooks: %s", turn.ErrorMessage)
	}
	if runtime.GOOS != "windows" && turn.ProjectRoot != "/home/dev/aa-cc-test" {
		t.Errorf("project root = %q, want the logged workspace", turn.ProjectRoot)
	}
}

// TestCLITurnEvidence_Incremental pins that the fold waits for a terminal
// record and that a later full re-read reproduces identical row identities.
func TestCLITurnEvidence_Incremental(t *testing.T) {
	body := readCLIFixture(t, fixtureCLIInteractive)
	cut := strings.Index(string(body), "cli.slash_command.used")
	cut = strings.LastIndex(string(body[:cut]), "\n") + 1
	a, path := copyCLILog(t, body[:cut])
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil || len(first.ToolEvents) != 0 {
		t.Fatalf("a turn still retrying must emit nothing yet: %+v %v", first.ToolEvents, err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil || len(second.ToolEvents) != 4 {
		t.Fatalf("closing records must emit the evidence: %d %v", len(second.ToolEvents), err)
	}
	full, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, ev := range second.ToolEvents {
		ids[ev.SourceEventID] = true
	}
	for _, ev := range full.ToolEvents {
		if !ids[ev.SourceEventID] {
			t.Fatalf("re-read produced a new identity %q (would duplicate rows)", ev.SourceEventID)
		}
	}
}

// TestCLITurnEvidence_HeadlessSuccess: the headless fixture's finished turn
// yields its usage from the outcome record and no evidence rows.
func TestCLITurnEvidence_HeadlessSuccess(t *testing.T) {
	a, path := copyCLILog(t, readCLIFixture(t, fixtureCLIHeadless))
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 1 {
		t.Fatalf("headless success: tools=%d tokens=%d", len(res.ToolEvents), len(res.TokenEvents))
	}
	tk := res.TokenEvents[0]
	if tk.InputTokens != 18031 || tk.OutputTokens != 569 || tk.CacheReadTokens != 23296 || tk.Reliability != models.ReliabilityAccurate {
		t.Fatalf("headless usage: %+v", tk)
	}
}

// TestCLITurnRows is the per-shape table for the turn classifier.
func TestCLITurnRows(t *testing.T) {
	const (
		conv = "e0e0e001-0000-4000-8000-000000000001"
		gen  = "e0e0e002-0000-4000-8000-000000000002"
		trk  = "e0e0e003-0000-4000-8000-000000000003"
		trk2 = "e0e0e004-0000-4000-8000-000000000004"
	)
	init := `[2026-09-27T11:13:12.334Z] conversationClassification.init {"conversationId":"` + conv + `","workspacePath":"/w"}` + "\n"
	create := `[2026-09-27T11:13:23.859Z] analytics.track {"eventName":"cli.request.create","props":{"invocationID":"` + gen + `","conversationId":"` + conv + `"}}` + "\n"
	start := func(id, surface string) string {
		return `[2026-09-27T11:13:23.860Z] structured-log.info {"key":"agent_cli","message":"agent_cli.turn.start","metadata":{"request_id":"` + id + `","surface":"` + surface + `"}}` + "\n"
	}
	outcome := func(id, extra string) string {
		return `[2026-09-27T11:13:30.000Z] structured-log.info {"key":"agent_cli","message":"agent_cli.turn.outcome","metadata":{"request_id":"` + id + `"` + extra + `}}` + "\n"
	}
	hook := func(step string) string {
		return `[2026-09-27T11:13:31.000Z] analytics.track {"eventName":"cli.hook.executed","props":{"hookStep":"` + step + `","hookSource":"user"}}` + "\n"
	}
	dispose := `[2026-09-27T11:13:44.957Z] conversationClassification.dispose {"conversationId":"` + conv + `"}` + "\n"
	headlessTokens := `,"conversation_id":"` + conv + `","surface":"headless","retries_attempted":"2","input_tokens":"29","output_tokens":"5","cache_read_tokens":"16352","cache_write_tokens":"0"`

	for _, tc := range []struct {
		name       string
		log        string
		wantRaw    []string
		wantTokens int
		wantDetail string
	}{
		{"interactive_success_finishes_silently", init + create + start(trk, "interactive") + hook("afterAgentResponse") + hook("stop") + outcome(trk, `,"surface":"interactive","outcome":"success"`) + dispose, nil, 0, ""},
		{"interactive_error_outcome", init + create + start(trk, "interactive") + outcome(trk, `,"surface":"interactive","outcome":"error","error_type":"retriable","error_code":"unavailable"`) + dispose, []string{"cursor_cli.turn_error"}, 0, "outcome error (error_type retriable, error_code unavailable)"},
		{"headless_error_with_final_usage", start(trk, "headless") + outcome(trk, `,"outcome":"error"`+headlessTokens) + hook("sessionEnd"), []string{"cursor_cli.turn_error"}, 1, "final attempt only"},
		{"superseded_turn", init + create + start(trk, "interactive") + start(trk2, "interactive") + outcome(trk2, `,"surface":"interactive","outcome":"success"`) + dispose, []string{cursorusage.RawToolTurnUnfinished}, 0, "a new turn started before it finished"},
		{"killed_before_outcome", init + create + start(trk, "interactive") + dispose, []string{cursorusage.RawToolTurnUnfinished}, 0, "session ended before the turn finished"},
		{"still_running_emits_nothing", init + create + start(trk, "interactive") + hook("afterAgentThought"), nil, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, path := copyCLILog(t, []byte(tc.log))
			res, err := a.ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatal(err)
			}
			var raws []string
			for _, ev := range res.ToolEvents {
				raws = append(raws, ev.RawToolName)
				if ev.SessionID != conv {
					t.Errorf("session = %q", ev.SessionID)
				}
				if tc.wantDetail != "" && !strings.Contains(ev.ErrorMessage, tc.wantDetail) {
					t.Errorf("detail %q missing %q", ev.ErrorMessage, tc.wantDetail)
				}
			}
			if strings.Join(raws, ",") != strings.Join(tc.wantRaw, ",") {
				t.Fatalf("rows = %v, want %v", raws, tc.wantRaw)
			}
			if len(res.TokenEvents) != tc.wantTokens {
				t.Fatalf("token rows = %d, want %d", len(res.TokenEvents), tc.wantTokens)
			}
		})
	}
}
