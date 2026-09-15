package kirocli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// This file pins the flat-bundle parser against the FIRST live
// interactive capture of a rich session (2026-09-03, via the Kiro Crew
// step-in — the fixture lives under testdata/kirocrew/kiro-cli/ because
// that capture is one half of the kiro-crew double-count pair).
//
// It exists because that capture exposed a silent data-loss bug: every
// content block's `data` was typed `string`, but only `kind:"text"`
// carries a string — `thinking`, `toolUse` and `toolResult` carry
// OBJECTS. json.Unmarshal therefore failed for the WHOLE LINE on every
// assistant turn, so a real session captured its first pure-text Prompt
// and nothing else, warning "malformed stream line" 19 times. The
// pre-existing fixtures (testdata/kirocli/flat-*.jsonl) are text-only and
// could not catch it.

const (
	liveSessionID = "sess0001-0000-4000-8000-000000000001"
	liveFixture   = "kirocrew"
)

// stageLiveBundle copies the anonymized live bundle into a
// `.kiro/sessions/cli/` tree so classifyLayout recognises it, and returns
// the watch root plus the `.jsonl` trigger path.
func stageLiveBundle(t *testing.T) (root, trigger string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), ".kiro", "sessions")
	dir := filepath.Join(root, "cli")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".json", ".jsonl"} {
		src := filepath.Join("..", "..", "..", "testdata", liveFixture, "kiro-cli", liveSessionID+ext)
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read fixture %s: %v", src, err)
		}
		if err := os.WriteFile(filepath.Join(dir, liveSessionID+ext), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, filepath.Join(dir, liveSessionID+".jsonl")
}

// TestParseFlatBundle_LiveRichSession is the regression pin for the
// polymorphic-block bug: a real session must decode every line.
func TestParseFlatBundle_LiveRichSession(t *testing.T) {
	root, trigger := stageLiveBundle(t)
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), trigger, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none — every line of a real session must decode", res.Warnings)
	}

	byType := map[string]int{}
	for _, e := range res.ToolEvents {
		byType[e.ActionType]++
	}
	want := map[string]int{
		models.ActionUserPrompt:       1,
		models.ActionAssistantMessage: 10,
		models.ActionReadFile:         1,
		models.ActionWriteFile:        1,
		models.ActionEditFile:         1,
		models.ActionRunCommand:       6,
	}
	for k, n := range want {
		if byType[k] != n {
			t.Errorf("action %s = %d, want %d", k, byType[k], n)
		}
	}
	if len(res.ToolEvents) != 20 {
		t.Errorf("ToolEvents = %d, want 20", len(res.ToolEvents))
	}
}

// TestParseFlatBundle_ToolResultsCorrelate pins that each toolUse row gets
// its paired ToolResults verdict in the SAME window (the bundle is re-read
// whole every tick, so correlation never has to cross a parse boundary).
func TestParseFlatBundle_ToolResultsCorrelate(t *testing.T) {
	root, trigger := stageLiveBundle(t)
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), trigger, 0)
	if err != nil {
		t.Fatal(err)
	}
	var tools, pending, withOutput, failed int
	for _, e := range res.ToolEvents {
		if e.RawToolName == "" {
			continue
		}
		tools++
		if e.OutcomePending {
			pending++
		}
		if e.ToolOutput != "" {
			withOutput++
		}
		if !e.Success {
			failed++
			if e.ErrorMessage == "" {
				t.Errorf("tool %s failed with no error message", e.SourceEventID)
			}
		}
	}
	if tools != 9 {
		t.Fatalf("tool rows = %d, want 9", tools)
	}
	if pending != 0 {
		t.Errorf("%d tool rows still OutcomePending; every call has a paired result in this fixture", pending)
	}
	// 8 of 9 print something; `del hello.py` succeeds silently.
	if withOutput != 8 {
		t.Errorf("%d tool rows carry output, want 8", withOutput)
	}
	// EXACTLY TWO failures, and this is the load-bearing assertion: both
	// came back with toolResult status="success" and exit_status="exit
	// code: 1" — `del hello.py && dir /b` (the PowerShell host rejects
	// `&&`) and the follow-up bare `dir /b`. Reading `status` alone would
	// file both as successful commands.
	if failed != 2 {
		t.Errorf("failed tool rows = %d, want exactly 2 (the non-zero shell exits)", failed)
	}
}

// TestParseFlatBundle_CrewDrivenSurface pins the agentSurfaces override:
// a bundle whose session_state.agent_name is "kirocrew" is a DESKTOP
// surface (AWS Kiro Crew drove it), not the layout's default cli/kiro-cli.
func TestParseFlatBundle_CrewDrivenSurface(t *testing.T) {
	root, trigger := stageLiveBundle(t)
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), trigger, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces = %d, want 1", len(res.SessionSurfaces))
	}
	s := res.SessionSurfaces[0]
	if s.Surface != models.SurfaceDesktop || s.SurfaceHost != "kiro-crew" {
		t.Errorf("surface = %s/%s, want desktop/kiro-crew", s.Surface, s.SurfaceHost)
	}
	if s.SessionID != liveSessionID {
		t.Errorf("surface session = %q, want %q", s.SessionID, liveSessionID)
	}
}

// TestSurfaceForAgent is the table-level pin: an unlisted agent name falls
// through to the layout answer, and the prefix-shaped Crew agent names
// that were NEVER observed on a session are deliberately NOT claimed.
func TestSurfaceForAgent(t *testing.T) {
	cases := []struct {
		agent    string
		wantKind string
		wantHost string
	}{
		{"kirocrew", models.SurfaceDesktop, "kiro-crew"},
		{"kiro_default", models.SurfaceCLI, "kiro-cli"},
		{"", models.SurfaceCLI, "kiro-cli"},
		// Named in ~/.kiro/crew/agent_model_state.json but never observed
		// on a session — claiming them would be a guess.
		{"kirocrew-lite", models.SurfaceCLI, "kiro-cli"},
		{"kirocrew-heartbeat", models.SurfaceCLI, "kiro-cli"},
	}
	for _, tc := range cases {
		got := surfaceForAgent(layoutFlat, "s1", tc.agent)
		if got.Surface != tc.wantKind || got.SurfaceHost != tc.wantHost {
			t.Errorf("surfaceForAgent(%q) = %s/%s, want %s/%s",
				tc.agent, got.Surface, got.SurfaceHost, tc.wantKind, tc.wantHost)
		}
	}
	// A blank session id must never produce a stamp.
	if got := surfaceForAgent(layoutFlat, "", "kirocrew"); got.SessionID != "" || got.Surface != "" {
		t.Errorf("surfaceForAgent with no session id = %+v, want the zero value", got)
	}
}
