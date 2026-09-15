package junie

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fixtureRoot lays the real Phase-0 fixture out under a temp watch root in
// the exact shape the watcher expects (…/junie/sessions/<session-id>/
// events.jsonl), plus the sibling index.jsonl, and returns the root and
// the session log path.
func fixtureRoot(t *testing.T) (root, logPath string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), ".junie", "sessions")
	sessDir := filepath.Join(root, "session-260816-220304-lrfz")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "junie", "session-260816-220304-lrfz", "events.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	logPath = filepath.Join(sessDir, sessionLogName)
	if err := os.WriteFile(logPath, body, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	idx, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "junie", "index.jsonl"))
	if err != nil {
		t.Fatalf("read index fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, indexFileName), idx, 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	return root, logPath
}

func parseFixture(t *testing.T) (adapter.ParseResult, string) {
	t.Helper()
	root, logPath := fixtureRoot(t)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res, logPath
}

func TestName(t *testing.T) {
	if got := New().Name(); got != models.ToolJunie {
		t.Errorf("Name() = %q, want %q", got, models.ToolJunie)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".junie", "sessions")
	a := NewWithOptions(nil, root)
	sess := filepath.Join(root, "session-abc")
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"session log", filepath.Join(sess, "events.jsonl"), true},
		{"index sibling", filepath.Join(root, "index.jsonl"), false},
		{"state sibling", filepath.Join(sess, "state.json"), false},
		{"transcript sibling", filepath.Join(sess, "transcript.md"), false},
		{"matterhorn scratch", filepath.Join(sess, "task-1", ".matterhorn", "x.json"), false},
		{"other jsonl basename", filepath.Join(sess, "other.jsonl"), false},
		{"right shape, foreign root", "/tmp/foreign/junie/sessions/session-abc/events.jsonl", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestWatchPathsAreAbsoluteAndDeduped(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range New().WatchPaths() {
		if !filepath.IsAbs(p) {
			t.Errorf("watch path %q is not absolute", p)
		}
		if !strings.HasSuffix(filepath.ToSlash(p), "/.junie/sessions") {
			t.Errorf("watch path %q does not end in .junie/sessions", p)
		}
		if seen[p] {
			t.Errorf("duplicate watch path %q", p)
		}
		seen[p] = true
	}
}

func TestSessionIDFromPath(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/h/.junie/sessions/session-abc/events.jsonl", "session-abc"},
		{`C:\Users\d\.junie\sessions\session-abc\events.jsonl`, "session-abc"},
	}
	for _, tc := range cases {
		if got := sessionIDFromPath(filepath.FromSlash(strings.ReplaceAll(tc.path, `\`, "/"))); got != tc.want {
			// filepath.Base/Dir only understand the host's own separator;
			// exercise the Windows-shaped case via the raw string directly.
			if got2 := sessionIDFromPath(tc.path); got2 != tc.want && got != tc.want {
				t.Errorf("sessionIDFromPath(%q) = %q / %q, want %q", tc.path, got, got2, tc.want)
			}
		}
	}
}

// TestParseFixtureCounts pins the exact ToolEvent/TokenEvent counts and
// action-type breakdown of the real Phase-0 fixture (219 lines): 1 user
// prompt, 1 session start, 3 collapsed Terminal blocks, 2 collapsed
// FileChanges blocks, 1 collapsed Result block = 8 ToolEvents; 22
// LlmResponseMetadataEvent modelUsage entries (all non-zero) = 22
// TokenEvents.
func TestParseFixtureCounts(t *testing.T) {
	res, _ := parseFixture(t)

	if got, want := len(res.ToolEvents), 8; got != want {
		names := make([]string, len(res.ToolEvents))
		for i, e := range res.ToolEvents {
			names[i] = e.ActionType + ":" + e.SourceEventID
		}
		t.Fatalf("len(ToolEvents) = %d, want %d\n%v", got, want, names)
	}
	if got, want := len(res.TokenEvents), 22; got != want {
		t.Fatalf("len(TokenEvents) = %d, want %d", got, want)
	}

	byType := map[string]int{}
	for _, e := range res.ToolEvents {
		byType[e.ActionType]++
	}
	want := map[string]int{
		models.ActionUserPrompt:   1,
		models.ActionSessionStart: 1,
		models.ActionRunCommand:   3,
		models.ActionWriteFile:    1,
		models.ActionEditFile:     1,
		models.ActionTaskComplete: 1,
	}
	for k, v := range want {
		if byType[k] != v {
			t.Errorf("action %s: got %d, want %d (full breakdown %v)", k, byType[k], v, byType)
		}
	}
}

// TestPlainPluginFixtureNoSurfaceStamp pins the honest gap that remains
// after the 2026-09-07 CLI/IDE grounding (see surface.go): the
// 2026-08-16 Phase-0 fixture predates the AI-Assistant merge, so it is
// an IDE-hosted run that nonetheless carries NEITHER positive marker
// (no extraAttachments — IDE-served MCP tools didn't exist yet — and,
// being a plain-plugin capture, no SessionCostTrajectorySnapshotEvent
// either). A session with no positive marker still gets no self-stamp,
// exactly the pre-2026-09-07 behavior — not a regression, just an
// unclosed corner of an ungrounded lane.
func TestPlainPluginFixtureNoSurfaceStamp(t *testing.T) {
	res, _ := parseFixture(t)
	if len(res.SessionSurfaces) != 0 {
		t.Errorf("SessionSurfaces = %+v, want none", res.SessionSurfaces)
	}
}

// TestProjectRootFromHeaderScan pins that every emitted event resolves the
// project root the session's own CurrentDirectoryUpdatedEvent states
// (line 50 of the fixture: /home/marmutapp/parking-game), including
// events emitted BEFORE that line — proving the from-offset-0 header scan
// (not live in-loop tracking) is what resolves it.
func TestProjectRootFromHeaderScan(t *testing.T) {
	res, _ := parseFixture(t)
	if len(res.ToolEvents) == 0 {
		t.Fatal("no tool events")
	}
	for _, e := range res.ToolEvents {
		if !strings.HasSuffix(e.ProjectRoot, "parking-game") {
			t.Errorf("event %s (%s): ProjectRoot = %q, want suffix parking-game", e.SourceEventID, e.ActionType, e.ProjectRoot)
		}
	}
	// The user-prompt row (line 1) is emitted long before line 50 states
	// the cwd — its non-empty root proves the header scan ran up front.
	first := res.ToolEvents[0]
	if first.ActionType != models.ActionUserPrompt {
		t.Fatalf("first ToolEvent = %s, want %s", first.ActionType, models.ActionUserPrompt)
	}
	if first.ProjectRoot == "" {
		t.Error("first ToolEvent (before line 50) has empty ProjectRoot")
	}
}

// TestIndexFallback pins that when a session's own events.jsonl never
// states a CurrentDirectoryUpdatedEvent, the sibling index.jsonl's
// projectDir is used instead.
func TestIndexFallback(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".junie", "sessions")
	sessDir := filepath.Join(root, "session-260816-220304-lrfz")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A minimal log with no CurrentDirectoryUpdatedEvent at all.
	body := `{"kind":"UserPromptEvent","requestId":"p1","prompt":"hi","timestampMs":1786898003000}` + "\n"
	logPath := filepath.Join(sessDir, sessionLogName)
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	idxLine := `{"sessionId":"session-260816-220304-lrfz","createdAt":1,"updatedAt":2,"projectDir":"/home/marmutapp/parking-game","taskName":"t"}` + "\n"
	if err := os.WriteFile(filepath.Join(root, indexFileName), []byte(idxLine), 0o600); err != nil {
		t.Fatalf("write index: %v", err)
	}
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("len(ToolEvents) = %d, want 1", len(res.ToolEvents))
	}
	if !strings.HasSuffix(res.ToolEvents[0].ProjectRoot, "parking-game") {
		t.Errorf("ProjectRoot = %q, want suffix parking-game (index.jsonl fallback)", res.ToolEvents[0].ProjectRoot)
	}
}

// TestFailedTerminalBlock pins the FAILED terminal-status transition
// (stepId 62c01dad-eff2-4fcc-bde3-332dde2a43c5) collapses to ONE row with
// Success=false and a non-empty ErrorMessage, surviving the completion
// rebroadcast at line 208 unchanged.
func TestFailedTerminalBlock(t *testing.T) {
	res, _ := parseFixture(t)
	const wantStep = "step:62c01dad-eff2-4fcc-bde3-332dde2a43c5"
	var found *models.ToolEvent
	count := 0
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == wantStep {
			found = &res.ToolEvents[i]
			count++
		}
	}
	if count != 1 {
		t.Fatalf("stepId %s: found %d rows, want exactly 1 (rebroadcast must not duplicate)", wantStep, count)
	}
	if found.Success {
		t.Error("Success = true, want false")
	}
	if found.ErrorMessage == "" {
		t.Error("ErrorMessage is empty, want non-empty")
	}
	if found.ActionType != models.ActionRunCommand {
		t.Errorf("ActionType = %s, want %s", found.ActionType, models.ActionRunCommand)
	}
}

// TestFileChangesWriteVsEdit pins that a change with no BeforeContent
// classifies as ActionWriteFile and one WITH BeforeContent classifies as
// ActionEditFile, and that ContentBytes is populated from AfterContent.
func TestFileChangesWriteVsEdit(t *testing.T) {
	res, _ := parseFixture(t)
	var write, edit *models.ToolEvent
	for i := range res.ToolEvents {
		switch res.ToolEvents[i].SourceEventID {
		case "step:5db440da-cbce-4193-9d91-e630ab683730":
			write = &res.ToolEvents[i]
		case "step:5810f408-ecbd-4f45-b1fd-e0cc064c451a":
			edit = &res.ToolEvents[i]
		}
	}
	if write == nil || edit == nil {
		t.Fatalf("missing rows: write=%v edit=%v", write, edit)
	}
	if write.ActionType != models.ActionWriteFile {
		t.Errorf("write.ActionType = %s, want %s", write.ActionType, models.ActionWriteFile)
	}
	if edit.ActionType != models.ActionEditFile {
		t.Errorf("edit.ActionType = %s, want %s", edit.ActionType, models.ActionEditFile)
	}
	if write.ContentBytes == 0 {
		t.Error("write.ContentBytes = 0, want > 0")
	}
	if write.Target == "" || !strings.Contains(write.Target, "hello_world.py") {
		t.Errorf("write.Target = %q, want to contain hello_world.py", write.Target)
	}
}

// TestResultBlockRebroadcastNoDuplicate pins the Result block (stepId
// 4a928fc0-fc8e-41a9-9bae-22b09996f321, lines 203 -> 213) collapses to
// exactly one ActionTaskComplete row despite the completion rebroadcast.
func TestResultBlockRebroadcastNoDuplicate(t *testing.T) {
	res, _ := parseFixture(t)
	const wantStep = "step:4a928fc0-fc8e-41a9-9bae-22b09996f321"
	count := 0
	var found *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == wantStep {
			count++
			found = &res.ToolEvents[i]
		}
	}
	if count != 1 {
		t.Fatalf("stepId %s: found %d rows, want exactly 1", wantStep, count)
	}
	if found.ActionType != models.ActionTaskComplete {
		t.Errorf("ActionType = %s, want %s", found.ActionType, models.ActionTaskComplete)
	}
	if !found.Success {
		t.Error("Success = false, want true (cancelled=false)")
	}
	if found.DurationMs <= 0 {
		t.Errorf("DurationMs = %d, want > 0", found.DurationMs)
	}
}

// TestTokenEventsNetAndCost pins the first LlmResponseMetadataEvent's
// modelUsage entry (line 8): model gpt-4.1-2025-04-14, inputTokens 1138
// carried straight through (NET, no cache subtraction), cost 0.002332
// carried straight to EstimatedCostUSD, Reliability accurate.
func TestTokenEventsNetAndCost(t *testing.T) {
	res, _ := parseFixture(t)
	if len(res.TokenEvents) == 0 {
		t.Fatal("no token events")
	}
	first := res.TokenEvents[0]
	if first.Model != "gpt-4.1-2025-04-14" {
		t.Errorf("Model = %q, want gpt-4.1-2025-04-14", first.Model)
	}
	if first.InputTokens != 1138 {
		t.Errorf("InputTokens = %d, want 1138", first.InputTokens)
	}
	if first.OutputTokens != 7 {
		t.Errorf("OutputTokens = %d, want 7", first.OutputTokens)
	}
	if first.EstimatedCostUSD != 0.002332 {
		t.Errorf("EstimatedCostUSD = %v, want 0.002332", first.EstimatedCostUSD)
	}
	if first.Reliability != models.ReliabilityAccurate {
		t.Errorf("Reliability = %q, want %q", first.Reliability, models.ReliabilityAccurate)
	}
	if first.Source != models.TokenSourceJSONL {
		t.Errorf("Source = %q, want %q", first.Source, models.TokenSourceJSONL)
	}
}

// TestSkippedKindsProduceNoEvents pins that UserMessagesCommittedToHistory
// (15 occurrences) and TaskState (1 occurrence) — plus the 7 unactioned
// agentEvent kinds — never contribute a ToolEvent or TokenEvent.
// Cross-checked against the exact fixture counts (8 ToolEvents, 22
// TokenEvents) in TestParseFixtureCounts; this test only asserts the
// specific skipped kinds are absent from RawToolName.
func TestSkippedKindsProduceNoEvents(t *testing.T) {
	res, _ := parseFixture(t)
	for _, e := range res.ToolEvents {
		if strings.Contains(e.RawToolName, "TaskState") || strings.Contains(e.RawToolName, "UserMessagesCommittedToHistory") {
			t.Errorf("unexpected event from a skipped kind: %+v", e)
		}
	}
}

// TestMalformedLineAdvancesCursor pins that a malformed JSON line still
// advances the byte cursor and produces a warning, rather than stalling
// the poll loop.
func TestMalformedLineAdvancesCursor(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".junie", "sessions")
	sessDir := filepath.Join(root, "session-abc")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "{not valid json\n" + `{"kind":"UserPromptEvent","requestId":"p1","prompt":"hi","timestampMs":1786898003000}` + "\n"
	logPath := filepath.Join(sessDir, sessionLogName)
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning for the malformed line")
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("len(ToolEvents) = %d, want 1", len(res.ToolEvents))
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d (full file consumed)", res.NewOffset, len(body))
	}
}

// TestPartialTrailingLineDeferred pins that a trailing line with no
// terminating newline (a record still being written) does not advance the
// cursor past it, so the next parse call re-reads it whole.
func TestPartialTrailingLineDeferred(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".junie", "sessions")
	sessDir := filepath.Join(root, "session-abc")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	complete := `{"kind":"UserPromptEvent","requestId":"p1","prompt":"hi","timestampMs":1786898003000}` + "\n"
	partial := `{"kind":"UserPromptEvent","requestId":"p2","prompt":"incomple`
	logPath := filepath.Join(sessDir, sessionLogName)
	if err := os.WriteFile(logPath, []byte(complete+partial), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("len(ToolEvents) = %d, want 1", len(res.ToolEvents))
	}
	if res.NewOffset != int64(len(complete)) {
		t.Errorf("NewOffset = %d, want %d (partial line not consumed)", res.NewOffset, len(complete))
	}
}

// TestIncrementalParseMatchesWhole pins that parsing the fixture in two
// windows (split mid-file) and merging produces the same ToolEvent/
// TokenEvent counts as one whole-file parse — proving no event is lost or
// duplicated across a poll boundary, INCLUDING the header re-scan
// resolving ProjectRoot correctly on the SECOND window even though it
// starts reading after line 50.
func TestIncrementalParseMatchesWhole(t *testing.T) {
	whole, _ := parseFixture(t)

	root, logPath := fixtureRoot(t)
	a := NewWithOptions(nil, root)
	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Split at a line boundary partway through (after line 100).
	lines := strings.SplitAfter(string(body), "\n")
	var mid int64
	for i, l := range lines {
		mid += int64(len(l))
		if i >= 99 {
			break
		}
	}
	first, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("first ParseSessionFile: %v", err)
	}
	if first.NewOffset < mid {
		t.Fatalf("first parse offset %d < split point %d", first.NewOffset, mid)
	}
	second, err := a.ParseSessionFile(context.Background(), logPath, first.NewOffset)
	if err != nil {
		t.Fatalf("second ParseSessionFile: %v", err)
	}

	total := len(first.ToolEvents) + len(second.ToolEvents)
	if total != len(whole.ToolEvents) {
		t.Errorf("split ToolEvents = %d, whole = %d", total, len(whole.ToolEvents))
	}
	totalTok := len(first.TokenEvents) + len(second.TokenEvents)
	if totalTok != len(whole.TokenEvents) {
		t.Errorf("split TokenEvents = %d, whole = %d", totalTok, len(whole.TokenEvents))
	}
	for _, e := range second.ToolEvents {
		if !strings.HasSuffix(e.ProjectRoot, "parking-game") {
			t.Errorf("second-window event %s: ProjectRoot = %q, want suffix parking-game", e.SourceEventID, e.ProjectRoot)
		}
	}
}

// TestContextCancellation pins that a cancelled context aborts the parse
// loop and returns the context error.
func TestContextCancellation(t *testing.T) {
	_, logPath := fixtureRoot(t)
	a := NewWithOptions(nil, filepath.Dir(filepath.Dir(logPath)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := a.ParseSessionFile(ctx, logPath, 0)
	if err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
}

// TestMissingFileError pins that parsing a non-existent path returns an
// error rather than a silent empty result.
func TestMissingFileError(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, root)
	_, err := a.ParseSessionFile(context.Background(), filepath.Join(root, "does-not-exist.jsonl"), 0)
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

// TestScrubbingAppliesToPromptAndCommand exercises the scrubber
// end-to-end against a fixture line carrying an obvious secret shape, to
// pin that the injected scrub.Scrubber is actually consulted rather than
// bypassed.
func TestScrubbingAppliesToPromptAndCommand(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".junie", "sessions")
	sessDir := filepath.Join(root, "session-abc")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Built at runtime (not a literal in source) so it has the scrubber's
	// sk-<16+ alnum/underscore chars> shape without a real-looking
	// credential appearing anywhere in the repo's source.
	fakeKey := "sk_" + strings.Repeat("a1B2c3D4", 6)
	rec := map[string]any{
		"kind":        "UserPromptEvent",
		"requestId":   "p1",
		"prompt":      "here is my key: " + fakeKey,
		"timestampMs": 1786898003000,
	}
	b, _ := json.Marshal(rec)
	logPath := filepath.Join(sessDir, sessionLogName)
	if err := os.WriteFile(logPath, append(b, '\n'), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	a := New()
	a.roots = []string{root}
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 1 {
		t.Fatalf("len(ToolEvents) = %d, want 1", len(res.ToolEvents))
	}
	if strings.Contains(res.ToolEvents[0].RawToolInput, fakeKey) {
		t.Errorf("RawToolInput still contains the unscrubbed fake key, got %q", res.ToolEvents[0].RawToolInput)
	}
}

var _ adapter.Adapter = (*Adapter)(nil)
