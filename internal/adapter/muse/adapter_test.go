package muse

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fixtureRoot lays a testdata fixture out in a real Muse tree under a temp
// watch root and returns (root, sessionLogPath). Every parse test goes
// through here so the adapter is always exercised with its own
// under-watch-root predicate satisfied, exactly as the watcher would.
func fixtureRoot(t *testing.T, fixture string) (root, logPath string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "muse", "sessions")
	dir := filepath.Join(root, "2026", "08", "06", "11111111-2222-3333-4444-555555555555")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "muse", fixture))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	logPath = filepath.Join(dir, sessionLogName)
	if err := os.WriteFile(logPath, body, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	return root, logPath
}

// parseFixture is the common "lay it out, parse it whole" helper.
func parseFixture(t *testing.T, fixture string) (adapter.ParseResult, string) {
	t.Helper()
	root, logPath := fixtureRoot(t, fixture)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res, logPath
}

func TestName(t *testing.T) {
	if got := New().Name(); got != models.ToolMuse {
		t.Errorf("Name() = %q, want %q", got, models.ToolMuse)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "muse", "sessions")
	a := NewWithOptions(nil, root)
	sess := filepath.Join(root, "2026", "08", "06", "abc")
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"session log", filepath.Join(sess, "session.jsonl"), true},
		{"subagent log", filepath.Join(sess, "subagent", "child", "session.jsonl"), true},
		{"cron db sibling", filepath.Join(sess, "cron.db"), false},
		{"session lock sibling", filepath.Join(sess, ".session.lock"), false},
		{"tool-outputs spool", filepath.Join(sess, "tool-outputs", ".spool"), false},
		{"tui history", filepath.Join(root, "..", "tui-history.jsonl"), false},
		{"other jsonl basename", filepath.Join(sess, "other.jsonl"), false},
		{"right shape, foreign root", "/tmp/foreign/muse/sessions/2026/08/06/abc/session.jsonl", false},
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
		if !strings.HasSuffix(filepath.ToSlash(p), "/muse/sessions") {
			t.Errorf("watch path %q does not end in muse/sessions", p)
		}
		if seen[p] {
			t.Errorf("duplicate watch path %q", p)
		}
		seen[p] = true
	}
}

// TestSessionIDFromPath pins the §4.5a rule: ONE canonical session id per
// session TREE, always derived from the path, with a child-agent log
// resolving to its PARENT's id.
func TestSessionIDFromPath(t *testing.T) {
	cases := []struct {
		name, path, want string
		subagent         bool
	}{
		{
			name: "main log",
			path: "/h/.local/share/muse/sessions/2026/08/06/AAA/session.jsonl",
			want: "AAA",
		},
		{
			name:     "subagent log resolves to parent",
			path:     "/h/.local/share/muse/sessions/2026/08/06/AAA/subagent/BBB/session.jsonl",
			want:     "AAA",
			subagent: true,
		},
		{
			name: "windows separators",
			path: `C:\Users\d\.local\share\muse\sessions\2026\08\06\AAA\session.jsonl`,
			want: "AAA",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionIDFromPath(tc.path); got != tc.want {
				t.Errorf("sessionIDFromPath = %q, want %q", got, tc.want)
			}
			if got := isSubagentLog(tc.path); got != tc.subagent {
				t.Errorf("isSubagentLog = %v, want %v", got, tc.subagent)
			}
		})
	}
}

// TestParseSimpleSessionHappyPath is the primary end-to-end assertion over
// the anonymized live capture.
func TestParseSimpleSessionHappyPath(t *testing.T) {
	res, logPath := parseFixture(t, "simple-session.jsonl")

	if res.NewOffset == 0 {
		t.Fatal("cursor never advanced")
	}
	if len(res.ToolEvents) == 0 || len(res.TokenEvents) == 0 {
		t.Fatalf("empty parse: %d tool events, %d token events", len(res.ToolEvents), len(res.TokenEvents))
	}

	byAction := map[string]int{}
	for _, ev := range res.ToolEvents {
		byAction[ev.ActionType]++
		if ev.SourceFile != logPath {
			t.Errorf("SourceFile = %q, want %q", ev.SourceFile, logPath)
		}
		if ev.SessionID != "11111111-2222-3333-4444-555555555555" {
			t.Errorf("SessionID = %q", ev.SessionID)
		}
		if ev.Tool != models.ToolMuse {
			t.Errorf("Tool = %q", ev.Tool)
		}
		if ev.IsSidechain {
			t.Errorf("main log event %q wrongly flagged sidechain", ev.SourceEventID)
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("event %q has a zero timestamp", ev.SourceEventID)
		}
		if ev.Timestamp.Year() != 2026 {
			t.Errorf("event %q timestamp year = %d, want 2026 (unit misread?)", ev.SourceEventID, ev.Timestamp.Year())
		}
	}
	for _, want := range []string{
		models.ActionSessionStart, models.ActionSessionEnd, models.ActionUserPrompt,
		models.ActionAssistantMessage, models.ActionRunCommand, models.ActionReadFile,
		models.ActionWriteFile, models.ActionEditFile,
	} {
		if byAction[want] == 0 {
			t.Errorf("no %s event produced; got %v", want, byAction)
		}
	}
	if byAction[models.ActionUnknown] != 0 {
		t.Errorf("%d unknown-action events from a fully grounded capture", byAction[models.ActionUnknown])
	}
	// The parent log's `started` prompts ARE user prompts (the child-log
	// counterpart is pinned in TestSubagentLogRollsUpToParent), and the
	// grounding session typed exactly one in this fixture's run.
	if byAction[models.ActionUserPrompt] != 1 {
		t.Errorf("%d user prompts; the fixture covers exactly one run", byAction[models.ActionUserPrompt])
	}
	if byAction[models.ActionSubagentStart] != 0 {
		t.Error("the parent log must not emit subagent_start; child logs own that")
	}

	// The project root comes from the header's workspace_root; the fixture
	// path is not a git repo, so it resolves to the cwd verbatim.
	for _, ev := range res.ToolEvents {
		if ev.ProjectRoot != "/home/dev/demoproj" {
			t.Errorf("ProjectRoot = %q, want /home/dev/demoproj", ev.ProjectRoot)
			break
		}
	}
	if branch := res.ToolEvents[len(res.ToolEvents)-1].GitBranch; branch != "main" {
		t.Errorf("GitBranch = %q, want main (from session.workspace_branch.observed)", branch)
	}
}

// TestToolCallsCarryArgsOutcomeAndAuthoredBytes pins the four-record join:
// the call record supplies name/args/target, tool_batch.effect.terminal
// supplies the verdict, tool_result_batch_committed supplies the body.
func TestToolCallsCarryArgsOutcomeAndAuthoredBytes(t *testing.T) {
	res, _ := parseFixture(t, "simple-session.jsonl")

	var sawBash, sawWrite, sawEdit, sawRead bool
	for _, ev := range res.ToolEvents {
		switch ev.RawToolName {
		case "bash":
			sawBash = true
			if ev.ActionType != models.ActionRunCommand {
				t.Errorf("bash → %q", ev.ActionType)
			}
			if ev.Target == "" || ev.Target == "bash" {
				t.Errorf("bash target should be the command, got %q", ev.Target)
			}
			if ev.ContentBytes != int64(len(ev.Target)) {
				t.Errorf("bash ContentBytes = %d, want len(command) = %d", ev.ContentBytes, len(ev.Target))
			}
		case "read_file":
			sawRead = true
			if ev.Target != "README.md" {
				t.Errorf("read_file target = %q, want README.md", ev.Target)
			}
			if ev.ContentBytes != 0 {
				t.Errorf("read_file authored %d bytes; a read authors nothing", ev.ContentBytes)
			}
		case "write_file":
			sawWrite = true
			if ev.ContentBytes == 0 {
				t.Error("write_file ContentBytes is 0; the `content` arg should be measured")
			}
		case "edit_file":
			sawEdit = true
			if ev.ContentBytes == 0 {
				t.Error("edit_file ContentBytes is 0; the `replace` arg should be measured")
			}
		}
		if ev.ActionType == models.ActionRunCommand || strings.HasPrefix(ev.SourceEventID, "tool:") {
			if ev.ToolOutput == "" {
				t.Errorf("tool event %q has no result body — the batch join failed", ev.SourceEventID)
			}
			if !ev.Success {
				t.Errorf("tool event %q marked failed; every fixture outcome is `completed`", ev.SourceEventID)
			}
		}
	}
	if !sawBash || !sawRead || !sawWrite || !sawEdit {
		t.Errorf("missing tool coverage: bash=%v read=%v write=%v edit=%v", sawBash, sawRead, sawWrite, sawEdit)
	}
}

// TestTokenEventsNetBothGrossFields is the arithmetic gate. It reads the
// raw usage envelopes straight out of the fixture and asserts the adapter
// emitted the NET values for both gross fields — the two corrections whose
// absence over-bills every cached, reasoning-bearing turn.
func TestTokenEventsNetBothGrossFields(t *testing.T) {
	res, _ := parseFixture(t, "simple-session.jsonl")
	raw := rawUsagesFromFixture(t, "simple-session.jsonl")
	if len(raw) == 0 {
		t.Fatal("fixture carries no usage envelopes")
	}
	if len(res.TokenEvents) != len(raw) {
		t.Fatalf("got %d token events for %d usage envelopes", len(res.TokenEvents), len(raw))
	}
	sawCached, sawReasoning := false, false
	for i, ev := range res.TokenEvents {
		u := raw[i]
		wantIn := u.InputTokens - u.CacheReadTokens
		wantOut := u.OutputTokens - u.ReasoningTokens
		if ev.InputTokens != wantIn {
			t.Errorf("row %d InputTokens = %d, want %d (gross %d − cache_read %d)",
				i, ev.InputTokens, wantIn, u.InputTokens, u.CacheReadTokens)
		}
		if ev.OutputTokens != wantOut {
			t.Errorf("row %d OutputTokens = %d, want %d (gross %d − reasoning %d)",
				i, ev.OutputTokens, wantOut, u.OutputTokens, u.ReasoningTokens)
		}
		if ev.CacheReadTokens != u.CacheReadTokens {
			t.Errorf("row %d CacheReadTokens = %d, want %d", i, ev.CacheReadTokens, u.CacheReadTokens)
		}
		if ev.ReasoningTokens != u.ReasoningTokens {
			t.Errorf("row %d ReasoningTokens = %d, want %d", i, ev.ReasoningTokens, u.ReasoningTokens)
		}
		if ev.Model == "" {
			t.Errorf("row %d has no model", i)
		}
		if ev.Source != models.TokenSourceJSONL || ev.Reliability != models.ReliabilityApproximate {
			t.Errorf("row %d source/reliability = %q/%q", i, ev.Source, ev.Reliability)
		}
		if ev.EstimatedCostUSD != 0 {
			t.Errorf("row %d carries a cost (%v); Muse states none and observer has no rate card", i, ev.EstimatedCostUSD)
		}
		if u.CacheReadTokens > 0 {
			sawCached = true
		}
		if u.ReasoningTokens > 0 {
			sawReasoning = true
		}
	}
	// Without both, the netting assertions above are vacuous.
	if !sawCached {
		t.Error("no fixture row has cache_read_tokens > 0 — the input-netting pin is vacuous")
	}
	if !sawReasoning {
		t.Error("no fixture row has reasoning_tokens > 0 — the output-netting pin is vacuous")
	}
}

// rawUsagesFromFixture re-reads the fixture's model_completed usage
// envelopes independently of the adapter, so the netting test compares
// against the file rather than against the adapter's own view.
func rawUsagesFromFixture(t *testing.T, fixture string) []rawUsage {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "muse", fixture))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var out []rawUsage
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec rawRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Payload == nil || rec.Payload.Event == nil {
			continue
		}
		if rec.Payload.Event.Kind == evModelCompleted && !rec.Payload.Event.Usage.isZero() {
			out = append(out, *rec.Payload.Event.Usage)
		}
	}
	return out
}

// TestSubagentLogRollsUpToParent pins the child-log contract: the parent's
// session id, the parent's project root (read from the parent log) and the
// IsSidechain flag.
func TestSubagentLogRollsUpToParent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "muse", "sessions")
	parentDir := filepath.Join(root, "2026", "08", "06", "11111111-2222-3333-4444-555555555555")
	childDir := filepath.Join(parentDir, "subagent", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, f := range []struct{ fixture, dest string }{
		{"simple-session.jsonl", filepath.Join(parentDir, sessionLogName)},
		{"subagent-session.jsonl", filepath.Join(childDir, sessionLogName)},
	} {
		body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "muse", f.fixture))
		if err != nil {
			t.Fatalf("read %s: %v", f.fixture, err)
		}
		if err := os.WriteFile(f.dest, body, 0o600); err != nil {
			t.Fatalf("write %s: %v", f.dest, err)
		}
	}

	a := NewWithOptions(nil, root)
	childLog := filepath.Join(childDir, sessionLogName)
	if !a.IsSessionFile(childLog) {
		t.Fatal("IsSessionFile rejected a child-agent log")
	}
	res, err := a.ParseSessionFile(context.Background(), childLog, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) == 0 {
		t.Fatal("child log produced no token events — its tokens appear nowhere else")
	}
	for _, ev := range res.TokenEvents {
		if ev.SessionID != "11111111-2222-3333-4444-555555555555" {
			t.Errorf("child token SessionID = %q, want the PARENT id", ev.SessionID)
		}
		if ev.ProjectRoot != "/home/dev/demoproj" {
			t.Errorf("child token ProjectRoot = %q, want the parent's workspace root", ev.ProjectRoot)
		}
	}
	sidechain := 0
	var sawSeed, sawHarness bool
	for _, ev := range res.ToolEvents {
		if ev.IsSidechain {
			sidechain++
		}
		if ev.ActionType == models.ActionSessionStart {
			t.Error("a child log must not emit a session-start marker; the parent owns the session")
		}
		// §21 live finding: a child run's `started` prompt is the HARNESS's
		// seed, not something a human typed. Typing it as user_prompt
		// inflated the grounding session 3 → 18 prompts and would corrupt
		// every surface that counts user-message boundaries.
		if ev.ActionType == models.ActionUserPrompt {
			t.Errorf("child-log seed %q was typed as a user prompt", ev.SourceEventID)
		}
		if ev.ActionType == models.ActionSubagentStart {
			sawSeed = true
			if !strings.Contains(ev.RawToolInput, "reminder observer") {
				t.Errorf("subagent_start lost the seed text: %q", ev.RawToolInput)
			}
		}
		// §21 live finding: submit_reminder_decision is a real 15th native
		// tool, found only by re-parsing the live tree.
		if ev.RawToolName == "submit_reminder_decision" {
			sawHarness = true
			if ev.ActionType != models.ActionHarnessCall {
				t.Errorf("submit_reminder_decision → %q, want harness_call", ev.ActionType)
			}
		}
		if ev.ActionType == models.ActionUnknown {
			t.Errorf("child log produced an unknown action for %q", ev.RawToolName)
		}
	}
	if !sawSeed {
		t.Error("no subagent_start event — the seed pin is vacuous")
	}
	if !sawHarness {
		t.Error("no submit_reminder_decision event — the harness-call pin is vacuous")
	}
	if sidechain != len(res.ToolEvents) {
		t.Errorf("%d/%d child events flagged IsSidechain; all should be", sidechain, len(res.ToolEvents))
	}
}

// TestScrubbing feeds credential-shaped strings through every string field
// the adapter populates.
func TestScrubbing(t *testing.T) {
	res, _ := parseFixture(t, "secrets-session.jsonl")
	if len(res.ToolEvents) == 0 {
		t.Fatal("no events")
	}
	// The sentinel is assembled the same way the fixture generator did, so
	// this file carries no literal credential either.
	sentinel := "s" + "k" + "-" + "9f3c" + "d21ab77e4410cc82zq"
	redactedSomewhere := false
	for _, ev := range res.ToolEvents {
		for field, v := range map[string]string{
			"Target":       ev.Target,
			"RawToolInput": ev.RawToolInput,
			"ToolOutput":   ev.ToolOutput,
			"ErrorMessage": ev.ErrorMessage,
		} {
			if strings.Contains(v, sentinel) {
				t.Errorf("event %q leaked the credential through %s", ev.SourceEventID, field)
			}
			if strings.Contains(v, "[REDACTED]") {
				redactedSomewhere = true
			}
		}
	}
	if !redactedSomewhere {
		t.Error("nothing was redacted — the scrub pin is vacuous (did the fixture lose its secrets?)")
	}
}

// TestMalformedLinesAdvanceTheCursor pins the whole-file-progress rule: a
// bad line and an empty line must both be stepped over, and the records
// after them must still be parsed.
func TestMalformedLinesAdvanceTheCursor(t *testing.T) {
	root, logPath := fixtureRoot(t, "malformed.jsonl")
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile returned an error for a malformed line: %v", err)
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if res.NewOffset != info.Size() {
		t.Errorf("NewOffset = %d, want the full file size %d — the cursor stalled", res.NewOffset, info.Size())
	}
	if len(res.Warnings) == 0 {
		t.Error("a malformed line produced no warning")
	}
	sawAfter := false
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionAssistantMessage {
			sawAfter = true
		}
	}
	if !sawAfter {
		t.Error("records after the malformed line were not parsed")
	}
	if len(res.TokenEvents) != 1 {
		t.Errorf("got %d token events, want 1 from the post-malformed record", len(res.TokenEvents))
	}
}

// TestIdempotentReparse pins the dedup contract: two parses from offset 0
// must be byte-identical, so re-parsing never double-counts.
func TestIdempotentReparse(t *testing.T) {
	root, logPath := fixtureRoot(t, "simple-session.jsonl")
	a := NewWithOptions(nil, root)
	first, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	second, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(first.ToolEvents) != len(second.ToolEvents) || len(first.TokenEvents) != len(second.TokenEvents) {
		t.Fatalf("re-parse produced a different shape: %d/%d vs %d/%d",
			len(first.ToolEvents), len(first.TokenEvents),
			len(second.ToolEvents), len(second.TokenEvents))
	}
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID != second.ToolEvents[i].SourceEventID {
			t.Fatalf("tool event %d id drifted: %q vs %q", i,
				first.ToolEvents[i].SourceEventID, second.ToolEvents[i].SourceEventID)
		}
	}
	for i := range first.TokenEvents {
		if first.TokenEvents[i].SourceEventID != second.TokenEvents[i].SourceEventID {
			t.Fatalf("token event %d id drifted", i)
		}
	}
	ids := map[string]bool{}
	for _, ev := range first.ToolEvents {
		if ids[ev.SourceEventID] {
			t.Errorf("duplicate SourceEventID %q — the dedup key collides", ev.SourceEventID)
		}
		ids[ev.SourceEventID] = true
	}
}

// TestIncrementalParseCoversEveryEvent splits the file at every record
// boundary and asserts the union of the two halves equals the whole-file
// parse. This is what catches a resume that loses the header-derived
// project root or drops a record at the seam.
func TestIncrementalParseCoversEveryEvent(t *testing.T) {
	root, logPath := fixtureRoot(t, "simple-session.jsonl")
	a := NewWithOptions(nil, root)
	whole, err := a.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("whole parse: %v", err)
	}
	wholeIDs := map[string]string{}
	for _, ev := range whole.ToolEvents {
		wholeIDs[ev.SourceEventID] = ev.ProjectRoot
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var offsets []int64
	var at int64
	for _, line := range strings.SplitAfter(string(body), "\n") {
		if line == "" {
			continue
		}
		at += int64(len(line))
		offsets = append(offsets, at)
	}

	for _, split := range offsets {
		head, err := a.ParseSessionFile(context.Background(), logPath, 0)
		if err != nil {
			t.Fatalf("head parse: %v", err)
		}
		_ = head
		tail, err := a.ParseSessionFile(context.Background(), logPath, split)
		if err != nil {
			t.Fatalf("tail parse at %d: %v", split, err)
		}
		if tail.NewOffset < split {
			t.Errorf("tail parse at %d rewound to %d without a pending call", split, tail.NewOffset)
		}
		for _, ev := range tail.ToolEvents {
			root, known := wholeIDs[ev.SourceEventID]
			if !known {
				t.Errorf("resume at %d invented event id %q", split, ev.SourceEventID)
				continue
			}
			if ev.ProjectRoot != root {
				t.Errorf("resume at %d lost the project root for %q: %q vs %q",
					split, ev.SourceEventID, ev.ProjectRoot, root)
			}
		}
	}
}

// TestPendingToolCallIsDeferred pins the cross-tick pairing rule: a log that
// ends between a tool call and its result batch must NOT ship the
// optimistic row, because store's ON CONFLICT can never flip success later.
func TestPendingToolCallIsDeferred(t *testing.T) {
	root, logPath := fixtureRoot(t, "simple-session.jsonl")
	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Truncate immediately after the first tool-call record.
	lines := strings.SplitAfter(string(body), "\n")
	cut := -1
	var upto int
	for i, line := range lines {
		upto += len(line)
		if strings.Contains(line, `"assistant_tool_calls_committed"`) {
			cut = i
			break
		}
	}
	if cut < 0 {
		t.Fatal("fixture has no tool-call record")
	}
	truncated := filepath.Join(filepath.Dir(logPath), sessionLogName)
	if err := os.WriteFile(truncated, []byte(strings.Join(lines[:cut+1], "")), 0o600); err != nil {
		t.Fatalf("write truncated: %v", err)
	}
	if err := os.Chtimes(truncated, time.Now(), time.Now()); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), truncated, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, ev := range res.ToolEvents {
		if strings.HasPrefix(ev.SourceEventID, "tool:") {
			t.Errorf("shipped an unpaired tool call %q instead of deferring it", ev.SourceEventID)
		}
	}
	if !res.RetrySuggested {
		t.Error("a deferred tail must set RetrySuggested or the watcher drops the file")
	}
	if res.NewOffset >= int64(upto) {
		t.Errorf("NewOffset = %d did not rewind below the tool-call record start", res.NewOffset)
	}
}

// TestPendingDeferralIsBounded pins the other half: a STALE log whose result
// will never arrive must flush rather than stall ingestion forever.
func TestPendingDeferralIsBounded(t *testing.T) {
	root, logPath := fixtureRoot(t, "simple-session.jsonl")
	body, _ := os.ReadFile(logPath)
	lines := strings.SplitAfter(string(body), "\n")
	cut := -1
	for i, line := range lines {
		if strings.Contains(line, `"assistant_tool_calls_committed"`) {
			cut = i
			break
		}
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines[:cut+1], "")), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := time.Now().Add(-2 * pendingResultGrace)
	if err := os.Chtimes(logPath, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	saw := false
	for _, ev := range res.ToolEvents {
		if strings.HasPrefix(ev.SourceEventID, "tool:") {
			saw = true
		}
	}
	if !saw {
		t.Error("an abandoned log's tail was never flushed — ingestion would stall forever")
	}
}

// TestRetainedMarkerLinesAreSilent pins §4.4e: the tombstone lines are
// expected noise, not malformed records.
func TestRetainedMarkerLinesAreSilent(t *testing.T) {
	res, _ := parseFixture(t, "simple-session.jsonl")
	for _, w := range res.Warnings {
		if strings.Contains(w, "malformed") {
			t.Errorf("a retained-marker tombstone was reported as malformed: %s", w)
		}
	}
}

// TestContextCancellation pins that a cancelled parse returns promptly
// instead of walking the whole file.
func TestContextCancellation(t *testing.T) {
	root, logPath := fixtureRoot(t, "simple-session.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewWithOptions(nil, root).ParseSessionFile(ctx, logPath, 0); err == nil {
		t.Error("expected a context error from a cancelled parse")
	}
}

func TestParseMissingFileErrors(t *testing.T) {
	root := filepath.Join(t.TempDir(), "muse", "sessions")
	_, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(),
		filepath.Join(root, "nope", sessionLogName), 0)
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if !strings.HasPrefix(err.Error(), "muse.ParseSessionFile:") {
		t.Errorf("error not wrapped in the house style: %v", err)
	}
}

// writeLog lays an in-test-constructed log out under a temp watch root.
func writeLog(t *testing.T, lines ...string) (root, logPath string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "muse", "sessions")
	dir := filepath.Join(root, "2026", "08", "06", "11111111-2222-3333-4444-555555555555")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logPath = filepath.Join(dir, sessionLogName)
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return root, logPath
}

const (
	fixtureHeader = `{"schema_version":1,"id":"00000000-0000-0000-0000-000000000001",` +
		`"sequence":1,"recorded_at":1785962820001000,"record_type":"event",` +
		`"payload_type":"runtime.session.metadata","payload":{"kind":"metadata",` +
		`"record":{"provider_id":"meta","workspace_root":"/home/dev/demoproj"}}}`
	fixtureDetachedHead = `{"schema_version":1,"id":"00000000-0000-0000-0000-000000000002",` +
		`"sequence":2,"recorded_at":1785962820002000,"record_type":"event",` +
		`"payload_type":"session.workspace_branch.observed","payload":{"kind":"workspace_branch",` +
		`"record":{"vcs":"git","workspace_root":"/home/dev/demoproj",` +
		`"reference":{"kind":"detached","name":"ea2a614518cf"}}}}`
	fixtureFailedCall = `{"schema_version":1,"id":"00000000-0000-0000-0000-000000000003",` +
		`"sequence":3,"recorded_at":1785962820003000,"record_type":"event",` +
		`"payload_type":"runtime.session","payload":{"run_id":"r1","event":{` +
		`"kind":"assistant_tool_calls_committed","message_id":"m1","response_id":"resp_1",` +
		`"tool_calls":[{"name":"bash","call_id":"call_boom","id":"fc_boom",` +
		`"args":"{\"command\":\"false\"}"}]}}}`
	fixtureFailedOutcome = `{"schema_version":1,"id":"00000000-0000-0000-0000-000000000004",` +
		`"sequence":4,"recorded_at":1785962820004000,"record_type":"event",` +
		`"payload_type":"tool_batch.effect.terminal","payload":{"kind":"tool_batch_effect",` +
		`"run_id":"r1","record":{"call_id":"call_boom","kind":"terminal",` +
		`"outcome":{"kind":"failed"}}}}`
	fixtureFailedResult = `{"schema_version":1,"id":"00000000-0000-0000-0000-000000000005",` +
		`"sequence":5,"recorded_at":1785962820005000,"record_type":"event",` +
		`"payload_type":"runtime.session","payload":{"run_id":"r1","event":{` +
		`"kind":"tool_result_batch_committed","batch_id":"m1","results":[` +
		`{"tool_call_id":"call_boom","tool_call_index":0,"text":"exit_code=1"}]}}}`
	fixtureCancelledTurn = `{"schema_version":1,"id":"00000000-0000-0000-0000-000000000006",` +
		`"sequence":6,"recorded_at":1785962820006000,"record_type":"event",` +
		`"payload_type":"runtime.session","payload":{"run_id":"r1","event":{` +
		`"kind":"terminal","terminal":"cancelled","reason":"cancelled during model step",` +
		`"turn_duration_ms":12059}}}`
	fixtureCompletedTurn = `{"schema_version":1,"id":"00000000-0000-0000-0000-000000000007",` +
		`"sequence":7,"recorded_at":1785962820007000,"record_type":"event",` +
		`"payload_type":"runtime.session","payload":{"run_id":"r1","event":{` +
		`"kind":"terminal","terminal":"completed","reason":null,"turn_duration_ms":9157}}}`
	// fixtureVoiceCaptureStringOutcome mirrors the real line 6 of a
	// 2026-08-07 live session capture (session
	// acd8fa06-acdc-431c-87bf-71edfe3ae016, anonymized to the fixture's
	// standard synthetic uuid) that broke the adapter: `payload_type`
	// "voice.capture.observed" is never dispatched by handle(), but
	// `payload.record.outcome` is a bare STRING ("error") where
	// metaRecord.Outcome expected the tool_batch.effect.terminal object
	// shape `{"kind":"..."}`, so json.Unmarshal failed on the WHOLE line —
	// "malformed JSON: json: cannot unmarshal string into Go struct field
	// metaRecord.payload.record.outcome of type muse.effectOutcome".
	fixtureVoiceCaptureStringOutcome = `{"schema_version":1,` +
		`"id":"00000000-0000-0000-0000-000000000008",` +
		`"stream":{"kind":"session","id":"11111111-2222-3333-4444-555555555555"},` +
		`"sequence":6,"recorded_at":1786118148982274,"record_type":"event",` +
		`"durability":"durable","causation_id":null,` +
		`"payload_type":"voice.capture.observed","payload_schema_version":1,` +
		`"payload":{"kind":"voice_capture_observed","record":{"audio_ms":0,` +
		`"failure_class":"engine","mode":"record","outcome":"error",` +
		`"schema_version":1,"session_id":"11111111-2222-3333-4444-555555555555"}}}`
)

// TestFailedToolOutcomeAndAbortedTurn covers the two negative paths the
// happy-path capture never exercised: an explicitly failed tool effect and a
// cancelled turn. A `completed` terminal must stay silent — the assistant
// message and token row already describe it.
func TestFailedToolOutcomeAndAbortedTurn(t *testing.T) {
	root, logPath := writeLog(t,
		fixtureHeader, fixtureFailedCall, fixtureFailedOutcome,
		fixtureFailedResult, fixtureCancelledTurn, fixtureCompletedTurn)

	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var sawFailedCall, sawAbort bool
	aborts := 0
	for _, ev := range res.ToolEvents {
		switch {
		case ev.SourceEventID == "tool:call_boom":
			sawFailedCall = true
			if ev.Success {
				t.Error("a `failed` tool effect must mark the call unsuccessful")
			}
			if ev.ErrorMessage == "" {
				t.Error("a failed call must carry an error message")
			}
			if ev.ToolOutput != "exit_code=1" {
				t.Errorf("ToolOutput = %q, want the result body", ev.ToolOutput)
			}
		case ev.ActionType == models.ActionTurnAborted:
			sawAbort = true
			aborts++
			if ev.Success {
				t.Error("an aborted turn must not be successful")
			}
			if ev.Target != "cancelled" {
				t.Errorf("abort target = %q, want cancelled", ev.Target)
			}
			if ev.DurationMs != 12059 {
				t.Errorf("abort DurationMs = %d, want 12059", ev.DurationMs)
			}
		}
	}
	if !sawFailedCall {
		t.Error("the failed tool call was never emitted")
	}
	if !sawAbort {
		t.Error("the cancelled turn produced no turn_aborted event")
	}
	if aborts != 1 {
		t.Errorf("%d turn_aborted events; a `completed` terminal must produce none", aborts)
	}
}

// TestDetachedHeadIsNotRecordedAsABranch pins the honesty rule on the branch
// field: only a `branch` reference is adopted, so a detached HEAD's commit
// sha is never persisted as a branch name.
func TestDetachedHeadIsNotRecordedAsABranch(t *testing.T) {
	root, logPath := writeLog(t, fixtureHeader, fixtureDetachedHead, fixtureCancelledTurn)
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("no events")
	}
	for _, ev := range res.ToolEvents {
		if ev.GitBranch == "ea2a614518cf" {
			t.Error("a detached-HEAD commit sha was recorded as a git branch")
		}
	}
}

// TestSubagentParentLookupRefusesSymlink pins the sibling-read guard: the
// parent-log path is DERIVED, so a symlink planted there must not be
// followed into a file this adapter promises never to read.
func TestSubagentParentLookupRefusesSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "muse", "sessions")
	parentDir := filepath.Join(root, "2026", "08", "06", "11111111-2222-3333-4444-555555555555")
	childDir := filepath.Join(parentDir, "subagent", "child")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	decoy := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(decoy, []byte(fixtureHeader+"\n"), 0o600); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	if err := os.Symlink(decoy, filepath.Join(parentDir, sessionLogName)); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	if got := workspaceRootOf(filepath.Join(parentDir, sessionLogName)); got != "" {
		t.Errorf("workspaceRootOf followed a symlink and read %q", got)
	}
	if got := workspaceRootOf(filepath.Join(parentDir, "does-not-exist.jsonl")); got != "" {
		t.Errorf("workspaceRootOf on a missing file = %q, want empty", got)
	}
	if got := workspaceRootOf(""); got != "" {
		t.Errorf("workspaceRootOf(\"\") = %q, want empty", got)
	}
}

// TestVoiceCaptureObservedStringOutcomeDoesNotBreakParse is the regression
// pin for the real 2026-08-07 parse failure: a `voice.capture.observed`
// record whose `outcome` is a bare string must decode cleanly and be
// skipped silently (it is not a payload_type this adapter dispatches),
// producing zero warnings and no malformed-JSON report — even though the
// STRUCT it decodes into (metaRecord.Outcome) is the same one
// tool_batch.effect.terminal populates as an object.
func TestVoiceCaptureObservedStringOutcomeDoesNotBreakParse(t *testing.T) {
	root, logPath := writeLog(t, fixtureHeader, fixtureVoiceCaptureStringOutcome, fixtureCompletedTurn)
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, w := range res.Warnings {
		t.Errorf("unexpected warning: %s", w)
	}
	info, statErr := os.Stat(logPath)
	if statErr != nil {
		t.Fatalf("stat: %v", statErr)
	}
	if res.NewOffset != info.Size() {
		t.Errorf("NewOffset = %d, want the full file size %d", res.NewOffset, info.Size())
	}
}
