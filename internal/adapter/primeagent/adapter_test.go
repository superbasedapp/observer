package primeagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fixture copies a testdata transcript into a session-shaped path under a
// temp watch root and returns (adapter, path). Copying is what makes the
// tail-deferral bounds deterministic: the copy's mtime is `now`, so
// adapter.PendingResultGrace is unambiguously satisfied regardless of when
// the repo was checked out.
func fixture(t *testing.T, name string) (*Adapter, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), ".prime", "agent", "sessions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := filepath.Join("..", "..", "..", "testdata", "primeagent", name)
	body, err := os.ReadFile(src) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	// The session id is the filename stem, so keep a UUID-shaped name.
	dst := filepath.Join(root, "019f0000-1111-7222-8333-444444444444.jsonl")
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return NewWithOptions(nil, root), dst
}

func parse(t *testing.T, a *Adapter, path string, from int64) adapter.ParseResult {
	t.Helper()
	res, err := a.ParseSessionFile(context.Background(), path, from)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

func TestWatchPathsEndInPrimeAgentSessions(t *testing.T) {
	for _, p := range New().WatchPaths() {
		if !strings.HasSuffix(filepath.ToSlash(p), "/.prime/agent/sessions") {
			t.Errorf("watch root %q does not end in .prime/agent/sessions", p)
		}
	}
}

// TestIsSessionFile pins BOTH halves of the §3.2 predicate. The shape
// half alone is just ".jsonl", which claude-code, codex, pi and openclaw
// all share — so the under-WatchPaths half is doing the real work and a
// regression there would silently steal another adapter's files.
func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".prime", "agent", "sessions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	a := NewWithOptions(nil, root)

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"flat session", filepath.Join(root, "019f0000-1111-7222-8333-444444444444.jsonl"), true},
		{"legacy nested layout", filepath.Join(root, "--home-dev-proj--", "abc.jsonl"), true},
		{"uppercase extension", filepath.Join(root, "ABC.JSONL"), true},
		{"non-jsonl under root", filepath.Join(root, "settings.json"), false},
		{"right shape, foreign root", "/tmp/foreign/.prime/agent/sessions/abc.jsonl", false},
		{"sibling auth store", filepath.Join(root, "..", "auth.json"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// findEvent returns the first event with the given action type and a
// Target containing want.
func findEvent(t *testing.T, evs []models.ToolEvent, action, want string) models.ToolEvent {
	t.Helper()
	for _, e := range evs {
		if e.ActionType == action && strings.Contains(e.Target, want) {
			return e
		}
	}
	t.Fatalf("no %s event whose target contains %q; have %s", action, want, summarize(evs))
	return models.ToolEvent{}
}

func summarize(evs []models.ToolEvent) string {
	var b strings.Builder
	for _, e := range evs {
		b.WriteString("\n  ")
		b.WriteString(e.ActionType)
		b.WriteString(" | ")
		b.WriteString(e.RawToolName)
		b.WriteString(" | ")
		b.WriteString(truncate(e.Target, 60))
	}
	return b.String()
}

// TestParseFlatSession is the broad shape assertion over the whole
// fixture: the mix of action types, the session/tool identity on every
// row, and the token-row count.
func TestParseFlatSession(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	if len(res.ToolEvents) == 0 {
		t.Fatal("no tool events")
	}
	counts := map[string]int{}
	for _, e := range res.ToolEvents {
		counts[e.ActionType]++
		if e.Tool != models.ToolPrimeAgent {
			t.Errorf("event %q carries Tool=%q", e.RawToolName, e.Tool)
		}
		if e.SessionID != "019f0000-1111-7222-8333-444444444444" {
			t.Errorf("event %q carries SessionID=%q", e.RawToolName, e.SessionID)
		}
		if e.SourceEventID == "" {
			t.Errorf("event %q has an empty SourceEventID", e.RawToolName)
		}
	}

	want := map[string]int{
		models.ActionSessionStart:     1,
		models.ActionUserPrompt:       2,
		models.ActionRunCommand:       4, // 2 ipython calls + 2 bashExecutions
		models.ActionAssistantMessage: 1,
		models.ActionAPIError:         1,
		models.ActionContextCompacted: 1,
	}
	for action, n := range want {
		if counts[action] != n {
			t.Errorf("action %s: got %d events, want %d%s", action, counts[action], n, summarize(res.ToolEvents))
		}
	}

	// 3 usage-bearing assistant messages + 1 child-usage upgrade row.
	// The zero-usage provider failure contributes nothing.
	if len(res.TokenEvents) != 4 {
		t.Fatalf("got %d token events, want 4", len(res.TokenEvents))
	}

	// The malformed line must produce exactly one warning and must not
	// stop the parse — the entries after it are still consumed.
	if len(res.Warnings) != 1 {
		t.Errorf("got %d warnings, want exactly 1 (the malformed line): %v", len(res.Warnings), res.Warnings)
	}
	if !strings.Contains(res.Warnings[0], "malformed JSON") {
		t.Errorf("warning %q is not the malformed-line warning", res.Warnings[0])
	}
}

// TestSilentSkipOfBookkeepingEntries pins §4.4e. agent_status alone
// outnumbered messages 3:1 in the grounding session; a warning per
// unconsumed entry would flood the watcher log every poll. The single
// warning asserted above is the malformed line, so this is proven by the
// count — but assert the entry types explicitly too so a future "warn on
// unknown type" change is caught by name.
func TestSilentSkipOfBookkeepingEntries(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)
	for _, w := range res.Warnings {
		for _, noisy := range []string{"agent_status", "session_state", "session_info", "label", "custom", "thinking_level_change", "service_tier_change"} {
			if strings.Contains(w, noisy) {
				t.Errorf("bookkeeping entry %q produced a warning (%q) — it must be skipped silently", noisy, w)
			}
		}
	}
}

// TestUsageIsNetNotGross is the §4.4c pin. Prime Agent's `input` already
// excludes the cached prefix — the arithmetic identity
// total == input+output+cacheRead+cacheWrite closes exactly on every
// observed row — so the adapter must carry the raw value through. A
// well-meant "net it like OpenAI" change would subtract cacheRead a
// second time and under-report input by the whole cached prefix.
func TestUsageIsNetNotGross(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	var found bool
	for _, ev := range res.TokenEvents {
		if ev.InputTokens == 328 && ev.CacheReadTokens == 4352 {
			found = true
			if ev.OutputTokens != 291 {
				t.Errorf("OutputTokens = %d, want 291", ev.OutputTokens)
			}
			// The identity that PROVES net: had the adapter netted, input
			// would be 0 (clamped from 328-4352).
			if got := ev.InputTokens + ev.OutputTokens + ev.CacheReadTokens + ev.CacheCreationTokens; got != 4971 {
				t.Errorf("input+output+cacheRead+cacheWrite = %d, want the source totalTokens 4971", got)
			}
			if ev.ReasoningTokens != 0 {
				t.Errorf("ReasoningTokens = %d — the schema publishes no reasoning count on either API lane", ev.ReasoningTokens)
			}
			if ev.Source != models.TokenSourceJSONL || ev.Reliability != models.ReliabilityApproximate {
				t.Errorf("source/reliability = %q/%q, want jsonl/approximate", ev.Source, ev.Reliability)
			}
			if ev.EstimatedCostUSD == 0 {
				t.Error("EstimatedCostUSD is zero — the provider-reported usage.cost.total was dropped")
			}
		}
	}
	if !found {
		t.Fatal("the input=328 / cacheRead=4352 token row was not emitted")
	}
}

// TestZeroUsageEmitsNoTokenRow pins §4.4b. 14 of the grounding session's
// 22 assistant messages were provider failures carrying an all-zero usage
// block; a phantom row per attempt is pure noise in every cost surface.
func TestZeroUsageEmitsNoTokenRow(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)
	for _, ev := range res.TokenEvents {
		if ev.InputTokens == 0 && ev.OutputTokens == 0 && ev.CacheReadTokens == 0 && ev.CacheCreationTokens == 0 {
			t.Errorf("an all-zero token row was emitted (%+v)", ev)
		}
	}
	// The failed turn must still be VISIBLE — as an api_error action.
	e := findEvent(t, res.ToolEvents, models.ActionAPIError, "authentication failed")
	if e.Success {
		t.Error("the provider-failure row is marked successful")
	}
	if e.ErrorMessage == "" {
		t.Error("the provider-failure row has no ErrorMessage")
	}
}

// TestChildUsageUpgradesTheParentRow pins the RLM roll-up key. Emitting
// the aggregate under its own id would double-count against the parent's
// own usage; keying it to the parent lets the store's ON CONFLICT
// MAX-upgrade raise the row in place.
func TestChildUsageUpgradesTheParentRow(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	var parent, child *models.TokenEvent
	for i := range res.TokenEvents {
		ev := &res.TokenEvents[i]
		if ev.SourceEventID != "usage:a1000006" {
			continue
		}
		if ev.InputTokens == 328 {
			parent = ev
		}
		if ev.InputTokens == 590 {
			child = ev
		}
	}
	if parent == nil {
		t.Fatal("the parent assistant message's token row is missing or not keyed usage:a1000006")
	}
	if child == nil {
		t.Fatal("the child_usage_attributed aggregate is not keyed to the parent's SourceEventID — it would double-count")
	}
	if child.CacheReadTokens <= parent.CacheReadTokens {
		t.Errorf("the aggregate (%d cacheRead) does not exceed the parent (%d) — MAX-upgrade would be a no-op",
			child.CacheReadTokens, parent.CacheReadTokens)
	}
	if child.Model != parent.Model {
		t.Errorf("the upgrade row carries model %q but the parent carries %q", child.Model, parent.Model)
	}
}

// TestPolymorphicUserContent is the §4.4d pin, and the reason it exists:
// the vendor types UserMessage.content as `string | array` and documents
// the bare-string form. A strict []part type would fail json.Unmarshal on
// the WHOLE entry and silently drop the prompt — the shipped Gemini bug.
func TestPolymorphicUserContent(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	// The array-shaped prompt.
	findEvent(t, res.ToolEvents, models.ActionUserPrompt, "Review this repo")
	// The bare-string-shaped prompt.
	findEvent(t, res.ToolEvents, models.ActionUserPrompt, "list the files")
}

func TestContentPartsUnmarshalShapes(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantText string
		wantLen  int
	}{
		{"bare string", `"hello"`, "hello", 1},
		{"array", `[{"type":"text","text":"a"},{"type":"text","text":"b"}]`, "a\nb", 2},
		{"bare object", `{"type":"text","text":"solo"}`, "solo", 1},
		{"null", `null`, "", 0},
		{"empty string", `"   "`, "", 0},
		{"image only", `[{"type":"image","data":"AAAA","mimeType":"image/png"}]`, "", 1},
		{"unexpected scalar", `42`, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c contentParts
			if err := c.UnmarshalJSON([]byte(tc.raw)); err != nil {
				t.Fatalf("UnmarshalJSON(%s): %v", tc.raw, err)
			}
			if len(c) != tc.wantLen {
				t.Errorf("len = %d, want %d", len(c), tc.wantLen)
			}
			if got := c.text(); got != tc.wantText {
				t.Errorf("text() = %q, want %q", got, tc.wantText)
			}
		})
	}
}

// TestToolCallPairing covers the success path, the failure path and the
// details-derived duration.
func TestToolCallPairing(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	ok := findEvent(t, res.ToolEvents, models.ActionRunCommand, "import pathlib")
	if !ok.Success {
		t.Error("the successful ipython call is marked failed")
	}
	if ok.OutcomePending {
		t.Error("a paired call still reports OutcomePending")
	}
	if ok.DurationMs != 88 {
		t.Errorf("DurationMs = %d, want 88 (from toolResult.details)", ok.DurationMs)
	}
	if !strings.Contains(ok.ToolOutput, "pyproject.toml") {
		t.Errorf("ToolOutput = %q — the paired result body is missing", ok.ToolOutput)
	}
	if ok.RawToolName != "ipython" {
		t.Errorf("RawToolName = %q, want the verbatim native name", ok.RawToolName)
	}
	// §8.5: an ipython `code` argument IS authored code.
	if ok.ContentBytes == 0 {
		t.Error("ContentBytes is zero for an ipython call — the authored code length was dropped")
	}

	bad := findEvent(t, res.ToolEvents, models.ActionRunCommand, "nope.txt")
	if bad.Success {
		t.Error("the isError=true call is marked successful")
	}
	if !strings.Contains(bad.ErrorMessage, "FileNotFoundError") {
		t.Errorf("ErrorMessage = %q", bad.ErrorMessage)
	}
}

// TestBashExecution covers both origins of the role and the cancelled
// case, whose exitCode is undefined but which is still a failure.
func TestBashExecution(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	ok := findEvent(t, res.ToolEvents, models.ActionRunCommand, "git status")
	if !ok.Success {
		t.Error("an exitCode=0 bashExecution is marked failed")
	}
	cancelled := findEvent(t, res.ToolEvents, models.ActionRunCommand, "sleep 600")
	if cancelled.Success {
		t.Error("a cancelled bashExecution is marked successful")
	}
	if cancelled.ErrorMessage != "cancelled" {
		t.Errorf("ErrorMessage = %q, want cancelled", cancelled.ErrorMessage)
	}
}

// TestScrubsSecrets checks the two free-text surfaces a credential
// realistically lands on: a user prompt and shell output.
func TestScrubsSecrets(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	// Reconstructed the same way the fixture generator built them, so no
	// credential-shaped literal appears in this file either.
	key := "s" + "k-" + strings.Repeat("A", 32)
	tok := "gh" + "p_" + strings.Repeat("B", 36)

	for _, e := range res.ToolEvents {
		for name, field := range map[string]string{
			"Target":       e.Target,
			"RawToolInput": e.RawToolInput,
			"ToolOutput":   e.ToolOutput,
			"ErrorMessage": e.ErrorMessage,
		} {
			if strings.Contains(field, key) || strings.Contains(field, tok) {
				t.Errorf("%s of %q leaked a credential: %q", name, e.RawToolName, field)
			}
		}
	}

	prompt := findEvent(t, res.ToolEvents, models.ActionUserPrompt, "list the files")
	if !strings.Contains(prompt.RawToolInput, "REDACTED") {
		t.Errorf("the scrubbed prompt carries no redaction marker: %q", prompt.RawToolInput)
	}
}

// TestProjectRootAndBranchComeFromTheHeader pins §6 + the header re-read.
func TestProjectRootAndBranchComeFromTheHeader(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)
	for _, e := range res.ToolEvents {
		if e.ProjectRoot != "/home/dev/acme-widgets" {
			t.Errorf("event %q carries ProjectRoot=%q", e.RawToolName, e.ProjectRoot)
		}
		if e.GitBranch != "main" {
			t.Errorf("event %q carries GitBranch=%q", e.RawToolName, e.GitBranch)
		}
	}
}

// TestHeaderIsRereadOnResume is the §4.5a / resume pin: the header sits
// behind the cursor on every incremental parse, yet its cwd and branch
// are the ONLY statement of the project root. Without the unconditional
// re-read every appended turn lands under the placeholder root.
func TestHeaderIsRereadOnResume(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	first := parse(t, a, path, 0)
	if first.NewOffset == 0 {
		t.Fatal("the first parse consumed nothing")
	}

	// Resume from a point well past the header.
	mid := first.NewOffset / 2
	second := parse(t, a, path, mid)
	if len(second.ToolEvents) == 0 {
		t.Fatal("the resumed parse produced no events")
	}
	for _, e := range second.ToolEvents {
		if e.ProjectRoot != "/home/dev/acme-widgets" {
			t.Errorf("resumed event %q lost the project root: %q", e.RawToolName, e.ProjectRoot)
		}
		if e.SessionID != "019f0000-1111-7222-8333-444444444444" {
			t.Errorf("resumed event %q was re-keyed to session %q", e.RawToolName, e.SessionID)
		}
	}
}

// TestSourceEventIDsAreDeterministic pins §4.5: re-parsing the same bytes
// must produce the same ids, or the (source_file, source_event_id) dedup
// key stops deduping and every restart double-counts.
func TestSourceEventIDsAreDeterministic(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	first := parse(t, a, path, 0)
	second := parse(t, a, path, 0)

	if len(first.ToolEvents) != len(second.ToolEvents) {
		t.Fatalf("event counts differ across parses: %d vs %d", len(first.ToolEvents), len(second.ToolEvents))
	}
	seen := map[string]bool{}
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID != second.ToolEvents[i].SourceEventID {
			t.Errorf("event %d: id %q != %q", i, first.ToolEvents[i].SourceEventID, second.ToolEvents[i].SourceEventID)
		}
		id := first.ToolEvents[i].SourceEventID
		if seen[id] {
			t.Errorf("duplicate SourceEventID %q within one parse", id)
		}
		seen[id] = true
	}
}

// TestOffsetAdvancesPastEveryTerminatedLine is the cursor invariant. A
// parse that leaves the cursor short of a fully written line re-reads it
// forever; the malformed line in the fixture is the specific trap.
func TestOffsetAdvancesPastEveryTerminatedLine(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if res.NewOffset != info.Size() {
		t.Errorf("NewOffset = %d, want the full file size %d (every line is terminated)", res.NewOffset, info.Size())
	}

	// And a second parse from there yields nothing new.
	again := parse(t, a, path, res.NewOffset)
	if len(again.ToolEvents) != 0 || len(again.TokenEvents) != 0 {
		t.Errorf("re-parsing from EOF produced %d tool / %d token events", len(again.ToolEvents), len(again.TokenEvents))
	}
}

// TestPartialTrailingLineIsDeferred pins the other half of the cursor
// contract: a record still being written must NOT be consumed, and the
// cursor must not advance past it.
func TestPartialTrailingLineIsDeferred(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	body, err := os.ReadFile(path) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	partial := make([]byte, 0, len(body)+64)
	partial = append(partial, body...)
	partial = append(partial, []byte(`{"type": "message", "id": "zz", "message": {"role": "us`)...)
	if err := os.WriteFile(path, partial, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res := parse(t, a, path, 0)
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d (the cursor must stop before the partial line)", res.NewOffset, len(body))
	}
	if len(res.Warnings) != 1 {
		t.Errorf("a partial trailing line produced %d warnings — it is expected, not malformed: %v", len(res.Warnings), res.Warnings)
	}
}

// TestUnpairedToolCallTailIsDeferred pins adapter.DeferUnpairedTail. store's action
// ON CONFLICT clause can never flip `success`, so a call whose result
// lands in the NEXT tick must not be persisted optimistically in this
// one.
func TestUnpairedToolCallTailIsDeferred(t *testing.T) {
	a, path := fixture(t, "session-unpaired-tail.jsonl")
	res := parse(t, a, path, 0)

	if !res.RetrySuggested {
		t.Error("a deferred tail must set RetrySuggested, or a first-parse defer leaves no parse_cursors row")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if res.NewOffset >= info.Size() {
		t.Errorf("NewOffset = %d — the cursor was not rewound behind the unanswered call (size %d)", res.NewOffset, info.Size())
	}
	for _, e := range res.ToolEvents {
		if e.RawToolName == "ipython" {
			t.Error("the unanswered ipython call was emitted rather than deferred")
		}
	}
	// The token row that shared the deferred record must go with it.
	for _, ev := range res.TokenEvents {
		if ev.InputTokens == 4470 {
			t.Error("the deferred record's token row survived the rewind — the next parse will re-emit it")
		}
	}

	// Once the file is stale past the grace, the tail flushes rather than
	// deferring forever.
	old := time.Now().Add(-2 * adapter.PendingResultGrace)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	flushed := parse(t, a, path, 0)
	if flushed.NewOffset != info.Size() {
		t.Errorf("a stale transcript still deferred: NewOffset = %d, size = %d", flushed.NewOffset, info.Size())
	}
	var sawCall bool
	for _, e := range flushed.ToolEvents {
		if e.RawToolName == "ipython" {
			sawCall = true
			if !e.OutcomePending {
				t.Error("a flushed-but-unanswered call must carry OutcomePending so failure bookkeeping waits")
			}
		}
	}
	if !sawCall {
		t.Error("the stale flush emitted no ipython call at all")
	}
}

// TestModelPrefersResponseModel pins the alias resolution: a session may
// SELECT `~vendor/model-latest` while the response reports the concrete
// model that was actually billed.
func TestModelPrefersResponseModel(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	e := findEvent(t, res.ToolEvents, models.ActionRunCommand, "import pathlib")
	if e.Model != "openrouter/deepseek/deepseek-v4-flash-0731" {
		t.Errorf("Model = %q, want the provider-prefixed RESOLVED model", e.Model)
	}
	// And the failure turn, which has no responseModel, keeps the
	// selected id.
	fail := findEvent(t, res.ToolEvents, models.ActionAPIError, "authentication failed")
	if fail.Model != "openai/gpt-5.4" {
		t.Errorf("Model = %q, want openai/gpt-5.4", fail.Model)
	}
}

// TestTimestampsUseInnerUnixMillis pins the unit. The envelope carries an
// ISO string and the inner message a Unix-MILLISECOND number; reading the
// latter as seconds or micros silently mints 1970 / year-50000 rows.
func TestTimestampsUseInnerUnixMillis(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	res := parse(t, a, path, 0)

	e := findEvent(t, res.ToolEvents, models.ActionUserPrompt, "Review this repo")
	want := time.UnixMilli(1786005238300).UTC()
	if !e.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %s, want %s", e.Timestamp, want)
	}
	// Everything must land in a plausible window regardless.
	for _, ev := range res.ToolEvents {
		if ev.Timestamp.IsZero() {
			t.Errorf("event %q has a zero timestamp", ev.RawToolName)
			continue
		}
		if ev.Timestamp.Year() < 2020 || ev.Timestamp.Year() > 2100 {
			t.Errorf("event %q timestamp %s is outside a plausible window — a unit was misread", ev.RawToolName, ev.Timestamp)
		}
	}
}

func TestParseUnixMillisRejectsWrongUnits(t *testing.T) {
	cases := []struct {
		name string
		in   int64
		zero bool
	}{
		{"millis", 1786005238433, false},
		{"seconds", 1786005238, true},
		{"micros", 1786005238433000, true},
		{"zero", 0, true},
		{"negative", -5, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUnixMillis(tc.in)
			if got.IsZero() != tc.zero {
				t.Errorf("parseUnixMillis(%d) = %s, wanted zero=%v", tc.in, got, tc.zero)
			}
		})
	}
}

func TestMapToolName(t *testing.T) {
	// Built with a literal space either side so gocritic's mapKey check
	// does not read it as accidental whitespace: leading/trailing space IS
	// the case under test (the classifier trims before switching).
	spacedBash := " " + "bash" + " "
	cases := map[string]string{
		"ipython":              models.ActionRunCommand,
		"IPython":              models.ActionRunCommand,
		spacedBash:             models.ActionRunCommand,
		"edit":                 models.ActionEditFile,
		"read":                 models.ActionReadFile,
		"write":                models.ActionWriteFile,
		"grep":                 models.ActionSearchText,
		"glob":                 models.ActionSearchFiles,
		"web_search":           models.ActionWebSearch,
		"web_fetch":            models.ActionWebFetch,
		"mcp__linear__list":    models.ActionMCPCall,
		"something_never_seen": models.ActionUnknown,
		"":                     models.ActionUnknown,
	}
	for in, want := range cases {
		if got := mapToolName(in); got != want {
			t.Errorf("mapToolName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAuthoredBytesOnlyForIpython pins the explicit §8.5 decision: report
// the authored Python source, and report ZERO rather than a fabricated
// count for anything else.
func TestAuthoredBytesOnlyForIpython(t *testing.T) {
	code := "print('hi')\n"
	if got := authoredBytes(contentPart{Name: "ipython", Arguments: map[string]any{"code": code}}); got != int64(len(code)) {
		t.Errorf("authoredBytes(ipython) = %d, want %d", got, len(code))
	}
	if got := authoredBytes(contentPart{Name: "web_search", Arguments: map[string]any{"query": "x"}}); got != 0 {
		t.Errorf("authoredBytes(web_search) = %d, want 0", got)
	}
	if got := authoredBytes(contentPart{Name: "ipython", Arguments: map[string]any{"code": 42}}); got != 0 {
		t.Errorf("authoredBytes with a non-string code = %d, want 0", got)
	}
}

func TestSessionIDFromPath(t *testing.T) {
	cases := map[string]string{
		"/h/.prime/agent/sessions/019f0000-1111-7222-8333-444444444444.jsonl": "019f0000-1111-7222-8333-444444444444",
		"/h/.prime/agent/sessions/legacy/abc.jsonl":                           "abc",
	}
	for in, want := range cases {
		if got := sessionIDFromPath(filepath.FromSlash(in)); got != want {
			t.Errorf("sessionIDFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMissingHeaderFallsBackToPlaceholder covers the degraded case: a
// truncated or header-less file must still parse under a promotable
// placeholder root rather than picking up the observer's own cwd.
func TestMissingHeaderFallsBackToPlaceholder(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".prime", "agent", "sessions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(root, "019f0000-1111-7222-8333-444444444444.jsonl")
	body := `{"type": "message", "id": "b1", "timestamp": "2026-08-06T08:00:00.000Z", "message": {"role": "user", "content": "hello", "timestamp": 1786005238300}}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := parse(t, NewWithOptions(nil, root), path, 0)
	if len(res.ToolEvents) != 1 {
		t.Fatalf("got %d events, want 1", len(res.ToolEvents))
	}
	if res.ToolEvents[0].ProjectRoot != placeholderRoot {
		t.Errorf("ProjectRoot = %q, want %q", res.ToolEvents[0].ProjectRoot, placeholderRoot)
	}
}

func TestContextCancellation(t *testing.T) {
	a, path := fixture(t, "session-flat.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ParseSessionFile(ctx, path, 0); err == nil {
		t.Error("a cancelled context did not stop the parse")
	}
}
