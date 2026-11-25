package droid

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Fixture coordinates. See testdata/factory/README.md for provenance.
const (
	fixtureDir = "../../../testdata/factory/sessions"

	linuxDir     = "linux-home-marmutapp-needlehaystack"
	linuxEncoded = "-home-marmutapp-needlehaystack"
	minimalID    = "774f4bf6-8025-4790-95b6-e8f854f09891"
	richID       = "11080800-d13f-4c9d-b6df-149ea74d7723"
	linuxCWD     = "/home/marmutapp/needlehaystack"

	windowsDir     = "windows-C-Users-auzy_-copilot-smoke"
	windowsEncoded = "-C-Users-auzy_-copilot-smoke"
	windowsID      = "7df5bcf0-6cd9-4c89-8925-1bf8b3fb061d"
	windowsCWD     = `C:\Users\auzy_\copilot-smoke`
)

// stage copies one fixture session (transcript + both sidecars) into a
// temp tree laid out exactly the way droid lays it out on disk:
//
//	<tmp>/.factory/sessions/<dash-encoded-cwd>/<uuid>.jsonl
//
// so IsSessionFile / WatchPaths / the sidecar sibling lookup all exercise
// the real path shape. Returns (home, transcriptPath).
func stage(t *testing.T, srcDir, encoded, id string) (home, transcript string) {
	t.Helper()
	home = t.TempDir()
	dst := filepath.Join(home, ".factory", "sessions", encoded)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, suffix := range []string{".jsonl", ".settings.json", ".settings.json.bak"} {
		body, err := os.ReadFile(filepath.Join(fixtureDir, srcDir, id+suffix))
		if err != nil {
			t.Fatalf("read fixture %s%s: %v", id, suffix, err)
		}
		if err := os.WriteFile(filepath.Join(dst, id+suffix), body, 0o600); err != nil {
			t.Fatalf("write fixture %s%s: %v", id, suffix, err)
		}
	}
	return home, filepath.Join(dst, id+".jsonl")
}

// parseStaged stages a fixture and parses it from offset 0.
func parseStaged(t *testing.T, srcDir, encoded, id string) (adapter.ParseResult, string) {
	t.Helper()
	home, transcript := stage(t, srcDir, encoded, id)
	a := NewWithOptions(nil, filepath.Join(home, ".factory", "sessions"))
	res, err := a.ParseSessionFile(context.Background(), transcript, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res, transcript
}

func eventsOfType(res adapter.ParseResult, actionType string) []models.ToolEvent {
	var out []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == actionType {
			out = append(out, ev)
		}
	}
	return out
}

// TestWatchPathsScopedToSessions pins the security invariant: the watch
// roots must never be the bare ~/.factory, which holds the global
// settings.json (plaintext BYOK API keys), auth.v2.*, certs/ and
// history.json.
func TestWatchPathsScopedToSessions(t *testing.T) {
	roots := New().WatchPaths()
	if len(roots) == 0 {
		t.Fatal("WatchPaths() returned no roots")
	}
	for _, r := range roots {
		norm := filepath.ToSlash(r)
		if !strings.HasSuffix(norm, "/.factory/sessions") {
			t.Errorf("watch root %q is not scoped to .factory/sessions", r)
		}
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join("/home", "u", ".factory", "sessions")
	a := NewWithOptions(nil, root)

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"transcript", filepath.Join(root, "-home-u-proj", "abc.jsonl"), true},
		{"settings sidecar", filepath.Join(root, "-home-u-proj", "abc.settings.json"), false},
		{"settings bak", filepath.Join(root, "-home-u-proj", "abc.settings.json.bak"), false},
		{"global settings", filepath.Join("/home", "u", ".factory", "settings.json"), false},
		{"history", filepath.Join("/home", "u", ".factory", "history.json"), false},
		{"outside watch root", "/home/u/.claude/projects/x/abc.jsonl", false},
		{"other tool jsonl under root-ish path", "/home/u/.qwen/projects/p/chats/a.jsonl", false},
		{"nested deeper under root", filepath.Join(root, "-home-u-proj", "sub", "abc.jsonl"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q)=%v want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestIsSessionFileWindowsSeparators covers a Windows-style path reaching
// the shape predicate (backslashes, drive letter, mixed case).
func TestIsSessionFileWindowsSeparators(t *testing.T) {
	if !matchesShape(`C:\Users\Auzy\.Factory\Sessions\-C-Users-auzy-proj\abc.JSONL`) {
		t.Error("matchesShape rejected a Windows-cased transcript path")
	}
	if matchesShape(`C:\Users\Auzy\.factory\sessions\-C-proj\abc.settings.json`) {
		t.Error("matchesShape accepted a settings sidecar")
	}
}

// TestParseMinimalSession covers a just-created session: one
// session_start line, no messages, an all-zero token sidecar.
func TestParseMinimalSession(t *testing.T) {
	res, transcript := parseStaged(t, linuxDir, linuxEncoded, minimalID)

	if len(res.ToolEvents) != 1 {
		t.Fatalf("ToolEvents=%d want 1: %+v", len(res.ToolEvents), res.ToolEvents)
	}
	ev := res.ToolEvents[0]
	if ev.ActionType != models.ActionSessionStart {
		t.Errorf("ActionType=%q want %q", ev.ActionType, models.ActionSessionStart)
	}
	if ev.SessionID != minimalID {
		t.Errorf("SessionID=%q want %q", ev.SessionID, minimalID)
	}
	if ev.Tool != models.ToolDroid {
		t.Errorf("Tool=%q want %q", ev.Tool, models.ToolDroid)
	}
	if want := crossmount.TranslateForeignPath(linuxCWD); ev.ProjectRoot != want {
		t.Errorf("ProjectRoot=%q want %q", ev.ProjectRoot, want)
	}
	// tokenUsage is all-zero on a fresh session: no token row at all
	// rather than a zero row.
	if len(res.TokenEvents) != 0 {
		t.Errorf("TokenEvents=%d want 0: %+v", len(res.TokenEvents), res.TokenEvents)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("Warnings=%v want none", res.Warnings)
	}
	info, err := os.Stat(transcript)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != info.Size() {
		t.Errorf("NewOffset=%d want %d (file size)", res.NewOffset, info.Size())
	}
}

// TestSidecarBakNeverRead pins that the `.settings.json.bak` snapshot of
// the PRIOR settings state is never consulted: the minimal fixture's .bak
// says model=claude-opus-5 while the live sidecar says the BYOK custom
// model, so reading the wrong file is directly observable.
func TestSidecarBakNeverRead(t *testing.T) {
	res, _ := parseStaged(t, linuxDir, linuxEncoded, minimalID)
	got := res.ToolEvents[0].Model
	if got == "claude-opus-5" {
		t.Fatal("model came from the .settings.json.bak snapshot")
	}
	if got != "custom:GPT-5.4-Mini-[OpenAI-BYOK]-0" {
		t.Errorf("Model=%q want the live sidecar's custom BYOK id", got)
	}
}

// TestParseRichSession walks the 17-line Linux fixture: prompts, context
// injection, host notices, thinking, a tool_use/tool_result pair, a
// compaction, and the failed turn outcome.
func TestParseRichSession(t *testing.T) {
	res, _ := parseStaged(t, linuxDir, linuxEncoded, richID)

	counts := map[string]int{}
	for _, ev := range res.ToolEvents {
		counts[ev.ActionType]++
		if ev.SessionID != richID {
			t.Errorf("event %q SessionID=%q want %q", ev.SourceEventID, ev.SessionID, richID)
		}
		if ev.SourceEventID == "" {
			t.Errorf("event %+v has an empty SourceEventID", ev)
		}
	}
	want := map[string]int{
		models.ActionSessionStart:     1,
		models.ActionUserPrompt:       3, // --update / hi / QUick summary…
		models.ActionSystemPrompt:     3, // three distinct llm_only context injections
		models.ActionNotification:     2, // two user_only host notices
		models.ActionAssistantMessage: 2,
		models.ActionReadFile:         1,
		models.ActionContextCompacted: 1,
		models.ActionAPIError:         1, // the reason:"error" turn outcome
	}
	for at, n := range want {
		if counts[at] != n {
			t.Errorf("action %q count=%d want %d (all=%v)", at, counts[at], n, counts)
		}
	}
	// reason:"completed" turn outcomes are deliberately not rowed.
	if counts[models.ActionTurnAborted] != 0 {
		t.Errorf("turn_aborted count=%d want 0", counts[models.ActionTurnAborted])
	}

	prompts := eventsOfType(res, models.ActionUserPrompt)
	var gotPrompts []string
	for _, p := range prompts {
		gotPrompts = append(gotPrompts, p.Target)
	}
	for _, wantText := range []string{"--update", "hi", "QUick summary of the project"} {
		found := false
		for _, g := range gotPrompts {
			if g == wantText {
				found = true
			}
		}
		if !found {
			t.Errorf("user prompt %q missing from %v", wantText, gotPrompts)
		}
	}
}

func TestRichSessionToolCallPairing(t *testing.T) {
	res, _ := parseStaged(t, linuxDir, linuxEncoded, richID)

	reads := eventsOfType(res, models.ActionReadFile)
	if len(reads) != 1 {
		t.Fatalf("read_file rows=%d want 1", len(reads))
	}
	ev := reads[0]
	if ev.RawToolName != "Read" {
		t.Errorf("RawToolName=%q want Read", ev.RawToolName)
	}
	if ev.SourceEventID != "tool:call_O8O2JaW9erPbi5enPKfY4dta" {
		t.Errorf("SourceEventID=%q want the tool_use id", ev.SourceEventID)
	}
	if ev.Target != linuxCWD+"/README.md" {
		t.Errorf("Target=%q want the file_path input", ev.Target)
	}
	if !ev.Success {
		t.Error("Success=false; the paired tool_result has is_error=false")
	}
	if !strings.Contains(ev.ToolOutput, "HaystackBench") {
		t.Errorf("ToolOutput missing the paired result body: %.120q", ev.ToolOutput)
	}
	if ev.ErrorMessage != "" {
		t.Errorf("ErrorMessage=%q want empty on a successful call", ev.ErrorMessage)
	}
	// The thinking block preceding the tool_use becomes PrecedingReasoning
	// — the plaintext summary only.
	if !strings.Contains(ev.PrecedingReasoning, "Summarizing repo context") {
		t.Errorf("PrecedingReasoning=%.120q want the thinking summary", ev.PrecedingReasoning)
	}
	if ev.Model != "custom:GPT-5.4-Mini-[OpenAI-BYOK]-0" {
		t.Errorf("Model=%q want the assistant message's modelId", ev.Model)
	}
}

// TestEncryptedReasoningNeverEmitted pins that droid's encrypted OpenAI
// Responses reasoning payloads (thinking.signature /
// message.openaiEncryptedContent) never reach a ToolEvent field.
func TestEncryptedReasoningNeverEmitted(t *testing.T) {
	for _, fx := range []struct{ dir, enc, id string }{
		{linuxDir, linuxEncoded, richID},
		{windowsDir, windowsEncoded, windowsID},
	} {
		res, _ := parseStaged(t, fx.dir, fx.enc, fx.id)
		for _, ev := range res.ToolEvents {
			blob := strings.Join([]string{
				ev.Target, ev.RawToolInput, ev.ToolOutput,
				ev.PrecedingReasoning, ev.ErrorMessage,
			}, "\x00")
			for _, needle := range []string{"gAAAAAB", "encrypted_content", "signatureProvider"} {
				if strings.Contains(blob, needle) {
					t.Errorf("%s: event %q leaked %q", fx.id, ev.SourceEventID, needle)
				}
			}
		}
	}
}

func TestRichSessionCompactionAndTurnOutcome(t *testing.T) {
	res, _ := parseStaged(t, linuxDir, linuxEncoded, richID)

	comp := eventsOfType(res, models.ActionContextCompacted)
	if len(comp) != 1 {
		t.Fatalf("context_compacted rows=%d want 1", len(comp))
	}
	c := comp[0]
	if !strings.HasPrefix(c.Target, "provider_switch_serialization: 3 msgs removed, ~3457 tokens") {
		t.Errorf("Target=%q want the summaryKind/removedCount/summaryTokens digest", c.Target)
	}
	if !strings.Contains(c.RawToolInput, `"removed_count":3`) {
		t.Errorf("RawToolInput=%q missing removed_count", c.RawToolInput)
	}
	// systemInfo's git/directory command OUTPUT pairs are dropped, not
	// stored (the "git log --oneline -5" output is the canary).
	blob := c.Target + c.RawToolInput + c.ToolOutput
	for _, needle := range []string{"git log --oneline", "ea2a614", "git status --porcelain"} {
		if strings.Contains(blob, needle) {
			t.Errorf("compaction row leaked systemInfo output %q", needle)
		}
	}
	if len(c.ToolOutput) > maxSummaryPreview {
		t.Errorf("ToolOutput=%d bytes want <= %d", len(c.ToolOutput), maxSummaryPreview)
	}

	errs := eventsOfType(res, models.ActionAPIError)
	if len(errs) != 1 {
		t.Fatalf("api_error rows=%d want 1", len(errs))
	}
	e := errs[0]
	if e.Success {
		t.Error("Success=true on a failed turn outcome")
	}
	if e.SourceEventID != "turn:21b9d4c4-0f25-4000-bcec-c24f62cf38f7" {
		t.Errorf("SourceEventID=%q want turn:<turnId>", e.SourceEventID)
	}
	// The cause lives in the preceding user_only notice, not on the
	// outcome record.
	if !strings.Contains(e.ErrorMessage, "No active subscription found") {
		t.Errorf("ErrorMessage=%.120q want the preceding host notice", e.ErrorMessage)
	}
}

// TestRichSessionTokens pins the session-level cumulative token row and
// the NET-input decision.
func TestRichSessionTokens(t *testing.T) {
	res, transcript := parseStaged(t, linuxDir, linuxEncoded, richID)

	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents=%d want 1: %+v", len(res.TokenEvents), res.TokenEvents)
	}
	tk := res.TokenEvents[0]
	if tk.SourceEventID != "tokens:"+richID {
		t.Errorf("SourceEventID=%q want tokens:<session-id>", tk.SourceEventID)
	}
	if tk.SourceFile != transcript {
		t.Errorf("SourceFile=%q want the transcript path %q", tk.SourceFile, transcript)
	}
	// Straight from sidecar tokenUsage — NOT inclusiveTokenUsage, NOT
	// lastCallTokenUsage, and input is NOT re-netted against cacheRead
	// (droid already persists it NET; 26934 < 45056 proves it).
	if tk.InputTokens != 26934 {
		t.Errorf("InputTokens=%d want 26934 (verbatim, already NET)", tk.InputTokens)
	}
	if tk.OutputTokens != 203 || tk.CacheReadTokens != 45056 || tk.ReasoningTokens != 80 {
		t.Errorf("out/cacheRead/reasoning=%d/%d/%d want 203/45056/80",
			tk.OutputTokens, tk.CacheReadTokens, tk.ReasoningTokens)
	}
	if tk.CacheCreationTokens != 0 {
		t.Errorf("CacheCreationTokens=%d want 0", tk.CacheCreationTokens)
	}
	if tk.Model != "custom:GPT-5.4-Mini-[OpenAI-BYOK]-0" {
		t.Errorf("Model=%q want the verbatim BYOK id", tk.Model)
	}
	if tk.Source != models.TokenSourceJSONL || tk.Reliability != models.ReliabilityApproximate {
		t.Errorf("source/reliability=%q/%q want jsonl/approximate", tk.Source, tk.Reliability)
	}
	if tk.Tool != models.ToolDroid || tk.SessionID != richID {
		t.Errorf("Tool/SessionID=%q/%q", tk.Tool, tk.SessionID)
	}
	if tk.Timestamp.IsZero() {
		t.Error("Timestamp is zero; want the last record timestamp")
	}
}

// TestParseWindowsSession covers the Windows-origin fixture: the
// todo_state event type, the Windows tool vocabulary, and — critically —
// that a `C:\...` cwd never gets the observer's own cwd prefixed onto it.
func TestParseWindowsSession(t *testing.T) {
	res, _ := parseStaged(t, windowsDir, windowsEncoded, windowsID)

	wantRoot := crossmount.TranslateForeignPath(windowsCWD)
	for _, ev := range res.ToolEvents {
		if ev.ProjectRoot != wantRoot {
			t.Fatalf("event %q ProjectRoot=%q want %q", ev.SourceEventID, ev.ProjectRoot, wantRoot)
		}
	}
	cwd, _ := os.Getwd()
	if strings.HasPrefix(wantRoot, cwd) {
		t.Fatalf("ProjectRoot %q resolved under the observer's own cwd %q "+
			"(crossmount.TranslateForeignPath missing before git.Resolve)", wantRoot, cwd)
	}

	todos := eventsOfType(res, models.ActionTodoUpdate)
	if len(todos) != 4 {
		// 2 todo_state records + 2 TodoWrite tool_use calls.
		t.Fatalf("todo_update rows=%d want 4: %+v", len(todos), todos)
	}
	var stateRows int
	for _, ev := range todos {
		if ev.RawToolName != models.ToolDroid+".todo_state" {
			continue
		}
		stateRows++
		// droid's payload is a flattened markdown STRING, stored verbatim.
		if !strings.Contains(ev.RawToolInput, "Inspect repository contents") {
			t.Errorf("todo_state RawToolInput=%.120q missing the checklist", ev.RawToolInput)
		}
		if strings.Contains(ev.RawToolInput, `"todos"`) {
			t.Errorf("todo_state RawToolInput looks re-serialized, want the raw string: %.120q", ev.RawToolInput)
		}
	}
	if stateRows != 2 {
		t.Errorf("todo_state rows=%d want 2", stateRows)
	}

	byRawName := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		byRawName[ev.RawToolName] = ev
	}
	if ls, ok := byRawName["LS"]; !ok {
		t.Error("no LS tool row")
	} else if ls.ActionType != models.ActionSearchFiles {
		t.Errorf("LS ActionType=%q want %q", ls.ActionType, models.ActionSearchFiles)
	}
	if rd, ok := byRawName["Read"]; !ok {
		t.Error("no Read tool row")
	} else if rd.ToolOutput != "smoke\n" {
		t.Errorf("Read ToolOutput=%q want the paired result body", rd.ToolOutput)
	}

	if len(res.TokenEvents) != 1 || res.TokenEvents[0].InputTokens != 18320 {
		t.Errorf("token events=%+v want one row with InputTokens=18320", res.TokenEvents)
	}
}

// TestCursorResume proves a resumed parse (a) makes progress, (b) emits
// the same events as a single full pass minus the once-only session-start
// marker, and (c) still resolves the session id + project root from line
// 1 even though its byte range starts past it.
func TestCursorResume(t *testing.T) {
	home, transcript := stage(t, linuxDir, linuxEncoded, richID)
	a := NewWithOptions(nil, filepath.Join(home, ".factory", "sessions"))
	ctx := context.Background()

	body, err := os.ReadFile(transcript)
	if err != nil {
		t.Fatal(err)
	}
	full, err := a.ParseSessionFile(ctx, transcript, 0)
	if err != nil {
		t.Fatalf("full parse: %v", err)
	}

	// Replay what the watcher actually does: parse a transcript that only
	// has its first 6 lines, then re-parse from the persisted cursor once
	// droid has appended the rest.
	var mid int64
	for i, n := 0, 0; i < len(body); i++ {
		if body[i] == '\n' {
			n++
			if n == 6 {
				mid = int64(i + 1)
				break
			}
		}
	}
	if mid == 0 {
		t.Fatal("could not find the 6th line boundary")
	}
	if err := os.WriteFile(transcript, body[:mid], 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := a.ParseSessionFile(ctx, transcript, 0)
	if err != nil {
		t.Fatalf("first-half parse: %v", err)
	}
	if first.NewOffset != mid {
		t.Fatalf("first-half NewOffset=%d want %d", first.NewOffset, mid)
	}
	if err := os.WriteFile(transcript, body, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(ctx, transcript, mid)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	if second.NewOffset != full.NewOffset {
		t.Errorf("resumed NewOffset=%d want %d", second.NewOffset, full.NewOffset)
	}
	if len(second.ToolEvents) == 0 {
		t.Fatal("resumed parse produced no events")
	}
	for _, ev := range second.ToolEvents {
		if ev.ActionType == models.ActionSessionStart {
			t.Error("resumed parse re-emitted the session-start marker")
		}
		if ev.SessionID != richID {
			t.Errorf("resumed event %q SessionID=%q want %q (header not re-read)", ev.SourceEventID, ev.SessionID, richID)
		}
		if ev.ProjectRoot != crossmount.TranslateForeignPath(linuxCWD) {
			t.Errorf("resumed event %q ProjectRoot=%q (header not re-read)", ev.SourceEventID, ev.ProjectRoot)
		}
	}

	// No event of the full pass is lost across the resume split.
	seen := map[string]bool{}
	for _, ev := range first.ToolEvents {
		seen[ev.SourceEventID] = true
	}
	for _, ev := range second.ToolEvents {
		seen[ev.SourceEventID] = true
	}
	for _, ev := range full.ToolEvents {
		if !seen[ev.SourceEventID] {
			t.Errorf("event %q lost across the resume split", ev.SourceEventID)
		}
	}
}

// TestMissingSidecarTolerated: droid writes the transcript and the sidecar
// independently, so a transcript with no sidecar must parse cleanly and
// simply produce no token row.
func TestMissingSidecarTolerated(t *testing.T) {
	home, transcript := stage(t, linuxDir, linuxEncoded, richID)
	if err := os.Remove(strings.TrimSuffix(transcript, ".jsonl") + ".settings.json"); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, filepath.Join(home, ".factory", "sessions"))
	res, err := a.ParseSessionFile(context.Background(), transcript, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("TokenEvents=%d want 0 without a sidecar", len(res.TokenEvents))
	}
	if len(res.ToolEvents) == 0 {
		t.Error("ToolEvents empty; the transcript should still parse")
	}
}

// TestMalformedSidecarTolerated: a truncated/garbage sidecar must not
// fail the parse.
func TestMalformedSidecarTolerated(t *testing.T) {
	home, transcript := stage(t, linuxDir, linuxEncoded, richID)
	sidecarPath := strings.TrimSuffix(transcript, ".jsonl") + ".settings.json"
	if err := os.WriteFile(sidecarPath, []byte(`{"tokenUsage":{"inputT`), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, filepath.Join(home, ".factory", "sessions"))
	res, err := a.ParseSessionFile(context.Background(), transcript, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("TokenEvents=%d want 0 on a malformed sidecar", len(res.TokenEvents))
	}
}

// writeTranscript builds a synthetic droid transcript in a staged tree.
func writeTranscript(t *testing.T, lines []string, trailingNewline bool) (a *Adapter, path string) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".factory", "sessions", "-tmp-proj")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := strings.Join(lines, "\n")
	if trailingNewline {
		body += "\n"
	}
	path = filepath.Join(dir, "aaaa-bbbb.jsonl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewWithOptions(nil, filepath.Join(home, ".factory", "sessions")), path
}

const synthStart = `{"type":"session_start","id":"sess-1","title":"t","cwd":"/tmp/proj"}`

func synthPrompt(id, text string) string {
	return `{"type":"message","id":"` + id + `","timestamp":"2026-07-28T10:00:00.000Z",` +
		`"message":{"role":"user","content":[{"type":"text","text":"` + text + `"}]}}`
}

// TestMalformedLineSkipAndAdvance: a garbage line must be warned about,
// skipped, and the cursor must still advance past it so the poll loop
// can't spin.
func TestMalformedLineSkipAndAdvance(t *testing.T) {
	lines := []string{
		synthStart,
		`{not json at all`,
		"",
		synthPrompt("m1", "after the garbage"),
	}
	a, path := writeTranscript(t, lines, true)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != info.Size() {
		t.Errorf("NewOffset=%d want %d (must advance past the bad line)", res.NewOffset, info.Size())
	}
	if len(res.Warnings) != 1 {
		t.Errorf("Warnings=%v want exactly one", res.Warnings)
	}
	prompts := eventsOfType(res, models.ActionUserPrompt)
	if len(prompts) != 1 || prompts[0].Target != "after the garbage" {
		t.Errorf("prompts=%+v want the record following the malformed line", prompts)
	}
}

// TestPartialTrailingLineDeferred: droid appends line-at-a-time, so a
// final line with no '\n' is still being written — it must not be
// consumed and the cursor must stop before it.
func TestPartialTrailingLineDeferred(t *testing.T) {
	lines := []string{synthStart, synthPrompt("m1", "complete"), synthPrompt("m2", "half-writ")}
	a, path := writeTranscript(t, lines, false)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset >= info.Size() {
		t.Errorf("NewOffset=%d want < %d (partial line must not be consumed)", res.NewOffset, info.Size())
	}
	prompts := eventsOfType(res, models.ActionUserPrompt)
	if len(prompts) != 1 || prompts[0].Target != "complete" {
		t.Errorf("prompts=%+v want only the terminated record", prompts)
	}
}

// TestCRLFCursorArithmetic: a Windows-written transcript uses \r\n; the
// cursor must advance by the exact terminator length.
func TestCRLFCursorArithmetic(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".factory", "sessions", "-C-proj")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "crlf.jsonl")
	body := synthStart + "\r\n" + synthPrompt("m1", "windows line") + "\r\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, filepath.Join(home, ".factory", "sessions"))
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset=%d want %d", res.NewOffset, len(body))
	}
	prompts := eventsOfType(res, models.ActionUserPrompt)
	if len(prompts) != 1 || prompts[0].Target != "windows line" {
		t.Errorf("prompts=%+v want the CRLF-terminated record", prompts)
	}
}

// TestContextInjectionDedup: droid re-injects the identical llm_only
// context block every turn; identical payloads must collapse onto one
// content-addressed SourceEventID while a different payload gets its own.
func TestContextInjectionDedup(t *testing.T) {
	ctxMsg := func(id, text string) string {
		return `{"type":"message","id":"` + id + `","timestamp":"2026-07-28T10:00:00.000Z",` +
			`"message":{"role":"user","visibility":"llm_only","content":[{"type":"text","text":"` + text + `"}]}}`
	}
	a, path := writeTranscript(t, []string{
		synthStart,
		ctxMsg("c1", "<system-reminder>same</system-reminder>"),
		ctxMsg("c2", "<system-reminder>same</system-reminder>"),
		ctxMsg("c3", "<system-reminder>different</system-reminder>"),
	}, true)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	rows := eventsOfType(res, models.ActionSystemPrompt)
	if len(rows) != 3 {
		t.Fatalf("system_prompt rows=%d want 3 (dedup happens on the store's event id)", len(rows))
	}
	ids := map[string]int{}
	for _, ev := range rows {
		ids[ev.SourceEventID]++
		if ev.MessageID == "" {
			t.Error("MessageID (content hash) not set on a system_prompt row")
		}
	}
	if len(ids) != 2 {
		t.Errorf("distinct SourceEventIDs=%d want 2 (identical payloads must share one)", len(ids))
	}
	if ids[rows[0].SourceEventID] != 2 {
		t.Errorf("identical context payloads did not share a SourceEventID: %v", ids)
	}
}

// TestToolResultErrorStamping: is_error=true flips Success and populates
// ErrorMessage from the result body.
func TestToolResultErrorStamping(t *testing.T) {
	a, path := writeTranscript(t, []string{
		synthStart,
		`{"type":"message","id":"a1","timestamp":"2026-07-28T10:00:00.000Z","message":{"role":"assistant","modelId":"claude-opus-5","content":[{"type":"tool_use","id":"call_1","name":"Execute","input":{"command":"false"}}]}}`,
		`{"type":"message","id":"u1","timestamp":"2026-07-28T10:00:01.000Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","is_error":true,"content":"exit status 1"}]}}`,
	}, true)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	rows := eventsOfType(res, models.ActionRunCommand)
	if len(rows) != 1 {
		t.Fatalf("run_command rows=%d want 1", len(rows))
	}
	ev := rows[0]
	if ev.Success {
		t.Error("Success=true on an is_error result")
	}
	if ev.ErrorMessage != "exit status 1" {
		t.Errorf("ErrorMessage=%q want the failure body", ev.ErrorMessage)
	}
	if ev.Target != "false" {
		t.Errorf("Target=%q want the command input", ev.Target)
	}
	if ev.Model != "claude-opus-5" {
		t.Errorf("Model=%q want the assistant modelId", ev.Model)
	}
}

// TestContextCancellation: a cancelled context aborts the line loop.
func TestContextCancellation(t *testing.T) {
	a, path := writeTranscript(t, []string{synthStart, synthPrompt("m1", "x")}, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ParseSessionFile(ctx, path, 0); err == nil {
		t.Error("want an error from a cancelled context")
	}
}

// TestParseMissingFile surfaces a wrapped error.
func TestParseMissingFile(t *testing.T) {
	a := New()
	_, err := a.ParseSessionFile(context.Background(), filepath.Join(t.TempDir(), "nope.jsonl"), 0)
	if err == nil {
		t.Fatal("want an error for a missing transcript")
	}
	if !strings.Contains(err.Error(), "droid.ParseSessionFile") {
		t.Errorf("err=%v want the droid.ParseSessionFile wrap", err)
	}
}

// --- cross-tick tool_use → tool_result pairing (adapter.DeferUnpairedTail)

// appendLine appends one more JSONL record to a staged transcript, the
// way droid does while a session runs.
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

const (
	synthToolUse = `{"type":"message","id":"a1","timestamp":"2026-07-28T10:00:00.000Z","message":{"role":"assistant","modelId":"claude-opus-5","content":[{"type":"tool_use","id":"call_1","name":"Execute","input":{"command":"false"}}]}}`
	synthToolErr = `{"type":"message","id":"u1","timestamp":"2026-07-28T10:00:01.000Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","is_error":true,"content":"exit status 1"}]}}`
)

// TestToolResultLandsOnNextPollTick is the regression for the
// cross-parse tool_result loss. Tick N sees the tool_use but not yet its
// result; tick N+1 sees the result. The pair MUST resolve into exactly
// one action row carrying the real outcome — the store's action
// ON CONFLICT clause updates neither `success` nor `error_message`, so a
// row shipped optimistically in tick N could never be corrected.
func TestToolResultLandsOnNextPollTick(t *testing.T) {
	a, path := writeTranscript(t, []string{synthStart, synthToolUse}, true)

	// Tick N: the result hasn't been written yet.
	res1, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("tick N: %v", err)
	}
	for _, ev := range res1.ToolEvents {
		if ev.ActionType == models.ActionRunCommand {
			t.Fatalf("tick N shipped an unanswered tool call (Success=%v, output=%q); "+
				"the outcome can never be corrected once persisted", ev.Success, ev.ToolOutput)
		}
	}
	if !res1.RetrySuggested {
		t.Error("a deferred tail must set RetrySuggested so the watcher keeps polling")
	}
	if res1.NewOffset != int64(len(synthStart)+1) {
		t.Errorf("tick N NewOffset = %d, want the tool_use line start %d",
			res1.NewOffset, len(synthStart)+1)
	}

	// Tick N+1: droid writes the tool_result.
	appendLine(t, path, synthToolErr)
	res2, err := a.ParseSessionFile(context.Background(), path, res1.NewOffset)
	if err != nil {
		t.Fatalf("tick N+1: %v", err)
	}
	rows := eventsOfType(res2, models.ActionRunCommand)
	if len(rows) != 1 {
		t.Fatalf("tick N+1 run_command rows = %d, want exactly 1", len(rows))
	}
	if rows[0].Success {
		t.Error("resumed pair kept Success=true; the is_error result was lost")
	}
	if rows[0].ErrorMessage != "exit status 1" {
		t.Errorf("ErrorMessage = %q, want the result body", rows[0].ErrorMessage)
	}
	if rows[0].ToolOutput != "exit status 1" {
		t.Errorf("ToolOutput = %q, want the result body", rows[0].ToolOutput)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if res2.NewOffset != info.Size() {
		t.Errorf("tick N+1 NewOffset = %d, want EOF %d", res2.NewOffset, info.Size())
	}
}

// TestUnpairedToolUseFlushedWhenTranscriptGoesStale pins the first
// deferral bound: an interrupted session never writes the result, so the
// call must eventually be emitted with its optimistic outcome rather
// than stalling the cursor forever.
func TestUnpairedToolUseFlushedWhenTranscriptGoesStale(t *testing.T) {
	a, path := writeTranscript(t, []string{synthStart, synthToolUse}, true)
	old := time.Now().Add(-2 * adapter.PendingResultGrace)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(eventsOfType(res, models.ActionRunCommand)) != 1 {
		t.Fatalf("a stale unanswered call must still be emitted: %+v", res.ToolEvents)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != info.Size() {
		t.Errorf("stale flush must advance the cursor to EOF: %d != %d", res.NewOffset, info.Size())
	}
	if res.RetrySuggested {
		t.Error("a flushed tail must not ask for a retry")
	}
}

// TestUnpairedToolUseFlushedWhenTailGrows pins the second deferral
// bound: a transcript that has written far past an unanswered call is
// plainly not waiting on it, so ingestion must not be held back.
func TestUnpairedToolUseFlushedWhenTailGrows(t *testing.T) {
	filler := synthPrompt("m9", strings.Repeat("x", 4096))
	lines := []string{synthStart, synthToolUse}
	for i := 0; i*len(filler) <= adapter.MaxDeferTailBytes; i++ {
		lines = append(lines, filler)
	}
	a, path := writeTranscript(t, lines, true)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(eventsOfType(res, models.ActionRunCommand)) != 1 {
		t.Fatal("an unanswered call far behind the write head must be flushed, not deferred")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != info.Size() {
		t.Errorf("NewOffset = %d, want EOF %d", res.NewOffset, info.Size())
	}
}

// TestResumedParseReplaysPrefixState pins the state-only prefix replay:
// a resumed parse must inherit the running model id and the last
// user_only host notice from bytes it does not re-emit. Without the
// replay the resumed rows carry Model="" and the failed turn outcome has
// no cause.
func TestResumedParseReplaysPrefixState(t *testing.T) {
	notice := `{"type":"message","id":"n1","timestamp":"2026-07-28T10:00:02.000Z","message":{"role":"user","visibility":"user_only","content":[{"type":"text","text":"No active subscription found."}]}}`
	assistant := `{"type":"message","id":"a2","timestamp":"2026-07-28T10:00:03.000Z","message":{"role":"assistant","modelId":"custom:GPT-5.4-Mini-[OpenAI-BYOK]-0","content":[{"type":"text","text":"trying"}]}}`
	outcome := `{"type":"agent_turn_outcome","id":"o1","turnId":"t1","reason":"error","resultKind":"provider_error"}`

	a, path := writeTranscript(t, []string{synthStart, notice, assistant, outcome}, true)
	// Resume just past the assistant line, so the notice AND the model
	// are both behind the cursor.
	resumeAt := int64(len(synthStart) + 1 + len(notice) + 1 + len(assistant) + 1)
	res, err := a.ParseSessionFile(context.Background(), path, resumeAt)
	if err != nil {
		t.Fatal(err)
	}
	rows := eventsOfType(res, models.ActionAPIError)
	if len(rows) != 1 {
		t.Fatalf("api_error rows = %d, want 1: %+v", len(rows), res.ToolEvents)
	}
	if rows[0].Model != "custom:GPT-5.4-Mini-[OpenAI-BYOK]-0" {
		t.Errorf("Model = %q, want the modelId replayed from before the cursor", rows[0].Model)
	}
	if rows[0].ErrorMessage != "No active subscription found." {
		t.Errorf("ErrorMessage = %q, want the host notice replayed from before the cursor",
			rows[0].ErrorMessage)
	}
	if rows[0].Timestamp.IsZero() {
		t.Error("Timestamp is zero — the replayed last-seen record timestamp was lost")
	}
}
