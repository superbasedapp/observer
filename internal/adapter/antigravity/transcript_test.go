package antigravity

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
)

// fixtureConversationID is the anonymized conversation uuid of
// testdata/antigravity/desktop (see testdata/antigravity/README.md).
const fixtureConversationID = "0f1e2d3c-4b5a-4c6d-8e9f-0a1b2c3d4e5f"

// desktopFixture is a desktop layout materialised in a temp $HOME with
// the anonymized transcript copied in.
type desktopFixture struct {
	adapter    *Adapter
	convRoot   string
	brainRoot  string
	transcript string
	pb         string
}

// setupDesktopTranscriptFixture copies the checked-in transcript into
// <home>/.gemini/antigravity/brain/<uuid>/.system_generated/logs/ and
// returns an adapter whose watch roots are BOTH desktop roots.
func setupDesktopTranscriptFixture(t *testing.T) desktopFixture {
	t.Helper()
	src := filepath.Join("..", "..", "..", "testdata", "antigravity", "desktop", "brain",
		fixtureConversationID, ".system_generated", "logs", "transcript.jsonl")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	home := t.TempDir()
	desktopRoot := filepath.Join(home, ".gemini", "antigravity")
	convRoot := filepath.Join(desktopRoot, "conversations")
	brainRoot := filepath.Join(desktopRoot, "brain")
	logsDir := filepath.Join(brainRoot, fixtureConversationID, ".system_generated", "logs")
	for _, d := range []string{convRoot, logsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	transcript := filepath.Join(logsDir, "transcript.jsonl")
	if err := os.WriteFile(transcript, body, 0o644); err != nil {
		t.Fatalf("write transcript: %v", err)
	}
	return desktopFixture{
		adapter:    NewWithOptions(nil, convRoot, brainRoot),
		convRoot:   convRoot,
		brainRoot:  brainRoot,
		transcript: transcript,
		pb:         filepath.Join(convRoot, fixtureConversationID+".pb"),
	}
}

func TestClassifyLayoutDesktopTranscript(t *testing.T) {
	const uuid = "0f1e2d3c-4b5a-4c6d-8e9f-0a1b2c3d4e5f"
	cases := []struct {
		name string
		path string
		want Layout
	}{
		{"unix transcript", "/home/u/.gemini/antigravity/brain/" + uuid + "/.system_generated/logs/transcript.jsonl", LayoutDesktopTranscript},
		{"windows transcript", `C:\Users\u\.gemini\antigravity\brain\` + strings.ToUpper(uuid) + `\.system_generated\logs\transcript.jsonl`, LayoutDesktopTranscript},
		{"wsl mount transcript", "/mnt/c/Users/u/.gemini/antigravity/brain/" + uuid + "/.system_generated/logs/transcript.jsonl", LayoutDesktopTranscript},
		{"transcript_full sibling", "/home/u/.gemini/antigravity/brain/" + uuid + "/.system_generated/logs/transcript_full.jsonl", LayoutUnknown},
		{"chunk rotation copy", "/home/u/.gemini/antigravity/brain/" + uuid + "/.system_generated/logs/chunks/transcript/00000000.jsonl", LayoutUnknown},
		{"legacy overview.txt", "/home/u/.gemini/antigravity/brain/" + uuid + "/.system_generated/logs/overview.txt", LayoutUnknown},
		{"step output", "/home/u/.gemini/antigravity/brain/" + uuid + "/.system_generated/steps/2/output.txt", LayoutUnknown},
		{"agy CLI brain tree", "/home/u/.gemini/antigravity-cli/brain/" + uuid + "/.system_generated/logs/transcript.jsonl", LayoutUnknown},
		{"non-uuid conversation dir", "/home/u/.gemini/antigravity/brain/notauuid/.system_generated/logs/transcript.jsonl", LayoutUnknown},
		{"desktop pb unchanged", "/home/u/.gemini/antigravity/conversations/" + uuid + ".pb", LayoutDesktop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyLayout(tc.path); got != tc.want {
				t.Errorf("classifyLayout(%q) = %v, want %v", tc.path, got, tc.want)
			}
			if tc.want == LayoutDesktopTranscript && desktopTranscriptConversationID(tc.path) != uuid {
				t.Errorf("desktopTranscriptConversationID(%q) = %q, want %q", tc.path, desktopTranscriptConversationID(tc.path), uuid)
			}
		})
	}
}

func TestDesktopTranscriptIsSessionFile(t *testing.T) {
	fx := setupDesktopTranscriptFixture(t)
	if !fx.adapter.IsSessionFile(fx.transcript) {
		t.Errorf("transcript under the brain watch root must be a session file: %s", fx.transcript)
	}
	if fx.adapter.IsSessionFile("/tmp/foreign/.gemini/antigravity/brain/" + fixtureConversationID + "/.system_generated/logs/transcript.jsonl") {
		t.Error("shape-match outside the watch roots must NOT match")
	}
	chunk := filepath.Join(fx.brainRoot, fixtureConversationID, ".system_generated", "logs", "chunks", "transcript", "00000000.jsonl")
	if fx.adapter.IsSessionFile(chunk) {
		t.Error("the chunk rotation copy must never be a session file (double ingest)")
	}
	// The CLI adapter never claims the desktop transcript.
	cli := NewCLI()
	cli.roots = []string{fx.brainRoot}
	if cli.IsSessionFile(fx.transcript) {
		t.Error("antigravity-cli adapter must not claim the desktop transcript")
	}
	// Roots: the desktop layout now has two.
	roots := defaultRootsForLayout("desktop")
	var sawBrain, sawConv bool
	for _, r := range roots {
		switch filepath.Base(r) {
		case "brain":
			sawBrain = true
		case "conversations":
			sawConv = true
		}
	}
	if !sawBrain || !sawConv {
		t.Errorf("defaultRootsForLayout(desktop) must carry brain/ AND conversations/: %v", roots)
	}
}

func TestParseDesktopTranscriptFixture(t *testing.T) {
	fx := setupDesktopTranscriptFixture(t)
	res, err := fx.adapter.ParseSessionFile(context.Background(), fx.transcript, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	fi, _ := os.Stat(fx.transcript)
	if res.NewOffset != fi.Size() {
		t.Errorf("NewOffset = %d, want file size %d", res.NewOffset, fi.Size())
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("transcript carries no usage; got %d TokenEvents", len(res.TokenEvents))
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}

	// Surface stamp: exactly one, ide/antigravity, on the conversation uuid.
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces = %+v, want exactly one", res.SessionSurfaces)
	}
	if s := res.SessionSurfaces[0]; s.SessionID != fixtureConversationID || s.Surface != models.SurfaceIDE || s.SurfaceHost != "antigravity" {
		t.Errorf("surface stamp = %+v, want {%s ide antigravity}", s, fixtureConversationID)
	}

	counts := map[string]int{}
	rawNames := map[string]int{}
	wantRoot, _ := rootFromWorkingDir(`c:\Users\dev\work\stepin`)
	for _, ev := range res.ToolEvents {
		counts[ev.ActionType]++
		rawNames[ev.RawToolName]++
		if ev.Tool != models.ToolAntigravity {
			t.Errorf("%s: Tool = %q", ev.SourceEventID, ev.Tool)
		}
		if ev.SessionID != fixtureConversationID {
			t.Errorf("%s: SessionID = %q", ev.SourceEventID, ev.SessionID)
		}
		if ev.SourceFile != fx.transcript {
			t.Errorf("%s: SourceFile = %q", ev.SourceEventID, ev.SourceFile)
		}
		if !strings.HasPrefix(ev.SourceEventID, transcriptEventIDPrefix+fixtureConversationID+":step:") {
			t.Errorf("SourceEventID %q not in the transcript namespace", ev.SourceEventID)
		}
		if ev.Model != "Gemini 3.6 Flash (High)" {
			t.Errorf("%s: Model = %q, want the settings-change display name", ev.SourceEventID, ev.Model)
		}
		if ev.ProjectRoot != wantRoot {
			t.Errorf("%s: ProjectRoot = %q, want %q (tool-call Cwd)", ev.SourceEventID, ev.ProjectRoot, wantRoot)
		}
		if ev.TurnIndex != 1 {
			t.Errorf("%s: TurnIndex = %d, want 1 (one USER_INPUT)", ev.SourceEventID, ev.TurnIndex)
		}
		if ev.Timestamp.IsZero() || ev.Timestamp.Year() != 2026 {
			t.Errorf("%s: Timestamp = %v", ev.SourceEventID, ev.Timestamp)
		}
	}
	want := map[string]int{
		models.ActionUserPrompt:       1,
		models.ActionAssistantMessage: 1,
		models.ActionSearchFiles:      3, // 2 list_dir + 1 find_by_name (GENERIC result)
		models.ActionReadFile:         1,
		models.ActionRunCommand:       4, // git status, python ×2, Remove-Item
		models.ActionWriteFile:        1,
		models.ActionEditFile:         1,
	}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s rows = %d, want %d (all counts %v)", k, counts[k], v, counts)
		}
	}
	if total := len(res.ToolEvents); total != 12 {
		t.Errorf("total events = %d, want 12 (%v)", total, counts)
	}
	for _, name := range []string{"list_dir", "view_file", "run_command", "write_to_file", "replace_file_content", "find_by_name", "transcript.user_input", "transcript.assistant_text"} {
		if rawNames[name] == 0 {
			t.Errorf("no row carries RawToolName %q (have %v)", name, rawNames)
		}
	}

	byID := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		byID[ev.SourceEventID] = ev
	}
	id := func(step int, suffix string) string {
		return transcriptEventIDPrefix + fixtureConversationID + ":step:" + itoa(step) + ":" + suffix
	}

	// USER_INPUT → user_prompt: the <USER_REQUEST> text only, no wrappers.
	up := byID[id(0, "user")]
	if !strings.HasPrefix(up.Target, "Summarise this repository") || strings.Contains(up.RawToolInput, "USER_SETTINGS_CHANGE") {
		t.Errorf("user_prompt Target/RawToolInput not unwrapped: %q / %q", up.Target, up.RawToolInput)
	}
	// git status: command Target, 289s wall time from the result header,
	// grouped under the planner step that invoked it.
	gs := byID[id(8, "tool")]
	if gs.Target != "git status" || gs.DurationMs != 289000 || gs.MessageID != transcriptEventIDPrefix+fixtureConversationID+":step:7" {
		t.Errorf("git status row = target %q duration %d message %q", gs.Target, gs.DurationMs, gs.MessageID)
	}
	if !strings.Contains(gs.ToolOutput, "working tree clean") {
		t.Errorf("run_command ToolOutput missing the command output: %q", gs.ToolOutput)
	}
	if !strings.Contains(gs.RawToolInput, `"Cwd"`) || strings.Contains(gs.RawToolInput, `\"git status\"`) {
		t.Errorf("RawToolInput must carry the UNWRAPPED args: %q", gs.RawToolInput)
	}
	// view_file: normalized path Target.
	vf := byID[id(6, "tool")]
	if wantPath := pathnorm.Normalize(`c:\Users\dev\work\stepin\README.md`); vf.Target != wantPath {
		t.Errorf("view_file Target = %q, want %q", vf.Target, wantPath)
	}
	// write_to_file: authored bytes counted, the planner's thinking rides along.
	wf := byID[id(10, "tool")]
	if wf.ContentBytes != int64(len("print(\"Hello World\")\n")) {
		t.Errorf("write_to_file ContentBytes = %d", wf.ContentBytes)
	}
	if !strings.Contains(wf.PrecedingReasoning, "Initiating Project Workspace") {
		t.Errorf("write_to_file PrecedingReasoning = %q", wf.PrecedingReasoning)
	}
	// replace_file_content: edit_file with the replacement counted.
	rf := byID[id(14, "tool")]
	if rf.ActionType != models.ActionEditFile || rf.ContentBytes != int64(len(`print("Hello Universe")`)) {
		t.Errorf("replace_file_content row = %s %d", rf.ActionType, rf.ContentBytes)
	}
	// GENERIC result paired with find_by_name: the tool name wins over
	// the type table's unknown fallback.
	fb := byID[id(22, "tool")]
	if fb.ActionType != models.ActionSearchFiles || fb.RawToolName != "find_by_name" {
		t.Errorf("GENERIC/find_by_name row = %s %q", fb.ActionType, fb.RawToolName)
	}
	// Final PLANNER_RESPONSE text → assistant_message.
	am := byID[id(23, "assistant")]
	if am.ActionType != models.ActionAssistantMessage || !strings.HasPrefix(am.Target, "### Project Summary") {
		t.Errorf("assistant row = %s %q", am.ActionType, am.Target)
	}
}

func TestParseDesktopTranscriptReparseIsStableAndCursorAware(t *testing.T) {
	fx := setupDesktopTranscriptFixture(t)
	ctx := context.Background()
	first, err := fx.adapter.ParseSessionFile(ctx, fx.transcript, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	// Cursor already at size: no work.
	same, err := fx.adapter.ParseSessionFile(ctx, fx.transcript, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(same.ToolEvents) != 0 || same.NewOffset != first.NewOffset {
		t.Errorf("parse at size must be a no-op: %d events, offset %d", len(same.ToolEvents), same.NewOffset)
	}
	// Any size change re-parses the whole file with IDENTICAL ids, so the
	// store's UNIQUE(source_file, source_event_id) index drops the repeats.
	again, err := fx.adapter.ParseSessionFile(ctx, fx.transcript, first.NewOffset-1)
	if err != nil {
		t.Fatalf("third parse: %v", err)
	}
	if len(again.ToolEvents) != len(first.ToolEvents) {
		t.Fatalf("re-parse emitted %d events, first emitted %d", len(again.ToolEvents), len(first.ToolEvents))
	}
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID != again.ToolEvents[i].SourceEventID {
			t.Errorf("event %d id drifted: %q vs %q", i, first.ToolEvents[i].SourceEventID, again.ToolEvents[i].SourceEventID)
		}
	}
}

// fakeCoverageReader returns fixed already-persisted Targets for one
// source file and records what it was asked for.
type fakeCoverageReader struct {
	askedFor []string
	user     []string
	asst     []string
}

func (f *fakeCoverageReader) LoadActionTargets(_ context.Context, sourceFile string) ([]string, []string, error) {
	f.askedFor = append(f.askedFor, sourceFile)
	return f.user, f.asst, nil
}

func TestParseDesktopTranscriptDedupsAgainstPBAugmentationRows(t *testing.T) {
	fx := setupDesktopTranscriptFixture(t)
	ctx := context.Background()
	// Without a .pb sibling nothing was ever persisted under the old
	// namespace — the reader must not even be consulted.
	reader := &fakeCoverageReader{}
	fx.adapter.WithTargetCoverageReader(reader)
	if _, err := fx.adapter.ParseSessionFile(ctx, fx.transcript, 0); err != nil {
		t.Fatal(err)
	}
	if len(reader.askedFor) != 0 {
		t.Errorf("coverage reader consulted without a .pb sibling: %v", reader.askedFor)
	}
	// With the sibling present, Targets the pre-cut-over augmentation
	// path persisted under the .pb's source_file suppress the text rows
	// (and only the text rows).
	if err := os.WriteFile(fx.pb, []byte("encrypted-opaque"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The store holds the 200-byte Target, exactly as the old augmentation
	// path truncated it — the match is byte-exact on that column.
	reader.user = []string{truncate("Summarise this repository in one paragraph.\r\n\r\nCreate a Python hello script and run it.\r\nChange it to print \"Hello Universe\" and run it again.\r\nDelete the script and confirm the directory no longer has it.", 200)}
	res, err := fx.adapter.ParseSessionFile(ctx, fx.transcript, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.askedFor) != 1 || reader.askedFor[0] != fx.pb {
		t.Errorf("coverage reader must be keyed on the sibling .pb: %v", reader.askedFor)
	}
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			t.Errorf("user_prompt already persisted under the .pb must be suppressed: %+v", ev.Target)
		}
	}
	if len(res.ToolEvents) != 11 {
		t.Errorf("expected 11 rows after suppressing the covered prompt, got %d", len(res.ToolEvents))
	}
}

func TestDesktopPBDefersToTranscriptSibling(t *testing.T) {
	fx := setupDesktopTranscriptFixture(t)
	ctx := context.Background()
	if err := os.WriteFile(fx.pb, []byte("encrypted-opaque-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := fx.adapter.ParseSessionFile(ctx, fx.pb, 0)
	if err != nil {
		t.Fatalf("pb parse: %v", err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Errorf(".pb must emit nothing when the transcript owns the conversation: %d/%d", len(res.ToolEvents), len(res.TokenEvents))
	}
	fi, _ := os.Stat(fx.pb)
	if res.NewOffset != fi.Size() {
		t.Errorf("cursor must advance past the skipped .pb: %d vs %d", res.NewOffset, fi.Size())
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "owns this conversation") {
		t.Errorf("first skip should say so once: %v", res.Warnings)
	}
	// Later rewrites of the .pb (it is rewritten per turn) stay silent.
	res, err = fx.adapter.ParseSessionFile(ctx, fx.pb, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("repeat skips must not warn: %v", res.Warnings)
	}
	// An adapter that does NOT watch brain/ keeps the pre-cut-over
	// behaviour (the guard is "this adapter owns the transcript", not
	// "the file exists").
	legacy := NewWithOptions(nil, fx.convRoot)
	res, err = legacy.ParseSessionFile(ctx, fx.pb, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "owns this conversation") {
			t.Errorf("guard fired for an adapter that does not watch brain/: %v", res.Warnings)
		}
	}
}

func TestModelFromSettingsChange(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"live wording", "<USER_REQUEST>\nhi\n</USER_REQUEST>\n<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 3.6 Flash (High). No need to comment on this change if the user doesn't ask about it.\n</USER_SETTINGS_CHANGE>", "Gemini 3.6 Flash (High)"},
		{"switch between models", "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from Gemini 3.6 Flash (High) to Claude Opus 4.6 (Thinking). No need to comment.\n</USER_SETTINGS_CHANGE>", "Claude Opus 4.6 (Thinking)"},
		{"no block", "<USER_REQUEST>\nhi\n</USER_REQUEST>", ""},
		{"block without a model rule", "<USER_SETTINGS_CHANGE>\nThe user changed setting `Theme` from Dark to Light.\n</USER_SETTINGS_CHANGE>", ""},
		{"placeholder enum is not a model", "last_selected_agent_model: MODEL_PLACEHOLDER_M71", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := modelFromSettingsChange(tc.content); got != tc.want {
				t.Errorf("modelFromSettingsChange = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDecodeToolArgsUnwrapsDoubleEncoding(t *testing.T) {
	calls := decodeTranscriptToolCalls([]byte(`[{"name":"run_command","args":{"CommandLine":"\"git status\"","Cwd":"\"c:\\\\work\"","WaitMsBeforeAsync":"5000","IsArtifact":"false","Plain":"already plain","Nested":{"k":1}}}]`))
	if len(calls) != 1 || calls[0].Name != "run_command" {
		t.Fatalf("decoded calls = %+v", calls)
	}
	args := decodeToolArgs(calls[0].Args)
	want := map[string]string{
		"CommandLine":       "git status",
		"Cwd":               `c:\work`,
		"WaitMsBeforeAsync": "5000",
		"IsArtifact":        "false",
		"Plain":             "already plain",
		"Nested":            `{"k":1}`,
	}
	for k, v := range want {
		if args[k] != v {
			t.Errorf("args[%s] = %q, want %q", k, args[k], v)
		}
	}
	if decodeTranscriptToolCalls([]byte(`not json`)) != nil || decodeTranscriptToolCalls(nil) != nil {
		t.Error("malformed / empty tool_calls must decode to nil")
	}
}

func TestSynthesizeDesktopTranscriptOrphanAndUnknownSteps(t *testing.T) {
	entries := []cliTranscriptEntry{
		{StepIndex: 0, Source: "USER_EXPLICIT", Type: "USER_INPUT", Status: "DONE", CreatedAt: "2026-01-15T09:00:00Z", Content: "<USER_REQUEST>\nrun it\n</USER_REQUEST>"},
		// A result with NO preceding tool_calls: the type table names
		// the action, the raw type rides on RawToolName.
		{StepIndex: 1, Source: "MODEL", Type: "RUN_COMMAND", Status: "DONE", CreatedAt: "2026-01-15T09:00:01Z", Content: "Created At: 2026-01-15T09:00:01Z\nCompleted At: 2026-01-15T09:00:03Z\n\nThe command completed successfully.\nOutput:\nok\n"},
		// A type the table has never seen: kept as unknown, never dropped.
		{StepIndex: 2, Source: "MODEL", Type: "BROWSER_PREVIEW", Status: "DONE", CreatedAt: "2026-01-15T09:00:04Z", Content: "Created At: 2026-01-15T09:00:04Z\nCompleted At: 2026-01-15T09:00:05Z\nopened http://localhost:3000"},
		// Empty content on an unseen type: still a row, Target = the type.
		{StepIndex: 3, Source: "SYSTEM", Type: "CHECKPOINT", Status: "DONE", CreatedAt: "2026-01-15T09:00:06Z"},
		// A planner step with neither text nor tool_calls contributes nothing.
		{StepIndex: 4, Source: "MODEL", Type: "PLANNER_RESPONSE", Status: "DONE", CreatedAt: "2026-01-15T09:00:07Z"},
		// A bad timestamp still yields a row.
		{StepIndex: 5, Source: "MODEL", Type: "PLANNER_RESPONSE", Status: "DONE", CreatedAt: "garbage", Content: "done"},
	}
	out := synthesizeDesktopTranscriptEvents(transcriptSynthInput{
		sessionPath:    "/x/transcript.jsonl",
		conversationID: "conv",
		projectRoot:    "/proj",
		entries:        entries,
	})
	if len(out) != 5 {
		t.Fatalf("got %d events, want 5: %+v", len(out), out)
	}
	orphan := out[1]
	if orphan.ActionType != models.ActionRunCommand || orphan.RawToolName != "transcript.run_command" || orphan.DurationMs != 2000 {
		t.Errorf("orphan RUN_COMMAND row = %s %q %d", orphan.ActionType, orphan.RawToolName, orphan.DurationMs)
	}
	if orphan.Target != "The command completed successfully." {
		t.Errorf("orphan Target should be the first non-header line, got %q", orphan.Target)
	}
	unknown := out[2]
	if unknown.ActionType != models.ActionUnknown || unknown.RawToolName != "transcript.browser_preview" || unknown.Target != "opened http://localhost:3000" {
		t.Errorf("unknown-type row = %s %q %q", unknown.ActionType, unknown.RawToolName, unknown.Target)
	}
	empty := out[3]
	if empty.ActionType != models.ActionUnknown || empty.Target != "checkpoint" {
		t.Errorf("empty unknown row = %s %q", empty.ActionType, empty.Target)
	}
	for _, ev := range out {
		if ev.Model != "" {
			t.Errorf("no settings change seen → Model must stay empty, got %q on %s", ev.Model, ev.SourceEventID)
		}
		if ev.Timestamp.IsZero() {
			t.Errorf("%s: zero timestamp", ev.SourceEventID)
		}
	}
}

func TestTranscriptResultDuration(t *testing.T) {
	cases := []struct {
		content string
		want    int64
	}{
		{"Created At: 2026-01-15T09:00:45Z\nCompleted At: 2026-01-15T09:05:34Z\nx", 289000},
		{"Created At: 2026-01-15T09:00:45Z\nx", 0},
		{"Created At: 2026-01-15T09:05:34Z\nCompleted At: 2026-01-15T09:00:45Z", 0},
		{"Created At: yesterday\nCompleted At: today", 0},
		{"", 0},
	}
	for _, tc := range cases {
		if got := transcriptResultDuration(tc.content); got != tc.want {
			t.Errorf("transcriptResultDuration(%q) = %d, want %d", tc.content, got, tc.want)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// TestParseDesktopTranscriptInFlightStepIsNotFrozen pins M4: a step the
// IDE has not finalised (status != DONE) emits nothing, so the partial
// content can never be the row that sticks under INSERT OR IGNORE; the
// finalised line lands on the next size change, and the FIFO pairing
// stays aligned across the in-flight step.
func TestParseDesktopTranscriptInFlightStepIsNotFrozen(t *testing.T) {
	fx := setupDesktopTranscriptFixture(t)
	ctx := context.Background()
	head := `{"step_index":0,"source":"USER_EXPLICIT","type":"USER_INPUT","status":"DONE","created_at":"2026-01-15T09:00:00Z","content":"<USER_REQUEST>\nrun it\n</USER_REQUEST>"}` + "\n" +
		`{"step_index":1,"source":"MODEL","type":"PLANNER_RESPONSE","status":"DONE","created_at":"2026-01-15T09:00:01Z","tool_calls":[{"name":"run_command","args":{"CommandLine":"\"python hello.py\""}}]}` + "\n"
	inFlight := head + `{"step_index":2,"source":"MODEL","type":"RUN_COMMAND","status":"RUNNING","created_at":"2026-01-15T09:00:02Z","content":"Created At: 2026-01-15T09:00:02Z\npartial output so far"}` + "\n" +
		`{"step_index":3,"source":"MODEL","type":"PLANNER_RESPONSE","status":"DONE","created_at":"2026-01-15T09:00:03Z","tool_calls":[{"name":"list_dir","args":{"DirectoryPath":"\"c:\\\\w\""}}]}` + "\n" +
		`{"step_index":4,"source":"MODEL","type":"LIST_DIRECTORY","status":"DONE","created_at":"2026-01-15T09:00:04Z","content":"Created At: 2026-01-15T09:00:04Z\nCompleted At: 2026-01-15T09:00:04Z\n{\"name\":\"README.md\"}"}` + "\n"
	if err := os.WriteFile(fx.transcript, []byte(inFlight), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := fx.adapter.ParseSessionFile(ctx, fx.transcript, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		ids[ev.SourceEventID] = ev
	}
	if _, frozen := ids[transcriptEventIDPrefix+fixtureConversationID+":step:2:tool"]; frozen {
		t.Fatal("an in-flight RUN_COMMAND step must emit nothing")
	}
	// The DONE list_dir after it must still pair with ITS OWN call, not
	// inherit the in-flight command's pending invocation.
	ld, ok := ids[transcriptEventIDPrefix+fixtureConversationID+":step:4:tool"]
	if !ok || ld.RawToolName != "list_dir" || ld.ActionType != models.ActionSearchFiles {
		t.Fatalf("list_dir after an in-flight step mis-paired: %+v", ld)
	}
	if len(res.ToolEvents) != 2 {
		t.Errorf("events = %d, want 2 (prompt + list_dir)", len(res.ToolEvents))
	}
	// The IDE finalises the line in place; the next size change lands it.
	finalised := strings.Replace(inFlight,
		`"status":"RUNNING","created_at":"2026-01-15T09:00:02Z","content":"Created At: 2026-01-15T09:00:02Z\npartial output so far"`,
		`"status":"DONE","created_at":"2026-01-15T09:00:02Z","content":"Created At: 2026-01-15T09:00:02Z\nCompleted At: 2026-01-15T09:00:09Z\n\nThe command exited with code 0.\nOutput:\nHello World\n"`, 1)
	if err := os.WriteFile(fx.transcript, []byte(finalised), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = fx.adapter.ParseSessionFile(ctx, fx.transcript, res.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	var landed bool
	for _, ev := range res.ToolEvents {
		if ev.SourceEventID == transcriptEventIDPrefix+fixtureConversationID+":step:2:tool" {
			landed = true
			if ev.RawToolName != "run_command" || ev.DurationMs != 7000 || !strings.Contains(ev.ToolOutput, "Hello World") {
				t.Errorf("finalised step landed with the wrong content: %+v", ev)
			}
		}
	}
	if !landed || len(res.ToolEvents) != 3 {
		t.Errorf("finalised step must land (%v), events = %d, want 3", landed, len(res.ToolEvents))
	}
}

func TestModelFromSettingsChangeLastBlockWins(t *testing.T) {
	content := "<USER_REQUEST>\nhi\n</USER_REQUEST>\n" +
		"<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 3.6 Flash (High). No need to comment.\n</USER_SETTINGS_CHANGE>\n" +
		"<USER_SETTINGS_CHANGE>\nThe user changed setting `Theme` from Dark to Light.\n</USER_SETTINGS_CHANGE>\n" +
		"<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from Gemini 3.6 Flash (High) to Claude Opus 4.6 (Thinking). No need to comment.\n</USER_SETTINGS_CHANGE>"
	if got := modelFromSettingsChange(content); got != "Claude Opus 4.6 (Thinking)" {
		t.Errorf("last block must win, got %q", got)
	}
}
