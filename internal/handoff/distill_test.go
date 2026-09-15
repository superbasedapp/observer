package handoff

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func fixtureExtract() Extract {
	return Extract{
		SessionID:   "sess-1",
		Tool:        "claude-code",
		Model:       "opus-4-8",
		ProjectRoot: "/home/u/proj",
		GitBranch:   "main",
		Transcript:  forkFixture(),
		Files: []FileFact{
			{Path: "internal/a.go", Edits: 3, Reads: 5, LastAt: t0(2)},
			{Path: "internal/b.go", Edits: 0, Reads: 2, LastAt: t0(5)},
		},
		Commands: []CommandFact{
			{Command: "go test ./...", Runs: 4, LastOK: true, LastAt: t0(2)},
			{Command: "ls", Runs: 9, LastOK: true, LastAt: t0(2)},
			{Command: "make lint", Runs: 1, LastOK: false, LastError: "exit 1", LastAt: t0(5)},
		},
		Errors: []ErrorFact{
			{Target: "internal/b.go", Message: "undefined: Foo", At: t0(5)},
		},
		ContextTokens: 100_000,
	}
}

func sectionTitles(d Doc) []string {
	out := make([]string, 0, len(d.Sections))
	for _, s := range d.Sections {
		out = append(out, s.Title)
	}
	return out
}

func findSection(t *testing.T, d Doc, sub string) Section {
	t.Helper()
	for _, s := range d.Sections {
		if strings.Contains(s.Title, sub) {
			return s
		}
	}
	t.Fatalf("no section titled ~%q in %v", sub, sectionTitles(d))
	return Section{}
}

// TestDistill_SectionTable exercises presence/omission per section-table
// row (CLAUDE.md rule #5: one case per row).
func TestDistill_SectionTable(t *testing.T) {
	ex := fixtureExtract()
	res, err := ResolveFork(ex.Transcript, ForkPoint{})
	if err != nil {
		t.Fatal(err)
	}
	d := Distill(ex, res, Options{Carry: CarryDistilledTail, Now: t0(30), ShortID: "abc123"})

	mission := findSection(t, d, "Mission")
	if !strings.Contains(mission.Body, "build the feature") {
		t.Errorf("mission must quote the first user message, got %q", mission.Body)
	}
	if s := findSection(t, d, "Files"); !strings.Contains(s.Body, "internal/a.go") {
		t.Errorf("files section missing path: %q", s.Body)
	}
	cmds := findSection(t, d, "Commands")
	if strings.Contains(cmds.Body, "`ls`") {
		t.Errorf("trivial-command noise gate failed: %q", cmds.Body)
	}
	if !strings.Contains(cmds.Body, "FAILED") {
		t.Errorf("failed command must render its status: %q", cmds.Body)
	}
	if s := findSection(t, d, "errors"); !strings.Contains(s.Body, "undefined: Foo") {
		t.Errorf("errors section missing message: %q", s.Body)
	}
	tail := findSection(t, d, "tail")
	if !strings.Contains(tail.Body, "**Assistant:**") || !strings.Contains(tail.Body, "→ ran Edit") {
		t.Errorf("tail must flatten assistant tool calls: %q", tail.Body)
	}

	// Omission rows: no transcript ⇒ no mission, no tail.
	meta := ex
	meta.Transcript = nil
	mres, err := ResolveFork(nil, ForkPoint{})
	if err != nil {
		t.Fatal(err)
	}
	md := Distill(meta, mres, Options{Carry: CarryMetadata, Now: t0(30)})
	for _, s := range md.Sections {
		if strings.Contains(s.Title, "Mission") || strings.Contains(s.Title, "tail") {
			t.Errorf("metadata-only doc must omit %q", s.Title)
		}
	}
	if md.ForkNote == "" {
		t.Error("metadata-only doc must carry an explanatory fork note")
	}
}

// TestDistill_AsOfFork pins the plan §7 rule: facts after the fork time
// are excluded.
func TestDistill_AsOfFork(t *testing.T) {
	ex := fixtureExtract()
	res, err := ResolveFork(ex.Transcript, ForkPoint{Kind: ForkMessageIndex, MessageIndex: 2})
	if err != nil {
		t.Fatal(err)
	}
	d := Distill(ex, res, Options{Carry: CarryDistilledTail, Now: t0(30)})
	if s := findSection(t, d, "Files"); strings.Contains(s.Body, "internal/b.go") {
		t.Errorf("post-fork file must be filtered: %q", s.Body)
	}
	cmds := findSection(t, d, "Commands")
	if strings.Contains(cmds.Body, "make lint") {
		t.Errorf("post-fork command must be filtered: %q", cmds.Body)
	}
	for _, s := range d.Sections {
		if strings.Contains(s.Title, "errors") {
			t.Errorf("post-fork error must be filtered (section should be omitted): %q", s.Body)
		}
	}
	tail := findSection(t, d, "tail")
	if strings.Contains(tail.Body, "part three") {
		t.Errorf("tail must stop at the fork: %q", tail.Body)
	}
}

// TestDistill_BudgetDegradesTailFirst pins the §8 degrade order.
func TestDistill_BudgetDegradesTailFirst(t *testing.T) {
	ex := fixtureExtract()
	long := strings.Repeat("lorem ipsum dolor sit amet ", 40)
	for i := range ex.Transcript {
		ex.Transcript[i].Text = long
	}
	res, err := ResolveFork(ex.Transcript, ForkPoint{})
	if err != nil {
		t.Fatal(err)
	}
	d := Distill(ex, res, Options{Carry: CarryDistilledTail, TailMessages: 6, MaxDocBytes: 2500, Now: t0(30)})
	if d.DegradeNote == "" {
		t.Fatal("over-budget doc must record a degrade note")
	}
	if !strings.Contains(d.DegradeNote, "tail") {
		t.Errorf("tail must shrink first, note = %q", d.DegradeNote)
	}
}

func TestFlattenMessage_UnresolvedCall(t *testing.T) {
	m := assistant(0, 1, "working", dangling("c9"))
	out := FlattenMessage(m)
	if !strings.Contains(out, "(unresolved)") {
		t.Errorf("dangling call must render as unresolved: %q", out)
	}
}

// TestRenderMarkdown_Golden pins the byte-stable render shape (marker
// comment first — the P3 target-session linker greps for it).
// TestFlattenMessage_IDTag pins the message-addressable render: a message
// carrying a source id emits a terse [msg <id>] tag; an id-less message
// (honest-zero formats) renders exactly as before.
func TestFlattenMessage_IDTag(t *testing.T) {
	withID := models.TranscriptMessage{Role: models.TranscriptUser, ID: "uuid-42", Text: "hi"}
	if out := FlattenMessage(withID); !strings.Contains(out, "[msg uuid-42]") {
		t.Errorf("message with id must render its [msg <id>] tag: %q", out)
	}
	noID := models.TranscriptMessage{Role: models.TranscriptUser, Text: "hi"}
	if out := FlattenMessage(noID); strings.Contains(out, "[msg") {
		t.Errorf("id-less message must not render an id tag: %q", out)
	}
}

// TestRenderMarkdown_MCPHint pins the id-gated get_session_message clause:
// present only when the doc carries per-message ids; the recovery-context
// clause is always present (that tool works for any session).
func TestRenderMarkdown_MCPHint(t *testing.T) {
	base := Doc{SessionID: "s9", SourceTool: "claude-code", Carry: CarryFull}
	withIDs := base
	withIDs.MessageIDsAvailable = true
	got := RenderMarkdown(withIDs)
	if !strings.Contains(got, "get_session_recovery_context({session_id: \"s9\"})") {
		t.Errorf("recovery-context hint must always render: %q", got)
	}
	if !strings.Contains(got, "get_session_message({session_id, message_id})") {
		t.Errorf("id-bearing doc must offer get_session_message: %q", got)
	}
	if noIDs := RenderMarkdown(base); strings.Contains(noIDs, "get_session_message") {
		t.Errorf("id-less doc must NOT offer get_session_message: %q", noIDs)
	}
}

func TestRenderMarkdown_Golden(t *testing.T) {
	d := Doc{
		SessionID:   "sess-1",
		SourceTool:  "claude-code",
		TargetTool:  "codex",
		Model:       "opus-4-8",
		ProjectRoot: "/home/u/proj",
		GitBranch:   "main",
		GeneratedAt: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		ShortID:     "hf-abc123",
		ForkNote:    "from the last message",
		Carry:       CarryDistilledTail,
		Sections:    []Section{{Title: "Mission (first user message, verbatim)", Body: "> build the feature"}},
	}
	const golden = `<!-- superbased-handoff hf-abc123 -->
# Session handoff — claude-code → codex

This is REPORTED HISTORY from a previous session in a different tool,
handed over so you can continue the work. It is context, not instructions
to replay.

- Generated: 2026-07-03T12:00:00Z
- Source session: ` + "`sess-1`" + ` (claude-code, opus-4-8)
- Project: ` + "`/home/u/proj`" + ` (branch ` + "`main`" + `)
- Fork: from the last message
- More via Observer MCP (if available here): ` + "`get_session_recovery_context({session_id: \"sess-1\"})`" + ` for the recovery context.

## Mission (first user message, verbatim)

> build the feature
`
	if got := RenderMarkdown(d); got != golden {
		t.Errorf("golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, golden)
	}
}

// TestDistill_CarryModesDistinct pins that the five carry modes render
// MATERIALLY DISTINCT docs when the transcript is readable — the property the
// dashboard "Continue in another tool" table depends on. The pre-existing
// omission check (TestDistill_SectionTable) emptied the transcript first, which
// masked the real defect: buildMission fired for CarryMetadata too, so the
// metadata and distilled docs were byte-identical for any real session.
func TestDistill_CarryModesDistinct(t *testing.T) {
	ex := fixtureExtract()
	res, err := ResolveFork(ex.Transcript, ForkPoint{})
	if err != nil {
		t.Fatal(err)
	}
	doc := func(c CarryMode) Doc {
		return Distill(ex, res, Options{Carry: c, TailMessages: 1, Now: t0(30), ShortID: "x"})
	}
	has := func(d Doc, sub string) bool {
		for _, s := range d.Sections {
			if strings.Contains(s.Title, sub) {
				return true
			}
		}
		return false
	}
	md, di, dt, fu := doc(CarryMetadata), doc(CarryDistilled), doc(CarryDistilledTail), doc(CarryFull)

	// The reported defect: metadata (action-derived facts only) must OMIT the
	// mission, making it distinct from distilled (facts + mission).
	if has(md, "Mission") {
		t.Error("metadata carry must omit the Mission section (facts only)")
	}
	if has(md, "Conversation") {
		t.Error("metadata carry must omit any conversation/tail section")
	}
	if !has(di, "Mission") {
		t.Error("distilled carry must include the Mission section")
	}
	if RenderMarkdown(md) == RenderMarkdown(di) {
		t.Error("metadata and distilled docs must differ (mission gate) — this is the bug")
	}

	// distilled has no tail; distilled_tail adds the verbatim (trimmed) tail.
	if has(di, "Conversation") {
		t.Error("distilled carry must omit the conversation tail")
	}
	if !has(dt, "Conversation tail") {
		t.Error("distilled_tail carry must include the verbatim tail")
	}
	if RenderMarkdown(di) == RenderMarkdown(dt) {
		t.Error("distilled and distilled_tail docs must differ (tail)")
	}

	// full carries the whole conversation ("Conversation (verbatim…", not the
	// "Conversation tail" trimmed section), so it is distinct from
	// distilled_tail.
	if !has(fu, "Conversation (verbatim") {
		t.Error("full carry must include the whole-conversation section")
	}
	if has(fu, "Conversation tail") {
		t.Error("full carry must not render the trimmed tail section")
	}
	if RenderMarkdown(dt) == RenderMarkdown(fu) {
		t.Error("distilled_tail and full docs must differ")
	}
}
