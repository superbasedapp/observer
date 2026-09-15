package handoff

import (
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Section is one titled block of the HandoverDoc.
type Section struct {
	Title string
	Body  string
}

// Doc is the structured handover payload (plan §8). It is delivered and
// forgotten — never persisted (the handoffs table stores counts and enums
// only).
type Doc struct {
	SessionID   string
	SourceTool  string
	TargetTool  string
	Model       string
	ProjectRoot string
	GitBranch   string
	GeneratedAt time.Time
	ShortID     string
	ForkNote    string
	Carry       CarryMode
	Sections    []Section
	// DegradeNote records budget-driven shrinking ("" = none).
	DegradeNote string
	// MessageIDsAvailable is true when the carried transcript exposes at
	// least one per-message id (the source format records one — claude-code
	// uuid). It gates the render's get_session_message MCP hint to the
	// honest case: a target can only pull a message by id when ids exist.
	MessageIDsAvailable bool
}

// Options steers distillation. Zero values resolve to the [handoff]
// config defaults at the boundary; the pure layer applies final fallbacks.
type Options struct {
	TargetTool   string
	Carry        CarryMode
	TailMessages int
	MaxDocBytes  int
	Now          time.Time
	ShortID      string
}

func (o Options) withDefaults() Options {
	if o.Carry == "" {
		o.Carry = CarryDistilledTail
	}
	if o.TailMessages <= 0 {
		o.TailMessages = 6
	}
	if o.MaxDocBytes <= 0 {
		o.MaxDocBytes = 48 * 1024
	}
	return o
}

// sectionBuilder is one row of the ordered section table (CLAUDE.md rule
// #5). Returning ok=false omits the section — never an empty or fabricated
// one (plan §8 honesty rule).
type sectionBuilder struct {
	name  string
	build func(ex Extract, res ForkResolution, opts Options) (Section, bool)
}

var sectionTable = []sectionBuilder{
	{name: "mission", build: buildMission},
	{name: "state", build: buildWorkingState},
	{name: "commands", build: buildCommands},
	{name: "errors", build: buildErrors},
	{name: "tail", build: buildTail},
}

// Distill builds the HandoverDoc from a fork-cut extract, walking the
// section table in order and degrading to the byte budget (tail shrinks
// first, then the command list — plan §8).
func Distill(ex Extract, res ForkResolution, opts Options) Doc {
	opts = opts.withDefaults()
	cut := cutExtract(ex, res)

	doc := Doc{
		SessionID:   ex.SessionID,
		SourceTool:  ex.Tool,
		TargetTool:  opts.TargetTool,
		Model:       ex.Model,
		ProjectRoot: ex.ProjectRoot,
		GitBranch:   ex.GitBranch,
		GeneratedAt: opts.Now,
		ShortID:     opts.ShortID,
		ForkNote:    forkNote(ex, res),
		Carry:       opts.Carry,
	}
	doc.MessageIDsAvailable = transcriptHasIDs(cut.Transcript)
	doc.Sections = buildSections(cut, res, opts)

	// Budget degrade: shrink the tail by halves, then elide commands, then
	// give up gracefully (an over-budget doc still renders).
	for len(RenderMarkdown(doc)) > opts.MaxDocBytes && opts.TailMessages > 1 {
		opts.TailMessages /= 2
		doc.Sections = buildSections(cut, res, opts)
		doc.DegradeNote = fmt.Sprintf("tail shrunk to %d messages to fit the byte budget", opts.TailMessages)
	}
	if len(RenderMarkdown(doc)) > opts.MaxDocBytes && len(cut.Commands) > 8 {
		cut.Commands = cut.Commands[:8]
		doc.Sections = buildSections(cut, res, opts)
		doc.DegradeNote = strings.TrimPrefix(doc.DegradeNote+"; command list elided to fit the byte budget", "; ")
	}
	return doc
}

func buildSections(cut Extract, res ForkResolution, opts Options) []Section {
	var out []Section
	for _, b := range sectionTable {
		if s, ok := b.build(cut, res, opts); ok {
			out = append(out, s)
		}
	}
	return out
}

// cutExtract applies the as-of-fork rule (plan §7): transcript truncated
// at the resolved cut; action facts filtered to timestamps at or before
// the fork time (kept in full when either side lacks timestamps).
func cutExtract(ex Extract, res ForkResolution) Extract {
	fullCut := res.ResolvedIndex == 0 || res.ResolvedIndex >= len(ex.Transcript)
	if res.ResolvedIndex > 0 && res.ResolvedIndex <= len(ex.Transcript) {
		ex.Transcript = ex.Transcript[:res.ResolvedIndex]
	}
	if fullCut || res.ForkTime.IsZero() {
		return ex
	}
	ft := res.ForkTime
	files := ex.Files[:0:0]
	for _, f := range ex.Files {
		if f.LastAt.IsZero() || !f.LastAt.After(ft) {
			files = append(files, f)
		}
	}
	ex.Files = files
	cmds := ex.Commands[:0:0]
	for _, c := range ex.Commands {
		if c.LastAt.IsZero() || !c.LastAt.After(ft) {
			cmds = append(cmds, c)
		}
	}
	ex.Commands = cmds
	errs := ex.Errors[:0:0]
	for _, e := range ex.Errors {
		if e.At.IsZero() || !e.At.After(ft) {
			errs = append(errs, e)
		}
	}
	ex.Errors = errs
	return ex
}

func forkNote(ex Extract, res ForkResolution) string {
	switch {
	case res.ResolvedIndex == 0:
		return "metadata-only (no readable transcript)"
	case res.Snapped:
		return res.Reason
	case res.ResolvedIndex == len(ex.Transcript):
		return "from the last message"
	default:
		return fmt.Sprintf("forked after message %d of %d", res.ResolvedIndex, len(ex.Transcript))
	}
}

const missionCap = 600

func buildMission(ex Extract, _ ForkResolution, opts Options) (Section, bool) {
	// The mission quote is the distilled-carry addition OVER metadata, which
	// is "action-derived facts only" (files/commands/errors, no transcript
	// prose). Gating it here on the carry mode is what makes the metadata and
	// distilled docs actually distinct — without this gate buildMission fires
	// for CarryMetadata too whenever the transcript is readable, so the two
	// modes render byte-identical (and price identically in the §9 table).
	if opts.Carry == CarryMetadata {
		return Section{}, false
	}
	for _, m := range ex.Transcript {
		if m.Role != models.TranscriptUser || strings.TrimSpace(m.Text) == "" {
			continue
		}
		return Section{Title: "Mission (first user message, verbatim)", Body: "> " + strings.ReplaceAll(capText(m.Text, missionCap), "\n", "\n> ")}, true
	}
	return Section{}, false
}

func buildWorkingState(ex Extract, _ ForkResolution, _ Options) (Section, bool) {
	if len(ex.Files) == 0 {
		return Section{}, false
	}
	var b strings.Builder
	for i, f := range ex.Files {
		if i >= 30 {
			fmt.Fprintf(&b, "- … and %d more files\n", len(ex.Files)-i)
			break
		}
		fmt.Fprintf(&b, "- `%s` — %d edits, %d reads\n", f.Path, f.Edits, f.Reads)
	}
	return Section{Title: "Files touched", Body: strings.TrimRight(b.String(), "\n")}, true
}

// trivialCommands is the noise gate (mirrors the advisor C4 finding: `ls`
// ×31 tops raw command lists).
var trivialCommands = map[string]bool{
	"ls": true, "pwd": true, "cd": true, "echo": true, "cat": true,
	"which": true, "true": true, "clear": true,
}

func buildCommands(ex Extract, _ ForkResolution, _ Options) (Section, bool) {
	var b strings.Builder
	n := 0
	for _, c := range ex.Commands {
		fields := strings.Fields(c.Command)
		if len(fields) == 0 || (len(fields) == 1 && trivialCommands[fields[0]]) {
			continue
		}
		if n >= 15 {
			b.WriteString("- …\n")
			break
		}
		status := "ok"
		if !c.LastOK {
			status = "FAILED"
			if c.LastError != "" {
				status += ": " + capText(c.LastError, 120)
			}
		}
		fmt.Fprintf(&b, "- `%s` — %d runs, last %s\n", capText(c.Command, 160), c.Runs, status)
		n++
	}
	if n == 0 {
		return Section{}, false
	}
	return Section{Title: "Commands run", Body: strings.TrimRight(b.String(), "\n")}, true
}

func buildErrors(ex Extract, _ ForkResolution, _ Options) (Section, bool) {
	if len(ex.Errors) == 0 {
		return Section{}, false
	}
	var b strings.Builder
	for i, e := range ex.Errors {
		if i >= 10 {
			break
		}
		fmt.Fprintf(&b, "- `%s`: %s\n", e.Target, capText(e.Message, 200))
	}
	return Section{Title: "Unresolved errors", Body: strings.TrimRight(b.String(), "\n")}, true
}

// transcriptHasIDs reports whether any carried message exposes a source
// per-message id (gates the render's get_session_message MCP hint).
func transcriptHasIDs(msgs []models.TranscriptMessage) bool {
	for _, m := range msgs {
		if m.ID != "" {
			return true
		}
	}
	return false
}

func buildTail(ex Extract, _ ForkResolution, opts Options) (Section, bool) {
	if len(ex.Transcript) == 0 {
		return Section{}, false
	}
	msgs := ex.Transcript
	title := "Conversation tail (verbatim, flattened)"
	switch opts.Carry {
	case CarryMetadata, CarryDistilled:
		return Section{}, false
	case CarryFull:
		title = "Conversation (verbatim, flattened)"
	case CarryFullCache:
		title = "Conversation (verbatim, flattened, full read content)"
	default:
		if len(msgs) > opts.TailMessages {
			msgs = msgs[len(msgs)-opts.TailMessages:]
		}
	}
	var b strings.Builder
	for _, m := range msgs {
		b.WriteString(FlattenMessage(m))
		b.WriteString("\n")
	}
	return Section{Title: title, Body: strings.TrimRight(b.String(), "\n")}, true
}

// FlattenMessage renders one normalized message per the plan §8 tail
// rules: plain role labels so the target model reads reported history
// (not turns to imitate); tool calls as one narration line each with
// their result excerpt attached (Phase 0 D-P0.3).
func FlattenMessage(m models.TranscriptMessage) string {
	var b strings.Builder
	label := "User"
	if m.Role == models.TranscriptAssistant {
		label = "Assistant"
	}
	// A terse per-message id tag (only when the source recorded one —
	// claude-code JSONL uuid) makes the message addressable: a target tool
	// with the Observer MCP can pull the full, un-excerpted message via
	// get_session_message({session_id, message_id: <id>}). Honest-zero
	// formats emit no tag.
	if m.ID != "" {
		fmt.Fprintf(&b, "**%s** [msg %s]**:** %s\n", label, m.ID, strings.TrimSpace(m.Text))
	} else {
		fmt.Fprintf(&b, "**%s:** %s\n", label, strings.TrimSpace(m.Text))
	}
	for _, c := range m.ToolCalls {
		fmt.Fprintf(&b, "  → ran %s %s\n", c.Name, c.InputExcerpt)
		if c.ResultExcerpt != "" {
			fmt.Fprintf(&b, "    result: %s\n", c.ResultExcerpt)
		} else if !c.Resolved {
			b.WriteString("    result: (unresolved)\n")
		}
	}
	if m.Truncated {
		b.WriteString("  [message truncated at read time]\n")
	}
	return b.String()
}

func capText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
