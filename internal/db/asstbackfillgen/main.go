// Command asstbackfillgen generates internal/db/migrations/
// 078_assistant_text_action_type_relabel.sql — the historical repair
// that finishes the WP-T6/B2 assistant-text relabel sweep.
//
//	regenerate: make assistant-migration-build
//	drift gate: make verify-assistant-migration
//
// It is the SIBLING of internal/db/taxbackfillgen, deliberately not an
// extension of it. taxbackfillgen is sourced from internal/tooltax and
// is unknown-only: every statement it emits carries
// `AND action_type = 'unknown'`, so it can only ever move rows OUT of
// the unknown bucket. This generator rewrites rows that an adapter
// already classified (task_complete -> assistant_message), which is a
// strictly stronger operation and must never be folded into 077's
// output. Its source is also different: the `<tool>.assistant_text`
// family is a set of observer-SYNTHESIZED markers, not native tool
// names, so it has no place in the tooltax (tool, native name) table.
//
// The four-predicate guard every emitted statement carries is documented
// on the migration header below and enforced by main_test.go.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/genout"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// defaultOutDir is the directory holding the committed migration,
// relative to the repo root (where `make assistant-migration-build`
// runs). The drift gate points it at a scratch dir instead.
const defaultOutDir = "internal/db/migrations"

// migrationName is the committed file name. The generator owns it — the
// caller only chooses a directory — so the drift gate cannot diff the
// wrong file by accident. 078 is highest-applied (077) + 1.
const migrationName = "078_assistant_text_action_type_relabel.sql"

// oldType is the ONLY action type a statement may rewrite, and newType
// the only value it may write. Spelling both halves in the WHERE and
// the SET is what makes each statement a PAIR REWRITE rather than an
// assignment: a row an adapter deliberately typed something else
// survives untouched, and a second execution matches nothing.
const (
	oldType = models.ActionTaskComplete
	newType = models.ActionAssistantMessage
)

// claudeCodeHookSourceFile is the exact actions.source_file sentinel
// every claude-code HOOK row carries (cmd/observer/hook.go:
// baseToolEvent sets SourceFile: "claude-code:hook" for every hook
// event). The Stop hook is the one genuinely turn-terminal producer of
// `claudecode.assistant_text`, so its rows must keep task_complete —
// this is the carve-out a mechanical rewrite would get wrong.
// TestHookSourceFileSentinelMatchesHookWriter pins the spelling against
// the hook writer's own source.
const claudeCodeHookSourceFile = "claude-code:hook"

// site is one `<tool>.assistant_text` raw name plus every actions.tool
// value a row carrying it can have.
type site struct {
	// raw is the exact actions.raw_tool_name literal.
	raw string
	// tools are the exact actions.tool values a row with this raw name
	// can carry: the emit site's own Tool tag, PLUS every retag seam
	// that can relabel it after the fact (there are three in the tree —
	// codex -> open-interpreter, cline -> kilo-code, antigravity ->
	// antigravity-cli).
	tools []string
	// keepSourceFiles are exact actions.source_file sentinels whose rows
	// are genuinely turn-terminal and MUST keep task_complete.
	keepSourceFiles []string
	// emitSite documents where the rows come from; it is rendered into
	// the SQL so the migration explains itself.
	emitSite string
	// swept marks a raw name whose emit site this work package re-typed
	// (as opposed to one swept in an earlier cycle, whose task_complete
	// rows are pure stale history).
	swept bool
	// dynamicName marks a raw name the adapter BUILDS at runtime
	// (`toolID + ".assistant_text"`) rather than spelling as a literal,
	// so the source-literal conformance test knows not to look for it.
	dynamicName bool
}

// sites is the generator's table: the emit-site inventory, derived from
// the adapters, NOT from the corpus. Rows are grouped by why they need
// repairing.
//
// The (raw name -> tools) mapping is code-derived on purpose. Three
// adapters retag events after the parser built them, so the SAME raw
// name legitimately appears under more than one actions.tool value:
//
//   - internal/adapter/codex/adapter.go:747 (NewOpenInterpreter) retags
//     the entire codex parser's output to tool='open-interpreter';
//   - internal/adapter/kilocode/legacy.go:89 retags the cline parser's
//     output to tool='kilo-code';
//   - internal/adapter/antigravity/adapter.go:485 retags the CLI layout's
//     output to tool='antigravity-cli' (and migration 071 retagged the
//     historical rows the same way, by path).
//
// Missing one of those tools would leave a silent island of task_complete
// rows behind; scoping by tool is what keeps the rewrite exact.
var sites = []site{
	// ---------------------------------------------------------------
	// (a) The seven emit sites WP-T6/B2a re-typed. Their code now emits
	// assistant_message; everything already on disk says task_complete.
	// ---------------------------------------------------------------
	{
		raw:             "claudecode.assistant_text",
		tools:           []string{models.ToolClaudeCode},
		keepSourceFiles: []string{claudeCodeHookSourceFile},
		emitSite:        "internal/adapter/claudecode/adapter.go::assistantTextEvent (one row per text content block)",
		swept:           true,
	},
	{
		raw:      "codex.assistant_text",
		tools:    []string{models.ToolCodex, models.ToolOpenInterpreter},
		emitSite: "internal/adapter/codex/adapter.go::buildAgentMessageEvent (one row per agent_message)",
		swept:    true,
	},
	{
		raw:      "kilo-code-cli.assistant_text",
		tools:    []string{models.ToolKiloCodeCLI},
		emitSite: "internal/adapter/kilocode/adapter.go (one row per text part)",
		swept:    true,
	},
	{
		raw:      "aider.assistant_text",
		tools:    []string{models.ToolAider},
		emitSite: "internal/adapter/aider/parse.go::flushAssistant (seven prose boundaries)",
		swept:    true,
	},
	{
		raw:      "crush.assistant_text",
		tools:    []string{models.ToolCrush},
		emitSite: "internal/adapter/crush/adapter.go::assistantTextEvent (one row per text part)",
		swept:    true,
	},
	{
		raw:      "structured.assistant_text",
		tools:    []string{models.ToolAntigravity, models.ToolAntigravityCLI},
		emitSite: "internal/adapter/antigravity/structured.go (one row per synthesized step)",
		swept:    true,
	},
	{
		raw:      "transcript.assistant_text",
		tools:    []string{models.ToolAntigravity, models.ToolAntigravityCLI},
		emitSite: "internal/adapter/antigravity/transcript_cli.go (one row per MODEL/PLANNER_RESPONSE step)",
		swept:    true,
	},

	// ---------------------------------------------------------------
	// (b) The tools swept in an EARLIER cycle. Their code has emitted
	// assistant_message for a while; only history disagrees, so this is
	// pure repair with no semantic question attached.
	// ---------------------------------------------------------------
	{
		raw:      "cowork.assistant_text",
		tools:    []string{models.ToolCowork},
		emitSite: "internal/adapter/cowork/adapter.go (already emits assistant_message)",
	},
	{
		raw:      "cursor.assistant_text",
		tools:    []string{models.ToolCursor},
		emitSite: "internal/adapter/cursor/adapter.go (already emits assistant_message)",
	},
	{
		raw:         "cline.assistant_text",
		tools:       []string{models.ToolCline, models.ToolKiloCode},
		emitSite:    "internal/adapter/cline/adapter.go (raw name built as toolID+\".assistant_text\"; already emits assistant_message)",
		dynamicName: true,
	},
	{
		raw:         "roo-code.assistant_text",
		tools:       []string{models.ToolRooCode, models.ToolKiloCode},
		emitSite:    "internal/adapter/cline/adapter.go, roo-code tool id (same emit site as cline.assistant_text)",
		dynamicName: true,
	},
	{
		raw:      "opencode.assistant_text",
		tools:    []string{models.ToolOpenCode},
		emitSite: "internal/adapter/opencode/adapter.go (already emits assistant_message)",
	},
	{
		raw:      "openclaw.assistant_text",
		tools:    []string{models.ToolOpenClaw},
		emitSite: "internal/adapter/openclaw/adapter.go — THE EXEMPLAR: per-part assistant_message plus a separate stop-gated message.assistant.stop task_complete row",
	},
}

// header is the migration's own documentation, in the style of 077.
const header = `-- ` + migrationName + ` — GENERATED by internal/db/asstbackfillgen.
-- DO NOT EDIT BY HAND.
--
--   regenerate: make assistant-migration-build
--   drift gate: make verify-assistant-migration
--
-- WHAT THIS REPAIRS. The ` + "`" + `<tool>.assistant_text` + "`" + ` family is the model's
-- natural-language response text, recorded PER MESSAGE — one row per text
-- block / text part / prose chunk. Adapters historically typed those rows
-- ` + "`" + oldType + "`" + `, which is the wrong semantic label: the assistant talking
-- mid-turn is not a task completion (85-87 % of claude-code and codex turns
-- carry MORE THAN ONE such row). models.ActionAssistantMessage was added for
-- exactly this, five adapters were swept to it in an earlier cycle, and
-- WP-T6/B2a swept the remaining seven emit sites. This migration applies the
-- same relabel to the rows already on disk, so a per-type query stops being
-- silently wrong about which half of history it is reading.
--
-- WHAT STAYS ` + "`" + oldType + "`" + `. Evidence-grounded turn TERMINI: rows an adapter
-- emitted because the source stream said the turn ended. Those keep their
-- type and their own raw names — openclaw ` + "`" + `message.assistant.stop` + "`" + `
-- (stop-reason gated), kilo-code-cli ` + "`" + `assistant.stop` + "`" + `, opencode
-- ` + "`" + `complete:` + "`" + ` rows, codex's ` + "`" + `task_complete` + "`" + ` event_msg, cline
-- ` + "`" + `attempt_completion` + "`" + `, cline-cli ` + "`" + `submit_and_exit` + "`" + `, antigravity
-- ` + "`" + `structured.final_summary` + "`" + ` — none of which this migration can reach,
-- because it is scoped to exact ` + "`" + `.assistant_text` + "`" + ` raw names.
--
-- THE ONE NON-OBVIOUS CARVE-OUT. claude-code has TWO producers of
-- ` + "`" + `claudecode.assistant_text` + "`" + ` with genuinely different semantics: the
-- JSONL walker (one row per text block, mid-turn) and the Stop HOOK
-- (fires once on turn end, carries last_assistant_message). The hook rows
-- ARE turn-terminal and must keep ` + "`" + oldType + "`" + `. They are exactly separable
-- by ` + "`" + `source_file = '` + claudeCodeHookSourceFile + `'` + "`" + ` — every observer hook event
-- carries that sentinel and no transcript row ever does — so the
-- claude-code statement below carries an explicit carve-out. A blanket
-- rewrite over the raw name would mislabel those rows.
--
-- THE GUARD — four ANDed predicates, all four load-bearing:
--
--   1. EXACT OLD->NEW PAIR. ` + "`" + `SET action_type = '` + newType + `'` + "`" + ` always appears
--      together with ` + "`" + `AND action_type = '` + oldType + `'` + "`" + `, never a bare SET.
--      This is 078's replacement for 077's ` + "`" + `= 'unknown'` + "`" + ` guard: it makes
--      each statement a pair rewrite, so a row an adapter deliberately
--      typed something else is untouchable.
--   2. EXACT RAW-NAME LITERALS, never ` + "`" + `LIKE '%.assistant_text'` + "`" + `. 077's
--      rationale applies verbatim (SQLite LIKE is ASCII case-INSENSITIVE
--      and ` + "`" + `_` + "`" + ` is a wildcard — and these names are full of underscores),
--      plus a forward-compat hazard 077 did not face: a LIKE pattern would
--      silently capture any FUTURE ` + "`" + `.assistant_text` + "`" + ` name added after this
--      migration shipped, which by then may mean something else.
--   3. TOOL-SCOPED, one statement per actions.tool, exactly as 077 does.
--      Note a raw name can appear under more than one tool because three
--      adapters RETAG after parsing (codex -> open-interpreter, cline ->
--      kilo-code, antigravity -> antigravity-cli, the last of which
--      migration 071 also applied to history); every reachable tool is
--      enumerated, so no island of rows is left behind.
--   4. THE SOURCE-FILE CARVE-OUT described above. It is written
--      ` + "`" + `COALESCE(source_file, '') <> '...'` + "`" + ` because actions.source_file is
--      NULLable (001_initial.sql) and a bare ` + "`" + `<>` + "`" + ` is NULL — hence FALSE —
--      for a NULL source_file, which would silently SKIP walker rows that
--      have no source file rather than rewriting them.
--
-- IDEMPOTENT BY CONSTRUCTION. Predicate 1 means run 2 matches nothing: the
-- rows run 1 touched no longer have action_type = '` + oldType + `'.
--
-- NODE-LOCAL. actions.action_type is already on the org push wire; this
-- changes values, not shape, so there is no paired server migration.
`

// clause is one emitted UPDATE: one tool, its raw names, its carve-outs.
type clause struct {
	tool            string
	raws            []string
	keepSourceFiles []string
	notes           []string
}

func main() {
	outDir := flag.String("outdir", defaultOutDir, "directory the migration is written to")
	flag.Parse()

	data, err := generate()
	if err != nil {
		log.Fatalf("asstbackfillgen: %v", err)
	}
	if err := genout.WriteFile(filepath.Join(*outDir, migrationName), data); err != nil {
		log.Fatalf("asstbackfillgen: %v", err)
	}
}

// generate builds the migration's bytes from the site table. Pure: no
// clock, no environment, no filesystem.
func generate() ([]byte, error) {
	clauses, err := buildClauses()
	if err != nil {
		return nil, err
	}
	if len(clauses) == 0 {
		return nil, fmt.Errorf("no sites — refusing to emit a vacuous migration")
	}

	var buf bytes.Buffer
	buf.WriteString(header)
	for _, c := range clauses {
		buf.WriteString("\n")
		if err := writeClause(&buf, c); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// buildClauses inverts the site table into one clause per actions.tool.
//
// Grouping by tool means a tool's raw names share ONE statement, which is
// only sound if they also share the carve-out set — otherwise the
// carve-out would leak onto a raw name that never needed it. That is
// checked here rather than assumed.
func buildClauses() ([]clause, error) {
	byTool := map[string]*clause{}
	for _, s := range sites {
		if err := checkSQLSafe(s.raw); err != nil {
			return nil, fmt.Errorf("raw name %q: %w", s.raw, err)
		}
		if !strings.HasSuffix(s.raw, ".assistant_text") {
			return nil, fmt.Errorf("raw name %q is not in the .assistant_text family — this generator's scope is exactly that family", s.raw)
		}
		if len(s.tools) == 0 {
			return nil, fmt.Errorf("raw name %q has no tools — an unscoped rewrite is forbidden", s.raw)
		}
		for _, keep := range s.keepSourceFiles {
			if err := checkSQLSafe(keep); err != nil {
				return nil, fmt.Errorf("carve-out %q: %w", keep, err)
			}
		}
		for _, tool := range s.tools {
			if err := checkSQLSafe(tool); err != nil {
				return nil, fmt.Errorf("tool %q: %w", tool, err)
			}
			if tool == "" {
				return nil, fmt.Errorf("raw name %q has an empty tool — an unscoped rewrite is forbidden", s.raw)
			}
			c, ok := byTool[tool]
			if !ok {
				c = &clause{tool: tool, keepSourceFiles: append([]string(nil), s.keepSourceFiles...)}
				byTool[tool] = c
			} else if !sameSet(c.keepSourceFiles, s.keepSourceFiles) {
				return nil, fmt.Errorf("tool %q mixes carve-out sets (%v vs %v) across raw names — "+
					"grouping them into one statement would leak a carve-out",
					tool, c.keepSourceFiles, s.keepSourceFiles)
			}
			for _, existing := range c.raws {
				if existing == s.raw {
					return nil, fmt.Errorf("tool %q lists raw name %q twice", tool, s.raw)
				}
			}
			c.raws = append(c.raws, s.raw)
			c.notes = append(c.notes, s.raw+" — "+s.emitSite)
		}
	}

	tools := make([]string, 0, len(byTool))
	for tool := range byTool {
		tools = append(tools, tool)
	}
	sort.Strings(tools)

	out := make([]clause, 0, len(tools))
	for _, tool := range tools {
		c := byTool[tool]
		sort.Strings(c.raws)
		sort.Strings(c.notes)
		sort.Strings(c.keepSourceFiles)
		out = append(out, *c)
	}
	return out, nil
}

// sameSet reports whether two carve-out lists hold the same values.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// writeClause renders one UPDATE statement plus its provenance comment.
func writeClause(buf *bytes.Buffer, c clause) error {
	if len(c.raws) == 0 {
		return fmt.Errorf("clause for tool %q has no raw names", c.tool)
	}
	for _, n := range c.notes {
		fmt.Fprintf(buf, "-- %s\n", n)
	}
	fmt.Fprintf(buf, "UPDATE actions\n   SET action_type = %s\n", quote(newType))
	fmt.Fprintf(buf, " WHERE tool = %s\n", quote(c.tool))
	fmt.Fprintf(buf, "   AND action_type = %s\n", quote(oldType))
	if len(c.raws) == 1 {
		fmt.Fprintf(buf, "   AND raw_tool_name = %s", quote(c.raws[0]))
	} else {
		buf.WriteString("   AND raw_tool_name IN (\n")
		for i, r := range c.raws {
			sep := ","
			if i == len(c.raws)-1 {
				sep = ""
			}
			fmt.Fprintf(buf, "     %s%s\n", quote(r), sep)
		}
		buf.WriteString("   )")
	}
	for _, keep := range c.keepSourceFiles {
		fmt.Fprintf(buf, "\n   AND COALESCE(source_file, '') <> %s", quote(keep))
	}
	buf.WriteString(";\n")
	return nil
}

// quote renders a SQL string literal, doubling embedded quotes.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// checkSQLSafe rejects values that have no business in a generated SQL
// literal. A control character would still be quoted correctly, but it
// would also mean the site table picked up junk — better to fail
// generation than to ship it.
func checkSQLSafe(s string) error {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains a control character (%U)", r)
		}
	}
	return nil
}
