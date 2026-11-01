// Command taxbackfillgen generates the tool-taxonomy backfill migration
// (internal/db/migrations/196_tooltax_action_type_backfill_2.sql) from
// internal/tooltax — the one owner of the cross-adapter tool/MCP
// taxonomy.
//
// It used to write 077_tooltax_action_type_backfill.sql. 077 shipped in
// v1.36.0 and is frozen by the released-step rule (D-880, T-982,
// docs/migration-numbering.md): a database that already ran a step never
// runs it again, so a regenerated 077 would reach fresh installs only. 196
// re-applies the FULL current table instead, which is safe on a database
// that ran 077 because every statement only moves rows out of 'unknown'.
// Once 196 ships, a tooltax change needs yet another new step: point
// migrationName at it and freeze 196 the same way.
//
// It exists because the plan (docs/plans/tool-taxonomy-standardization-
// plan-2026-07-31.md §3) requires the repair SQL to be SOURCED FROM the
// taxonomy table, never hand-edited: a transcription of ~500 (tool,
// native) pairs into SQL is a second source of truth by construction,
// and it would rot the first time a tooltax row moved.
//
// Run with `make taxonomy-migration-build`; the drift gate is
// `make verify-taxonomy-migration` (and TestGeneratedMatchesCommitted
// in this package, which fails the Go suite too).
//
// The generator is PURE: no clock, no environment, no filesystem reads.
// Output order is fully sorted (tools, then action types, then native
// names) so regeneration is byte-stable and a diff is reviewable.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// defaultOutDir is the directory holding the committed migration,
// relative to the repo root (where `make taxonomy-migration-build`
// runs). The drift gate points it at a scratch dir instead.
const defaultOutDir = "internal/db/migrations"

// migrationName is the committed file name. The generator owns it — the
// caller only chooses a directory — so the drift gate cannot diff the
// wrong file by accident. 196 is integ's number by agreement with the plans
// line (which holds 177-195); 077 stays as shipped in v1.36.0.
const migrationName = "196_tooltax_action_type_backfill_2.sql"

// wrapWidth is the column at which an IN (...) list wraps. Purely
// cosmetic, but fixed so the emitted bytes are deterministic.
const wrapWidth = 66

// knownActionTypes is the models.Action* mirror: every canonical action
// type the generator is allowed to emit. It is spelled with models
// constants on purpose — tooltax may not import internal/models (see
// internal/tooltax/doc.go), so THIS is the place a tooltax action type
// with no models constant becomes an error instead of a string that
// only exists in one package. TestKnownActionTypesCoverTooltax pins the
// set equality in both directions.
var knownActionTypes = map[string]bool{
	models.ActionReadFile:            true,
	models.ActionWriteFile:           true,
	models.ActionEditFile:            true,
	models.ActionRunCommand:          true,
	models.ActionSearchText:          true,
	models.ActionSearchFiles:         true,
	models.ActionWebSearch:           true,
	models.ActionWebFetch:            true,
	models.ActionBrowserAction:       true,
	models.ActionMCPCall:             true,
	models.ActionSpawnSubagent:       true,
	models.ActionTodoUpdate:          true,
	models.ActionTaskComplete:        true,
	models.ActionAskUser:             true,
	models.ActionUserPrompt:          true,
	models.ActionAssistantMessage:    true,
	models.ActionTurnAborted:         true,
	models.ActionContextCompacted:    true,
	models.ActionSystemPrompt:        true,
	models.ActionPromptContext:       true,
	models.ActionAPIError:            true,
	models.ActionToolFailure:         true,
	models.ActionSubagentStart:       true,
	models.ActionSubagentStop:        true,
	models.ActionSessionStart:        true,
	models.ActionSessionEnd:          true,
	models.ActionNotification:        true,
	models.ActionCwdChange:           true,
	models.ActionUserPromptExpansion: true,
	models.ActionPostToolBatch:       true,
	models.ActionPermissionRequest:   true,
	models.ActionPermissionDenied:    true,
	models.ActionPermissionMode:      true,
	models.ActionSetup:               true,
	models.ActionInstructionsLoaded:  true,
	models.ActionConfigChange:        true,
	models.ActionWorktreeCreate:      true,
	models.ActionWorktreeRemove:      true,
	models.ActionTaskEvent:           true,
	models.ActionRateLimit:           true,
	models.ActionSubagentWait:        true,
	models.ActionAgentMessage:        true,
	models.ActionAgentControl:        true,
	models.ActionSkillInvoke:         true,
	models.ActionSchedule:            true,
	models.ActionToolSearch:          true,
	models.ActionStdinWrite:          true,
	models.ActionHarnessCall:         true,
	models.ActionUnknown:             true,
}

// header is the migration's own documentation, in the style of 024 (the
// named precedent) and 071: what it repairs, how it is scoped, why it is
// idempotent, and what it deliberately leaves alone.
const header = `-- ` + migrationName + `: GENERATED by internal/db/taxbackfillgen
-- from internal/tooltax. DO NOT EDIT BY HAND.
--
--   regenerate: make taxonomy-migration-build
--   drift gate: make verify-taxonomy-migration
--
-- WHAT THIS REPAIRS. Migration 024 backfilled the Claude Code names that
-- the adapter's private actionMap already knew, and explicitly deferred
-- the rest: "adding categories for these is a separate taxonomy decision".
-- The tool-taxonomy plan (docs/plans/tool-taxonomy-standardization-plan-
-- 2026-07-31.md) is that decision. internal/tooltax now owns one canonical
-- (tool, native tool name) -> action_type table, WP-T3 pointed the
-- claude-code / codex / cowork adapters at it, and this migration applies
-- the SAME table to the rows already on disk: the agent-orchestration and
-- harness families that had no category when they were ingested (codex
-- wait / wait_agent / spawn_agent / send_message / write_stdin, claude-code
-- Monitor / SendMessage / Skill / ToolSearch / ScheduleWakeup /
-- StructuredOutput), plus every other name tooltax resolves, plus the
-- unresolved ` + "`" + tooltax.MCPPrefix + `` + "`" + `-namespace rows, which are an MCP identity and
-- not a guess.
--
-- SCOPE: action_type = 'unknown' ONLY. Every statement carries that
-- guard, so this migration can only ever move rows OUT of the unknown
-- bucket. A row an adapter already classified is never re-classified,
-- which means the deliberate adapter semantics the plan calls out stay
-- exactly as they are: the post_tool_batch shadow rows (an mcp__* name
-- recorded under a batch marker) and cowork's semantic remaps.
--
-- SCOPE: tool. actions.tool is a first-class NOT NULL column, so every
-- tool-specific statement scopes with a plain ` + "`" + `tool = '<tool>'` + "`" + ` predicate
-- (no join, no correlated subquery needed). Tool scoping is what keeps a
-- name that means different things in different harnesses from being
-- flattened; the tool-less statements at the end carry only the names
-- tooltax declares as unambiguous across every adapter.
--
-- PRECEDENCE. Statement order reproduces tooltax.Resolve's top-down walk,
-- and the 'unknown' guard is what makes order load-bearing: whichever
-- statement fires first wins, and later ones see a row that is no longer
-- unknown. The order is therefore, exactly as in the table:
--   1. tool-specific literal names;
--   2. tool-specific name PREFIXES;
--   3. tool-less (any-tool) literal names;
--   4. the tool-less ` + "`" + tooltax.MCPPrefix + `` + "`" + ` prefix, last.
--
-- EXACT, CASE-SENSITIVE MATCHING. Literal names use ` + "`" + `IN (...)` + "`" + ` and
-- prefixes use ` + "`" + `substr(raw_tool_name, 1, N) = '<prefix>'` + "`" + `, NOT ` + "`" + `LIKE` + "`" + `.
-- SQLite's LIKE is ASCII case-INSENSITIVE by default, which would widen a
-- prefix rule beyond what tooltax's own strings.HasPrefix does (and would
-- additionally need ESCAPE handling, since '_' is a LIKE wildcard and every
-- MCP prefix is full of them). substr equality on a BINARY-collated column
-- replays the Go matcher byte for byte. Note this deliberately does NOT
-- replay tooltax.Resolve's second, NORMALIZED pass (lower-cased, '_'/'-'/'.'
-- stripped): that pass is a runtime affordance for adapters that normalize
-- before switching, and replaying it in SQL would retag rows on a fuzzy
-- match. Historical repair takes the exact-name half only.
--
-- IDEMPOTENT. Re-running is a no-op: the first run cleared 'unknown' for
-- every row these predicates can reach, and nothing here can match a row
-- it already updated.
--
-- WHY A SECOND STEP. Migration 077 applied the table as it stood in
-- v1.36.0 and is frozen as shipped (released-step rule, D-880,
-- docs/migration-numbering.md). This step re-applies the FULL current
-- table, so a database that ran 077 picks up only the rows the newer table
-- names: rows 077 already moved out of 'unknown' are never touched again.
-- A later tooltax change goes into yet another new step, never into this
-- one once it has shipped.
--
-- NODE-LOCAL. actions.action_type is already on the org push wire; this
-- changes values, not shape, so there is no paired server migration.
`

// clause is one emitted UPDATE. Exactly one of literals / prefix is set.
type clause struct {
	// tool scopes the statement; empty means any tool.
	tool string
	// actionType is the canonical value the statement writes.
	actionType string
	// literals are exact native names, sorted.
	literals []string
	// prefix is a native-name prefix (a tooltax glob row with the
	// trailing "*" trimmed).
	prefix string
}

func main() {
	outDir := flag.String("outdir", defaultOutDir, "directory the migration is written to")
	flag.Parse()

	data, err := generate()
	if err != nil {
		log.Fatalf("taxbackfillgen: %v", err)
	}
	if err := write(filepath.Join(*outDir, migrationName), data); err != nil {
		log.Fatalf("taxbackfillgen: %v", err)
	}
}

// generate builds the migration's bytes from the tooltax table. Pure:
// no clock, no environment, no filesystem.
func generate() ([]byte, error) {
	clauses, err := buildClauses()
	if err != nil {
		return nil, err
	}
	if len(clauses) == 0 {
		return nil, fmt.Errorf("tooltax produced no clauses — refusing to emit a vacuous migration")
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

// buildClauses walks the tooltax table and produces the ordered clause
// list. The four precedence classes are emitted in the table's own
// order; WITHIN a class everything is sorted, so the output is stable.
func buildClauses() ([]clause, error) {
	table := tooltax.Table()

	// literals[tool][native] = action type, first row wins (tooltax
	// resolves top-down). A later row that disagrees is a genuine table
	// ambiguity and must be loud, not silently dropped.
	literals := map[string]map[string]string{}
	// prefixes[tool] = ordered, deduped glob rows.
	prefixes := map[string][]clause{}
	seenPrefix := map[string]string{}

	for _, e := range table {
		if e.ActionType == tooltax.ActionUnknown {
			// Rows that resolve to unknown ON PURPOSE (a native name
			// that was seen and deliberately not bucketed). Emitting
			// them would be a no-op UPDATE of 'unknown' to 'unknown'.
			continue
		}
		if !knownActionTypes[e.ActionType] {
			return nil, fmt.Errorf("tooltax row (%q, %q) has action type %q with no models.Action* constant",
				e.Tool, e.Native, e.ActionType)
		}
		if err := checkSQLSafe(e.Tool); err != nil {
			return nil, fmt.Errorf("tool %q: %w", e.Tool, err)
		}
		if err := checkSQLSafe(e.Native); err != nil {
			return nil, fmt.Errorf("native name %q (tool %q): %w", e.Native, e.Tool, err)
		}

		if e.IsGlob() {
			prefix := strings.TrimSuffix(e.Native, "*")
			if prefix == "" {
				return nil, fmt.Errorf("tool %q has a bare %q glob — it would match every row", e.Tool, e.Native)
			}
			key := e.Tool + "\x00" + prefix
			if prior, dup := seenPrefix[key]; dup {
				if prior != e.ActionType {
					return nil, fmt.Errorf("tool %q prefix %q resolves to both %q and %q",
						e.Tool, prefix, prior, e.ActionType)
				}
				continue
			}
			seenPrefix[key] = e.ActionType
			prefixes[e.Tool] = append(prefixes[e.Tool], clause{
				tool: e.Tool, actionType: e.ActionType, prefix: prefix,
			})
			continue
		}

		if literals[e.Tool] == nil {
			literals[e.Tool] = map[string]string{}
		}
		if prior, dup := literals[e.Tool][e.Native]; dup {
			if prior != e.ActionType {
				return nil, fmt.Errorf("tool %q name %q resolves to both %q and %q",
					e.Tool, e.Native, prior, e.ActionType)
			}
			continue
		}
		literals[e.Tool][e.Native] = e.ActionType
	}

	if err := checkPrefixOverlap(prefixes); err != nil {
		return nil, err
	}

	var out []clause
	// Classes 1 + 2: per tool, literals then prefixes.
	for _, tool := range sortedTools(literals, prefixes) {
		if tool == "" {
			continue
		}
		out = append(out, groupLiterals(tool, literals[tool])...)
		out = append(out, sortPrefixes(prefixes[tool])...)
	}
	// Class 3: tool-less literals.
	out = append(out, groupLiterals("", literals[""])...)
	// Class 4: tool-less prefixes — the mcp__ namespace, last.
	out = append(out, sortPrefixes(prefixes[""])...)
	return out, nil
}

// checkPrefixOverlap rejects two prefixes for the same tool where one is
// a prefix of the other AND they disagree on the action type: emission
// order would silently decide the winner, which is exactly the kind of
// implicit precedence this package exists to remove.
func checkPrefixOverlap(prefixes map[string][]clause) error {
	for tool, cs := range prefixes {
		for i := range cs {
			for j := range cs {
				if i == j || cs[i].actionType == cs[j].actionType {
					continue
				}
				if strings.HasPrefix(cs[i].prefix, cs[j].prefix) {
					return fmt.Errorf("tool %q: prefix %q (%s) is shadowed by %q (%s)",
						tool, cs[i].prefix, cs[i].actionType, cs[j].prefix, cs[j].actionType)
				}
			}
		}
	}
	return nil
}

// sortedTools returns every tool that owns at least one clause, sorted.
func sortedTools(literals map[string]map[string]string, prefixes map[string][]clause) []string {
	seen := map[string]bool{}
	for tool := range literals {
		seen[tool] = true
	}
	for tool := range prefixes {
		seen[tool] = true
	}
	out := make([]string, 0, len(seen))
	for tool := range seen {
		out = append(out, tool)
	}
	sort.Strings(out)
	return out
}

// groupLiterals collapses a tool's native names into one clause per
// action type, with both the action types and the names sorted.
func groupLiterals(tool string, names map[string]string) []clause {
	if len(names) == 0 {
		return nil
	}
	byType := map[string][]string{}
	for native, at := range names {
		byType[at] = append(byType[at], native)
	}
	types := make([]string, 0, len(byType))
	for at := range byType {
		types = append(types, at)
	}
	sort.Strings(types)

	out := make([]clause, 0, len(types))
	for _, at := range types {
		lits := byType[at]
		sort.Strings(lits)
		out = append(out, clause{tool: tool, actionType: at, literals: lits})
	}
	return out
}

// sortPrefixes orders a tool's glob clauses by (prefix, action type).
func sortPrefixes(cs []clause) []clause {
	out := make([]clause, len(cs))
	copy(out, cs)
	sort.Slice(out, func(i, j int) bool {
		if out[i].prefix != out[j].prefix {
			return out[i].prefix < out[j].prefix
		}
		return out[i].actionType < out[j].actionType
	})
	return out
}

// writeClause renders one UPDATE statement.
func writeClause(buf *bytes.Buffer, c clause) error {
	fmt.Fprintf(buf, "UPDATE actions\n   SET action_type = %s\n", quote(c.actionType))
	first := " WHERE"
	if c.tool != "" {
		fmt.Fprintf(buf, " WHERE tool = %s\n", quote(c.tool))
		first = "   AND"
	}
	fmt.Fprintf(buf, "%s action_type = %s\n", first, quote(tooltax.ActionUnknown))

	switch {
	case c.prefix != "":
		fmt.Fprintf(buf, "   AND substr(raw_tool_name, 1, %d) = %s;\n",
			len(c.prefix), quote(c.prefix))
	case len(c.literals) == 1:
		fmt.Fprintf(buf, "   AND raw_tool_name = %s;\n", quote(c.literals[0]))
	case len(c.literals) > 1:
		buf.WriteString("   AND raw_tool_name IN (\n")
		writeList(buf, c.literals)
		buf.WriteString("   );\n")
	default:
		return fmt.Errorf("clause for tool %q / %q has neither literals nor a prefix", c.tool, c.actionType)
	}
	return nil
}

// writeList renders the IN (...) body: quoted names, comma-separated,
// greedily wrapped at wrapWidth. Greedy wrapping over a sorted list is
// deterministic.
func writeList(buf *bytes.Buffer, names []string) {
	const indent = "     "
	line := indent
	for i, n := range names {
		tok := quote(n)
		if i < len(names)-1 {
			tok += ","
		}
		switch {
		case line == indent:
			line += tok
		case len(line)+1+len(tok) > wrapWidth:
			buf.WriteString(line + "\n")
			line = indent + tok
		default:
			line += " " + tok
		}
	}
	buf.WriteString(line + "\n")
}

// quote renders a SQL string literal, doubling embedded quotes.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// checkSQLSafe rejects values that have no business in a generated SQL
// literal. A control character or a newline in a tool/native name would
// still be quoted correctly, but it would also mean the taxonomy table
// picked up junk — better to fail generation than to ship it.
func checkSQLSafe(s string) error {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains a control character (%U)", r)
		}
	}
	return nil
}

// write puts the bytes at path, creating the parent directory when the
// gate points it at a scratch location.
func write(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	//nolint:gosec // G306: a committed, publicly-distributed source artifact; world-readable is intended.
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
