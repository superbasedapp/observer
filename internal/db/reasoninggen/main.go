// Command reasoninggen generates internal/db/migrations/
// 079_reasoning_row_convergence.sql — the historical half of the B3
// reasoning-convergence arc (docs/plans/b3-reasoning-convergence-plan-2026-07-31.md).
//
// It is the SIBLING of internal/db/asstbackfillgen, deliberately kept
// separate: 078 is a pure pair REWRITE (task_complete ->
// assistant_message) over rows an adapter classified, while 079 DELETES
// rows — a strictly more dangerous mode that gets its own artifact, its
// own drift gate and its own review surface. Folding a delete mode into
// the relabel generator would mean one regeneration mistake could turn a
// rewrite into a deletion.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/genout"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// defaultOutDir is the directory holding the committed migration,
// relative to the repo root (where `make reasoning-migration-build`
// runs). The drift gate points it at a scratch dir instead.
const defaultOutDir = "internal/db/migrations"

// migrationName is the committed file name. The generator owns it — the
// caller only chooses a directory — so the drift gate cannot diff the
// wrong file by accident. 079 is highest-applied (078) + 1.
const migrationName = "079_reasoning_row_convergence.sql"

// placeholderRawName is the EXACT actions.raw_tool_name literal the
// retired codex reasoning emit site wrote. Spelled as one literal and
// matched with `=`, never LIKE (078's rule: SQLite LIKE is ASCII
// case-INSENSITIVE and `_` is a wildcard — and these names are full of
// underscores).
const placeholderRawName = "codex.reasoning"

// placeholderActionType is the ONLY action_type a delete may match. It
// is the type the retired emit site wrote for 100 % of the family
// (docs/audits/wpt6-cli-probes-2026-07-31/b2-investigation.md §2.1:
// `%.reasoning` = 15,615 rows, 100 % task_complete), so requiring it
// makes the delete blind to any row somebody re-typed on purpose.
const placeholderActionType = models.ActionTaskComplete

// The two placeholder TARGET shapes the retired producer could emit.
//
// The codex reasoning row carried the reasoning's readable summary in
// `target` when one existed. When none did — the overwhelming majority:
// 15,040 of the 15,369 historical codex rows — it carried one of two
// CONTENT-FREE placeholders instead:
//
//	"(reasoning)"                        — no summary, no encrypted body
//	"(encrypted reasoning, %d bytes)"    — fmt.Sprintf over len(encrypted)
//
// Both are recorded in the plan (§0.1) and the second is witnessed
// verbatim in the probe corpus
// (docs/audits/wpt6-cli-probes-2026-07-31/interpreter-findings.md:31,
// `(encrypted reasoning, 972 bytes)`). The emit site itself is gone —
// codex/adapter.go:1909 now documents its removal — so the shapes are
// pinned here rather than derived from live code.
const (
	placeholderExactTarget = "(reasoning)"
	placeholderEncPrefix   = "(encrypted reasoning, "
	placeholderEncSuffix   = " bytes)"
)

// digitSet is the character class the printf tail's `%d` can produce.
// The middle segment is required to trim to empty against it, which is
// SQLite's LIKE-free, GLOB-free way of saying "these are all digits".
const digitSet = "0123456789"

// The numeric segment is matched as a CANONICAL positive `%d`, not as
// "some digits". `fmt.Sprintf("(encrypted reasoning, %d bytes)", n)` with
// n = len(encrypted body) of a NON-EMPTY body can only ever render:
//
//   - no leading zero, and never a bare "0" — `%d` of a positive int has
//     a first digit in 1..9, and the producer only reached this branch
//     with a body to measure;
//   - at most 19 digits — n comes from len(), an int, and 19 is the
//     decimal width of the int64 ceiling (9223372036854775807). A
//     20-digit count cannot be a `%d` of any Go int on any platform.
//
// So `(encrypted reasoning, 0 bytes)`, `(… 0972 bytes)` and a 20-digit
// count are all shapes the retired producer could NOT emit — which
// means they are somebody else's string, and a DELETE must not reach
// them. Both bounds are expressed in the generated SQL and pinned by the
// migration test's surviving rows.
const (
	minPlaceholderDigit  = "1"
	maxPlaceholderDigit  = "9"
	maxPlaceholderDigits = 19
)

// markerKey is the schema_meta key 079 writes its ID high-water mark
// under.
//
// schema_meta is the repo's existing key/value table (001_initial.sql:3;
// `key TEXT PRIMARY KEY, value TEXT NOT NULL`), already written by the
// migration runner itself (internal/db/db.go:388) and by the path-hash
// backfill marker (db.go:595) — so a migration writing a KV row into it
// is an established mechanism, not a new one. Reusing it means 079
// creates NO table, which in turn means no new name for the org-push
// privacy sentinel to carry: schema_meta has never been on the wire
// (internal/store/orgpush.go selects no schema_meta column).
const markerKey = "migration_079_max_action_id"

// deleteTools are the actions.tool values whose codex-shaped placeholder
// rows this migration deletes.
//
// Both, not one: internal/adapter/codex/adapter.go::NewOpenInterpreter
// retags the ENTIRE codex parser's output to tool='open-interpreter',
// so the identical raw name and the identical placeholder targets appear
// under a second tool. Missing it would leave a silent island behind —
// the probe corpus caught exactly that shape
// (docs/audits/wpt6-cli-probes-2026-07-31/interpreter-findings.md:31).
var deleteTools = []string{models.ToolCodex, models.ToolOpenInterpreter}

// depMode says what happens to a dependent row: its own DELETE, or its
// action reference NULLed.
type depMode int

const (
	depDelete depMode = iota
	depNull
)

// dependency is one table that references actions(id) without
// ON DELETE CASCADE.
type dependency struct {
	table  string
	column string
	mode   depMode
	// why is rendered above the statement so the migration explains why
	// this table is handled the way it is.
	why string
}

// dependencies is the verified delete protocol, IN ORDER, transcribed
// from internal/retention/retention.go::deleteActionsOlder (:265 the
// excerpts/failure_context deletes, :304 the four NULLed reference
// columns) — the code path that already survived the live
// "FOREIGN KEY constraint failed (787)" regression of 2026-06-18. The
// column names are read from the DDL, not guessed:
// action_excerpts.action_id (001:161), failure_context.action_id
// (001:141), file_state.last_action_id (001:89),
// retrieval_signals.action_id (014:27), guard_events.action_id (040:52),
// process_runs.action_id (044:42), process_events.action_id (044:105).
var dependencies = []dependency{
	{
		table:  "action_excerpts",
		column: "action_id",
		mode:   depDelete,
		why: "FTS5 excerpts (001_initial.sql:160). The search path NEVER joins actions\n" +
			"-- (internal/compression/indexing/indexer.go), so a bare actions DELETE leaves\n" +
			"-- SEARCHABLE GHOSTS: rows the MCP search_past_outputs tool can still return\n" +
			"-- and whose action row no longer exists. ~15k of the delete candidates carry one.",
	},
	{
		table:  "failure_context",
		column: "action_id",
		mode:   depDelete,
		why: "failure_context.action_id is NOT NULL REFERENCES actions(id) (001_initial.sql:141),\n" +
			"-- so the row cannot survive its action — it is deleted, not NULLed.",
	},
	{
		table:  "file_state",
		column: "last_action_id",
		mode:   depNull,
		why: "file_state keeps its freshness value without the action link, so the\n" +
			"-- reference is NULLed rather than the row deleted (retention.go does the same).",
	},
	{
		table:  "retrieval_signals",
		column: "action_id",
		mode:   depNull,
		why: "retrieval_signals preserves the K43 long tail on purpose (014_retrieval_signals.sql\n" +
			"-- comment: \"orphan rows after action deletion are harmless\"); NULL the link.",
	},
	{
		table:  "guard_events",
		column: "action_id",
		mode:   depNull,
		why: "guard_events is an append-only, hash-CHAINED audit log with its own retention.\n" +
			"-- Deleting a row would break the chain; the action anchor is NULLed instead.",
	},
	{
		table:  "process_runs",
		column: "action_id",
		mode:   depNull,
		why:    "process_runs carries its own retention horizon and stays useful unattributed.",
	},
	{
		table:  "process_events",
		column: "action_id",
		mode:   depNull,
		why:    "process_events, same as process_runs.",
	},
}

// rewrite is one exact-pair action_type rewrite, in 078's vocabulary:
// the old type is named in the WHERE and the new one in the SET, so the
// statement can only ever convert oldType -> newType and a second
// execution matches nothing.
type rewrite struct {
	tool    string
	raw     string
	oldType string
	newType string
	why     string
}

// rewrites is fold-in A of the B3 plan (§0.6, §2d): the adjacent
// assistant-response family that 078's `.assistant_text`-scoped sweep
// could not reach.
//
// cursor IS included. internal/adapter/cursor/adapter.go:433 sets
// `ev.ActionType = models.ActionAssistantMessage` and
// `ev.RawToolName = "cursor.assistant_response"` on the SAME branch
// (EventAfterAgentResponse) — one unconditional pair, so every
// task_complete row under that name is stale history from before the
// sweep. The corpus agrees and says so unambiguously: the id ranges are
// DISJOINT, task_complete 3,414,956–3,890,894 entirely below
// assistant_message 4,433,781–4,438,297
// (docs/audits/wpt6-cli-probes-2026-07-31/b2-investigation.md §2.2).
//
// devin is DELIBERATELY EXCLUDED, and this is the load-bearing half of
// the fold-in. internal/adapter/devin/adapter.go:265-267 is a LIVE
// BRANCH, not a stale default:
//
//	action := models.ActionAssistantMessage
//	if len(cm.ToolCalls) == 0 && strings.EqualFold(metaFinish(cm.Metadata), "stop") {
//	    action = models.ActionTaskComplete
//	}
//
// A devin `devin.assistant_message` row typed task_complete therefore
// means "the provider's own finish_reason said stop AND the message
// requested no tools" — evidence-grounded terminality, exactly what
// models.ActionTaskComplete is for. Rewriting those 6 rows would destroy
// information the adapter deliberately recorded. They stay.
var rewrites = []rewrite{
	{
		tool:    models.ToolCursor,
		raw:     "cursor.assistant_response",
		oldType: models.ActionTaskComplete,
		newType: models.ActionAssistantMessage,
		why: "internal/adapter/cursor/adapter.go:433 (EventAfterAgentResponse) types this\n" +
			"-- assistant_message unconditionally; the task_complete rows are pre-sweep history\n" +
			"-- (disjoint id ranges, b2-investigation.md §2.2).",
	},
}

// header is the migration's own documentation, in the style of 077/078.
const header = `-- ` + migrationName + ` — GENERATED by internal/db/reasoninggen.
-- DO NOT EDIT BY HAND.
--
--   regenerate: make reasoning-migration-build
--   drift gate: make verify-reasoning-migration
--
-- APPLY-ONCE, AND WHY REGENERATING IS STILL CORRECT TODAY. Migrations are
-- keyed by version, not by content, so once a release has carried 079 its
-- bytes are frozen and a shape change needs a NEW migration. That line has
-- NOT been crossed: 079 is committed but UNRELEASED and applied nowhere
-- (the review's own node was verified at schema 78). Every regeneration
-- before the release that ships it is a normal edit of an unapplied file.
--
-- WHAT THIS REPAIRS (B3, docs/plans/b3-reasoning-convergence-plan-2026-07-31.md).
-- Model reasoning is NOT an action. It is something the model did on the way
-- to an action, and the taxonomy carries it as ` + "`" + `preceding_reasoning` + "`" + ` on the
-- successor event — grok's shape, which the B3 arc converged every adapter
-- onto. Fifteen emit sites used to mint a SEPARATE row for it instead, typed
-- ` + "`" + placeholderActionType + "`" + `, which produced 15,734 phantom "task completions" in the
-- live corpus. The emission half of B3 stopped all fifteen. This migration is
-- the historical half.
--
-- WHAT IT DELETES — and ONLY this. The codex/open-interpreter PLACEHOLDER
-- rows: the ` + "`" + placeholderExactTarget + "`" + ` and ` + "`" + placeholderEncPrefix + `N` + placeholderEncSuffix + "`" + ` rows the retired
-- emit site wrote when a reasoning item carried NO readable summary (15,040
-- of codex's 15,369). Those rows have no content, never had content, and
-- were never threaded anywhere: the encrypted body is opaque and the
-- placeholder string is a rendering of its LENGTH. Deleting them removes
-- rows, not information.
--
-- WHAT IT KEEPS. Everything content-bearing, including rows this migration
-- could technically reach:
--
--   * codex/open-interpreter reasoning rows whose target is REAL SUMMARY TEXT
--     (329 rows) — the predicate's target shapes exclude them by construction.
--   * gemini ` + "`" + `gemini.reasoning` + "`" + ` rows (15). Deleting them would be LOSSY and was
--     re-verified as such: their ` + "`" + `raw_tool_output` + "`" + ` holds 211–2,926 bytes while the
--     successor's ` + "`" + `preceding_reasoning` + "`" + ` holds a 200-char preview, and only 10 of
--     the 15 successors carry even that. The bytes exist in exactly one place.
--   * every other tool's reasoning rows (365 across 11 minority emitters).
--
-- ACCEPTED RESIDUE: ~679 content-bearing reasoning rows across 12 tools
-- survive this migration by design. They are historical rows of a shape no
-- adapter mints any more. A future arc may re-thread them onto their
-- successors; deleting them here would be data loss, and re-typing them
-- would be inventing a classification the producer never recorded.
--
-- THE DELETE PREDICATE — five ANDed conditions, all five load-bearing:
--
--   1. TOOL-SCOPED, one statement per actions.tool ('codex' and
--      'open-interpreter', the NewOpenInterpreter retag of the same parser).
--      Never an unscoped delete.
--   2. EXACT RAW-NAME LITERAL ` + "`" + placeholderRawName + "`" + `, never ` + "`" + `LIKE '%.reasoning'` + "`" + `.
--      077/078's rationale applies verbatim (SQLite LIKE is ASCII
--      case-INSENSITIVE and ` + "`" + `_` + "`" + ` is a wildcard) and the stakes are higher here:
--      a LIKE pattern would reach every OTHER tool's reasoning rows, which
--      this migration must not touch. NO LIKE and NO GLOB appears anywhere
--      in this file.
--   3. EXACT ACTION TYPE ` + "`" + placeholderActionType + "`" + `. A row somebody re-typed on
--      purpose is out of reach.
--   4. THE PRODUCER INVARIANT ` + "`" + `raw_tool_output = target` + "`" + `. The retired emit site
--      wrote the same placeholder string into both columns; a row where they
--      differ carries something the placeholder producer never wrote.
--   5. THE EXACT TARGET SHAPES. Either the literal ` + "`" + placeholderExactTarget + "`" + `, or the
--      printf tail ` + "`" + placeholderEncPrefix + `%d` + placeholderEncSuffix + "`" + ` matched as a CANONICAL
--      POSITIVE ` + "`" + `%d` + "`" + `, not as "some digits": prefix by substr, suffix by
--      substr from the end, the numeric segment bounded BETWEEN 1 AND 19
--      characters, its FIRST character bounded BETWEEN '1' AND '9', and the
--      whole segment required to trim to empty against the digit set. The
--      trim is how "all digits" is expressed without LIKE or GLOB (SQLite's
--      TRIM(X,Y) strips any Y-character from both ends, so a non-digit
--      anywhere survives and fails the test).
--
--      The two numeric bounds are not decoration. The producer's argument
--      was ` + "`" + `len(encrypted body)` + "`" + ` of a NON-EMPTY body, so ` + "`" + `%d` + "`" + ` could never
--      render a leading zero, never a bare ` + "`" + `0` + "`" + `, and never more than 19
--      digits (the decimal width of the int64 ceiling). Without these
--      bounds the predicate would reach ` + "`" + `(encrypted reasoning, 0 bytes)` + "`" + `,
--      ` + "`" + `(encrypted reasoning, 0972 bytes)` + "`" + ` and 20-digit counts — strings
--      this producer could not have written, i.e. somebody else's data.
--
-- THE HONEST CLAIM. This is PRODUCER-INVARIANT MATCHING, not a mathematical
-- proof of content-freeness. What is asserted: the predicate matches every
-- placeholder the retired producer could emit, and no row carrying real
-- summary text AND all five conditions was observed in the corpus. What is
-- NOT asserted: that no such row can exist. A reasoning summary whose text
-- happened to be exactly ` + "`" + placeholderExactTarget + "`" + ` — or exactly the printf rendering of its
-- own encrypted length — would be indistinguishable from a placeholder, and
-- would be deleted. That is the residual, stated rather than hidden.
--
-- A KNOWN, DELIBERATE UNDER-REACH: condition 4 does not match rows whose
-- ` + "`" + `raw_tool_output` + "`" + ` is NULL (the column arrived in migration 027; any
-- placeholder row older than that has none). Those rows survive. Relaxing
-- the invariant to reach them would trade a guard for a handful of rows —
-- the wrong trade for a DELETE.
--
-- BEFORE THE DELETE: THE DEPENDENCY PROTOCOL. Seven tables reference
-- actions(id) with no ON DELETE CASCADE. Two are cleared, five have their
-- reference NULLed, in the order verified by
-- internal/retention/retention.go::deleteActionsOlder — the path that
-- already survived the live "FOREIGN KEY constraint failed (787)" regression
-- (2026-06-18) that left the actions table un-pruned. Skipping
-- ` + "`" + `action_excerpts` + "`" + ` would be worse than a constraint error: FTS5 search never
-- joins actions, so the excerpts would become SEARCHABLE GHOSTS of rows that
-- no longer exist. Every dependent statement is scoped by the SAME candidate
-- predicate as the delete.
--
-- FOLD-IN: the cursor ` + "`" + `cursor.assistant_response` + "`" + ` pair rewrite that 078's
-- ` + "`" + `.assistant_text` + "`" + ` scoping could not reach. devin's ` + "`" + `devin.assistant_message` + "`" + `
-- task_complete rows are EXCLUDED — they come from a live branch keyed on the
-- provider's own finish_reason (adapter.go:265-267), which is exactly the
-- evidence ` + "`" + placeholderActionType + "`" + ` is for.
--
-- THE ID HIGH-WATER MARKER. Before anything is deleted, ` + "`" + `MAX(actions.id)` + "`" + ` is
-- recorded in schema_meta under ` + "`" + markerKey + "`" + `. actions.id is an
-- autoincrement rowid, i.e. insertion order, so "no phantom reasoning row was
-- minted after 079 applied" becomes a well-defined check: any offending row
-- has ` + "`" + `id > marker` + "`" + `. It is recorded BEFORE the delete on purpose — recording
-- it after would leave surviving pre-079 rows above the mark and make the
-- check produce false positives.
--
-- DECAY, HONESTLY. The migration runner is atomic, but it coordinates DB
-- WRITERS, not binary versions: an old daemon that is still running after 079
-- applies will keep minting the rows this migration just deleted. Nothing
-- here can prevent that, and no write-boundary enforcement is being added in
-- this arc — that is the accepted trade. What exists instead: the marker makes
-- the decay MEASURABLE, the release notes and the daemon-restart runbook carry
-- the restart requirement, and a generator-side AST guard makes re-introducing
-- an emit site un-shippable going forward.
--
-- ORG DIVERGENCE, ACCEPTED. Org push is append-only
-- (internal/store/orgpush.go) and the server has no retraction rail, so rows
-- already pushed stay in org rollups after this local delete. The org side
-- holds counts and metadata only — never the placeholder content, which was
-- content-free to begin with. No retraction mechanism exists or is being
-- added for this.
--
-- IDEMPOTENT BY CONSTRUCTION. The deletes match nothing on a second run (the
-- rows are gone); the rewrite is an exact old->new pair, so run 2 finds no
-- row at the old type; the marker INSERT is ` + "`" + `ON CONFLICT DO NOTHING` + "`" + `, so the
-- first-apply high-water mark is never overwritten.
--
-- NODE-LOCAL. No new table and no new column: schema_meta is the repo's
-- existing KV table and has never been on the org-push wire. actions.* shape
-- is unchanged, so there is no paired server migration.
`

func main() {
	outDir := flag.String("outdir", defaultOutDir, "directory the migration is written to")
	flag.Parse()

	data, err := generate()
	if err != nil {
		log.Fatalf("reasoninggen: %v", err)
	}
	if err := genout.WriteFile(filepath.Join(*outDir, migrationName), data); err != nil {
		log.Fatalf("reasoninggen: %v", err)
	}
}

// generate builds the migration's bytes from the tables above. Pure: no
// clock, no environment, no filesystem, no map iteration.
func generate() ([]byte, error) {
	if err := validate(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.WriteString(header)

	writeMarker(&buf)
	for _, tool := range deleteTools {
		if err := writeToolBlock(&buf, tool); err != nil {
			return nil, err
		}
	}
	for _, rw := range rewrites {
		writeRewrite(&buf, rw)
	}
	return buf.Bytes(), nil
}

// validate refuses to emit anything from a malformed table. Every check
// here is a way the generator could otherwise produce a DELETE that
// reaches further than intended.
func validate() error {
	if len(deleteTools) == 0 {
		return fmt.Errorf("no delete tools — refusing to emit a vacuous migration")
	}
	seenTool := map[string]bool{}
	for _, tool := range deleteTools {
		if tool == "" {
			return fmt.Errorf("empty tool — an unscoped delete is forbidden")
		}
		if seenTool[tool] {
			return fmt.Errorf("tool %q listed twice", tool)
		}
		seenTool[tool] = true
		if err := checkSQLSafe(tool); err != nil {
			return fmt.Errorf("tool %q: %w", tool, err)
		}
	}
	if !strings.HasSuffix(placeholderRawName, ".reasoning") {
		return fmt.Errorf("raw name %q is not in the .reasoning family — this generator's delete scope is exactly that family", placeholderRawName)
	}
	for _, s := range []string{
		placeholderRawName, placeholderActionType, placeholderExactTarget,
		placeholderEncPrefix, placeholderEncSuffix, digitSet, markerKey,
	} {
		if err := checkSQLSafe(s); err != nil {
			return fmt.Errorf("literal %q: %w", s, err)
		}
	}
	if placeholderExactTarget == "" || placeholderEncPrefix == "" || placeholderEncSuffix == "" {
		return fmt.Errorf("an empty placeholder shape would match far more than a placeholder")
	}
	if len(dependencies) == 0 {
		return fmt.Errorf("no dependency protocol — a bare actions DELETE leaves FTS ghosts and trips FK 787")
	}
	seenDep := map[string]bool{}
	for _, d := range dependencies {
		if d.table == "" || d.column == "" {
			return fmt.Errorf("dependency %+v is missing a table or column", d)
		}
		if seenDep[d.table] {
			return fmt.Errorf("dependency table %q listed twice", d.table)
		}
		seenDep[d.table] = true
		if err := checkSQLSafe(d.table); err != nil {
			return fmt.Errorf("dependency table %q: %w", d.table, err)
		}
		if err := checkSQLSafe(d.column); err != nil {
			return fmt.Errorf("dependency column %q: %w", d.column, err)
		}
	}
	for _, rw := range rewrites {
		if rw.tool == "" || rw.raw == "" {
			return fmt.Errorf("rewrite %+v is missing a tool or raw name — an unscoped rewrite is forbidden", rw)
		}
		if rw.oldType == "" || rw.newType == "" || rw.oldType == rw.newType {
			return fmt.Errorf("rewrite %+v is not an exact old->new pair", rw)
		}
		for _, s := range []string{rw.tool, rw.raw, rw.oldType, rw.newType} {
			if err := checkSQLSafe(s); err != nil {
				return fmt.Errorf("rewrite literal %q: %w", s, err)
			}
		}
	}
	return nil
}

// writeMarker emits the high-water-mark INSERT. It is the FIRST
// statement in the body: MAX(actions.id) must be read before any row is
// deleted (see the header).
func writeMarker(buf *bytes.Buffer) {
	buf.WriteString("\n-- ---------------------------------------------------------------\n")
	buf.WriteString("-- (0) ID high-water marker — recorded BEFORE anything is deleted.\n")
	buf.WriteString("--\n")
	buf.WriteString("-- actions.id is an autoincrement rowid, so it is insertion order. Any\n")
	buf.WriteString("-- reasoning row with id > this mark was minted AFTER 079 applied, which\n")
	buf.WriteString("-- is exactly the decay a still-running old daemon produces. ON CONFLICT\n")
	buf.WriteString("-- DO NOTHING keeps the FIRST apply's value authoritative.\n")
	buf.WriteString("-- ---------------------------------------------------------------\n")
	fmt.Fprintf(buf, "INSERT INTO schema_meta (key, value)\n")
	fmt.Fprintf(buf, "VALUES (%s, (SELECT CAST(COALESCE(MAX(id), 0) AS TEXT) FROM actions))\n", quote(markerKey))
	buf.WriteString("ON CONFLICT(key) DO NOTHING;\n")
}

// writeToolBlock emits one tool's dependency protocol followed by its
// actions DELETE. Order matters and is the point of the block: every
// dependent reference is cleared BEFORE the rows it points at go away.
func writeToolBlock(buf *bytes.Buffer, tool string) error {
	fmt.Fprintf(buf, "\n-- ---------------------------------------------------------------\n")
	fmt.Fprintf(buf, "-- %s — dependency protocol, then the placeholder delete.\n", tool)
	fmt.Fprintf(buf, "-- ---------------------------------------------------------------\n")

	for _, d := range dependencies {
		fmt.Fprintf(buf, "\n-- %s\n", d.why)
		switch d.mode {
		case depDelete:
			fmt.Fprintf(buf, "DELETE FROM %s\n WHERE %s IN (\n", d.table, d.column)
		case depNull:
			fmt.Fprintf(buf, "UPDATE %s\n   SET %s = NULL\n WHERE %s IN (\n", d.table, d.column, d.column)
		default:
			return fmt.Errorf("dependency %q has an unknown mode %d", d.table, d.mode)
		}
		buf.WriteString(candidateSubquery(tool))
		buf.WriteString(" );\n")
	}

	fmt.Fprintf(buf, "\n-- The delete itself. Same predicate, spelled inline.\n")
	fmt.Fprintf(buf, "DELETE FROM actions\n")
	buf.WriteString(predicate(tool, " "))
	buf.WriteString(";\n")
	return nil
}

// candidateSubquery renders the candidate-id SELECT used to scope every
// dependent statement. It is the SAME predicate as the delete's, so a
// dependent row can never be cleared for an action that survives.
func candidateSubquery(tool string) string {
	var b strings.Builder
	b.WriteString("   SELECT id\n     FROM actions\n")
	b.WriteString(predicate(tool, "    "))
	b.WriteString("\n")
	return b.String()
}

// predicate renders the ANDed delete conditions at the given indent. The
// substr/length offsets are DERIVED from the placeholder constants,
// never typed twice: a change to the printf shape moves them
// automatically.
func predicate(tool, indent string) string {
	prefixLen := len(placeholderEncPrefix)
	suffixLen := len(placeholderEncSuffix)
	// The numeric segment starts one character past the prefix and runs
	// to the start of the suffix, so its length is
	// length(target) - (prefix + suffix). Bounding that BETWEEN 1 AND 19
	// does two jobs at once: NON-EMPTY (so
	// "(encrypted reasoning,  bytes)" cannot match) and no wider than a
	// Go int can render.
	midStart := prefixLen + 1
	fixedLen := prefixLen + suffixLen

	var b strings.Builder
	fmt.Fprintf(&b, "%sWHERE tool = %s\n", indent, quote(tool))
	fmt.Fprintf(&b, "%s  AND action_type = %s\n", indent, quote(placeholderActionType))
	fmt.Fprintf(&b, "%s  AND raw_tool_name = %s\n", indent, quote(placeholderRawName))
	fmt.Fprintf(&b, "%s  AND raw_tool_output = target\n", indent)
	fmt.Fprintf(&b, "%s  AND (\n", indent)
	fmt.Fprintf(&b, "%s        target = %s\n", indent, quote(placeholderExactTarget))
	fmt.Fprintf(&b, "%s     OR (\n", indent)
	fmt.Fprintf(&b, "%s              substr(target, 1, %d) = %s\n", indent, prefixLen, quote(placeholderEncPrefix))
	fmt.Fprintf(&b, "%s          AND substr(target, -%d) = %s\n", indent, suffixLen, quote(placeholderEncSuffix))
	fmt.Fprintf(&b, "%s          AND length(target) - %d BETWEEN 1 AND %d\n", indent, fixedLen, maxPlaceholderDigits)
	fmt.Fprintf(&b, "%s          AND substr(target, %d, 1) BETWEEN %s AND %s\n",
		indent, midStart, quote(minPlaceholderDigit), quote(maxPlaceholderDigit))
	fmt.Fprintf(&b, "%s          AND trim(substr(target, %d, length(target) - %d), %s) = ''\n",
		indent, midStart, fixedLen, quote(digitSet))
	fmt.Fprintf(&b, "%s        )\n", indent)
	fmt.Fprintf(&b, "%s      )", indent)
	return b.String()
}

// writeRewrite emits one exact-pair action_type rewrite.
func writeRewrite(buf *bytes.Buffer, rw rewrite) {
	fmt.Fprintf(buf, "\n-- ---------------------------------------------------------------\n")
	fmt.Fprintf(buf, "-- Fold-in: %s / %s — exact pair rewrite, 078's vocabulary.\n", rw.tool, rw.raw)
	fmt.Fprintf(buf, "-- %s\n", rw.why)
	fmt.Fprintf(buf, "-- ---------------------------------------------------------------\n")
	fmt.Fprintf(buf, "UPDATE actions\n   SET action_type = %s\n", quote(rw.newType))
	fmt.Fprintf(buf, " WHERE tool = %s\n", quote(rw.tool))
	fmt.Fprintf(buf, "   AND action_type = %s\n", quote(rw.oldType))
	fmt.Fprintf(buf, "   AND raw_tool_name = %s;\n", quote(rw.raw))
}

// quote renders a SQL string literal, doubling embedded quotes.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// checkSQLSafe rejects values that have no business in a generated SQL
// literal. A control character would still be quoted correctly, but it
// would also mean a table above picked up junk — better to fail
// generation than to ship it.
func checkSQLSafe(s string) error {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains a control character (%U)", r)
		}
	}
	return nil
}
