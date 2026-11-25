package main

// backfill_reasoning_converge.go — the historical half of B3's ACCEPTED
// RESIDUE (docs/plans/b3-reasoning-convergence-plan-2026-07-31.md,
// internal/db/migrations/079_reasoning_row_convergence.sql).
//
// B3's principle: model reasoning is NOT an action. It is something the
// model did on the way to an action, and the taxonomy carries it as
// `preceding_reasoning` on the SUCCEEDING row — never as a
// `task_complete` action of its own. Fifteen emit sites used to mint one
// anyway; the emission half of B3 stopped all fifteen and migration 079
// deleted the codex/open-interpreter PLACEHOLDER rows — the `(reasoning)`
// and `(encrypted reasoning, N bytes)` rows that carried no readable
// summary.
//
// 079 deliberately stopped there: every row whose target is REAL SUMMARY
// TEXT survived, because deleting those would be data loss. That survivor
// set is the residue this pass addresses — by CARRYING each row's text
// onto its successor first, and only then deleting the row.
//
// WHY THIS IS A DB-ONLY PASS AND NOT A SOURCE-FILE RE-WALK. The reasoning
// text is already in the DB in full: the retired emit sites wrote the
// 200-char preview to `target` and the untruncated body to
// `raw_tool_output`. Measured over a 695-row live residue, 682 rows carry
// a `raw_tool_output` and 681 of those have it either byte-equal to
// `target` or an exact prefix-extension of it — i.e. the same text,
// longer. Re-walking twelve adapters' source trees would reimplement
// twelve parsers to recover bytes that are one SELECT away, and would
// depend on files that may be gone. The single row where the two columns
// hold DIFFERENT text is not converged at all (see carryText).
//
// The prefix test is BYTE-wise on purpose. The retired emit sites cut the
// preview with a byte slice (`s[:200]`), so a preview can end mid-rune;
// a rune-wise comparison (SQLite's char-based substr, for one) then
// reports a divergence that is an artifact of the cut, not of the text.
//
// WHAT IS CARRIED. The longest PROVABLE rendition of the row's own text:
// `raw_tool_output` when it is a prefix-extension of `target`, else
// `target`. This deliberately exceeds the 200-char cap every live
// threading site applies — a pass that DELETES the only copy of a body
// must not also truncate it. `preceding_reasoning` is node-local and has
// never been selected by the org-push seam (internal/store/orgpush.go),
// so a longer historical value has no wire consequence.

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"sort"
	"strings"
)

// reasoningResidueSpec is one row of the candidate table: the EXACT
// (tool, raw_tool_name) pair a retired B3 emit site minted its
// `task_complete` reasoning rows under.
//
// Exact pairs only — never a LIKE/suffix match. 079's rationale applies
// verbatim: SQLite LIKE is ASCII case-insensitive and `_` is a wildcard,
// and a pattern here would reach rows this pass has no grounding for.
type reasoningResidueSpec struct {
	// Tool is the actions.tool value, matched with =.
	Tool string
	// RawToolName is the actions.raw_tool_name value, matched with =.
	RawToolName string
	// Site names the retired emit site the pair is grounded in, so a
	// future reader can check the claim rather than trust the table.
	Site string
}

// reasoningResidueSpecs is the candidate table — the ONE owner of "which
// rows are B3 reasoning residue". Every pair is grounded in a retired
// emit site named in the B3 plan's §1 matrix. Pairs with zero rows in any
// given corpus are harmless: they are exact matches, so they simply
// select nothing.
//
// Two documented ABSENCES: openclaw (openclaw/adapter.go:947) and copilot
// (copilot/adapter.go:225) are §1 matrix rows whose retired raw name is
// not recoverable from the shipped tree or from the corpus (neither tool
// has a surviving reasoning-shaped row). Guessing a name for a DELETE
// would be inventing a predicate, so they are omitted: a row this table
// does not name is a row this pass never touches.
var reasoningResidueSpecs = []reasoningResidueSpec{
	{"codex", "codex.reasoning", "codex/adapter.go:3065"},
	{"open-interpreter", "codex.reasoning", "codex/adapter.go:3065 (NewOpenInterpreter retag)"},
	{"kilo-code-cli", "kilo-code-cli.reasoning", "kilocode/adapter.go:786"},
	{"kilo-code", "cline.reasoning", "cline/adapter.go:504 (kilocode.LegacyAdapter retag)"},
	{"cowork", "cowork.reasoning", "cowork/adapter.go:786"},
	{"opencode", "opencode.reasoning", "opencode/adapter.go:734"},
	{"pi", "pi.reasoning", "pi/adapter.go:272"},
	{"hermes", "hermes.reasoning", "hermes/parse.go:321"},
	{"cline", "cline.reasoning", "cline/adapter.go:504"},
	{"gemini-cli", "gemini.reasoning", "gemini/parser.go:607"},
	{"cline-cli", "clinecli.reasoning", "clinecli/parse.go:655"},
	{"copilot-cli", "copilot-cli.reasoning", "copilotcli/events.go:813"},
	{"antigravity", "structured.reasoning", "antigravity/structured.go:565"},
	{"antigravity-cli", "structured.reasoning", "antigravity/structured.go:565"},
	{"crush", "crush.reasoning", "crush/adapter.go:371"},
	{"cursor", "cursor.thinking", "cursor/adapter.go:392, cursor/pending.go:24"},
}

// reasoningResidueOutcome names why a residue row ended where it did.
// Every candidate row gets exactly one.
type reasoningResidueOutcome string

const (
	// outcomeCarried — the text was written onto the successor's empty
	// preceding_reasoning. The row is deletable: its bytes moved.
	outcomeCarried reasoningResidueOutcome = "carried"
	// outcomePreserved — the successor already carried this exact text
	// (the adapters listed in B3 §1 as "ALREADY threads" wrote it at
	// ingest). Nothing to write; the row is deletable because its bytes
	// are already somewhere else.
	outcomePreserved reasoningResidueOutcome = "already_preserved"
	// outcomeOccupied — the successor's preceding_reasoning is non-empty
	// and does NOT contain this text. B3's never-overwrite rule forbids
	// writing; the bytes exist only on the residue row.
	outcomeOccupied reasoningResidueOutcome = "successor_occupied"
	// outcomeSuperseded — last-wins: a later reasoning row reached the
	// successor first, so this one was dropped exactly as the live
	// threading state drops it.
	outcomeSuperseded reasoningResidueOutcome = "superseded_last_wins"
	// outcomeTurnBoundary — a user_prompt ended the turn before any
	// successor consumed the text. B3 discards it rather than carrying
	// it across the boundary.
	outcomeTurnBoundary reasoningResidueOutcome = "turn_boundary_discarded"
	// outcomeNoSuccessor — the session held no further non-residue action.
	outcomeNoSuccessor reasoningResidueOutcome = "no_successor"
	// outcomeDivergent — raw_tool_output holds text that is NOT an
	// extension of target, so the row's full body cannot be carried
	// without inventing which of the two is "the reasoning". Never
	// touched, never deleted.
	outcomeDivergent reasoningResidueOutcome = "divergent_body"
)

// resolved reports whether the outcome's bytes provably survive the row's
// deletion. Only these outcomes are deletable by default.
func (o reasoningResidueOutcome) resolved() bool {
	return o == outcomeCarried || o == outcomePreserved
}

// reasoningAction is one row of a session's action timeline as the
// planner sees it. Residue is nil for ordinary actions.
type reasoningAction struct {
	ID                 int64
	ActionType         string
	PrecedingReasoning string
	// Residue is non-nil when this row is a B3 reasoning residue row.
	Residue *reasoningResidue
}

// reasoningResidue is the residue-specific payload of a candidate row.
type reasoningResidue struct {
	Tool          string
	RawToolName   string
	Target        string
	RawToolOutput string
}

// carryText returns the longest PROVABLE rendition of the row's own
// reasoning text, and whether the row is convergeable at all.
//
// `raw_tool_output` is preferred only when it is byte-equal to `target`
// or an exact prefix-extension of it — that is the proof that the two
// columns hold the same text and the longer one merely has more of it.
// Anything else (a body that diverges from the preview, or an empty
// target with no body) is not convergeable: choosing between two
// different strings would be inventing a classification the producer
// never recorded.
func (r reasoningResidue) carryText() (string, bool) {
	target := r.Target
	body := r.RawToolOutput
	switch {
	case target == "" && body == "":
		return "", false
	case body == "":
		return target, true
	case target == "":
		// No preview to prove the body against. The producer always
		// wrote target; a row without one is not a shape this pass
		// has grounding for.
		return "", false
	case body == target:
		return target, true
	case strings.HasPrefix(body, target):
		return body, true
	default:
		return "", false
	}
}

// reasoningCarry is one planned write: text onto ActionID's empty
// preceding_reasoning, sourced from ResidueID.
type reasoningCarry struct {
	ActionID  int64
	ResidueID int64
	Text      string
}

// reasoningDisposition is the planner's verdict for one residue row.
type reasoningDisposition struct {
	ResidueID int64
	Tool      string
	Outcome   reasoningResidueOutcome
	// Bytes is len(carried text) — what deletion would discard when the
	// outcome is unresolved.
	Bytes int
}

// reasoningPlan is the pure result of planning one session.
type reasoningPlan struct {
	Carries      []reasoningCarry
	Dispositions []reasoningDisposition
}

// planReasoningSession applies B3's four threading semantics to one
// session's ordered action timeline and returns what to write and what
// each residue row's fate is. Pure: no I/O, no DB, no clock.
//
// The semantics are the ones the shipped adapters implement (the
// reference implementation is crush's threadState, internal/adapter/
// crush/adapter.go — CONSUMED-ONCE, LAST-WINS, TURN-BOUNDARY DISCARD,
// SESSION-SCOPED), transposed from "events being built" to "rows already
// stored":
//
//   - CONSUMED-ONCE: the FIRST successor consumes the pending text and
//     clears it, whether or not the write lands. The planner never scans
//     ahead for a successor with an empty slot — hunting would be a
//     different algorithm that stamps one thought across a whole session.
//   - LAST-WINS: a second residue row before any successor replaces the
//     first; the first is superseded.
//   - TURN-BOUNDARY DISCARD: a user_prompt row clears the pending text.
//   - SESSION-SCOPED: enforced by the caller — this function is handed
//     one session's rows and can express nothing else.
//
// And one rule this pass adds, because it writes onto rows that already
// exist rather than onto fresh events:
//
//   - NEVER OVERWRITE: a successor whose preceding_reasoning is non-empty
//     keeps it. If it already contains the residue text the row is
//     `already_preserved`; otherwise `successor_occupied`.
func planReasoningSession(actions []reasoningAction) reasoningPlan {
	var plan reasoningPlan

	// pending mirrors crush's threadState: the text a residue row
	// produced, plus the row it came from, until a successor consumes it.
	var (
		pendingText string
		pendingID   int64
		hasPending  bool
	)
	discard := func(outcome reasoningResidueOutcome, tool string) {
		if !hasPending {
			return
		}
		plan.Dispositions = append(plan.Dispositions, reasoningDisposition{
			ResidueID: pendingID, Tool: tool, Outcome: outcome, Bytes: len(pendingText),
		})
		hasPending = false
	}
	pendingTool := ""

	for _, a := range actions {
		if a.Residue != nil {
			text, ok := a.Residue.carryText()
			if !ok {
				plan.Dispositions = append(plan.Dispositions, reasoningDisposition{
					ResidueID: a.ID, Tool: a.Residue.Tool, Outcome: outcomeDivergent,
				})
				continue
			}
			// LAST-WINS: the row already pending is superseded.
			discard(outcomeSuperseded, pendingTool)
			pendingText, pendingID, pendingTool, hasPending = text, a.ID, a.Residue.Tool, true
			continue
		}
		if a.ActionType == "user_prompt" {
			// TURN-BOUNDARY DISCARD.
			discard(outcomeTurnBoundary, pendingTool)
			continue
		}
		if !hasPending {
			continue
		}
		// CONSUMED-ONCE: this successor consumes the pending text
		// regardless of whether the write lands.
		switch {
		case a.PrecedingReasoning == "":
			plan.Carries = append(plan.Carries, reasoningCarry{
				ActionID: a.ID, ResidueID: pendingID, Text: pendingText,
			})
			plan.Dispositions = append(plan.Dispositions, reasoningDisposition{
				ResidueID: pendingID, Tool: pendingTool, Outcome: outcomeCarried, Bytes: len(pendingText),
			})
		case strings.Contains(a.PrecedingReasoning, pendingText):
			plan.Dispositions = append(plan.Dispositions, reasoningDisposition{
				ResidueID: pendingID, Tool: pendingTool, Outcome: outcomePreserved, Bytes: len(pendingText),
			})
		default:
			// NEVER OVERWRITE.
			plan.Dispositions = append(plan.Dispositions, reasoningDisposition{
				ResidueID: pendingID, Tool: pendingTool, Outcome: outcomeOccupied, Bytes: len(pendingText),
			})
		}
		hasPending = false
	}
	// End of session with text still pending: no successor ever arrived.
	discard(outcomeNoSuccessor, pendingTool)
	return plan
}

// ReasoningConvergeToolStat is one tool's row of the per-tool report.
type ReasoningConvergeToolStat struct {
	Tool             string `json:"tool"`
	Examined         int    `json:"examined"`
	Carried          int    `json:"carried"`
	AlreadyPreserved int    `json:"already_preserved"`
	Unresolved       int    `json:"unresolved"`
	Deleted          int    `json:"deleted"`
	UnresolvedBytes  int64  `json:"unresolved_bytes"`
}

// ReasoningConvergeBackfill summarises the --reasoning-converge pass.
type ReasoningConvergeBackfill struct {
	Applied           bool `json:"applied"`
	DiscardUnresolved bool `json:"discard_unresolved"`

	RowsExamined     int `json:"rows_examined"`
	SessionsExamined int `json:"sessions_examined"`

	Carried          int `json:"carried"`
	AlreadyPreserved int `json:"already_preserved"`

	RetainedOccupied     int `json:"retained_successor_occupied"`
	RetainedSuperseded   int `json:"retained_superseded_last_wins"`
	RetainedTurnBoundary int `json:"retained_turn_boundary"`
	RetainedNoSuccessor  int `json:"retained_no_successor"`
	SkippedDivergent     int `json:"skipped_divergent_body"`

	// UnresolvedBytes is the reasoning text that exists ONLY on residue
	// rows the pass could not converge — what a --reasoning-converge-
	// discard-unresolved run would destroy.
	UnresolvedBytes int64 `json:"unresolved_bytes"`

	RowsDeleted           int `json:"rows_deleted"`
	ExcerptsDeleted       int `json:"excerpts_deleted"`
	FailureContextDeleted int `json:"failure_context_deleted"`
	ReferencesNulled      int `json:"references_nulled"`
	// DerivedRowsDeleted counts the file_changes and task_transitions rows
	// keyed to a deleted row, deleted with it.
	DerivedRowsDeleted int `json:"derived_rows_deleted"`

	PerTool []ReasoningConvergeToolStat `json:"per_tool"`
}

// backfillReasoningConverge converges the B3 reasoning residue: it
// carries each surviving reasoning row's text onto its successor's
// preceding_reasoning and deletes the row, mirroring migration 079's
// dependency protocol.
//
// DRY RUN BY DEFAULT. apply=false plans everything and writes nothing.
//
// discardUnresolved widens the delete from "rows whose bytes provably
// survive" (carried + already_preserved) to "every candidate row B3's
// semantics account for" — i.e. it also deletes the rows whose text
// last-wins/turn-boundary/never-overwrite dropped. That is the strict
// reading of B3, and it destroys UnresolvedBytes of text that exists
// nowhere else, which is why it is a separate opt-in. Divergent-body
// rows are never deleted under either setting.
//
// The whole mutation runs in ONE transaction, so a mid-run failure can
// never leave a row deleted with its text uncarried.
//
// Idempotent: a second run finds the carried rows gone, and the rows it
// retained resolve to the same retained outcomes.
func backfillReasoningConverge(ctx context.Context, db *sql.DB, apply, discardUnresolved bool, out io.Writer) (ReasoningConvergeBackfill, error) {
	res := ReasoningConvergeBackfill{Applied: apply, DiscardUnresolved: discardUnresolved}
	if db == nil {
		return res, fmt.Errorf("backfill reasoning-converge: nil DB")
	}

	residue, sessions, err := loadReasoningResidue(ctx, db)
	if err != nil {
		return res, err
	}
	res.RowsExamined = len(residue)
	res.SessionsExamined = len(sessions)
	if len(residue) == 0 {
		return res, nil
	}

	perTool := map[string]*ReasoningConvergeToolStat{}
	stat := func(tool string) *ReasoningConvergeToolStat {
		s, ok := perTool[tool]
		if !ok {
			s = &ReasoningConvergeToolStat{Tool: tool}
			perTool[tool] = s
		}
		return s
	}
	for _, r := range residue {
		stat(r.Tool).Examined++
	}

	var (
		carries  []reasoningCarry
		toDelete []int64
	)
	for _, sessionID := range sessions {
		actions, err := loadReasoningSessionTimeline(ctx, db, sessionID, residue)
		if err != nil {
			return res, err
		}
		plan := planReasoningSession(actions)
		carries = append(carries, plan.Carries...)
		for _, d := range plan.Dispositions {
			s := stat(d.Tool)
			switch d.Outcome {
			case outcomeCarried:
				res.Carried++
				s.Carried++
			case outcomePreserved:
				res.AlreadyPreserved++
				s.AlreadyPreserved++
			case outcomeOccupied:
				res.RetainedOccupied++
			case outcomeSuperseded:
				res.RetainedSuperseded++
			case outcomeTurnBoundary:
				res.RetainedTurnBoundary++
			case outcomeNoSuccessor:
				res.RetainedNoSuccessor++
			case outcomeDivergent:
				res.SkippedDivergent++
			}
			if !d.Outcome.resolved() && d.Outcome != outcomeDivergent {
				s.Unresolved++
				s.UnresolvedBytes += int64(d.Bytes)
				res.UnresolvedBytes += int64(d.Bytes)
			}
			deletable := d.Outcome.resolved() ||
				(discardUnresolved && d.Outcome != outcomeDivergent)
			if deletable {
				toDelete = append(toDelete, d.ResidueID)
				s.Deleted++
			}
		}
	}
	res.RowsDeleted = len(toDelete)

	for _, s := range perTool {
		res.PerTool = append(res.PerTool, *s)
	}
	sort.Slice(res.PerTool, func(i, j int) bool {
		if res.PerTool[i].Examined != res.PerTool[j].Examined {
			return res.PerTool[i].Examined > res.PerTool[j].Examined
		}
		return res.PerTool[i].Tool < res.PerTool[j].Tool
	})

	if apply {
		counts, err := applyReasoningConvergence(ctx, db, carries, toDelete)
		if err != nil {
			return res, err
		}
		res.ExcerptsDeleted = counts.excerpts
		res.FailureContextDeleted = counts.failureContext
		res.ReferencesNulled = counts.referencesNulled
		res.DerivedRowsDeleted = counts.derivedDeleted
	} else {
		counts, err := countReasoningDependents(ctx, db, toDelete)
		if err != nil {
			return res, err
		}
		res.ExcerptsDeleted = counts.excerpts
		res.FailureContextDeleted = counts.failureContext
		res.ReferencesNulled = counts.referencesNulled
		res.DerivedRowsDeleted = counts.derivedDeleted
	}

	if out != nil {
		writeReasoningConvergeReport(out, res)
	}
	return res, nil
}

// loadReasoningResidue selects every candidate row in ONE table scan and
// filters to the exact (tool, raw_tool_name) pairs in
// reasoningResidueSpecs. Returns the rows keyed by action id, plus the
// session ids they occur in, in stable order.
func loadReasoningResidue(ctx context.Context, db *sql.DB) (map[int64]reasoningResidue, []string, error) {
	tools := map[string]bool{}
	names := map[string]bool{}
	pairs := map[string]bool{}
	for _, s := range reasoningResidueSpecs {
		tools[s.Tool] = true
		names[s.RawToolName] = true
		pairs[s.Tool+"\x00"+s.RawToolName] = true
	}
	toolList, nameList := sortedStringSet(tools), sortedStringSet(names)

	// One scan: the IN lists narrow it, the exact-pair check in Go is
	// what actually decides. Placeholders only — never interpolation.
	//nolint:gosec // G202: the only concatenated fragments are `?` placeholder
	// runs generated from len(); every tool / raw-name value binds via args.
	query := `SELECT id, session_id, tool, raw_tool_name,
	                 COALESCE(target, ''), COALESCE(raw_tool_output, '')
	            FROM actions
	           WHERE action_type = 'task_complete'
	             AND tool IN (` + placeholders(len(toolList)) + `)
	             AND raw_tool_name IN (` + placeholders(len(nameList)) + `)`
	args := make([]any, 0, len(toolList)+len(nameList))
	for _, t := range toolList {
		args = append(args, t)
	}
	for _, n := range nameList {
		args = append(args, n)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("backfill reasoning-converge: select residue: %w", err)
	}
	defer rows.Close()

	residue := map[int64]reasoningResidue{}
	var sessions []string
	seenSession := map[string]bool{}
	for rows.Next() {
		var (
			id                 int64
			sessionID          string
			tool, name         string
			target, toolOutput string
		)
		if err := rows.Scan(&id, &sessionID, &tool, &name, &target, &toolOutput); err != nil {
			return nil, nil, fmt.Errorf("backfill reasoning-converge: scan residue: %w", err)
		}
		if !pairs[tool+"\x00"+name] {
			continue
		}
		residue[id] = reasoningResidue{Tool: tool, RawToolName: name, Target: target, RawToolOutput: toolOutput}
		if !seenSession[sessionID] {
			seenSession[sessionID] = true
			sessions = append(sessions, sessionID)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("backfill reasoning-converge: iterate residue: %w", err)
	}
	sort.Strings(sessions)
	return residue, sessions, nil
}

// loadReasoningSessionTimeline loads one session's actions in the order
// the planner walks them: (timestamp, id). actions.id is an autoincrement
// rowid, so it breaks timestamp ties by insertion order.
func loadReasoningSessionTimeline(ctx context.Context, db *sql.DB, sessionID string, residue map[int64]reasoningResidue) ([]reasoningAction, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, action_type, COALESCE(preceding_reasoning, '')
		  FROM actions
		 WHERE session_id = ?
		 ORDER BY timestamp, id`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("backfill reasoning-converge: select session %s: %w", sessionID, err)
	}
	defer rows.Close()

	var out []reasoningAction
	for rows.Next() {
		var a reasoningAction
		if err := rows.Scan(&a.ID, &a.ActionType, &a.PrecedingReasoning); err != nil {
			return nil, fmt.Errorf("backfill reasoning-converge: scan session %s: %w", sessionID, err)
		}
		if r, ok := residue[a.ID]; ok {
			rr := r
			a.Residue = &rr
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backfill reasoning-converge: iterate session %s: %w", sessionID, err)
	}
	return out, nil
}

// reasoningDependentCounts holds the dependency-protocol row counts.
type reasoningDependentCounts struct {
	excerpts         int
	failureContext   int
	referencesNulled int
	derivedDeleted   int
}

// reasoningDerivedRows are the rows derived from an action that go WITH it
// (MISC2-02): lines-of-code counts and todo status changes. Neither table
// has a foreign key to actions, so a bare action delete left them as
// orphans; internal/store's component purge and internal/retention delete
// them with their action, and so does this pass. Migration 079's shipped
// protocol (reasoningNullRefs) predates both tables and is unchanged.
var reasoningDerivedRows = []struct{ table, column string }{
	{"file_changes", "action_id"},
	{"task_transitions", "action_id"},
}

// reasoningNullRefs is migration 079's NULL-the-reference list, verbatim:
// five tables whose action_id has no ON DELETE CASCADE and whose rows stay
// useful unattributed (internal/retention/retention.go::deleteActionsOlder,
// the path that survived the 2026-06-18 "FOREIGN KEY constraint failed
// (787)" regression).
var reasoningNullRefs = []struct{ table, column string }{
	{"file_state", "last_action_id"},
	{"retrieval_signals", "action_id"},
	{"guard_events", "action_id"},
	{"process_runs", "action_id"},
	{"process_events", "action_id"},
}

// reasoningExcerptCountSQL / reasoningExcerptDeleteSQL count and delete the
// FTS5 excerpts of a chunk of action ids (ph is a code-built `?` run).
//
// action_id is UNINDEXED in action_excerpts (001_initial.sql), so the old
// `... FROM action_excerpts WHERE action_id IN (...)` planned as a full scan
// of every stored excerpt once per 400-id chunk, in the dry run AND inside
// the apply transaction (T-415, the FTSSTALL class). Both now resolve the
// ids through the FTS5 shadow table action_excerpts_content (c0 is
// action_id, indexed by migration 147): the count reads only that index
// (one content row per FTS row, so the count is identical), and the delete
// reaches the virtual table by rowid equality, the same shape as the
// indexer's replace-delete. The ids are bound int64 values, as they were
// before, so the set of rows matched is unchanged. Pinned by
// TestReasoningExcerptSQLSeeksByC0.
func reasoningExcerptCountSQL(ph string) string {
	return `SELECT COUNT(*) FROM action_excerpts_content WHERE c0 IN (` + ph + `)`
}

func reasoningExcerptDeleteSQL(ph string) string {
	return `DELETE FROM action_excerpts WHERE rowid IN (SELECT id FROM action_excerpts_content WHERE c0 IN (` + ph + `))`
}

// countReasoningDependents reports what the dependency protocol WOULD
// touch, for the dry run. Read-only.
func countReasoningDependents(ctx context.Context, db *sql.DB, ids []int64) (reasoningDependentCounts, error) {
	var c reasoningDependentCounts
	for _, chunk := range chunkIDs(ids, 400) {
		args := int64Args(chunk)
		ph := placeholders(len(chunk))
		var n int
		if err := db.QueryRowContext(ctx, reasoningExcerptCountSQL(ph), args...).Scan(&n); err != nil {
			return c, fmt.Errorf("backfill reasoning-converge: count action_excerpts: %w", err)
		}
		c.excerpts += n
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM failure_context WHERE action_id IN (`+ph+`)`, args...).Scan(&n); err != nil {
			return c, fmt.Errorf("backfill reasoning-converge: count failure_context: %w", err)
		}
		c.failureContext += n
		for _, ref := range reasoningNullRefs {
			if err := db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM `+ref.table+` WHERE `+ref.column+` IN (`+ph+`)`, args...).Scan(&n); err != nil {
				return c, fmt.Errorf("backfill reasoning-converge: count %s: %w", ref.table, err)
			}
			c.referencesNulled += n
		}
		for _, d := range reasoningDerivedRows {
			if err := db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM `+d.table+` WHERE `+d.column+` IN (`+ph+`)`, args...).Scan(&n); err != nil {
				return c, fmt.Errorf("backfill reasoning-converge: count %s: %w", d.table, err)
			}
			c.derivedDeleted += n
		}
	}
	return c, nil
}

// applyReasoningConvergence performs the carries and the deletes in ONE
// transaction: either every carried row's text landed on its successor
// AND the row is gone, or nothing changed. A partial apply is exactly the
// failure mode this pass must not have.
func applyReasoningConvergence(ctx context.Context, db *sql.DB, carries []reasoningCarry, ids []int64) (reasoningDependentCounts, error) {
	var c reasoningDependentCounts
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return c, fmt.Errorf("backfill reasoning-converge: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The carries come FIRST: the text must be on the successor before
	// the row that holds it can go. The WHERE re-asserts the empty slot
	// so a concurrent writer can never be overwritten.
	stmt, err := tx.PrepareContext(ctx, `
		UPDATE actions
		   SET preceding_reasoning = ?
		 WHERE id = ?
		   AND (preceding_reasoning IS NULL OR preceding_reasoning = '')`)
	if err != nil {
		return c, fmt.Errorf("backfill reasoning-converge: prepare carry: %w", err)
	}
	defer stmt.Close()
	for _, cr := range carries {
		if _, err := stmt.ExecContext(ctx, cr.Text, cr.ActionID); err != nil {
			return c, fmt.Errorf("backfill reasoning-converge: carry onto action %d: %w", cr.ActionID, err)
		}
	}

	// Dependency protocol, then the delete — migration 079's order.
	// action_excerpts FIRST: FTS5 search never joins actions
	// (internal/compression/indexing/indexer.go), so a bare actions
	// DELETE would leave SEARCHABLE GHOSTS.
	for _, chunk := range chunkIDs(ids, 400) {
		args := int64Args(chunk)
		ph := placeholders(len(chunk))

		//nolint:gosec // G202: ph is a generated `?` placeholder run; ids bind via args.
		r, err := tx.ExecContext(ctx, reasoningExcerptDeleteSQL(ph), args...)
		if err != nil {
			return c, fmt.Errorf("backfill reasoning-converge: delete action_excerpts: %w", err)
		}
		if n, err := r.RowsAffected(); err == nil {
			c.excerpts += int(n)
		}

		// failure_context.action_id is NOT NULL REFERENCES actions(id),
		// so the row cannot survive its action — deleted, not NULLed.
		//nolint:gosec // G202: ph is a generated `?` placeholder run; ids bind via args.
		r, err = tx.ExecContext(ctx, `DELETE FROM failure_context WHERE action_id IN (`+ph+`)`, args...)
		if err != nil {
			return c, fmt.Errorf("backfill reasoning-converge: delete failure_context: %w", err)
		}
		if n, err := r.RowsAffected(); err == nil {
			c.failureContext += int(n)
		}

		for _, ref := range reasoningNullRefs {
			//nolint:gosec // G202: ref.table / ref.column come from the code-constant
			// reasoningNullRefs table (migration 079's list); ids bind via args.
			r, err := tx.ExecContext(ctx,
				`UPDATE `+ref.table+` SET `+ref.column+` = NULL WHERE `+ref.column+` IN (`+ph+`)`, args...)
			if err != nil {
				return c, fmt.Errorf("backfill reasoning-converge: null %s.%s: %w", ref.table, ref.column, err)
			}
			if n, err := r.RowsAffected(); err == nil {
				c.referencesNulled += int(n)
			}
		}

		for _, d := range reasoningDerivedRows {
			//nolint:gosec // G202: d.table / d.column come from the code-constant
			// reasoningDerivedRows table; ids bind via args.
			r, err := tx.ExecContext(ctx,
				`DELETE FROM `+d.table+` WHERE `+d.column+` IN (`+ph+`)`, args...)
			if err != nil {
				return c, fmt.Errorf("backfill reasoning-converge: delete %s: %w", d.table, err)
			}
			if n, err := r.RowsAffected(); err == nil {
				c.derivedDeleted += int(n)
			}
		}

		//nolint:gosec // G202: ph is a generated `?` placeholder run; ids bind via args.
		if _, err := tx.ExecContext(ctx, `DELETE FROM actions WHERE id IN (`+ph+`)`, args...); err != nil {
			return c, fmt.Errorf("backfill reasoning-converge: delete actions: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return c, fmt.Errorf("backfill reasoning-converge: commit: %w", err)
	}
	return c, nil
}

// writeReasoningConvergeReport prints the human-readable report: what the
// pass did, or in dry run what it would do.
func writeReasoningConvergeReport(out io.Writer, res ReasoningConvergeBackfill) {
	mode := "dry run"
	if res.Applied {
		mode = "applied"
	}
	fmt.Fprintf(out, "reasoning-converge (%s): %d residue row(s) across %d session(s)\n",
		mode, res.RowsExamined, res.SessionsExamined)
	if res.RowsExamined == 0 {
		fmt.Fprintf(out, "  nothing to converge - the B3 residue is clear.\n")
		return
	}
	verb := "would carry"
	delVerb := "would delete"
	if res.Applied {
		verb, delVerb = "carried", "deleted"
	}
	fmt.Fprintf(out, "  %s onto a successor: %d\n", verb, res.Carried)
	fmt.Fprintf(out, "  already preserved on the successor: %d\n", res.AlreadyPreserved)
	fmt.Fprintf(out, "  retained - successor's preceding_reasoning already holds different text: %d\n", res.RetainedOccupied)
	fmt.Fprintf(out, "  retained - superseded by a later reasoning row (last-wins): %d\n", res.RetainedSuperseded)
	fmt.Fprintf(out, "  retained - turn boundary reached before a successor: %d\n", res.RetainedTurnBoundary)
	fmt.Fprintf(out, "  retained - no successor in the session: %d\n", res.RetainedNoSuccessor)
	fmt.Fprintf(out, "  skipped - raw_tool_output diverges from target (never touched): %d\n", res.SkippedDivergent)
	fmt.Fprintf(out, "  %s: %d action row(s), %d action_excerpts, %d failure_context, %d file_changes/task_transitions, %d reference(s) NULLed\n",
		delVerb, res.RowsDeleted, res.ExcerptsDeleted, res.FailureContextDeleted, res.DerivedRowsDeleted, res.ReferencesNulled)
	if len(res.PerTool) > 0 {
		fmt.Fprintf(out, "  per tool (examined / carried / preserved / unresolved / deleted):\n")
		for _, t := range res.PerTool {
			fmt.Fprintf(out, "    %-18s %5d %5d %5d %5d %5d\n",
				t.Tool, t.Examined, t.Carried, t.AlreadyPreserved, t.Unresolved, t.Deleted)
		}
	}
	unresolved := res.RetainedOccupied + res.RetainedSuperseded + res.RetainedTurnBoundary + res.RetainedNoSuccessor
	if unresolved > 0 {
		if res.DiscardUnresolved {
			fmt.Fprintf(out,
				"  NOTE: --reasoning-converge-discard-unresolved is set - %d unresolved row(s) carrying %d byte(s)\n"+
					"        of reasoning text that exists nowhere else are included in the delete above.\n",
				unresolved, res.UnresolvedBytes)
		} else {
			fmt.Fprintf(out,
				"  NOTE: %d row(s) are RETAINED because B3's semantics send their text nowhere and deleting\n"+
					"        them would destroy %d byte(s) that exist only there (the loss migration 079 declined\n"+
					"        to take). Pass --reasoning-converge-discard-unresolved to delete them anyway.\n",
				unresolved, res.UnresolvedBytes)
		}
	}
	if !res.Applied {
		fmt.Fprintf(out, "  nothing written (dry run) - re-run with --apply:\n    observer backfill --reasoning-converge --apply\n")
	}
	// Same honest caveat as --codex-fork-dedup: org push is append-only.
	fmt.Fprintf(out, "  note: rows already pushed to an org server are NOT retracted - this cleans the local DB only.\n")
}

// placeholders renders n comma-separated SQL placeholders.
func placeholders(n int) string {
	if n <= 0 {
		return "NULL"
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// chunkIDs splits ids into slices of at most size, keeping every IN list
// well under SQLite's variable limit.
func chunkIDs(ids []int64, size int) [][]int64 {
	if len(ids) == 0 {
		return nil
	}
	var out [][]int64
	for i := 0; i < len(ids); i += size {
		end := i + size
		if end > len(ids) {
			end = len(ids)
		}
		out = append(out, ids[i:end])
	}
	return out
}

// int64Args widens ids for database/sql's variadic args.
func int64Args(ids []int64) []any {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return args
}

// sortedStringSet returns a set's keys in stable order, so the generated SQL
// and its bound arguments always line up.
func sortedStringSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
