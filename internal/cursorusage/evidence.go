package cursorusage

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Row identity lives on columns EVERY reader receives: action_type and
// source_event_id. The org receives neither raw_tool_name (never on the
// push wire) nor error_message in every share mode (only under the
// full_tool_bodies tier), so a predicate over those would make the node
// and the org disagree about the same session. Tally is therefore the ONE
// fold every loader (the node store seam, the doctor, the org rollup)
// runs over plain rows; none of them re-derives a count in SQL.

const (
	// SourceEventUnfinishedSuffix ends the SourceEventID of a turn that
	// never finished (TurnSourceEventID with RawToolTurnUnfinished).
	SourceEventUnfinishedSuffix = ":unfinished"
	// SourceEventResponseHookSuffix ends the SourceEventID of an
	// assistant row written from Cursor's afterAgentResponse hook (the
	// cursor adapter keys every hook row `<generation>:<event>`, and the
	// IDE hooks-log replay reuses that id).
	SourceEventResponseHookSuffix = ":" + RawToolResponseHook
	// SourceEventOutcomePrefix prefixes the SourceEventID of a token_usage
	// row recovered from a headless cursor-agent turn-outcome log record.
	SourceEventOutcomePrefix = "cursor-cli-outcome:"
	// PartialUsageNote is the banner for a session whose usage came from a
	// turn-outcome record marked unreliable (an interrupted / retried
	// turn): Cursor logs only the final attempt.
	PartialUsageNote = "Partial usage: Cursor's log recovered the final attempt of an interrupted or retried turn. Earlier attempts may be missing; token counts and estimated cost shown are a lower bound."
)

// TurnSourceEventID is the SourceEventID of a turn_aborted row for the
// cursor-agent turn keyed by tracker whose RawToolName is rawTool (either
// RawToolTurnUnfinished or RawToolTurnFailedPrefix+<outcome>). The writer
// (internal/adapter/cursor) builds ids only through this, so a reader can
// tell an unfinished turn from a failed one without raw_tool_name.
func TurnSourceEventID(tracker, rawTool string) string {
	return SourceEventTurnPrefix + tracker + ":" + strings.TrimPrefix(rawTool, RawToolTurnFailedPrefix)
}

// Row is one action row as a loader reads it: only the fields the fold
// looks at. ErrorMessage may be empty (the org receives it only under the
// full_tool_bodies tier); the fold then leaves the detail sentence out
// rather than guessing it.
type Row struct {
	ActionType    string
	SourceEventID string
	ErrorMessage  string
}

// EvidenceActionTypes are the action types a loader must select: rows of
// any other type never change the Evidence, so a loader filters on this
// set and hands Tally everything that matched.
var EvidenceActionTypes = []string{
	models.ActionUserPrompt,
	models.ActionAssistantMessage,
	models.ActionTurnAborted,
	models.ActionAPIError,
}

// rowKind is one row of the ordered row-identity table: the first match
// counts the row. Adding an evidence kind is adding a row.
type rowKind struct {
	match func(Row) bool
	add   func(*Evidence, Row)
}

func isTurnRow(r Row) bool {
	return r.ActionType == models.ActionTurnAborted && strings.HasPrefix(r.SourceEventID, SourceEventTurnPrefix)
}

var rowKinds = []rowKind{
	{
		match: func(r Row) bool { return r.ActionType == models.ActionUserPrompt },
		add:   func(e *Evidence, _ Row) { e.Prompts++ },
	},
	{
		match: func(r Row) bool {
			return r.ActionType == models.ActionAssistantMessage && strings.HasSuffix(r.SourceEventID, SourceEventResponseHookSuffix)
		},
		add: func(e *Evidence, _ Row) { e.ResponseHooks++ },
	},
	{
		match: func(r Row) bool {
			return isTurnRow(r) && strings.HasSuffix(r.SourceEventID, SourceEventUnfinishedSuffix)
		},
		add: func(e *Evidence, r Row) {
			e.UnfinishedTurns++
			e.LatestTurnDetail = r.ErrorMessage
		},
	},
	{
		match: isTurnRow,
		add: func(e *Evidence, r Row) {
			e.FailedTurns++
			e.LatestTurnDetail = r.ErrorMessage
		},
	},
	{
		match: func(r Row) bool {
			return r.ActionType == models.ActionAPIError && strings.HasPrefix(r.SourceEventID, SourceEventAttemptPrefix)
		},
		add: func(e *Evidence, _ Row) { e.FailedAttempts++ },
	},
}

// Tally folds a session's rows, oldest first, into Evidence. The
// LatestTurnDetail is the error_message of the LAST turn row, so callers
// order by timestamp ascending (ties broken deterministically).
func Tally(rows []Row) Evidence {
	var e Evidence
	for _, r := range rows {
		for _, k := range rowKinds {
			if k.match(r) {
				k.add(&e, r)
				break
			}
		}
	}
	return e
}

// WithoutDetail returns e with the per-turn detail sentence removed: the
// shape to explain to a viewer who may not see error_message content.
func (e Evidence) WithoutDetail() Evidence {
	e.LatestTurnDetail = ""
	return e
}

// AppliesTo reports whether this package explains missing usage for a
// session captured by tool. It is the one place the Cursor scope of these
// rules is decided, so the node dashboard and the org rollup ask it rather
// than each comparing a tool name.
func AppliesTo(tool string) bool {
	return tool == models.ToolCursor
}
