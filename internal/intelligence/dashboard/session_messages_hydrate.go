package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Page-window hydration for handleSessionMessages (node dashboard
// performance audit 2026-09-29).
//
// The Messages endpoint derives the WHOLE session timeline on every poll
// (sessionmsg.Derive, sort, locate and pagination all need every row), but
// only the returned window — a page of 25-100 rows, or the ?tail window —
// is ever serialized. The content-bearing display fields (FullText,
// FullTextElided, HasFullOutput, Excerpt) are pure pass-through: Derive
// never reads them (it reads only MessageID, SourceEventID, ActionType,
// Timestamp, EffortLevel, ServiceTier and StopReason of an ActionRow), and
// neither the sort keys, the orphan-token stub logic nor the account
// matching touch them. So loadMessageActionRows loads a LIGHT row for every
// action, and hydrateMessageActions fills the heavy fields for just the
// action ids that end up in the response window. On a 33k-action session
// that is the difference between materializing ~75 MB of raw_tool_input
// plus a LENGTH walk over ~54 MB of raw_tool_output on every poll and
// reading a few dozen rows.

// idQueryChunk bounds the number of bound parameters in one IN (...) list,
// keeping every statement far below SQLite's host-parameter limit however
// large the id set is.
const idQueryChunk = 500

// messageActionHeavy is one action's content-bearing fields, loaded only
// for the rows of the response window.
type messageActionHeavy struct {
	// rawInput is actions.raw_tool_input, loaded only for the action types
	// whose inline full text is their raw input (fullTextFromRawInput);
	// empty for every other type.
	rawInput string
	// rawOutputLen is LENGTH(COALESCE(raw_tool_output, '')) — SQLite's
	// character count for TEXT, exactly as the pre-hydration loader
	// computed it.
	rawOutputLen int64
	// asstBody is raw_tool_output capped at fullTextInlineMax characters,
	// for assistant_message rows only (the browser-chat answer body).
	asstBody string
	// excerpt is the action's first action_excerpts.excerpt (full text),
	// empty when none exists.
	excerpt string
}

// fullTextFromRawInput lists the action types whose inline full text is
// their raw_tool_input (falling back to target when the input is empty).
// The ONE owner of that list: both the heavy SQL and
// resolveMessageActionFullText are built from it.
var fullTextFromRawInput = []string{"user_prompt", "system_prompt", "ask_user", "run_command"}

// usesRawInputFullText reports whether actionType is in fullTextFromRawInput.
func usesRawInputFullText(actionType string) bool {
	for _, t := range fullTextFromRawInput {
		if t == actionType {
			return true
		}
	}
	return false
}

// resolveMessageActionFullText derives a tool call's inline display fields
// (full_text, full_text_elided, has_full_output) from its light identity
// (action type + target) and its heavy fields. This is the pre-hydration
// loader's per-row logic, unchanged:
//
//   - full text defaults to target; user_prompt/system_prompt/ask_user/
//     run_command use their raw input when present; run_command's argv JSON
//     is joined into a shell line;
//   - a browser-chat assistant_message shows its (SQL-capped) response body;
//   - text longer than fullTextInlineMax bytes is cut and flagged elided, and
//     a browser assistant body whose source exceeded the cap is flagged
//     elided too (the SQL substr already trimmed it, so the byte check alone
//     cannot see the original length);
//   - has_full_output is true when raw_tool_output is non-empty.
func resolveMessageActionFullText(actionType, target string, h messageActionHeavy, browserSession bool) (fullText string, elided, hasFullOutput bool) {
	fullText = target
	if usesRawInputFullText(actionType) && h.rawInput != "" {
		fullText = h.rawInput
	}
	if actionType == "run_command" {
		fullText = decodeCommandInput(fullText)
	}
	// Browser chat: the assistant's on-screen answer is stored in
	// raw_tool_output (target is only a one-line preview). Gated on
	// browserSession so coding-agent assistant_message rows (model
	// narration) render exactly as before.
	browserAnswer := browserSession && actionType == "assistant_message"
	if browserAnswer && h.asstBody != "" {
		fullText = h.asstBody
	}
	if len(fullText) > fullTextInlineMax {
		fullText = fullText[:fullTextInlineMax]
		elided = true
	}
	if browserAnswer && h.rawOutputLen > fullTextInlineMax {
		elided = true
	}
	return fullText, elided, h.rawOutputLen > 0
}

// hydrateMessageActions loads the heavy display fields plus the first
// excerpt for each of ids (the action ids of the response window only).
// Ids absent from actions yield no entry; a caller treats a missing entry
// as the zero messageActionHeavy.
func hydrateMessageActions(ctx context.Context, db *sql.DB, ids []int64) (map[int64]messageActionHeavy, error) {
	ids = uniqueIDs(ids)
	out := make(map[int64]messageActionHeavy, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	typeList := "'" + strings.Join(fullTextFromRawInput, "','") + "'"
	err := forEachIDChunk(ids, idQueryChunk, func(chunk []int64) error {
		placeholders, args := idPlaceholders(chunk)
		//nolint:gosec // G202: typeList is built from the fullTextFromRawInput code constant and the IN list is "?" placeholders; every value is bound.
		q := `SELECT a.id,
		        CASE WHEN a.action_type IN (` + typeList + `)
		             THEN COALESCE(a.raw_tool_input, '') ELSE '' END,
		        LENGTH(COALESCE(a.raw_tool_output, '')),
		        CASE WHEN a.action_type = 'assistant_message'
		             THEN substr(COALESCE(a.raw_tool_output, ''), 1, ?)
		             ELSE '' END
		   FROM actions a
		  WHERE a.id IN (` + placeholders + `)`
		rows, err := db.QueryContext(ctx, q, append([]any{fullTextInlineMax}, args...)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var h messageActionHeavy
			if err := rows.Scan(&id, &h.rawInput, &h.rawOutputLen, &h.asstBody); err != nil {
				return err
			}
			out[id] = h
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("dashboard.hydrateMessageActions: %w", err)
	}
	excerpts, err := loadActionExcerpts(ctx, db, ids, 0)
	if err != nil {
		return nil, fmt.Errorf("dashboard.hydrateMessageActions: %w", err)
	}
	for id, ex := range excerpts {
		h := out[id]
		h.excerpt = ex
		out[id] = h
	}
	return out, nil
}

// uniqueIDs returns ids with duplicates removed, first occurrence order
// kept. The input slice is not modified.
func uniqueIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// forEachIDChunk calls fn with consecutive sub-slices of ids of at most
// size elements, stopping at the first error.
func forEachIDChunk(ids []int64, size int, fn func([]int64) error) error {
	if size < 1 {
		size = 1
	}
	for start := 0; start < len(ids); start += size {
		end := start + size
		if end > len(ids) {
			end = len(ids)
		}
		if err := fn(ids[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// idPlaceholders returns "?,?,…" for ids plus the matching bound args.
func idPlaceholders(ids []int64) (string, []any) {
	placeholders := strings.Repeat("?,", len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return placeholders[:len(placeholders)-1], args
}
