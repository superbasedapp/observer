package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

// cloudlocal_texts.go holds the bounded excerpt substrate (prompt heads and
// failure texts) of the cloud-intelligence store seam (cloudlocal.go
// describes the whole seam).

// -- excerpt substrate (bounded-context enrichment only) ---------------------

// CloudSessionTexts is the raw, node-local TEXT substrate for one session: the
// user's own prompts, the last assistant message, and recorded tool-failure
// messages. It is loaded ONLY on the bounded-context-enrichment path; the
// structural path never calls this read, so a structural envelope cannot even
// have content to leak.
//
// What is deliberately NOT here: commands, tool outputs, file contents, paths,
// and reasoning. Those columns exist on the actions row and are never selected.
type CloudSessionTexts struct {
	UserPrompts           []string
	FinalAssistantMessage string
	AssistantMessages     []string
	Errors                []string
}

// Bounds on the text substrate read. They are generous enough that the pure
// selector always has candidates to sample across, and small enough that the
// read stays cheap.
const (
	cloudMaxPromptRows = 200
	// cloudMaxErrorRows bounds the failure population the pure layer CLASSIFIES
	// and COUNTS. It is deliberately large: unlike a prompt, a failure row never
	// leaves this process as text — only the class label it matched, plus an
	// integer count, ever reaches an envelope — so reading more rows buys a
	// truer distribution at no disclosure cost. The old bound of 8 EARLIEST rows
	// meant the shipped classes described the session's first few failures, not
	// its failures (Q1).
	cloudMaxErrorRows = 2000
	// cloudErrorTailRows is the late window of the head+tail split, so the LAST
	// observed failure class survives a session that blew past the bound.
	cloudErrorTailRows = 400
	// cloudErrorScanBytes bounds how much of one error_message is read. Only the
	// classifier ever sees these bytes and it matches short phrases, so the
	// leading 512 bytes carry the whole signal.
	cloudErrorScanBytes = 512
	// cloudPromptHeadRows is the CONTIGUOUS head window of prompt rows always
	// returned, ahead of the strided remainder.
	//
	// It exists because the pure selector's "first REAL prompt" is defined AFTER
	// harness filtering (a `/clear` envelope, a caveat block, a system reminder
	// are not the developer's prompt), and that filtering happens in Go — SQL
	// cannot know which of the earliest rows are injections. A contiguous head
	// therefore has to be handed over so the earliest surviving prompt is the
	// true one. 24 is the documented BOUND on that guarantee: a session whose
	// first 24 prompt rows are ALL harness injections would have its "first real
	// prompt" drawn from the strided remainder instead — later than the truth,
	// never a different kind of thing. Real sessions open with at most a handful.
	cloudPromptHeadRows = 24
	// cloudTextScanBytes bounds how much of one text column is read. The pure
	// selector caps each excerpt at 1024 pre-scrub bytes, so reading much more
	// than that would only move bytes around in memory.
	cloudTextScanBytes = 4096
)

// notSidechain is the predicate every CONTENT read carries (A1).
//
// A Claude sub-agent shares the PARENT's session id, and its rows land in the
// same `actions` table with is_sidechain = 1. Two of those rows are text:
//
//   - the parent's DELEGATION INSTRUCTION becomes a `user_prompt` row, so a
//     sub-agent brief — routinely a paste of tool output, a file excerpt, or a
//     record the parent wanted analyzed — qualified as the session's
//     "first_user_prompt" and shipped as the developer's own words;
//   - a sub-agent's reply becomes an `assistant_message` row, so the LAST one
//     could be a sub-agent's report rather than the session's conclusion.
//
// Neither is the developer's prompt, and both are richer in incidental content
// than a real prompt is. The excerpt reads therefore take main-thread rows only.
// The STRUCTURAL reads (counts, mixes, outcomes) deliberately do not: a
// sub-agent's work is the session's work, and a count carries no content.
const notSidechain = ` AND COALESCE(is_sidechain, 0) = 0`

// LoadCloudSessionTexts reads the bounded text substrate for one session. The
// SQL is deliberately dumb: it selects candidate rows in time order and leaves
// every judgement (which prompts are harness-injected, which are duplicates,
// which to sample) to the pure selector in internal/cloudevidence. NODE-LOCAL.
//
// It reads from the pool. The envelope build path does NOT use it — it reads the
// same substrate inside its own snapshot via LoadCloudEvidenceBundle (A7).
func (s *Store) LoadCloudSessionTexts(ctx context.Context, sessionID string) (CloudSessionTexts, error) {
	return loadCloudSessionTexts(ctx, s.db, sessionID, nil)
}

// loadCloudSessionTexts is the shared implementation, over any cloudReader so it
// can run inside the evidence snapshot.
//
// When failures is non-nil it receives EVERY recorded failure message of the
// session and out.Errors is left empty: the caller is classifying the whole
// population as it streams (A8) rather than taking a window of it. When it is
// nil the bounded head+tail window is materialized, for callers that want the
// messages themselves.
func loadCloudSessionTexts(ctx context.Context, db cloudReader, sessionID string, failures func(string)) (CloudSessionTexts, error) {
	var out CloudSessionTexts
	prompts, err := loadCloudPromptRows(ctx, db, sessionID)
	if err != nil {
		return CloudSessionTexts{}, err
	}
	out.UserPrompts = prompts

	final, err := cloudTextRows(ctx, db, `
		SELECT substr(CASE WHEN length(COALESCE(raw_tool_input, '')) > length(COALESCE(target, ''))
		                   THEN raw_tool_input ELSE COALESCE(target, '') END, 1, ?)
		  FROM actions
		 WHERE session_id = ? AND action_type = 'assistant_message'
		       AND COALESCE(target, '') <> ''`+notSidechain+`
		 ORDER BY timestamp DESC, id DESC
		 LIMIT 1`, cloudTextScanBytes, sessionID)
	if err != nil {
		return CloudSessionTexts{}, err
	}
	if len(final) > 0 {
		out.FinalAssistantMessage = final[0]
	}

	if failures != nil {
		if err := streamCloudFailures(ctx, db, sessionID, failures); err != nil {
			return CloudSessionTexts{}, err
		}
		return out, nil
	}

	// The failure population, as a head window plus a tail window in time order:
	// the pure layer counts classes over ALL of it and always keeps the LAST
	// observed class, so both ends have to be present.
	errs, err := cloudTextRows(ctx, db, `
		WITH ordered AS (
		  SELECT substr(error_message, 1, ?) AS body,
		         ROW_NUMBER() OVER (ORDER BY timestamp ASC, id ASC) AS rn,
		         COUNT(*)     OVER ()                               AS total
		    FROM actions
		   WHERE session_id = ? AND `+cloudFailureRowPredicate+notSidechain+`
		)
		SELECT body FROM ordered
		 WHERE rn <= ? OR rn > total - ?
		 ORDER BY rn ASC`,
		cloudErrorScanBytes, sessionID,
		cloudMaxErrorRows-cloudErrorTailRows, cloudErrorTailRows)
	if err != nil {
		return CloudSessionTexts{}, err
	}
	out.Errors = errs
	return out, nil
}

// cloudFailureRowPredicate selects the session's FAILURE population.
//
// It is not just `action_type = 'tool_failure'` (A8): an action of any kind that
// recorded success = 0 with an error message is a failure of this session, and
// counting only the rows one adapter happens to label `tool_failure` reported a
// distribution over a subset while calling it the session's.
const cloudFailureRowPredicate = `(COALESCE(action_type, '') = 'tool_failure' OR COALESCE(success, 1) = 0)
	         AND COALESCE(error_message, '') <> ''`

// streamCloudFailures hands EVERY failure message of the session to sink, in
// time order, one at a time. The caller classifies each one into a closed-
// vocabulary label and keeps only counters, so no message is ever materialized
// as a population and no cap is needed (A8).
func streamCloudFailures(ctx context.Context, db cloudReader, sessionID string, sink func(string)) error {
	rows, err := db.QueryContext(ctx, `
		SELECT substr(error_message, 1, ?)
		  FROM actions
		 WHERE session_id = ? AND `+cloudFailureRowPredicate+notSidechain+`
		 ORDER BY timestamp ASC, id ASC`, cloudErrorScanBytes, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadCloudSessionTexts: failure stream: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var body sql.NullString
		if err := rows.Scan(&body); err != nil {
			return fmt.Errorf("store.LoadCloudSessionTexts: scan failure row: %w", err)
		}
		if strings.TrimSpace(body.String) == "" {
			continue
		}
		sink(body.String)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudSessionTexts: failure stream: %w", err)
	}
	return nil
}

// loadCloudPromptRows returns the session's user prompts as a CONTIGUOUS HEAD
// window plus a STRIDED SAMPLE across the whole remaining population, in time
// order, bounded at cloudMaxPromptRows.
//
// WHY NOT `LIMIT 200` (the F6 fix). The head-only read meant a 500-prompt
// session's excerpts were drawn entirely from its first 200 prompts, so the
// "evenly strided across the session" spread the pure selector performs was
// striding across a prefix — the end of the session could not be quoted at all.
// The head window is still needed (see cloudPromptHeadRows) so the first REAL
// prompt survives harness filtering in Go; everything past it is sampled across
// the true population.
//
// A user prompt's fullest text sits in raw_tool_input on the adapters that
// record it, with target holding a truncated rendering; the longer of the two is
// taken so the first prompt is not clipped to an ellipsis.
func loadCloudPromptRows(ctx context.Context, db cloudReader, sessionID string) ([]string, error) {
	// The population is the session's CANONICAL main-thread prompts (T-635):
	// a prompt both the tool's hook and its transcript recorded is one prompt,
	// through the one pairing table (canonicalPromptsBySession over
	// sessionmsg.CanonicalPrompts). Hook rows are only identifiable in Go, so
	// the fold reads the prompt METADATA (no text), the head plus stride is
	// chosen over the folded list here, and only the chosen rows' text is read.
	bySession, err := canonicalPromptsBySession(ctx, db,
		`a.session_id = ? AND COALESCE(a.is_sidechain, 0) = 0`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadCloudSessionTexts: prompts: %w", err)
	}
	prompts := bySession[sessionID]
	total := len(prompts)
	if total == 0 {
		return nil, nil
	}
	head := cloudPromptHeadRows
	if head > cloudMaxPromptRows {
		head = cloudMaxPromptRows
	}
	stride := 1
	if remaining := total - head; remaining > 0 {
		if budget := cloudMaxPromptRows - head; budget > 0 && remaining > budget {
			stride = (remaining + budget - 1) / budget
		}
	}
	// rn is the 1-based time-order position, the same selection the SQL
	// window used: the head, every stride-th row after it, and the last.
	var ids []int64
	for i := range prompts {
		rn := i + 1
		if rn <= head || (rn-head)%stride == 0 || rn == total {
			id, perr := strconv.ParseInt(prompts[i].ActionID, 10, 64)
			if perr != nil {
				return nil, fmt.Errorf("store.LoadCloudSessionTexts: prompt id %q: %w", prompts[i].ActionID, perr)
			}
			ids = append(ids, id)
		}
	}
	bodies := make(map[int64]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, cloudTextScanBytes)
	marks := make([]byte, 0, 2*len(ids))
	for i, id := range ids {
		if i > 0 {
			marks = append(marks, ',')
		}
		marks = append(marks, '?')
		args = append(args, id)
	}
	//nolint:gosec // G202: marks is a run of "?" placeholders; values bind via args.
	rows, err := db.QueryContext(ctx, `
		SELECT id,
		       substr(CASE WHEN length(COALESCE(raw_tool_input, '')) > length(COALESCE(target, ''))
		                   THEN raw_tool_input ELSE COALESCE(target, '') END, 1, ?)
		  FROM actions
		 WHERE id IN (`+string(marks)+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadCloudSessionTexts: prompt text: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id int64
		var body sql.NullString
		if err := rows.Scan(&id, &body); err != nil {
			return nil, fmt.Errorf("store.LoadCloudSessionTexts: scan prompt: %w", err)
		}
		bodies[id] = body.String
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadCloudSessionTexts: prompt text: %w", err)
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if body := bodies[id]; strings.TrimSpace(body) != "" {
			out = append(out, body)
		}
	}
	return out, nil
}

// cloudTextRows runs a one-column text query and returns the non-empty values.
func cloudTextRows(ctx context.Context, db cloudReader, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadCloudSessionTexts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("store.LoadCloudSessionTexts: scan: %w", err)
		}
		if strings.TrimSpace(v.String) == "" {
			continue
		}
		out = append(out, v.String)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadCloudSessionTexts: %w", err)
	}
	return out, nil
}
