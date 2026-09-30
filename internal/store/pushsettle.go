package store

import (
	"strings"
	"time"
)

// PushSettle is the token_usage settle holdback of the org push
// (S10-SPEED, agent migration 136). A transcript-timed adapter (claude-code,
// codex) can stamp a token row's generation duration (gen_ms) in a LATER
// parse than the one that first inserted the row - the proof that a
// message is complete (a later message's record, a turn_duration record)
// is often written seconds after the message itself. The org ingest is
// insert-only (ON CONFLICT DO NOTHING), so a row pushed before its stamp
// would never carry it on the org.
//
// The holdback stops the token_usage lane of SelectUnpushedSince at the
// first row that is still UNSETTLED - every one of:
//
//   - gen_ms IS NULL,
//   - tool is one of Tools (the caller resolves them from the integration
//     registry: TokenTier.GenerationTiming == transcript),
//   - the row's timestamp is newer than now - Window,
//   - no later token_usage row exists in the same session (a later row
//     means the parse that could have proven this one already ran).
//
// The cursor never passes a held row, so it ships on a later tick - stamped
// or, once Window elapses, unstamped. Rows behind it wait with it (the
// cursor is a single id watermark). The zero value (no Tools) disables the
// holdback: byte-identical to the pre-136 push.
type PushSettle struct {
	// Tools is the transcript-timed tool set. Values are bound as SQL
	// parameters.
	Tools []string
	// Window bounds how long an unstamped row is held. <= 0 disables.
	Window time.Duration
	// Now is the clock (nil = time.Now); tests inject it.
	Now func() time.Time
}

// DefaultPushSettleWindow is the holdback bound the org client uses. The
// measured stamp lag on live claude-code transcripts is a median of ~14 s
// (the completion evidence is the next message or the turn's closing
// record), so 10 minutes covers every turn short of an abandoned one.
const DefaultPushSettleWindow = 10 * time.Minute

// active reports whether the holdback applies.
func (p PushSettle) active() bool { return len(p.Tools) > 0 && p.Window > 0 }

// heldExpr returns the SQL expression (aliased token_usage "tu") that is 1
// for an unsettled row, plus its bound arguments. Only called when active.
func (p PushSettle) heldExpr() (string, []any) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	cutoff := now().UTC().Add(-p.Window).Format("2006-01-02T15:04:05.000Z")
	ph := strings.TrimSuffix(strings.Repeat("?,", len(p.Tools)), ",")
	args := make([]any, 0, len(p.Tools)+1)
	for _, t := range p.Tools {
		args = append(args, t)
	}
	args = append(args, cutoff)
	// julianday() of an unparseable timestamp is NULL, so the comparison is
	// NULL and the row is NOT held: the holdback fails open to "push".
	expr := `CASE WHEN tu.gen_ms IS NULL
	              AND tu.tool IN (` + ph + `)
	              AND julianday(tu.timestamp) > julianday(?)
	              AND NOT EXISTS (SELECT 1 FROM token_usage tu2
	                               WHERE tu2.session_id = tu.session_id AND tu2.id > tu.id)
	         THEN 1 ELSE 0 END`
	return expr, args
}
