package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// genMsOrNull / genBasisOrNull / genTimingVOrNull map a TokenEvent's
// generation-timing triple (agent migration 136, S10-SPEED) onto the
// token_usage insert: all three NULL unless the adapter captured a positive
// duration, so a row without timing is byte-identical to a pre-136 row.
func genMsOrNull(e models.TokenEvent) any {
	if e.GenMs <= 0 {
		return nil
	}
	return e.GenMs
}

func genBasisOrNull(e models.TokenEvent) any {
	if e.GenMs <= 0 || e.GenBasis == "" {
		return nil
	}
	return e.GenBasis
}

func genTimingVOrNull(e models.TokenEvent) any {
	if e.GenMs <= 0 {
		return nil
	}
	return e.GenTimingV
}

// splitGenStamps separates stamp-only re-emissions (TokenEvent.GenStampOnly)
// from the rows to insert. A stamp-only event without a duration carries
// nothing and is dropped.
func splitGenStamps(tokens []models.TokenEvent) (insert, stamps []models.TokenEvent) {
	for _, tk := range tokens {
		switch {
		case !tk.GenStampOnly:
			insert = append(insert, tk)
		case tk.GenMs > 0 && tk.SourceFile != "" && tk.SourceEventID != "":
			stamps = append(stamps, tk)
		}
	}
	return insert, stamps
}

// stampGenTiming is the narrow seam for a generation-timing stamp proven
// AFTER the row's first insert: it UPDATEs only gen_ms / gen_basis /
// gen_timing_v of an EXISTING (source_file, source_event_id) row, under the
// same rule as the InsertTokenEvents upsert (fill a NULL, or replace a
// strictly older parser version). A missing row (never inserted, or pruned
// by retention) is left missing.
func (s *Store) stampGenTiming(ctx context.Context, stamps []models.TokenEvent) error {
	for _, e := range stamps {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE token_usage SET gen_ms = ?, gen_basis = ?, gen_timing_v = ?
			  WHERE source_file = ? AND source_event_id = ?
			    AND `+genStampRule,
			e.GenMs, genBasisOrNull(e), e.GenTimingV,
			e.SourceFile, e.SourceEventID, e.GenTimingV); err != nil {
			return fmt.Errorf("store.stampGenTiming: %w", err)
		}
	}
	return nil
}

// genStampRule is the one after-the-fact stamp rule both stamp seams share
// (the InsertTokenEvents upsert states the same rule for an insert): a stamp
// lands on a row with no timing, or replaces a STRICTLY older parser
// version. Its single placeholder is the stamp's gen_timing_v.
const genStampRule = `(gen_ms IS NULL OR COALESCE(gen_timing_v, 0) < ?)`

// TranscriptKeyMessageID is the transcript token_usage column an export's
// per-call id may equal (otlpvendor.TimingKeyMessageID, pinned equal by a
// cmd/observer test).
const TranscriptKeyMessageID = "message_id"

// transcriptKeyColumns is the closed table of token_usage columns a
// TranscriptGenStamp may be keyed on: the key name is never spliced into SQL
// unless it is a row here.
var transcriptKeyColumns = map[string]string{
	TranscriptKeyMessageID: "message_id",
}

// TranscriptGenStamp is one generation duration a tool's own OpenTelemetry
// export reported for a model call, addressed to the TRANSCRIPT's token row
// for the same call: the row of Tool in SessionID whose Key column equals
// KeyValue.
type TranscriptGenStamp struct {
	Tool      string
	SessionID string
	Key       string
	KeyValue  string
	GenMs     int64
}

// GenStampOutcome says what StampTranscriptGenTiming did.
type GenStampOutcome int

// Stamp outcomes.
const (
	// GenStampApplied: the row had no timing and now carries the stamp.
	GenStampApplied GenStampOutcome = iota + 1
	// GenStampKept: the row exists and its own timing wins (an adapter's
	// native or transcript timing, or an earlier export stamp).
	GenStampKept
	// GenStampNoRow: no transcript row matches yet (not ingested, or pruned).
	GenStampNoRow
)

// StampTranscriptGenTiming is the one seam that writes an OTel-export
// generation duration onto a transcript token row (AP-131 follow-up). It
// UPDATEs only gen_ms / gen_basis / gen_timing_v, with basis
// models.GenBasisOTel at version models.GenTimingVOTel (the floor), under
// genStampRule: so it only fills a row whose gen_ms is NULL, never replaces
// an adapter's timing, and is itself replaced by any adapter timing that
// arrives later (every adapter version is >= 1). It never inserts: a missing
// row is reported as GenStampNoRow for the caller to retry.
func (s *Store) StampTranscriptGenTiming(ctx context.Context, st TranscriptGenStamp) (GenStampOutcome, error) {
	col, ok := transcriptKeyColumns[st.Key]
	if !ok {
		return 0, fmt.Errorf("store.StampTranscriptGenTiming: unknown transcript key %q", st.Key)
	}
	if st.GenMs <= 0 || st.Tool == "" || st.SessionID == "" || st.KeyValue == "" {
		return 0, fmt.Errorf("store.StampTranscriptGenTiming: incomplete stamp %+v", st)
	}
	where := `tool = ? AND session_id = ? AND ` + col + ` = ?`
	//nolint:gosec // G202: col comes from the closed transcriptKeyColumns table, values are bound.
	res, err := s.db.ExecContext(ctx,
		`UPDATE token_usage SET gen_ms = ?, gen_basis = ?, gen_timing_v = ?
		  WHERE `+where+` AND `+genStampRule,
		st.GenMs, models.GenBasisOTel, models.GenTimingVOTel,
		st.Tool, st.SessionID, st.KeyValue, models.GenTimingVOTel)
	if err != nil {
		return 0, fmt.Errorf("store.StampTranscriptGenTiming: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		return GenStampApplied, nil
	}
	var one int
	//nolint:gosec // G202: col comes from the closed transcriptKeyColumns table, values are bound.
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM token_usage WHERE `+where+` LIMIT 1`,
		st.Tool, st.SessionID, st.KeyValue).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return GenStampNoRow, nil
	case err != nil:
		return 0, fmt.Errorf("store.StampTranscriptGenTiming: %w", err)
	}
	return GenStampKept, nil
}
