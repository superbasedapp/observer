package store

import (
	"context"
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
			    AND (gen_ms IS NULL OR COALESCE(gen_timing_v, 0) < ?)`,
			e.GenMs, genBasisOrNull(e), e.GenTimingV,
			e.SourceFile, e.SourceEventID, e.GenTimingV); err != nil {
			return fmt.Errorf("store.stampGenTiming: %w", err)
		}
	}
	return nil
}
