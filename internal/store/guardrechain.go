package store

import (
	"context"
	"fmt"
	"time"
)

// GuardRechainReport is the result of RechainGuardGaps.
type GuardRechainReport struct {
	// Gaps is the number of rows whose link fails only because the row
	// before them was deleted.
	Gaps int
	// FirstGapID is the first such row: every link from here on is
	// rewritten (0 when there are none).
	FirstGapID int64
	// Rehashed is the number of rows whose chain_prev / chain_hash was
	// rewritten.
	Rehashed int
	// OldTailHash is the chain_hash of the newest row before the rewrite:
	// the value an earlier export or org copy of the chain ends on.
	OldTailHash string
	// MarkerID is the id of the guard_rechain row recording the rewrite.
	MarkerID int64
	// Applied is true when the links were rewritten and the marker added.
	Applied bool
	// Refused is non-empty when the chain holds a break that is not a
	// deletion gap, and says which.
	Refused string
}

// GuardRechainRuleID is the rule_id of the marker row RechainGuardGaps
// appends, so the rewrite is itself on the record.
const GuardRechainRuleID = "guard_rechain"

// RechainGuardGaps re-links the guard_events chain over deletion gaps: rows
// whose stored chain_prev names a row that no longer exists (observer guard
// dedup-events --keep-hashes leaves one per deleted run). A row counts as a
// gap only when ALL of these hold, so a re-link can never cover an edit:
// its only failure is the broken link, its own content still hashes to its
// stored chain_hash under its stored chain_prev, and the id just below it
// is absent. Any other failing row refuses the whole run.
//
// With apply, every link from the first gap on is recomputed and a marker
// row (rule GuardRechainRuleID) is appended in the same transaction,
// recording the gap count and the old tail hash, so a chain exported or
// pushed before the rewrite can still be matched to this one. Runs in one
// write transaction taken before any read, like DedupGuardEvents.
func (s *Store) RechainGuardGaps(ctx context.Context, apply bool, now time.Time) (GuardRechainReport, error) {
	var report GuardRechainReport
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("store.RechainGuardGaps: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`UPDATE schema_meta SET value = value WHERE key = ?`, guardChainCheckpointKey); err != nil {
		return report, fmt.Errorf("store.RechainGuardGaps: lock: %w", err)
	}

	anchor, err := guardAnchorBefore(ctx, tx, 0)
	if err != nil {
		return report, err
	}
	rows, err := loadGuardEventRowsTx(ctx, tx, 0)
	if err != nil {
		return report, err
	}
	present := make(map[int64]bool, len(rows))
	for i := range rows {
		present[rows[i].ID] = true
	}

	firstGap := -1
	prev := anchor
	for i := range rows {
		r := &rows[i]
		classes := guardRowBreaks(prev, r)
		switch {
		case len(classes) == 0:
		case len(classes) == 1 && classes[0] == guardBreakLink && !present[r.ID-1]:
			report.Gaps++
			if firstGap < 0 {
				firstGap = i
				report.FirstGapID = r.ID
			}
		default:
			report.Refused = fmt.Sprintf(
				"id %d fails as %s, which is not a deletion gap; re-linking over it would hide it", r.ID, classes[0])
			return report, nil
		}
		prev = r.ChainHash
	}
	if report.Gaps == 0 {
		return report, nil
	}
	report.OldTailHash = rows[len(rows)-1].ChainHash
	if !apply {
		return report, nil
	}

	upd, err := tx.PrepareContext(ctx,
		`UPDATE guard_events SET chain_prev = ?, chain_hash = ? WHERE id = ?`)
	if err != nil {
		return report, fmt.Errorf("store.RechainGuardGaps: prepare: %w", err)
	}
	defer upd.Close()
	link := anchor
	if firstGap > 0 {
		link = rows[firstGap-1].ChainHash
	}
	for i := firstGap; i < len(rows); i++ {
		r := &rows[i]
		hash := guardChainHash(link, r.canonicalBytes())
		if r.ChainPrev != link || r.ChainHash != hash {
			if _, err := upd.ExecContext(ctx, link, hash, r.ID); err != nil {
				return report, fmt.Errorf("store.RechainGuardGaps: rewrite %d: %w", r.ID, err)
			}
			report.Rehashed++
		}
		link = hash
	}

	marker := GuardEventRow{
		TS:        now,
		Tool:      "observer",
		EventKind: "audit",
		RuleID:    GuardRechainRuleID,
		Category:  "posture",
		Severity:  "info",
		Decision:  "allow",
		Source:    "observer",
		Reason: fmt.Sprintf(
			"audit chain re-linked over %d deletion gap(s) from id %d (rows removed by observer guard dedup-events); %d link(s) rewritten; previous tail hash %s",
			report.Gaps, report.FirstGapID, report.Rehashed, report.OldTailHash),
	}
	if err := insertGuardEventsTx(ctx, tx, []GuardEventRow{marker}); err != nil {
		return report, err
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT MAX(id) FROM guard_events`).Scan(&report.MarkerID); err != nil {
		return report, fmt.Errorf("store.RechainGuardGaps: marker id: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return report, fmt.Errorf("store.RechainGuardGaps: commit: %w", err)
	}
	report.Applied = true
	return report, nil
}
