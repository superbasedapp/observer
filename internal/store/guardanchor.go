package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"time"
)

// guardAnchorUnprovenListMax caps GuardAnchorRepairReport.Unproven.
const guardAnchorUnprovenListMax = 20

// guardAnchorProgressEvery is the default GuardAnchorRepairOptions.ProgressEvery.
const guardAnchorProgressEvery = 10 * time.Second

// GuardAnchorRepairOptions selects what RepairGuardAnchors does.
type GuardAnchorRepairOptions struct {
	// Apply writes the proven anchors; false only reports.
	Apply bool
	// Ceiling is the highest action id tried. 0 means the highest id the
	// node ever issued for an action (sqlite_sequence; actions ids are
	// AUTOINCREMENT, so never reused).
	Ceiling int64
	// Radius bounds each row's search to the action ids within Radius of the
	// row's hint, [hint-Radius, hint+Radius] inside [1, Ceiling]. 0 searches
	// the whole [1, Ceiling] for every row.
	Radius int64
	// Workers is how many goroutines hash one row's range once the first
	// block around its hint has not proven it. <= 0 means
	// DefaultGuardAnchorWorkers(). The result does not depend on it.
	Workers int
	// Progress, when non-nil, is called every ProgressEvery (default 10 s)
	// from its own goroutine while the search runs.
	Progress      func(GuardAnchorProgress)
	ProgressEvery time.Duration
}

// GuardAnchorProgress is a snapshot of a running RepairGuardAnchors search.
type GuardAnchorProgress struct {
	// Done is the number of candidates searched so far, of Candidates.
	Done, Candidates int
	Proven, Unproven int
	// Hashed is the number of hashes computed so far.
	Hashed  int64
	Elapsed time.Duration
}

// GuardAnchorUnproven is one candidate no action id in its search range
// reproduced, and why.
type GuardAnchorUnproven struct {
	ID int64
	// Hint, Lo and Hi are the row's first window, Windows how many windows
	// were searched and Skipped how many were not searched again because an
	// earlier row with the same content came up empty in them (all 0 when the
	// row could not be searched at all).
	Hint, Lo, Hi     int64
	Windows, Skipped int
	Reason           string
}

// Reasons a candidate stays unproven, besides the newGuardAnchorPreimage ones.
const (
	// GuardAnchorOutsideRadius: every window was bounded by the radius and no
	// id in any of them matched. A wider --radius (0 = the whole range) searches further.
	GuardAnchorOutsideRadius = "no action id within the radius reproduces its stored hash"
	// GuardAnchorNoID: the whole [1, Ceiling] was searched. The row was
	// edited in some other way, or its id lies above the ceiling.
	GuardAnchorNoID = "no action id in the whole range reproduces its stored hash"
	// GuardAnchorRepeatMissed: like GuardAnchorOutsideRadius, but at least one
	// window was not searched again because an earlier row with the same
	// content (a repeat carries the same action id) came up empty in it.
	GuardAnchorRepeatMissed = "no action id within the radius reproduces its stored hash (windows an identical earlier row came up empty in were not searched again)"
	// guardAnchorSplitMismatch: the fast path matched an id the canonical
	// bytes do not confirm. A bug guard, never expected; the row is left.
	guardAnchorSplitMismatch = "the split preimage disagrees with the canonical bytes"
)

// GuardAnchorRepairReport is the result of RepairGuardAnchors.
type GuardAnchorRepairReport struct {
	// Candidates is the number of rows that fail verification as rewritten
	// rows and carry no action id at all (action_id and action_anchor both
	// NULL): the shape maintenance left before agent migration 197.
	Candidates int
	// Proven is the number of candidates whose stored chain_hash one action
	// id reproduces, every other column as stored.
	Proven int
	// Unproven lists the first candidates no action id in their search range
	// reproduced (at most guardAnchorUnprovenListMax), with the reason;
	// UnprovenCount counts all of them and UnprovenByReason by reason. Those
	// rows stay reported by verify-audit.
	Unproven         []GuardAnchorUnproven
	UnprovenCount    int
	UnprovenByReason map[string]int
	// Ceiling is the highest action id tried.
	Ceiling int64
	// Radius is the search radius around each row's hint (0 = whole range).
	Radius int64
	// Workers is the number of hashing goroutines per row.
	Workers int
	// Tries is the number of ids the searches tried in walk order: every id
	// of each window that did not prove the row, and in the window that did,
	// the ids up to and including its anchor. It is what a single-goroutine
	// search computes and does not depend on Workers.
	Tries int64
	// Hashed is the number of hashes actually computed (>= Tries; workers
	// may finish a block past a row's anchor).
	Hashed int64
	// Distances counts the proven rows per hint rule (GuardAnchorHint*) by
	// how far the anchor lay from that hint (GuardAnchorDistanceBuckets
	// order).
	Distances map[string][]int
	// Elapsed is the time the search took (not the write).
	Elapsed time.Duration
	// Interrupted is true when the context was cancelled during the search:
	// the counts cover the rows searched so far and nothing was written.
	Interrupted bool
	// Repaired is the number of rows whose action_anchor was written
	// (Apply only).
	Repaired int
	// Applied is true when the proven anchors were written.
	Applied bool
}

// GuardAnchorDistanceBuckets are the upper bounds (inclusive) of the
// GuardAnchorRepairReport.Distances buckets; the last bucket is everything
// above the last bound.
var GuardAnchorDistanceBuckets = []int64{0, 10, 100, 1_000, 10_000, 100_000, 1_000_000}

// guardAnchorDistanceBucket is the Distances index for distance d (>= 0).
func guardAnchorDistanceBucket(d int64) int {
	for i, bound := range GuardAnchorDistanceBuckets {
		if d <= bound {
			return i
		}
	}
	return len(GuardAnchorDistanceBuckets)
}

// guardAnchorFix is one proven repair: row id and the action id that
// reproduces its stored hash.
type guardAnchorFix struct {
	id, anchor int64
}

// RepairGuardAnchors restores the action id of guard_events rows whose
// action_id maintenance cleared before agent migration 197 (ledger
// GUARD-CHAIN-1). Such a row hashes to a value its stored columns no longer
// reproduce, so verify-audit reports it as a rewritten row.
//
// The repair is a proof, not a judgement: for each such row it tries action
// ids and accepts one only when SHA-256(chain_prev || 0x1e || canonical
// bytes with that id) equals the row's stored chain_hash, every other column
// exactly as stored. A row edited in any other way reproduces no hash and is
// left as it is; no chain_prev or chain_hash is ever rewritten, so a broken
// link (a deleted row) stays reported. The only column written is
// action_anchor, and only where it and action_id are both NULL.
//
// Each row is searched outward from its hints (guardAnchorHintRules) in
// turn, within opts.Radius of each when set; a row no id in those windows
// proves is reported unproven with the reason, never guessed. The search
// runs outside any write transaction; Apply then takes the write lock and
// re-proves each row inside it before writing, so a row that changed in
// between is skipped. A cancelled
// ctx returns the partial report (Interrupted) with ctx's error and writes
// nothing.
func (s *Store) RepairGuardAnchors(ctx context.Context, opts GuardAnchorRepairOptions) (GuardAnchorRepairReport, error) {
	report := GuardAnchorRepairReport{
		Ceiling: opts.Ceiling, Radius: max(opts.Radius, 0), Workers: opts.Workers,
		UnprovenByReason: map[string]int{},
		Distances:        map[string][]int{},
	}
	if report.Workers <= 0 {
		report.Workers = DefaultGuardAnchorWorkers()
	}
	if report.Ceiling <= 0 {
		ceiling, err := s.actionIDCeiling(ctx)
		if err != nil {
			return report, err
		}
		report.Ceiling = ceiling
	}

	rows, err := s.db.QueryContext(ctx, guardEventSelectColumns+` ORDER BY id ASC`)
	if err != nil {
		return report, fmt.Errorf("store.RepairGuardAnchors: query: %w", err)
	}
	all, err := loadGuardEventRows(rows, "store.RepairGuardAnchors")
	if err != nil {
		return report, err
	}
	// Pre-pass: which rows are candidates, so progress knows the total.
	candidate := make([]bool, len(all))
	for i := range all {
		r := &all[i]
		if r.hashedActionID() != nil {
			continue
		}
		if guardChainHash(r.ChainPrev, r.canonicalBytes()) == r.ChainHash {
			continue // an action-less row that verifies (a hook verdict)
		}
		candidate[i] = true
		report.Candidates++
	}

	var done, proven, unproven atomic.Int64
	var hashed atomic.Int64
	start := time.Now()
	stopProgress := startGuardAnchorProgress(opts, report.Candidates, start, &done, &proven, &unproven, &hashed)
	defer stopProgress()

	// next[i] is the anchor of the first row after i that still carries one.
	next := make([]int64, len(all))
	for i, nextID := len(all)-1, int64(0); i >= 0; i-- {
		next[i] = nextID
		if id := all[i].hashedActionID(); id != nil {
			nextID = *id
		}
	}

	hints := newGuardAnchorHints()
	search := guardAnchorSearcher{
		radius: report.Radius, ceiling: report.Ceiling, workers: report.Workers,
		hashed: &hashed, memo: hints,
	}
	var fixes []guardAnchorFix
	var misses []guardAnchorMiss // every unproven candidate, in id order
	for i := range all {
		r := &all[i]
		if !candidate[i] {
			if id := r.hashedActionID(); id != nil {
				hints.observe(r, *id)
			}
			continue
		}
		var out guardAnchorOutcome
		p, why := newGuardAnchorPreimage(r)
		if p == nil {
			out.miss = &GuardAnchorUnproven{ID: r.ID, Reason: why}
		} else {
			out, err = search.prove(ctx, r, p, hints.hintsFor(guardAnchorHintInput{row: r, key: p.key, next: next[i]}))
			if err != nil {
				report.Interrupted = true
				report.Hashed = hashed.Load()
				report.Elapsed = time.Since(start)
				report.addMisses(misses)
				return report, err
			}
		}
		done.Add(1)
		report.Tries += out.tries
		if out.miss != nil {
			unproven.Add(1)
			misses = append(misses, guardAnchorMiss{row: r, preimage: p, entry: *out.miss})
			continue
		}
		proven.Add(1)
		report.addProven(out.rule, out.dist)
		fixes = append(fixes, guardAnchorFix{id: r.ID, anchor: out.anchor})
		hints.observeProven(r, p.key, out.anchor)
	}
	// Retry pass: a row whose content was proven only by a LATER row tries
	// that anchor (one hash), so a repeat that preceded its content's first
	// proof is not left behind.
	kept := misses[:0]
	for _, m := range misses {
		if anchor, ok := search.retry(m); ok {
			report.Tries++
			proven.Add(1)
			unproven.Add(-1)
			report.addProven(GuardAnchorHintContent, 0)
			fixes = append(fixes, guardAnchorFix{id: m.row.ID, anchor: anchor})
			continue
		}
		kept = append(kept, m)
	}
	report.addMisses(kept)
	report.Hashed = hashed.Load()
	report.Elapsed = time.Since(start)
	stopProgress()
	if !opts.Apply || len(fixes) == 0 {
		return report, nil
	}
	sort.Slice(fixes, func(a, b int) bool { return fixes[a].id < fixes[b].id })
	n, err := s.writeGuardAnchors(ctx, fixes)
	if err != nil {
		return report, err
	}
	report.Repaired = n
	report.Applied = true
	return report, nil
}

// addProven counts one proven row under its hint rule and distance bucket.
func (r *GuardAnchorRepairReport) addProven(rule string, dist int64) {
	r.Proven++
	if r.Distances[rule] == nil {
		r.Distances[rule] = make([]int, len(GuardAnchorDistanceBuckets)+1)
	}
	r.Distances[rule][guardAnchorDistanceBucket(dist)]++
}

// addMisses records the unproven candidates (in id order).
func (r *GuardAnchorRepairReport) addMisses(misses []guardAnchorMiss) {
	for _, m := range misses {
		r.UnprovenCount++
		r.UnprovenByReason[m.entry.Reason]++
		if len(r.Unproven) < guardAnchorUnprovenListMax {
			r.Unproven = append(r.Unproven, m.entry)
		}
	}
}

// guardAnchorMiss is one unproven candidate kept for the retry pass.
type guardAnchorMiss struct {
	row      *GuardEventRow
	preimage *guardAnchorPreimage // nil when the row cannot be searched
	entry    GuardAnchorUnproven
}

// guardAnchorOutcome is one candidate's search result: the proven anchor
// (with the hint rule whose window proved it and the distance from that
// hint) or the unproven entry, and the walk-order tries over every window
// searched.
type guardAnchorOutcome struct {
	anchor int64
	rule   string
	dist   int64
	tries  int64
	miss   *GuardAnchorUnproven
}

// guardAnchorSearcher proves candidates one at a time.
type guardAnchorSearcher struct {
	radius, ceiling int64
	workers         int
	hashed          *atomic.Int64
	// memo holds the anchors proven so far (the retry pass) and the bounded
	// windows each content already came up empty in.
	memo *guardAnchorHints
}

// prove searches one candidate: the window around each hint in turn (radius
// 0: the whole range, searched once), stopping at the first window that
// proves it. With a radius, a window an earlier row with the same content
// already came up empty in is not searched again: repeats of one row carry
// its action id (guardAnchorHintRules), so searching it again would only
// repeat the miss for every repeat. The proof of record is the canonical
// serialization: an id the split preimage matched is accepted only when
// canonicalBytes with it reproduces the stored hash.
func (s guardAnchorSearcher) prove(ctx context.Context, r *GuardEventRow, p *guardAnchorPreimage, hints []guardAnchorHint) (guardAnchorOutcome, error) {
	var out guardAnchorOutcome
	miss := &GuardAnchorUnproven{ID: r.ID, Reason: GuardAnchorOutsideRadius}
	var searched []guardAnchorWindow // this row's windows so far, merged
	for _, h := range hints {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		w, ok := newGuardAnchorWalk(h.id, s.radius, s.ceiling)
		if !ok {
			miss.Reason = GuardAnchorNoID // no action id was ever issued
			break
		}
		if miss.Windows == 0 && miss.Skipped == 0 {
			miss.Hint, miss.Lo, miss.Hi = w.hint, w.lo, w.hi
		}
		bounded := !w.whole(s.ceiling)
		if bounded && s.memo.missedBefore(p.key, w) {
			miss.Skipped++
			continue
		}
		miss.Windows++
		// Ids an earlier window of this row already tried are not tried again,
		// so a row never costs more than one walk over the whole range.
		w.skip = searched
		anchor, found, err := searchGuardAnchor(ctx, p, w, s.workers, s.hashed)
		if err != nil {
			return out, err
		}
		if !found {
			out.tries += w.size()
			searched = mergeGuardAnchorWindows(append(searched, w.window()))
			if len(searched) == 1 && searched[0] == (guardAnchorWindow{1, s.ceiling}) {
				miss.Reason = GuardAnchorNoID
				break // every id has been tried
			}
			if bounded {
				s.memo.markMissed(p.key, w)
			}
			continue
		}
		out.tries += w.triesThrough(anchor)
		if !confirmGuardAnchor(r, anchor) {
			miss.Reason = guardAnchorSplitMismatch
			break
		}
		out.anchor, out.rule, out.dist = anchor, h.rule, absInt64(anchor-w.hint)
		return out, nil
	}
	if miss.Reason == GuardAnchorOutsideRadius && miss.Skipped > 0 {
		miss.Reason = GuardAnchorRepeatMissed
	}
	out.miss = miss
	return out, nil
}

// retry tries an unproven candidate at the latest anchor proven for its
// content (one hash), for the retry pass.
func (s guardAnchorSearcher) retry(m guardAnchorMiss) (int64, bool) {
	if m.preimage == nil || (m.entry.Reason != GuardAnchorOutsideRadius && m.entry.Reason != GuardAnchorRepeatMissed) {
		return 0, false
	}
	anchor, ok := s.memo.content[m.preimage.key]
	if !ok || anchor > s.ceiling {
		return 0, false
	}
	s.hashed.Add(1)
	if !m.preimage.newTrier().try(anchor) || !confirmGuardAnchor(m.row, anchor) {
		return 0, false
	}
	return anchor, true
}

// confirmGuardAnchor is the proof of record: r with action id anchor and
// every other column as stored reproduces its stored chain_hash. r is left
// without an anchor.
func confirmGuardAnchor(r *GuardEventRow, anchor int64) bool {
	r.actionAnchor = &anchor
	defer func() { r.actionAnchor = nil }()
	return guardChainHash(r.ChainPrev, r.canonicalBytes()) == r.ChainHash
}

// startGuardAnchorProgress calls opts.Progress every opts.ProgressEvery
// until the returned stop func is called (idempotent). A nil Progress
// starts nothing.
func startGuardAnchorProgress(opts GuardAnchorRepairOptions, candidates int, start time.Time, done, proven, unproven, hashed *atomic.Int64) func() {
	if opts.Progress == nil {
		return func() {}
	}
	every := opts.ProgressEvery
	if every <= 0 {
		every = guardAnchorProgressEvery
	}
	quit := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-quit:
				return
			case <-t.C:
				opts.Progress(GuardAnchorProgress{
					Done: int(done.Load()), Candidates: candidates,
					Proven: int(proven.Load()), Unproven: int(unproven.Load()),
					Hashed: hashed.Load(), Elapsed: time.Since(start),
				})
			}
		}
	}()
	var once atomic.Bool
	return func() {
		if once.CompareAndSwap(false, true) {
			close(quit)
			<-finished
		}
	}
}

// absInt64 is |v|.
func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// actionIDCeiling is the highest action id this node ever issued.
func (s *Store) actionIDCeiling(ctx context.Context) (int64, error) {
	var ceiling int64
	err := s.db.QueryRowContext(ctx, `
		SELECT MAX(
		    COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'actions'), 0),
		    COALESCE((SELECT MAX(id) FROM actions), 0),
		    COALESCE((SELECT MAX(action_anchor) FROM guard_events), 0))`).Scan(&ceiling)
	if err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: ceiling: %w", err)
	}
	return ceiling, nil
}

// writeGuardAnchors re-proves and writes each fix in one write transaction
// and returns how many rows it wrote.
func (s *Store) writeGuardAnchors(ctx context.Context, fixes []guardAnchorFix) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Take the write lock first (the DedupGuardEvents pattern): no writer
	// can change a row between its re-proof and its update.
	if _, err := tx.ExecContext(ctx,
		`UPDATE schema_meta SET value = value WHERE key = ?`, guardChainCheckpointKey); err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: lock: %w", err)
	}
	upd, err := tx.PrepareContext(ctx,
		`UPDATE guard_events SET action_anchor = ? WHERE id = ? AND action_id IS NULL AND action_anchor IS NULL`)
	if err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: prepare: %w", err)
	}
	defer upd.Close()
	written := 0
	for _, f := range fixes {
		r, err := scanGuardEventRow(tx.QueryRowContext(ctx, guardEventSelectColumns+` WHERE id = ?`, f.id))
		if errors.Is(err, sql.ErrNoRows) {
			continue // the row is gone (a prune or dedup in between)
		}
		if err != nil {
			return 0, fmt.Errorf("store.RepairGuardAnchors: reload %d: %w", f.id, err)
		}
		if r.hashedActionID() != nil {
			continue
		}
		anchor := f.anchor
		r.actionAnchor = &anchor
		if guardChainHash(r.ChainPrev, r.canonicalBytes()) != r.ChainHash {
			continue
		}
		res, err := upd.ExecContext(ctx, f.anchor, f.id)
		if err != nil {
			return 0, fmt.Errorf("store.RepairGuardAnchors: update %d: %w", f.id, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			written++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.RepairGuardAnchors: commit: %w", err)
	}
	return written, nil
}
