package archivesvc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// Bucket B (process capture) mover — P3.4 of
// docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §9.
//
// It is the SAME copy → verify → delete shape as the Bucket A mover in
// mover.go, running the SAME verification primitive (archive.VerifyTables, via
// VerifyWindow). That reuse is the whole reason Bucket A was built first: a
// defect there costs a re-index, so it is where the safety machinery earned its
// four mutation proofs. Bucket B inherits the proven implementation rather than
// getting a second, differently-worded one.
//
// What differs is only what the difference demands:
//   - the unit is a UTC day, not a project (see archive.Window for why);
//   - the shape guard carries MAX(last_seen_at), because process_runs rows
//     mutate while a process is alive and a count would not notice;
//   - there is no rehydrate-by-replay, because reads go DIRECT to the archive
//     (design §4.3) and copying rows back would re-grow the hot database on a
//     read.

// ProcessHotStore is the slice of the hot store seam a Bucket B move needs,
// declared at the consumer.
type ProcessHotStore interface {
	// ProcessStaleWindows lists days past the archive horizon.
	ProcessStaleWindows(ctx context.Context, archiveDays, maxWindows int) ([]archive.WindowCandidate, error)
	// ProcessWindowShape reports the guard the delete re-checks.
	ProcessWindowShape(ctx context.Context, w archive.Window) (archive.WindowShape, error)
	// ProcessExportWindow streams a window's rows into sink.
	ProcessExportWindow(ctx context.Context, w archive.Window, batchRows int, sink archive.WindowSink) error
	// ProcessArchiveComplete deletes the hot rows and writes the marker in
	// one transaction, refusing if the guard moved.
	ProcessArchiveComplete(ctx context.Context, c archive.WindowCompletion) error
	// DeleteProcessArchivedWindow drops a marker whose cold rows have expired.
	DeleteProcessArchivedWindow(ctx context.Context, day string) error
}

// ProcessColdStore is the slice of internal/archivestore a Bucket B move needs.
type ProcessColdStore interface {
	archive.WindowSink
	// DeleteProcessWindow clears any prior cold copy of the window.
	DeleteProcessWindow(ctx context.Context, w archive.Window) error
	// ProcessWindowDigest re-reads the cold copy and fingerprints it.
	ProcessWindowDigest(ctx context.Context, w archive.Window, batchRows int) (*archive.WindowDigest, error)
	// ExpireProcessWindowsBefore is the cold-storage delete horizon.
	ExpireProcessWindowsBefore(ctx context.Context, cutoffDay string, maxDays int) ([]string, error)
}

// ProcessMover performs Bucket B moves. It owns no SQL.
type ProcessMover struct {
	// Hot is the hot-database seam.
	Hot ProcessHotStore
	// Cold is the archive-database seam.
	Cold ProcessColdStore
	// BatchRows bounds one streamed batch; zero applies the default.
	BatchRows int
	// Now is the injectable clock stamping archived_at.
	Now func() time.Time
}

// ProcessSweepResult is the per-pass report.
type ProcessSweepResult struct {
	// Considered is how many stale windows the selector offered.
	Considered int
	// Archived is how many completed the full copy→verify→delete.
	Archived int
	// RowsArchived is the total verified rows moved this pass.
	RowsArchived int64
	// Skipped counts windows that were empty or changed mid-move.
	Skipped int
	// Failed counts windows that errored; each is left entirely hot.
	Failed int
	// Expired is how many cold windows the expiry horizon removed.
	Expired int
}

// SweepProcess archives one bounded batch of stale process windows.
//
// Bounded, deliberately (design §5.1): a 40 GB backlog converges over a few
// ordinary retention passes rather than turning one pass into the incident this
// arc exists to prevent.
//
// A per-window failure does NOT abort the batch — one unhealthy day must not
// block every other day from leaving the hot database — and every failure mode
// leaves that window's hot rows fully intact.
func (m *ProcessMover) SweepProcess(ctx context.Context, archiveDays, maxWindows int) (ProcessSweepResult, error) {
	var res ProcessSweepResult
	candidates, err := m.Hot.ProcessStaleWindows(ctx, archiveDays, maxWindows)
	if err != nil {
		return res, fmt.Errorf("archivesvc.SweepProcess: candidates: %w", err)
	}
	res.Considered = len(candidates)

	var errs []error
	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		out, err := m.ArchiveProcessWindow(ctx, c.Window)
		if err != nil {
			res.Failed++
			errs = append(errs, err)
			continue
		}
		if out.Result == ResultArchived {
			res.Archived++
			res.RowsArchived += out.RowsArchived
		} else {
			res.Skipped++
		}
	}
	return res, errors.Join(errs...)
}

// ProcessOutcome is the per-window report of one move.
type ProcessOutcome struct {
	Window       archive.Window
	Result       Result
	RowsArchived int64
}

// ArchiveProcessWindow moves ONE day of process capture to cold storage.
//
// Step order is the safety contract, identical in shape to
// [Mover.ArchiveCodeIntelProject] and identical in intent:
//
//  1. Capture the window's shape FIRST, so the guard the delete re-checks
//     describes the state the copy actually read.
//  2. Pre-clear any cold copy left by a crashed earlier attempt. Upserting over
//     it would leave orphans that make the read-back digest disagree with the
//     hot digest forever, wedging the window permanently. Not a "delete first":
//     the hot rows are untouched throughout.
//  3. Copy hot→cold through a tee, so the HOT digest comes from the same single
//     pass that does the copying.
//  4. Read the cold copy BACK out of the archive file and fingerprint it.
//  5. Verify, with the primitive Bucket A's delete is gated on. Any mismatch
//     aborts with the hot rows intact.
//  6. Only now delete the hot rows and write the marker, in one transaction,
//     with the step-1 guard re-checked inside it.
func (m *ProcessMover) ArchiveProcessWindow(ctx context.Context, w archive.Window) (ProcessOutcome, error) {
	out := ProcessOutcome{Window: w}
	if !w.Valid() {
		return out, fmt.Errorf("archivesvc: invalid window %q", w.Day)
	}

	shape, err := m.Hot.ProcessWindowShape(ctx, w)
	if err != nil {
		return out, fmt.Errorf("archivesvc: %s: shape: %w", w.Day, err)
	}
	if shape.Empty() {
		out.Result = ResultEmpty
		return out, nil
	}

	if err := m.Cold.DeleteProcessWindow(ctx, w); err != nil {
		return out, fmt.Errorf("archivesvc: %s: pre-clear cold copy: %w", w.Day, err)
	}

	tee := archive.NewWindowTeeSink(m.Cold)
	if err := m.Hot.ProcessExportWindow(ctx, w, m.BatchRows, tee); err != nil {
		return out, fmt.Errorf("archivesvc: %s: copy: %w", w.Day, err)
	}
	hotDigest := tee.Digest()
	if hotDigest.Empty() {
		// The shape said there were rows; the export produced none. Refusing
		// beats marking the window archived: a marker with no cold rows behind
		// it is the worst possible outcome for capture that has no second copy.
		out.Result = ResultEmpty
		return out, fmt.Errorf("archivesvc: %s: shape reported %d rows but the export produced none",
			w.Day, shape.TotalRows())
	}

	coldDigest, err := m.Cold.ProcessWindowDigest(ctx, w, m.BatchRows)
	if err != nil {
		return out, fmt.Errorf("archivesvc: %s: read back cold copy: %w", w.Day, err)
	}
	if err := archive.VerifyWindow(hotDigest, coldDigest); err != nil {
		return out, fmt.Errorf("archivesvc: %s: %w", w.Day, err)
	}

	err = m.Hot.ProcessArchiveComplete(ctx, archive.WindowCompletion{
		Window:        w,
		ExpectedShape: shape,
		ArchivedAt:    m.now().Unix(),
		RowsArchived:  coldDigest.TotalRows(),
	})
	if err != nil {
		// Concurrent capture is an expected outcome, not a fault: the window
		// stays hot and is re-offered next pass.
		if errors.Is(err, archive.ErrProjectChanged) {
			out.Result = ResultChanged
			return out, nil
		}
		return out, fmt.Errorf("archivesvc: %s: complete: %w", w.Day, err)
	}

	out.Result = ResultArchived
	out.RowsArchived = coldDigest.TotalRows()
	return out, nil
}

// ExpireProcessWindows is the SECOND horizon (P3.6): the point past which even
// cold storage stops keeping process capture.
//
// The two-horizon model is the operator-visible improvement of this whole
// bucket. Today [observer.process].retention_days DELETES at 30 days and
// nothing is recoverable after that. With archival on, archive_days moves
// capture to cold storage well before that (default 14), and retention_days
// becomes the ARCHIVE FILE's own delete horizon — so the same 30 days now means
// "hot for 14, recoverable for 30" instead of "hot for 30, then gone".
//
// The marker is dropped only AFTER its rows are, so a marker never outlives the
// data it promises.
func (m *ProcessMover) ExpireProcessWindows(ctx context.Context, retentionDays, maxWindows int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	if maxWindows <= 0 {
		maxWindows = archive.DefaultMaxUnitsPerPass
	}
	cutoff := m.now().UTC().AddDate(0, 0, -retentionDays).Format("2006-01-02")
	days, err := m.Cold.ExpireProcessWindowsBefore(ctx, cutoff, maxWindows)
	if err != nil {
		return 0, fmt.Errorf("archivesvc.ExpireProcessWindows: %w", err)
	}
	var errs []error
	for _, d := range days {
		if err := m.Hot.DeleteProcessArchivedWindow(ctx, d); err != nil {
			errs = append(errs, err)
		}
	}
	return len(days), errors.Join(errs...)
}

func (m *ProcessMover) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now().UTC()
}
