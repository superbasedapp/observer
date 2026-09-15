package archivesvc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// HotStore is the slice of the hot store seam (internal/store) an archive move
// needs. It is declared HERE, at the consumer, so this package depends on a
// narrow behaviour contract rather than on *store.Store — and so a test can
// exercise the mover's ordering against a fake without a SQLite file.
type HotStore interface {
	// CodeIntelStaleProjects lists projects past the staleness horizon.
	CodeIntelStaleProjects(ctx context.Context, retentionDays int) ([]archive.Candidate, error)
	// CodeIntelProjectShape reports the (watermark, files) guard pair.
	CodeIntelProjectShape(ctx context.Context, project string) (watermark, files int64, err error)
	// CodeIntelExportProject streams the project's rows into sink.
	CodeIntelExportProject(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error
	// CodeIntelArchiveComplete deletes the hot rows and writes the marker in
	// one transaction, refusing if the guard pair moved.
	CodeIntelArchiveComplete(ctx context.Context, c archive.Completion) error

	// --- rehydrate half (P2) ---

	// CodeIntelArchivedProject reports the marker row, if any.
	CodeIntelArchivedProject(ctx context.Context, project string) (archive.Marker, bool, error)
	// CodeIntelClearArchivedProject removes the marker row.
	CodeIntelClearArchivedProject(ctx context.Context, project string) error
	// CodeIntelDeleteProject clears a project's hot rows.
	//
	// The rehydrate path calls this, which reads alarming until you see why:
	// a replay must land on an EMPTY hot project. codeintel_minhash has no
	// unique constraint hot-side, so replaying onto leftovers duplicates
	// bands, and a crashed earlier replay is exactly the state that leaves
	// leftovers. Deleting them is not data loss — the archive copy is intact
	// and about to be re-read — and the rehydrate refuses to run at all when
	// the hot rows are NEWER than the marker (a live re-index).
	//
	// Declaring the real name rather than a soothing alias keeps "one owner
	// per table": there is one project-delete fan-out in this codebase, not
	// two that can drift.
	CodeIntelDeleteProject(ctx context.Context, project string) error
	// CodeIntelImportSink returns the sink that replays archived rows into
	// the hot tables with their ids preserved.
	CodeIntelImportSink(project string) archive.ProjectSink
	// CodeIntelProjectDigest fingerprints the project's CURRENT hot rows —
	// used after a replay to verify what actually landed.
	CodeIntelProjectDigest(ctx context.Context, project string, batchRows int) (archive.ProjectDigest, error)
	// CodeIntelBuildDerived rebuilds the FTS + embedding rows for a project.
	CodeIntelBuildDerived(ctx context.Context, project string) error
	// CodeIntelResolveCalls re-runs name-matched CALLS resolution. Idempotent
	// (it only fills dst_id=0 edges), so on a faithfully replayed project it
	// resolves nothing — it is run anyway so a rehydrated project converges
	// on exactly the state a fresh index produces.
	CodeIntelResolveCalls(ctx context.Context, project string) (int, error)
}

// ColdStore is the slice of internal/archivestore an archive move needs. It
// embeds archive.ProjectSink because the copy writes THROUGH the sink seam —
// the mover never learns the archive's schema.
type ColdStore interface {
	archive.ProjectSink
	// DeleteCodeIntelProject clears any prior cold copy of the project.
	DeleteCodeIntelProject(ctx context.Context, project string) error
	// CodeIntelProjectDigest re-reads the cold copy and fingerprints it.
	CodeIntelProjectDigest(ctx context.Context, project string, batchRows int) (archive.ProjectDigest, error)
	// StreamCodeIntelProject reads the cold copy back out through a sink —
	// the same reader verification uses, pointed at the hot import sink.
	StreamCodeIntelProject(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error
	// CodeIntelProjectParsers reports the DISTINCT parser backends behind the
	// cold copy, for the staleness pre-check.
	CodeIntelProjectParsers(ctx context.Context, project string) ([]string, error)
}

// Result classifies what happened to one candidate.
type Result int

const (
	// ResultUnknown is the ZERO VALUE, and it deliberately does not mean
	// "archived".
	//
	// Every failure path returns a zero-valued Outcome alongside its error.
	// If the zero value were ResultArchived, a caller that inspected the
	// outcome before the error — or a test that forgot to — would read
	// "archived" off a move that never happened. On the only-copy bucket that
	// misreading is the difference between "your process trail is in cold
	// storage" and "your process trail is gone", so the zero value is
	// reserved for "no move was concluded".
	ResultUnknown Result = iota
	// ResultArchived means the rows were copied, verified, and removed from
	// the hot database, and the marker was written.
	ResultArchived
	// ResultEmpty means the project had no rows to move. Nothing is written
	// and NO marker is created: claiming a project is recoverable from cold
	// storage when nothing was put there would be a lie the honest-surface
	// work in P2 then faithfully repeats.
	ResultEmpty
	// ResultChanged means the project was re-indexed mid-move, so the hot
	// delete refused. The cold copy is left in place (it is a harmless
	// superset that the next attempt overwrites) and the project stays hot.
	// This is a normal outcome, not a failure.
	ResultChanged
)

// String renders the result for logs.
func (r Result) String() string {
	switch r {
	case ResultUnknown:
		return "unknown"
	case ResultArchived:
		return "archived"
	case ResultEmpty:
		return "empty"
	case ResultChanged:
		return "changed"
	default:
		return "unknown"
	}
}

// Outcome is the per-project report of one move.
type Outcome struct {
	Project      string
	Result       Result
	RowsArchived int64
}

// SweepResult is the per-pass report the retention orchestration records.
type SweepResult struct {
	// Considered is how many stale projects existed before the per-pass cap.
	Considered int
	// Attempted is how many this pass actually tried (the capped batch).
	Attempted int
	// Archived is how many completed the full copy→verify→delete.
	Archived int
	// RowsArchived is the total verified rows moved this pass.
	RowsArchived int64
	// Skipped counts candidates that were empty or changed mid-move.
	Skipped int
	// Failed counts candidates that errored. The joined error is returned
	// alongside; a failed project is left entirely hot.
	Failed int
}

// Mover performs archive moves. It owns no SQL — see the package doc.
type Mover struct {
	// Hot is the hot-database seam.
	Hot HotStore
	// Cold is the archive-database seam.
	Cold ColdStore
	// BatchRows bounds one streamed batch; zero applies
	// archive.DefaultBatchRows.
	BatchRows int
	// Now is the injectable clock stamping archived_at; nil uses time.Now
	// in UTC.
	Now func() time.Time
	// AcceptParser reports whether a cold copy produced by the named parser
	// backend is still replayable. Nil accepts every parser.
	//
	// Injected rather than hard-coded because this package must not learn the
	// code-intelligence backend vocabulary — that belongs to
	// internal/codeintel, and baking a copy of it here is exactly the kind of
	// knowledge duplication that goes stale silently. A false answer is not a
	// failure: it routes the rehydrate to the re-index path, which is the
	// disaster-recovery floor that always works because the source is the
	// repo itself.
	AcceptParser func(parser string) bool
}

func (m *Mover) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now().UTC()
}

// SweepCodeIntel archives one bounded batch of stale codeintel projects.
//
// Bounded, deliberately: design §5.1 rules out draining a 40 GB backlog in a
// single pass. The sweep runs on the ordinary startup + periodic retention
// tick, so a capped batch converges over a few passes without any one pass
// becoming the incident the arc exists to prevent.
//
// A per-project failure does NOT abort the batch: the remaining candidates are
// still attempted and every error is joined into the returned error, because
// one unhealthy project must not indefinitely block every other project from
// leaving the hot database. Every failure mode leaves that project's hot rows
// fully intact.
func (m *Mover) SweepCodeIntel(ctx context.Context, retentionDays int, opts archive.PlanOptions) (SweepResult, error) {
	var res SweepResult
	candidates, err := m.Hot.CodeIntelStaleProjects(ctx, retentionDays)
	if err != nil {
		return res, fmt.Errorf("archivesvc.SweepCodeIntel: candidates: %w", err)
	}
	res.Considered = len(candidates)
	batch := archive.SelectCandidates(candidates, opts)
	res.Attempted = len(batch)

	var errs []error
	for _, c := range batch {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		out, err := m.ArchiveCodeIntelProject(ctx, c.Project)
		if err != nil {
			res.Failed++
			errs = append(errs, err)
			continue
		}
		switch out.Result {
		case ResultArchived:
			res.Archived++
			res.RowsArchived += out.RowsArchived
		default:
			res.Skipped++
		}
	}
	return res, errors.Join(errs...)
}

// ArchiveCodeIntelProject moves ONE project to cold storage.
//
// The step order is the safety contract, and each step exists for a reason
// that is not obvious from the happy path:
//
//  1. Capture the project's shape (watermark + file count) FIRST, so the
//     guard the final delete re-checks describes the state the copy actually
//     read — not the state a candidate list described some projects ago.
//  2. Pre-clear any cold copy. A crashed earlier attempt can have left a
//     partial or now-superset copy behind; upserting over it would leave
//     orphan rows that make the read-back digest disagree with the hot digest
//     forever, wedging the project permanently. This is not "delete first":
//     the hot rows are untouched throughout.
//  3. Copy hot→cold through a tee sink, so the HOT digest is produced by the
//     same single pass that does the copying. Reading the hot tables a second
//     time to fingerprint them would open a window in which a concurrent
//     writer makes the two reads disagree for reasons unrelated to copy
//     fidelity.
//  4. Read the cold copy BACK out of the archive file and fingerprint it.
//     Digesting what the writer believed it wrote would verify the writer's
//     memory, not the durable copy.
//  5. Verify. Any mismatch aborts with the hot rows intact.
//  6. Only now delete the hot rows and write the marker, in one transaction,
//     with the guard from step 1 re-checked inside it.
func (m *Mover) ArchiveCodeIntelProject(ctx context.Context, project string) (Outcome, error) {
	out := Outcome{Project: project}

	watermark, files, err := m.Hot.CodeIntelProjectShape(ctx, project)
	if err != nil {
		return out, fmt.Errorf("archivesvc: %s: shape: %w", project, err)
	}
	if files == 0 {
		out.Result = ResultEmpty
		return out, nil
	}

	if err := m.Cold.DeleteCodeIntelProject(ctx, project); err != nil {
		return out, fmt.Errorf("archivesvc: %s: pre-clear cold copy: %w", project, err)
	}

	tee := archive.NewTeeSink(m.Cold)
	if err := m.Hot.CodeIntelExportProject(ctx, project, m.BatchRows, tee); err != nil {
		return out, fmt.Errorf("archivesvc: %s: copy: %w", project, err)
	}
	hotDigest := tee.Digest()
	if hotDigest.Empty() {
		// The file count said there were rows; the export produced none.
		// Rather than treat that as "nothing to do" and mark the project
		// archived, refuse — a marker with no cold rows behind it is the
		// worst possible outcome for a bucket whose whole promise is
		// recoverability.
		out.Result = ResultEmpty
		return out, fmt.Errorf("archivesvc: %s: %d files reported but export produced no rows",
			project, files)
	}

	coldDigest, err := m.Cold.CodeIntelProjectDigest(ctx, project, m.BatchRows)
	if err != nil {
		return out, fmt.Errorf("archivesvc: %s: read back cold copy: %w", project, err)
	}
	if err := archive.Verify(hotDigest, coldDigest); err != nil {
		return out, fmt.Errorf("archivesvc: %s: %w", project, err)
	}

	err = m.Hot.CodeIntelArchiveComplete(ctx, archive.Completion{
		Project:           project,
		ExpectedWatermark: watermark,
		ExpectedFiles:     files,
		ArchivedAt:        m.now().Unix(),
		RowsArchived:      coldDigest.TotalRows(),
	})
	if err != nil {
		// A concurrent re-index is an expected outcome, not a fault: the
		// project simply stays hot and is re-offered next pass. The sentinel
		// lives in the pure package so this composer can recognise it without
		// importing internal/store.
		if errors.Is(err, archive.ErrProjectChanged) {
			out.Result = ResultChanged
			return out, nil
		}
		return out, fmt.Errorf("archivesvc: %s: complete: %w", project, err)
	}

	out.Result = ResultArchived
	out.RowsArchived = coldDigest.TotalRows()
	return out, nil
}
