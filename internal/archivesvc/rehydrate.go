package archivesvc

import (
	"context"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// This file is the inverse of mover.go: P2 of the corpus archival arc
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §4.2, §9).
//
// The design gives two rehydrate paths, cheapest first:
//
//  1. COLD-COPY REPLAY — stream the project's rows back out of archive.db into
//     the hot tables, ids preserved, then rebuild the derived state a fresh
//     index would build.
//  2. RE-INDEX FALLBACK — when the cold copy is absent, incomplete, or was
//     produced by a parser backend this build no longer honours, fall back to
//     `observer index <path>`: the same command an operator runs for a
//     never-indexed project, and the floor that always works because the
//     source of truth for Bucket A is the repository on disk.
//
// This package decides WHICH path applies and executes path 1. It never runs
// the indexer: composing an index pass here would drag the whole
// internal/codeintel engine into what is meant to be a thin composer of two
// storage seams. Path 2 is returned as a decision, and the surface that asked
// (CLI / MCP) tells the operator the command.

// RehydrateResult classifies what a rehydrate attempt concluded.
type RehydrateResult int

const (
	// RehydrateRestored means the cold copy was replayed into the hot tables,
	// verified against what actually landed, derived state rebuilt, and the
	// marker cleared. The project is hot again.
	RehydrateRestored RehydrateResult = iota
	// RehydrateNotArchived means the project has no marker. Nothing was done.
	// This is the overwhelmingly common answer and costs one indexed
	// primary-key lookup — the archive file is never opened.
	RehydrateNotArchived
	// RehydrateAlreadyHot means the project carries a marker but its hot rows
	// are NEWER than the archived watermark: something re-indexed it since.
	// The marker is cleared (it was lying) and NOTHING is replayed — a replay
	// here would overwrite a current index with an older one, which is the
	// single worst outcome this path can produce.
	RehydrateAlreadyHot
	// RehydrateReindexRequired means path 1 is unavailable — the cold copy is
	// missing, does not match what the marker says was archived, or was
	// produced by a parser this build no longer accepts. The marker is KEPT
	// (the project genuinely is archived, and saying otherwise would be the
	// dishonest-empty failure mode) and the hot tables are left untouched.
	RehydrateReindexRequired
)

// String renders the result for logs and CLI output.
func (r RehydrateResult) String() string {
	switch r {
	case RehydrateRestored:
		return "restored"
	case RehydrateNotArchived:
		return "not-archived"
	case RehydrateAlreadyHot:
		return "already-hot"
	case RehydrateReindexRequired:
		return "reindex-required"
	default:
		return "unknown"
	}
}

// RehydrateOutcome reports one rehydrate attempt.
type RehydrateOutcome struct {
	// Project is the project key.
	Project string
	// Result is what happened.
	Result RehydrateResult
	// Marker is the marker row as it was found, zero when there was none.
	// Surfaces render Marker.LastIndexedAt as the "last indexed <date>".
	Marker archive.Marker
	// RowsRestored is the verified hot row count after a replay.
	RowsRestored int64
	// Reason explains a RehydrateReindexRequired outcome in operator terms.
	// Empty for every other result.
	Reason string
}

// RehydrateCodeIntelProject brings one archived project back into the hot
// database.
//
// The step order is the safety contract:
//
//  1. Read the marker. No marker ⇒ nothing to do, and the archive file is
//     never opened. This is the common path and it must stay O(1).
//  2. Compare the hot rows against the marker's watermark. A project that has
//     been re-indexed since it was archived is LIVE; replaying an older cold
//     copy over it would destroy current data to satisfy a stale marker. Clear
//     the marker and stop.
//  3. Pre-check the cold copy's parser backends before touching anything hot,
//     so a stale cold copy costs one small indexed read rather than a delete
//     and a partial replay.
//  4. Clear the hot project. A replay must land on empty: hot codeintel_minhash
//     has no unique constraint, so leftovers from a crashed earlier replay
//     would duplicate rather than overwrite.
//  5. Stream cold → hot through a tee, so the COLD digest is produced by the
//     same single pass that does the writing.
//  6. Re-read the HOT tables and verify. Digesting what the writer believed it
//     wrote would verify the writer's memory, not what landed. This is the
//     SAME archive.Verify the outbound mover gates its delete on — there is
//     one verification primitive in this arc, used in both directions.
//  7. Rebuild derived state (FTS, embeddings) and re-run call resolution, so
//     the restored project is indistinguishable from a freshly indexed one.
//  8. Only now clear the marker.
//
// Any failure from step 4 onward rolls the hot project back to empty and keeps
// the marker. That leaves the system in the state it was already in — archived,
// recoverable — rather than in a half-restored one where the marker says
// "archived" while the hot tables answer queries with a partial graph.
func (m *Mover) RehydrateCodeIntelProject(ctx context.Context, project string) (RehydrateOutcome, error) {
	out := RehydrateOutcome{Project: project}

	marker, found, err := m.Hot.CodeIntelArchivedProject(ctx, project)
	if err != nil {
		return out, fmt.Errorf("archivesvc: %s: read marker: %w", project, err)
	}
	if !found {
		out.Result = RehydrateNotArchived
		return out, nil
	}
	out.Marker = marker

	hotWatermark, hotFiles, err := m.Hot.CodeIntelProjectShape(ctx, project)
	if err != nil {
		return out, fmt.Errorf("archivesvc: %s: hot shape: %w", project, err)
	}
	if hotFiles > 0 && hotWatermark > marker.LastIndexedAt {
		// Live index wins over cold copy, always. The marker is stale
		// bookkeeping and clearing it is the honest repair.
		if err := m.Hot.CodeIntelClearArchivedProject(ctx, project); err != nil {
			return out, fmt.Errorf("archivesvc: %s: clear stale marker: %w", project, err)
		}
		out.Result = RehydrateAlreadyHot
		return out, nil
	}

	if m.AcceptParser != nil {
		parsers, perr := m.Cold.CodeIntelProjectParsers(ctx, project)
		if perr != nil {
			return out, fmt.Errorf("archivesvc: %s: cold parsers: %w", project, perr)
		}
		if len(parsers) == 0 {
			out.Result = RehydrateReindexRequired
			out.Reason = "no cold copy found in the archive"
			return out, nil
		}
		for _, p := range parsers {
			if !m.AcceptParser(p) {
				out.Result = RehydrateReindexRequired
				out.Reason = fmt.Sprintf("cold copy was produced by parser %q, which this build no longer accepts", p)
				return out, nil
			}
		}
	}

	if err := m.Hot.CodeIntelDeleteProject(ctx, project); err != nil {
		return out, fmt.Errorf("archivesvc: %s: clear hot rows before replay: %w", project, err)
	}

	res, err := m.replay(ctx, project, marker)
	if err != nil || res.Result == RehydrateReindexRequired {
		// Roll the hot side back to empty so the marker stays truthful. The
		// rollback is best-effort: if it too fails, the replay error is the
		// one worth reporting, with the rollback failure joined onto it.
		if rbErr := m.Hot.CodeIntelDeleteProject(ctx, project); rbErr != nil {
			err = errors.Join(err, fmt.Errorf("archivesvc: %s: roll back partial replay: %w", project, rbErr))
		}
		res.Project = project
		res.Marker = marker
		return res, err
	}

	if err := m.Hot.CodeIntelBuildDerived(ctx, project); err != nil {
		if rbErr := m.Hot.CodeIntelDeleteProject(ctx, project); rbErr != nil {
			err = errors.Join(err, rbErr)
		}
		return out, fmt.Errorf("archivesvc: %s: rebuild derived: %w", project, err)
	}
	if _, err := m.Hot.CodeIntelResolveCalls(ctx, project); err != nil {
		if rbErr := m.Hot.CodeIntelDeleteProject(ctx, project); rbErr != nil {
			err = errors.Join(err, rbErr)
		}
		return out, fmt.Errorf("archivesvc: %s: resolve calls: %w", project, err)
	}

	// Last, and only now: the project is fully hot, so the marker would be a
	// lie if it stayed.
	if err := m.Hot.CodeIntelClearArchivedProject(ctx, project); err != nil {
		return out, fmt.Errorf("archivesvc: %s: clear marker: %w", project, err)
	}

	out.Result = RehydrateRestored
	out.RowsRestored = res.RowsRestored
	return out, nil
}

// replay executes steps 5 and 6: stream the cold copy into the hot tables and
// verify what landed. It leaves the hot rows in place on success and reports
// RehydrateReindexRequired (never an error) for the two "the cold copy is not
// usable" conditions, so the caller's rollback path handles both alike.
func (m *Mover) replay(ctx context.Context, project string, marker archive.Marker) (RehydrateOutcome, error) {
	out := RehydrateOutcome{Project: project, Marker: marker}

	tee := archive.NewTeeSink(m.Hot.CodeIntelImportSink(project))
	if err := m.Cold.StreamCodeIntelProject(ctx, project, m.BatchRows, tee); err != nil {
		return out, fmt.Errorf("archivesvc: %s: replay cold copy: %w", project, err)
	}
	coldDigest := tee.Digest()

	if coldDigest.Empty() {
		out.Result = RehydrateReindexRequired
		out.Reason = "no cold copy found in the archive"
		return out, nil
	}
	// The marker records the row count that was VERIFIED into cold storage.
	// A cold copy that no longer carries that many rows has been truncated,
	// partially expired, or otherwise changed behind the arc's back — and
	// unlike the row-for-row digest below, this is the only check that can
	// notice rows going missing between the archive and the rehydrate, since
	// both sides of that digest are read after the fact.
	if marker.RowsArchived > 0 && coldDigest.TotalRows() != marker.RowsArchived {
		out.Result = RehydrateReindexRequired
		out.Reason = fmt.Sprintf("cold copy holds %d rows but %d were archived — it is incomplete",
			coldDigest.TotalRows(), marker.RowsArchived)
		return out, nil
	}

	hotDigest, err := m.Hot.CodeIntelProjectDigest(ctx, project, m.BatchRows)
	if err != nil {
		return out, fmt.Errorf("archivesvc: %s: read back replayed rows: %w", project, err)
	}
	if err := archive.Verify(hotDigest, coldDigest); err != nil {
		return out, fmt.Errorf("archivesvc: %s: %w", project, err)
	}

	out.Result = RehydrateRestored
	out.RowsRestored = hotDigest.TotalRows()
	return out, nil
}
