package archive

import "sort"

// DefaultMaxUnitsPerPass bounds how many cold units one retention pass moves.
//
// The bound is the point, not the number. Design §5.1 is explicit that an
// existing 40 GB database must NOT be drained by a "loop until done" sweep —
// that is the same anti-pattern Phase 0 removed from shrinkToCap, where a
// single retention pass could hold the machine for minutes. A capped batch per
// pass, run on the ordinary startup + periodic tick, converges just as surely
// and never turns one pass into an incident.
const DefaultMaxUnitsPerPass = 8

// Candidate is one unit eligible to move to cold storage: a project key plus
// the staleness watermark that made it eligible.
//
// Watermark is load-bearing beyond ordering. The mover carries it into the
// hot-side delete, which re-checks it inside its own transaction and aborts if
// it has moved — that is what makes a concurrent re-index cancel the move
// rather than silently lose the newly indexed rows.
type Candidate struct {
	// Project is the git-root identity key shared by every codeintel_* row.
	Project string
	// Watermark is MAX(codeintel_files.indexed_at) for the project, in unix
	// seconds, as observed at selection time.
	Watermark int64
}

// Completion carries everything the hot side needs to finish one move
// atomically: the guard values it must re-check, and the facts it records on
// the marker row.
//
// It lives in this pure package rather than in the store so that the mover
// which composes hot and cold sides speaks only archive types — neither
// storage package's types cross into the other or into the composer
// (CLAUDE.md "no type leakage past the seam").
type Completion struct {
	// Project is the project key being archived.
	Project string
	// ExpectedWatermark is MAX(indexed_at) as observed just before the copy
	// began. The hot delete re-checks it inside its own transaction and
	// refuses if it moved — that is what makes a concurrent re-index cancel
	// the move instead of losing the newly indexed rows.
	ExpectedWatermark int64
	// ExpectedFiles is the file count observed alongside the watermark.
	// Checked too, because a re-index could in principle reproduce the same
	// watermark second while changing the file set.
	ExpectedFiles int64
	// ArchivedAt is the completion timestamp (unix seconds).
	ArchivedAt int64
	// RowsArchived is the VERIFIED cold row count recorded on the marker —
	// the number read back out of the archive, never the number the writer
	// believed it wrote.
	RowsArchived int64
}

// Marker is one archival marker row: the cheap, hot-side answer to "was this
// unit archived, or was it simply never indexed?"
//
// Telling those two apart without opening the archive file is the whole point
// of the marker (design §5.1). An archived project that reports zero symbols
// exactly like a never-indexed one is the dishonest-empty failure mode
// (memory:feedback_honest_disable_copy); the surfaces read this row to say
// "archived, last indexed <date>" instead.
//
// It lives in this pure package for the same reason [Completion] does: the
// composer in internal/archivesvc and the read surfaces that render it speak
// archive types, so neither has to import a storage package to learn what an
// archived unit looks like.
type Marker struct {
	// Project is the git-root identity key.
	Project string
	// ArchivedAt is when the move completed (unix seconds).
	ArchivedAt int64
	// LastIndexedAt is the MAX(indexed_at) watermark the unit carried when it
	// was archived — the date a surface reports, and the value a rehydrate
	// compares against to tell a replayed copy from a live re-index.
	LastIndexedAt int64
	// RowsArchived is the total row count moved to cold storage, for the
	// aggregate storage surface (design §4.4) without opening the archive.
	RowsArchived int64
}

// PlanOptions parameterizes [SelectCandidates].
type PlanOptions struct {
	// MaxUnitsPerPass caps the batch. Zero or negative applies
	// [DefaultMaxUnitsPerPass]; there is deliberately no "unlimited"
	// sentinel, because an unbounded sweep is the failure mode this cap
	// exists to prevent.
	MaxUnitsPerPass int
}

// SelectCandidates orders eligible units coldest-first and caps the batch.
//
// Coldest-first matters when the batch is smaller than the backlog: the
// projects least likely to be reopened move first, so the hot working set
// converges on "recently active" (design §1.3) after a handful of passes
// rather than moving an arbitrary slice each time. Ties break on the project
// key so a given backlog produces a stable, reproducible batch order — a test
// asserting "these two moved" must not be flaky on map iteration order.
//
// The input slice is not modified; the returned slice is a fresh copy.
func SelectCandidates(in []Candidate, opts PlanOptions) []Candidate {
	limit := opts.MaxUnitsPerPass
	if limit <= 0 {
		limit = DefaultMaxUnitsPerPass
	}
	if len(in) == 0 {
		return nil
	}
	out := make([]Candidate, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Watermark != out[j].Watermark {
			return out[i].Watermark < out[j].Watermark
		}
		return out[i].Project < out[j].Project
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
