package archive

import "fmt"

// Reclaim planning — the pure half of `observer archive reclaim` (corpus
// archival design §5.2 / §9 P5).
//
// Archival moves rows OUT of the hot database, but SQLite does not shrink the
// file when rows leave: the pages go on the freelist and the file stays the
// size it grew to. Reclaim is the operator-invoked step that turns those freed
// pages back into free disk.
//
// Everything here is arithmetic and refusal rules. No SQL, no filesystem, no
// exec — the caller measures, this decides, and imports_test.go pins that
// separation. The point of the split is that the REFUSALS are testable: a
// free-space precondition that only exists inside a CLI function is a
// precondition nobody can prove is load-bearing.

// ReclaimDecision is the verdict on whether a reclaim may proceed.
type ReclaimDecision string

const (
	// ReclaimReady — the preconditions hold; the copy may be written.
	ReclaimReady ReclaimDecision = "ready"
	// ReclaimDaemonLive — the observer daemon is running. VACUUM INTO reads
	// the whole file and the result must be a consistent snapshot of a
	// database nobody is writing; more importantly the SWAP that follows
	// replaces the file under a live daemon's open handles.
	ReclaimDaemonLive ReclaimDecision = "daemon_live"
	// ReclaimNoSpace — not enough free disk for the compacted copy.
	ReclaimNoSpace ReclaimDecision = "no_space"
	// ReclaimNothingToReclaim — the freelist is empty (or below the floor), so
	// a rewrite would copy the whole file to save nothing.
	ReclaimNothingToReclaim ReclaimDecision = "nothing_to_reclaim"
)

// MinReclaimBytes is the floor below which a reclaim is not worth the rewrite.
//
// A reclaim rewrites the ENTIRE database — tens of GB of I/O — so it has to buy
// something proportionate. 256 MiB is deliberately modest: it is large enough
// that nobody rewrites 30 GB to recover a rounding error, and small enough that
// it never stands between an operator and a real reclamation. It is a floor on
// the default path only; ReclaimInput.Force lifts it, because an operator who
// has read the number and still wants the compaction (before a backup, say) is
// not making a mistake.
const MinReclaimBytes = 256 << 20

// ReclaimInput is everything measured about the database and its volume. Every
// field is an observation; none of it is inferred here.
type ReclaimInput struct {
	// FileBytes is the database file's size on disk.
	FileBytes int64
	// PageSize / FreelistPages come from PRAGMA page_size / freelist_count.
	// Both are O(1) header reads — this measurement never walks the file, so
	// it is safe to take on a large database (unlike dbstat).
	PageSize      int64
	FreelistPages int64
	// FreeDiskBytes is free space on the volume holding the database.
	FreeDiskBytes int64
	// FreeDiskKnown is false where the platform cannot answer (statfs is
	// unix-only). The space precondition is then SKIPPED rather than guessed —
	// an unmeasurable volume must not silently become a "0 bytes free"
	// refusal, nor a fabricated "plenty of room" pass.
	FreeDiskKnown bool
	// DaemonLive reports whether the observer daemon is up.
	DaemonLive bool
	// Force lifts MinReclaimBytes only. It does NOT lift the daemon or space
	// preconditions: those are correctness and safety, not thresholds.
	Force bool
}

// ReclaimPlan is the decision plus the numbers behind it, so the CLI renders
// one honest report for both the "here is what it would return" view and the
// refusal.
type ReclaimPlan struct {
	Decision ReclaimDecision `json:"decision"`
	// ReclaimableBytes is freelist pages × page size: what a full rewrite is
	// expected to return. It EXCLUDES fragmentation inside live pages, so a
	// real reclaim usually frees somewhat more. Under-promising is the right
	// direction for a number an operator plans a maintenance window around.
	ReclaimableBytes int64 `json:"reclaimable_bytes"`
	// EstimatedAfterBytes is the projected post-reclaim file size.
	EstimatedAfterBytes int64 `json:"estimated_after_bytes"`
	// RequiredFreeBytes is the free space the operation needs.
	RequiredFreeBytes int64 `json:"required_free_bytes"`
	// ShortfallBytes is how much more free space is needed; 0 unless the
	// decision is ReclaimNoSpace.
	ShortfallBytes int64 `json:"shortfall_bytes"`
	// Reason is the operator-facing sentence for a refusal, empty when ready.
	Reason string `json:"reason,omitempty"`
}

// OK reports whether the plan permits the reclaim to run.
func (p ReclaimPlan) OK() bool { return p.Decision == ReclaimReady }

// PlanReclaim applies the precondition rules, in order, first match wins
// (CLAUDE.md rule 5 — an ordered rule set, not a nested conditional).
//
// The required-space rule is the one worth explaining, because it is smaller
// than the number the audit uses elsewhere. A bare `VACUUM` needs ~2× the file:
// SQLite builds a full temp copy and then rewrites the original in place, so
// both exist at once and the temp is invisible to the operator. `VACUUM INTO`
// needs ~1×: it writes ONE new file, the destination, and never touches the
// source. The compacted destination cannot be larger than the source, so the
// source's own size is a safe upper bound on it — and a bound we can state
// without pretending to predict compaction precisely.
//
// The source file is then RENAMED aside rather than deleted, which costs no
// additional space (a rename within a filesystem moves no bytes) and is what
// makes the whole operation reversible.
func PlanReclaim(in ReclaimInput) ReclaimPlan {
	plan := ReclaimPlan{
		ReclaimableBytes:  in.PageSize * in.FreelistPages,
		RequiredFreeBytes: in.FileBytes,
	}
	plan.EstimatedAfterBytes = in.FileBytes - plan.ReclaimableBytes
	if plan.EstimatedAfterBytes < 0 {
		plan.EstimatedAfterBytes = 0
	}

	switch {
	case in.DaemonLive:
		plan.Decision = ReclaimDaemonLive
		plan.Reason = "the observer daemon is running — a reclaim rewrites the database file and then replaces it, " +
			"which a live daemon's open handles cannot survive. Stop it first " +
			"(docs/daemon-restart-runbook.md: route OFF → stop → reclaim → relaunch → route ON)"

	case plan.ReclaimableBytes < MinReclaimBytes && !in.Force:
		plan.Decision = ReclaimNothingToReclaim
		plan.Reason = fmt.Sprintf(
			"only %d bytes are on the freelist — below the %d-byte floor. A reclaim rewrites the whole file, "+
				"so there is nothing here worth the I/O. Let archival and retention free more pages first, or pass --force",
			plan.ReclaimableBytes, int64(MinReclaimBytes),
		)

	case in.FreeDiskKnown && in.FreeDiskBytes < plan.RequiredFreeBytes:
		plan.Decision = ReclaimNoSpace
		plan.ShortfallBytes = plan.RequiredFreeBytes - in.FreeDiskBytes
		plan.Reason = fmt.Sprintf(
			"not enough free disk: VACUUM INTO writes a fresh compacted copy alongside the original, so it needs "+
				"room for a whole second file (need %d bytes free, have %d, short by %d). "+
				"Free space or point [observer].db_path at a larger volume, then retry",
			plan.RequiredFreeBytes, in.FreeDiskBytes, plan.ShortfallBytes,
		)

	default:
		plan.Decision = ReclaimReady
	}
	return plan
}
