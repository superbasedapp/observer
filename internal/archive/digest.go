package archive

import (
	"errors"
	"fmt"
	"strconv"
)

// ErrDigestMismatch is the sentinel every verification failure wraps. The
// archive mover treats it as "abort the move, leave the hot rows alone" — it
// is the single condition standing between a copy and an irreversible delete,
// so it must never be swallowed or downgraded to a warning.
var ErrDigestMismatch = errors.New("archive: cold copy does not match the hot rows")

// ErrProjectChanged is the sentinel a hot-side store wraps when it refuses to
// delete because the unit was rewritten between the copy and the delete (for
// Bucket A: a concurrent re-index bumped MAX(indexed_at) or changed the file
// count).
//
// It lives in this pure package, not in the store, so the composer that
// recognises the outcome — a normal "leave it hot, retry next pass", not a
// fault — can do so without importing a storage package.
var ErrProjectChanged = errors.New("archive: unit changed during archive; hot rows left intact")

// TableDigest is one table's contribution to a [ProjectDigest]: an exact row
// count plus an order-independent checksum over every column of every row.
//
// Two properties matter and are deliberate:
//
//   - Order-independent, so neither side needs an ORDER BY (which on a wide
//     table can cost a sort the verification does not need).
//   - Accumulated by ADDITION, not XOR. XOR would let two identical rows
//     cancel out, which is precisely the corruption shape a duplicate-key
//     upsert bug produces; wrapping addition has no such blind spot.
type TableDigest struct {
	Rows int64
	Sum  uint64
}

// Add folds one row's [FileRow.Digest]-style hash into the digest.
func (t *TableDigest) Add(rowDigest uint64) {
	t.Rows++
	t.Sum += rowDigest
}

// ProjectDigest is the full fingerprint of one archived unit — every table it
// spans. The hot side and the cold side each produce one and [Verify] compares
// them field for field.
type ProjectDigest struct {
	Files      TableDigest
	Nodes      TableDigest
	Edges      TableDigest
	Sites      TableDigest
	Embeddings TableDigest
	Minhash    TableDigest
}

// TotalRows is the sum of every table's row count — the number reported as
// "rows archived" and stored on the marker row.
func (d ProjectDigest) TotalRows() int64 {
	return d.Files.Rows + d.Nodes.Rows + d.Edges.Rows +
		d.Sites.Rows + d.Embeddings.Rows + d.Minhash.Rows
}

// Empty reports whether the unit has no rows at all. An empty unit is not
// archived: there is nothing to move, and writing a marker for it would claim
// data is recoverable from cold storage when none was ever put there.
func (d ProjectDigest) Empty() bool { return d.TotalRows() == 0 }

// NamedTable pairs a table's name with its digest. It is the shape
// [VerifyTables] compares, so every archived bucket — however many tables it
// spans — presents itself to verification the same way.
type NamedTable struct {
	Name   string
	Digest TableDigest
}

// tables enumerates the digest's per-table fields for table-driven comparison,
// so adding a table to the archive is one row here rather than another branch
// in a growing if-ladder (CLAUDE.md §5).
func (d ProjectDigest) tables() []NamedTable {
	return []NamedTable{
		{"codeintel_files", d.Files},
		{"codeintel_nodes", d.Nodes},
		{"codeintel_edges", d.Edges},
		{"codeintel_sites", d.Sites},
		{"codeintel_embeddings", d.Embeddings},
		{"codeintel_minhash", d.Minhash},
	}
}

// Verify reports whether the rows read back OUT of the archive file (cold)
// reproduce the rows read out of the hot tables (hot), exactly.
//
// This is the gate the copy-then-delete mover must pass before it deletes
// anything. Two rules make it meaningful rather than ceremonial:
//
//   - `cold` MUST be produced by re-reading the archive file, not by digesting
//     what the writer believed it wrote. A digest of the writer's own input
//     verifies the writer's memory, not the durable copy.
//   - Any error at all aborts the move. There is no "close enough" branch;
//     for the non-regenerable bucket (design §2.2) the archive copy is the
//     ONLY copy, so a partial verification is a data-loss bug wearing a
//     success message.
//
// The returned error names the first table that disagrees and whether the
// count or the checksum diverged, so an operator report says which table lost
// rows rather than just "mismatch".
func Verify(hot, cold ProjectDigest) error {
	return VerifyTables(hot.tables(), cold.tables())
}

// VerifyTables is THE comparison primitive of this arc. [Verify] (Bucket A,
// codeintel) and [VerifyWindow] (Bucket B, process capture) are both thin
// adapters over it — there is one implementation of "does the cold copy
// reproduce the hot rows", and every bucket is gated by that same one.
//
// That single-implementation property is not tidiness. Bucket B is the
// ONLY-COPY bucket (design §2.2): its rows are live eBPF/ETW capture with no
// source artifact to re-derive them from, so a second, subtly weaker verifier
// written for it would be a data-loss bug with a success message. Bucket A,
// which is regenerable, is what earned this code its confidence — so Bucket B
// inherits it verbatim rather than getting its own.
//
// The comparison is positional: callers pass table lists built by the same
// method on both sides, so index i names the same table on both. A length
// mismatch is a programming error and is reported as one rather than silently
// verifying the shorter prefix — the exact shape a "short-circuited loop"
// mutation produces.
func VerifyTables(hot, cold []NamedTable) error {
	if len(hot) != len(cold) {
		return fmt.Errorf("%w: compared %d tables against %d — the two digests describe different units",
			ErrDigestMismatch, len(hot), len(cold))
	}
	for i := range hot {
		h, c := hot[i].Digest, cold[i].Digest
		name := hot[i].Name
		if h.Rows != c.Rows {
			return fmt.Errorf("%w: %s row count hot=%d cold=%d",
				ErrDigestMismatch, name, h.Rows, c.Rows)
		}
		if h.Sum != c.Sum {
			return fmt.Errorf("%w: %s checksum hot=%s cold=%s (%d rows each)",
				ErrDigestMismatch, name,
				strconv.FormatUint(h.Sum, 16), strconv.FormatUint(c.Sum, 16), h.Rows)
		}
	}
	return nil
}
