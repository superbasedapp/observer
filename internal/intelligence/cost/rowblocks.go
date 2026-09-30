package cost

// rawRowBlockSize is how many rows one rawRowBlocks block holds.
const rawRowBlockSize = 4096

// rawRowBlocks accumulates the big per-window loaders' rows (loadProxyRows,
// loadJSONLRows) in fixed-size blocks and copies them into one exact-size
// slice at the end. A plain append on a slice of rawRow (~330 B each) grows
// by 1.25x past a few hundred elements, so a 170k-row window copied and
// zeroed every row several times over; measured on the reference node that
// growth was ~20% of a 30-day Analysis-panel load (lane R2-PARITY-2).
type rawRowBlocks struct {
	full [][]rawRow
	cur  []rawRow
	n    int
}

// add appends one row.
func (b *rawRowBlocks) add(r rawRow) {
	if len(b.cur) == cap(b.cur) {
		if b.cur != nil {
			b.full = append(b.full, b.cur)
		}
		b.cur = make([]rawRow, 0, rawRowBlockSize)
	}
	b.cur = append(b.cur, r)
	b.n++
}

// rows returns every added row, in order, as one slice (nil when none).
func (b *rawRowBlocks) rows() []rawRow {
	if len(b.full) == 0 {
		return b.cur
	}
	out := make([]rawRow, 0, b.n)
	for _, blk := range b.full {
		out = append(out, blk...)
	}
	return append(out, b.cur...)
}
