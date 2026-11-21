package store

import (
	"context"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
)

// guardAnchorBlock is how many walk distances one search block covers (two
// ids each: up to 8,192 hashes, a few milliseconds). The first block of a row
// runs on the caller's goroutine, so a row proven near its hint never starts
// a worker; cancellation is checked between blocks.
const guardAnchorBlock = 1 << 12

// DefaultGuardAnchorWorkers is the default number of goroutines that hash one
// row's range: GOMAXPROCS, at most 4 (a modest share of a laptop node).
func DefaultGuardAnchorWorkers() int {
	return min(runtime.GOMAXPROCS(0), 4)
}

// guardAnchorWalk is the order one row's search tries action ids in:
// outward from hint within [lo, hi] (hint, hint+1, hint-1, hint+2, hint-2,
// ...), skipping ids outside the range and ids in skip (the windows an
// earlier hint of the same row already searched). lo <= hint <= hi.
type guardAnchorWalk struct {
	hint, lo, hi int64
	// skip is sorted and disjoint (mergeGuardAnchorWindows).
	skip []guardAnchorWindow
}

// guardAnchorWindow is a searched range of action ids, [lo, hi].
type guardAnchorWindow struct{ lo, hi int64 }

// newGuardAnchorWalk is the walk around hint, bounded by radius (0 = no
// bound) and by [1, ceiling]. ok is false when ceiling < 1 (nothing to try).
func newGuardAnchorWalk(hint, radius, ceiling int64) (guardAnchorWalk, bool) {
	if ceiling < 1 {
		return guardAnchorWalk{}, false
	}
	hint = min(max(hint, 1), ceiling)
	w := guardAnchorWalk{hint: hint, lo: 1, hi: ceiling}
	if radius > 0 {
		// Saturating: hint+radius cannot wrap for any int64 radius.
		if radius < hint {
			w.lo = hint - radius
		}
		if radius < ceiling-hint {
			w.hi = hint + radius
		}
	}
	return w, true
}

// window is the walk's range.
func (w guardAnchorWalk) window() guardAnchorWindow { return guardAnchorWindow{w.lo, w.hi} }

// whole reports whether the walk's range is every id in [1, ceiling].
func (w guardAnchorWalk) whole(ceiling int64) bool { return w.lo == 1 && w.hi == ceiling }

// skipped reports whether id lies in a skipped window.
func (w guardAnchorWalk) skipped(id int64) bool {
	for _, s := range w.skip {
		if id < s.lo {
			return false
		}
		if id <= s.hi {
			return true
		}
	}
	return false
}

// count is the number of ids the walk tries within [a, b].
func (w guardAnchorWalk) count(a, b int64) int64 {
	a, b = max(a, w.lo), min(b, w.hi)
	if a > b {
		return 0
	}
	n := b - a + 1
	for _, s := range w.skip {
		if lo, hi := max(a, s.lo), min(b, s.hi); lo <= hi {
			n -= hi - lo + 1
		}
	}
	return n
}

// size is the number of ids the walk tries.
func (w guardAnchorWalk) size() int64 { return w.count(w.lo, w.hi) }

// maxDist is the largest distance from hint the walk reaches.
func (w guardAnchorWalk) maxDist() int64 { return max(w.hi-w.hint, w.hint-w.lo) }

// triesThrough is how many ids the walk tries up to and including id (an id
// the walk tries): the Tries a sequential search that stops at id counts.
func (w guardAnchorWalk) triesThrough(id int64) int64 {
	d := id - w.hint
	if d < 0 {
		d = -d
	}
	var before int64 // ids at a smaller distance
	if d > 0 {
		before = w.count(w.hint-d+1, w.hint+d-1)
	}
	if id >= w.hint {
		return before + 1
	}
	if up := w.hint + d; up <= w.hi && !w.skipped(up) {
		before++ // the walk tries hint+d before hint-d
	}
	return before + 1
}

// scan tries the walk's distances [d0, d1) in walk order and returns the
// first id that proves the row, and how many ids it hashed.
func (w guardAnchorWalk) scan(tr *guardAnchorTrier, d0, d1 int64) (id int64, hashed int64, ok bool) {
	for d := d0; d < d1; d++ {
		if up := w.hint + d; up <= w.hi && !w.skipped(up) {
			hashed++
			if tr.try(up) {
				return up, hashed, true
			}
		}
		if down := w.hint - d; d > 0 && down >= w.lo && !w.skipped(down) {
			hashed++
			if tr.try(down) {
				return down, hashed, true
			}
		}
	}
	return 0, hashed, false
}

// mergeGuardAnchorWindows is ws sorted and merged into disjoint windows
// (adjacent ones joined).
func mergeGuardAnchorWindows(ws []guardAnchorWindow) []guardAnchorWindow {
	if len(ws) == 0 {
		return nil
	}
	sorted := append([]guardAnchorWindow(nil), ws...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].lo < sorted[j].lo })
	out := sorted[:1]
	for _, s := range sorted[1:] {
		last := &out[len(out)-1]
		if s.lo <= last.hi+1 {
			last.hi = max(last.hi, s.hi)
			continue
		}
		out = append(out, s)
	}
	return out
}

// searchGuardAnchor walks w for the id whose preimage reproduces p's stored
// hash. The result is the one a sequential walk returns (the first match in
// walk order) for any workers: the first block runs here, the rest is split
// into blocks handed out in walk order, and a match only stops workers from
// taking LATER blocks, so every earlier block is finished before the earliest
// match is taken. hashed counts every hash computed (more than the walk's
// Tries when workers > 1). A cancelled ctx returns its error.
func searchGuardAnchor(ctx context.Context, p *guardAnchorPreimage, w guardAnchorWalk, workers int, hashed *atomic.Int64) (int64, bool, error) {
	end := min(int64(guardAnchorBlock), w.maxDist()+1)
	id, n, ok := w.scan(p.newTrier(), 0, end)
	hashed.Add(n)
	if ok || end > w.maxDist() {
		return id, ok, nil
	}
	nblocks := (w.maxDist() + 1 - end + guardAnchorBlock - 1) / guardAnchorBlock
	var (
		next, best atomic.Int64 // next block to hand out; earliest block with a match
		mu         sync.Mutex
		bestID     int64 // the match in block best (guarded by mu)
	)
	best.Store(nblocks) // no match yet
	work := func() {
		tr := p.newTrier()
		for ctx.Err() == nil {
			b := next.Add(1) - 1
			if b >= nblocks || b > best.Load() {
				return
			}
			d0 := end + b*guardAnchorBlock
			id, n, ok := w.scan(tr, d0, min(d0+guardAnchorBlock, w.maxDist()+1))
			hashed.Add(n)
			if !ok {
				continue
			}
			mu.Lock()
			if b < best.Load() {
				best.Store(b)
				bestID = id
			}
			mu.Unlock()
		}
	}
	workers = max(workers, 1)
	var wg sync.WaitGroup
	for range workers - 1 {
		wg.Go(work)
	}
	work()
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	if best.Load() < nblocks {
		return bestID, true, nil
	}
	return 0, false, nil
}
