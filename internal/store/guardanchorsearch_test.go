package store

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sync/atomic"
	"testing"
)

// TestNewGuardAnchorWalk: the radius clamps to [1, ceiling] and never
// overflows.
func TestNewGuardAnchorWalk(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                  string
		hint, radius, ceiling int64
		want                  guardAnchorWalk
		ok, whole             bool
	}{
		{"no radius is the whole range", 50, 0, 100, guardAnchorWalk{hint: 50, lo: 1, hi: 100}, true, true},
		{"radius inside the range", 50, 10, 100, guardAnchorWalk{hint: 50, lo: 40, hi: 60}, true, false},
		{"radius past the bottom", 5, 10, 100, guardAnchorWalk{hint: 5, lo: 1, hi: 15}, true, false},
		{"radius past the top", 95, 10, 100, guardAnchorWalk{hint: 95, lo: 85, hi: 100}, true, false},
		{"radius wider than the range", 50, 1000, 100, guardAnchorWalk{hint: 50, lo: 1, hi: 100}, true, true},
		{"widest radius", 50, math.MaxInt64, math.MaxInt64, guardAnchorWalk{hint: 50, lo: 1, hi: math.MaxInt64}, true, true},
		{"hint below 1 clamps", 0, 3, 100, guardAnchorWalk{hint: 1, lo: 1, hi: 4}, true, false},
		{"hint above the ceiling clamps", 500, 3, 100, guardAnchorWalk{hint: 100, lo: 97, hi: 100}, true, false},
		{"radius 1 at the hint", 7, 1, 7, guardAnchorWalk{hint: 7, lo: 6, hi: 7}, true, false},
		{"no actions ever issued", 1, 0, 0, guardAnchorWalk{}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w, ok := newGuardAnchorWalk(tc.hint, tc.radius, tc.ceiling)
			if ok != tc.ok || !reflect.DeepEqual(w, tc.want) {
				t.Fatalf("newGuardAnchorWalk(%d, %d, %d) = (%+v, %v), want (%+v, %v)", tc.hint, tc.radius, tc.ceiling, w, ok, tc.want, tc.ok)
			}
			if ok && w.whole(tc.ceiling) != tc.whole {
				t.Fatalf("whole = %v, want %v", w.whole(tc.ceiling), tc.whole)
			}
		})
	}
}

// guardAnchorWalkOrder is the reference walk order: what the search tried,
// one id at a time, before the split.
func guardAnchorWalkOrder(w guardAnchorWalk) []int64 {
	var out []int64
	for d := int64(0); ; d++ {
		up, down := w.hint+d, w.hint-d
		if up > w.hi && down < w.lo {
			return out
		}
		if up <= w.hi && !inGuardAnchorWindows(w.skip, up) {
			out = append(out, up)
		}
		if d > 0 && down >= w.lo && !inGuardAnchorWindows(w.skip, down) {
			out = append(out, down)
		}
	}
}

func inGuardAnchorWindows(ws []guardAnchorWindow, id int64) bool {
	for _, s := range ws {
		if id >= s.lo && id <= s.hi {
			return true
		}
	}
	return false
}

// guardAnchorSkipSets are the earlier-window sets the walk tests run with:
// none, one inside, one across each end, two, and one covering everything
// small walks reach.
var guardAnchorSkipSets = [][]guardAnchorWindow{
	nil,
	{{4, 5}},
	{{1, 3}},
	{{9, 20}},
	{{2, 2}, {6, 8}},
	{{1, 20}},
}

// TestGuardAnchorWalkTriesThrough: size and triesThrough match the
// reference walk order (an id's position in it), for every id of every
// small walk, with and without earlier windows to skip.
func TestGuardAnchorWalkTriesThrough(t *testing.T) {
	t.Parallel()
	for ceiling := int64(1); ceiling <= 12; ceiling++ {
		for hint := int64(1); hint <= ceiling; hint++ {
			for radius := int64(0); radius <= 6; radius++ {
				for _, skip := range guardAnchorSkipSets {
					w, _ := newGuardAnchorWalk(hint, radius, ceiling)
					w.skip = skip
					order := guardAnchorWalkOrder(w)
					if int64(len(order)) != w.size() {
						t.Fatalf("%+v: walk has %d ids, size %d", w, len(order), w.size())
					}
					for i, id := range order {
						if got := w.triesThrough(id); got != int64(i+1) {
							t.Fatalf("%+v: triesThrough(%d) = %d, want %d", w, id, got, i+1)
						}
					}
				}
			}
		}
	}
}

// TestMergeGuardAnchorWindows: sorted, overlapping and adjacent windows
// joined, disjoint ones kept apart.
func TestMergeGuardAnchorWindows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want []guardAnchorWindow
	}{
		{nil, nil},
		{[]guardAnchorWindow{{5, 9}}, []guardAnchorWindow{{5, 9}}},
		{[]guardAnchorWindow{{20, 30}, {1, 5}}, []guardAnchorWindow{{1, 5}, {20, 30}}},
		{[]guardAnchorWindow{{1, 5}, {6, 9}}, []guardAnchorWindow{{1, 9}}},
		{[]guardAnchorWindow{{1, 10}, {3, 4}}, []guardAnchorWindow{{1, 10}}},
		{[]guardAnchorWindow{{10, 20}, {1, 12}, {30, 31}}, []guardAnchorWindow{{1, 20}, {30, 31}}},
	}
	for _, tc := range cases {
		if got := mergeGuardAnchorWindows(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("merge(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestSearchGuardAnchorMatchesSequential: the blocked, multi-worker search
// returns what the one-id-at-a-time walk over canonicalBytes returns, for
// anchors at the hint, at and around block boundaries, at both range ends,
// outside the radius and absent, for 1, 2 and 4 workers.
func TestSearchGuardAnchorMatchesSequential(t *testing.T) {
	t.Parallel()
	const ceiling, hint = 40_000, 20_000
	cases := []struct {
		name   string
		anchor int64
		radius int64
		skip   []guardAnchorWindow
	}{
		{"at the hint", hint, 0, nil},
		{"one above", hint + 1, 0, nil},
		{"one below", hint - 1, 0, nil},
		{"last distance of the first block", hint - (guardAnchorBlock - 1), 0, nil},
		{"first distance of the second block", hint + guardAnchorBlock, 0, nil},
		{"deep in a later block, below", hint - 15_123, 0, nil},
		{"the first id", 1, 0, nil},
		{"the ceiling", ceiling, 0, nil},
		{"just inside the radius", hint + 9_000, 9_000, nil},
		{"just outside the radius", hint - 9_001, 9_000, nil},
		{"above the ceiling", ceiling + 5, 0, nil},
		{"just past an earlier window", hint + 3_001, 0, []guardAnchorWindow{{hint - 5_000, hint + 3_000}}},
		{"inside an earlier window: not tried", hint + 10, 0, []guardAnchorWindow{{hint - 5_000, hint + 3_000}}},
		{"below two earlier windows", 2_000, 0, []guardAnchorWindow{{1, 1_999}, {hint - 100, hint + 100}}},
	}
	base := guardAnchorShapes()["v2 with grant"]
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := sealedGuardRow(base, "", tc.anchor)
			w, _ := newGuardAnchorWalk(hint, tc.radius, ceiling)
			w.skip = tc.skip
			// Reference: the walk over the canonical bytes.
			wantID, wantTries, wantOK := int64(0), w.size(), false
			for i, id := range guardAnchorWalkOrder(w) {
				r.actionAnchor = &id
				if guardChainHash(r.ChainPrev, r.canonicalBytes()) == r.ChainHash {
					wantID, wantTries, wantOK = id, int64(i+1), true
					break
				}
			}
			r.actionAnchor = nil
			p, why := newGuardAnchorPreimage(&r)
			if p == nil {
				t.Fatal(why)
			}
			for _, workers := range []int{1, 2, 4} {
				var hashed atomic.Int64
				id, ok, err := searchGuardAnchor(context.Background(), p, w, workers, &hashed)
				if err != nil || id != wantID || ok != wantOK {
					t.Fatalf("workers %d: search = (%d, %v, %v), want (%d, %v, nil)", workers, id, ok, err, wantID, wantOK)
				}
				tries := w.size()
				if ok {
					tries = w.triesThrough(id)
				}
				if tries != wantTries || hashed.Load() < tries {
					t.Fatalf("workers %d: tries %d hashed %d, want tries %d", workers, tries, hashed.Load(), wantTries)
				}
			}
		})
	}
}

// TestSearchGuardAnchorCancelled: a cancelled context stops a search that
// would otherwise walk past its first block.
func TestSearchGuardAnchorCancelled(t *testing.T) {
	t.Parallel()
	r := sealedGuardRow(guardAnchorShapes()["v1"], "", 1)
	p, _ := newGuardAnchorPreimage(&r)
	w, _ := newGuardAnchorWalk(1_000_000, 0, 2_000_000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var hashed atomic.Int64
	for _, workers := range []int{1, 4} {
		if _, ok, err := searchGuardAnchor(ctx, p, w, workers, &hashed); ok || !errors.Is(err, context.Canceled) {
			t.Fatalf("workers %d: search on a cancelled ctx = (%v, %v)", workers, ok, err)
		}
	}
}
