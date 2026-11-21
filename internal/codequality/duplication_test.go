package codequality

import "testing"

// bucketsFor gives node id the band hashes base+band for bands [0, n) and
// unique hashes for the rest, so two nodes built with the same base share
// exactly n bands.
func bucketsFor(id int64, base int64, n int) []Bucket {
	out := make([]Bucket, 0, TotalBands)
	for band := 0; band < TotalBands; band++ {
		h := id*1000 + int64(band) // unique
		if band < n {
			h = base + int64(band)
		}
		out = append(out, Bucket{NodeID: id, Band: band, Hash: h})
	}
	return out
}

func sym(id int64, file, kind string, start, end int) Symbol {
	return Symbol{ID: id, File: file, Name: "f", Kind: kind, StartLine: start, EndLine: end}
}

func TestDuplicate(t *testing.T) {
	cases := []struct {
		name          string
		symbols       []Symbol
		buckets       []Bucket
		eligible      int
		cloned        int
		groups        int
		eligibleLines int
		clonedLines   int
		skipped       int
	}{
		{
			name:     "two near clones above the band threshold",
			symbols:  []Symbol{sym(1, "a.go", "function", 1, 10), sym(2, "b.go", "function", 1, 10), sym(3, "c.go", "method", 1, 20)},
			buckets:  append(append(bucketsFor(1, 500, MinSharedBands), bucketsFor(2, 500, MinSharedBands)...), bucketsFor(3, 900, 12)...),
			eligible: 3, cloned: 2, groups: 1, eligibleLines: 40, clonedLines: 20,
		},
		{
			name:     "one band short of the threshold is not a clone",
			symbols:  []Symbol{sym(1, "a.go", "function", 1, 10), sym(2, "b.go", "function", 1, 10)},
			buckets:  append(bucketsFor(1, 500, MinSharedBands-1), bucketsFor(2, 500, MinSharedBands-1)...),
			eligible: 2, eligibleLines: 20,
		},
		{
			name:     "short bodies, classes and unknown spans are not eligible",
			symbols:  []Symbol{sym(1, "a.go", "function", 1, 3), sym(2, "b.go", "class", 1, 50), sym(3, "c.go", "function", 5, 0), sym(4, "d.go", "function", 1, 6)},
			buckets:  append(append(bucketsFor(1, 500, 12), bucketsFor(2, 500, 12)...), bucketsFor(4, 500, 12)...),
			eligible: 1, eligibleLines: 6,
		},
		{
			name:     "a nested function is not a clone of its parent; lines union per file",
			symbols:  []Symbol{sym(1, "a.go", "function", 1, 20), sym(2, "a.go", "function", 5, 15)},
			buckets:  append(bucketsFor(1, 500, 12), bucketsFor(2, 500, 12)...),
			eligible: 2, eligibleLines: 20,
		},
		{
			name: "transitive pairs join one group",
			symbols: []Symbol{
				sym(1, "a.go", "function", 1, 10), sym(2, "b.go", "function", 1, 10),
				sym(3, "c.go", "function", 1, 10),
			},
			// 1~2 share bands 0-5 (base 500); 2~3 share bands 6-11 (base 700).
			buckets: []Bucket{
				{1, 0, 500},
				{1, 1, 501},
				{1, 2, 502},
				{1, 3, 503},
				{1, 4, 504},
				{1, 5, 505},
				{1, 6, 1},
				{1, 7, 2},
				{1, 8, 3},
				{1, 9, 4},
				{1, 10, 5},
				{1, 11, 6},
				{2, 0, 500},
				{2, 1, 501},
				{2, 2, 502},
				{2, 3, 503},
				{2, 4, 504},
				{2, 5, 505},
				{2, 6, 706},
				{2, 7, 707},
				{2, 8, 708},
				{2, 9, 709},
				{2, 10, 710},
				{2, 11, 711},
				{3, 0, 30},
				{3, 1, 31},
				{3, 2, 32},
				{3, 3, 33},
				{3, 4, 34},
				{3, 5, 35},
				{3, 6, 706},
				{3, 7, 707},
				{3, 8, 708},
				{3, 9, 709},
				{3, 10, 710},
				{3, 11, 711},
			},
			eligible: 3, cloned: 3, groups: 1, eligibleLines: 30, clonedLines: 30,
		},
		{
			name:     "no symbols",
			eligible: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fig := Duplicate(c.symbols, c.buckets)
			if fig.EligibleSymbols != c.eligible || fig.ClonedSymbols != c.cloned || fig.Groups != c.groups ||
				fig.EligibleLines != c.eligibleLines || fig.ClonedLines != c.clonedLines || fig.SkippedBuckets != c.skipped {
				t.Fatalf("got %+v", fig)
			}
			if c.eligible == 0 && fig.LineShare != nil {
				t.Fatal("no eligible symbols must leave the share nil, never 0")
			}
		})
	}
}

func TestDuplicateSkipsBoilerplateBuckets(t *testing.T) {
	var symbols []Symbol
	var buckets []Bucket
	for i := int64(1); i <= MaxBucketMembers+1; i++ {
		symbols = append(symbols, sym(i, "f.go", "function", int(i)*100, int(i)*100+9))
		buckets = append(buckets, bucketsFor(i, 500, 12)...)
	}
	fig := Duplicate(symbols, buckets)
	if fig.ClonedSymbols != 0 || fig.SkippedBuckets != TotalBands {
		t.Fatalf("got cloned=%d skipped=%d", fig.ClonedSymbols, fig.SkippedBuckets)
	}
}

func TestDuplicateTopGroupsBounded(t *testing.T) {
	var symbols []Symbol
	var buckets []Bucket
	id := int64(1)
	for g := 0; g < TopGroups+3; g++ {
		size := 2 + g%2
		for m := 0; m < size; m++ {
			symbols = append(symbols, sym(id, "g.go", "function", int(id)*100, int(id)*100+9+g))
			buckets = append(buckets, bucketsFor(id, int64(10000*(g+1)), 12)...)
			id++
		}
	}
	fig := Duplicate(symbols, buckets)
	if fig.Groups != TopGroups+3 || len(fig.TopGroups) != TopGroups {
		t.Fatalf("groups=%d listed=%d", fig.Groups, len(fig.TopGroups))
	}
	for i := 1; i < len(fig.TopGroups); i++ {
		if fig.TopGroups[i].Lines > fig.TopGroups[i-1].Lines {
			t.Fatalf("not sorted by lines: %+v", fig.TopGroups)
		}
	}
}
