package cost

import "testing"

func TestRawRowBlocksKeepsOrder(t *testing.T) {
	for _, n := range []int{0, 1, rawRowBlockSize - 1, rawRowBlockSize, rawRowBlockSize + 1, 3*rawRowBlockSize + 7} {
		var b rawRowBlocks
		for i := 0; i < n; i++ {
			b.add(rawRow{tokens: TokenBundle{Input: int64(i)}})
		}
		got := b.rows()
		if len(got) != n {
			t.Fatalf("n=%d: got %d rows", n, len(got))
		}
		for i, r := range got {
			if r.tokens.Input != int64(i) {
				t.Fatalf("n=%d: row %d holds %d", n, i, r.tokens.Input)
			}
		}
	}
}
