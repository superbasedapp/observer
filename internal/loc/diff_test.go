package loc

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestSplitLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty is nil", in: "", want: nil},
		{name: "single line no newline", in: "a", want: []string{"a"}},
		{name: "single line trailing newline", in: "a\n", want: []string{"a"}},
		{name: "two lines", in: "a\nb", want: []string{"a", "b"}},
		{name: "two lines trailing newline", in: "a\nb\n", want: []string{"a", "b"}},
		{name: "lone newline is one blank line", in: "\n", want: []string{""}},
		{name: "blank line kept in the middle", in: "a\n\nb\n", want: []string{"a", "", "b"}},
		{name: "trailing blank line kept", in: "a\n\n", want: []string{"a", ""}},
		{name: "crlf stripped", in: "a\r\nb\r\n", want: []string{"a", "b"}},
		{name: "lone cr stripped at end of line", in: "a\r\n", want: []string{"a"}},
		{name: "no newline at eof after crlf", in: "a\r\nb", want: []string{"a", "b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitLines(tc.in)
			if !equalStrings(got, tc.want) {
				t.Fatalf("SplitLines(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeWS(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "unchanged", in: "a := 1", want: "a := 1"},
		{name: "leading tab collapsed", in: "\ta := 1", want: "a := 1"},
		{name: "trailing space trimmed", in: "a := 1   ", want: "a := 1"},
		{name: "interior run collapsed", in: "a   :=\t1", want: "a := 1"},
		{name: "all whitespace becomes empty", in: " \t ", want: ""},
		{name: "empty stays empty", in: "", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeWS(tc.in); got != tc.want {
				t.Fatalf("normalizeWS(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDiffBasicAlignments(t *testing.T) {
	tests := []struct {
		name string
		old  []string
		new  []string
		want []Hunk
	}{
		{
			name: "both empty",
			old:  nil,
			new:  nil,
			want: nil,
		},
		{
			name: "identical",
			old:  []string{"a", "b"},
			new:  []string{"a", "b"},
			want: []Hunk{{Op: OpEqual, OldStart: 0, OldEnd: 2, NewStart: 0, NewEnd: 2}},
		},
		{
			name: "pure insert into empty",
			old:  nil,
			new:  []string{"a", "b"},
			want: []Hunk{{Op: OpInsert, OldStart: 0, OldEnd: 0, NewStart: 0, NewEnd: 2}},
		},
		{
			name: "pure delete to empty",
			old:  []string{"a", "b"},
			new:  nil,
			want: []Hunk{{Op: OpDelete, OldStart: 0, OldEnd: 2, NewStart: 0, NewEnd: 0}},
		},
		{
			name: "append at end",
			old:  []string{"a"},
			new:  []string{"a", "b"},
			want: []Hunk{
				{Op: OpEqual, OldStart: 0, OldEnd: 1, NewStart: 0, NewEnd: 1},
				{Op: OpInsert, OldStart: 1, OldEnd: 1, NewStart: 1, NewEnd: 2},
			},
		},
		{
			name: "delete in the middle",
			old:  []string{"a", "b", "c"},
			new:  []string{"a", "c"},
			want: []Hunk{
				{Op: OpEqual, OldStart: 0, OldEnd: 1, NewStart: 0, NewEnd: 1},
				{Op: OpDelete, OldStart: 1, OldEnd: 2, NewStart: 1, NewEnd: 1},
				{Op: OpEqual, OldStart: 2, OldEnd: 3, NewStart: 1, NewEnd: 2},
			},
		},
		{
			name: "replace in the middle emits delete then insert",
			old:  []string{"a", "b", "c"},
			new:  []string{"a", "B", "c"},
			want: []Hunk{
				{Op: OpEqual, OldStart: 0, OldEnd: 1, NewStart: 0, NewEnd: 1},
				{Op: OpDelete, OldStart: 1, OldEnd: 2, NewStart: 1, NewEnd: 1},
				{Op: OpInsert, OldStart: 2, OldEnd: 2, NewStart: 1, NewEnd: 2},
				{Op: OpEqual, OldStart: 2, OldEnd: 3, NewStart: 2, NewEnd: 3},
			},
		},
		{
			name: "whitespace-only change pairs as equal",
			old:  []string{"a := 1", "b := 2"},
			new:  []string{"\ta := 1", "\tb   :=  2"},
			want: []Hunk{{Op: OpEqual, OldStart: 0, OldEnd: 2, NewStart: 0, NewEnd: 2}},
		},
		{
			name: "nothing in common",
			old:  []string{"a", "b"},
			new:  []string{"x", "y"},
			want: []Hunk{
				{Op: OpDelete, OldStart: 0, OldEnd: 2, NewStart: 0, NewEnd: 0},
				{Op: OpInsert, OldStart: 2, OldEnd: 2, NewStart: 0, NewEnd: 2},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Diff(tc.old, tc.new)
			if !equalHunks(got, tc.want) {
				t.Fatalf("Diff() =\n%s\nwant\n%s", formatHunks(got), formatHunks(tc.want))
			}
			assertTiles(t, got, len(tc.old), len(tc.new))
		})
	}
}

// TestDiffReindentIsAllEqual pins the pass-1 ruling: a whole-file
// reindent produces no delete/insert at all, only OpEqual pairs.
func TestDiffReindentIsAllEqual(t *testing.T) {
	const n = 200
	oldLines := make([]string, n)
	newLines := make([]string, n)
	for i := range oldLines {
		oldLines[i] = fmt.Sprintf("value%d := compute(%d)", i, i)
		newLines[i] = "\t" + oldLines[i]
	}
	got := Diff(oldLines, newLines)
	want := []Hunk{{Op: OpEqual, OldStart: 0, OldEnd: n, NewStart: 0, NewEnd: n}}
	if !equalHunks(got, want) {
		t.Fatalf("Diff() =\n%s\nwant\n%s", formatHunks(got), formatHunks(want))
	}
}

// TestDiffPassTwoRefinesResidue exercises pass 2 directly on the input
// shape it exists for: a residue that pass 1 left as one whole-region
// delete+insert. Pass 2 re-runs Myers over the RAW lines and splits it
// into the aligned sub-hunks around the surviving line.
//
// Note the standing invariant documented on Diff: while pass 1 succeeds
// exactly, it cannot leave a raw-equal pair inside a residue (raw
// equality implies normalized equality, which would have extended pass
// 1's LCS), so pass 2 only bites when pass 1 degraded. That is exactly
// what this test simulates by handing refineResidues the degenerate
// pass-1 tiling.
func TestDiffPassTwoRefinesResidue(t *testing.T) {
	oldLines := []string{"a", "b", "c"}
	newLines := []string{"x", "b", "y"}

	degenerate := []Hunk{
		{Op: OpDelete, OldStart: 0, OldEnd: 3, NewStart: 0, NewEnd: 0},
		{Op: OpInsert, OldStart: 3, OldEnd: 3, NewStart: 0, NewEnd: 3},
	}
	got := refineResidues(degenerate, oldLines, newLines)
	want := []Hunk{
		{Op: OpDelete, OldStart: 0, OldEnd: 1, NewStart: 0, NewEnd: 0},
		{Op: OpInsert, OldStart: 1, OldEnd: 1, NewStart: 0, NewEnd: 1},
		{Op: OpEqual, OldStart: 1, OldEnd: 2, NewStart: 1, NewEnd: 2},
		{Op: OpDelete, OldStart: 2, OldEnd: 3, NewStart: 2, NewEnd: 2},
		{Op: OpInsert, OldStart: 3, OldEnd: 3, NewStart: 2, NewEnd: 3},
	}
	if !equalHunks(got, want) {
		t.Fatalf("refineResidues() =\n%s\nwant\n%s", formatHunks(got), formatHunks(want))
	}
	assertTiles(t, got, len(oldLines), len(newLines))
}

// TestDiffPassTwoCannotIntroduceEqualsWhenPassOneIsExact pins the other
// half of the invariant above: for an exact pass 1, running pass 2 is a
// no-op, so Diff's output equals the pass-1 tiling.
func TestDiffPassTwoCannotIntroduceEqualsWhenPassOneIsExact(t *testing.T) {
	rng := rand.New(rand.NewSource(0x10C))
	for trial := 0; trial < 200; trial++ {
		oldLines := randomLines(rng, 0, 25, 6)
		newLines := randomLines(rng, 0, 25, 6)

		pass1 := hunksFromPairs(
			lcsPairs(normalizeAll(oldLines), normalizeAll(newLines)),
			0, len(oldLines), 0, len(newLines),
		)
		pass2 := refineResidues(append([]Hunk(nil), pass1...), oldLines, newLines)
		if !equalHunks(pass1, pass2) {
			t.Fatalf("trial %d: pass 2 changed an exact pass-1 tiling\nold=%#v\nnew=%#v\npass1=\n%s\npass2=\n%s",
				trial, oldLines, newLines, formatHunks(pass1), formatHunks(pass2))
		}
	}
}

// TestDiffHunksTileInputs is the property test for the tiling contract:
// over randomized inputs, the old ranges of OpEqual+OpDelete reproduce
// [0, len(old)) exactly and the new ranges of OpEqual+OpInsert reproduce
// [0, len(new)) exactly.
func TestDiffHunksTileInputs(t *testing.T) {
	rng := rand.New(rand.NewSource(0x10C15))
	for trial := 0; trial < 2000; trial++ {
		oldLines := randomLines(rng, 0, 40, 8)
		newLines := randomLines(rng, 0, 40, 8)
		hunks := Diff(oldLines, newLines)
		assertTilesTrial(t, trial, hunks, oldLines, newLines)
	}
}

// TestDiffHunksTileInputsWithWhitespaceNoise reruns the tiling property
// over inputs whose lines differ only in whitespace, which is the case
// that drives pass 1's normalized pairing.
func TestDiffHunksTileInputsWithWhitespaceNoise(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBEEF))
	pads := []string{"", " ", "\t", "  \t ", "   "}
	for trial := 0; trial < 1000; trial++ {
		base := randomLines(rng, 1, 30, 6)
		oldLines := make([]string, len(base))
		newLines := make([]string, 0, len(base))
		for i, line := range base {
			oldLines[i] = line
			switch rng.Intn(4) {
			case 0: // drop the line
			case 1: // whitespace-only change
				newLines = append(newLines, pads[rng.Intn(len(pads))]+line+pads[rng.Intn(len(pads))])
			case 2: // real change
				newLines = append(newLines, line+"_x")
			default:
				newLines = append(newLines, line)
			}
		}
		hunks := Diff(oldLines, newLines)
		assertTilesTrial(t, trial, hunks, oldLines, newLines)
	}
}

func TestDiffDegraded(t *testing.T) {
	tests := []struct {
		name   string
		oldLen int
		newLen int
		want   bool
	}{
		{name: "both small", oldLen: 10, newLen: 10, want: false},
		{name: "both at the threshold", oldLen: DiffFallbackLines, newLen: DiffFallbackLines, want: false},
		{name: "old over the threshold", oldLen: DiffFallbackLines + 1, newLen: 1, want: true},
		{name: "new over the threshold", oldLen: 1, newLen: DiffFallbackLines + 1, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DiffDegraded(make([]string, tc.oldLen), make([]string, tc.newLen))
			if got != tc.want {
				t.Fatalf("DiffDegraded(%d, %d) = %v, want %v", tc.oldLen, tc.newLen, got, tc.want)
			}
		})
	}
}

// TestDiffLargeInputFallsBackToPlainCounting pins the >20k behaviour: one
// delete over everything old, one insert over everything new, and no
// alignment search.
func TestDiffLargeInputFallsBackToPlainCounting(t *testing.T) {
	n := DiffFallbackLines + 1
	oldLines := make([]string, n)
	newLines := make([]string, n)
	for i := range oldLines {
		oldLines[i] = fmt.Sprintf("line %d", i)
		newLines[i] = oldLines[i] // identical, yet still degraded
	}

	start := time.Now()
	got := Diff(oldLines, newLines)
	elapsed := time.Since(start)

	want := []Hunk{
		{Op: OpDelete, OldStart: 0, OldEnd: n, NewStart: 0, NewEnd: 0},
		{Op: OpInsert, OldStart: n, OldEnd: n, NewStart: 0, NewEnd: n},
	}
	if !equalHunks(got, want) {
		t.Fatalf("Diff() =\n%s\nwant\n%s", formatHunks(got), formatHunks(want))
	}
	if elapsed > 5*time.Second {
		t.Fatalf("degraded Diff took %s, want it to be trivial", elapsed)
	}
	assertTiles(t, got, n, n)
}

// TestDiffDisjointLargeInputsAreFast pins the bound on the search itself:
// two 5000-line sequences sharing nothing must not run a quadratic Myers
// walk. The lines-present-on-one-side-only prefilter collapses this to
// linear work.
func TestDiffDisjointLargeInputsAreFast(t *testing.T) {
	const n = 5000
	oldLines := make([]string, n)
	newLines := make([]string, n)
	for i := 0; i < n; i++ {
		oldLines[i] = fmt.Sprintf("old-%d", i)
		newLines[i] = fmt.Sprintf("new-%d", i)
	}

	start := time.Now()
	got := Diff(oldLines, newLines)
	elapsed := time.Since(start)

	want := []Hunk{
		{Op: OpDelete, OldStart: 0, OldEnd: n, NewStart: 0, NewEnd: 0},
		{Op: OpInsert, OldStart: n, OldEnd: n, NewStart: 0, NewEnd: n},
	}
	if !equalHunks(got, want) {
		t.Fatalf("Diff() =\n%s\nwant\n%s", formatHunks(got), formatHunks(want))
	}
	if elapsed > 10*time.Second {
		t.Fatalf("disjoint 5000x5000 Diff took %s, want it to be fast", elapsed)
	}
	assertTiles(t, got, n, n)
}

// TestDiffLargeMostlySharedInputIsFast covers the other realistic large
// shape: a big file with a handful of edits.
func TestDiffLargeMostlySharedInputIsFast(t *testing.T) {
	const n = 5000
	oldLines := make([]string, n)
	newLines := make([]string, n)
	for i := 0; i < n; i++ {
		oldLines[i] = fmt.Sprintf("line %d", i)
		newLines[i] = oldLines[i]
	}
	for _, i := range []int{7, 1000, 2500, 4999} {
		newLines[i] = fmt.Sprintf("changed %d", i)
	}

	start := time.Now()
	hunks := Diff(oldLines, newLines)
	elapsed := time.Since(start)
	if elapsed > 10*time.Second {
		t.Fatalf("mostly-shared 5000x5000 Diff took %s, want it to be fast", elapsed)
	}
	assertTiles(t, hunks, n, n)

	var equalLines int
	for _, h := range hunks {
		if h.Op == OpEqual {
			equalLines += h.OldEnd - h.OldStart
		}
	}
	if equalLines != n-4 {
		t.Fatalf("equal lines = %d, want %d", equalLines, n-4)
	}
}

// TestMyersPairsRespectsEditDistanceCap pins the bounded search: past the
// cap myersPairs reports failure instead of allocating without limit.
func TestMyersPairsRespectsEditDistanceCap(t *testing.T) {
	a := []string{"a", "b", "c", "d"}
	b := []string{"w", "x", "y", "z"}
	if _, ok := myersPairs(a, b, 2); ok {
		t.Fatal("myersPairs succeeded with an edit distance far above the cap")
	}
	if _, ok := myersPairs(a, b, len(a)+len(b)); !ok {
		t.Fatal("myersPairs failed with the full edit-distance budget")
	}
}

// ---- helpers ----

func randomLines(rng *rand.Rand, minLen, maxLen, alphabet int) []string {
	n := minLen
	if maxLen > minLen {
		n += rng.Intn(maxLen - minLen)
	}
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("l%d", rng.Intn(alphabet))
	}
	return out
}

func assertTiles(t *testing.T, hunks []Hunk, oldLen, newLen int) {
	t.Helper()
	assertTilesTrial(t, -1, hunks, make([]string, oldLen), make([]string, newLen))
}

func assertTilesTrial(t *testing.T, trial int, hunks []Hunk, oldLines, newLines []string) {
	t.Helper()
	oldCursor, newCursor := 0, 0
	for i, h := range hunks {
		switch h.Op {
		case OpEqual:
			if h.OldEnd-h.OldStart != h.NewEnd-h.NewStart {
				t.Fatalf("trial %d hunk %d: OpEqual spans differ: %+v", trial, i, h)
			}
			if h.OldEnd == h.OldStart {
				t.Fatalf("trial %d hunk %d: empty OpEqual: %+v", trial, i, h)
			}
			if h.OldStart != oldCursor || h.NewStart != newCursor {
				t.Fatalf("trial %d hunk %d: OpEqual does not tile at (%d,%d): %+v", trial, i, oldCursor, newCursor, h)
			}
			oldCursor = h.OldEnd
			newCursor = h.NewEnd
		case OpDelete:
			if h.NewStart != h.NewEnd {
				t.Fatalf("trial %d hunk %d: OpDelete has a new range: %+v", trial, i, h)
			}
			if h.OldEnd <= h.OldStart {
				t.Fatalf("trial %d hunk %d: empty OpDelete: %+v", trial, i, h)
			}
			if h.OldStart != oldCursor {
				t.Fatalf("trial %d hunk %d: OpDelete does not tile at %d: %+v", trial, i, oldCursor, h)
			}
			oldCursor = h.OldEnd
		case OpInsert:
			if h.OldStart != h.OldEnd {
				t.Fatalf("trial %d hunk %d: OpInsert has an old range: %+v", trial, i, h)
			}
			if h.NewEnd <= h.NewStart {
				t.Fatalf("trial %d hunk %d: empty OpInsert: %+v", trial, i, h)
			}
			if h.NewStart != newCursor {
				t.Fatalf("trial %d hunk %d: OpInsert does not tile at %d: %+v", trial, i, newCursor, h)
			}
			newCursor = h.NewEnd
		}
	}
	if oldCursor != len(oldLines) {
		t.Fatalf("trial %d: old ranges covered %d lines, want %d\n%s", trial, oldCursor, len(oldLines), formatHunks(hunks))
	}
	if newCursor != len(newLines) {
		t.Fatalf("trial %d: new ranges covered %d lines, want %d\n%s", trial, newCursor, len(newLines), formatHunks(hunks))
	}
}

func equalHunks(a, b []Hunk) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func formatHunks(hunks []Hunk) string {
	var sb strings.Builder
	if len(hunks) == 0 {
		return "  (none)"
	}
	for _, h := range hunks {
		fmt.Fprintf(&sb, "  %-6s old[%d,%d) new[%d,%d)\n", h.Op, h.OldStart, h.OldEnd, h.NewStart, h.NewEnd)
	}
	return strings.TrimRight(sb.String(), "\n")
}
