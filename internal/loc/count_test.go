package loc

import (
	"fmt"
	"testing"
)

// TestCountTransitionTable is the class-transition table (plan §1), one
// test case per cell of the 4x4 code/comment/blank/unknown matrix. Each
// case is a single paired line inside a one-delete/one-insert change
// region.
func TestCountTransitionTable(t *testing.T) {
	tests := []struct {
		name string
		old  LineClass
		new  LineClass
		want Stats
	}{
		{name: "code to code is one modified", old: ClassCode, new: ClassCode, want: Stats{ModifiedCode: 1}},
		{name: "code to comment", old: ClassCode, new: ClassComment, want: Stats{DeletedCode: 1, AddedComment: 1}},
		{name: "code to blank", old: ClassCode, new: ClassBlank, want: Stats{DeletedCode: 1, Blank: 1}},
		{name: "code to unknown", old: ClassCode, new: ClassUnknown, want: Stats{DeletedCode: 1, Unknown: 1}},

		{name: "comment to code", old: ClassComment, new: ClassCode, want: Stats{DeletedComment: 1, AddedCode: 1}},
		{name: "comment to comment has no modified column", old: ClassComment, new: ClassComment, want: Stats{DeletedComment: 1, AddedComment: 1}},
		{name: "comment to blank", old: ClassComment, new: ClassBlank, want: Stats{DeletedComment: 1, Blank: 1}},
		{name: "comment to unknown", old: ClassComment, new: ClassUnknown, want: Stats{DeletedComment: 1, Unknown: 1}},

		{name: "blank to code", old: ClassBlank, new: ClassCode, want: Stats{Blank: 1, AddedCode: 1}},
		{name: "blank to comment", old: ClassBlank, new: ClassComment, want: Stats{Blank: 1, AddedComment: 1}},
		{name: "blank to blank counts both sides", old: ClassBlank, new: ClassBlank, want: Stats{Blank: 2}},
		{name: "blank to unknown", old: ClassBlank, new: ClassUnknown, want: Stats{Blank: 1, Unknown: 1}},

		{name: "unknown to code", old: ClassUnknown, new: ClassCode, want: Stats{Unknown: 1, AddedCode: 1}},
		{name: "unknown to comment", old: ClassUnknown, new: ClassComment, want: Stats{Unknown: 1, AddedComment: 1}},
		{name: "unknown to blank", old: ClassUnknown, new: ClassBlank, want: Stats{Unknown: 1, Blank: 1}},
		{name: "unknown to unknown counts both sides", old: ClassUnknown, new: ClassUnknown, want: Stats{Unknown: 2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hunks := []Hunk{
				{Op: OpDelete, OldStart: 0, OldEnd: 1, NewStart: 0, NewEnd: 0},
				{Op: OpInsert, OldStart: 1, OldEnd: 1, NewStart: 0, NewEnd: 1},
			}
			got := Count(hunks, []LineClass{tc.old}, []LineClass{tc.new}, []string{"old"}, []string{"new"})
			assertStats(t, got, tc.want)
		})
	}
}

// TestCountPureDeleteTable is rule 4: a deleted line with no counterpart.
func TestCountPureDeleteTable(t *testing.T) {
	tests := []struct {
		name string
		old  LineClass
		want Stats
	}{
		{name: "code", old: ClassCode, want: Stats{DeletedCode: 1}},
		{name: "comment", old: ClassComment, want: Stats{DeletedComment: 1}},
		{name: "blank", old: ClassBlank, want: Stats{Blank: 1}},
		{name: "unknown", old: ClassUnknown, want: Stats{Unknown: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hunks := []Hunk{{Op: OpDelete, OldStart: 0, OldEnd: 1, NewStart: 0, NewEnd: 0}}
			got := Count(hunks, []LineClass{tc.old}, nil, []string{"old"}, nil)
			assertStats(t, got, tc.want)
		})
	}
}

// TestCountPureInsertTable is rule 5: an inserted line with no
// counterpart.
func TestCountPureInsertTable(t *testing.T) {
	tests := []struct {
		name string
		new  LineClass
		want Stats
	}{
		{name: "code", new: ClassCode, want: Stats{AddedCode: 1}},
		{name: "comment", new: ClassComment, want: Stats{AddedComment: 1}},
		{name: "blank", new: ClassBlank, want: Stats{Blank: 1}},
		{name: "unknown", new: ClassUnknown, want: Stats{Unknown: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hunks := []Hunk{{Op: OpInsert, OldStart: 0, OldEnd: 0, NewStart: 0, NewEnd: 1}}
			got := Count(hunks, nil, []LineClass{tc.new}, nil, []string{"new"})
			assertStats(t, got, tc.want)
		})
	}
}

// TestCountEqualPairs is rule 1: an OpEqual pair costs nothing when the
// raw texts match and exactly one Whitespace when they do not.
func TestCountEqualPairs(t *testing.T) {
	tests := []struct {
		name    string
		oldLine string
		newLine string
		want    Stats
	}{
		{name: "identical raw text is untouched", oldLine: "a := 1", newLine: "a := 1", want: Stats{}},
		{name: "leading tab is one whitespace", oldLine: "a := 1", newLine: "\ta := 1", want: Stats{Whitespace: 1}},
		{name: "trailing space is one whitespace", oldLine: "a := 1", newLine: "a := 1  ", want: Stats{Whitespace: 1}},
		{name: "interior retab is one whitespace", oldLine: "a := 1", newLine: "a\t:=\t1", want: Stats{Whitespace: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hunks := []Hunk{{Op: OpEqual, OldStart: 0, OldEnd: 1, NewStart: 0, NewEnd: 1}}
			got := Count(hunks, []LineClass{ClassCode}, []LineClass{ClassCode}, []string{tc.oldLine}, []string{tc.newLine})
			assertStats(t, got, tc.want)
		})
	}
}

// TestCountTransitionTableIsDeleteThenInsertExceptCodeToCode pins the
// derivation rule the table encodes: the only cell that collapses a pair
// into one count is code -> code; every other cell is exactly
// deleteTable[old] + insertTable[new].
func TestCountTransitionTableIsDeleteThenInsertExceptCodeToCode(t *testing.T) {
	for o := LineClass(0); o < classIndex; o++ {
		for n := LineClass(0); n < classIndex; n++ {
			if o == ClassCode && n == ClassCode {
				continue
			}
			t.Run(fmt.Sprintf("%s_to_%s", o, n), func(t *testing.T) {
				want := deleteTable[o]
				want.Add(insertTable[n])
				assertStats(t, transitionTable[o][n], want)
			})
		}
	}
}

// TestCountOutOfRangeClassesAreUnknown is rule 6: a caller that
// classified a different text than it diffed must degrade to
// ClassUnknown, never panic.
func TestCountOutOfRangeClassesAreUnknown(t *testing.T) {
	tests := []struct {
		name       string
		hunks      []Hunk
		oldClasses []LineClass
		newClasses []LineClass
		oldLines   []string
		newLines   []string
		want       Stats
	}{
		{
			name:       "short old classes",
			hunks:      []Hunk{{Op: OpDelete, OldStart: 0, OldEnd: 2, NewStart: 0, NewEnd: 0}},
			oldClasses: []LineClass{ClassCode},
			oldLines:   []string{"a", "b"},
			want:       Stats{DeletedCode: 1, Unknown: 1},
		},
		{
			name:       "short new classes",
			hunks:      []Hunk{{Op: OpInsert, OldStart: 0, OldEnd: 0, NewStart: 0, NewEnd: 2}},
			newClasses: []LineClass{ClassCode},
			newLines:   []string{"a", "b"},
			want:       Stats{AddedCode: 1, Unknown: 1},
		},
		{
			name:  "no classes at all",
			hunks: []Hunk{{Op: OpDelete, OldStart: 0, OldEnd: 1, NewStart: 0, NewEnd: 0}, {Op: OpInsert, OldStart: 1, OldEnd: 1, NewStart: 0, NewEnd: 1}},
			want:  Stats{Unknown: 2},
		},
		{
			name:       "class value outside the enum",
			hunks:      []Hunk{{Op: OpDelete, OldStart: 0, OldEnd: 1, NewStart: 0, NewEnd: 0}},
			oldClasses: []LineClass{LineClass(200)},
			oldLines:   []string{"a"},
			want:       Stats{Unknown: 1},
		},
		{
			name:       "equal hunk indexes past the lines",
			hunks:      []Hunk{{Op: OpEqual, OldStart: 0, OldEnd: 2, NewStart: 0, NewEnd: 2}},
			oldClasses: []LineClass{ClassCode, ClassCode},
			newClasses: []LineClass{ClassCode, ClassCode},
			oldLines:   []string{"a"},
			newLines:   []string{"a"},
			want:       Stats{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Count(tc.hunks, tc.oldClasses, tc.newClasses, tc.oldLines, tc.newLines)
			assertStats(t, got, tc.want)
		})
	}
}

// TestCountRegionPairsThenSpills is rule 2: within a change region the
// first min(len(D), len(I)) lines pair up and the rest are pure
// deletes/inserts.
func TestCountRegionPairsThenSpills(t *testing.T) {
	tests := []struct {
		name    string
		deletes int
		inserts int
		want    Stats
	}{
		{name: "more deletes than inserts", deletes: 3, inserts: 1, want: Stats{ModifiedCode: 1, DeletedCode: 2}},
		{name: "more inserts than deletes", deletes: 1, inserts: 3, want: Stats{ModifiedCode: 1, AddedCode: 2}},
		{name: "equal sizes are all modified", deletes: 3, inserts: 3, want: Stats{ModifiedCode: 3}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldLines := make([]string, tc.deletes)
			for i := range oldLines {
				oldLines[i] = fmt.Sprintf("old %d", i)
			}
			newLines := make([]string, tc.inserts)
			for i := range newLines {
				newLines[i] = fmt.Sprintf("new %d", i)
			}
			hunks := Diff(oldLines, newLines)
			got := Count(hunks, allCode(tc.deletes), allCode(tc.inserts), oldLines, newLines)
			assertStats(t, got, tc.want)
		})
	}
}

// ---- acceptance scenarios (plan §5 criteria 1 and 9) ----

// TestCountOneLineReplacementIsOneModified: a one-line replacement is 1
// modified line, not 1 deleted plus 1 added.
func TestCountOneLineReplacementIsOneModified(t *testing.T) {
	oldLines := []string{"a := 1"}
	newLines := []string{"a := 2"}
	got := Count(Diff(oldLines, newLines), allCode(1), allCode(1), oldLines, newLines)
	assertStats(t, got, Stats{ModifiedCode: 1})
}

// TestCountReindentIsWhitespaceNotModified: a 200-line reindent is 200
// whitespace and 0 modified.
func TestCountReindentIsWhitespaceNotModified(t *testing.T) {
	const n = 200
	oldLines := make([]string, n)
	newLines := make([]string, n)
	for i := range oldLines {
		oldLines[i] = fmt.Sprintf("value%d := compute(%d)", i, i)
		newLines[i] = "\t" + oldLines[i]
	}
	got := Count(Diff(oldLines, newLines), allCode(n), allCode(n), oldLines, newLines)
	assertStats(t, got, Stats{Whitespace: n})
}

// TestCountMassRenameIsNModified: a rename touching one identifier on
// each of 50 lines is 50 modified lines. This is by design (plan §1) —
// loc counts line slots, not edit intent.
func TestCountMassRenameIsNModified(t *testing.T) {
	const n = 50
	oldLines := make([]string, n)
	newLines := make([]string, n)
	for i := range oldLines {
		oldLines[i] = fmt.Sprintf("alphaValue%d := compute(%d)", i, i)
		newLines[i] = fmt.Sprintf("betaValue%d := compute(%d)", i, i)
	}
	got := Count(Diff(oldLines, newLines), allCode(n), allCode(n), oldLines, newLines)
	assertStats(t, got, Stats{ModifiedCode: n})
}

// TestCountMovedBlockIsDeleteAndAdd: a 5-line block moved from the top to
// the bottom of a 20-line file.
//
// Observed behaviour of this implementation: the longest common
// subsequence is the untouched 15-line tail, so the moved block aligns as
// 5 pure deletes at the top and 5 pure inserts at the bottom — 5 deleted
// code lines plus 5 added code lines, NOT 5 modified pairs. Moved blocks
// are counted GROSS (plan §1: "moved blocks = delete + add (gross),
// stated in the UI"); loc has no move detection and does not pretend to.
func TestCountMovedBlockIsDeleteAndAdd(t *testing.T) {
	const n = 20
	const block = 5
	oldLines := make([]string, n)
	for i := range oldLines {
		oldLines[i] = fmt.Sprintf("statement%d()", i)
	}
	newLines := make([]string, 0, n)
	newLines = append(newLines, oldLines[block:]...)
	newLines = append(newLines, oldLines[:block]...)

	hunks := Diff(oldLines, newLines)
	assertTilesTrial(t, 0, hunks, oldLines, newLines)

	got := Count(hunks, allCode(n), allCode(n), oldLines, newLines)
	assertStats(t, got, Stats{DeletedCode: block, AddedCode: block})
}

// TestCountPureAppend: appended lines are added, nothing else.
func TestCountPureAppend(t *testing.T) {
	oldLines := []string{"a := 1"}
	newLines := []string{"a := 1", "b := 2", "c := 3"}
	got := Count(Diff(oldLines, newLines), allCode(1), allCode(3), oldLines, newLines)
	assertStats(t, got, Stats{AddedCode: 2})
}

// TestCountPureDelete: removed lines are deleted, nothing else.
func TestCountPureDelete(t *testing.T) {
	oldLines := []string{"a := 1", "b := 2", "c := 3"}
	newLines := []string{"a := 1"}
	got := Count(Diff(oldLines, newLines), allCode(3), allCode(1), oldLines, newLines)
	assertStats(t, got, Stats{DeletedCode: 2})
}

// TestCountEmptyBothSides: nothing in, nothing out.
func TestCountEmptyBothSides(t *testing.T) {
	got := Count(Diff(nil, nil), nil, nil, nil, nil)
	assertStats(t, got, Stats{})
	if got.Total() != 0 {
		t.Fatalf("Total() = %d, want 0", got.Total())
	}
}

// TestCountMixedRealisticEdit walks one small end-to-end edit through
// Diff and Count with a real class mix.
func TestCountMixedRealisticEdit(t *testing.T) {
	oldLines := []string{
		"// old comment",
		"",
		"a := 1",
		"b := 2",
	}
	newLines := []string{
		"// old comment",
		"",
		"\ta := 1", // whitespace only
		"a := 999", // replaces b := 2 (code -> code)
		"// added", // pure insert, comment
	}
	oldClasses := []LineClass{ClassComment, ClassBlank, ClassCode, ClassCode}
	newClasses := []LineClass{ClassComment, ClassBlank, ClassCode, ClassCode, ClassComment}

	hunks := Diff(oldLines, newLines)
	assertTilesTrial(t, 0, hunks, oldLines, newLines)

	got := Count(hunks, oldClasses, newClasses, oldLines, newLines)
	assertStats(t, got, Stats{Whitespace: 1, ModifiedCode: 1, AddedComment: 1})
}

// ---- helpers ----

func allCode(n int) []LineClass {
	out := make([]LineClass, n)
	for i := range out {
		out[i] = ClassCode
	}
	return out
}

func assertStats(t *testing.T, got, want Stats) {
	t.Helper()
	if got != want {
		t.Fatalf("Stats mismatch\n got: %s\nwant: %s", formatStats(got), formatStats(want))
	}
}

func formatStats(s Stats) string {
	return fmt.Sprintf(
		"added_code=%d modified_code=%d deleted_code=%d added_comment=%d deleted_comment=%d whitespace=%d blank=%d unknown=%d",
		s.AddedCode, s.ModifiedCode, s.DeletedCode, s.AddedComment, s.DeletedComment, s.Whitespace, s.Blank, s.Unknown,
	)
}
