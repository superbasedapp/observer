package loc

import "testing"

func TestSplitAuthored(t *testing.T) {
	share := func(v float64) *float64 { return &v }
	cases := []struct {
		name          string
		code, comment int64
		wantShare     *float64
	}{
		{"empty scope has no share", 0, 0, nil},
		{"code only", 10, 0, share(0)},
		{"comment only", 0, 4, share(1)},
		{"mostly comments", 25, 75, share(0.75)},
		{"one in five", 80, 20, share(0.2)},
		{"negative clamps", -5, 5, share(1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitAuthored(tc.code, tc.comment)
			if tc.wantShare == nil {
				if got.CommentShare != nil {
					t.Fatalf("share = %v, want nil", *got.CommentShare)
				}
				return
			}
			if got.CommentShare == nil || *got.CommentShare != *tc.wantShare {
				t.Fatalf("share = %v, want %v", got.CommentShare, *tc.wantShare)
			}
			if got.CodeLines < 0 || got.CommentLines < 0 {
				t.Fatalf("negative count survived: %+v", got)
			}
		})
	}
}

func TestAuthoredSplitAddRecomputes(t *testing.T) {
	a := SplitAuthored(90, 10) // 10%
	b := SplitAuthored(10, 90) // 90%
	sum := a.Add(b)
	if sum.CodeLines != 100 || sum.CommentLines != 100 || sum.CommentShare == nil || *sum.CommentShare != 0.5 {
		t.Fatalf("Add = %+v, want 100/100 at 0.5 (recomputed, not averaged)", sum)
	}
}

func TestStatsAuthoredSplitExcludesNonAuthoredBuckets(t *testing.T) {
	s := Stats{AddedCode: 6, ModifiedCode: 2, DeletedCode: 50, AddedComment: 2, DeletedComment: 9, Whitespace: 40, Blank: 30, Unknown: 7}
	got := s.AuthoredSplit()
	if got.CodeLines != 8 || got.CommentLines != 2 || got.CommentShare == nil || *got.CommentShare != 0.2 {
		t.Fatalf("AuthoredSplit = %+v, want code 8 / comment 2 / 0.2", got)
	}
}
