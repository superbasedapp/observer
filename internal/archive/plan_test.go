package archive

import "testing"

// TestSelectCandidatesIsBoundedAndColdestFirst pins the two properties that
// make the sweep safe rather than merely correct: it never returns more than
// the cap (design §5.1 — no loop-until-done pass), and it moves the coldest
// units first so the hot working set converges on "recently active" instead of
// shedding an arbitrary slice each pass.
func TestSelectCandidatesIsBoundedAndColdestFirst(t *testing.T) {
	t.Parallel()
	in := []Candidate{
		{Project: "/fresh", Watermark: 900},
		{Project: "/ancient", Watermark: 100},
		{Project: "/middle", Watermark: 500},
	}
	got := SelectCandidates(in, PlanOptions{MaxUnitsPerPass: 2})
	if len(got) != 2 {
		t.Fatalf("returned %d candidates, want the cap of 2", len(got))
	}
	if got[0].Project != "/ancient" || got[1].Project != "/middle" {
		t.Fatalf("order = %q,%q; want coldest-first /ancient,/middle", got[0].Project, got[1].Project)
	}
	// The caller's slice must survive intact — the retention pass reports
	// "considered" from it after the plan has been taken.
	if in[0].Project != "/fresh" {
		t.Fatal("SelectCandidates reordered the caller's slice in place")
	}
}

// TestSelectCandidatesTieBreakIsStable pins deterministic batch composition:
// equal watermarks (common — many projects last indexed in the same sweep)
// must not produce a different batch run to run, or an operator chasing a
// stuck project would see it move in and out of the batch at random.
func TestSelectCandidatesTieBreakIsStable(t *testing.T) {
	t.Parallel()
	in := []Candidate{
		{Project: "/c", Watermark: 100},
		{Project: "/a", Watermark: 100},
		{Project: "/b", Watermark: 100},
	}
	for i := 0; i < 5; i++ {
		got := SelectCandidates(in, PlanOptions{MaxUnitsPerPass: 2})
		if got[0].Project != "/a" || got[1].Project != "/b" {
			t.Fatalf("iteration %d: order = %q,%q; want /a,/b", i, got[0].Project, got[1].Project)
		}
	}
}

// TestSelectCandidatesDefaultsTheCap pins that there is no "unlimited"
// spelling: a zero or negative cap falls back to the default rather than
// draining the whole backlog in one pass.
func TestSelectCandidatesDefaultsTheCap(t *testing.T) {
	t.Parallel()
	in := make([]Candidate, DefaultMaxUnitsPerPass+5)
	for i := range in {
		in[i] = Candidate{Project: string(rune('a' + i)), Watermark: int64(i)}
	}
	for _, cap := range []int{0, -1} {
		got := SelectCandidates(in, PlanOptions{MaxUnitsPerPass: cap})
		if len(got) != DefaultMaxUnitsPerPass {
			t.Errorf("cap %d returned %d candidates, want the default %d",
				cap, len(got), DefaultMaxUnitsPerPass)
		}
	}
}

// TestSelectCandidatesEmpty is the no-work path: nothing stale, nothing to do.
func TestSelectCandidatesEmpty(t *testing.T) {
	t.Parallel()
	if got := SelectCandidates(nil, PlanOptions{}); got != nil {
		t.Fatalf("empty input returned %v, want nil", got)
	}
}
