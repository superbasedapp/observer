package sandboxcred

import "testing"

// foldOK is a stamped request every fold row passes.
func foldOK() FoldFacts {
	return FoldFacts{
		Found: true, Lane: LaneLocal, Live: true, HelperLive: true,
		Token: "tok-SENTINEL-0000", TokenHash: Hash("tok-SENTINEL-0000"),
		Session: "11111111-2222-3333-4444-555555555555", ClaimedByRun: true, FreshClaim: true,
	}
}

// TestDecideFoldRows is one case per row of foldRules, plus the pass.
func TestDecideFoldRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mut      func(*FoldFacts)
		code     FoldCode
		session  string
		mismatch bool
	}{
		{"every row holds", func(*FoldFacts) {}, FoldNative, "11111111-2222-3333-4444-555555555555", false},
		{"no record", func(f *FoldFacts) { f.Found = false }, FoldNoRecord, "", false},
		{"hosted lane keeps its session", func(f *FoldFacts) { f.Lane = LaneHosted }, FoldHostedLane, "", false},
		{"unknown lane", func(f *FoldFacts) { f.Lane = "bogus" }, FoldHostedLane, "", false},
		{"not live", func(f *FoldFacts) { f.Live = false }, FoldNotLive, "", false},
		{"helper gone", func(f *FoldFacts) { f.HelperLive = false }, FoldHelperGone, "", false},
		{"no token", func(f *FoldFacts) { f.Token = "" }, FoldNotRelayed, "", false},
		{"wrong token", func(f *FoldFacts) { f.Token = "tok-SENTINEL-9999" }, FoldNotRelayed, "", false},
		{"no stored token hash", func(f *FoldFacts) { f.TokenHash = "" }, FoldNotRelayed, "", false},
		{"no session named", func(f *FoldFacts) { f.Session = "" }, FoldNoSession, "", false},
		{"session the run's hooks do not claim", func(f *FoldFacts) { f.ClaimedByRun = false }, FoldNotRunSession, "", true},
		{"a session the node recorded before the run claimed it", func(f *FoldFacts) { f.FreshClaim = false }, FoldResumed, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := foldOK()
			tc.mut(&f)
			got := DecideFold(f)
			if got.Code != tc.code || got.Session != tc.session || got.Mismatch != tc.mismatch {
				t.Fatalf("DecideFold = %+v, want code %s session %q mismatch %v", got, tc.code, tc.session, tc.mismatch)
			}
		})
	}
}

// TestFoldRulesCovered pins one case above per row: a new row needs a case.
func TestFoldRulesCovered(t *testing.T) {
	t.Parallel()
	if len(foldRules) != 8 {
		t.Fatalf("foldRules has %d rows; add a TestDecideFoldRows case for each new one and update this count", len(foldRules))
	}
}
