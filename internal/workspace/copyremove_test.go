package workspace

import (
	"strings"
	"testing"
)

func TestDecideCopyRemoval(t *testing.T) {
	ok := CopyRemovalFacts{Return: CopyReturnReturned, Compared: true}
	cases := []struct {
		name   string
		edit   func(f *CopyRemovalFacts)
		remove bool
		want   string
	}{
		{"the run is live", func(f *CopyRemovalFacts) { f.RunLive = true }, false, "still going"},
		{"a stamped copy", func(f *CopyRemovalFacts) { f.Stamped = true }, false, "refused to run git"},
		{"a pending return", func(f *CopyRemovalFacts) { f.Return = CopyReturnPending }, false, "not been brought back"},
		{"a refused return", func(f *CopyRemovalFacts) { f.Return = CopyReturnRefused }, false, "did not come back"},
		{"no record", func(f *CopyRemovalFacts) { f.Return = CopyReturnUnknown }, false, "no record"},
		{"not compared", func(f *CopyRemovalFacts) { f.Compared, f.CompareError = false, "too big" }, false, "could not compare the copy with its last commit: too big"},
		{"changed files", func(f *CopyRemovalFacts) { f.Changed = 3 }, false, "3 file(s) in the copy are changed"},
		{"extra files", func(f *CopyRemovalFacts) { f.Extra = 2 }, false, "2 file(s) in the copy are not in its last commit"},
		{"returned and clean", func(*CopyRemovalFacts) {}, true, ""},
		{"nothing new and clean", func(f *CopyRemovalFacts) { f.Return = CopyReturnNothingNew }, true, ""},
	}
	for _, c := range cases {
		f := ok
		c.edit(&f)
		v := DecideCopyRemoval(f)
		if v.Remove != c.remove || !strings.Contains(v.Reason, c.want) {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
	if len(copyRemovalRules) != 9 {
		t.Fatalf("copyRemovalRules has %d rows; give the new row a case", len(copyRemovalRules))
	}
}

func TestLocalReturnFor(t *testing.T) {
	cases := []struct {
		src          Source
		ret, bare    bool
		whyMentioned string
	}{
		{SourceLive, false, false, "your own folder"},
		{SourceCloneLocal, true, false, ""},
		{SourceCloneRemote, true, true, ""},
		{SourceWorktree, false, false, "already in your repository"},
	}
	for _, c := range cases {
		r, ok := LocalReturnFor(c.src)
		if !ok || r.Return != c.ret || r.Bare != c.bare || !strings.Contains(r.Why, c.whyMentioned) {
			t.Errorf("%s: %+v", c.src, r)
		}
	}
	if _, ok := LocalReturnFor("other"); ok {
		t.Fatal("an unknown source has a rule")
	}
	if len(localReturnRules) != 4 {
		t.Fatalf("localReturnRules has %d rows", len(localReturnRules))
	}
}
