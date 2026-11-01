package secquickscan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestParseBoxRefList keeps only box refs naming a commit.
func TestParseBoxRefList(t *testing.T) {
	t.Parallel()
	out := []byte("aaaaaaaa refs/observer/sandbox/RUN1\n" +
		"bbbbbbbb refs/heads/observer-sandbox/RUN2/work\n" +
		"cccccccc refs/heads/main\n" +
		"not-hex refs/observer/sandbox/RUN3\n" +
		"dddddddd refs/observer/sandbox/\n" +
		"eeeeeeee refs/observer/sandbox/../x\n")
	want := []BoxRefTip{{Ref: "refs/observer/sandbox/RUN1", Tip: "aaaaaaaa"}, {Ref: "refs/heads/observer-sandbox/RUN2/work", Tip: "bbbbbbbb"}}
	if got := ParseBoxRefList(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

// TestBoxRangeArgs: one argv per exclusion row; a bad id is refused.
func TestBoxRangeArgs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		r    BoxRange
		want []string
	}{
		{BoxRange{Tip: "aaaaaaa", Exclude: ExcludeAllRefs}, []string{"rev-list", "--reverse", "aaaaaaa", "--single-worktree", "--not", "--all", "--"}},
		{BoxRange{Tip: "aaaaaaa", Exclude: ExcludeOtherRefs}, []string{"rev-list", "--reverse", "aaaaaaa", "--single-worktree", "--not", "--exclude=refs/observer/sandbox/*", "--exclude=refs/heads/observer-sandbox/*", "--all", "--"}},
		{BoxRange{Tip: "aaaaaaa", Not: []string{"bbbbbbb"}, Exclude: ExcludeNone}, []string{"rev-list", "--reverse", "aaaaaaa", "^bbbbbbb", "--"}},
	} {
		got, ok := tc.r.rangeArgs()
		if !ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%+v: %v %v", tc.r, got, ok)
		}
	}
	if _, ok := (BoxRange{Tip: "--all"}).rangeArgs(); ok {
		t.Fatal("a bad tip was accepted")
	}
	if _, ok := (BoxRange{Tip: "aaaaaaa", Not: []string{"HEAD"}}).rangeArgs(); ok {
		t.Fatal("a bad Not was accepted")
	}
}

// TestWalkBoxUnlistableRange: a range git cannot list scans its tip alone
// and reports the range unread (an unknown remainder), never clean.
func TestWalkBoxUnlistableRange(t *testing.T) {
	t.Parallel()
	git := func(_ context.Context, _ string, _ int, _ time.Duration, args ...string) ([]byte, bool, error) {
		return nil, false, errors.New("git failed")
	}
	c := &CommitScan{Engine: &Engine{Git: git}}
	res := c.WalkBox(context.Background(), "/r", []BoxRange{{Key: "k", Tip: "aaaaaaa"}}, nil)
	if len(res) != 1 || !res[0].RangeUnread || len(res[0].Commits) != 1 || res[0].Commits[0].Verdict != VerdictUnknown || res[0].Verdict() != VerdictUnknown {
		t.Fatalf("res %+v", res)
	}
}

// TestListBoxRefsOverCap (lane sec-box audit finding 2): a listing past the
// byte cap keeps its whole lines and says so; one past the ref cap keeps
// the first refs in order and says so; neither is "no listing", so the
// walk still records the cut and walks the first refs.
func TestListBoxRefsOverCap(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&b, "%040x refs/observer/sandbox/RUN%02d\n", i+1, i)
	}
	all := b.String()
	cut := all[:len(all)-4] // the last line cut inside its ref name
	for _, tc := range []struct {
		name     string
		out      string
		over     bool
		max      int
		want     int
		wantOver bool
	}{
		{"under both caps", all, false, 0, 6, false},
		{"byte cap: the cut line is dropped", cut, true, 0, 5, true},
		{"ref cap", all, false, 4, 4, true},
	} {
		out, over := tc.out, tc.over
		git := func(context.Context, string, int, time.Duration, ...string) ([]byte, bool, error) {
			return []byte(out), over, nil
		}
		c := &CommitScan{Engine: &Engine{Git: git}, MaxBoxRefs: tc.max}
		list, ok := c.ListBoxRefs(context.Background(), "/r")
		if !ok || len(list.Refs) != tc.want || list.OverCap != tc.wantOver {
			t.Errorf("%s: ok=%v refs=%d over=%v", tc.name, ok, len(list.Refs), list.OverCap)
			continue
		}
		if list.Refs[0].Ref != "refs/observer/sandbox/RUN00" || list.Refs[tc.want-1].Ref != fmt.Sprintf("refs/observer/sandbox/RUN%02d", tc.want-1) {
			t.Errorf("%s: not the first refs in order: %+v", tc.name, list.Refs)
		}
	}
	failing := func(context.Context, string, int, time.Duration, ...string) ([]byte, bool, error) {
		return nil, false, errors.New("git failed")
	}
	if _, ok := (&CommitScan{Engine: &Engine{Git: failing}}).ListBoxRefs(context.Background(), "/r"); ok {
		t.Fatal("a failed listing read as a listing")
	}
	if n := (&CommitScan{}).BoxWalksPerTick(); n != MaxBoxWalksPerTick {
		t.Fatalf("default walks per tick %d", n)
	}
}
