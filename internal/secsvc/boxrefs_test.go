//go:build !sbo_omit_security

package secsvc

import (
	"reflect"
	"testing"
)

// TestPlanBoxRefs: one case per row of PlanBoxRefs's table.
func TestPlanBoxRefs(t *testing.T) {
	t.Parallel()
	prev := map[string]string{
		"refs/observer/sandbox/RUNA":            "aaaaaaa",
		"refs/observer/sandbox/RUNB":            "bbbbbbb",
		"refs/heads/observer-sandbox/RUNC/work": "ccccccc",
	}
	listing := []BoxRef{
		{Ref: "refs/observer/sandbox/RUNA", Tip: "aaaaaaa"},
		{Ref: "refs/observer/sandbox/RUNB", Tip: "bbbbbb2"},
		{Ref: "refs/observer/sandbox/RUND", Tip: "ddddddd"},
		{Ref: "refs/observer/sandbox/RUND", Tip: "eeeeeee"},
	}
	walks, next := PlanBoxRefs(prev, listing)
	want := []BoxRefWalk{
		{Ref: "refs/observer/sandbox/RUNB", Tip: "bbbbbb2", From: "bbbbbbb", RunID: "RUNB"},
		{Ref: "refs/observer/sandbox/RUND", Tip: "ddddddd", RunID: "RUND"},
	}
	if !reflect.DeepEqual(walks, want) {
		t.Fatalf("walks %+v", walks)
	}
	wantNext := map[string]string{
		"refs/observer/sandbox/RUNA": "aaaaaaa", "refs/observer/sandbox/RUNB": "bbbbbb2", "refs/observer/sandbox/RUND": "ddddddd",
	}
	if !reflect.DeepEqual(next, wantNext) {
		t.Fatalf("next %v (the deleted worktree branch must be forgotten)", next)
	}
	if w, _ := PlanBoxRefs(next, listing[:3]); len(w) != 0 {
		t.Fatalf("an unchanged listing walks %+v", w)
	}
}

// TestBoxRunID: the run each box namespace names.
func TestBoxRunID(t *testing.T) {
	t.Parallel()
	for ref, want := range map[string]string{
		"refs/observer/sandbox/RUN1":            "RUN1",
		"refs/heads/observer-sandbox/RUN2/work": "RUN2",
		"refs/heads/observer-sandbox/RUN3":      "RUN3",
		"refs/heads/main":                       "",
	} {
		if got := BoxRunID(ref); got != want {
			t.Errorf("%s: %q", ref, got)
		}
	}
}

// TestPlanBoxRefsClaimed (lane sec-box audit finding 5): only a worktree
// branch, whose name the box can write, carries a claimed run id.
func TestPlanBoxRefsClaimed(t *testing.T) {
	t.Parallel()
	walks, _ := PlanBoxRefs(nil, []BoxRef{
		{Ref: "refs/heads/observer-sandbox/RUNW/work", Tip: "aaaaaaa"},
		{Ref: "refs/observer/sandbox/RUNR", Tip: "bbbbbbb"},
	})
	if len(walks) != 2 || !walks[0].Claimed || walks[0].RunID != "RUNW" || walks[1].Claimed {
		t.Fatalf("walks %+v", walks)
	}
}

// TestCapBoxWalksAndKeepUnwalked (lane sec-box audit finding 3): the walk
// cap keeps the first walks; a ref the tick did not finish goes back to
// its previous tip, or is forgotten when it had none, so it is walked
// again next tick.
func TestCapBoxWalksAndKeepUnwalked(t *testing.T) {
	t.Parallel()
	walks := []BoxRefWalk{{Ref: "a"}, {Ref: "b"}, {Ref: "c"}}
	for _, tc := range []struct {
		max            int
		kept, deferred int
	}{{0, 3, 0}, {3, 3, 0}, {5, 3, 0}, {2, 2, 1}, {1, 1, 2}} {
		k, d := CapBoxWalks(walks, tc.max)
		if len(k) != tc.kept || len(d) != tc.deferred || (len(d) > 0 && d[0].Ref != walks[tc.max].Ref) {
			t.Errorf("max %d: kept %v deferred %v", tc.max, k, d)
		}
	}
	prev := map[string]string{"moved": "old", "same": "s"}
	next := map[string]string{"moved": "new", "same": "s", "fresh": "f", "done": "d"}
	got := KeepUnwalked(prev, next, []string{"moved", "fresh"})
	want := map[string]string{"moved": "old", "same": "s", "done": "d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kept %v, want %v", got, want)
	}
	if next["moved"] != "new" {
		t.Fatal("KeepUnwalked changed its input")
	}
	if got := KeepUnwalked(prev, next, nil); !reflect.DeepEqual(got, next) {
		t.Fatalf("nothing left: %v", got)
	}
}
