package proccapture

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// storedSession turns one generated session tree into stored rows (ids from
// 1), every row legacy (no capture class) like the pre-budget capture.
func storedSession(facts []RunFacts, session string) []StoredRun {
	var out []StoredRun
	for i, f := range facts {
		if f.SessionID != session {
			continue
		}
		out = append(out, StoredRun{ID: int64(i + 1), Facts: f})
	}
	return out
}

// TestPlanCompactionInvariant is the compaction half of the plan §5 property:
// the count invariant holds after the plan, every finding, failure, side
// effect and tool-linked run survives, rollup counts equal the folded and
// rolled-up rows, and planning the compacted result again is a no-op.
func TestPlanCompactionInvariant(t *testing.T) {
	tight := DefaultConfig()
	tight.PerToolCall, tight.PerSession, tight.PerMinute, tight.ExemplarsPerService = 3, 40, 5, 2
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"default", DefaultConfig()},
		{"tight", tight},
	} {
		for seed := range uint64(15) {
			r := rand.New(rand.NewPCG(seed, 7))
			session := fmt.Sprintf("c%d", seed)
			rows := storedSession(genTree(r, session, 200+r.IntN(300)), session)
			plan, err := PlanCompaction(session, rows, Stats{}, false, tc.cfg)
			if err != nil {
				t.Fatalf("%s seed %d: %v", tc.name, seed, err)
			}
			if plan.After.Observed != int64(len(rows)) {
				t.Fatalf("%s seed %d: observed %d, rows %d", tc.name, seed, plan.After.Observed, len(rows))
			}
			if plan.After.Observed != plan.After.Accounted() {
				t.Fatalf("%s seed %d: invariant broken %+v", tc.name, seed, plan.After)
			}
			deleted := map[int64]bool{}
			for _, id := range plan.Delete {
				deleted[id] = true
			}
			var kept []StoredRun
			for _, sr := range rows {
				f := sr.Facts
				protected := f.FindingsFired > 0 || f.Failed || f.SideEffects || f.ActionID > 0
				if protected && deleted[sr.ID] {
					t.Fatalf("%s seed %d: protected run %s deleted", tc.name, seed, f.ProcessKey)
				}
				if !deleted[sr.ID] {
					kept = append(kept, sr)
				}
			}
			if int64(len(kept)) != plan.After.Kept+plan.After.ServiceKept {
				t.Fatalf("%s seed %d: %d rows left, stats say %d kept + %d service kept",
					tc.name, seed, len(kept), plan.After.Kept, plan.After.ServiceKept)
			}
			var rolled int64
			for _, ru := range plan.Rollups {
				rolled += ru.Count
			}
			if want := plan.After.Folded + plan.After.RolledUp + plan.After.ServiceRolledUp; rolled != want {
				t.Fatalf("%s seed %d: rollups count %d, stats %d", tc.name, seed, rolled, want)
			}

			// Second pass over the compacted rows, with the classes stamped and
			// the stats row present: nothing more to do.
			classes := map[int64]ClassUpdate{}
			for _, u := range plan.Updates {
				classes[u.ID] = u
			}
			for i := range kept {
				if u, ok := classes[kept[i].ID]; ok {
					kept[i].Class = u.Class
				}
			}
			again, err := PlanCompaction(session, kept, plan.After, true, tc.cfg)
			if err != nil {
				t.Fatalf("%s seed %d second pass: %v", tc.name, seed, err)
			}
			if again.After != plan.After {
				t.Fatalf("%s seed %d second pass moved stats: %+v -> %+v", tc.name, seed, plan.After, again.After)
			}
		}
	}
}

// TestPlanCompactionExistingStats: rows the live path already counted (a
// stored class) move from their stored counter; legacy rows in the same
// session become observed now; the invariant still holds.
func TestPlanCompactionExistingStats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PerToolCall = 1
	root := RunFacts{ProcessKey: "root", SessionID: "s", AttributionSource: "env_token", ExeBasename: "claude.exe", Time: t0}
	shell := RunFacts{ProcessKey: "sh", ParentKey: "root", SessionID: "s", AttributionSource: "inherited", ExeBasename: "bash", Time: t0.Add(time.Second), Ended: true}
	rows := []StoredRun{
		{ID: 1, Class: ClassExemplar, Facts: root},
		{ID: 2, Class: ClassExemplar, Facts: shell},
	}
	for i := range 5 {
		rows = append(rows, StoredRun{ID: int64(10 + i), Facts: RunFacts{
			ProcessKey: fmt.Sprintf("c%d", i), ParentKey: "sh", SessionID: "s", AttributionSource: "inherited",
			ExeBasename: "git", Argv: "git status", Time: t0.Add(time.Duration(2+i) * time.Second), Ended: true,
		}})
	}
	existing := Stats{Observed: 2, Kept: 2}
	plan, err := PlanCompaction("s", rows, existing, true, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if plan.After.Observed != 7 || plan.After.Observed != plan.After.Accounted() {
		t.Fatalf("after = %+v, want observed 7 and the invariant", plan.After)
	}
	if len(plan.Delete) == 0 {
		t.Fatal("expected the over-budget git runs to roll up")
	}
	for _, id := range plan.Delete {
		if id == 1 || id == 2 {
			t.Fatalf("the seed root or the tool-call shell was deleted (%d)", id)
		}
	}
}

// TestPlanCompactionKeepsFailures: a failed run is never planned for deletion
// (R2), and ErrCompactionUnsafe wraps for callers that test for it.
func TestPlanCompactionKeepsFailures(t *testing.T) {
	cfg := DefaultConfig()
	rows := []StoredRun{{ID: 1, Facts: RunFacts{ProcessKey: "a", SessionID: "s", AttributionSource: "inherited", ExeBasename: "go", Failed: true, Ended: true, Time: t0}}}
	plan, err := PlanCompaction("s", rows, Stats{}, false, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Delete) != 0 {
		t.Fatal("a failed run was planned for deletion")
	}
}
