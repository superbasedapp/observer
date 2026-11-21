package proccapture

import (
	"sort"
	"time"
)

// Outcome is one run's final decision in a replay.
type Outcome struct {
	Facts    RunFacts
	Decision Decision
	// Detached is true when the run was kept and a later child turned it into
	// a service root (the detach heuristic); its Decision is then the
	// service-root keep.
	Detached bool
}

// ReplayResult is what Replay produced: every run's outcome in replay order,
// the per-session stats (the count invariant holds per session) and the
// rollup groups.
type ReplayResult struct {
	Outcomes []Outcome
	Stats    map[string]Stats
	Rollups  []Rollup
}

// Replay runs stored (or generated) runs through the decision table as the
// live Observer would, in start order, with each run's FINAL facts (Ended,
// Failed, AliveFor known). It rebuilds the tree-derived facts with Derive
// from ParentKey, so legacy rows that predate the budget replay correctly. A
// parent that starts after its child (clock skew) is treated as untracked.
//
// It is how Estimate projects volume and how `observer process compact`
// (another agent's command) plans a compaction. Pure; history is not
// modified.
func Replay(history []RunFacts, cfg Config) ReplayResult {
	p := NewPolicy(cfg)
	runs := make([]RunFacts, len(history))
	copy(runs, history)
	sort.SliceStable(runs, func(i, j int) bool {
		if !runs[i].Time.Equal(runs[j].Time) {
			return runs[i].Time.Before(runs[j].Time)
		}
		return runs[i].ProcessKey < runs[j].ProcessKey
	})
	runs = parentsFirst(runs)

	ledger := NewLedger()
	acc := NewAccumulator()
	lineage := make(map[string]*Lineage, len(runs))
	index := make(map[string]int, len(runs))
	toolCallEnded := make(map[string]time.Time)
	lastActivity := make(map[string]time.Time)
	res := ReplayResult{Outcomes: make([]Outcome, 0, len(runs))}

	for _, f := range runs {
		parent := lineage[f.ParentKey]
		if parent != nil && p.Enabled() {
			// The detach heuristic: the parent keeps spawning after its tool
			// call ended. Only a KEPT parent detaches (a rolled-up one has no
			// row to mark), the same rule the live Observer applies.
			if i, ok := index[parent.ProcessKey]; ok && res.Outcomes[i].Decision.Action == ActionKeep &&
				p.ShouldDetach(*parent, toolCallEnded[parent.ToolCallKey], f.Time) {
				out := &res.Outcomes[i]
				from := out.Decision.Counter
				out.Facts.ServiceRootKey = out.Facts.ProcessKey
				out.Facts.DetachHeuristic = true
				out.Decision.Action = ActionDetach
				out.Decision.Class = ClassServiceRoot
				out.Decision.Counter = CounterServiceKept
				out.Detached = true
				acc.Move(out.Facts.SessionID, from, CounterServiceKept)
				parent.ServiceRootKey = parent.ProcessKey
			}
		}
		if p.Enabled() {
			p.Derive(&f, parent)
			f.SessionLastActivity = lastActivity[f.SessionID]
		}
		d := p.Classify(f, ledger.State(f))
		ledger.Record(f, d)
		acc.Record(f, d)

		l := LineageOf(f, d)
		lineage[f.ProcessKey] = &l
		index[f.ProcessKey] = len(res.Outcomes)
		res.Outcomes = append(res.Outcomes, Outcome{Facts: f, Decision: d})

		if f.ToolCallRoot && f.Ended {
			toolCallEnded[f.ProcessKey] = f.Time.Add(f.AliveFor)
		}
		if f.Attributed() && f.ServiceRootKey == "" && f.Time.After(lastActivity[f.SessionID]) {
			lastActivity[f.SessionID] = f.Time
		}
	}
	delta := acc.Delta()
	res.Stats = delta.Stats
	res.Rollups = delta.Rollups
	return res
}

// UnattributedGroup is the machine-rollup group an unattributed row joins
// when the unattributed policy rolls it up after pending_hours (plan §8
// ruling 3): no session, group_kind unattributed, keyed by executable and
// argv template per bucket. The retention pass and Estimate both use it.
func UnattributedGroup(f RunFacts, cfg Config) GroupKey {
	return GroupKey{
		Kind:             GroupUnattributed,
		BucketStart:      BucketStart(f.Time, cfg.bucket()),
		ExeBasename:      f.ExeBasename,
		ArgvTemplateHash: TemplateHash(f.ExeBasename, f.Argv),
	}
}

// RollupUnattributed groups unattributed rows into machine-rollup increments
// (one per UnattributedGroup), the pure half of the retention pass's
// unattributed policy.
func RollupUnattributed(rows []RunFacts, cfg Config) []Rollup {
	acc := NewAccumulator()
	for _, f := range rows {
		acc.AddRollup(UnattributedGroup(f, cfg), f)
	}
	return acc.Delta().Rollups
}

// parentsFirst reorders time-sorted runs so a run whose parent is in the
// history comes after that parent. Stored start times are coarse (a snapshot
// backend stamps a parent and the child it started in the same poll alike),
// and a child replayed before its parent would look like an AI tool's root
// (R3) and be kept. The live path does not need this: it receives runs in
// start-tick order. Otherwise time order is preserved; a parent cycle (a
// recycled key) is broken where it is found.
func parentsFirst(runs []RunFacts) []RunFacts {
	pos := make(map[string]int, len(runs))
	for i, r := range runs {
		if _, dup := pos[r.ProcessKey]; !dup {
			pos[r.ProcessKey] = i
		}
	}
	out := make([]RunFacts, 0, len(runs))
	placed := make([]bool, len(runs))
	var chain []int
	for i := range runs {
		if placed[i] {
			continue
		}
		// Walk up through not-yet-placed parents, then place them top-down.
		chain = chain[:0]
		seen := map[int]bool{}
		for j := i; ; {
			chain = append(chain, j)
			seen[j] = true
			p, ok := pos[runs[j].ParentKey]
			if !ok || placed[p] || seen[p] || runs[j].ParentKey == "" {
				break
			}
			j = p
		}
		for k := len(chain) - 1; k >= 0; k-- {
			placed[chain[k]] = true
			out = append(out, runs[chain[k]])
		}
	}
	return out
}
