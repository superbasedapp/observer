package proccapture

import (
	"errors"
	"fmt"
)

// Compaction planning for `observer process compact` (plan §4.9 and §9.4):
// the decision table applied to rows a session has ALREADY stored, most of
// them written before the capture budget existed. The plan is pure; the store
// executes it copy-then-delete in one transaction per session
// (store.CompactProcessSession).

// StoredRun is one stored process_runs row as the planner sees it: its row id,
// its stored capture_class ("" for a legacy row written before the budget)
// and the facts the decision table reasons over.
type StoredRun struct {
	ID    int64
	Class CaptureClass
	Facts RunFacts
}

// ClassUpdate stamps a kept legacy row with the capture class (and service
// root) the decision table gave it, so the summary's service list and the
// next compaction see it the way the live path would have written it.
type ClassUpdate struct {
	ID             int64
	Class          CaptureClass
	ServiceRootKey string
}

// CompactionPlan is what compacting one session would do. Apply it with
// store.CompactProcessSession; print it for a dry run.
type CompactionPlan struct {
	SessionID string
	// Rows is the number of stored rows the plan was computed over.
	Rows int
	// Delete are the row ids the decision table folds, rolls up or drops.
	// Never a finding, a failure, a side effect or a tool-linked run.
	Delete []int64
	// Updates stamp kept legacy rows with their capture class.
	Updates []ClassUpdate
	// Folds are the fold_count increments, keyed by the KEPT anchor's
	// process key.
	Folds map[string]int64
	// Rollups are the rollup increments the deleted runs become.
	Rollups []Rollup
	// Before is the session's stats row as read (zero when HadStats is
	// false); StatsDelta the increment the plan adds to it; After the result.
	Before     Stats
	HadStats   bool
	StatsDelta Stats
	After      Stats
	// Removed counts the deleted rows by the counter they move to.
	Removed map[Counter]int64
}

// Kept is the number of rows left after the plan runs.
func (p CompactionPlan) Kept() int { return p.Rows - len(p.Delete) }

// Empty reports whether applying the plan would write nothing.
func (p CompactionPlan) Empty() bool {
	return len(p.Delete) == 0 && len(p.Updates) == 0 && len(p.Folds) == 0 &&
		len(p.Rollups) == 0 && p.StatsDelta == (Stats{})
}

// ErrCompactionUnsafe is returned when the decision table would remove a run
// the compaction must never delete (a finding, a failure, a side effect or a
// tool-linked run). R1 to R3 keep them, so this is a broken-invariant guard,
// not a normal outcome: the session is left untouched.
var ErrCompactionUnsafe = errors.New("proccapture: compaction would remove a protected run")

// counterForClass is the stats counter a stored row with this class is
// counted under: the live path counts service roots and service rows as
// service_kept and everything else it keeps as kept.
func counterForClass(c CaptureClass) Counter {
	if c == ClassServiceRoot || c == ClassService {
		return CounterServiceKept
	}
	return CounterKept
}

// PlanCompaction replays a session's stored rows through the decision table
// (Replay) and turns the outcomes into a CompactionPlan:
//
//   - a LEGACY row (no stored class, written before the budget) the table
//     folds, rolls up or drops is deleted, its rollup increment written and
//     its fold counted on its kept anchor;
//   - a kept legacy row is stamped with the class the table gave it;
//   - a row that already has a class is final and left as it is: the live
//     path (or an earlier compaction) decided it with the full tree in view,
//     and a replay over a compacted session sees fewer runs, so re-deciding
//     it would flip rows back and forth. Running a compaction twice is a
//     no-op;
//   - the stats delta moves each row from the counter it is stored under
//     (none for a legacy row, which becomes observed now) to its new one, so
//     the count invariant (observed == kept + folded + rolled_up +
//     service_kept + service_rolled_up + dropped) holds after the plan
//     whenever it held before.
//
// existing / hasStats are the session's process_capture_stats row. With no
// row, every stored row is counted as newly observed. Pure; rows are not
// modified.
func PlanCompaction(sessionID string, rows []StoredRun, existing Stats, hasStats bool, cfg Config) (CompactionPlan, error) {
	plan := CompactionPlan{
		SessionID: sessionID,
		Rows:      len(rows),
		Before:    existing,
		HadStats:  hasStats,
		Removed:   map[Counter]int64{},
	}
	if !hasStats {
		plan.Before = Stats{}
	}
	byKey := make(map[string]StoredRun, len(rows))
	facts := make([]RunFacts, 0, len(rows))
	for _, r := range rows {
		byKey[r.Facts.ProcessKey] = r
		facts = append(facts, r.Facts)
	}
	res := Replay(facts, cfg)

	removed := make(map[string]bool)
	var delta Stats
	var folds []string
	acc := NewAccumulator()
	for _, o := range res.Outcomes {
		sr, ok := byKey[o.Facts.ProcessKey]
		if !ok {
			continue
		}
		var prev Counter
		if hasStats && sr.Class != "" {
			prev = counterForClass(sr.Class)
		}
		var next Counter
		switch {
		case !o.Decision.Action.Persists() && sr.Class == "":
			f := sr.Facts
			if f.FindingsFired > 0 || f.Failed || f.SideEffects || f.ActionID > 0 {
				return CompactionPlan{}, fmt.Errorf("%w: %s (%s, rule %s)", ErrCompactionUnsafe, f.ProcessKey, f.ExeBasename, o.Decision.Rule)
			}
			next = o.Decision.Counter
			plan.Delete = append(plan.Delete, sr.ID)
			plan.Removed[next]++
			removed[sr.Facts.ProcessKey] = true
			if o.Decision.BudgetHit {
				delta.BudgetHits++
			}
			if o.Decision.Action == ActionFold || o.Decision.Action == ActionRollup {
				acc.AddRollup(o.Decision.Group, f)
			}
			if o.Decision.Action == ActionFold && o.Decision.FoldAnchor != "" {
				folds = append(folds, o.Decision.FoldAnchor)
			}
		case sr.Class != "":
			next = counterForClass(sr.Class)
		default:
			next = o.Decision.Counter
			if o.Decision.Class != "" {
				root := ""
				if o.Decision.Class == ClassServiceRoot || o.Decision.Class == ClassService {
					root = o.Facts.ServiceRootKey
				}
				plan.Updates = append(plan.Updates, ClassUpdate{ID: sr.ID, Class: o.Decision.Class, ServiceRootKey: root})
			}
		}
		if prev == "" {
			delta.Observed++
		} else {
			delta.bump(prev, -1)
		}
		delta.bump(next, 1)
	}
	for _, anchor := range folds {
		if _, stored := byKey[anchor]; stored && !removed[anchor] {
			if plan.Folds == nil {
				plan.Folds = map[string]int64{}
			}
			plan.Folds[anchor]++
		}
	}
	plan.Rollups = acc.Delta().Rollups
	plan.StatsDelta = delta
	plan.After = plan.Before
	plan.After.Add(delta)
	return plan, nil
}
