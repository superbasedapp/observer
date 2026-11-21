package proccapture

import (
	"sort"
	"time"
)

// Rollup is one accumulated rollup group (a process_rollups row, or the
// increment an upsert adds to one).
type Rollup struct {
	Key GroupKey
	// ActionID is the tool call the group's runs belong to, when known (0 =
	// none). Not part of the key: the parent and service root already scope
	// the group.
	ActionID int64
	// Count, FailedCount: how many runs, and how many of them failed.
	Count       int64
	FailedCount int64
	// DurationSumMs / DurationMaxMs / CPUSumMs / PeakRSSBytes are the
	// resource totals of the group's runs.
	DurationSumMs int64
	DurationMaxMs int64
	CPUSumMs      int64
	PeakRSSBytes  int64
	// FirstSeen / LastSeen bound the group's run start times.
	FirstSeen time.Time
	LastSeen  time.Time
	// ExampleArgvPreview / ExampleProcessKey are one (the first) member, so a
	// reader can see what the group is.
	ExampleArgvPreview string
	ExampleProcessKey  string
}

// add folds one run into the group.
func (r *Rollup) add(f RunFacts) {
	r.Count++
	if f.Failed {
		r.FailedCount++
	}
	r.DurationSumMs += f.DurationMs
	r.DurationMaxMs = max(r.DurationMaxMs, f.DurationMs)
	r.CPUSumMs += f.CPUMs
	r.PeakRSSBytes = max(r.PeakRSSBytes, f.PeakRSSBytes)
	t := f.Time
	if r.FirstSeen.IsZero() || (!t.IsZero() && t.Before(r.FirstSeen)) {
		r.FirstSeen = t
	}
	if t.After(r.LastSeen) {
		r.LastSeen = t
	}
	if r.ExampleProcessKey == "" {
		r.ExampleProcessKey = f.ProcessKey
		r.ExampleArgvPreview = f.Argv
	}
	if r.ActionID == 0 {
		r.ActionID = f.ActionID
	}
}

// Merge adds other's counters into r (same key). It is what the store's
// upsert does in SQL, spelled once in Go for the replay and the tests.
func (r *Rollup) Merge(o Rollup) {
	r.Count += o.Count
	r.FailedCount += o.FailedCount
	r.DurationSumMs += o.DurationSumMs
	r.DurationMaxMs = max(r.DurationMaxMs, o.DurationMaxMs)
	r.CPUSumMs += o.CPUSumMs
	r.PeakRSSBytes = max(r.PeakRSSBytes, o.PeakRSSBytes)
	if r.FirstSeen.IsZero() || (!o.FirstSeen.IsZero() && o.FirstSeen.Before(r.FirstSeen)) {
		r.FirstSeen = o.FirstSeen
	}
	if o.LastSeen.After(r.LastSeen) {
		r.LastSeen = o.LastSeen
	}
	if r.ExampleProcessKey == "" {
		r.ExampleProcessKey, r.ExampleArgvPreview = o.ExampleProcessKey, o.ExampleArgvPreview
	}
	if r.ActionID == 0 {
		r.ActionID = o.ActionID
	}
}

// Stats is one session's capture counters (a process_capture_stats row, or
// the increment an upsert adds to one). Counters may be negative in an
// increment: a run detached after it was kept moves from Kept to ServiceKept.
type Stats struct {
	Observed        int64
	Kept            int64
	Folded          int64
	RolledUp        int64
	ServiceKept     int64
	ServiceRolledUp int64
	Dropped         int64
	BudgetHits      int64
}

// Add adds o into s.
func (s *Stats) Add(o Stats) {
	s.Observed += o.Observed
	s.Kept += o.Kept
	s.Folded += o.Folded
	s.RolledUp += o.RolledUp
	s.ServiceKept += o.ServiceKept
	s.ServiceRolledUp += o.ServiceRolledUp
	s.Dropped += o.Dropped
	s.BudgetHits += o.BudgetHits
}

// Accounted is the right-hand side of the count invariant.
func (s Stats) Accounted() int64 {
	return s.Kept + s.Folded + s.RolledUp + s.ServiceKept + s.ServiceRolledUp + s.Dropped
}

// bump adds n to one counter.
func (s *Stats) bump(c Counter, n int64) {
	switch c {
	case CounterKept:
		s.Kept += n
	case CounterFolded:
		s.Folded += n
	case CounterRolledUp:
		s.RolledUp += n
	case CounterServiceKept:
		s.ServiceKept += n
	case CounterServiceRolledUp:
		s.ServiceRolledUp += n
	case CounterDropped:
		s.Dropped += n
	}
}

// Delta is what one flush writes beside its process_runs rows: rollup
// increments, per-session stats increments ("" = the machine), and fold
// increments keyed by the anchor process key.
type Delta struct {
	Rollups []Rollup
	Stats   map[string]Stats
	Folds   map[string]int64
}

// Empty reports whether the delta writes nothing.
func (d Delta) Empty() bool { return len(d.Rollups) == 0 && len(d.Stats) == 0 && len(d.Folds) == 0 }

// Accumulator builds a Delta from final decisions. Not safe for concurrent
// use.
type Accumulator struct {
	rollups map[GroupKey]*Rollup
	order   []GroupKey
	stats   map[string]Stats
	folds   map[string]int64
}

// NewAccumulator returns an empty Accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{
		rollups: make(map[GroupKey]*Rollup),
		stats:   make(map[string]Stats),
		folds:   make(map[string]int64),
	}
}

// AddRollup adds one run to its group.
func (a *Accumulator) AddRollup(key GroupKey, f RunFacts) {
	r := a.rollups[key]
	if r == nil {
		r = &Rollup{Key: key}
		a.rollups[key] = r
		a.order = append(a.order, key)
	}
	r.add(f)
}

// Count records one final decision in the session's stats: observed + the
// decision's counter (+ a budget hit).
func (a *Accumulator) Count(session string, d Decision) {
	s := a.stats[session]
	s.Observed++
	s.bump(d.Counter, 1)
	if d.BudgetHit {
		s.BudgetHits++
	}
	a.stats[session] = s
}

// Move re-counts one already-counted run from one counter to another (a kept
// run that later became a service root). Observed is unchanged.
func (a *Accumulator) Move(session string, from, to Counter) {
	s := a.stats[session]
	s.bump(from, -1)
	s.bump(to, 1)
	a.stats[session] = s
}

// Fold increments the fold count of the anchor row.
func (a *Accumulator) Fold(anchorKey string) {
	if anchorKey != "" {
		a.folds[anchorKey]++
	}
}

// Record applies one final decision: the stats count, the rollup for
// fold/rollup, and the fold count for fold.
func (a *Accumulator) Record(f RunFacts, d Decision) {
	a.Count(f.SessionID, d)
	switch d.Action {
	case ActionFold:
		a.AddRollup(d.Group, f)
		a.Fold(d.FoldAnchor)
	case ActionRollup:
		a.AddRollup(d.Group, f)
	}
}

// Delta returns the accumulated delta, rollups in first-seen order.
func (a *Accumulator) Delta() Delta {
	d := Delta{}
	for _, k := range a.order {
		d.Rollups = append(d.Rollups, *a.rollups[k])
	}
	if len(a.stats) > 0 {
		d.Stats = make(map[string]Stats, len(a.stats))
		for k, v := range a.stats {
			d.Stats[k] = v
		}
	}
	if len(a.folds) > 0 {
		d.Folds = make(map[string]int64, len(a.folds))
		for k, v := range a.folds {
			d.Folds[k] = v
		}
	}
	return d
}

// SortRollupsByCount orders rollups by count descending, then by key, the
// order the summary read shows them in.
func SortRollupsByCount(rs []Rollup) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Count != rs[j].Count {
			return rs[i].Count > rs[j].Count
		}
		return rs[i].Key.ExeBasename < rs[j].Key.ExeBasename
	})
}
