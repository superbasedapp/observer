package workspace

import (
	"sort"
	"time"
)

// copysweep.go chooses which managed copies the daemon's age sweep checks in
// one pass (decision SBXD-2, `[terminal.sandbox].returned_copy_retention_days`).
// The sweep never decides a removal itself: every copy it picks is handed to
// the same removal table a click walks (DecideCopyRemoval, its facts read
// again for that copy), so age only ever removes what a click would. This
// file is the pick: an ordered table of reasons to leave a copy for a later
// pass, walked top-down per copy, then the oldest first, capped at one batch
// (the archival invariant: one capped batch per pass, never a loop until
// done).

// CopySweepCandidate is one managed copy as the sweep sees it, from files
// the host wrote (the copy's meta.json and its return record).
type CopySweepCandidate struct {
	ID string
	// Since is when the copy's work came home (its return's end), else when
	// the copy was made; zero when neither is known.
	Since time.Time
	// Return is one of the CopyReturn* states (CopyReturnUnknown with no
	// record: a container or microVM copy, matched by its returned ref when
	// it is checked).
	Return string
	// RunLive: the run still has its relay record.
	RunLive bool
	// KeptAt is when this process last checked the copy and the removal
	// table kept it (zero for never).
	KeptAt time.Time
}

// CopySweepPolicy is one pass's bounds.
type CopySweepPolicy struct {
	// MinAge is returned_copy_retention_days as a duration; a copy younger
	// than it is left.
	MinAge time.Duration
	// Recheck is how long a copy the table kept is left before it is
	// checked again (so a copy that holds work never starves the batch).
	Recheck time.Duration
	// Max caps the copies checked in one pass.
	Max int
}

// copySweepSkipRule is one row: a copy that matches is left for a later
// pass, for the named reason.
type copySweepSkipRule struct {
	name  string
	match func(c CopySweepCandidate, p CopySweepPolicy, now time.Time) bool
}

// copySweepSkipRules are walked top-down; a copy no row matches is checked.
var copySweepSkipRules = []copySweepSkipRule{
	{"live", func(c CopySweepCandidate, _ CopySweepPolicy, _ time.Time) bool { return c.RunLive }},
	{"undated", func(c CopySweepCandidate, _ CopySweepPolicy, _ time.Time) bool { return c.Since.IsZero() }},
	{"young", func(c CopySweepCandidate, p CopySweepPolicy, now time.Time) bool { return now.Sub(c.Since) < p.MinAge }},
	// The removal table keeps these whatever the copy holds; checking them
	// would only read the copy for nothing.
	{"not_returned", func(c CopySweepCandidate, _ CopySweepPolicy, _ time.Time) bool {
		return c.Return == CopyReturnPending || c.Return == CopyReturnRefused
	}},
	{"kept_recently", func(c CopySweepCandidate, p CopySweepPolicy, now time.Time) bool {
		return !c.KeptAt.IsZero() && now.Sub(c.KeptAt) < p.Recheck
	}},
}

// CopySweepSkip names the first row that leaves c for a later pass ("" when
// c is checked now).
func CopySweepSkip(c CopySweepCandidate, p CopySweepPolicy, now time.Time) string {
	for _, r := range copySweepSkipRules {
		if r.match(c, p, now) {
			return r.name
		}
	}
	return ""
}

// PlanCopySweep returns the ids one pass checks, oldest first, at most
// p.Max of them, and how many were due in all (due - len(check) are left to
// the next pass). A policy with no MinAge or no Max checks nothing: the
// sweep is off.
func PlanCopySweep(cands []CopySweepCandidate, p CopySweepPolicy, now time.Time) (check []string, due int) {
	if p.MinAge <= 0 || p.Max <= 0 {
		return nil, 0
	}
	var picked []CopySweepCandidate
	for _, c := range cands {
		if CopySweepSkip(c, p, now) == "" {
			picked = append(picked, c)
		}
	}
	sort.SliceStable(picked, func(i, j int) bool {
		if !picked[i].Since.Equal(picked[j].Since) {
			return picked[i].Since.Before(picked[j].Since)
		}
		return picked[i].ID < picked[j].ID
	})
	for _, c := range picked[:min(len(picked), p.Max)] {
		check = append(check, c.ID)
	}
	return check, len(picked)
}
