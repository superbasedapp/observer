//go:build !sbo_omit_security

package seccustomsvc

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// ScheduleInput is one scheduled pass: the [security.custom] settings, the
// power state read at the boundary, and the projects to scan.
type ScheduleInput struct {
	Every          time.Duration
	PauseOnBattery bool
	// Power is "ac", "battery" or "unknown" (internal/powerstate).
	Power    string
	Projects []string
}

// ScheduleReport is what one pass did.
type ScheduleReport struct {
	Ran    int `json:"ran"`
	Failed int `json:"failed"`
	// Held counts the driver and project pairs that did not run, by the
	// schedule table's reason.
	Held map[string]int `json:"held,omitempty"`
}

// LastRunReader is the optional store half that keeps the schedule's last
// run per driver and project across a daemon restart: the newest recorded
// scan run of that driver over that project with that scope. A FindingStore
// that does not implement it leaves the schedule in memory only (every pair
// is due once after a restart).
type LastRunReader interface {
	SecLastDriverRun(ctx context.Context, rootHash, driver string, scope secfinding.Scope) (time.Time, error)
}

// The daemon's store keeps the schedule across restarts.
var _ LastRunReader = (*store.Store)(nil)

// lastScheduled returns the pair's last scheduled run: the one this process
// recorded, else the newest scheduled scan run the store holds (read once
// per pair and kept). A store read that fails reads as never run, so the
// pair is due, as it was before this was kept.
func (s *Service) lastScheduled(ctx context.Context, key, driver, proj string) time.Time {
	s.schedMu.Lock()
	last, known := s.lastSched[key]
	s.schedMu.Unlock()
	if known {
		return last
	}
	r, ok := s.o.Store.(LastRunReader)
	if !ok {
		return time.Time{}
	}
	t, err := r.SecLastDriverRun(ctx, secposture.ProjectRootHash(proj), driver, policy.FindingScopeScheduled)
	if err != nil {
		return time.Time{}
	}
	s.schedMu.Lock()
	if s.lastSched == nil {
		s.lastSched = map[string]time.Time{}
	}
	if _, raced := s.lastSched[key]; !raced {
		s.lastSched[key] = t
	}
	last = s.lastSched[key]
	s.schedMu.Unlock()
	return last
}

// scheduledErrorMax caps the error sentence a failed scheduled run keeps.
const scheduledErrorMax = 240

// scheduledFailure is the coverage of a scheduled run that failed before
// it recorded a scan run of its own.
type scheduledFailure struct {
	Outcome secscan.Outcome `json:"outcome"`
	Reason  string          `json:"reason"`
	Error   string          `json:"error"`
}

// recordScheduledFailure records a scan run for a scheduled run that failed
// before Run recorded one (the record no longer loads, a refused path, the
// runner not wired, a store write that failed), so the pair keeps its
// last-run time across a daemon restart and the failure is visible with
// its error. Run inserts its scan run last, so an error from Run means no
// row was written for this run. The error is one sentence, clipped and
// stripped of control characters; sec_scan_runs is node-local. The reason
// store.SecRunReasonNotRun marks the row as a run that never executed, so
// the last-scan time, the scanner notes and the org posture's freshness
// and outcome counts leave it out.
func (s *Service) recordScheduledFailure(ctx context.Context, rec seccustom.Record, proj string, started time.Time, runErr error) {
	if s.o.Store == nil || runErr == nil {
		return
	}
	_ = s.o.Store.InsertSecScanRun(ctx, store.SecScanRun{
		ProjectRootHash: secposture.ProjectRootHash(proj), Driver: rec.Driver(), Scope: policy.FindingScopeScheduled,
		Coverage: scheduledFailure{Outcome: secscan.OutcomeFailed, Reason: store.SecRunReasonNotRun, Error: secfinding.Clip(runErr.Error(), scheduledErrorMax)},
		Outcome:  string(secscan.OutcomeFailed), StartedAt: started, Duration: s.o.Now().Sub(started),
	})
}

// RunScheduled runs every accepted scanner over every project that the
// schedule table says is due (seccustom.DecideSchedule), one run at a time,
// with scope scheduled. A record that does not load (unaudited, edited by
// hand) is skipped: Records already raised its finding. A run that fails
// still counts as this pair's run, so a broken scanner is retried at the
// next interval, never in a tight loop; one that failed before it recorded
// a scan run gets a failed scan run with its error, so that holds across a
// daemon restart too.
func (s *Service) RunScheduled(ctx context.Context, in ScheduleInput) ScheduleReport {
	rep := ScheduleReport{Held: map[string]int{}}
	if in.Every <= 0 {
		rep.Held[seccustom.ScheduleOff]++
		return rep
	}
	recs, _ := s.Records(ctx)
	for _, rec := range recs {
		for _, proj := range in.Projects {
			if ctx.Err() != nil {
				return rep
			}
			key := rec.ID + "\x00" + proj
			last := s.lastScheduled(ctx, key, rec.Driver(), proj)
			d := seccustom.DecideSchedule(seccustom.ScheduleFacts{
				Every: in.Every, PauseOnBattery: in.PauseOnBattery, Power: in.Power, LastRun: last, Now: s.o.Now(),
			})
			if !d.Run {
				rep.Held[d.Reason]++
				continue
			}
			s.schedMu.Lock()
			if s.lastSched == nil {
				s.lastSched = map[string]time.Time{}
			}
			s.lastSched[key] = s.o.Now()
			s.schedMu.Unlock()
			started := s.o.Now()
			if _, err := s.Run(ctx, rec.ID, proj, policy.FindingScopeScheduled); err != nil {
				rep.Failed++
				s.recordScheduledFailure(ctx, rec, proj, started, err)
				continue
			}
			rep.Ran++
		}
	}
	return rep
}
