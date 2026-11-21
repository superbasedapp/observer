package cloudagentssvc

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TickInterval is how often the loop checks which accounts are due.
const TickInterval = time.Minute

// StartDelay keeps the first automatic sync off the daemon's start path.
const StartDelay = 30 * time.Second

// backoffRule is one row of the automatic-retry table: after a failure of
// class, wait base doubled per consecutive failure, at most max. Walked
// top-down; class "" matches every class.
type backoffRule struct {
	class cloudagents.ErrorClass
	base  time.Duration
	max   time.Duration
}

var backoffRules = []backoffRule{
	// A missing CLI or login needs the user; retry rarely.
	{cloudagents.ErrNotInstalled, 6 * time.Hour, 24 * time.Hour},
	{cloudagents.ErrNotSignedIn, 6 * time.Hour, 24 * time.Hour},
	{cloudagents.ErrPermissionDenied, 6 * time.Hour, 24 * time.Hour},
	{cloudagents.ErrRateLimited, time.Hour, 6 * time.Hour},
	{"", 15 * time.Minute, 6 * time.Hour},
}

// BackoffFor returns the wait after the n-th consecutive failure of class.
func BackoffFor(class cloudagents.ErrorClass, n int) time.Duration {
	for _, r := range backoffRules {
		if r.class != "" && r.class != class {
			continue
		}
		d := r.base
		for i := 1; i < n && d < r.max; i++ {
			d *= 2
		}
		if d > r.max {
			d = r.max
		}
		return d
	}
	return time.Hour
}

func (s *Service) recordFailure(id int64, class cloudagents.ErrorClass, now time.Time) {
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()
	s.failures[id]++
	s.backoff[id] = now.Add(BackoffFor(class, s.failures[id]))
}

func (s *Service) clearBackoff(id int64) {
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()
	delete(s.failures, id)
	delete(s.backoff, id)
}

func (s *Service) backedOff(id int64, now time.Time) bool {
	s.backoffMu.Lock()
	defer s.backoffMu.Unlock()
	return now.Before(s.backoff[id])
}

// SyncDue syncs every linked account whose connector interval has passed
// since its last attempt and that is not backing off. With no linked
// account it makes no vendor call.
func (s *Service) SyncDue(ctx context.Context) []SyncResult {
	accts, err := s.st.ListCloudConnectorAccounts(ctx, "")
	if err != nil || len(accts) == 0 {
		return nil
	}
	now := s.now()
	var out []SyncResult
	for _, a := range accts {
		c, ok := cloudagents.ConnectorByID(a.Connector)
		if !ok || s.backedOff(a.ID, now) {
			continue
		}
		cp, found, err := s.st.LoadCloudSyncCheckpoint(ctx, a.ID, models.SyncStreamDiscovery, "")
		if err != nil {
			continue
		}
		if found && !cp.LastAttemptAt.IsZero() && now.Sub(cp.LastAttemptAt) < c.Interval {
			continue
		}
		r, _ := s.SyncAccount(ctx, a.ID)
		out = append(out, r)
		if ctx.Err() != nil {
			break
		}
	}
	return out
}

// Run is the daemon loop: after StartDelay it checks every TickInterval
// for due accounts until ctx ends. Fail-soft: errors are recorded on the
// account, never returned.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTimer(StartDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.SyncDue(ctx)
		t.Reset(TickInterval)
	}
}
