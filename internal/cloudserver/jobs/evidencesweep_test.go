package jobs_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// fakeEvidenceSweeps records every SweepExpiredEvidence call and answers from
// a script of errors (nil once the script runs out).
type fakeEvidenceSweeps struct {
	mu    sync.Mutex
	calls []time.Time
	errs  []error
}

func (f *fakeEvidenceSweeps) SweepExpiredEvidence(_ context.Context, now time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, now)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return 0, err
	}
	return 1, nil
}

func (f *fakeEvidenceSweeps) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// lockedBuffer is a log sink safe to read while the sweeper goroutine writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestEvidenceSweeperSweepsAtStartAndEachIntervalAndStopsOnCancel pins the
// CLOUD-01 loop: one sweep at start, one per interval, and the loop returns
// when the worker's context ends.
func TestEvidenceSweeperSweepsAtStartAndEachIntervalAndStopsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		f := &fakeEvidenceSweeps{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			jobs.RunEvidenceSweeper(ctx, f, jobs.EvidenceSweeperConfig{Interval: 5 * time.Minute, Logger: slog.New(slog.DiscardHandler)})
		}()

		synctest.Wait()
		if got := f.count(); got != 1 {
			t.Fatalf("sweeps at start = %d, want 1", got)
		}
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if got := f.count(); got != 2 {
			t.Fatalf("sweeps after one interval = %d, want 2", got)
		}
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if got := f.count(); got != 3 {
			t.Fatalf("sweeps after two intervals = %d, want 3", got)
		}

		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("RunEvidenceSweeper did not return after its context was canceled")
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if got := f.count(); got != 3 {
			t.Fatalf("sweeps after cancel = %d, want still 3", got)
		}
	})
}

// TestEvidenceSweeperIsFailSoft pins that a failed pass is logged and the
// loop keeps going: one database error must not end the sweeping for the life
// of the worker.
func TestEvidenceSweeperIsFailSoft(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f := &fakeEvidenceSweeps{errs: []error{errors.New("permission denied for function sbci_sweep_expired_evidence")}}
		var logs lockedBuffer
		go jobs.RunEvidenceSweeper(ctx, f, jobs.EvidenceSweeperConfig{
			Interval: time.Minute, Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		})

		synctest.Wait()
		if !strings.Contains(logs.String(), "evidence sweep failed") {
			t.Fatalf("a failed sweep must be logged; log = %q", logs.String())
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if got := f.count(); got != 2 {
			t.Fatalf("sweeps after a failed first pass = %d, want 2 (fail-soft)", got)
		}
		cancel()
		synctest.Wait()
	})
}

// TestEvidenceSweeperUsesTheConfiguredClock pins that each pass passes the
// clock's now to the store (the sweep deletes by expires_at <= now).
func TestEvidenceSweeperUsesTheConfiguredClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fixed := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
		f := &fakeEvidenceSweeps{}
		go jobs.RunEvidenceSweeper(ctx, f, jobs.EvidenceSweeperConfig{
			Interval: time.Minute, Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return fixed },
		})
		synctest.Wait()
		cancel()
		synctest.Wait()
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.calls) != 1 || !f.calls[0].Equal(fixed) {
			t.Fatalf("sweep calls = %v, want one at %v", f.calls, fixed)
		}
	})
}

// TestResolveEvidenceSweepInterval pins the SBCI_EVIDENCE_SWEEP_INTERVAL
// rules: unset is the default, a valid duration within the bounds is taken,
// and anything else refuses the worker's start (the evidence TTL is a privacy
// promise, so a typo must not silently stretch it).
func TestResolveEvidenceSweepInterval(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{name: "unset is the default", raw: "", want: jobs.DefaultEvidenceSweepInterval},
		{name: "blank is the default", raw: "   ", want: jobs.DefaultEvidenceSweepInterval},
		{name: "a valid duration", raw: "1m", want: time.Minute},
		{name: "surrounding space is trimmed", raw: " 10m ", want: 10 * time.Minute},
		{name: "the minimum", raw: jobs.MinEvidenceSweepInterval.String(), want: jobs.MinEvidenceSweepInterval},
		{name: "the maximum", raw: jobs.MaxEvidenceSweepInterval.String(), want: jobs.MaxEvidenceSweepInterval},
		{name: "not a duration", raw: "five minutes", wantErr: true},
		{name: "a bare number", raw: "300", wantErr: true},
		{name: "zero", raw: "0s", wantErr: true},
		{name: "negative", raw: "-5m", wantErr: true},
		{name: "below the minimum", raw: "1s", wantErr: true},
		{name: "above the maximum", raw: "2h", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jobs.ResolveEvidenceSweepInterval(func(name string) string {
				if name != jobs.EnvEvidenceSweepInterval {
					t.Fatalf("read unexpected variable %q", name)
				}
				return tc.raw
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveEvidenceSweepInterval(%q) = %v, want an error", tc.raw, got)
				}
				if !strings.Contains(err.Error(), jobs.EnvEvidenceSweepInterval) {
					t.Fatalf("error %q does not name %s", err, jobs.EnvEvidenceSweepInterval)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ResolveEvidenceSweepInterval(%q) = %v, %v; want %v", tc.raw, got, err, tc.want)
			}
		})
	}
	if jobs.DefaultEvidenceSweepInterval < jobs.MinEvidenceSweepInterval || jobs.DefaultEvidenceSweepInterval > jobs.MaxEvidenceSweepInterval {
		t.Fatalf("default %v is outside [%v, %v]", jobs.DefaultEvidenceSweepInterval, jobs.MinEvidenceSweepInterval, jobs.MaxEvidenceSweepInterval)
	}
}

// TestStartEvidenceSweeperRefusesABadInterval pins that a bad interval refuses
// the worker's start and sweeps nothing, and a good one starts the loop.
func TestStartEvidenceSweeperRefusesABadInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		log := slog.New(slog.DiscardHandler)

		bad := &fakeEvidenceSweeps{}
		if err := jobs.StartEvidenceSweeper(ctx, log, bad, func(string) string { return "nope" }); err == nil {
			t.Fatal("StartEvidenceSweeper accepted an unparsable interval")
		}
		synctest.Wait()
		if got := bad.count(); got != 0 {
			t.Fatalf("a refused start swept %d times, want 0", got)
		}

		good := &fakeEvidenceSweeps{}
		if err := jobs.StartEvidenceSweeper(ctx, log, good, func(string) string { return "" }); err != nil {
			t.Fatalf("StartEvidenceSweeper with the default interval: %v", err)
		}
		synctest.Wait()
		if got := good.count(); got != 1 {
			t.Fatalf("sweeps right after start = %d, want 1", got)
		}
		time.Sleep(jobs.DefaultEvidenceSweepInterval)
		synctest.Wait()
		if got := good.count(); got != 2 {
			t.Fatalf("sweeps after the default interval = %d, want 2", got)
		}
		cancel()
		synctest.Wait()
	})
}

// TestEvidenceSweptBeforeLeaseParksTheJobAndReleasesItsReservation pins the
// other half of CLOUD-01 on PostgreSQL (review part A, point 4): the sweeper
// runs as sbci_worker (0151), deletes a still-queued job's evidence at its
// expires_at, and leaves the job queued; the next lease then parks it
// evidence_expired through Gate 3's deleted-object branch (not its TTL
// branch: the lease runs at the submit instant, inside the TTL) and releases
// its reservation, so a swept job never reaches a provider and never holds a
// unit.
func TestEvidenceSweptBeforeLeaseParksTheJobAndReleasesItsReservation(t *testing.T) {
	s, pool, acct := setup(t)
	ctx := context.Background()
	t0 := time.Now()
	sub := submitWithEvidence(t, s, acct, "swept", []byte(`{"secret":"bytes"}`), t0)

	workerStore, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatalf("NewForRole(worker): %v", err)
	}
	// One pass of the real loop as the worker role, at a clock past expiry.
	sweepCtx, stop := context.WithCancel(ctx)
	passed := make(chan struct{})
	go func() {
		defer close(passed)
		jobs.RunEvidenceSweeper(sweepCtx, sweepOnce{workerStore, stop}, jobs.EvidenceSweeperConfig{
			Interval: time.Hour, Logger: slog.New(slog.DiscardHandler),
			Now: func() time.Time { return t0.Add(2 * time.Hour) },
		})
	}()
	<-passed

	var deleted bool
	var jobState string
	if err := pool.QueryRow(ctx,
		`SELECT eo.deleted_at IS NOT NULL, j.state FROM analysis_jobs j
		   JOIN evidence_objects eo ON eo.account_id = j.account_id AND eo.id = j.evidence_pk
		  WHERE j.account_id = $1::uuid AND j.id = $2::uuid`, acct, sub.JobID).Scan(&deleted, &jobState); err != nil {
		t.Fatalf("read evidence/job: %v", err)
	}
	if !deleted || jobState != "queued" {
		t.Fatalf("after the sweep: evidence deleted=%v, job state=%q; want deleted and still queued", deleted, jobState)
	}

	out, err := newWorker(s, verifiedAttestor{}).ProcessOnce(ctx, t0)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "parked" || out.Reason != store.ReasonEvidenceExpired {
		t.Fatalf("want parked/evidence_expired for swept evidence, got %+v", out)
	}
	var resState string
	if err := pool.QueryRow(ctx,
		`SELECT state FROM usage_reservations WHERE account_id = $1::uuid AND id = $2::uuid`,
		acct, sub.ReservationID).Scan(&resState); err != nil {
		t.Fatalf("read reservation: %v", err)
	}
	if resState != "released" {
		t.Fatalf("reservation of the parked job = %q, want released", resState)
	}
}

// sweepOnce runs the real store sweep and then ends the loop, so a test can
// drive exactly one pass of RunEvidenceSweeper without a ticker race.
type sweepOnce struct {
	s    *store.Store
	stop context.CancelFunc
}

func (o sweepOnce) SweepExpiredEvidence(ctx context.Context, now time.Time) (int, error) {
	defer o.stop()
	return o.s.SweepExpiredEvidence(ctx, now)
}
