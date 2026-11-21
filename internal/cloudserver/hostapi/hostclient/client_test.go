package hostclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// tickers hands Run one channel per interval, so the test decides when each
// loop passes (no sleeps).
type tickers struct {
	byEvery map[time.Duration]chan time.Time
	started chan time.Duration
}

func (tk *tickers) newTicker(d time.Duration) (<-chan time.Time, func()) {
	tk.started <- d
	return tk.byEvery[d], func() {}
}

// TestClientRunDrivesBothLoops: a dispatch tick sends the outbox, a
// reconcile tick reconciles, and Run returns once the context ends.
func TestClientRunDrivesBothLoops(t *testing.T) {
	t.Parallel()
	ms := newMemStore()
	ms.addOrg(store.OrgReconcileView{OrgID: orgA, DisplayName: "A", Status: "active", LifecycleGen: 1, HostID: "host-1"})
	in := must(t)(hostapi.EvictIntent(orgA, 1))
	ms.enqueue(in)
	sent := make(chan hostapi.Request, 4)
	tr := &scripted{answer: func(_ hostclient.Host, r hostapi.Request) hostapi.Answer {
		sent <- r
		if r.Path == pc.PathRouteCheck {
			return answerJSON(t, pc.RouteCheckResponse{Served: true, State: pc.StateActive, LifecycleGen: 1})
		}
		if r.Path == pc.PathTenantHealth(orgA) {
			return answerJSON(t, pc.HealthResponse{
				TenantID: orgA, Status: pc.HealthHealthy, LastPush: pc.PushRecent,
				Backlog: pc.BacklogClear, Quota: pc.QuotaOK, Error: pc.ErrNone,
			})
		}
		return answerJSON(t, pc.EvictResponse{Evicted: true})
	}}
	disp := newDispatcher(t, ms, tr, resolver{})
	rec := newReconciler(t, ms, tr, 0)
	tk := &tickers{
		byEvery: map[time.Duration]chan time.Time{time.Second: make(chan time.Time), time.Minute: make(chan time.Time)},
		started: make(chan time.Duration, 2),
	}
	c, err := hostclient.New(hostclient.Config{
		Dispatcher: disp, Reconciler: rec, DispatchEvery: time.Second, ReconcileEvery: time.Minute,
		NewTicker: tk.newTicker, OnError: func(err error) { t.Errorf("pass error: %v", err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	<-tk.started
	<-tk.started

	tk.byEvery[time.Second] <- testNow
	if r := <-sent; r.Path != pc.PathTenantEvict(orgA) {
		t.Fatalf("dispatch tick sent %s", r.Path)
	}
	// A second dispatch tick is received only once the first pass returned
	// (the channel is unbuffered), so the row is acked before reconciling;
	// that pass claims nothing and sends nothing.
	tk.byEvery[time.Second] <- testNow
	tk.byEvery[time.Minute] <- testNow
	if r := <-sent; r.Path != pc.PathRouteCheck {
		t.Fatalf("reconcile tick sent %s first, want route-check", r.Path)
	}
	if r := <-sent; r.Path != pc.PathTenantHealth(orgA) {
		t.Fatalf("reconcile tick sent %s second, want health", r.Path)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
	if _, err := hostclient.New(hostclient.Config{}); err == nil {
		t.Fatal("New accepted an empty config")
	}
}
