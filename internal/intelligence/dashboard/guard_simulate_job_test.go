package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Demo bug #14: identical simulate requests share one run, a progress poll
// answers 202 with counts while the run works and the run's answer once it
// is done, and a finished answer serves a repeat request at once.

// TestGuardSimulate_IdenticalRequestsShareOneRun holds the evaluation slot so
// the run queues, sends two identical plain requests and a progress poll, and
// checks one run served all three with one answer.
func TestGuardSimulate_IdenticalRequestsShareOneRun(t *testing.T) {
	s, _, _ := newGuardRecipeServer(t)
	release, err := acquireGuardSimulateSlot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const url = "/api/guard/simulate?hours=24&recipe=1&level=strict&scope=global"
	before := simulateRunsStarted.Load()

	var wg sync.WaitGroup
	bodies := make([]string, 2)
	codes := make([]int, 2)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, url, nil))
			codes[i], bodies[i] = rr.Code, rr.Body.String()
		}(i)
	}
	// While the slot is held the run reports itself queued.
	deadline := time.Now().Add(5 * time.Second)
	var prog simulateProgress
	for {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, url+"&progress=1", nil))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("progress while queued: %d %s", rr.Code, rr.Body.String())
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &prog); err != nil {
			t.Fatal(err)
		}
		if prog.Queued || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !prog.Running || !prog.Queued {
		t.Fatalf("a run waiting for the slot reports running+queued: %+v", prog)
	}
	release()
	wg.Wait()

	if got := simulateRunsStarted.Load() - before; got != 1 {
		t.Fatalf("two identical requests and a poll started %d runs, want 1", got)
	}
	for i := range codes {
		if codes[i] != http.StatusOK {
			t.Fatalf("request %d: %d %s", i, codes[i], bodies[i])
		}
	}
	if bodies[0] != bodies[1] {
		t.Fatalf("the two requests read different answers:\n%s\n%s", bodies[0], bodies[1])
	}
	var resp struct {
		Scanned      *int            `json:"scanned"`
		ComputedAt   string          `json:"computed_at"`
		RecipeReplay json.RawMessage `json:"recipe_replay"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &resp); err != nil || resp.Scanned == nil || resp.ComputedAt == "" || len(resp.RecipeReplay) == 0 {
		t.Fatalf("answer shape: %v %s", err, bodies[0])
	}

	// A finished run answers a poll and a repeat request at once, starting
	// nothing new.
	for _, u := range []string{url + "&progress=1", url} {
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, u, nil))
		if rr.Code != http.StatusOK || rr.Body.String() != bodies[0] {
			t.Fatalf("%s after the run: %d %s", u, rr.Code, rr.Body.String())
		}
	}
	if got := simulateRunsStarted.Load() - before; got != 1 {
		t.Fatalf("a repeat request started a run: %d", got)
	}

	// A different query is a different run.
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/guard/simulate?hours=25", nil))
	if rr.Code != http.StatusOK || simulateRunsStarted.Load()-before != 2 {
		t.Fatalf("a different query: %d, runs %d", rr.Code, simulateRunsStarted.Load()-before)
	}
}

// TestSimulateRunAbandonment is the abandonment table: a run stops only when
// no request waits on it and no poll is recent, and a stopped run leaves the
// registry so the next identical request starts afresh.
func TestSimulateRunAbandonment(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		waiters  int
		lastPoll time.Time
		finished bool
		wantStop bool
	}{
		{"a waiting request keeps it", 1, time.Time{}, false, false},
		{"a recent poll keeps it", 0, now.Add(-simulateAbandonAfter / 2), false, false},
		{"a stale poll stops it", 0, now.Add(-2 * simulateAbandonAfter), false, true},
		{"no waiter and never polled stops it", 0, time.Time{}, false, true},
		{"a finished run is never stopped", 0, time.Time{}, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := &simulateRunRegistry{runs: map[string]*simulateRun{}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			run := &simulateRun{key: "k", cancel: cancel, done: make(chan struct{}), waiters: c.waiters, lastPoll: c.lastPoll}
			if c.finished {
				close(run.done)
			}
			reg.runs["k"] = run
			reg.sweep(run, now)
			stopped := ctx.Err() != nil
			if stopped != c.wantStop {
				t.Fatalf("stopped = %v, want %v", stopped, c.wantStop)
			}
			if _, kept := reg.runs["k"]; kept == c.wantStop {
				t.Fatalf("registry kept = %v after stop = %v", kept, c.wantStop)
			}
		})
	}
}
