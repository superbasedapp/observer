package orgclient

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

type pushCall struct {
	at        time.Duration
	rails     bool
	railsOnly bool
}

// TestRunPushLoopSchedule drives the activity-driven push loop with a fake
// cycle on a fake clock. One case per behaviour: the immediate first rail
// cycle, idle ceiling, the floor, coalescing, the backlog re-kick, the
// server hint, and a failed first rail cycle retried on the backoff.
func TestRunPushLoopSchedule(t *testing.T) {
	type kick struct{ at time.Duration }
	tests := []struct {
		name      string
		kicks     []kick
		wakes     []kick
		results   []PushResult
		errs      []error
		serverMin time.Duration
		cycles    int
		want      []pushCall
	}{
		{
			name:   "first cycle immediate with rails, then the idle ceiling",
			cycles: 3,
			want:   []pushCall{{0, true, false}, {120 * time.Second, true, false}, {240 * time.Second, true, false}},
		},
		{
			name:   "activity right after a push waits for the 15 s floor and is light",
			kicks:  []kick{{time.Second}},
			cycles: 2,
			want:   []pushCall{{0, true, false}, {15 * time.Second, false, false}},
		},
		{
			name:   "a burst coalesces into one push 3 s after the last turn",
			kicks:  []kick{{30 * time.Second}, {31 * time.Second}, {32 * time.Second}},
			cycles: 3,
			// The light push does not move the ceiling: the next rail
			// cycle is still 120 s after the last rail cycle.
			want: []pushCall{{0, true, false}, {35 * time.Second, false, false}, {120 * time.Second, true, false}},
		},
		{
			name:    "a full batch pushes again after 1 s",
			results: []PushResult{{More: true}, {}},
			cycles:  3,
			want:    []pushCall{{0, true, false}, {time.Second, false, false}, {120 * time.Second, true, false}},
		},
		{
			name:      "the server hint raises the floor",
			kicks:     []kick{{time.Second}},
			serverMin: 40 * time.Second,
			cycles:    2,
			want:      []pushCall{{0, true, false}, {40 * time.Second, false, false}},
		},
		{
			// Sol A5-06: an hour of org backpressure after the first push
			// does not delay the 120 s ceiling. Each ceiling cycle refreshes
			// the rails on time without uploading; the pending activity waits
			// for the backpressure window.
			name:      "server backpressure never delays the ceiling; inside it the ceiling is rail-only",
			kicks:     []kick{{100 * time.Second}},
			serverMin: time.Hour,
			cycles:    4,
			want: []pushCall{
				{0, true, false}, {120 * time.Second, true, true}, {240 * time.Second, true, true}, {360 * time.Second, true, true},
			},
		},
		{
			// `observer org push-now` against a running daemon: the
			// operator's wake runs a cycle at once, past the oversized-batch
			// circuit's hour-long pause (round 3 bug 2).
			name:   "an operator wake runs a cycle at once past the oversized-batch pause",
			errs:   []error{ErrBatchTooLarge, nil},
			wakes:  []kick{{10 * time.Second}},
			cycles: 2,
			want:   []pushCall{{0, true, false}, {10 * time.Second, true, false}},
		},
		{
			name:   "an operator wake on an idle loop runs a cycle at once, not at the ceiling",
			wakes:  []kick{{50 * time.Second}},
			cycles: 2,
			want:   []pushCall{{0, true, false}, {50 * time.Second, true, false}},
		},
		{
			name:   "a failed first rail cycle is retried as a rail cycle on the backoff",
			errs:   []error{errors.New("org down"), nil},
			cycles: 2,
			want:   []pushCall{{0, true, false}, {250 * time.Millisecond, true, false}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := New(config.OrgClientConfig{PushIntervalSeconds: 120}, nil, &memBearerStore{}, "v", http.DefaultClient, quietLogger())
				c.serverPushMin.Store(int64(tc.serverMin))
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				start := time.Now()
				for _, k := range tc.kicks {
					go func(d time.Duration) {
						time.Sleep(d)
						c.NotePushActivity()
					}(k.at)
				}
				for _, k := range tc.wakes {
					go func(d time.Duration) {
						time.Sleep(d)
						c.WakePushLoop()
					}(k.at)
				}
				var got []pushCall
				cycle := func(_ context.Context, kind cycleKind) (PushResult, error) {
					i := len(got)
					got = append(got, pushCall{time.Since(start), kind.rails, kind.railsOnly})
					if len(got) == tc.cycles {
						cancel()
					}
					var res PushResult
					if i < len(tc.results) {
						res = tc.results[i]
					}
					var err error
					if i < len(tc.errs) {
						err = tc.errs[i]
					}
					return res, err
				}
				if err := c.runPushLoop(ctx, cycle); !errors.Is(err, context.Canceled) {
					t.Fatalf("runPushLoop = %v, want context.Canceled", err)
				}
				if len(got) != len(tc.want) {
					t.Fatalf("cycles = %+v, want %+v", got, tc.want)
				}
				for i := range got {
					w := tc.want[i]
					// The backoff is jittered +-25%; everything else is exact.
					if w.at == 250*time.Millisecond {
						assertWithin(t, "backoff gap", got[i].at, w.at)
					} else if got[i].at != w.at {
						t.Fatalf("cycle %d at %v, want %v (all: %+v)", i, got[i].at, w.at, got)
					}
					if got[i].rails != w.rails || got[i].railsOnly != w.railsOnly {
						t.Fatalf("cycle %d rails=%v railsOnly=%v, want %v/%v (all: %+v)",
							i, got[i].rails, got[i].railsOnly, w.rails, w.railsOnly, got)
					}
				}
			})
		})
	}
}

// TestNotePushMinInterval pins the hint parser: whole seconds, clamped to an
// hour, and an absent or bad header clears the hint.
func TestNotePushMinInterval(t *testing.T) {
	c := New(config.OrgClientConfig{}, nil, &memBearerStore{}, "v", http.DefaultClient, quietLogger())
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"30", 30 * time.Second},
		{" 45 ", 45 * time.Second},
		{"", 0},
		{"soon", 0},
		{"-5", 0},
		{"99999", time.Hour},
	} {
		c.serverPushMin.Store(int64(7 * time.Second))
		resp := &http.Response{Header: http.Header{}}
		if tc.header != "" {
			resp.Header.Set(orgcontract.HeaderPushMinInterval, tc.header)
		}
		c.notePushMinInterval(resp)
		if got := time.Duration(c.serverPushMin.Load()); got != tc.want {
			t.Errorf("header %q -> %v, want %v", tc.header, got, tc.want)
		}
	}
	c.notePushMinInterval(nil)
	if c.serverPushMin.Load() != 0 {
		t.Error("nil response did not clear the hint")
	}
}
