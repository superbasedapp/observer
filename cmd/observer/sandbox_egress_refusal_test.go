//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_egress_refusal_test.go pins lane N1's helper hand-off with a fake
// channel: the helper's reporter bounds and sends, the daemon's receiver
// validates, bounds and writes through the store seam.

// fakeRefusalStore records what the receiver writes.
type fakeRefusalStore struct {
	mu     sync.Mutex
	rows   []store.SandboxEgressRefusal
	pruned int
	// drops are the dropped counts written, by run, and uncertain the
	// counts that may be the run's.
	drops     map[string]int
	uncertain map[string]int
	// linkLost and closed are the link-loss counts written (F-012).
	linkLost map[string]int
	closed   map[string]int
}

func (f *fakeRefusalStore) InsertSandboxEgressRefusal(_ context.Context, r store.SandboxEgressRefusal) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, r)
	return true, nil
}

func (f *fakeRefusalStore) AddSandboxEgressRefusalDrops(_ context.Context, runID string, n, uncertain int, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.drops == nil {
		f.drops, f.uncertain = map[string]int{}, map[string]int{}
	}
	if n > 0 {
		f.drops[runID] += n
	}
	if uncertain > 0 {
		f.uncertain[runID] += uncertain
	}
	return nil
}

func (f *fakeRefusalStore) AddSandboxEgressRefusalLinkLoss(_ context.Context, runID string, lost, closed int, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.linkLost == nil {
		f.linkLost, f.closed = map[string]int{}, map[string]int{}
	}
	f.linkLost[runID] += lost
	f.closed[runID] += closed
	return nil
}

// linkLoss returns copies of the link-loss counts written.
func (f *fakeRefusalStore) linkLoss() (map[string]int, map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, c := map[string]int{}, map[string]int{}
	for k, v := range f.linkLost {
		l[k] = v
	}
	for k, v := range f.closed {
		c[k] = v
	}
	return l, c
}

// dropCounts returns copies of the counts written.
func (f *fakeRefusalStore) dropCounts() (map[string]int, map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, u := map[string]int{}, map[string]int{}
	for k, v := range f.drops {
		d[k] = v
	}
	for k, v := range f.uncertain {
		u[k] = v
	}
	return d, u
}

func (f *fakeRefusalStore) PruneSandboxEgressRefusals(context.Context, time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruned++
	return 0, nil
}

func (f *fakeRefusalStore) all() []store.SandboxEgressRefusal {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.SandboxEgressRefusal(nil), f.rows...)
}

// waitForRefusal polls cond for up to 5 seconds.
func waitForRefusal(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// TestEgressRefusalReporterBoundsAndNeverBlocks: one send per host per
// minute, and a sender stuck on the daemon never blocks the gateway.
func TestEgressRefusalReporterBoundsAndNeverBlocks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var sent []sandboxrelay.EgressRefusalReport
	release := make(chan struct{})
	r := newEgressRefusalReporter(ctx, func(_ context.Context, rep sandboxrelay.EgressRefusalReport) error {
		mu.Lock()
		sent = append(sent, rep)
		mu.Unlock()
		<-release
		return nil
	}, false)
	at := time.Now()
	r.Report(sandboxnet.Refusal{Host: "evil.example", Port: 443, Rule: sandboxnet.RefusalAllowListMiss, Key: sandboxnet.KeyEgressAllowHosts, At: at})
	r.Report(sandboxnet.Refusal{Host: "evil.example", Port: 443, Rule: sandboxnet.RefusalAllowListMiss, At: at})
	done := make(chan struct{})
	go func() {
		// The sender is stuck: far more refusals than the queue holds
		// must still return at once.
		for i := 0; i < 10*egressRefusalQueue; i++ {
			r.Report(sandboxnet.Refusal{Host: "h" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + ".example", Rule: sandboxnet.RefusalSSRFFloor, At: at})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Report blocked on a stuck sender")
	}
	close(release)
	waitForRefusal(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(sent) >= 1 })
	mu.Lock()
	first := sent[0]
	mu.Unlock()
	if first.Host != "evil.example" || first.Port != 443 || first.Rule != "allow-list-miss" || first.Key != sandboxnet.KeyEgressAllowHosts || first.AtMS != at.UnixMilli() {
		t.Fatalf("first report %+v", first)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	n := len(sent)
	mu.Unlock()
	if n > sandboxnet.DefaultRefusalsPerMinute {
		t.Fatalf("%d sends in a minute, want at most %d", n, sandboxnet.DefaultRefusalsPerMinute)
	}
}

// TestEgressRefusalReportOversizedHost (audit N1-A2): a refusal of a host
// longer than the payload bound still encodes, under the cut host with its
// marker and the rule.
func TestEgressRefusalReportOversizedHost(t *testing.T) {
	rep := egressRefusalReport(sandboxnet.Refusal{Host: strings.Repeat("a", 300) + ".example", Port: 443, Rule: sandboxnet.RefusalAllowListMiss, At: time.Now()})
	if len(rep.Host) != 253 || !strings.HasSuffix(rep.Host, sandboxrelay.EgressHostTruncated) || rep.Rule != string(sandboxnet.RefusalAllowListMiss) {
		t.Fatalf("report %+v", rep)
	}
	if _, err := sandboxrelay.EncodeEgressRefusalReport(rep); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

// TestEgressRefusalReceiverRows is one row per receiver rule.
func TestEgressRefusalReceiverRows(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	bound := sandboxrelayd.RunRecord{RunID: "relay-1", TerminalRunID: "term-1", ProjectRoot: "/p/one"}
	unbound := sandboxrelayd.RunRecord{RunID: "relay-2", ProjectRoot: "/p/two"}
	cases := []struct {
		name   string
		run    sandboxrelayd.RunRecord
		rep    sandboxrelay.EgressRefusalReport
		write  bool
		runID  string
		wantAt time.Time
	}{
		{"bound run is stored under its terminal run", bound, sandboxrelay.EgressRefusalReport{Host: "a.example", Port: 443, Rule: "allow-list-miss", Key: "terminal.sandbox.egress_allow_hosts", AtMS: now.UnixMilli()}, true, "term-1", now},
		{"unbound run is stored under its relay run", unbound, sandboxrelay.EgressRefusalReport{Host: "a.example", Rule: "ssrf-floor", AtMS: now.UnixMilli()}, true, "relay-2", now},
		{"rule outside the vocabulary is dropped", bound, sandboxrelay.EgressRefusalReport{Host: "b.example", Rule: "made-up", AtMS: now.UnixMilli()}, false, "", time.Time{}},
		{"a skewed clock takes the daemon's time", bound, sandboxrelay.EgressRefusalReport{Host: "c.example", Rule: "ssrf-floor", AtMS: now.Add(-48 * time.Hour).UnixMilli()}, true, "term-1", now},
		{"a run with no id is dropped", sandboxrelayd.RunRecord{}, sandboxrelay.EgressRefusalReport{Host: "d.example", Rule: "ssrf-floor", AtMS: now.UnixMilli()}, false, "", time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &egressRefusalReceiver{lim: sandboxnet.NewRefusalLimiter(0), now: func() time.Time { return now }}
			row, ok := r.row(tc.run, tc.rep)
			if ok != tc.write {
				t.Fatalf("written %v, want %v", ok, tc.write)
			}
			if !ok {
				return
			}
			if row.RunID != tc.runID || row.ProjectRoot != tc.run.ProjectRoot || row.Host != tc.rep.Host || row.Rule != tc.rep.Rule || !row.At.Equal(tc.wantAt) || row.Backend != "" || row.Tier != "" {
				t.Fatalf("row %+v", row)
			}
		})
	}
}

// TestEgressRefusalReceiverBoundsAndPrunes: the receiver writes one row per
// host per minute and prunes when it starts.
func TestEgressRefusalReceiverBoundsAndPrunes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeRefusalStore{}
	r := newEgressRefusalReceiver(ctx, f, nil)
	run := sandboxrelayd.RunRecord{RunID: "relay-1", TerminalRunID: "term-1"}
	at := time.Now().UnixMilli()
	for i := 0; i < 5; i++ {
		r.OnEgressRefusal(run, sandboxrelay.EgressRefusalReport{Host: "a.example", Rule: "ssrf-floor", AtMS: at})
	}
	r.OnEgressRefusal(run, sandboxrelay.EgressRefusalReport{Host: "b.example", Rule: "ssrf-floor", AtMS: at})
	waitForRefusal(t, func() bool { return len(f.all()) == 2 })
	time.Sleep(20 * time.Millisecond)
	if n := len(f.all()); n != 2 {
		t.Fatalf("%d rows, want 2", n)
	}
	f.mu.Lock()
	pruned := f.pruned
	f.mu.Unlock()
	if pruned < 1 {
		t.Fatal("the receiver did not prune on start")
	}
	if newEgressRefusalReceiver(ctx, nil, nil).onEgressRefusal() != nil {
		t.Fatal("a receiver without a store installed a hook")
	}
}

// TestEgressRefusalReceiverDropped (lane OC, audit findings O3-W2 and
// OC-A1): a feed's dropped and uncertain counts are written under the run
// id the rows carry (the stored terminal run when bound, else the relay
// run), the counts of one run added together; a zero count or no run
// writes nothing; a receiver without a store installs no hook.
func TestEgressRefusalReceiverDropped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeRefusalStore{}
	r := newEgressRefusalReceiver(ctx, f, nil)
	r.OnDropped(sandboxrelayd.RunRecord{RunID: "relay-1", TerminalRunID: "term-1"}, egressRefusalDropCount{Dropped: 7})
	r.OnDropped(sandboxrelayd.RunRecord{RunID: "relay-1", TerminalRunID: "term-1"}, egressRefusalDropCount{Uncertain: 2})
	r.OnDropped(sandboxrelayd.RunRecord{RunID: "relay-2"}, egressRefusalDropCount{Dropped: 3})
	r.OnDropped(sandboxrelayd.RunRecord{RunID: "relay-3"}, egressRefusalDropCount{})
	r.OnDropped(sandboxrelayd.RunRecord{}, egressRefusalDropCount{Dropped: 5})
	waitForRefusal(t, func() bool {
		d, u := f.dropCounts()
		return d["term-1"] == 7 && u["term-1"] == 2 && d["relay-2"] == 3
	})
	time.Sleep(20 * time.Millisecond)
	if d, u := f.dropCounts(); len(d) != 2 || len(u) != 1 {
		t.Fatalf("drops %v uncertain %v, want only term-1 and relay-2", d, u)
	}
	if newEgressRefusalReceiver(ctx, nil, nil).onDropped() != nil {
		t.Fatal("a receiver without a store installed a dropped hook")
	}
}

// TestEgressRefusalReceiverCountsLimiterDrops is audit finding OC-A2's
// probe: 40 distinct hosts of one run in one minute and one refusal from
// the minute before are each either written or counted against the run;
// a repeat of a host the minute already wrote is neither (nothing new).
func TestEgressRefusalReceiverCountsLimiterDrops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeRefusalStore{}
	now := time.Now().Truncate(time.Minute).Add(30 * time.Second)
	r := newEgressRefusalReceiverAt(ctx, f, nil, func() time.Time { return now })
	run := sandboxrelayd.RunRecord{RunID: "relay-1", TerminalRunID: "term-1"}
	rep := func(host string, at time.Time) sandboxrelay.EgressRefusalReport {
		return sandboxrelay.EgressRefusalReport{V: sandboxrelay.EgressRefusalVersion, Host: host, Port: 443, Rule: "allow-list-miss", Key: "terminal.sandbox.egress_allow_hosts", AtMS: at.UnixMilli()}
	}
	for i := 0; i < 40; i++ {
		r.OnEgressRefusal(run, rep("h"+strconv.Itoa(i)+".example", now))
	}
	r.OnEgressRefusal(run, rep("h0.example", now))
	r.OnEgressRefusal(run, rep("late.example", now.Add(-40*time.Second)))
	waitForRefusal(t, func() bool {
		d, _ := f.dropCounts()
		return len(f.all()) == sandboxnet.DefaultRefusalsPerMinute && d["term-1"] == 41-sandboxnet.DefaultRefusalsPerMinute
	})
	time.Sleep(20 * time.Millisecond)
	if d, _ := f.dropCounts(); len(f.all())+d["term-1"] != 41 {
		t.Fatalf("41 distinct refusals: %d rows, %d counted", len(f.all()), d["term-1"])
	}
}
