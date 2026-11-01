//go:build linux

package sandboxrelayd

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// healthLog collects every health the daemon hands OnHealth.
type healthLog struct {
	mu  sync.Mutex
	got []Health
}

func (l *healthLog) on(_ RunRecord, h Health) {
	l.mu.Lock()
	l.got = append(l.got, h)
	l.mu.Unlock()
}

func (l *healthLog) last() Health {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.got) == 0 {
		return Health{}
	}
	return l.got[len(l.got)-1]
}

func (l *healthLog) calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.got)
}

// waitHealth waits until the last health has cause c.
func (l *healthLog) waitHealth(t *testing.T, c DegradedCause) Health {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h := l.last(); h.Has(c) {
			return h
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("health never recorded %s: %+v", c, l.last())
	return Health{}
}

// TestHealthRecordsEveryDegradedEvent (P-032, milestone 2a): a refused, a
// rate-limited, a replayed and a dropped event each lower the run's health
// once, and OnHealth hears of each change (and only of a change).
func TestHealthRecordsEveryDegradedEvent(t *testing.T) {
	tr := newBindTree(t)
	run := bindRun(t, "run-h", tr)
	log := &healthLog{}
	d := &Daemon{
		SweepInterval: -1, OnHealth: log.on, Rate: RunRate{Requests: 0.001, Burst: 6},
		Gated: func(req sandboxrelay.HookRequest) bool { return req.Args[1] == "PreToolUse" },
	}
	h := startBindHarness(t, d, run)
	if r := h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.ws + `"}`)}); r.Refused != "" || log.calls() != 0 {
		t.Fatalf("a clean event lowered the run: %q %d", r.Refused, log.calls())
	}
	h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.other + `"}`)})
	d.FlushHealth()
	h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.other + `"}`)})
	d.FlushHealth()
	if got := log.last(); !slices.Equal(got.Causes, []DegradedCause{CauseRefused}) || log.calls() != 1 {
		t.Fatalf("after two refusals: %+v in %d calls", got, log.calls())
	}
	h.send(t, run, sandboxrelay.HookRequest{Args: []string{"claude-code", "PostToolUse"}, Replay: true})
	d.FlushHealth()
	if !log.last().Has(CauseReplayed) {
		t.Fatalf("a replayed event: %+v", log.last())
	}
	// The executor fails: the event is dropped.
	h.daemon.Exec = func(context.Context, RunRecord, sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
		return sandboxrelay.HookResponse{}, errors.New("child failed")
	}
	msg, _ := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PostToolUse"}})
	_, _ = linkRoundTripRaw(t, h, run, msg)
	log.waitHealth(t, CauseDropped)
	// The bucket is spent: rate limited.
	for range 3 {
		_, _ = linkRoundTripRaw(t, h, run, msg)
	}
	got := log.waitHealth(t, CauseRateLimited)
	want := []DegradedCause{CauseRefused, CauseRateLimited, CauseDropped, CauseReplayed}
	if !slices.Equal(got.Causes, want) {
		t.Fatalf("causes %v, want %v", got.Causes, want)
	}
	if st, _ := d.Run(run.RunID); !slices.Equal(st.Health().Causes, want) {
		t.Fatalf("run state health %v", st.Health().Causes)
	}
	if got.CauseList() != "refused,rate_limited,dropped,replayed" || !slices.Equal(ParseCauses(got.CauseList()+",bogus"), want) {
		t.Fatalf("cause list %q", got.CauseList())
	}
}

// TestHookDriftReachesTheDaemon (P-032, milestone 2b): the helper reads the
// launch's hook registration before the box runs; once a later read lost an
// event, the run is marked hooks_drifted within one verification interval,
// and a spooled replay re-checks first.
func TestHookDriftReachesTheDaemon(t *testing.T) {
	var mu sync.Mutex
	reg := HookRegistration{Events: []string{"PreToolUse", "PostToolUse"}}
	log := &healthLog{}
	m := startMultiRelay(t, 4, 4, false, func(d *Daemon, f *Forwarder) {
		d.OnHealth = log.on
		f.HookInterval = 50 * time.Millisecond
		f.HookProbe = func() (HookRegistration, error) {
			mu.Lock()
			defer mu.Unlock()
			return HookRegistration{Events: slices.Clone(reg.Events), Covered: reg.Covered, Conflict: reg.Conflict}, nil
		}
	})
	m.fw.ReadLaunchHooks()
	time.Sleep(120 * time.Millisecond)
	if log.calls() != 0 || m.fw.HooksDrifted() {
		t.Fatal("an unchanged registration drifted")
	}
	mu.Lock()
	reg.Events = []string{"PostToolUse"}
	mu.Unlock()
	h := log.waitHealth(t, CauseHooksDrifted)
	if h.MissedHeartbeats != 0 {
		t.Fatalf("drift counted heartbeats: %+v", h)
	}
	if !m.fw.HooksDrifted() {
		t.Fatal("the helper does not know it drifted")
	}
}

// TestHookDriftCheckedBeforeAReplay: with no timer, a spooled replay is
// what makes the helper read the registration again.
func TestHookDriftCheckedBeforeAReplay(t *testing.T) {
	var mu sync.Mutex
	conflict := false
	log := &healthLog{}
	m := startMultiRelay(t, 4, 4, false, func(d *Daemon, f *Forwarder) {
		d.OnHealth = log.on
		d.Gated = func(sandboxrelay.HookRequest) bool { return false }
		f.HookInterval = -1
		f.HookProbe = func() (HookRegistration, error) {
			mu.Lock()
			defer mu.Unlock()
			return HookRegistration{Events: []string{"PostToolUse"}, Conflict: conflict}, nil
		}
	})
	m.fw.ReadLaunchHooks()
	mu.Lock()
	conflict = true
	mu.Unlock()
	req := hookReq("late")
	req.Replay = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := BoxRoundTrip(ctx, m.sock, m.box(t), req, fastConn()); err != nil {
		t.Fatal(err)
	}
	log.waitHealth(t, CauseHooksDrifted)
	log.waitHealth(t, CauseReplayed)
}

// TestBoxCannotSendRunHealth: the helper's health kind is refused from a
// box (the box channel is not trusted to report the run's health) and
// never reaches the daemon.
func TestBoxCannotSendRunHealth(t *testing.T) {
	log := &healthLog{}
	m := startMultiRelay(t, 4, 4, false, func(d *Daemon, _ *Forwarder) { d.OnHealth = log.on })
	body, _ := EncodeHealthReport(HealthReport{HooksDrifted: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := BoxRoundTrip(ctx, m.sock, m.box(t), sandboxrelay.HookRequest{Kind: sandboxrelay.KindRunHealth, Args: []string{"claude-code"}, Stdin: body}, fastConn())
	if err == nil {
		t.Fatal("a box's run_health was answered")
	}
	time.Sleep(100 * time.Millisecond)
	if log.last().Has(CauseHooksDrifted) {
		t.Fatal("a box's run_health reached the daemon")
	}
}

// TestMissedHeartbeatsReachTheDaemon (P-032, milestone 2c): a daemon that
// goes silent while the helper waits on it for heartbeats is counted, and
// the count reaches the run's health.
func TestMissedHeartbeatsReachTheDaemon(t *testing.T) {
	log := &healthLog{}
	m := startMultiRelay(t, 4, 4, false, func(d *Daemon, f *Forwarder) {
		d.OnHealth = log.on
		d.Heartbeat = -1
		f.Heartbeat = 40 * time.Millisecond
		d.Exec = func(_ context.Context, _ RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			time.Sleep(400 * time.Millisecond)
			return sandboxrelay.HookResponse{Stdout: req.Stdin}, nil
		}
	})
	box := fastConn()
	box.IdleTimeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = BoxRoundTrip(ctx, m.sock, m.box(t), hookReq("silent daemon"), box)
	h := log.waitHealth(t, CauseHeartbeatMissed)
	if h.MissedHeartbeats < 2 {
		t.Fatalf("missed heartbeats %d", h.MissedHeartbeats)
	}
}

// TestHealthReportBounds: a report is strict and bounded.
func TestHealthReportBounds(t *testing.T) {
	for _, bad := range []string{`{"v":1,"missed_heartbeats":-1}`, `{"v":2}`, `{"v":1,"extra":1}`, `{"v":1,"dropped":2000000}`, `{"v":1} {}`, `nope`} {
		if _, err := DecodeHealthReport([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	b, _ := EncodeHealthReport(HealthReport{HooksDrifted: true, MissedHeartbeats: 3})
	if r, err := DecodeHealthReport(b); err != nil || !r.HooksDrifted || r.MissedHeartbeats != 3 {
		t.Fatalf("round trip %+v %v", r, err)
	}
}

// TestHookDriftTable: one case per row of the drift table, and the
// changes that are not a loss.
func TestHookDriftTable(t *testing.T) {
	base := HookRegistration{Events: []string{"A", "B"}}
	for _, tc := range []struct {
		name        string
		launch, now HookRegistration
		want        bool
	}{
		{"unchanged", base, base, false},
		{"an event added", base, HookRegistration{Events: []string{"A", "B", "C"}}, false},
		{"stopped reading as a configuration", base, HookRegistration{Events: []string{"A", "B"}, Conflict: true}, true},
		{"a conflict already at launch", HookRegistration{Conflict: true}, HookRegistration{Conflict: true}, false},
		{"the covering surface gone", HookRegistration{Covered: true}, HookRegistration{}, true},
		{"an event gone", base, HookRegistration{Events: []string{"B"}}, true},
		{"nothing registered at launch", HookRegistration{}, HookRegistration{}, false},
		{"a hooks-off switch set", base, HookRegistration{Events: []string{"A", "B"}, Disabled: []string{"s@p"}}, true},
		{"a switch already set at launch", HookRegistration{Disabled: []string{"s@p"}}, HookRegistration{Disabled: []string{"s@p"}}, false},
		{"a switch cleared", HookRegistration{Disabled: []string{"s@p"}}, HookRegistration{}, false},
	} {
		if got, _ := HookDrift(tc.launch, tc.now); got != tc.want {
			t.Errorf("%s: drift %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestBindTerminalRun: the record gains its stored terminal run, stays
// private, and cannot be rebound to another run.
func TestBindTerminalRun(t *testing.T) {
	obs := shortDir(t)
	rec, err := NewRunRecord(RunRecord{RunID: "run-t", Tool: "claude-code", WorkspaceDir: "/w"})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	if err := BindTerminalRun(obs, "run-t", "term-1"); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRun(obs, "run-t")
	if err != nil || got.TerminalRunID != "term-1" || string(got.LinkSecret) != string(rec.LinkSecret) {
		t.Fatalf("bound record %+v %v", got, err)
	}
	if err := BindTerminalRun(obs, "run-t", "term-1"); err != nil {
		t.Fatalf("binding the same run again: %v", err)
	}
	if err := BindTerminalRun(obs, "run-t", "term-2"); err == nil {
		t.Fatal("rebound to another terminal run")
	}
	for _, bad := range []string{"", "a/b", "x\n"} {
		if err := BindTerminalRun(obs, "run-t", bad); err == nil {
			t.Errorf("bound %q", bad)
		}
	}
	if err := BindTerminalRun(obs, "no-run", "term-1"); err == nil {
		t.Fatal("bound a missing record")
	}
}
