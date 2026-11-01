package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/service"
)

// fakeLiveSource is a scriptable liveRunSource.
type fakeLiveSource struct {
	mu    sync.Mutex
	runs  []dashapi.LiveSandboxRun
	ended []string
}

func (f *fakeLiveSource) LiveSandboxedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

func (f *fakeLiveSource) liveRuns(time.Time) []dashapi.LiveSandboxRun {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dashapi.LiveSandboxRun(nil), f.runs...)
}

func (f *fakeLiveSource) endLiveRuns(_ context.Context, reason, _ string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.runs)
	for range f.runs {
		f.ended = append(f.ended, reason)
	}
	f.runs = nil
	return n
}

func (f *fakeLiveSource) set(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = nil
	for i := 0; i < n; i++ {
		f.runs = append(f.runs, dashapi.LiveSandboxRun{RunID: "r", Tool: "claude-code", Backend: "bwrap", AgeSeconds: 60, NativeResume: true})
	}
}

// installLiveSource installs src as the daemon's source for one test.
func installLiveSource(t *testing.T, src liveRunSource) {
	t.Helper()
	setLiveRunSource(src)
	t.Cleanup(func() { setLiveRunSource(nil) })
}

// fastLivePoll makes pending waits poll quickly for one test.
func fastLivePoll(t *testing.T) {
	t.Helper()
	saved := liveRunPollEvery
	liveRunPollEvery = 5 * time.Millisecond
	t.Cleanup(func() { liveRunPollEvery = saved })
}

// TestLiveRunGateTable pins one case per row of the gate table, the zero
// count proceeding on every trigger, and an unknown trigger asking.
func TestLiveRunGateTable(t *testing.T) {
	for _, tc := range []struct {
		trigger liveRunTrigger
		policy  string
		want    liveRunVerdict
	}{
		{liveRunTriggerUpdateApply, liveRunPolicyAskImmediately, liveRunAsk},
		{liveRunTriggerUpdateApply, liveRunPolicyDefer, liveRunDefer},
		{liveRunTriggerDashboardRestart, liveRunPolicyDefer, liveRunAsk},
		{liveRunTriggerServiceRestart, "", liveRunAsk},
		{liveRunTriggerServiceInstall, "", liveRunAsk},
		{liveRunTriggerDeactivation, "", liveRunAsk},
		{liveRunTriggerPolicyTeardown, liveRunPolicyAskImmediately, liveRunDefer},
	} {
		if got := liveRunGate(tc.trigger, 1, tc.policy); got != tc.want {
			t.Errorf("gate(%s, 1, %q) = %s, want %s", tc.trigger, tc.policy, got, tc.want)
		}
		if got := liveRunGate(tc.trigger, 0, tc.policy); got != liveRunProceed {
			t.Errorf("gate(%s, 0, %q) = %s, want proceed (nothing live)", tc.trigger, tc.policy, got)
		}
	}
	if got := liveRunGate("something_new", 2, ""); got != liveRunAsk {
		t.Errorf("unknown trigger = %s, want ask", got)
	}
	if len(liveRunGateTable) != 7 {
		t.Errorf("the gate table has %d rows; add a case above for each new row", len(liveRunGateTable))
	}
	if normalizeLiveRunPolicy("") != liveRunPolicyDefer || normalizeLiveRunPolicy("bogus") != liveRunPolicyDefer ||
		normalizeLiveRunPolicy(liveRunPolicyAskImmediately) != liveRunPolicyAskImmediately {
		t.Error("normalizeLiveRunPolicy does not default to defer")
	}
}

// TestPendingRestartFiresAtZero: "restart when they finish" fires the
// restart once the count reaches zero, not before; a second request keeps
// the first; the state shows the pending restart meanwhile.
func TestPendingRestartFiresAtZero(t *testing.T) {
	fastLivePoll(t)
	src := &fakeLiveSource{}
	src.set(1)
	installLiveSource(t, src)
	var restarts atomic.Int32
	d := newDaemonLiveRuns(func() error { restarts.Add(1); return nil }, nil, nil)
	d.pendingStopped = make(chan struct{}, 1)
	if err := d.RestartWhenFinished(); err != nil {
		t.Fatal(err)
	}
	if err := d.RestartWhenFinished(); err != nil {
		t.Fatal(err)
	}
	if st := d.State(); !st.RestartPending || len(st.Runs) != 1 {
		t.Fatalf("state = %+v, want pending with one run", st)
	}
	time.Sleep(30 * time.Millisecond)
	if restarts.Load() != 0 {
		t.Fatal("the restart fired while a run was live")
	}
	src.set(0)
	select {
	case <-d.pendingStopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the pending restart never fired")
	}
	if restarts.Load() != 1 {
		t.Fatalf("restarts = %d, want 1", restarts.Load())
	}
	if d.State().RestartPending {
		t.Fatal("still pending after it fired")
	}
}

// TestPendingRestartCancelled: a cancelled pending restart never fires,
// even when the count later reaches zero.
func TestPendingRestartCancelled(t *testing.T) {
	fastLivePoll(t)
	src := &fakeLiveSource{}
	src.set(2)
	installLiveSource(t, src)
	var restarts atomic.Int32
	d := newDaemonLiveRuns(func() error { restarts.Add(1); return nil }, nil, nil)
	d.pendingStopped = make(chan struct{}, 1)
	if err := d.RestartWhenFinished(); err != nil {
		t.Fatal(err)
	}
	if !d.CancelPending() {
		t.Fatal("CancelPending = false with a pending restart")
	}
	src.set(0)
	select {
	case <-d.pendingStopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled wait never exited")
	}
	time.Sleep(20 * time.Millisecond)
	if restarts.Load() != 0 {
		t.Fatalf("a cancelled restart fired %d times", restarts.Load())
	}
	if d.CancelPending() {
		t.Fatal("CancelPending = true with nothing pending")
	}
}

// TestEndRunsRecordsTheShutdownReason: the owner's "end them" ends every run
// with daemon_shutdown (resumable where the tool has native resume).
func TestEndRunsRecordsTheShutdownReason(t *testing.T) {
	src := &fakeLiveSource{}
	src.set(2)
	installLiveSource(t, src)
	d := newDaemonLiveRuns(nil, nil, nil)
	n, err := d.EndRuns(context.Background())
	if err != nil || n != 2 || len(src.ended) != 2 || src.ended[0] != "daemon_shutdown" {
		t.Fatalf("EndRuns = %d %v, ended %v", n, err, src.ended)
	}
	if err := d.RestartWhenFinished(); !errors.Is(err, errNoRestartHook) {
		t.Fatalf("RestartWhenFinished without a hook = %v", err)
	}
}

// fakeLiveClient is a scriptable daemonLiveRunsClient.
type fakeLiveClient struct {
	answered bool
	runs     []dashapi.LiveSandboxRun
	ends     int
	queries  int
	// drainAfter empties runs after this many queries (-1: never).
	drainAfter int
}

func (f *fakeLiveClient) client() daemonLiveRunsClient {
	return daemonLiveRunsClient{
		query: func(context.Context) (daemonLiveRunsReport, error) {
			f.queries++
			if f.drainAfter >= 0 && f.queries > f.drainAfter {
				f.runs = nil
			}
			return daemonLiveRunsReport{Answered: f.answered, Runs: f.runs}, nil
		},
		end: func(context.Context) (int, error) {
			f.ends++
			n := len(f.runs)
			f.runs = nil
			return n, nil
		},
	}
}

var oneCLIRun = []dashapi.LiveSandboxRun{{RunID: "r1", Tool: "claude-code", Backend: "bwrap", AgeSeconds: 120, NativeResume: true}}

// stubServiceRestart makes `observer service restart` testable: systemd
// present, systemctl recorded, the daemon client scripted.
func stubServiceRestart(t *testing.T, fc *fakeLiveClient) *[]string {
	t.Helper()
	savedSD, savedCtl, savedClient := systemdAvailable, serviceSystemctl, newDaemonLiveRunsClient
	t.Cleanup(func() { systemdAvailable, serviceSystemctl, newDaemonLiveRunsClient = savedSD, savedCtl, savedClient })
	systemdAvailable = func() bool { return true }
	var ran []string
	serviceSystemctl = func(c service.Command) error { ran = append(ran, strings.Join(c.Args, " ")); return nil }
	newDaemonLiveRunsClient = func(string) daemonLiveRunsClient { return fc.client() }
	return &ran
}

func runServiceRestart(t *testing.T, args ...string) (string, error) {
	t.Helper()
	fastLivePoll(t)
	cmd := newServiceRestartCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	cmd.SetContext(context.Background())
	err := cmd.Execute()
	return out.String(), err
}

// TestServiceRestartLiveRuns covers `observer service restart` with no
// daemon, nothing live, a live run and no flag, --end-sandboxed-runs and
// --when-idle.
func TestServiceRestartLiveRuns(t *testing.T) {
	t.Run("no daemon: restarts as before, with a warning", func(t *testing.T) {
		ran := stubServiceRestart(t, &fakeLiveClient{drainAfter: -1})
		out, err := runServiceRestart(t)
		if err != nil || len(*ran) != 1 || !strings.Contains(out, "WARN no running daemon reported") {
			t.Fatalf("err %v, systemctl %v, out %q", err, *ran, out)
		}
	})
	t.Run("nothing live: restarts, says nothing", func(t *testing.T) {
		ran := stubServiceRestart(t, &fakeLiveClient{answered: true, drainAfter: -1})
		out, err := runServiceRestart(t)
		if err != nil || len(*ran) != 1 || out != "" {
			t.Fatalf("err %v, systemctl %v, out %q", err, *ran, out)
		}
	})
	t.Run("live, no flag: refused naming the run", func(t *testing.T) {
		ran := stubServiceRestart(t, &fakeLiveClient{answered: true, runs: oneCLIRun, drainAfter: -1})
		_, err := runServiceRestart(t)
		if err == nil || !errors.Is(err, errLiveSandboxedRuns) || len(*ran) != 0 ||
			!strings.Contains(err.Error(), "claude-code on bwrap") || !strings.Contains(err.Error(), "--when-idle") {
			t.Fatalf("err %v, systemctl %v", err, *ran)
		}
	})
	t.Run("--end-sandboxed-runs ends them through the daemon, then restarts", func(t *testing.T) {
		fc := &fakeLiveClient{answered: true, runs: oneCLIRun, drainAfter: -1}
		ran := stubServiceRestart(t, fc)
		out, err := runServiceRestart(t, "--end-sandboxed-runs")
		if err != nil || fc.ends != 1 || len(*ran) != 1 || !strings.Contains(out, "Ended 1 sandboxed run") {
			t.Fatalf("err %v, ends %d, systemctl %v, out %q", err, fc.ends, *ran, out)
		}
	})
	t.Run("--when-idle waits, then restarts", func(t *testing.T) {
		fc := &fakeLiveClient{answered: true, runs: oneCLIRun, drainAfter: 3}
		ran := stubServiceRestart(t, fc)
		out, err := runServiceRestart(t, "--when-idle")
		if err != nil || fc.queries < 4 || fc.ends != 0 || len(*ran) != 1 || !strings.Contains(out, "Waiting for 1 sandboxed run") {
			t.Fatalf("err %v, queries %d, systemctl %v, out %q", err, fc.queries, *ran, out)
		}
	})
	t.Run("both flags refused", func(t *testing.T) {
		ran := stubServiceRestart(t, &fakeLiveClient{answered: true, drainAfter: -1})
		if _, err := runServiceRestart(t, "--when-idle", "--end-sandboxed-runs"); err == nil || len(*ran) != 0 {
			t.Fatalf("err %v, systemctl %v", err, *ran)
		}
	})
}

// TestServiceInstallNowLiveRuns: install --now on a running unit whose
// binary changed asks first (refused naming the run), upgrade leaves the old
// process running and says why, and a unit already running this binary is
// not asked about at all.
func TestServiceInstallNowLiveRuns(t *testing.T) {
	fc := &fakeLiveClient{answered: true, runs: oneCLIRun, drainAfter: -1}
	c := fc.client()
	changed := &fakeServiceProbe{active: true, pid: 42, exe: "/old/observer"}
	same := &fakeServiceProbe{active: true, pid: 42, exe: "/x/observer"}
	r := serviceRefresh{scope: service.ScopeUser, exe: "/x/observer"}
	var out bytes.Buffer
	opts := serviceInstallOptions{now: true, stdout: &out, liveRuns: serviceLiveRunChoice(false, false), deps: serviceInstallDeps{liveRuns: &c}}
	if err := serviceInstallLiveRunCheck(opts, r, *changed.probe()); err == nil || !errors.Is(err, errLiveSandboxedRuns) {
		t.Fatalf("install --now with a live run: err = %v", err)
	}
	opts.upgrade = true
	out.Reset()
	if err := serviceInstallLiveRunCheck(opts, r, *changed.probe()); err != nil || !strings.Contains(out.String(), "keeps its current process") {
		t.Fatalf("upgrade with a live run: err %v, out %q", err, out.String())
	}
	opts.upgrade = false
	fc.queries = 0
	if err := serviceInstallLiveRunCheck(opts, r, *same.probe()); err != nil || fc.queries != 0 {
		t.Fatalf("no restart due: err %v, daemon asked %d times", err, fc.queries)
	}
	opts.liveRuns = serviceLiveRunChoice(false, true)
	if err := serviceInstallLiveRunCheck(opts, r, *changed.probe()); err != nil || fc.ends != 1 {
		t.Fatalf("--end-sandboxed-runs: err %v, ends %d", err, fc.ends)
	}
}

// TestComponentsDeactivationHold: through the dashboard's components
// service, a change deactivating the sandbox is refused naming the runs
// while one is live (its preview says so), and with nothing live the
// preview and the apply are the service's own.
func TestComponentsDeactivationHold(t *testing.T) {
	requireComponents(t, "terminals.sandbox")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "none.db"))+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc, err := newComponentsService(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeLiveSource{}
	installLiveSource(t, src)
	h := withLiveRunHold(svc)
	ch := componentsvc.Change{Remove: []string{"terminals.sandbox"}}
	plain, err := svc.Preview(context.Background(), ch)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.Preview(context.Background(), ch)
	if err != nil || len(got.Issues) != len(plain.Issues) {
		t.Fatalf("with nothing live the preview changed: %v vs %v (%v)", got.Issues, plain.Issues, err)
	}
	src.set(1)
	got, _ = h.Preview(context.Background(), ch)
	if len(got.Issues) != len(plain.Issues)+1 || !strings.Contains(got.Issues[len(got.Issues)-1], "claude-code on bwrap") {
		t.Fatalf("live preview issues = %v", got.Issues)
	}
	if _, err := h.Apply(context.Background(), ch, componentsvc.ApplyOptions{Principal: "dashboard"}); !errors.Is(err, errDeactivationHeld) {
		t.Fatalf("Apply with a live run = %v, want the hold", err)
	}
	raw, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(raw), "[components]") {
		t.Fatalf("a held change was written:\n%s", raw)
	}
	// An unrelated change is not held.
	if ids := liveRunHeldIDs([]string{"codeintel"}); len(ids) != 0 {
		t.Fatalf("codeintel held: %v", ids)
	}
	if ids := liveRunHeldIDs([]string{"terminals.sandbox.oci", "isolation", "terminals"}); len(ids) != 3 {
		t.Fatalf("held ids = %v", ids)
	}
}

// TestPolicyFollowerWaitsForLiveRuns: a blocked sandbox component's teardown
// waits while sandboxed runs are live (one deferred_live_sandbox audit),
// other blocked components are torn down at once, and the next pass after
// the runs end tears the sandbox component down.
func TestPolicyFollowerWaitsForLiveRuns(t *testing.T) {
	f := &componentPolicyFollower{tornDown: map[string]bool{}, waiting: map[string]bool{}}
	f.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	live := 1
	f.liveSandboxed = func() int { return live }
	got := f.holdForLiveRuns(context.Background(), []string{"codeintel", "terminals.sandbox"})
	if len(got) != 1 || got[0] != "codeintel" || !f.waiting["terminals.sandbox"] {
		t.Fatalf("with a live run: %v (waiting %v)", got, f.waiting)
	}
	got = f.holdForLiveRuns(context.Background(), []string{"terminals.sandbox"})
	if len(got) != 0 {
		t.Fatalf("second pass: %v", got)
	}
	live = 0
	got = f.holdForLiveRuns(context.Background(), []string{"terminals.sandbox"})
	if len(got) != 1 {
		t.Fatalf("after the runs ended: %v, want the teardown", got)
	}
}

// TestOnlyTheGatedRestartRequestsARestart is the test-backed note that the
// node binary has no config-driven restart of its own: restartRequested is
// set in exactly one place, daemonRestartFunc in sandbox_liveruns.go, which
// the restart route reaches only after the live-run question.
func TestOnlyTheGatedRestartRequestsARestart(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`restartRequested\.Store\(true\)`)
	var where []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for range re.FindAllIndex(raw, -1) {
			where = append(where, f)
		}
	}
	if len(where) != 1 || where[0] != "sandbox_liveruns.go" {
		t.Fatalf("restartRequested is set in %v; want only sandbox_liveruns.go (a new self-restart must go through the live-run gate)", where)
	}
}

// TestDeferredUpdateRaisesTheQuestion: an update deferred for live
// sandboxed runs shows in the seam's state with the policy in force (both
// values), "apply when they finish" is refused with nothing deferred, and
// once accepted re-runs the apply when the count reaches zero.
func TestDeferredUpdateRaisesTheQuestion(t *testing.T) {
	fastLivePoll(t)
	src := &fakeLiveSource{}
	src.set(1)
	installLiveSource(t, src)
	var deferred atomic.Bool
	var applied atomic.Int32
	saved := updateLiveDeferredHook.Load()
	t.Cleanup(func() { updateLiveDeferredHook.Store(saved) })
	updateLiveDeferredHook.Store(&liveDeferredHooks{
		pending: deferred.Load,
		apply:   func(context.Context) error { applied.Add(1); deferred.Store(false); return nil },
	})
	for _, policy := range []string{liveRunPolicyDefer, liveRunPolicyAskImmediately} {
		d := newDaemonLiveRuns(nil, func() string { return policy }, nil)
		wireLiveRunUpdateHooks(d)
		if err := d.ApplyUpdateWhenFinished(); err == nil {
			t.Fatalf("%s: apply_when_finished accepted with no deferral", policy)
		}
		deferred.Store(true)
		st := d.State()
		if !st.UpdateDeferred || st.Policy != policy {
			t.Fatalf("%s: state = %+v", policy, st)
		}
		d.pendingStopped = make(chan struct{}, 1)
		if err := d.ApplyUpdateWhenFinished(); err != nil {
			t.Fatal(err)
		}
		if !d.State().UpdatePending {
			t.Fatalf("%s: not pending", policy)
		}
		src.set(0)
		select {
		case <-d.pendingStopped:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: the pending apply never ran", policy)
		}
		src.set(1)
	}
	if applied.Load() != 2 {
		t.Fatalf("applied %d times, want 2", applied.Load())
	}
}

// TestLiveRunPolicyFromConfig: the policy is read fresh from the config,
// defaulting to defer.
func TestLiveRunPolicyFromConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	write := func(body string) {
		if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "x.db"))+"\"\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := liveRunPolicyFromConfig(cfgPath)
	write("")
	if got := read(); got != liveRunPolicyDefer {
		t.Fatalf("default = %q", got)
	}
	write("[terminal.sandbox]\nlive_run_update_policy = \"ask_immediately\"\n")
	if got := read(); got != liveRunPolicyAskImmediately {
		t.Fatalf("set = %q", got)
	}
}

// TestDaemonRestartPreflight (SBX-UPD audit finding 1): the preflight the
// restart route runs before it ends live runs refuses exactly what the
// restart refuses (no re-exec on this OS as dashapi.ErrRestartUnsupported, a
// config that would not come back) and schedules nothing.
func TestDaemonRestartPreflight(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(bad, []byte("[observer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restartRequested.Store(false)
	err := daemonRestartPreflight(bad)()
	if err == nil || restartRequested.Load() {
		t.Fatalf("a broken config: err %v, restart requested %v", err, restartRequested.Load())
	}
	if !reexecSupported() && !errors.Is(err, dashapi.ErrRestartUnsupported) {
		t.Fatalf("no re-exec on this OS: err %v", err)
	}
	if err := daemonRestartFunc(bad, func() {})(); err == nil || restartRequested.Load() {
		t.Fatalf("the restart hook went ahead past a refusing preflight: %v", err)
	}
}
