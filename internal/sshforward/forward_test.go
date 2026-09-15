package sshforward

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sshprofile"
)

// --- fakes ------------------------------------------------------------------

// fakeProcess stands in for the ssh child. Nothing forks in this suite.
type fakeProcess struct {
	mu       sync.Mutex
	stopped  int
	stderr   string
	exitErr  error
	exitCh   chan struct{}
	exitOnce sync.Once
}

func newFakeProcess() *fakeProcess {
	return &fakeProcess{exitCh: make(chan struct{})}
}

// Wait blocks until the test calls die().
func (p *fakeProcess) Wait() error {
	<-p.exitCh
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitErr
}

// Stop records the kill and unblocks Wait, like a real signal would.
func (p *fakeProcess) Stop() error {
	p.mu.Lock()
	p.stopped++
	p.mu.Unlock()
	p.die(nil)
	return nil
}

// StderrTail returns the canned stderr.
func (p *fakeProcess) StderrTail() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stderr
}

// die makes the child exit with the given error.
func (p *fakeProcess) die(err error) {
	p.exitOnce.Do(func() {
		p.mu.Lock()
		if err != nil {
			p.exitErr = err
		}
		p.mu.Unlock()
		close(p.exitCh)
	})
}

func (p *fakeProcess) stopCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopped
}

// fakeSpawner hands out pre-built fakeProcesses and records every argv.
type fakeSpawner struct {
	mu    sync.Mutex
	argvs [][]string
	procs []*fakeProcess
	err   error
	// onSpawn, when set, runs after the process is created (used to make a
	// child die immediately).
	onSpawn func(*fakeProcess)
}

func (s *fakeSpawner) Spawn(argv []string) (Process, error) {
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return nil, err
	}
	p := newFakeProcess()
	s.argvs = append(s.argvs, append([]string(nil), argv...))
	s.procs = append(s.procs, p)
	hook := s.onSpawn
	s.mu.Unlock()
	if hook != nil {
		hook(p)
	}
	return p, nil
}

func (s *fakeSpawner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.argvs)
}

func (s *fakeSpawner) lastArgv() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.argvs) == 0 {
		return nil
	}
	return s.argvs[len(s.argvs)-1]
}

func (s *fakeSpawner) proc(i int) *fakeProcess {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.procs[i]
}

// testProfiles is the operator-authored allow-list every test resolves against.
func testProfiles() []sshprofile.Profile {
	return []sshprofile.Profile{
		{Name: "sb-devbox", Label: "Dev box", Host: "devbox.internal", User: "dev"},
		{Name: "other", Host: "other.internal", DashboardPort: 9099},
	}
}

// newTestManager builds a Manager whose every OS seam is faked: nothing forks,
// nothing binds, nothing dials.
func newTestManager(t *testing.T, sp Spawner, mutate func(*Options)) *Manager {
	t.Helper()
	opts := Options{
		Enabled:    true,
		Profiles:   testProfiles(),
		Spawner:    sp,
		AllocPort:  func() (int, error) { return 40001, nil },
		Probe:      func(int) error { return nil },
		KnownHosts: func(sshprofile.Profile) (bool, bool) { return true, true },
		// Short so a deliberately-failing readiness path does not stall the
		// suite.
		ReadyTimeout:  200 * time.Millisecond,
		ProbeInterval: 5 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&opts)
	}
	m := New(opts)
	t.Cleanup(m.Close)
	return m
}

// --- tests ------------------------------------------------------------------

// TestConnectIsIdempotent pins that a second Connect for a live forward reuses
// the child rather than spawning another. A double-click in the switcher must
// not leak an ssh process.
func TestConnectIsIdempotent(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, nil)

	first, err := m.Connect("sb-devbox")
	if err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	if first.State != StateConnected {
		t.Fatalf("state %q, want %q", first.State, StateConnected)
	}
	second, err := m.Connect("sb-devbox")
	if err != nil {
		t.Fatalf("second Connect: %v", err)
	}
	if got := sp.count(); got != 1 {
		t.Fatalf("spawned %d children for two Connects, want 1", got)
	}
	if second.LocalPort != first.LocalPort {
		t.Fatalf("second Connect returned port %d, want the live %d", second.LocalPort, first.LocalPort)
	}
	if second.URL != LocalURL(first.LocalPort) {
		t.Fatalf("URL %q, want %q", second.URL, LocalURL(first.LocalPort))
	}
}

// TestConnectRefusesUnknownProfile pins THE gate: a name that is not in the
// operator's config can never become a connection, and nothing is spawned.
func TestConnectRefusesUnknownProfile(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, nil)

	for _, name := range []string{"nope", "", "sb-devbox ", "SB-DEVBOX", "../sb-devbox", "sb-devbox;id"} {
		if _, err := m.Connect(name); !errors.Is(err, ErrUnknownProfile) {
			t.Fatalf("Connect(%q) error = %v, want ErrUnknownProfile", name, err)
		}
	}
	if got := sp.count(); got != 0 {
		t.Fatalf("spawned %d children for unknown profiles, want 0", got)
	}
}

// TestConnectRefusesUnknownHostKey pins the known_hosts precondition. A -N
// forward has no terminal on which to accept a key, and Observer never
// auto-accepts one, so an unknown host is refused BEFORE anything is spawned
// and the message names the fix.
func TestConnectRefusesUnknownHostKey(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, func(o *Options) {
		o.KnownHosts = func(sshprofile.Profile) (bool, bool) { return false, true }
	})

	_, err := m.Connect("sb-devbox")
	if !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("Connect error = %v, want ErrHostKeyUnknown", err)
	}
	if !strings.Contains(err.Error(), "known_hosts") || !strings.Contains(err.Error(), "SSH terminal") {
		t.Fatalf("error %q must tell the operator how to fix it (open an SSH terminal once, accept the key)", err)
	}
	if got := sp.count(); got != 0 {
		t.Fatalf("spawned %d children despite an untrusted host key, want 0", got)
	}
	// The refusal must not leave a phantom row claiming a port.
	inst, _ := m.Get("sb-devbox")
	if inst.State != StateDisconnected || inst.LocalPort != 0 {
		t.Fatalf("after a refused connect: state=%q port=%d, want disconnected/0", inst.State, inst.LocalPort)
	}
}

// TestConnectProceedsWhenCheckerHasNoVerdict pins the fail-open direction of the
// PRE-FLIGHT specifically: it exists to improve an error message, and must never
// invent a refusal when it could not reach a verdict. ssh itself (with
// StrictHostKeyChecking=ask + BatchMode=yes) remains the enforcement.
func TestConnectProceedsWhenCheckerHasNoVerdict(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, func(o *Options) {
		o.KnownHosts = func(sshprofile.Profile) (bool, bool) { return false, false }
	})
	if _, err := m.Connect("sb-devbox"); err != nil {
		t.Fatalf("Connect: %v — a checker with no verdict must not block the attempt", err)
	}
	if got := sp.count(); got != 1 {
		t.Fatalf("spawned %d children, want 1", got)
	}
}

// TestConnectPassesConfiguredRemotePort pins the end-to-end wire property: the
// -L argument's remote port comes from the profile, and the local port from the
// daemon's allocator. Nothing in Connect's signature can influence either.
func TestConnectPassesConfiguredRemotePort(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, func(o *Options) {
		o.AllocPort = func() (int, error) { return 45678, nil }
	})
	inst, err := m.Connect("other") // dashboard_port = 9099
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if inst.DashboardPort != 9099 {
		t.Fatalf("DashboardPort = %d, want 9099", inst.DashboardPort)
	}
	argv := sp.lastArgv()
	want := "127.0.0.1:45678:127.0.0.1:9099"
	found := false
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "-L" && argv[i+1] == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("argv %v lacks -L %s", argv, want)
	}
	if inst.URL != "http://127.0.0.1:45678" {
		t.Fatalf("URL = %q, want http://127.0.0.1:45678", inst.URL)
	}
}

// TestDisconnectKillsTheChild pins that Disconnect actually terminates the ssh
// process and clears the row, and that a second Disconnect is a success rather
// than a spurious error from a stale UI.
func TestDisconnectKillsTheChild(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, nil)

	if _, err := m.Connect("sb-devbox"); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := m.Disconnect("sb-devbox"); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if got := sp.proc(0).stopCount(); got != 1 {
		t.Fatalf("child stopped %d times, want 1", got)
	}
	inst, _ := m.Get("sb-devbox")
	if inst.State != StateDisconnected || inst.URL != "" {
		t.Fatalf("after Disconnect: state=%q url=%q, want disconnected and no URL", inst.State, inst.URL)
	}
	if err := m.Disconnect("sb-devbox"); err != nil {
		t.Fatalf("second Disconnect: %v — disconnecting an already-closed forward must be a no-op success", err)
	}
}

// TestDisconnectRefusesUnknownProfile pins that the disconnect verb resolves
// names against the SAME allow-list as connect.
func TestDisconnectRefusesUnknownProfile(t *testing.T) {
	t.Parallel()

	m := newTestManager(t, &fakeSpawner{}, nil)
	if err := m.Disconnect("nope"); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("Disconnect error = %v, want ErrUnknownProfile", err)
	}
}

// TestTestReportsAuthOK pins the happy path: known_hosts already trusts the
// host and the probe exits zero.
func TestTestReportsAuthOK(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	var gotArgv []string
	m := newTestManager(t, sp, func(o *Options) {
		o.TestRunner = func(argv []string) (bool, string, error) {
			gotArgv = argv
			return true, "", nil
		}
	})

	result, err := m.Test("sb-devbox")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !result.AuthOK {
		t.Fatal("AuthOK = false, want true")
	}
	if !result.KnownHostsChecked || !result.KnownHostsOK {
		t.Fatalf("KnownHostsChecked=%v KnownHostsOK=%v, want true/true", result.KnownHostsChecked, result.KnownHostsOK)
	}
	if result.Stderr != "" {
		t.Fatalf("Stderr = %q, want empty on a clean success", result.Stderr)
	}
	// Test must never spawn a lasting forward or touch m.live.
	if got := sp.count(); got != 0 {
		t.Fatalf("Test spawned %d forwards via the connect-path Spawner, want 0", got)
	}
	if inst, _ := m.Get("sb-devbox"); inst.State != StateDisconnected {
		t.Fatalf("Test left state %q, want disconnected — a probe must leave no live state", inst.State)
	}
	wantArgv, err := sshprofile.TestArgv(testProfiles()[0], sshprofile.Options{})
	if err != nil {
		t.Fatalf("sshprofile.TestArgv: %v", err)
	}
	if strings.Join(gotArgv, " ") != strings.Join(wantArgv, " ") {
		t.Fatalf("TestRunner argv = %v, want %v", gotArgv, wantArgv)
	}
}

// TestTestReportsAuthFailureAsAResultNotAnError pins the design contract: a
// probe that ran but failed to authenticate is an honest TestResult, not an
// error — the operator asked "does this work?" and "no" is a valid answer.
func TestTestReportsAuthFailureAsAResultNotAnError(t *testing.T) {
	t.Parallel()

	m := newTestManager(t, &fakeSpawner{}, func(o *Options) {
		o.TestRunner = func([]string) (bool, string, error) {
			return false, "Permission denied (publickey).", nil
		}
	})

	result, err := m.Test("sb-devbox")
	if err != nil {
		t.Fatalf("Test: %v — a failed probe must not be a Go error", err)
	}
	if result.AuthOK {
		t.Fatal("AuthOK = true, want false")
	}
	if !strings.Contains(result.Stderr, "Permission denied") {
		t.Fatalf("Stderr = %q, want the probe's excerpt", result.Stderr)
	}
}

// TestTestSurvivesAnUnknownHostAndReportsIt pins that Test does NOT gate the
// probe on the known-hosts verdict (TestArgv's own StrictHostKeyChecking=ask +
// BatchMode=yes already fails the probe honestly) — it only reports the
// verdict alongside the result.
func TestTestSurvivesAnUnknownHostAndReportsIt(t *testing.T) {
	t.Parallel()

	var ranProbe bool
	m := newTestManager(t, &fakeSpawner{}, func(o *Options) {
		o.KnownHosts = func(sshprofile.Profile) (bool, bool) { return false, true }
		o.TestRunner = func([]string) (bool, string, error) {
			ranProbe = true
			return false, "Host key verification failed.", nil
		}
	})

	result, err := m.Test("sb-devbox")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !ranProbe {
		t.Fatal("Test never ran the probe despite an untrusted host — known_hosts must not gate the probe")
	}
	if !result.KnownHostsChecked || result.KnownHostsOK {
		t.Fatalf("KnownHostsChecked=%v KnownHostsOK=%v, want true/false", result.KnownHostsChecked, result.KnownHostsOK)
	}
	if result.AuthOK {
		t.Fatal("AuthOK = true, want false")
	}
}

// TestTestNoVerdictIsHonestlyReported pins the two-value known-hosts contract
// surfacing through TestResult: "could not check" must never collapse into
// either true or false.
func TestTestNoVerdictIsHonestlyReported(t *testing.T) {
	t.Parallel()

	m := newTestManager(t, &fakeSpawner{}, func(o *Options) {
		o.KnownHosts = func(sshprofile.Profile) (bool, bool) { return false, false }
		o.TestRunner = func([]string) (bool, string, error) { return true, "", nil }
	})

	result, err := m.Test("sb-devbox")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if result.KnownHostsChecked {
		t.Fatal("KnownHostsChecked = true, want false (no verdict)")
	}
	if result.KnownHostsOK {
		t.Fatal("KnownHostsOK = true despite no verdict")
	}
}

// TestTestRefusesUnknownProfile pins that Test resolves against the SAME
// allow-list as Connect/Disconnect and never runs a probe for a name nobody
// configured.
func TestTestRefusesUnknownProfile(t *testing.T) {
	t.Parallel()

	var ran bool
	m := newTestManager(t, &fakeSpawner{}, func(o *Options) {
		o.TestRunner = func([]string) (bool, string, error) { ran = true; return true, "", nil }
	})

	if _, err := m.Test("nope"); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("Test error = %v, want ErrUnknownProfile", err)
	}
	if ran {
		t.Fatal("Test ran the probe for an unknown profile")
	}
}

// TestTestDisabledManagerRefuses pins the same kill switch Connect honors.
func TestTestDisabledManagerRefuses(t *testing.T) {
	t.Parallel()

	m := newTestManager(t, &fakeSpawner{}, func(o *Options) { o.Enabled = false })
	if _, err := m.Test("sb-devbox"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Test error = %v, want ErrDisabled", err)
	}
}

// TestTestRunnerFailureToStartIsAnError pins the OTHER half of the contract:
// when the probe itself could not run (e.g. ssh missing), that IS an error —
// distinct from a probe that ran and failed to authenticate.
func TestTestRunnerFailureToStartIsAnError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("exec: \"ssh\": executable file not found in $PATH")
	m := newTestManager(t, &fakeSpawner{}, func(o *Options) {
		o.TestRunner = func([]string) (bool, string, error) { return false, "", wantErr }
	})

	_, err := m.Test("sb-devbox")
	if !errors.Is(err, ErrForwardFailed) {
		t.Fatalf("Test error = %v, want ErrForwardFailed", err)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("Test error = %v, want it to wrap %v", err, wantErr)
	}
}

// TestTestNilManagerIsHonestNotFatal mirrors TestNilManagerIsHonestNotFatal
// for the Test verb.
func TestTestNilManagerIsHonestNotFatal(t *testing.T) {
	t.Parallel()

	var m *Manager
	if _, err := m.Test("sb-devbox"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("nil Test = %v, want ErrDisabled", err)
	}
}

// TestCloseKillsEveryForward pins the daemon-exit contract: no `ssh -N` child
// outlives the process that opened it.
func TestCloseKillsEveryForward(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	ports := []int{40001, 40002}
	idx := 0
	m := newTestManager(t, sp, func(o *Options) {
		o.AllocPort = func() (int, error) {
			p := ports[idx]
			idx++
			return p, nil
		}
	})
	if _, err := m.Connect("sb-devbox"); err != nil {
		t.Fatalf("Connect sb-devbox: %v", err)
	}
	if _, err := m.Connect("other"); err != nil {
		t.Fatalf("Connect other: %v", err)
	}

	m.Close()

	for i := 0; i < 2; i++ {
		if got := sp.proc(i).stopCount(); got != 1 {
			t.Fatalf("child %d stopped %d times, want 1", i, got)
		}
	}
	for _, inst := range m.List() {
		if inst.State != StateDisconnected {
			t.Fatalf("%s state after Close = %q, want disconnected", inst.Name, inst.State)
		}
	}
	// A Connect after Close must not resurrect a forward.
	if _, err := m.Connect("sb-devbox"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Connect after Close = %v, want ErrDisabled", err)
	}
}

// TestChildDeathBecomesAnHonestErrorRow pins that a forward whose ssh dies stops
// being advertised as connected: the row flips to error with ssh's own reason,
// so the UI never offers a link to a dead port.
func TestChildDeathBecomesAnHonestErrorRow(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, nil)
	if _, err := m.Connect("sb-devbox"); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	proc := sp.proc(0)
	proc.mu.Lock()
	proc.stderr = "Host key verification failed.\r\n"
	proc.mu.Unlock()
	proc.die(errors.New("exit status 255"))

	deadline := time.Now().Add(2 * time.Second)
	for {
		inst, _ := m.Get("sb-devbox")
		if inst.State == StateError {
			if !strings.Contains(inst.Error, "Host key verification failed") {
				t.Fatalf("error row reason = %q, want ssh's own stderr", inst.Error)
			}
			if inst.URL != "" {
				t.Fatalf("a dead forward still advertises URL %q", inst.URL)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("forward never flipped to error; state = %q", inst.State)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestConnectRetriesAfterAFailedForward pins that a dead/failed row is REPLACED
// on the next Connect rather than being handed back as a live forward.
func TestConnectRetriesAfterAFailedForward(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, nil)
	if _, err := m.Connect("sb-devbox"); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	sp.proc(0).die(errors.New("exit status 255"))

	deadline := time.Now().Add(2 * time.Second)
	for {
		if inst, _ := m.Get("sb-devbox"); inst.State == StateError {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("forward never flipped to error")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := m.Connect("sb-devbox"); err != nil {
		t.Fatalf("re-Connect: %v", err)
	}
	if got := sp.count(); got != 2 {
		t.Fatalf("spawned %d children, want 2 (the failed one must be replaced, not reused)", got)
	}
}

// TestConnectFailsWhenForwardNeverComesUp pins the readiness contract: a child
// that starts but never binds is a failure, the child is killed, and ssh's own
// stderr is carried into the message.
func TestConnectFailsWhenForwardNeverComesUp(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, func(o *Options) {
		o.Probe = func(int) error { return errors.New("connection refused") }
	})
	sp.mu.Lock()
	sp.onSpawn = func(p *fakeProcess) {
		p.mu.Lock()
		p.stderr = "bind [127.0.0.1]:40001: Address already in use\n"
		p.mu.Unlock()
	}
	sp.mu.Unlock()

	_, err := m.Connect("sb-devbox")
	if !errors.Is(err, ErrForwardFailed) {
		t.Fatalf("Connect error = %v, want ErrForwardFailed", err)
	}
	if !strings.Contains(err.Error(), "Address already in use") {
		t.Fatalf("error %q drops ssh's own reason", err)
	}
	if got := sp.proc(0).stopCount(); got != 1 {
		t.Fatalf("failed child stopped %d times, want 1 — a timed-out attempt must not leak a process", got)
	}
	if inst, _ := m.Get("sb-devbox"); inst.State != StateDisconnected {
		t.Fatalf("state after a failed connect = %q, want disconnected", inst.State)
	}
}

// TestConnectStopsWaitingWhenTheChildDies pins that a child exiting during the
// readiness wait ends it immediately instead of burning the whole timeout.
func TestConnectStopsWaitingWhenTheChildDies(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	sp.onSpawn = func(p *fakeProcess) { p.die(errors.New("exit status 255")) }
	m := newTestManager(t, sp, func(o *Options) {
		o.Probe = func(int) error { return errors.New("connection refused") }
		o.ReadyTimeout = 10 * time.Second // must NOT be waited out
	})

	start := time.Now()
	_, err := m.Connect("sb-devbox")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrForwardFailed) {
		t.Fatalf("Connect error = %v, want ErrForwardFailed", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("waited %s for a child that had already exited", elapsed)
	}
}

// TestDisabledManagerRefusesEverything pins the [terminal.ssh].enabled kill
// switch.
func TestDisabledManagerRefusesEverything(t *testing.T) {
	t.Parallel()

	sp := &fakeSpawner{}
	m := newTestManager(t, sp, func(o *Options) { o.Enabled = false })
	if m.Enabled() {
		t.Fatal("Enabled() true for a disabled manager")
	}
	if _, err := m.Connect("sb-devbox"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Connect error = %v, want ErrDisabled", err)
	}
	if got := sp.count(); got != 0 {
		t.Fatalf("spawned %d children while disabled, want 0", got)
	}
	// List still enumerates, so the UI can explain WHY the switcher is inert
	// rather than silently showing nothing.
	if got := len(m.List()); got != 2 {
		t.Fatalf("List returned %d rows while disabled, want 2", got)
	}
}

// TestListReportsDisconnectedByDefault pins the zero state.
func TestListReportsDisconnectedByDefault(t *testing.T) {
	t.Parallel()

	m := newTestManager(t, &fakeSpawner{}, nil)
	rows := m.List()
	if len(rows) != 2 {
		t.Fatalf("List returned %d rows, want 2", len(rows))
	}
	for _, r := range rows {
		if r.State != StateDisconnected || r.URL != "" || r.LocalPort != 0 {
			t.Fatalf("%s: %+v, want a bare disconnected row", r.Name, r)
		}
	}
	if rows[0].Label != "Dev box" {
		t.Fatalf("Label = %q, want the operator's label", rows[0].Label)
	}
	if rows[1].Label != "other" {
		t.Fatalf("Label = %q, want the name as fallback", rows[1].Label)
	}
	if rows[1].DashboardPort != 9099 || rows[0].DashboardPort != sshprofile.DefaultDashboardPort {
		t.Fatalf("dashboard ports = %d/%d", rows[0].DashboardPort, rows[1].DashboardPort)
	}
}

// TestNilManagerIsHonestNotFatal pins the degraded-wiring path: a daemon with no
// terminal stack must report "nothing here", never panic.
func TestNilManagerIsHonestNotFatal(t *testing.T) {
	t.Parallel()

	var m *Manager
	if m.Enabled() {
		t.Fatal("nil manager reports enabled")
	}
	if got := m.List(); got != nil {
		t.Fatalf("nil manager listed %v", got)
	}
	if _, ok := m.Get("sb-devbox"); ok {
		t.Fatal("nil manager resolved a profile")
	}
	if _, err := m.Connect("sb-devbox"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("nil Connect = %v, want ErrDisabled", err)
	}
	if err := m.Disconnect("sb-devbox"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("nil Disconnect = %v, want ErrDisabled", err)
	}
	m.Close() // must not panic
}

// TestTrimTailStripsControlSequences pins that ssh stderr reaching a UI can
// never carry an escape sequence, and is bounded.
func TestTrimTailStripsControlSequences(t *testing.T) {
	t.Parallel()

	got := trimTail("Host key\x1b[31m verification\r\n\tfailed.\x00")
	if strings.ContainsAny(got, "\x1b\x00\r\n\t") {
		t.Fatalf("trimTail left control bytes in %q", got)
	}
	if got != "Host key[31m verification failed." {
		t.Fatalf("trimTail = %q", got)
	}
	if len(trimTail(strings.Repeat("x", 5000))) > 240 {
		t.Fatal("trimTail is unbounded")
	}
}
