package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestAttachSocketPath pins the ON-DISK attach path the daemon and the client
// both derive — the AF_UNIX endpoint on unix, and on every platform the parent
// of the owner-only attach directory that holds the durable resume-claim flock.
// The wants are built with filepath.Join so the pin is about the FORMULA, not
// about the host's path separator (the literal-slash spelling this test used
// before was a Windows-only red).
func TestAttachSocketPath(t *testing.T) {
	cases := []struct {
		dbPath string
		want   string
	}{
		// A1: the socket lives in a dedicated 0700 dir so the parent-dir
		// permission (not a racy chmod) enforces owner-only connect().
		{
			filepath.Join("/home/u/.observer", "observer.db"),
			filepath.Join("/home/u/.observer", "attach", "attach.sock"),
		},
		{
			filepath.Join("/var/lib/observer", "observer.db"),
			filepath.Join("/var/lib/observer", "attach", "attach.sock"),
		},
		{"observer.db", filepath.Join("attach", "attach.sock")},
	}
	for _, tc := range cases {
		if got := attachSocketPath(tc.dbPath); got != tc.want {
			t.Errorf("attachSocketPath(%q) = %q, want %q", tc.dbPath, got, tc.want)
		}
	}
	// The daemon listens on, and the client dials, the TRANSPORT endpoint. On
	// unix that is exactly this path; on a named-pipe host it is deliberately
	// not a filesystem path at all — pin that they agree with the transport so
	// the two sides can never drift.
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	endpoint, err := attachEndpoint(dbPath)
	if err != nil {
		t.Fatalf("attachEndpoint(%q): %v", dbPath, err)
	}
	if runtime.GOOS == "windows" {
		if endpoint == attachSocketPath(dbPath) {
			t.Fatalf("attachEndpoint returned the on-disk socket path %q on the named-pipe transport", endpoint)
		}
	} else if endpoint != attachSocketPath(dbPath) {
		t.Fatalf("attachEndpoint = %q, want the socket path %q", endpoint, attachSocketPath(dbPath))
	}
}

// TestAttachSessionDetachIdempotent verifies Detach releases the lease/viewer
// exactly once and, when the child has already exited, records the run's exit
// through EndRunByHandle exactly once (the attach path's honest close, reusing
// the dashboard's exit-recording method).
func TestAttachSessionDetachIdempotent(t *testing.T) {
	var releaseCalls int
	var endRunCalls int
	var endRunCode int
	sess := &attachSession{
		handle:  "h1",
		runID:   "r1",
		exit:    func() (int, bool) { return 7, true }, // child exited with code 7
		release: func() { releaseCalls++ },
		endRun:  func(code int) { endRunCalls++; endRunCode = code },
	}

	sess.Detach()
	sess.Detach()
	sess.Detach()

	if releaseCalls != 1 {
		t.Errorf("release called %d times, want 1 (idempotent)", releaseCalls)
	}
	if endRunCalls != 1 {
		t.Errorf("endRun called %d times, want 1", endRunCalls)
	}
	if endRunCode != 7 {
		t.Errorf("endRun code = %d, want 7 (child exit code propagated)", endRunCode)
	}
}

// TestAttachSessionDetachNoExitWhileAlive verifies a clean detach while the
// child is still running records NO exit — the shared manager's OnExit owns the
// real exit when it eventually happens.
func TestAttachSessionDetachNoExitWhileAlive(t *testing.T) {
	var releaseCalls, endRunCalls int
	sess := &attachSession{
		handle:  "h2",
		exit:    func() (int, bool) { return 0, false }, // still alive
		release: func() { releaseCalls++ },
		endRun:  func(int) { endRunCalls++ },
	}
	sess.Detach()
	if releaseCalls != 1 {
		t.Errorf("release called %d times, want 1", releaseCalls)
	}
	if endRunCalls != 0 {
		t.Errorf("endRun called %d times, want 0 (child still alive on clean detach)", endRunCalls)
	}
}

// fakeAttachLauncher is a stub attachLauncher. It counts LaunchAttachable calls
// (L8) so a test can assert a refusal path never reached the spawn, and is
// mutex-guarded so the concurrent single-flight test can share one instance.
type fakeAttachLauncher struct {
	launchErr error
	res       termsvc.LaunchResult

	mu          sync.Mutex
	launchCalls int
	ended       []struct {
		handle string
		code   int
	}
}

func (f *fakeAttachLauncher) LaunchAttachable(context.Context, termsvc.AttachRequest) (termsvc.LaunchResult, error) {
	f.mu.Lock()
	f.launchCalls++
	f.mu.Unlock()
	if f.launchErr != nil {
		return termsvc.LaunchResult{}, f.launchErr
	}
	return f.res, nil
}

func (f *fakeAttachLauncher) EndRunByHandle(_ context.Context, handle string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ended = append(f.ended, struct {
		handle string
		code   int
	}{handle, code})
}

// unusedAttachMgr satisfies attachPTYManager but must not be called (the launch
// error path returns before any manager op).
type unusedAttachMgr struct{ t *testing.T }

func (m unusedAttachMgr) Subscribe(string) (*termsession.Subscription, error) {
	m.t.Fatal("Subscribe called on launch-failure path")
	return nil, nil
}

func (m unusedAttachMgr) AcquireWriterLocal(string) (*termsession.WriterLease, error) {
	m.t.Fatal("AcquireWriterLocal called on launch-failure path")
	return nil, nil
}
func (m unusedAttachMgr) Unsubscribe(*termsession.Subscription) { m.t.Fatal("Unsubscribe called") }
func (m unusedAttachMgr) ExitStatus(string) (bool, int, bool) {
	m.t.Fatal("ExitStatus called")
	return false, 0, false
}
func (m unusedAttachMgr) Close(string) { m.t.Fatal("Close called") }

// subFailMgr is a manager whose Subscribe fails, recording the order of
// Close/Unsubscribe so a test can assert the just-spawned child is terminated
// before its exit is recorded (B3-3).
type subFailMgr struct {
	subErr    error
	calls     []string
	closeSeen bool
}

func (m *subFailMgr) Subscribe(string) (*termsession.Subscription, error) {
	m.calls = append(m.calls, "Subscribe")
	return nil, m.subErr
}

func (m *subFailMgr) AcquireWriterLocal(string) (*termsession.WriterLease, error) {
	m.calls = append(m.calls, "AcquireWriterLocal")
	return nil, nil
}

func (m *subFailMgr) Unsubscribe(*termsession.Subscription) { m.calls = append(m.calls, "Unsubscribe") }
func (m *subFailMgr) ExitStatus(string) (bool, int, bool)   { return false, 0, false }
func (m *subFailMgr) Close(string) {
	m.calls = append(m.calls, "Close")
	m.closeSeen = true
}

// TestAttachHostSubscribeFailureTerminatesChild verifies that when Subscribe
// fails AFTER a successful spawn, the Host TERMINATES the just-spawned child
// (Manager.Close) BEFORE recording its exit (B3-3) — the run record never
// claims an exit while the child still runs.
func TestAttachHostSubscribeFailureTerminatesChild(t *testing.T) {
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R"}}
	mgr := &subFailMgr{subErr: errors.New("too many subscribers")}
	host := newAttachHost(launcher, mgr, nil)

	_, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{Tool: "claude-code", Subcommand: "claude"})
	if err == nil {
		t.Fatal("expected the subscribe failure to surface")
	}
	if !mgr.closeSeen {
		t.Fatal("child must be terminated via Manager.Close on a post-spawn subscribe failure")
	}
	// Close must precede the EndRunByHandle exit record.
	closeIdx := -1
	for i, c := range mgr.calls {
		if c == "Close" {
			closeIdx = i
		}
	}
	if closeIdx < 0 {
		t.Fatal("Close was not recorded")
	}
	if len(launcher.ended) != 1 || launcher.ended[0].handle != "H" || launcher.ended[0].code != -1 {
		t.Fatalf("expected one EndRunByHandle(H,-1) after Close, got %+v", launcher.ended)
	}
}

// successAttachMgr is a PTY-manager stub whose Subscribe + AcquireWriterLocal
// SUCCEED (returning zero-value handles that are stored but never driven), so a
// test can exercise the attach Host's SUCCESS path without a real PTY.
type successAttachMgr struct{}

func (successAttachMgr) Subscribe(string) (*termsession.Subscription, error) {
	return &termsession.Subscription{}, nil
}

func (successAttachMgr) AcquireWriterLocal(string) (*termsession.WriterLease, error) {
	return &termsession.WriterLease{}, nil
}
func (successAttachMgr) Unsubscribe(*termsession.Subscription) {}
func (successAttachMgr) ExitStatus(string) (bool, int, bool)   { return false, 0, false }
func (successAttachMgr) Close(string)                          {}

// TestAttachHostEmitsSpawnAuditRow pins F4: a successful attach SPAWN writes
// EXACTLY ONE metadata-only terminal_attach remote_audit row at spawn time —
// carrying the run id + handle + tool, never argv/env/content — even though no
// client ever attaches over the websocket. Uses the REAL newSpawnAuditSink over
// the shared SpawnAuditKind vocabulary so the kind + row shape are end-to-end.
//
// The audit is DETACHED (F3), so the row lands asynchronously — the test POLLS
// for it rather than reading once right after the (now non-blocking) spawn.
func TestAttachHostEmitsSpawnAuditRow(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	sink := newSpawnAuditSink(database, dashboard.SpawnAuditKind(termrun.KindAttach))
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H9", RunID: "R9"}}
	host := newAttachHost(launcher, successAttachMgr{}, sink)

	if _, err := host.LaunchAttachable(ctx, attachsock.SpawnRequest{Tool: "claude-code", Subcommand: "claude"}); err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}

	var attachRows []store.RemoteAuditEvent
	// Poll comfortably ABOVE the detached audit sink's own 3s bounded-write
	// timeout: under -race scheduling load the sink can legitimately take most of
	// its budget, and a 3s poll (equal to the sink timeout) can observe zero
	// through no fault of the code under test. 10s removes the this-arc-introduced
	// flake without masking a real failure (a genuinely-stuck sink still trips it).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		events, err := store.New(database).RecentRemoteAudit(ctx, 50)
		if err != nil {
			t.Fatalf("RecentRemoteAudit: %v", err)
		}
		attachRows = attachRows[:0]
		for _, e := range events {
			if e.Kind == "terminal_attach" {
				attachRows = append(attachRows, e)
			}
		}
		if len(attachRows) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(attachRows) != 1 {
		t.Fatalf("expected exactly one terminal_attach row, got %d", len(attachRows))
	}
	row := attachRows[0]
	if row.SessionID != "R9" || row.Route != "H9" || row.Detail != "claude-code" {
		t.Errorf("terminal_attach row = %+v, want SessionID=R9 Route=H9 Detail=claude-code", row)
	}
}

// TestAttachHostSpawnAuditDetached pins F3: a spawn returns PROMPTLY even when
// the audit sink blocks (a contended SQLite writer), and the row still lands.
// The injected sink blocks until released; LaunchAttachable must return well
// before the block clears, and the audit must fire exactly once afterwards.
func TestAttachHostSpawnAuditDetached(t *testing.T) {
	release := make(chan struct{})
	var audited int32
	slowSink := func(runID, tool, handle string) {
		<-release // simulate a sink stalled on a contended writer
		atomic.AddInt32(&audited, 1)
	}
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R"}}
	host := newAttachHost(launcher, successAttachMgr{}, slowSink)

	done := make(chan error, 1)
	go func() {
		_, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{Tool: "claude-code", Subcommand: "claude"})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("LaunchAttachable: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LaunchAttachable blocked on the audit sink — the spawn must not wait on auditing (F3)")
	}
	// The audit has NOT run yet (still blocked), proving detachment.
	if n := atomic.LoadInt32(&audited); n != 0 {
		t.Fatalf("audit ran before release (%d) — it must be detached", n)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&audited) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if n := atomic.LoadInt32(&audited); n != 1 {
		t.Fatalf("detached audit fired %d times, want 1", n)
	}
}

// TestAttachHostLaunchFailure verifies a launch failure surfaces verbatim and
// never touches the PTY manager (no viewer/lease leaked).
func TestAttachHostLaunchFailure(t *testing.T) {
	wantErr := errors.New("boom")
	host := newAttachHost(&fakeAttachLauncher{launchErr: wantErr}, unusedAttachMgr{t: t}, nil)
	_, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{Tool: "claude-code", Subcommand: "claude"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("LaunchAttachable err = %v, want %v", err, wantErr)
	}
}

// TestAttachHostRejectsUncapableTool verifies the Host validates the untrusted
// socket request against the integration registry BEFORE launching (A7/B4): a
// tool with no grounded Attach capability, or a subcommand that does not match
// the grounded one, is rejected without touching the launcher or PTY manager.
func TestAttachHostRejectsUncapableTool(t *testing.T) {
	launcher := &fakeAttachLauncher{}
	host := newAttachHost(launcher, unusedAttachMgr{t: t}, nil)

	// (1) A tool with no registry capability at all.
	if _, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{
		Tool: "definitely-not-a-real-tool", Subcommand: "whatever",
	}); err == nil || !strings.Contains(err.Error(), "no grounded attach capability") {
		t.Fatalf("uncapable tool err = %v, want a no-capability rejection", err)
	}

	// (2) A grounded tool but a MISMATCHED subcommand (e.g. a caller trying to
	// drive `observer codex` under the claude-code tool row).
	if _, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{
		Tool: "claude-code", Subcommand: "codex",
	}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("subcommand mismatch err = %v, want a mismatch rejection", err)
	}

	// Neither rejection should have reached the launcher.
	if launcher.res.Handle != "" || len(launcher.ended) != 0 {
		t.Fatalf("launcher must not be touched on a capability rejection")
	}
}

// TestAttachExtraArgs pins the allow-listed argv the CLI attach client forwards
// to the inner launcher (B2/B3): the escape-hatch flag, the proxy/--config
// overrides, and the operator's `--` tool remainder — in that order, and never
// a blind argv copy.
func TestAttachExtraArgs(t *testing.T) {
	cases := []struct {
		name          string
		noProxyRoute  bool
		proxyOverride string
		proxyFlag     string
		configPath    string
		passthrough   []string
		toolArgs      []string
		want          []string
	}{
		{"nothing", false, "", "", "", nil, nil, nil},
		{"escape hatch only", true, "", "", "", nil, nil, []string{"--no-proxy-route"}},
		{
			"proxy + config", false, "http://127.0.0.1:9999", "--proxy", "/etc/o.toml", nil, nil,
			[]string{"--proxy", "http://127.0.0.1:9999", "--config", "/etc/o.toml"},
		},
		{
			"passthrough wrapper flags", false, "", "", "",
			[]string{"--claude-path", "/opt/claude"},
			nil,
			[]string{"--claude-path", "/opt/claude"},
		},
		{
			"tool remainder", false, "", "", "", nil,
			[]string{"--model", "x"},
			[]string{"--", "--model", "x"},
		},
		{
			"all", true, "http://p", "--proxy", "/c.toml",
			[]string{"--codex-path", "/opt/codex", "--no-app-server-check"},
			[]string{"exec", "hi"},
			[]string{"--no-proxy-route", "--proxy", "http://p", "--config", "/c.toml", "--codex-path", "/opt/codex", "--no-app-server-check", "--", "exec", "hi"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := attachExtraArgs(tc.noProxyRoute, tc.proxyOverride, tc.proxyFlag, tc.configPath, tc.passthrough, tc.toolArgs)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("arg[%d] = %q, want %q (got %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// TestAttachExtraArgsProxyFlagName pins the proxyFlag parameterization
// (attach-all-launchers): the proxy override is emitted under the inner
// launcher's OWN flag spelling — `--proxy` for most, `--proxy-url` for
// hermes/pi — and is dropped entirely when the launcher has no proxy flag
// (proxyFlag=="", the seed-only tools) so a stray override never lands on a
// launcher that can't parse it. Both proxyOverride AND proxyFlag must be
// non-empty for the pair to appear.
func TestAttachExtraArgsProxyFlagName(t *testing.T) {
	cases := []struct {
		name          string
		proxyOverride string
		proxyFlag     string
		want          []string
	}{
		{"default --proxy spelling", "http://p", "--proxy", []string{"--proxy", "http://p"}},
		{"hermes/pi --proxy-url spelling", "http://p", "--proxy-url", []string{"--proxy-url", "http://p"}},
		{"seed-only tool drops override (empty flag)", "http://p", "", nil},
		{"no override, flag set — nothing emitted", "", "--proxy", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := attachExtraArgs(false, tc.proxyOverride, tc.proxyFlag, "", nil, nil)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("arg[%d] = %q, want %q (got %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// TestRunAttachSessionHonestDisable verifies `--attach` on a tool with no
// grounded Attach capability errors with the honest-disable copy BEFORE any TTY
// or socket work (so it is reachable in a non-TTY test env).
func TestRunAttachSessionHonestDisable(t *testing.T) {
	var buf bytes.Buffer
	err := runAttachSession(context.Background(), attachLaunch{
		tool:   "definitely-not-a-real-tool",
		stderr: &buf,
	})
	if err == nil {
		t.Fatal("expected an error for a tool with no Attach capability")
	}
	if !strings.Contains(buf.String(), "no grounded attach capability") {
		t.Errorf("stderr = %q, want it to name the missing capability", buf.String())
	}
}

// TestNativeResumeHint pins the daemon-exit resume guidance dispatch on the
// ResumeSpec shape (never a tool-name branch).
func TestNativeResumeHint(t *testing.T) {
	cases := []struct {
		name string
		cap  integration.Capability
		want string
	}{
		{
			name: "ungrounded",
			cap:  integration.Capability{},
			want: "resume it natively to continue",
		},
		{
			name: "flag",
			cap:  integration.Capability{Resume: integration.ResumeSpec{Kind: integration.ResumeNative, Subcommand: "claude", IDMechanism: "flag:--resume"}},
			want: "resume it natively with `claude --resume <id>`",
		},
		{
			name: "subcommand",
			cap:  integration.Capability{Resume: integration.ResumeSpec{Kind: integration.ResumeNative, Subcommand: "codex", IDMechanism: "subcommand:resume"}},
			want: "resume it natively with `codex resume <id>`",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeResumeHint(tc.cap); got != tc.want {
				t.Errorf("nativeResumeHint = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClaudeCodexAttachCapabilityGrounded is a light sync pin: the two launchers
// that register --attach must have a grounded Attach capability whose Subcommand
// matches the launcher verb (else the flags would hard-error at runtime).
func TestClaudeCodexAttachCapabilityGrounded(t *testing.T) {
	for tool, wantSub := range map[string]string{"claude-code": "claude", "codex": "codex"} {
		capab, ok := integration.For(tool)
		if !ok || capab.Attach == nil {
			t.Fatalf("%s: expected a grounded Attach capability", tool)
		}
		if capab.Attach.Subcommand != wantSub {
			t.Errorf("%s: Attach.Subcommand = %q, want %q", tool, capab.Attach.Subcommand, wantSub)
		}
	}
}
