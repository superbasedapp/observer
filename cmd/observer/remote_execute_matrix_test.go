package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/remoteauth"
	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termlease"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// --- fakes for a real, process-free termsession/termsvc assembly ---

type fakePTY struct{ done chan struct{} }

func newFakePTY() *fakePTY { return &fakePTY{done: make(chan struct{})} }

func (p *fakePTY) Read([]byte) (int, error)    { <-p.done; return 0, io.EOF }
func (p *fakePTY) Write(b []byte) (int, error) { return len(b), nil }
func (p *fakePTY) Resize(uint16, uint16) error { return nil }
func (p *fakePTY) Wait() (int, error)          { <-p.done; return 0, nil }
func (p *fakePTY) Kill() error {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	return nil
}
func (p *fakePTY) Close() error { return nil }

type fakeSpawner struct{}

func (fakeSpawner) Spawn(termsession.Spec) (termsession.PTY, error) { return newFakePTY(), nil }

type nopRunRecorder struct{}

func (nopRunRecorder) RecordRun(context.Context, termrun.Run) error                 { return nil }
func (nopRunRecorder) EndRun(context.Context, string, time.Time, int, string) error { return nil }
func (nopRunRecorder) RecordCorrelation(context.Context, termrun.Correlation) error { return nil }
func (nopRunRecorder) RecordGUISpawn(context.Context, termrun.Run) error            { return nil }

type mgrLauncher struct{ mgr *termsession.Manager }

func (l mgrLauncher) Spawn(req termsvc.LaunchRequest) (string, error) {
	return l.mgr.Create(termsession.Spec{
		BinPath:    "/observer",
		Subcommand: req.Subcommand,
		SessionID:  req.SessionID,
		ArgvMode:   argvModeForKind(req.Kind),
	})
}

// executeHarness is a fully-assembled remote-execute stack (the same components
// observer dashboard / observer start wire via wireRemoteExecuteTier) with a
// process-free PTY spawner.
type executeHarness struct {
	adapter *launchManagerAdapter
	rc      dashboard.RemoteController
	mgr     *termsession.Manager
	device  string // valid raw device-session id
	handle  string // live, termsvc-tracked handle
	allow   *atomic.Bool
}

func newExecuteHarness(t *testing.T) *executeHarness {
	t.Helper()
	mgr := termsession.NewManager(termsession.Options{Spawner: fakeSpawner{}})
	t.Cleanup(mgr.Shutdown)
	svc := termsvc.New(termsvc.Options{
		Recorder: nopRunRecorder{},
		Launcher: mgrLauncher{mgr: mgr},
		Feed:     termfeed.New(termfeed.Options{}),
	})
	// Launch a handoff → a live, termsvc-tracked handle (the LaunchPolicy leg).
	res, err := svc.LaunchHandoff(context.Background(), termsvc.HandoffRequest{
		Tool: "claude-code", Subcommand: "claude", SessionID: "src-session",
	})
	if err != nil {
		t.Fatalf("LaunchHandoff: %v", err)
	}

	// A real, Ready() remote controller with a known secret; pair a device.
	raw, enc, err := remoteauth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	hash, err := remoteauth.HashSecret(raw)
	if err != nil {
		t.Fatalf("HashSecret: %v", err)
	}
	rc := dashboard.NewRemoteController(dashboard.RemoteOptions{
		HashedSecret:    hash,
		AllowedHosts:    []string{"remote.example:8443"},
		RateLimitPerMin: 60,
		Session:         remoteauth.SessionParams{TTL: time.Hour, Idle: time.Hour, Max: 5},
	})
	device := pairDevice(t, rc, enc)

	adapter := &launchManagerAdapter{svc: svc, mgr: mgr}
	allow := &atomic.Bool{}
	allow.Store(true)
	// Exactly the wiring wireRemoteExecuteTier performs for both commands.
	authz, ok := rc.(dashboard.TerminalControlAuthorizer)
	if !ok {
		t.Fatal("remote controller does not implement TerminalControlAuthorizer")
	}
	adapter.wireRemoteExecute(authz, func() bool { return allow.Load() })

	return &executeHarness{adapter: adapter, rc: rc, mgr: mgr, device: device, handle: res.Handle, allow: allow}
}

// pairDevice drives the controller's own /api/remote/pair route to obtain a
// valid device-session cookie (the raw session id).
func pairDevice(t *testing.T, rc dashboard.RemoteController, encSecret string) string {
	t.Helper()
	var pair http.HandlerFunc
	for _, rt := range rc.Routes() {
		if rt.Pattern == "/api/remote/pair" {
			pair = rt.Handler
		}
	}
	if pair == nil {
		t.Fatal("no /api/remote/pair route")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/remote/pair", strings.NewReader(`{"secret":"`+encSecret+`"}`))
	rec := httptest.NewRecorder()
	pair(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pair = %d: %s", rec.Code, rec.Body.String())
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "sb_remote_session" {
			return ck.Value
		}
	}
	t.Fatal("pair returned no session cookie")
	return ""
}

// mintCap mints a fresh valid terminal-control capability + confirm for the
// harness's device + handle (the local approve-execute step).
func (h *executeHarness) mintCap(t *testing.T) (capTok, confirm string) {
	t.Helper()
	authz := h.rc.(dashboard.TerminalControlAuthorizer)
	// MintTerminalControl takes the device-session HASH (what Sessions() surfaces).
	hashID := h.rc.Sessions()[0].ID
	tok, cfm, err := authz.MintTerminalControl(hashID, h.handle)
	if err != nil {
		t.Fatalf("MintTerminalControl: %v", err)
	}
	return tok, cfm
}

// resetWriter clears any live writer lease so the next cell starts clean.
func (h *executeHarness) resetWriter() { h.mgr.RevokeWriter(h.handle, "test-reset") }

// validReq builds an all-legs-valid request with a fresh capability.
func (h *executeHarness) validReq(t *testing.T) dashboard.RemoteWriterRequest {
	capTok, confirm := h.mintCap(t)
	return dashboard.RemoteWriterRequest{
		Handle:          h.handle,
		DeviceSessionID: h.device,
		CapabilityToken: capTok,
		Confirm:         confirm,
		RemoteExposed:   true,
	}
}

func runAuthorizationMatrix(t *testing.T) {
	t.Helper()
	h := newExecuteHarness(t)

	// The ONE designed grant cell: every leg valid.
	t.Run("grant/all-valid", func(t *testing.T) {
		h.allow.Store(true)
		w, err := h.adapter.AcquireWriterRemote(h.validReq(t))
		if err != nil || w == nil {
			t.Fatalf("all-valid must GRANT, got writer=%v err=%v", w, err)
		}
		h.resetWriter()
	})

	// Pre-consume denials: the capability is NOT burned, proven by a follow-up
	// all-valid acquire with the SAME capability succeeding.
	preConsumeCells := []struct {
		name   string
		mutate func(*executeHarness, *dashboard.RemoteWriterRequest)
		want   error
	}{
		{"deny/not-remote-exposed", func(_ *executeHarness, r *dashboard.RemoteWriterRequest) { r.RemoteExposed = false }, termlease.ErrNotRemoteExposed},
		{"deny/allow-terminal-off", func(hh *executeHarness, _ *dashboard.RemoteWriterRequest) { hh.allow.Store(false) }, termlease.ErrTerminalDisabled},
		{"deny/bad-device-session", func(_ *executeHarness, r *dashboard.RemoteWriterRequest) { r.DeviceSessionID = "not-a-session" }, termlease.ErrNoDeviceSession},
		{"deny/policy-unknown-handle", func(_ *executeHarness, r *dashboard.RemoteWriterRequest) { r.Handle = "UNKNOWN-HANDLE" }, termlease.ErrPolicyDenied},
		{"deny/missing-device", func(_ *executeHarness, r *dashboard.RemoteWriterRequest) { r.DeviceSessionID = "" }, termlease.ErrMissingField},
	}
	for _, c := range preConsumeCells {
		t.Run(c.name, func(t *testing.T) {
			h.allow.Store(true)
			capTok, confirm := h.mintCap(t)
			req := dashboard.RemoteWriterRequest{
				Handle: h.handle, DeviceSessionID: h.device,
				CapabilityToken: capTok, Confirm: confirm, RemoteExposed: true,
			}
			c.mutate(h, &req)
			if _, err := h.adapter.AcquireWriterRemote(req); !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
			// The capability must have survived (not consumed pre-consume): a
			// fresh all-valid acquire with the SAME cap now grants.
			h.allow.Store(true)
			w, err := h.adapter.AcquireWriterRemote(dashboard.RemoteWriterRequest{
				Handle: h.handle, DeviceSessionID: h.device,
				CapabilityToken: capTok, Confirm: confirm, RemoteExposed: true,
			})
			if err != nil || w == nil {
				t.Fatalf("capability was consumed by a PRE-consume denial (%s): re-acquire err=%v", c.name, err)
			}
			h.resetWriter()
		})
	}

	// Wrong confirm consumes NOTHING (§4.γ.2) — the cap survives for a retry.
	t.Run("deny/wrong-confirm-survives", func(t *testing.T) {
		h.allow.Store(true)
		capTok, confirm := h.mintCap(t)
		if _, err := h.adapter.AcquireWriterRemote(dashboard.RemoteWriterRequest{
			Handle: h.handle, DeviceSessionID: h.device,
			CapabilityToken: capTok, Confirm: "wrong", RemoteExposed: true,
		}); !errors.Is(err, termlease.ErrCapabilityRejected) {
			t.Fatalf("wrong confirm want ErrCapabilityRejected, got %v", err)
		}
		w, err := h.adapter.AcquireWriterRemote(dashboard.RemoteWriterRequest{
			Handle: h.handle, DeviceSessionID: h.device,
			CapabilityToken: capTok, Confirm: confirm, RemoteExposed: true,
		})
		if err != nil || w == nil {
			t.Fatalf("wrong confirm burned the capability: re-acquire err=%v", err)
		}
		h.resetWriter()
	})

	// Absent / garbage capability → rejected at the consume leg.
	for _, tc := range []struct{ name, tok, confirm string }{
		{"deny/absent-cap", "", "x"},
		{"deny/garbage-cap", "garbage-token", "garbage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.allow.Store(true)
			if _, err := h.adapter.AcquireWriterRemote(dashboard.RemoteWriterRequest{
				Handle: h.handle, DeviceSessionID: h.device,
				CapabilityToken: tc.tok, Confirm: tc.confirm, RemoteExposed: true,
			}); !errors.Is(err, termlease.ErrCapabilityRejected) {
				t.Fatalf("%s want ErrCapabilityRejected, got %v", tc.name, err)
			}
		})
	}

	// Single-use: a granted capability cannot be replayed.
	t.Run("deny/replay-consumed-cap", func(t *testing.T) {
		h.allow.Store(true)
		capTok, confirm := h.mintCap(t)
		req := dashboard.RemoteWriterRequest{
			Handle: h.handle, DeviceSessionID: h.device,
			CapabilityToken: capTok, Confirm: confirm, RemoteExposed: true,
		}
		if _, err := h.adapter.AcquireWriterRemote(req); err != nil {
			t.Fatalf("first acquire should grant: %v", err)
		}
		h.resetWriter()
		if _, err := h.adapter.AcquireWriterRemote(req); !errors.Is(err, termlease.ErrCapabilityRejected) {
			t.Fatalf("replayed capability want ErrCapabilityRejected, got %v", err)
		}
	})

	// Default-on lease policy: independently-authorized remotes may supersede a
	// local writer and then one another. Each losing lease is takeover-fenced;
	// exactly one live writer remains after every transition.
	t.Run("grant/authenticated-remote-takeover-chain", func(t *testing.T) {
		h.allow.Store(true)
		h.mgr.SetAllowRemoteTakeoverSource(func() bool { return true })
		local, err := h.mgr.AcquireWriterLocal(h.handle)
		if err != nil {
			t.Fatalf("AcquireWriterLocal: %v", err)
		}
		remoteA, err := h.adapter.AcquireWriterRemote(h.validReq(t))
		if err != nil {
			t.Fatalf("remote-over-local: %v", err)
		}
		<-local.Revoked()
		if !local.RevokeIsTakeover() {
			t.Fatal("remote-over-local did not takeover-fence the local lease")
		}
		if _, err := local.Write([]byte("stale-local")); !errors.Is(err, termsession.ErrNotWriter) {
			t.Fatalf("superseded local Write = %v, want ErrNotWriter", err)
		}
		remoteB, err := h.adapter.AcquireWriterRemote(h.validReq(t))
		if err != nil {
			t.Fatalf("remote-over-remote: %v", err)
		}
		<-remoteA.Revoked()
		if !remoteA.RevokeIsTakeover() {
			t.Fatal("remote-over-remote did not takeover-fence the losing remote lease")
		}
		if _, err := remoteA.Write([]byte("stale-remote")); !errors.Is(err, termsession.ErrNotWriter) {
			t.Fatalf("superseded remote Write = %v, want ErrNotWriter", err)
		}
		if _, err := remoteB.Write([]byte("live")); err != nil {
			t.Fatalf("final remote writer fenced unexpectedly: %v", err)
		}
		h.resetWriter()
	})

	// Lease held locally: the §4.δ conjunction passes but the manager refuses a
	// remote acquire while the owner-local writer holds the lease (§4.α.3).
	t.Run("deny/held-locally", func(t *testing.T) {
		h.allow.Store(true)
		h.mgr.SetAllowRemoteTakeoverSource(func() bool { return false })
		local, err := h.mgr.AcquireWriterLocal(h.handle)
		if err != nil {
			t.Fatalf("AcquireWriterLocal: %v", err)
		}
		if _, err := h.adapter.AcquireWriterRemote(h.validReq(t)); !errors.Is(err, termsession.ErrHeldLocally) {
			t.Fatalf("held-locally want ErrHeldLocally, got %v", err)
		}
		local.Release()
		h.mgr.SetAllowRemoteTakeoverSource(func() bool { return true })
		h.resetWriter()
	})
}

// TestRemoteTerminalAuthorizationMatrixDashboard exercises the fully-assembled
// remote-execute authorization conjunction as `observer dashboard` wires it
// (wireRemoteExecuteTier). Exactly one designed cell grants; every other denies
// before any PTY mutation, and a pre-consume denial never burns the capability.
func TestRemoteTerminalAuthorizationMatrixDashboard(t *testing.T) {
	runAuthorizationMatrix(t)
}

// TestRemoteTerminalAuthorizationMatrixStart exercises the identical conjunction
// as `observer start` wires it — the two commands share wireRemoteExecuteTier, so
// this pins that the shared assembly holds for the start path too.
func TestRemoteTerminalAuthorizationMatrixStart(t *testing.T) {
	runAuthorizationMatrix(t)
}

// TestExecuteUnavailableUntilWired pins the fail-closed default: an adapter with
// no authorizer wired refuses every remote acquire (ErrLaunchExecuteUnavailable),
// regardless of otherwise-valid inputs.
func TestExecuteUnavailableUntilWired(t *testing.T) {
	mgr := termsession.NewManager(termsession.Options{Spawner: fakeSpawner{}})
	t.Cleanup(mgr.Shutdown)
	a := &launchManagerAdapter{mgr: mgr} // remoteAuthz nil
	if _, err := a.AcquireWriterRemote(dashboard.RemoteWriterRequest{
		Handle: "H", DeviceSessionID: "d", CapabilityToken: "c", Confirm: "x", RemoteExposed: true,
	}); !errors.Is(err, dashboard.ErrLaunchExecuteUnavailable) {
		t.Fatalf("unwired adapter want ErrLaunchExecuteUnavailable, got %v", err)
	}
}

// TestConcurrentTerminalCapabilityConsume pins the §8.1 race: two clients race a
// single capability; exactly one acquires the writer lease, the other receives a
// non-retryable denial (ErrCapabilityRejected), and only one lease results. Run
// under -race.
func TestConcurrentTerminalCapabilityConsume(t *testing.T) {
	h := newExecuteHarness(t)
	h.allow.Store(true)
	capTok, confirm := h.mintCap(t)
	req := dashboard.RemoteWriterRequest{
		Handle: h.handle, DeviceSessionID: h.device,
		CapabilityToken: capTok, Confirm: confirm, RemoteExposed: true,
	}

	var wg sync.WaitGroup
	var grants, rejects atomic.Int32
	start := make(chan struct{})
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			_, err := h.adapter.AcquireWriterRemote(req)
			results[idx] = err
			if err == nil {
				grants.Add(1)
			} else if errors.Is(err, termlease.ErrCapabilityRejected) {
				rejects.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if grants.Load() != 1 {
		t.Fatalf("want exactly ONE grant, got %d (results: %v)", grants.Load(), results)
	}
	if rejects.Load() != 1 {
		t.Fatalf("want exactly ONE non-retryable ErrCapabilityRejected denial, got %d (results: %v)", rejects.Load(), results)
	}
	// Only one lease exists.
	if _, held := h.mgr.WriterHolder(h.handle); !held {
		t.Fatal("expected exactly one live writer lease after the race")
	}
}
