package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// launch_exit_linger_test.go is the F1 anti-regression (adversarial review
// 2026-07-19): a real attach run whose child EXITS must keep its remote-sensitive
// classification for as long as the termsession.Manager still holds the handle
// (the ~30s ExitLinger during which the PTY is still subscribable). It wires the
// REAL termsvc.Service (byMeta lifecycle) + REAL termsession.Manager (linger) +
// the REAL dashboard visibleSnapshot / handleLaunchWS gates, so the assembled
// chain — exit → EndRunByHandle → remote snapshot exclusion → WS refusal — is
// proven end to end, not against a pre-classified fake.

// lingerPTY blocks Read/Wait until the child "exits" (finish) or is killed, so a
// session stays live until the test signals a NATURAL process exit — after which
// the Manager fires OnExit and starts the ExitLinger clock (the window under
// test). Distinct from Manager.Close, which force-reaps and REMOVES immediately
// (no linger).
type lingerPTY struct {
	dead     chan struct{}
	killOnce sync.Once
}

func newLingerPTY() *lingerPTY { return &lingerPTY{dead: make(chan struct{})} }

func (p *lingerPTY) Read([]byte) (int, error)    { <-p.dead; return 0, io.EOF }
func (p *lingerPTY) Write(b []byte) (int, error) { return len(b), nil }
func (p *lingerPTY) Resize(uint16, uint16) error { return nil }
func (p *lingerPTY) Wait() (int, error)          { <-p.dead; return 0, nil }
func (p *lingerPTY) Kill() error                 { p.finish(); return nil }
func (p *lingerPTY) Close() error                { return nil }

// finish simulates the child process exiting on its own — Wait returns, which
// drives the Manager's natural-exit → linger path (NOT the Close/remove path).
func (p *lingerPTY) finish() { p.killOnce.Do(func() { close(p.dead) }) }

type lingerSpawner struct {
	mu   sync.Mutex
	last *lingerPTY
}

func (s *lingerSpawner) Spawn(termsession.Spec) (termsession.PTY, error) {
	pty := newLingerPTY()
	s.mu.Lock()
	s.last = pty
	s.mu.Unlock()
	return pty, nil
}

func (s *lingerSpawner) lastPTY() *lingerPTY {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// svcMgrLauncher is the termsvc.Launcher over a real Manager (a minimal stand-in
// for cmd's ptyLauncher, without the OOB plumbing the sensitivity gates don't
// consult).
type svcMgrLauncher struct{ mgr *termsession.Manager }

func (l svcMgrLauncher) Spawn(req termsvc.LaunchRequest) (string, error) {
	return l.mgr.Create(termsession.Spec{
		BinPath:    "observer",
		Subcommand: req.Subcommand,
		ArgvMode:   termsession.ArgvModeFresh,
	})
}

// svcManagerAdapter is a faithful mirror of cmd's launchManagerAdapter for the
// two seams this test exercises: Snapshot (prune + Kind enrichment from termsvc)
// and IsRemoteSensitiveSession (run KIND via the shared termrun table). Every
// other interface method delegates to the Manager or is an unused stub.
type svcManagerAdapter struct {
	svc *termsvc.Service
	mgr *termsession.Manager
}

func (a *svcManagerAdapter) Create(LaunchSpec) (string, error)           { return "", nil }
func (a *svcManagerAdapter) CreateFresh(FreshLaunchSpec) (string, error) { return "", nil }
func (a *svcManagerAdapter) CreateResume(ResumeLaunchSpec) (string, string, error) {
	return "", "", nil
}
func (a *svcManagerAdapter) CreateSetup(SetupSpec) (string, error) { return "", nil }
func (a *svcManagerAdapter) CreateGUI(GUILaunchSpec) (GUILaunchResult, error) {
	return GUILaunchResult{}, ErrLaunchGUIUnsupported
}
func (a *svcManagerAdapter) GUIRuns() []GUIRunInfo { return nil }
func (a *svcManagerAdapter) Subscribe(handle string) (LaunchSubscription, error) {
	return a.mgr.Subscribe(handle)
}

func (a *svcManagerAdapter) SubscribeRemote(handle string) (LaunchSubscription, error) {
	return a.mgr.SubscribeRemote(handle)
}

func (a *svcManagerAdapter) IsSetupSession(handle string) bool { return a.mgr.IsSetupSession(handle) }

func (a *svcManagerAdapter) IsRemoteSensitiveSession(handle string) bool {
	kind, _, ok := a.svc.KindForHandle(handle)
	return ok && termrun.IsRemoteSensitiveKind(kind)
}

func (a *svcManagerAdapter) Unsubscribe(sub LaunchSubscription) {
	if ts, ok := sub.(*termsession.Subscription); ok {
		a.mgr.Unsubscribe(ts)
	}
}

func (a *svcManagerAdapter) AcquireWriterLocal(handle string) (LaunchWriter, error) {
	return a.mgr.AcquireWriterLocal(handle)
}

func (a *svcManagerAdapter) AcquireWriterRemote(RemoteWriterRequest) (LaunchWriter, error) {
	return nil, ErrLaunchExecuteUnavailable
}
func (a *svcManagerAdapter) Close(handle string) { a.mgr.Close(handle) }
func (a *svcManagerAdapter) SessionForRun(runID string) (string, bool) {
	return a.svc.SessionForRun(runID)
}
func (a *svcManagerAdapter) RevokeAllRemoteWriters(string) int              { return 0 }
func (a *svcManagerAdapter) RevokeRemoteWriterByHolder(string, string) bool { return false }

func (a *svcManagerAdapter) Snapshot() []LaunchInfo {
	live := a.mgr.Snapshot()
	liveHandles := make(map[string]struct{}, len(live))
	for _, s := range live {
		liveHandles[s.ID] = struct{}{}
	}
	a.svc.PruneEndedHandles(liveHandles)
	out := make([]LaunchInfo, 0, len(live))
	for _, s := range live {
		info := LaunchInfo{
			ID: s.ID, Subcommand: s.Subcommand, SessionID: s.SessionID,
			CreatedAt: s.CreatedAt, Setup: s.Setup, Exited: s.Exited, ExitCode: s.ExitCode,
		}
		if runID, ok := a.svc.RunIDForHandle(s.ID); ok {
			info.RunID = runID
		}
		if kind, tool, ok := a.svc.KindForHandle(s.ID); ok {
			info.Kind = string(kind)
			info.Tool = tool
		}
		out = append(out, info)
	}
	return out
}

func terminalSessionIDs(t *testing.T, s *Server, remote bool) map[string]LaunchInfo {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/sessions", nil)
	if remote {
		req = req.WithContext(withRemoteExposed(req.Context()))
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/terminal/sessions = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Sessions []LaunchInfo `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	return idsOf(body.Sessions)
}

// TestAttachExitLingerStaysRemoteSensitive is the F1 assembled negative test: an
// exited-but-lingering attach handle must still be (a) excluded from the remote
// snapshot and (b) refused over the WS — the confidentiality hole that opened
// when EndRunByHandle used to delete byMeta at exit while the Manager kept the
// PTY subscribable through ExitLinger.
func TestAttachExitLingerStaysRemoteSensitive(t *testing.T) {
	// ReapInterval huge → the reaper never removes the exited session, so it
	// lingers in the Manager for the whole test (the ExitLinger window). svc is
	// referenced by the OnExit closure by variable (assigned just below), the
	// same mutual-reference shape cmd's buildTerminalStack uses.
	var svc *termsvc.Service
	spawner := &lingerSpawner{}
	mgr := termsession.NewManager(termsession.Options{
		Spawner:      spawner,
		ReapInterval: time.Hour,
		Now:          time.Now,
		OnExit: func(se termsession.SessionExit) {
			if svc != nil {
				svc.EndRunByHandle(context.Background(), se.Handle, se.ExitCode)
			}
		},
	})
	t.Cleanup(mgr.Shutdown)

	launcher := svcMgrLauncher{mgr: mgr}
	svc = termsvc.New(termsvc.Options{Recorder: nopSvcRecorder{}, Launcher: launcher})
	adapter := &svcManagerAdapter{svc: svc, mgr: mgr}

	tdir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: tdir + "/d.db"})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database, LaunchManager: adapter})
	if err != nil {
		t.Fatalf("dashboard.New: %v", err)
	}

	res, err := svc.LaunchAttachable(context.Background(), termsvc.AttachRequest{
		Tool: "claude-code", Subcommand: "claude",
	})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	handle, ok := svc.HandleForRun(res.RunID)
	if !ok {
		t.Fatal("no handle for the launched attach run")
	}

	// While live: sensitive, and remote snapshot already excludes it.
	if !adapter.IsRemoteSensitiveSession(handle) {
		t.Fatal("live attach handle must be remote-sensitive")
	}
	if _, present := terminalSessionIDs(t, s, true)[handle]; present {
		t.Fatal("remote snapshot must not disclose a LIVE attach handle")
	}

	// Exit the child NATURALLY (Wait returns). OnExit → EndRunByHandle; the
	// Manager keeps the handle through ExitLinger. Poll until the live-run map is
	// gone (exit recorded).
	spawner.lastPTY().finish()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, live := svc.RunIDForHandle(handle); !live {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, live := svc.RunIDForHandle(handle); live {
		t.Fatal("EndRunByHandle never fired — the live-run map is still present")
	}

	// The handle is still in the Manager (lingering, exited).
	stillHeld := false
	for _, info := range mgr.Snapshot() {
		if info.ID == handle {
			stillHeld = true
			if !info.Exited {
				t.Fatal("expected the lingering handle to be marked exited")
			}
		}
	}
	if !stillHeld {
		t.Fatal("precondition failed: Manager no longer holds the exited handle (no linger to test)")
	}

	// F1 core: classification survives the exit for as long as the Manager holds
	// the handle.
	if !adapter.IsRemoteSensitiveSession(handle) {
		t.Fatal("F1: exited-but-lingering attach handle LOST its remote-sensitive classification")
	}

	// R2-2 interleaving: a STALE live-handle set (one captured before this handle
	// registered — modeled by the empty set, which never saw it) must NOT drop
	// the classification while it is still within the grace / lingering. Pre-fix,
	// the set-only prune deleted byMeta here and reopened the exit-linger hole.
	svc.PruneEndedHandles(map[string]struct{}{})
	if !adapter.IsRemoteSensitiveSession(handle) {
		t.Fatal("R2-2: a stale-set PruneEndedHandles reopened the exit-linger classification hole")
	}

	// (a) Remote snapshot still EXCLUDES the lingering row; the local owner sees
	// it (exited).
	if _, present := terminalSessionIDs(t, s, true)[handle]; present {
		t.Fatal("F1: remote snapshot disclosed an exited-but-lingering attach handle")
	}
	if _, present := terminalSessionIDs(t, s, false)[handle]; !present {
		t.Fatal("local owner snapshot should still list the lingering attach handle")
	}

	// (b) Remote WS subscribe is REFUSED during linger (1008 policy close, closed
	// as "session not found" so a remote caller cannot distinguish refused vs
	// absent). Driven through the real handleLaunchWS with remote provenance.
	srv := remoteExposedWSServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, derr := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/launch/"+handle, nil)
	if derr != nil {
		// A dial-time rejection is an acceptable "refused" outcome too.
		return
	}
	defer func() { _ = c.CloseNow() }()
	_, _, rerr := c.Read(ctx)
	if rerr == nil {
		t.Fatal("F1: remote WS read succeeded for a lingering attach handle — it must be refused")
	}
	if cs := websocket.CloseStatus(rerr); cs != websocket.StatusPolicyViolation {
		t.Fatalf("F1: remote WS close status = %v, want policy-violation (1008)", cs)
	}
}

// nopSvcRecorder is a no-op termsvc.RunRecorder (persistence is out of scope for
// this classification-lifecycle proof).
type nopSvcRecorder struct{}

func (nopSvcRecorder) RecordRun(context.Context, termrun.Run) error                 { return nil }
func (nopSvcRecorder) EndRun(context.Context, string, time.Time, int, string) error { return nil }
func (nopSvcRecorder) RecordCorrelation(context.Context, termrun.Correlation) error { return nil }
func (nopSvcRecorder) RecordGUISpawn(context.Context, termrun.Run) error            { return nil }
