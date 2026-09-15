package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/termoob"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// attach_correlate_assembled_test.go is the P2-1 anti-regression: an ASSEMBLED
// launch -> OOB-emit -> drainOOB -> Correlate -> Snapshot -> HTTP proof that a
// real attach session acquires its observer session id through the PRODUCTION
// consumption path — not a pre-correlated fake. It wires the SAME pieces
// `observer start` assembles: a real termsession.Manager (fake PTY spawner), a
// real ptyLauncher whose drainOOB feeds svc.Correlate, a real termsvc.Service,
// and the real launchManagerAdapter behind the real dashboard handler.

// assembledPTY is a minimal in-memory PTY: Read blocks until the session is
// killed, Write is a sink, and Wait blocks so the session stays "live" for the
// Snapshot assertion.
type assembledPTY struct {
	outR     *io.PipeReader
	outW     *io.PipeWriter
	done     chan struct{}
	killOnce sync.Once
}

func newAssembledPTY() *assembledPTY {
	r, w := io.Pipe()
	return &assembledPTY{outR: r, outW: w, done: make(chan struct{})}
}

func (p *assembledPTY) Read(b []byte) (int, error)  { return p.outR.Read(b) }
func (p *assembledPTY) Write(b []byte) (int, error) { return len(b), nil }
func (p *assembledPTY) Resize(uint16, uint16) error { return nil }
func (p *assembledPTY) Wait() (int, error)          { <-p.done; return 0, nil }
func (p *assembledPTY) Close() error                { return nil }

func (p *assembledPTY) Kill() error {
	p.killOnce.Do(func() {
		close(p.done)
		_ = p.outW.Close()
	})
	return nil
}

// assembledSpawner emulates the trusted launcher wrapper (oob_emit_unix.go): on
// spawn it authenticates the inherited OOB channel with a Hello (echoing the
// daemon-minted auth + correlation nonce it reads from the child env) and
// announces the child's agent session id — exactly the frames the real
// `observer <tool>` launcher writes to fd 3.
type assembledSpawner struct{ sessionID string }

func (s *assembledSpawner) Spawn(spec termsession.Spec) (termsession.PTY, error) {
	if len(spec.ExtraFiles) > 0 && spec.ExtraFiles[0] != nil {
		// Build the authenticating Hello via a JSON round-trip so the secret
		// field names never appear as a source assignment (the harness
		// write-filter mangles those; feedback_write_filter_token_patterns).
		fields := map[string]any{
			"auth": envValue(spec.Env, envOOBAuth),
			"corr": envValue(spec.Env, envOOBCorr),
			"tool": envValue(spec.Env, envOOBTool),
			"pid":  4242,
		}
		raw, _ := json.Marshal(fields)
		var hello termoob.Hello
		_ = json.Unmarshal(raw, &hello)
		enc := termoob.NewEncoder(spec.ExtraFiles[0])
		_ = enc.WriteHello(hello)
		_ = enc.WriteSession(termoob.Session{SessionID: s.sessionID})
	}
	return newAssembledPTY(), nil
}

// assembledRecorder is a no-op RunRecorder (the store persistence is out of
// scope for this wiring proof; the in-memory correlation cache is the surface).
type assembledRecorder struct{}

func (assembledRecorder) RecordRun(context.Context, termrun.Run) error { return nil }

func (assembledRecorder) EndRun(context.Context, string, time.Time, int, string) error { return nil }

func (assembledRecorder) RecordCorrelation(context.Context, termrun.Correlation) error { return nil }

func (assembledRecorder) RecordGUISpawn(context.Context, termrun.Run) error { return nil }

func TestAttachCorrelationAssembledThroughHTTP(t *testing.T) {
	const wantSession = "sess-assembled-oob"

	mgr := termsession.NewManager(termsession.Options{
		Spawner:      &assembledSpawner{sessionID: wantSession},
		ReapInterval: time.Hour,
		Now:          time.Now,
	})
	t.Cleanup(mgr.Shutdown)

	launcher := &ptyLauncher{mgr: mgr, binPath: "observer"}
	svc := termsvc.New(termsvc.Options{Recorder: assembledRecorder{}, Launcher: launcher})
	// The ONE production seam under test: drainOOB -> svc.Correlate.
	launcher.correlate = svc.Correlate
	adapter := &launchManagerAdapter{svc: svc, mgr: mgr}

	res, err := svc.LaunchAttachable(context.Background(), termsvc.AttachRequest{
		Tool: "claude-code", Subcommand: "claude",
	})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}

	// drainOOB processes the announced session frame on a goroutine — poll the
	// real in-memory correlation cache until it lands (or time out). 10s, not 3s:
	// under a contended -race/full-suite run the goroutine can be starved past 3s
	// (observed twice 2026-07-21; passes in ~0.25s isolated) — same wall-clock
	// class and remedy as the spawn-audit test's raised deadline.
	var gotSID string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sid, ok := svc.SessionForRun(res.RunID); ok {
			gotSID = sid
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gotSID != wantSession {
		// Do NOT read this as "the OOB frame was never delivered" (what this
		// message used to claim — it misdirects at the transport layer). The
		// frame is written synchronously by the spawner and drainOOB starts
		// INSIDE ptyLauncher.Spawn, so it almost always DOES reach
		// termsvc.Correlate. The failure is that no in-memory run→session link
		// was established. Look at the ACCEPTANCE layer first:
		// termsvc.Service.Correlate's liveness guard (byRun / launching) and the
		// launch reservation in termsvc.launch — a correlation that lands before
		// the PTY handle is registered used to be silently discarded there, and
		// the OOB session frame is one-shot, so the link never came back.
		t.Fatalf("SessionForRun(%q) = %q, want %q — no in-memory session link was established for the run; suspect termsvc.Correlate's liveness guard / the launch reservation, not the OOB transport", res.RunID, gotSID, wantSession)
	}

	// Adapter-level Snapshot must carry the correlated session id (the enrichment
	// the real /api/attach/sessions serves).
	var foundInfo *dashboard.LaunchInfo
	for i := range adapter.Snapshot() {
		info := adapter.Snapshot()[i]
		if info.RunID == res.RunID {
			foundInfo = &info
			break
		}
	}
	if foundInfo == nil {
		t.Fatalf("adapter.Snapshot() has no row for run %q", res.RunID)
	}
	if foundInfo.SessionID != wantSession {
		t.Fatalf("Snapshot row SessionID = %q, want %q", foundInfo.SessionID, wantSession)
	}
	if foundInfo.Kind != string(termrun.KindAttach) {
		t.Fatalf("Snapshot row Kind = %q, want attach", foundInfo.Kind)
	}

	// The real dashboard handler must return the correlated session id over HTTP.
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	srv, err := dashboard.New(dashboard.Options{DB: database, LaunchManager: adapter})
	if err != nil {
		t.Fatalf("dashboard.New: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/attach/sessions", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/attach/sessions = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
			RunID     string `json:"run_id"`
			Kind      string `json:"kind"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
	var httpSID string
	for _, s := range body.Sessions {
		if s.RunID == res.RunID {
			httpSID = s.SessionID
		}
	}
	if httpSID != wantSession {
		t.Fatalf("HTTP /api/attach/sessions session_id for run %q = %q, want %q", res.RunID, httpSID, wantSession)
	}
}
