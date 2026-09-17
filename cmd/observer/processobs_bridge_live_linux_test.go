//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/processobs/bridge"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestProcessBridgeLive_CrossOSAttribution is the §5.5 live smoke for the FULL
// cross-OS path: the WSL bridge backend execs the real Windows observer.exe
// process-bridge over interop → the Observer stores the (unattributed) Windows
// process table → the deferred CorrelateCrossOS pass joins the AI-tool root to
// a session by cwd/tool/time. It spawns a fake "claude.exe" (a copy of the
// Windows binary) whose cwd IS the seeded session's project root and asserts
// that exact process is attributed cross_os_correlation / medium.
//
// Gated: skipped unless OBSERVER_PROCESS_BRIDGE_LIVE=1 AND a Windows
// observer.exe resolves (bin/observer.exe or $OBSERVER_WINDOWS_BINARY). Run it
// from WSL with the binary built:
//
//	go build -o bin/observer.exe ./cmd/observer            # on the Windows host
//	GOOS=linux go test -c -o /tmp/o.test ./cmd/observer/
//	OBSERVER_PROCESS_BRIDGE_LIVE=1 /tmp/o.test -test.run TestProcessBridgeLive
func TestProcessBridgeLive_CrossOSAttribution(t *testing.T) {
	if os.Getenv("OBSERVER_PROCESS_BRIDGE_LIVE") != "1" {
		t.Skip("cross-OS bridge live smoke: set OBSERVER_PROCESS_BRIDGE_LIVE=1 to run (WSL only)")
	}
	winObserver, ok := bridge.ResolveWindowsObserver(os.Getenv("OBSERVER_WINDOWS_BINARY"))
	if !ok {
		t.Skip("no Windows observer.exe resolved — build bin/observer.exe or set OBSERVER_WINDOWS_BINARY")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)

	// The project root is the Windows form of the binary's directory, so a
	// process launched there has cwd == project_root. No pidbridge row: the
	// cross-OS path has no direct hit, exactly like production.
	binDir := filepath.Dir(winObserver)
	projectRootWin := wslMountToWindows(binDir)
	projID, err := st.UpsertProject(ctx, projectRootWin, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	const sess = "sess-bridge-live"
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		sess, projID, "claude-code", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// A fake "claude.exe" (copy of the Windows binary) running a long-lived
	// subcommand with cwd == the project root — the AI-tool root to attribute.
	fakeClaude := filepath.Join(binDir, "claude.exe")
	if err := copyFile(winObserver, fakeClaude); err != nil {
		t.Fatalf("copy fake claude.exe: %v", err)
	}
	defer func() { _ = os.Remove(fakeClaude) }()
	claudeCmd := exec.CommandContext(ctx, fakeClaude, "process-bridge", "--interval-ms", "3000")
	claudeCmd.Dir = binDir // → Windows cwd == projectRootWin
	claudeCmd.Stdout = nil // discard its NDJSON
	if err := claudeCmd.Start(); err != nil {
		t.Fatalf("spawn fake claude.exe: %v", err)
	}
	defer func() { _ = claudeCmd.Process.Kill(); _ = claudeCmd.Wait() }()
	time.Sleep(1500 * time.Millisecond) // let it settle so the bridge sees it

	// Real bridge backend → Observer → store. nil seed (everything unattributed,
	// like the cross-OS topology); capture_unattributed so the rows persist.
	obs := processobs.NewObserver(processobs.Options{
		Backend:             bridge.New(bridge.Options{WindowsBinaryPath: winObserver, PollIntervalMS: 1000}),
		Attributor:          processobs.NewAttributor(nil, buildProcessScrubber(config.Default().Observer.Process), nil),
		Sink:                st,
		CaptureUnattributed: true,
		BatchSize:           100,
		FlushInterval:       300 * time.Millisecond,
	})
	done := make(chan struct{})
	go func() { _ = obs.Run(ctx); close(done) }()
	time.Sleep(6 * time.Second) // a few bridge polls + flushes
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("observer did not stop")
	}

	// Deferred cross-OS pass, then read the session's now-attributed tree.
	n, err := st.CorrelateCrossOS(context.Background(), sess)
	if err != nil {
		t.Fatalf("CorrelateCrossOS: %v", err)
	}
	runs, err := st.ProcessRunsForSession(context.Background(), sess)
	if err != nil {
		t.Fatalf("ProcessRunsForSession: %v", err)
	}

	var sawClaude bool
	for _, r := range runs {
		if !strings.EqualFold(r.ExeBasename, "claude.exe") {
			continue
		}
		sawClaude = true
		if r.AttributionSource != string(processobs.AttrCrossOSCorrelation) {
			t.Errorf("claude.exe attribution source = %q, want cross_os_correlation", r.AttributionSource)
		}
		if r.AttributionConfidence != string(processobs.ConfMedium) {
			t.Errorf("claude.exe confidence = %q, want medium", r.AttributionConfidence)
		}
	}
	if !sawClaude {
		t.Fatalf("fake claude.exe not attributed to the session (cross_os pass attributed %d rows; session has %d runs)", n, len(runs))
	}
	t.Logf("live cross-OS smoke: %d rows attributed by CorrelateCrossOS; session tree has %d runs", n, len(runs))
}

// TestProcessBridgeLive_EnvTokenAttribution is the §5.5 P-B6 (EV) live smoke:
// the FULL cross-OS path attributing a Windows process at HIGH confidence via a
// tree-inherited session-id env var — no cwd/time heuristic, no CorrelateCrossOS
// pass. It spawns a fake "claude.exe" whose Windows environment carries
// CLAUDE_CODE_SESSION_ID == the seeded session id (pushed across the WSL→Windows
// boundary via WSLENV, which the P-B0 spike found is REQUIRED), wires the
// env-token seam (SessionSeedByID), and asserts that process lands env_token /
// high at capture time.
//
// Gated identically to TestProcessBridgeLive_CrossOSAttribution. Run from WSL
// with a FRESHLY-BUILT bin/observer.exe (the capturer must contain the env-read
// code):
//
//	go build -o bin/observer.exe ./cmd/observer            # on the Windows host
//	GOOS=linux go test -c -o /tmp/o.test ./cmd/observer/
//	OBSERVER_PROCESS_BRIDGE_LIVE=1 /tmp/o.test -test.run TestProcessBridgeLive_EnvToken
func TestProcessBridgeLive_EnvTokenAttribution(t *testing.T) {
	if os.Getenv("OBSERVER_PROCESS_BRIDGE_LIVE") != "1" {
		t.Skip("cross-OS bridge live smoke: set OBSERVER_PROCESS_BRIDGE_LIVE=1 to run (WSL only)")
	}
	winObserver, ok := bridge.ResolveWindowsObserver(os.Getenv("OBSERVER_WINDOWS_BINARY"))
	if !ok {
		t.Skip("no Windows observer.exe resolved — build bin/observer.exe or set OBSERVER_WINDOWS_BINARY")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)

	const sess = "sess-envtoken-live"
	projID, err := st.UpsertProject(ctx, wslMountToWindows(filepath.Dir(winObserver)), "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		sess, projID, "claude-code", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// A fake "claude.exe" carrying CLAUDE_CODE_SESSION_ID == the seeded session
	// id in its Windows environment (pushed via WSLENV). Its cwd is deliberately
	// NOT the project root, so ONLY the env token can attribute it — a pure EV
	// assertion (cwd correlation would also match if cwd==root).
	binDir := filepath.Dir(winObserver)
	fakeClaude := filepath.Join(binDir, "claude.exe")
	if err := copyFile(winObserver, fakeClaude); err != nil {
		t.Fatalf("copy fake claude.exe: %v", err)
	}
	defer func() { _ = os.Remove(fakeClaude) }()
	claudeCmd := exec.CommandContext(ctx, fakeClaude, "process-bridge", "--interval-ms", "3000")
	claudeCmd.Dir = "/" // cwd != project root (rules out the medium cwd match)
	claudeCmd.Env = envWithWSLShare(os.Environ(), "CLAUDE_CODE_SESSION_ID", sess)
	claudeCmd.Stdout = nil
	if err := claudeCmd.Start(); err != nil {
		t.Fatalf("spawn fake claude.exe: %v", err)
	}
	defer func() { _ = claudeCmd.Process.Kill(); _ = claudeCmd.Wait() }()
	time.Sleep(1500 * time.Millisecond)

	// Real bridge backend → Observer → store, with the EV seam wired (nil pid
	// seed, like the cross-OS topology). capture_unattributed so non-token rows
	// still persist.
	attr := processobs.NewAttributor(nil, buildProcessScrubber(config.Default().Observer.Process), nil)
	attr.SetTokenLookup(func(token string) (processobs.Seed, bool) {
		s, ok, lerr := st.SessionSeedByID(context.Background(), token)
		if lerr != nil || !ok {
			return processobs.Seed{}, false
		}
		return s, true
	})
	obs := processobs.NewObserver(processobs.Options{
		Backend:             bridge.New(bridge.Options{WindowsBinaryPath: winObserver, PollIntervalMS: 1000}),
		Attributor:          attr,
		Sink:                st,
		CaptureUnattributed: true,
		BatchSize:           100,
		FlushInterval:       300 * time.Millisecond,
	})
	done := make(chan struct{})
	go func() { _ = obs.Run(ctx); close(done) }()
	time.Sleep(6 * time.Second)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("observer did not stop")
	}

	// NO CorrelateCrossOS — EV attributes at capture.
	runs, err := st.ProcessRunsForSession(context.Background(), sess)
	if err != nil {
		t.Fatalf("ProcessRunsForSession: %v", err)
	}
	var sawClaude bool
	for _, r := range runs {
		if !strings.EqualFold(r.ExeBasename, "claude.exe") {
			continue
		}
		sawClaude = true
		if r.AttributionSource != string(processobs.AttrEnvToken) {
			t.Errorf("claude.exe attribution source = %q, want env_token", r.AttributionSource)
		}
		if r.AttributionConfidence != string(processobs.ConfHigh) {
			t.Errorf("claude.exe confidence = %q, want high", r.AttributionConfidence)
		}
		if r.SessionID != sess {
			t.Errorf("claude.exe session = %q, want %q", r.SessionID, sess)
		}
	}
	if !sawClaude {
		t.Fatalf("fake claude.exe not attributed by EV (session has %d runs) — check WSLENV propagation + a freshly-built bin/observer.exe", len(runs))
	}
	t.Logf("live EV smoke: claude.exe attributed env_token/high; session tree has %d runs", len(runs))
}

// envWithWSLShare returns base with key=value set and key added to WSLENV so WSL
// interop forwards it into a spawned Windows process (the P-B0 spike found a
// bare var does NOT cross the boundary). WSLENV is a colon-separated list; an
// existing value is preserved and merged.
func envWithWSLShare(base []string, key, value string) []string {
	const wslenv = "WSLENV"
	existing := ""
	out := make([]string, 0, len(base)+2)
	for _, kv := range base {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			out = append(out, kv)
			continue
		}
		switch k := kv[:eq]; {
		case strings.EqualFold(k, wslenv):
			existing = kv[eq+1:] // drop; re-added merged below
		case strings.EqualFold(k, key):
			// drop; re-added with our value below
		default:
			out = append(out, kv)
		}
	}
	merged := key
	if existing != "" {
		merged = existing + ":" + key
	}
	return append(out, wslenv+"="+merged, key+"="+value)
}

// wslMountToWindows converts /mnt/d/foo/bar to D:\foo\bar (test helper).
func wslMountToWindows(p string) string {
	if strings.HasPrefix(p, "/mnt/") && len(p) > 6 {
		drive := strings.ToUpper(p[5:6])
		return drive + ":" + strings.ReplaceAll(p[6:], "/", `\`)
	}
	return p
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755) //nolint:gosec // executable copy for the smoke
}
