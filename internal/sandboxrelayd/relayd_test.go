//go:build linux

package sandboxrelayd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

var testRules = sandboxrelay.RequestRules{EnvAllowed: func(n string) bool { return n == "OBSERVER_SANDBOX" }}

// shortDir keeps unix socket paths under the 107-byte limit.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "sbr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func TestRunRecordRoundTrip(t *testing.T) {
	obs := shortDir(t)
	rec, err := NewRunRecord(RunRecord{RunID: "run-1", Tool: "claude-code", WorkspaceDir: "/w", Roots: []string{"/w"}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rec.BoxSecret, rec.LinkSecret) {
		t.Fatal("the box and link secrets must differ")
	}
	if err := WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	if err := WriteRun(obs, rec); err == nil {
		t.Fatal("a second write of the same run was accepted")
	}
	got, err := ReadRun(obs, "run-1")
	if err != nil || got.Tool != "claude-code" || !bytes.Equal(got.LinkSecret, rec.LinkSecret) {
		t.Fatalf("read %+v %v", got.Tool, err)
	}
	if _, err := ReadRun(obs, "../x"); !errors.Is(err, ErrBadRecord) {
		t.Fatalf("a path-shaped run id: %v", err)
	}
	if _, err := ReadRun(obs, "run-2"); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("a missing run: %v", err)
	}
	if err := RemoveRun(obs, "run-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRun(obs, "run-1"); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("after remove: %v", err)
	}
}

// TestBoxRecordRefusals: no record means "outside any sandbox"; a record
// that exists but is a link, group-writable, or in a shared directory is a
// fault, never "outside".
func TestBoxRecordRefusals(t *testing.T) {
	if _, ok, err := ReadBoxRecord(filepath.Join(shortDir(t), BoxRecordName)); ok || err != nil {
		t.Fatalf("no record: ok %v err %v", ok, err)
	}
	rec, _ := NewRunRecord(RunRecord{RunID: "run-1"})
	good := shortDir(t)
	if err := os.Chmod(good, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteBoxRecord(good, rec); err != nil {
		t.Fatal(err)
	}
	if br, ok, err := ReadBoxRecord(filepath.Join(good, BoxRecordName)); !ok || err != nil || br.RunID != "run-1" {
		t.Fatalf("a good record: %+v %v %v", br, ok, err)
	}
	shared := shortDir(t)
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := WriteBoxRecord(shared, rec); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadBoxRecord(filepath.Join(shared, BoxRecordName)); !ok || err == nil {
		t.Fatalf("a record in a world-writable directory: ok %v err %v", ok, err)
	}
	linked := shortDir(t)
	_ = os.Chmod(linked, 0o700)
	if err := os.Symlink(filepath.Join(good, BoxRecordName), filepath.Join(linked, BoxRecordName)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadBoxRecord(filepath.Join(linked, BoxRecordName)); !ok || err == nil {
		t.Fatalf("a linked record: ok %v err %v", ok, err)
	}
}

// TestConfinedFiles: the confused-deputy rule. Only regular files under
// the run's roots are read; a path elsewhere (~/.ssh), a symlink at any
// component, a directory and a relative path are refused with ErrRefused.
func TestConfinedFiles(t *testing.T) {
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	secret := filepath.Join(base, "home", ".ssh", "id_ed25519")
	for _, d := range []string{filepath.Join(ws, "sub"), filepath.Dir(secret)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ws, "sub", "t.jsonl"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(ws, "leak")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(secret), filepath.Join(ws, "dirlink")); err != nil {
		t.Fatal(err)
	}
	f := ConfinedFiles([]string{ws})
	if b, err := f.ReadFile(filepath.Join(ws, "sub", "t.jsonl")); err != nil || string(b) != "ok" {
		t.Fatalf("an in-root file: %q %v", b, err)
	}
	if fh, err := f.Open(filepath.Join(ws, "sub", "t.jsonl")); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		_ = fh.Close()
	}
	for _, p := range []string{
		secret,
		filepath.Join(ws, "leak"),
		filepath.Join(ws, "dirlink", "id_ed25519"),
		filepath.Join(ws, "sub"),
		filepath.Join(ws, "..", "home", ".ssh", "id_ed25519"),
		"sub/t.jsonl",
		"",
	} {
		if _, err := f.ReadFile(p); !hookctx.IsRefused(err) {
			t.Errorf("%q: %v, want a refusal", p, err)
		}
		if _, err := f.Stat(p); !hookctx.IsRefused(err) {
			t.Errorf("stat %q: %v, want a refusal", p, err)
		}
	}
	if _, err := ConfinedFiles(nil).ReadFile(filepath.Join(ws, "sub", "t.jsonl")); !hookctx.IsRefused(err) {
		t.Fatalf("no roots: %v", err)
	}
}

// relay stands up the whole same-kernel topology over real unix sockets:
// the daemon's link endpoint, the helper's forwarder on the run's relay
// socket, and returns the box record a client uses.
type relay struct {
	obs, sock string
	rec       RunRecord
	daemon    *Daemon
	execs     []sandboxrelay.HookRequest
	mu        sync.Mutex
}

func startRelay(t *testing.T, exec Executor) *relay {
	t.Helper()
	r := &relay{obs: shortDir(t), sock: shortDir(t)}
	_ = os.Chmod(r.sock, 0o700)
	rec, err := NewRunRecord(RunRecord{RunID: "run-1", Tool: "claude-code", WorkspaceDir: "/w", Roots: []string{"/w"}})
	if err != nil {
		t.Fatal(err)
	}
	r.rec = rec
	if err := WriteRun(r.obs, rec); err != nil {
		t.Fatal(err)
	}
	if err := WriteBoxRecord(r.sock, rec); err != nil {
		t.Fatal(err)
	}
	if exec == nil {
		exec = func(_ context.Context, run RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			r.mu.Lock()
			r.execs = append(r.execs, req)
			r.mu.Unlock()
			return sandboxrelay.HookResponse{Exit: 0, Stdout: []byte("ran for " + run.RunID + ": " + string(req.Stdin))}, nil
		}
	}
	link := filepath.Join(r.obs, "link.sock")
	dln, err := net.Listen("unix", link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r.daemon = &Daemon{ObserverDir: r.obs, Exec: exec, Rules: testRules, Peer: PeerSameUser}
	go func() { _ = r.daemon.Serve(ctx, dln) }()
	bln, err := net.Listen("unix", filepath.Join(r.sock, RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	fw := &Forwarder{Run: rec, Rules: testRules, Peer: PeerSameUser, DialDaemon: func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", link)
	}}
	go func() { _ = fw.Serve(ctx, bln) }()
	return r
}

func (r *relay) box(t *testing.T) BoxRecord {
	t.Helper()
	br, ok, err := ReadBoxRecord(filepath.Join(r.sock, BoxRecordName))
	if !ok || err != nil {
		t.Fatalf("box record: %v %v", ok, err)
	}
	return br
}

func roundTrip(t *testing.T, r *relay, br BoxRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return BoxRoundTrip(ctx, r.sock, br, req, sandboxrelay.DefaultConnLimits)
}

// TestRelayEndToEnd: a box request crosses the helper and the link to the
// daemon's executor, which sees the run the CHANNEL named, and the answer
// comes back to the box.
func TestRelayEndToEnd(t *testing.T) {
	r := startRelay(t, nil)
	resp, err := roundTrip(t, r, r.box(t), sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}, Stdin: []byte("payload")})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Stdout) != "ran for run-1: payload" {
		t.Fatalf("stdout %q", resp.Stdout)
	}
	// The daemon counts a request served after its answer is sent, so the
	// box can read the answer before the count moves: wait for the count
	// (it flaked about 1 in 4 runs under -race when read at once).
	waitUntil(t, 5*time.Second, "the run's handler state counts the request", func() bool {
		st, ok := r.daemon.Run("run-1")
		return ok && st.Served.Load() == 1
	})
}

// TestRelayRefusesForgedRun (mutation proof, P2 acceptance): a box client
// claiming another run, or using another run's secret, is refused and the
// executor never runs.
func TestRelayRefusesForgedRun(t *testing.T) {
	r := startRelay(t, nil)
	br := r.box(t)
	other := br
	other.RunID = "run-2"
	if _, err := roundTrip(t, r, other, sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}}); err == nil {
		t.Fatal("a box claiming run-2 was answered")
	}
	wrong := br
	wrong.BoxSecret = bytes.Repeat([]byte{7}, sandboxrelay.SecretSize)
	if _, err := roundTrip(t, r, wrong, sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}}); err == nil {
		t.Fatal("a box with the wrong secret was answered")
	}
	// The box secret is not the link secret: a box that reaches the link
	// endpoint with what it can read is refused there too.
	link := filepath.Join(r.obs, "link.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	msg, _ := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}})
	boxAsLink := r.rec
	boxAsLink.LinkSecret = br.BoxSecret
	if _, err := LinkRoundTrip(ctx, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", link)
	}, boxAsLink, msg, sandboxrelay.DefaultConnLimits); err == nil {
		t.Fatal("the box secret authenticated on the link")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.execs) != 0 {
		t.Fatalf("the executor ran %d forged requests", len(r.execs))
	}
}

// TestRelayValidatesTheRequest: an undeclarable variable never reaches the
// daemon.
func TestRelayValidatesTheRequest(t *testing.T) {
	r := startRelay(t, nil)
	_, err := roundTrip(t, r, r.box(t), sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}, Env: map[string]string{"OBSERVER_HOOK_SHAPE_LOG": "/etc/passwd"}})
	if err == nil {
		t.Fatal("an undeclarable variable was relayed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.execs) != 0 {
		t.Fatal("the executor ran a refused request")
	}
}

// TestRelayExecutorFailure: an executor error closes the channel, so the
// box sees a failure (and a gate event blocks), never an empty allow.
func TestRelayExecutorFailure(t *testing.T) {
	r := startRelay(t, func(context.Context, RunRecord, sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
		return sandboxrelay.HookResponse{}, errors.New("boom")
	})
	if _, err := roundTrip(t, r, r.box(t), sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}}); err == nil {
		t.Fatal("a failed execution answered the box")
	}
}

// TestRelayLargePayload: a payload larger than one frame round-trips, and
// one over the per-message cap is refused before it is sent.
func TestRelayLargePayload(t *testing.T) {
	r := startRelay(t, nil)
	big := bytes.Repeat([]byte("z"), 2<<20)
	resp, err := roundTrip(t, r, r.box(t), sandboxrelay.HookRequest{Args: []string{"claude-code", "PostToolUse"}, Stdin: big})
	if err != nil || !strings.HasSuffix(string(resp.Stdout), string(big[:64])) {
		t.Fatalf("a 2 MiB payload: %v", err)
	}
	if _, err := roundTrip(t, r, r.box(t), sandboxrelay.HookRequest{Args: []string{"claude-code", "PostToolUse"}, Stdin: make([]byte, sandboxrelay.MaxMessage)}); err == nil {
		t.Fatal("a payload over the message cap was sent")
	}
}

// TestPruneRuns: only records older than the bound go; a fresh one stays.
func TestPruneRuns(t *testing.T) {
	obs := shortDir(t)
	for _, id := range []string{"old", "new"} {
		rec, err := NewRunRecord(RunRecord{RunID: id})
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteRun(obs, rec); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(RunsDir(obs), "old.json"), past, past); err != nil {
		t.Fatal(err)
	}
	n, err := PruneRuns(obs, 7*24*time.Hour, time.Now())
	if err != nil || n != 1 {
		t.Fatalf("pruned %d %v", n, err)
	}
	if _, err := ReadRun(obs, "new"); err != nil {
		t.Fatalf("the fresh record went: %v", err)
	}
}
