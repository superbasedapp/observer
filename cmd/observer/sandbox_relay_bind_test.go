//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// The P-026 follow-ups of lane sbx-p2b on the cmd side: the box cannot
// steer the host hook.

// twoRepos is a workspace repository and another repository beside it.
func twoRepos(t *testing.T) (ws, other string) {
	t.Helper()
	base := t.TempDir()
	ws, other = filepath.Join(base, "ws"), filepath.Join(base, "other")
	for _, d := range []string{filepath.Join(ws, ".git"), filepath.Join(other, ".git"), filepath.Join(other, ".claude", "skills", "s")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(other, ".claude", "skills", "s", "SKILL.md"), []byte("---\nname: s\n---\nsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return ws, other
}

// daemonProcess makes this test process's hook context a relay child's,
// for the run whose workspace is ws.
func daemonProcess(t *testing.T, ws string) {
	t.Helper()
	hc := hookctx.Daemon(context.Background(), hookctx.Request{}, hookctx.Channel{
		RunID: "run-a", ProjectRoot: ws, Files: sandboxrelayd.ConfinedFiles([]string{ws}), Contains: sandboxrelayd.ConfinedContains([]string{ws}),
	}, hookctx.DaemonProviders{})
	hookctx.SetProcess(hc)
	t.Cleanup(func() { hookctx.SetProcess(nil) })
}

// TestRelayChildProjectRootIsTheRuns (P-026 a): on the daemon path the
// event's project (the key of the posture, the dirty marker and the quick
// scan) is the run's, whatever directory the payload names; the host path
// is unchanged.
func TestRelayChildProjectRootIsTheRuns(t *testing.T) {
	ws, other := twoRepos(t)
	if got := hookProjectRoot(&policy.Event{Cwd: other}); got != other {
		t.Fatalf("host path: %q, want the payload's repository %q", got, other)
	}
	daemonProcess(t, ws)
	for _, pe := range []*policy.Event{{Cwd: other}, {ProjectRoot: other}, {Cwd: other, ProjectRoot: other}, {}} {
		if got := hookProjectRoot(pe); got != ws {
			t.Errorf("daemon path, event %+v: project %q, want the run's %q", *pe, got, ws)
		}
	}
}

// TestRelayChildSkillSnapshotConfined (P-026 a): on the daemon path a skill
// snapshot never scans or reads outside the run's roots, whatever cwd or
// transcript path the payload names.
func TestRelayChildSkillSnapshotConfined(t *testing.T) {
	ws, other := twoRepos(t)
	daemonProcess(t, ws)
	env := productionSkillSnapEnv()
	ctx := context.Background()
	if _, err := env.Scan(ctx, other, guidance.DefaultOptions()); !errors.Is(err, hookctx.ErrRefused) {
		t.Fatalf("a scan of another repository: %v", err)
	}
	if _, err := env.ReadSkill(other, filepath.Join(other, ".claude", "skills", "s", "SKILL.md"), 1<<20); !errors.Is(err, hookctx.ErrRefused) {
		t.Fatalf("a read in another repository: %v", err)
	}
	if _, err := env.ReadSkill(ws, filepath.Join(other, ".claude", "skills", "s", "SKILL.md"), 1<<20); !errors.Is(err, hookctx.ErrRefused) {
		t.Fatalf("a read outside its anchor's run: %v", err)
	}
	if _, err := env.Scan(ctx, ws, guidance.DefaultOptions()); errors.Is(err, hookctx.ErrRefused) {
		t.Fatalf("a scan of the run's own workspace was refused: %v", err)
	}
	snap, ok := buildSkillSnapshot(ctx, env, skillSnapRequest{SessionID: "s", Event: "session_start", Cwd: other, TranscriptPath: filepath.Join(other, ".claude", "projects", "x.jsonl")})
	if ok && len(snap.Members) > 0 {
		t.Fatalf("a snapshot anchored in another repository recorded %d members", len(snap.Members))
	}
}

// TestRelayChildDirResolvesLinks (P-026 d): the relay child's working
// directory is resolved before the roots check, so a link the box planted
// in the workspace cannot move the host child into another repository.
func TestRelayChildDirResolvesLinks(t *testing.T) {
	ws, other := twoRepos(t)
	if err := testSymlink(t, other, filepath.Join(ws, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	run := sandboxrelayd.RunRecord{WorkspaceDir: ws, Roots: []string{ws}}
	for cwd, want := range map[string]string{
		filepath.Join(ws, "sub"):  filepath.Join(ws, "sub"),
		filepath.Join(ws, "out"):  ws,
		other:                     ws,
		"":                        ws,
		filepath.Join(ws, "gone"): ws,
	} {
		if got := relayChildDir(run, cwd); got != want {
			t.Errorf("relayChildDir(%q) = %q, want %q", cwd, got, want)
		}
	}
}

// TestRelayRequestGated: the daemon's gate table is the registry's plan.
func TestRelayRequestGated(t *testing.T) {
	for _, tc := range []struct {
		req  sandboxrelay.HookRequest
		want bool
	}{
		{sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PreToolUse"}}, true},
		{sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PostToolUse"}}, false},
		{sandboxrelay.HookRequest{Kind: sandboxrelay.KindLaunchGate, Args: []string{"claude-code"}}, true},
	} {
		if got := relayRequestGated(tc.req); got != tc.want {
			t.Errorf("%v: gated %v, want %v", tc.req.Args, got, tc.want)
		}
	}
}

// boxRelay stands a run's relay up for the box side: the run record, the
// box record in a private socket dir, the daemon and the forwarder.
type boxRelay struct {
	mu      sync.Mutex
	live    []string
	replays []string
}

func startBoxRelay(t *testing.T, ws string, replayDelay time.Duration) *boxRelay {
	t.Helper()
	obs, sock := relayShortDir(t), relayShortDir(t)
	if err := os.Chmod(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	run, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-box", Tool: "claude-code", ProjectRoot: ws, WorkspaceDir: ws, Roots: []string{ws}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, run); err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteBoxRecord(sock, run); err != nil {
		t.Fatal(err)
	}
	b := &boxRelay{}
	d := &sandboxrelayd.Daemon{ObserverDir: obs, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser, Gated: relayRequestGated,
		Exec: func(_ context.Context, _ sandboxrelayd.RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			if req.Replay {
				time.Sleep(replayDelay)
			}
			b.mu.Lock()
			if req.Replay {
				b.replays = append(b.replays, req.Args[1])
			} else {
				b.live = append(b.live, req.Args[1])
			}
			b.mu.Unlock()
			return sandboxrelay.HookResponse{Stdout: []byte("{}")}, nil
		}}
	link := filepath.Join(obs, "link.sock")
	dln, err := net.Listen("unix", link)
	if err != nil {
		t.Fatal(err)
	}
	bln, err := net.Listen("unix", filepath.Join(sock, sandboxrelayd.RelaySocketName))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.Serve(ctx, dln) }()
	fw := &sandboxrelayd.Forwarder{Run: run, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser, DialDaemon: func(ctx context.Context) (net.Conn, error) {
		var dl net.Dialer
		return dl.DialContext(ctx, "unix", link)
	}}
	go func() { _ = fw.Serve(ctx, bln) }()
	oldSock, oldRec, oldSpool := boxSocketDir, boxRecordPath, relaySpoolDir
	boxSocketDir, boxRecordPath, relaySpoolDir = sock, filepath.Join(sock, sandboxrelayd.BoxRecordName), filepath.Join(t.TempDir(), "spool")
	t.Cleanup(func() { boxSocketDir, boxRecordPath, relaySpoolDir = oldSock, oldRec, oldSpool })
	return b
}

func (b *boxRelay) counts() (live, replays int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.live), len(b.replays)
}

func spoolFiles(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(relaySpoolDir)
	if err != nil {
		return 0
	}
	return len(entries)
}

// TestBoxReplayNeverDelaysAGate (P-026 b): a guest-filled spool cannot
// delay a gate answer: a gate event is answered with no replay at all, a
// capture-only event replays only after its own answer, and a gate event
// planted in the spool is refused by the daemon and dropped.
func TestBoxReplayNeverDelaysAGate(t *testing.T) {
	ws, _ := twoRepos(t)
	const delay = 400 * time.Millisecond
	b := startBoxRelay(t, ws, delay)
	for range 3 {
		if err := spoolRequest(sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PostToolUse"}, Stdin: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	// A gate event the guest planted in its own spool.
	if err := spoolRequest(sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "PreToolUse"}, Stdin: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	start := time.Now()
	code, boxed := boxHookRelay([]string{"claude-code", "PreToolUse"}, bytes.NewReader([]byte(`{}`)), &out, &errb)
	if took := time.Since(start); took >= delay {
		t.Fatalf("the gate answer took %s: a replay ran before or after it", took)
	}
	if !boxed || code != 0 || out.String() != "{}" {
		t.Fatalf("gate answer: boxed %v code %d out %q err %q", boxed, code, out.String(), errb.String())
	}
	if live, replays := b.counts(); live != 1 || replays != 0 || spoolFiles(t) != 4 {
		t.Fatalf("after the gate: live %d replays %d spool %d", live, replays, spoolFiles(t))
	}
	out.Reset()
	code, _ = boxHookRelay([]string{"claude-code", "PostToolUse"}, bytes.NewReader([]byte(`{}`)), &out, &errb)
	if code != 0 || out.String() != "{}" {
		t.Fatalf("capture answer: code %d out %q", code, out.String())
	}
	if live, replays := b.counts(); live != 2 || replays != 3 || spoolFiles(t) != 0 {
		t.Fatalf("after the capture event: live %d replays %d spool %d (the planted gate event must be refused and dropped)", live, replays, spoolFiles(t))
	}
}

// TestBoxRefusedAnswers (P-026 a): a request the host refused blocks a gate
// event and drops a capture-only one (never spooled).
func TestBoxRefusedAnswers(t *testing.T) {
	ws, other := twoRepos(t)
	b := startBoxRelay(t, ws, 0)
	foreign := []byte(`{"cwd":"` + other + `","session_id":"x"}`)
	var out, errb bytes.Buffer
	code, boxed := boxHookRelay([]string{"claude-code", "PreToolUse"}, bytes.NewReader(foreign), &out, &errb)
	if !boxed || (code == 0 && !bytes.Contains(out.Bytes(), []byte("deny")) && !bytes.Contains(out.Bytes(), []byte("block"))) {
		t.Fatalf("a refused gate event was not blocked: code %d out %q err %q", code, out.String(), errb.String())
	}
	out.Reset()
	code, _ = boxHookRelay([]string{"claude-code", "PostToolUse"}, bytes.NewReader(foreign), &out, &errb)
	if code != 0 || out.Len() != 0 || spoolFiles(t) != 0 {
		t.Fatalf("a refused capture event: code %d out %q spool %d", code, out.String(), spoolFiles(t))
	}
	if live, _ := b.counts(); live != 0 {
		t.Fatalf("the executor ran %d refused requests", live)
	}
}

// TestRelayRefusesAnotherRepositoryEndToEnd (P-026 a, through the real
// executor and database): a relayed event whose payload names another
// repository writes nothing; the same event in the run's workspace lands.
func TestRelayRefusesAnotherRepositoryEndToEnd(t *testing.T) {
	bin := probeHookTestBinary(t)
	ws, other := twoRepos(t)
	setTestHome(t, t.TempDir())
	h := startRelayHarness(t, bin, ws, "")
	args := []string{"claude-code", "UserPromptSubmit"}
	payload := func(cwd, sid string) []byte {
		return []byte(`{"session_id":"` + sid + `","hook_event_name":"UserPromptSubmit","cwd":"` + cwd + `","prompt":"hello"}`)
	}
	resp, err := h.relayed(t, sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: args, Cwd: ws, Stdin: payload(other, "foreign")})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Refused != sandboxrelay.RefusedPath {
		t.Fatalf("a payload naming another repository: %+v", resp)
	}
	if n := tableCounts(t, filepath.Join(h.obs, "observer.db")); len(n) != 0 {
		t.Fatalf("a refused event wrote rows: %v", n)
	}
	resp, err = h.relayed(t, sandboxrelay.HookRequest{Kind: sandboxrelay.KindHook, Args: args, Cwd: ws, Stdin: payload(ws, "own")})
	if err != nil || resp.Refused != "" {
		t.Fatalf("the run's own event: %+v %v", resp, err)
	}
	if n := tableCounts(t, filepath.Join(h.obs, "observer.db")); len(n) == 0 {
		t.Fatal("the run's own event never reached the database")
	}
}
