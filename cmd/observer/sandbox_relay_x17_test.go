//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/secipc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// x17Node is one node's security state for the X17 check: a guard-enforced
// config whose signed guard posture says the security module is active, a
// git project with a signed CLEAN project posture, and the quick-scan
// endpoint served with the production scanner (the daemon's role).
type x17Node struct {
	obs, cfg, ws string
}

func newX17Node(t *testing.T, staged string) x17Node {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	n := x17Node{obs: relayShortDir(t), ws: t.TempDir()}
	n.cfg = writeRelayConfig(t, n.obs, "[guard]\nenabled = true\nmode = \"enforce\"\n")
	key, err := guardposture.LoadOrCreateKey(guardposture.KeyPath(n.cfg))
	if err != nil {
		t.Fatal(err)
	}
	gp := enforcedPosture
	gp.SecurityRecorded, gp.SecurityActive, gp.WrittenAt = true, true, time.Now()
	// The merged gate (lane SEC-GATEFIX) reads the active pack set the
	// guard posture signs.
	gp.SecurityPacks = []string{"security", "security.secrets"}
	if _, err := guardposture.Write(guardposture.PosturePath(n.cfg), gp, key); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...) //nolint:gosec // G204: fixed git argv in a temp repo
		cmd.Dir = n.ws
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(n.ws, "README"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "README")
	git("commit", "-q", "-m", "init")
	layout := secposture.LayoutFor(n.cfg)
	pkey, err := secposture.LoadOrCreateKey(layout.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// QuickScanAvailable: the daemon serves the quick-scan endpoint below,
	// so its posture file says so (the hook honours a file that says it
	// does not, lane SEC-GATEFIX milestone 2g).
	f := secposture.File{
		ProjectRootHash: secposture.ProjectRootHash(n.ws), Packs: []string{"security", "security.secrets"}, Sequence: 1,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), QuickScanAvailable: true,
	}
	if _, err := secposture.Write(layout, f, pkey); err != nil {
		t.Fatal(err)
	}
	// What the agent's write left staged (the write itself happened through
	// a shell, so the hook saw a write-capable call, not the content).
	if err := os.WriteFile(filepath.Join(n.ws, "cfg.py"), []byte(staged), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "cfg.py")
	ln, _, err := secipc.Listen(layout.Dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = secipc.Serve(ctx, ln, securityQuickScanner(layout, newSecurityQuickScanEngine(func(string, string) string { return "" })))
	}()
	return n
}

// x17Payloads are the agent's two calls: a shell write, then a commit at
// once (the security plan's X17).
func x17Payloads(ws string) [][]byte {
	call := func(cmd string) []byte {
		return []byte(fmt.Sprintf(`{"session_id":"x17","hook_event_name":"PreToolUse","cwd":%q,"tool_name":"Bash","tool_input":{"command":%q}}`, ws, cmd))
	}
	return [][]byte{call("printf x >> cfg.py"), call("git commit -m wip")}
}

// TestRelayX17CommitGateInsideTheBox is the P2 acceptance tied to the
// security plan's X17 (sandbox plan section 13 P2, revision 5 M1): with the
// security module active, an agent's write-then-commit relayed out of a box
// gets the same security state, and so the same answer, as the same calls
// on the host. A staged secret is found by the quick scan and the commit is
// asked; the same commit without it proceeds with no prompt.
func TestRelayX17CommitGateInsideTheBox(t *testing.T) {
	bin := probeHookTestBinary(t)
	setTestHome(t, t.TempDir())
	const secret = "aws_access_key_id = \"" + fakeSecretAWSKeyID + "\"\n"
	answers := map[string][]byte{}
	for _, tc := range []struct {
		name, staged string
	}{{"secret", secret}, {"clean", "x = 1\n"}} {
		direct1 := newX17Node(t, tc.staged)
		var dout []byte
		for _, p := range x17Payloads(direct1.ws) {
			_, dout = direct(t, bin, direct1.cfg, direct1.ws, []string{"codex", "PreToolUse"}, p)
		}
		boxed := newX17Node(t, tc.staged)
		h := &relayHarness{obs: boxed.obs, cfg: boxed.cfg}
		rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-x17", Tool: "codex", ProjectRoot: boxed.ws, WorkspaceDir: boxed.ws, Roots: []string{boxed.ws}})
		if err != nil {
			t.Fatal(err)
		}
		h.rec = rec
		if err := sandboxrelayd.WriteRun(h.obs, rec); err != nil {
			t.Fatal(err)
		}
		h.link = filepath.Join(h.obs, "link.sock")
		ln, err := net.Listen("unix", h.link)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		d := &sandboxrelayd.Daemon{ObserverDir: h.obs, Exec: relayExecutor(h.cfg, bin), Rules: relayRules, Peer: sandboxrelayd.PeerSameUser}
		go func() { _ = d.Serve(ctx, ln) }()
		var rout []byte
		for _, p := range x17Payloads(boxed.ws) {
			resp, err := h.relayed(t, sandboxrelay.HookRequest{
				Kind: sandboxrelay.KindHook, Args: []string{"codex", "PreToolUse"}, Cwd: boxed.ws,
				Env: map[string]string{sandboxEnvMarker: "1"}, Stdin: p,
			})
			if err != nil {
				cancel()
				t.Fatalf("%s: relayed: %v", tc.name, err)
			}
			rout = resp.Stdout
		}
		cancel()
		if !bytes.Equal(rout, dout) {
			t.Errorf("%s: the commit in the box answered %s, on the host %s", tc.name, rout, dout)
		}
		answers[tc.name] = rout
	}
	t.Logf("secret commit: %s; clean commit: %s", answers["secret"], answers["clean"])
	if !bytes.Contains(answers["secret"], []byte(`"permissionDecision":"ask"`)) && !bytes.Contains(answers["secret"], []byte(`"permissionDecision":"deny"`)) {
		t.Errorf("the commit with a staged secret was not stopped: %s", answers["secret"])
	}
	if bytes.Contains(answers["clean"], []byte(`"permissionDecision":"ask"`)) || bytes.Contains(answers["clean"], []byte(`"permissionDecision":"deny"`)) {
		t.Errorf("the clean commit was stopped: %s", answers["clean"])
	}
}

// TestRelayX17CommitGateInACloneRun is X17 under clone delivery (audit
// finding 1 of lane sbx-p2b): the original project holds a signed clean
// posture and a clean index, the run's clone has a secret staged, and the
// agent's relayed write-then-commit inside the clone is still stopped. Had
// the relay keyed the run on the original project, the quick scan would
// read the original's clean index and wave the commit through.
func TestRelayX17CommitGateInACloneRun(t *testing.T) {
	bin := probeHookTestBinary(t)
	setTestHome(t, t.TempDir())
	orig := newX17Node(t, "x = 1\n")
	clone := filepath.Join(t.TempDir(), "clone")
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...) //nolint:gosec // G204: fixed git argv in a temp repo
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git(filepath.Dir(clone), "clone", "-q", orig.ws, clone)
	secret := "aws_access_key_id = \"" + fakeSecretAWSKeyID + "\"\n"
	if err := os.WriteFile(filepath.Join(clone, "cfg.py"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	git(clone, "add", "cfg.py")
	h := &relayHarness{obs: orig.obs, cfg: orig.cfg}
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{
		RunID: "run-x17c", Tool: "codex", ProjectRoot: orig.ws, WorkspaceDir: clone, Roots: []string{clone},
		Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: clone,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.rec = rec
	if err := sandboxrelayd.WriteRun(h.obs, rec); err != nil {
		t.Fatal(err)
	}
	h.link = filepath.Join(h.obs, "link.sock")
	ln, err := net.Listen("unix", h.link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &sandboxrelayd.Daemon{ObserverDir: h.obs, Exec: relayExecutor(h.cfg, bin), Rules: relayRules, Peer: sandboxrelayd.PeerSameUser}
	go func() { _ = d.Serve(ctx, ln) }()
	var out []byte
	for _, p := range x17Payloads(clone) {
		resp, err := h.relayed(t, sandboxrelay.HookRequest{
			Kind: sandboxrelay.KindHook, Args: []string{"codex", "PreToolUse"}, Cwd: clone,
			Env: map[string]string{sandboxEnvMarker: "1"}, Stdin: p,
		})
		if err != nil {
			t.Fatalf("relayed: %v", err)
		}
		out = resp.Stdout
	}
	t.Logf("clone commit: %s", out)
	if !bytes.Contains(out, []byte(`"permissionDecision":"ask"`)) && !bytes.Contains(out, []byte(`"permissionDecision":"deny"`)) {
		t.Errorf("the commit of a secret staged in the clone was not stopped: %s", out)
	}
}
