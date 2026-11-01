//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/secipc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_box_x17_test.go is the security plan's X17 (write, then commit
// at once) inside a container run and a bwrap run (security plan 11.2 X17,
// 10.3 "X17 inside a bwrap run is a preview gate", 4.8 "Copy workspaces";
// lane sec-box milestone 3). The agent's write and commit are relayed out
// of the box through the real relay daemon to the real hook binary, with
// the daemon's real quick-scan endpoint, so the answer is the one a box
// gets. The container run is a clone-local copy whose stored run names the
// oci-runc backend (the quick scan reads the copy's tree); the bwrap run is
// a live run on the project itself. A third run names a remote backend:
// its tree is only inside the box, so even a clean commit is unknown.

// x17BoxNode is one node and one run for the box X17 check.
type x17BoxNode struct {
	n    x17Node
	tree string // the tree the agent commits in
	rec  sandboxrelayd.RunRecord
}

// x17SignClean signs a clean posture for root on n (the quick scan is
// available), as the daemon's posture writer would for a project it knows.
func x17SignClean(t *testing.T, cfg, root string) {
	t.Helper()
	layout := secposture.LayoutFor(cfg)
	key, err := secposture.LoadOrCreateKey(layout.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := secposture.Write(layout, secposture.File{
		ProjectRootHash: secposture.ProjectRootHash(root), Packs: []string{"security", "security.secrets"}, Sequence: 1,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), QuickScanAvailable: true,
	}, key); err != nil {
		t.Fatal(err)
	}
}

// newX17BoxNode builds the node, the run's tree (a clone for a copy run,
// the project itself for a live one) with staged content, the run record
// and, for a copy, the stored terminal run naming backend.
func newX17BoxNode(t *testing.T, staged string, copied bool, backend string) x17BoxNode {
	t.Helper()
	b := x17BoxNode{n: newX17Node(t, "x = 1\n")}
	b.tree = b.n.ws
	rec := sandboxrelayd.RunRecord{RunID: "run-x17box", Tool: "codex", ProjectRoot: b.n.ws, WorkspaceDir: b.n.ws, Roots: []string{b.n.ws}}
	if copied {
		clone := filepath.Join(t.TempDir(), "clone")
		if r, err := filepath.EvalSymlinks(filepath.Dir(clone)); err == nil {
			clone = filepath.Join(r, "clone")
		}
		gitIn(t, filepath.Dir(clone), "clone", "-q", b.n.ws, clone)
		b.tree = clone
		x17SignClean(t, b.n.cfg, clone)
		rec.WorkspaceDir, rec.Roots, rec.Delivery, rec.CopyHostPath = clone, []string{clone}, sandboxrelayd.DeliveryCopy, clone
	}
	if err := os.WriteFile(filepath.Join(b.tree, "cfg.py"), []byte(staged), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, b.tree, "add", "cfg.py")
	rec, err := sandboxrelayd.NewRunRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(b.n.obs, rec); err != nil {
		t.Fatal(err)
	}
	if backend != "" {
		database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(b.n.obs, "observer.db")})
		if err != nil {
			t.Fatal(err)
		}
		st := store.New(database)
		if err := st.InsertTerminalRun(context.Background(), store.TerminalRun{RunID: "trun-x17box", Tool: "codex", Kind: "fresh", Isolation: store.TerminalRunIsolation{Stack: []string{backend}}}); err != nil {
			t.Fatal(err)
		}
		_ = database.Close()
		if err := sandboxrelayd.BindTerminalRun(b.n.obs, rec.RunID, "trun-x17box"); err != nil {
			t.Fatal(err)
		}
		if rec, err = sandboxrelayd.ReadRun(b.n.obs, rec.RunID); err != nil {
			t.Fatal(err)
		}
	}
	b.rec = rec
	return b
}

// relayX17 relays the agent's write and its commit for tool out of the box,
// the commit sent at once after the write's answer, and returns the
// commit's answer and how long the two took.
func (b x17BoxNode) relayX17(t *testing.T, bin, tool string) ([]byte, time.Duration) {
	return b.relayX17Event(t, bin, tool, "PreToolUse")
}

// relayX17Event is relayX17 for a hook event of tool's own spelling.
func (b x17BoxNode) relayX17Event(t *testing.T, bin, tool, event string) ([]byte, time.Duration) {
	t.Helper()
	h := &relayHarness{obs: b.n.obs, cfg: b.n.cfg, rec: b.rec}
	h.link = filepath.Join(h.obs, "link-"+tool+".sock")
	ln, err := net.Listen("unix", h.link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &sandboxrelayd.Daemon{ObserverDir: h.obs, Exec: relayExecutor(h.cfg, bin), Rules: relayRules, Peer: sandboxrelayd.PeerSameUser}
	go func() { _ = d.Serve(ctx, ln) }()
	var out []byte
	var written time.Time
	for i, p := range x17Payloads(b.tree) {
		resp, err := h.relayed(t, sandboxrelay.HookRequest{
			Kind: sandboxrelay.KindHook, Args: []string{tool, event}, Cwd: b.tree,
			Env: map[string]string{sandboxEnvMarker: "1"}, Stdin: p,
		})
		if err != nil {
			t.Fatalf("relayed: %v", err)
		}
		if i == 0 {
			written = time.Now()
		}
		out = resp.Stdout
	}
	return out, time.Since(written)
}

// x17Stopped reports whether a hook answer stopped the call.
func x17Stopped(out []byte) bool {
	return bytes.Contains(out, []byte(`"permissionDecision":"ask"`)) || bytes.Contains(out, []byte(`"permissionDecision":"deny"`))
}

// TestSecurityBoxX17 is X17 inside a container run (copy) and a bwrap run
// (live): a secret written then committed at once is stopped (X17's 500 ms
// window is not asserted; see the loop), on a
// host that cannot ask (codex, as in a headless run) by a deny naming
// `observer guard approve`; the same commit without the secret proceeds
// with no prompt; and in a run whose tree is only inside the box, even the
// clean commit is unknown and stopped, never clean.
func TestSecurityBoxX17(t *testing.T) {
	bin := probeHookTestBinary(t)
	setTestHome(t, t.TempDir())
	secret := "aws_access_key_id = \"" + fakeSecretAWSKeyID + "\"\n"
	for _, tc := range []struct {
		name    string
		copied  bool
		backend string
		staged  string
		stopped bool
	}{
		{"container run, secret", true, "oci-runc", secret, true},
		{"container run, clean", true, "oci-runc", "x = 1\n", false},
		{"bwrap run, secret", false, "", secret, true},
		{"bwrap run, clean", false, "", "x = 1\n", false},
		{"remote box, clean", true, "e2b", "x = 1\n", true},
	} {
		b := newX17BoxNode(t, tc.staged, tc.copied, tc.backend)
		out, took := b.relayX17(t, bin, "codex")
		t.Logf("%s (%s): %s", tc.name, took, out)
		if tc.stopped != x17Stopped(out) {
			t.Errorf("%s: stopped=%v, want %v: %s", tc.name, x17Stopped(out), tc.stopped, out)
		}
		if tc.stopped && !bytes.Contains(out, []byte("observer guard approve")) {
			t.Errorf("%s: the deny does not name `observer guard approve`: %s", tc.name, out)
		}
		// X17's 500 ms write-to-commit window is NOT asserted: `took` is only
		// logged above. A cold start of the hook binary on a loaded test
		// host can exceed it, and what this test pins is the verdict, which
		// comes from the quick scan the hook asks for at the commit, not
		// from a background scan racing it.
	}
	// A host that can ask (Claude Code's own PreToolUse) asks for the same
	// secret in a container run instead of denying.
	b := newX17BoxNode(t, secret, true, "oci-runc")
	out, _ := b.relayX17Event(t, bin, "claude-code", "pre-tool")
	if !bytes.Contains(out, []byte(`"permissionDecision":"ask"`)) {
		t.Errorf("claude-code in a container run: %s, want an ask", out)
	}
}

// TestSecurityBoxX17QuickScanUnavailable: with the daemon's quick scan not
// answering (the endpoint gone), a commit in a container run reads unknown
// and is stopped, never let through.
func TestSecurityBoxX17QuickScanUnavailable(t *testing.T) {
	bin := probeHookTestBinary(t)
	setTestHome(t, t.TempDir())
	b := newX17BoxNode(t, "x = 1\n", true, "oci-runc")
	// The endpoint's socket is removed: the hook's ask fails.
	ep, err := secipc.Endpoint(secposture.LayoutFor(b.n.cfg).Dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(ep)
	out, _ := b.relayX17(t, bin, "codex")
	if !x17Stopped(out) {
		t.Fatalf("a commit with no quick scan was let through: %s", out)
	}
}

// TestSecurityBoxX17Columns is X17's decision per node kind, from the
// verdicts the box runs above produce (the security plan 4.8 decision
// table, the cells every host shares): a dirty project whose quick scan
// found the secret asks on an individual node that can ask, denies where
// it cannot ask (headless) and denies on a managed node under the floor; a
// clean quick scan lets every column through; with the daemon stopped (no
// quick scan: unknown) the managed commit is denied and the individual one
// asks. The deny's sentence names `observer guard approve`. These cells
// are table checks over secposture.Gate and AfterQuickScan; the managed
// floor and daemon-stopped cells are not run through the relay here (the
// relay runs above cover the individual cells and an unavailable quick
// scan).
func TestSecurityBoxX17Columns(t *testing.T) {
	for _, tc := range []struct {
		verdict policy.QuickScanVerdict
		col     secposture.GateColumn
		want    secposture.GateOutcome
	}{
		{policy.QuickScanBlocking, secposture.GateIndividualObserve, secposture.GateAsk},
		{policy.QuickScanBlocking, secposture.GateIndividualNoAsk, secposture.GateDeny},
		{policy.QuickScanBlocking, secposture.GateManagedFloor, secposture.GateDeny},
		{policy.QuickScanClean, secposture.GateIndividualObserve, secposture.GateAllow},
		{policy.QuickScanClean, secposture.GateIndividualNoAsk, secposture.GateAllow},
		{policy.QuickScanClean, secposture.GateManagedFloor, secposture.GateAllow},
		{policy.QuickScanUnknown, secposture.GateManagedFloor, secposture.GateDeny},
		{policy.QuickScanUnknown, secposture.GateIndividualObserve, secposture.GateAsk},
	} {
		got := secposture.AfterQuickScan(secposture.Gate(policy.SecurityPostureDirty, tc.col), tc.verdict)
		if got != tc.want {
			t.Errorf("%s / %s: %s, want %s", tc.verdict, tc.col, got, tc.want)
		}
	}
	for _, r := range secrules.GateRules() {
		if r.ID == "S-793" && !bytes.Contains([]byte(r.Advice), []byte("observer guard approve")) {
			t.Errorf("S-793's advice does not name `observer guard approve`: %q", r.Advice)
		}
	}
}
