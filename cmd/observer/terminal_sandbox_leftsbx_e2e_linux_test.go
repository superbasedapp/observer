//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_leftsbx_e2e_linux_test.go is lane LEFT-SBX's own
// end-to-end file (milestone 6): a bwrap launch in a repository with a real
// linked worktree and a large org-bind folder, and an oci worktree-source
// run through the fake engine.

// leftSBXRepoWithWorktree makes a repository with one commit and a real
// linked worktree (`git worktree add`) beside it; it returns the repository,
// the linked worktree and its git dir under .git/worktrees.
func leftSBXRepoWithWorktree(t *testing.T, base, name string) (repo, wt, wtGitDir string) {
	t.Helper()
	repo = filepath.Join(base, name)
	gitInitForTest(t, repo)
	wt = filepath.Join(base, name+"-feature")
	gitForTest(t, repo, "worktree", "add", "-q", "-b", "feature", wt)
	entries, err := os.ReadDir(filepath.Join(repo, ".git", "worktrees"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("git worktree add left %v (%v)", entries, err)
	}
	return repo, wt, filepath.Join(repo, ".git", "worktrees", entries[0].Name())
}

// leftSBXLargeFolder fills dir with n empty files (a build cache).
func leftSBXLargeFolder(t *testing.T, dir string, n int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := os.WriteFile(filepath.Join(dir, "c"+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestLeftSBXBwrapLinkedWorktreeAndLargeOrgBind: a live workspace with a
// real linked worktree, and an org write bind holding a 5000-entry cache
// folder and a repository with its own linked worktree. The plan protects
// both linked-worktree git dirs on the one table's rows and pins them, the
// large folder does not refuse the launch, and the tier variable comes only
// from the run's tier. Where bwrap runs, the box then cannot write either
// worktree git dir's commondir, can still write the cache folder, and the
// host's git in the linked worktree is unaffected.
func TestLeftSBXBwrapLinkedWorktreeAndLargeOrgBind(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	base := t.TempDir()
	if r, err := filepath.EvalSymlinks(base); err == nil {
		base = r
	}
	ws, wsTree, wsWT := leftSBXRepoWithWorktree(t, base, "ws")
	bind := filepath.Join(base, "orgbind")
	cache := filepath.Join(bind, "cache")
	leftSBXLargeFolder(t, cache, 5000)
	_, _, bindWT := leftSBXRepoWithWorktree(t, bind, "team")

	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv(sandbox.EnvEgress, "host") // a spoofed inherited tier
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "none", ExtraRWBinds: []string{bind}}, nil, t.TempDir(), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.orgRWBinds = []string{bind}

	ovs, pins, err := rt.protection(home, ws, integration.SandboxSpec{})
	if err != nil {
		t.Fatalf("a 5000-entry cache folder below an org bind refused the plan: %v", err)
	}
	got := map[string]sandbox.Overlay{}
	for _, o := range ovs {
		got[o.Path] = o
	}
	for _, gd := range []string{wsWT, bindWT} {
		if o, ok := got[filepath.Join(gd, "commondir")]; !ok || o.Kind != sandbox.OverlayReadOnly {
			t.Errorf("%s/commondir is not read-only in the plan: %+v (present %v)", gd, o, ok)
		}
		if !slices.Contains(pins, gd) {
			t.Errorf("%s is not pinned", gd)
		}
	}

	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not on PATH: the plan half ran, the live half is a live check")
	}
	bwrapUsableForTest(t)
	res, err := rt.Prepare(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: ws, WorkspaceSource: "live"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	script := fmt.Sprintf(`
try() { if ( eval "$2" ) >/dev/null 2>&1; then echo "DONE $1"; else echo "BLOCKED $1"; fi; }
try wscommondir   "echo /tmp/evil > %[1]s/commondir"
try bindcommondir "echo /tmp/evil > %[2]s/commondir"
try wsrename      "mv %[1]s %[1]s-moved"
try cache         "echo ok > %[3]s/c1"
echo "TIER=$%[4]s"
`, wsWT, bindWT, cache, sandbox.EnvEgress)
	out, err := runSandboxed(t, res.WrapArgv, home, script)
	if err != nil {
		t.Fatalf("sandboxed script failed: %v\n%s", err, out)
	}
	lines := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		lines[strings.TrimSpace(sc.Text())] = true
	}
	for _, name := range []string{"wscommondir", "bindcommondir", "wsrename"} {
		if !lines["BLOCKED "+name] {
			t.Errorf("%s was not refused inside the box:\n%s", name, out)
		}
	}
	if !lines["DONE cache"] {
		t.Errorf("the box could not write the org bind's cache folder:\n%s", out)
	}
	if lines["TIER=host"] {
		t.Errorf("the inherited tier reached the box:\n%s", out)
	}
	if got := gitForTest(t, wsTree, "rev-parse", "--git-common-dir"); !strings.HasSuffix(got, filepath.Join("ws", ".git")) {
		t.Errorf("the host's git in the linked worktree reads %q", got)
	}
}

// TestLeftSBXOCIWorktreeSourceRefusedThroughTheFakeEngine: with the
// worktree source on and oci-runc the node's container backend (a healthy
// fake engine), the picker offers the source unavailable naming oci-runc,
// and a launch that asks for it is refused before anything happens: no
// `git worktree add` in the main repository, no container created, no
// engine call beyond what the probe needs (the lane's decision: the oci
// route stays refused until its object-store return is proven live).
func TestLeftSBXOCIWorktreeSourceRefusedThroughTheFakeEngine(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	stubWorktreeOrgPin(t, false)
	countProbeEnv(t, true)
	f := newOCIFake(t)
	cfg := ociTestConfig(t, true, "oci-runc")
	cfg.Terminal.Sandbox.AllowWorktreeSource = true
	cfg.Terminal.Sandbox.OCI.Socket = f.sock
	rt := ociTestRuntime(t, cfg)
	if _, ok := rt.drivers[sandboxbackend.BackendOCIRunc]; !ok {
		t.Fatalf("the oci driver is not active: %v", rt.inactiveDrivers)
	}
	var src *struct {
		ok     bool
		reason string
	}
	for _, s := range rt.sources() {
		if s.ID == string(workspace.SourceWorktree) {
			src = &struct {
				ok     bool
				reason string
			}{s.Available, s.Reason}
		}
	}
	if src == nil || src.ok || !strings.Contains(src.reason, sandboxbackend.BackendOCIRunc) {
		t.Fatalf("worktree source on an oci node: %+v, want unavailable naming oci-runc", src)
	}
	repo := filepath.Join(t.TempDir(), "repo")
	gitInitForTest(t, repo)
	// The launch names the container row (oci-runc is beta, so only a named
	// launch takes it, P-062), as `observer <tool> --observer-sandbox
	// oci-runc` does.
	rt.forceBackend = sandboxbackend.BackendOCIRunc
	_, err := rt.Prepare(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: repo, WorkspaceSource: "worktree"})
	if err == nil {
		t.Fatal("a worktree-source launch on an oci node was prepared")
	}
	if !strings.Contains(err.Error(), "bwrap") {
		t.Errorf("the refusal does not say the source runs only on bwrap: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(repo, ".git", "worktrees")); serr == nil {
		t.Error("the refused launch still ran git worktree add in the main repository")
	}
	f.mu.Lock()
	creates := f.creates
	f.mu.Unlock()
	if creates != 0 {
		t.Errorf("the refused launch created %d containers", creates)
	}
	if f.callIndex("POST /containers/create") >= 0 {
		t.Error("the refused launch reached the engine's create")
	}
}
