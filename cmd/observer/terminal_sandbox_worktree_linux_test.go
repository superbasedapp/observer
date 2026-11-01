//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestBwrapWorktreeSourceBox is the live proof of milestones 1 to 3 through
// the real launch path (Prepare -> host helper -> bwrap) in this test
// binary. The main repository sits under the box's blinded home, so the box
// reaches it only through the worktree binds. Inside the box git commits on
// the run's branch, while every write that would change what the next host
// git command runs or which commit a host ref names is refused: a planted
// hook, the config, info/, config.worktree, alternates, the worktree's
// pointers, the main checkout's HEAD and index, packed-refs, another
// branch, a new branch, a tag and another worktree's git dir. After the run
// the watcher ends it: the clean worktree goes, the branch with the commit
// stays. It runs with allow_tool_config_writes off and on: the worktree
// protections hold either way.
func TestBwrapWorktreeSourceBox(t *testing.T) {
	bwrapUsableForTest(t)
	for _, writes := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_tool_config_writes=%v", writes), func(t *testing.T) { bwrapWorktreeSourceBox(t, writes) })
	}
}

func bwrapWorktreeSourceBox(t *testing.T, toolConfigWrites bool) {
	for _, bin := range []string{"bash", "git"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH - skipping", bin)
		}
	}
	old := sandboxWorktreeEndPoll
	sandboxWorktreeEndPoll = 50 * time.Millisecond
	t.Cleanup(func() { sandboxWorktreeEndPoll = old })

	home := t.TempDir()
	t.Setenv("HOME", home)
	repo := filepath.Join(home, "src", "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wtGit(t, repo, "init", "-q")
	wtGit(t, repo, "checkout", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wtGit(t, repo, "add", "-A")
	wtGit(t, repo, "commit", "-q", "-m", "init")
	wtGit(t, repo, "branch", "other")
	wtGit(t, repo, "tag", "v1")
	// Another worktree whose git dir the box must not touch.
	wtGit(t, repo, "worktree", "add", "-q", "-b", "feature", filepath.Join(home, "src", "feature"))
	common := filepath.Join(repo, ".git")
	mainSHA := gitOut(t, repo, "rev-parse", "HEAD")
	snapshot := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(common, rel))
		if err != nil {
			return "<missing>"
		}
		return string(b)
	}
	watched := []string{
		"config", "HEAD", "index", "packed-refs", "refs/heads/main", "refs/heads/other", "refs/tags/v1",
		"info/exclude", "worktrees/feature/HEAD", "objects/info/alternates", "config.worktree",
	}
	before := map[string]string{}
	for _, rel := range watched {
		before[rel] = snapshot(rel)
	}

	stubWorktreeOrgPin(t, false)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "host", AllowWorktreeSource: true, AllowToolConfigWrites: toolConfigWrites}, nil, t.TempDir(), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Prepare(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: repo, WorkspaceSource: "worktree"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	ws := res.Dir
	runID := filepath.Base(filepath.Dir(ws))
	branch := "observer-sandbox/" + runID + "/work"
	admin := filepath.Join(common, "worktrees", filepath.Base(ws))

	script := fmt.Sprintf(`
C=%[1]q; W=%[2]q; A=%[3]q
export GIT_AUTHOR_NAME=box GIT_AUTHOR_EMAIL=box@example.com GIT_COMMITTER_NAME=box GIT_COMMITTER_EMAIL=box@example.com
try() { if ( eval "$2" ) >/dev/null 2>&1; then echo "DONE $1"; else echo "BLOCKED $1"; fi; }
cd $W
try commit      "printf w > work.txt && git add work.txt && git commit -q -m box"
try hook        "printf '#!/bin/sh\necho pwned\n' > $C/hooks/post-checkout"
try hookdir     "mkdir $C/hooks/x"
try config      "printf '[core]\n\tfsmonitor = evil\n' >> $C/config"
try gitconfig   "git config core.hooksPath /tmp/evil"
try info        "printf x >> $C/info/exclude"
try cfgwt       "printf x > $C/config.worktree"
try alternates  "printf /tmp/evil > $C/objects/info/alternates"
try commondir   "printf /tmp/evil > $A/commondir"
try gitdir      "printf /tmp/evil > $A/gitdir"
try admincfg    "printf x > $A/config.worktree"
try gitfile     "printf 'gitdir: /tmp/evil' > $W/.git"
try mainhead    "printf 'ref: refs/heads/other\n' > $C/HEAD"
try mainindex   "printf x > $C/index"
try packed      "printf x > $C/packed-refs"
try mainref     "git update-ref refs/heads/main HEAD"
try newbranch   "git branch evil"
try tag         "git tag evil"
try otherwt     "printf x > $C/worktrees/feature/HEAD"
git rev-parse HEAD
`, common, ws, admin)
	out, err := runSandboxed(t, res.WrapArgv, home, script)
	if err != nil {
		t.Fatalf("sandboxed script failed: %v\n%s", err, out)
	}
	lines := map[string]bool{}
	var boxHead string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		lines[l] = true
		if len(l) == 40 {
			boxHead = l
		}
	}
	if !lines["DONE commit"] {
		t.Fatalf("git could not commit on the run's branch inside the box:\n%s", out)
	}
	for _, name := range []string{
		"hook", "hookdir", "config", "gitconfig", "info", "cfgwt", "alternates", "commondir", "gitdir", "admincfg",
		"gitfile", "mainhead", "mainindex", "packed", "mainref", "newbranch", "tag", "otherwt",
	} {
		if !lines["BLOCKED "+name] {
			t.Errorf("%s was not refused inside the box:\n%s", name, out)
		}
	}
	// On the host: nothing the next host git command runs or follows
	// changed, and the main checkout's refs are where they were.
	for _, rel := range watched {
		if got := snapshot(rel); got != before[rel] {
			t.Errorf("host %s changed: %q -> %q", rel, before[rel], got)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(common, "hooks")); len(entries) > 0 {
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".sample") {
				t.Errorf("a hook appeared on the host: %s", e.Name())
			}
		}
	}
	if gitOut(t, repo, "rev-parse", "refs/heads/main") != mainSHA {
		t.Error("the main branch moved")
	}
	if got := gitOut(t, repo, "rev-parse", "refs/heads/"+branch); got != boxHead || got == mainSHA {
		t.Fatalf("the run's branch = %q, want the box's commit %q", got, boxHead)
	}

	// The run ended (the host helper removed its relay record): the
	// watcher removes the clean worktree and keeps the branch with the
	// commit, listed.
	claim := filepath.Join(r.observerDir, sandboxWorktreeDirName, "."+runID+".ending")
	deadline := time.Now().Add(20 * time.Second)
	for {
		rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(r.observerDir, runID))
		_, cerr := os.Lstat(claim)
		if err == nil && rec.State == sandboxWorktreeKept && os.IsNotExist(cerr) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ended run was not finished: record %+v %v", rec, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Lstat(ws); !os.IsNotExist(err) {
		t.Errorf("the ended run's clean worktree %s was not removed (%v)", ws, err)
	}
	if gitOut(t, repo, "rev-parse", "refs/heads/"+branch) != boxHead {
		t.Error("the branch holding the run's commit was not kept")
	}
	rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(r.observerDir, runID))
	if err != nil || rec.State != sandboxWorktreeKept || !strings.Contains(rec.Reason, branch) {
		t.Errorf("record after the end = %+v %v, want kept naming the branch", rec, err)
	}
	if meta, ok := readWorkspaceMeta(filepath.Dir(ws)); !ok || meta.Branch != branch {
		t.Errorf("meta.json for `observer workspaces ls` = %+v %v, want branch %q", meta, ok, branch)
	}
}
