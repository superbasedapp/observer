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

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestBwrapRepositoryGitRenameRefused is the live proof of the pins
// (SBX-WORKTREE-SOURCE audit finding 4) through the real launch path
// (Prepare -> host helper -> bwrap): inside the box a repository two levels
// under an org write bind, and the live workspace's own repository, keep
// their .git writable, but neither the .git nor the repository folder can be
// renamed aside (EBUSY), so no replacement .git with a planted config or
// hook can take their place; the hooks and config stay read-only.
func TestBwrapRepositoryGitRenameRefused(t *testing.T) {
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH - skipping")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	observerDir := t.TempDir()
	ws := t.TempDir()
	mkGitDir(t, ws)
	bind := t.TempDir()
	repo := filepath.Join(bind, "team", "repo")
	mkGitDir(t, repo)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "host", ExtraRWBinds: []string{bind}}, nil, observerDir, exe, nil)
	if err != nil {
		t.Fatalf("newSandboxRuntime: %v", err)
	}
	rt.orgRWBinds = []string{bind}
	res, err := rt.Prepare(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: ws, WorkspaceSource: "live"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	script := fmt.Sprintf(`
R=%[1]q; W=%[2]q
try() { if ( eval "$2" ) >/dev/null 2>&1; then echo "DONE $1"; else echo "BLOCKED $1"; fi; }
try orgwrite   "printf x > $R/.git/scratch"
try wswrite    "printf x > $W/.git/scratch"
try orggitmv   "mv $R/.git $R/.git.old"
try orgrepomv  "mv $R $R.old"
try wsgitmv    "mv $W/.git $W/.git.old"
try orghook    "printf x > $R/.git/hooks/post-commit"
try orgconfig  "printf x >> $R/.git/config"
`, repo, ws)
	out, err := runSandboxed(t, res.WrapArgv, home, script)
	if err != nil {
		t.Fatalf("sandboxed script failed: %v\n%s", err, out)
	}
	lines := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		lines[strings.TrimSpace(sc.Text())] = true
	}
	for _, name := range []string{"orgwrite", "wswrite"} {
		if !lines["DONE "+name] {
			t.Errorf("%s: a write inside a pinned .git was refused (the pin must keep it writable):\n%s", name, out)
		}
	}
	for _, name := range []string{"orggitmv", "orgrepomv", "wsgitmv", "orghook", "orgconfig"} {
		if !lines["BLOCKED "+name] {
			t.Errorf("%s was not refused inside the box:\n%s", name, out)
		}
	}
	for _, p := range []string{filepath.Join(repo, ".git", "config"), filepath.Join(ws, ".git", "config")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("host %s is gone after the run: %v", p, err)
		}
	}
	for _, p := range []string{repo + ".old", filepath.Join(repo, ".git.old"), filepath.Join(ws, ".git.old")} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("a rename reached the host: %s exists", p)
		}
	}
}
