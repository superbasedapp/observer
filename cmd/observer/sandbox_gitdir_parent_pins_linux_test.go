//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// sandbox_gitdir_parent_pins_linux_test.go: the Linux live re-check 3 D2
// fix. Inside the box `mv .git/info .git/info-moved` then a fresh
// `.git/info/attributes` succeeded (and the same through objects/info and
// its alternates), because only `.git` itself was pinned: the read-only
// overlay moved with its renamed folder, and the host's git read both
// box-written files.

func gitForTest(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func gitInitForTest(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	gitForTest(t, dir, "init", "-q")
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n"), 0o600)
	gitForTest(t, dir, "add", "a.txt")
	gitForTest(t, dir, "commit", "-qm", "one")
}

// TestGitDirParentFoldersArePinned: the launch's pins hold, after each
// .git, the folders that hold a protected path, for a live workspace, an
// org write bind's repository and a submodule git dir under it, parents
// first.
func TestGitDirParentFoldersArePinned(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	ws := t.TempDir()
	gitInitForTest(t, ws)
	bind := t.TempDir()
	repo := filepath.Join(bind, "team", "repo")
	gitInitForTest(t, repo)
	mod := filepath.Join(repo, ".git", "modules", "lib")
	for _, d := range []string{"objects/info", "refs", "info", "hooks"} {
		if err := os.MkdirAll(filepath.Join(mod, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(mod, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, Egress: "none", ExtraRWBinds: []string{bind}}, nil, t.TempDir(), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.orgRWBinds = []string{bind}
	_, pins, err := rt.protection(t.TempDir(), ws, integration.SandboxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, gd := range []string{filepath.Join(ws, ".git"), filepath.Join(repo, ".git"), mod} {
		at := slices.Index(pins, gd)
		if at < 0 {
			t.Fatalf("%s is not pinned: %q", gd, pins)
		}
		prev := at
		for _, rel := range []string{"info", "objects", "objects/info"} {
			i := slices.Index(pins, filepath.Join(gd, rel))
			if i < 0 {
				t.Errorf("%s/%s is not pinned: %q", gd, rel, pins)
				continue
			}
			if i < prev {
				t.Errorf("%s/%s is pinned before its parent", gd, rel)
			}
			prev = i
		}
	}
}

// TestBwrapGitDirParentRenameRefused (D2 through the real launch path):
// renaming .git/info, .git/objects/info or .git/objects aside is refused in
// the box, so neither info/attributes nor objects/info/alternates can be
// recreated in a fresh folder; the box's own commit still works; the host's
// git reads nothing planted, and Observer's placeholders are gone after the
// run, none left in a moved folder.
func TestBwrapGitDirParentRenameRefused(t *testing.T) {
	bwrapUsableForTest(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	ws := t.TempDir()
	gitInitForTest(t, ws)
	// A placeholder must be created: neither file exists after an init.
	for _, p := range []string{".git/info/attributes", ".git/objects/info/alternates"} {
		_ = os.Remove(filepath.Join(ws, p))
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSandboxRuntime(config.TerminalSandboxConfig{Enabled: true, HomeMode: "tmpfs", Egress: "host"}, nil, t.TempDir(), exe, nil)
	if err != nil {
		t.Fatalf("newSandboxRuntime: %v", err)
	}
	res, err := rt.Prepare(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: ws, WorkspaceSource: "live"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	script := fmt.Sprintf(`
W=%[1]q; G=$W/.git
try() { if ( eval "$2" ) >/dev/null 2>&1; then echo "DONE $1"; else echo "BLOCKED $1"; fi; }
try infomv     "mv $G/info $G/info-moved"
try objinfomv  "mv $G/objects/info $G/objects/info-moved"
try objmv      "mv $G/objects $G/objects-moved"
try attrs      "echo '* diff=evil' > $G/info/attributes"
try alts       "echo /nowhere/objects > $G/objects/info/alternates"
try infonew    "rm -rf $G/info && mkdir $G/info && echo '* diff=evil' > $G/info/attributes"
try commit     "cd $W && echo two >> a.txt && GIT_AUTHOR_NAME=b GIT_AUTHOR_EMAIL=b@e GIT_COMMITTER_NAME=b GIT_COMMITTER_EMAIL=b@e git commit -qam two"
`, ws)
	out, err := runSandboxed(t, res.WrapArgv, home, script)
	if err != nil {
		t.Fatalf("sandboxed script failed: %v\n%s", err, out)
	}
	lines := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		lines[strings.TrimSpace(sc.Text())] = true
	}
	for _, name := range []string{"infomv", "objinfomv", "objmv", "attrs", "alts", "infonew"} {
		if !lines["BLOCKED "+name] {
			t.Errorf("%s was not refused inside the box:\n%s", name, out)
		}
	}
	if !lines["DONE commit"] {
		t.Errorf("the box's own commit failed:\n%s", out)
	}
	if got := gitForTest(t, ws, "check-attr", "diff", "a.txt"); strings.Contains(got, "evil") {
		t.Errorf("the host's git reads a planted attribute: %s", got)
	}
	if got := gitForTest(t, ws, "count-objects", "-v"); strings.Contains(got, "alternate") {
		t.Errorf("the host's git reads a planted alternate: %s", got)
	}
	for _, p := range []string{".git/info-moved", ".git/objects/info-moved", ".git/objects-moved", ".git/info/attributes", ".git/objects/info/alternates"} {
		if _, err := os.Lstat(filepath.Join(ws, p)); err == nil {
			t.Errorf("%s exists on the host after the run (a moved folder or a placeholder left behind)", p)
		}
	}
}
