//go:build !sbo_omit_security && !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secgithooks"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
)

func githookRepo(t *testing.T) (string, func(args ...string) error) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) error {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := c.CombinedOutput()
		if err != nil {
			return errors.New(string(out))
		}
		return nil
	}
	for _, a := range [][]string{{"init", "-q"}, {"config", "user.email", "t@example.invalid"}, {"config", "user.name", "t"}} {
		if err := run(a...); err != nil {
			t.Fatal(err)
		}
	}
	return dir, run
}

// TestGithooksBlockFailsOpenThroughGit runs real commits through the
// installed hook with a stand-in observer: the refusal status refuses the
// commit, exit 0 and any other code (observer's generic error 1 for an
// unknown verb or a config error, an inactive module) let it through, and
// --no-verify always does. Uninstall restores the developer's own hook
// byte for byte.
func TestGithooksBlockFailsOpenThroughGit(t *testing.T) {
	dir, run := githookRepo(t)
	setTestHome(t, t.TempDir())
	hooks := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	own := "#!/bin/sh\necho own-hook-ran >> \"$(git rev-parse --git-dir)/own.log\"\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte(own), 0o755); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(t.TempDir(), "observer")
	setFake := func(code string) {
		if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit "+code+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tg, err := secsvc.ResolveGithookTarget(context.Background(), gitview.RunReadOnlyTimeout, dir)
	if err != nil || tg.Refusal != "" || tg.HooksDir != hooks {
		t.Fatalf("target %+v %v", tg, err)
	}
	if err := secsvc.InstallGithooks(tg, fake); err != nil {
		t.Fatal(err)
	}
	st, _ := secsvc.GithooksStatus(tg)
	if len(st) != 2 || !st[0].Installed || !st[0].Foreign || !st[1].Installed || st[1].Foreign {
		t.Fatalf("status %+v", st)
	}
	commit := func(name string, extra ...string) error {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run("add", name); err != nil {
			t.Fatal(err)
		}
		return run(append([]string{"commit", "-q", "-m", name}, extra...)...)
	}
	setFake(strconv.Itoa(secgithooks.RefuseExit))
	if err := commit("a"); err == nil {
		t.Fatal("the refusal status did not refuse the commit")
	}
	if err := commit("a", "--no-verify"); err != nil {
		t.Fatalf("--no-verify: %v", err)
	}
	for _, code := range []string{"0", "1", "3", "2"} {
		setFake(code)
		if err := commit("f" + code); err != nil {
			t.Fatalf("exit %s refused the commit: %v", code, err)
		}
	}
	if log, _ := os.ReadFile(filepath.Join(dir, ".git", "own.log")); strings.Count(string(log), "own-hook-ran") != 4 {
		t.Fatalf("the developer's own hook did not run after the block: %q", log)
	}
	if n, err := secsvc.UninstallGithooks(tg); err != nil || n != 2 {
		t.Fatalf("uninstall: %d %v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(hooks, "pre-commit")); string(b) != own {
		t.Fatalf("pre-commit not restored byte for byte: %q", b)
	}
	if _, err := os.Stat(filepath.Join(hooks, "pre-push")); !os.IsNotExist(err) {
		t.Fatal("the pre-push hook Observer created is still there")
	}
}

// TestGithooksRefuseOutsideTheRepository: a core.hooksPath outside the
// repository is reported and never written.
func TestGithooksRefuseOutsideTheRepository(t *testing.T) {
	dir, run := githookRepo(t)
	outside := t.TempDir()
	if err := run("config", "core.hooksPath", outside); err != nil {
		t.Fatal(err)
	}
	tg, err := secsvc.ResolveGithookTarget(context.Background(), gitview.RunReadOnlyTimeout, dir)
	if err != nil || tg.Refusal == "" {
		t.Fatalf("target %+v %v", tg, err)
	}
	if err := secsvc.InstallGithooks(tg, "/bin/true"); err == nil {
		t.Fatal("installed outside the repository")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote into %s", outside)
	}
}

// TestPrecommitCheckFindsAStagedSecret: the check over the staged change
// refuses a staged secret and passes a clean change.
func TestPrecommitCheckFindsAStagedSecret(t *testing.T) {
	dir, run := githookRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "conf.py"), []byte("token = \"ghp_"+strings.Repeat("a1B2", 9)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("add", "conf.py"); err != nil {
		t.Fatal(err)
	}
	line, refuse := githookVerdictLine("commit", githookEngine().Scan(context.Background(), secquickscan.Request{Root: dir}))
	if !refuse || !strings.Contains(line, "conf.py:1") || strings.Contains(line, "a1B2") {
		t.Fatalf("staged secret: %v %q", refuse, line)
	}
	if err := run("rm", "-q", "--cached", "conf.py"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("add", "ok.py"); err != nil {
		t.Fatal(err)
	}
	if line, refuse := githookVerdictLine("commit", githookEngine().Scan(context.Background(), secquickscan.Request{Root: dir})); refuse {
		t.Fatalf("clean change refused: %q", line)
	}
	if forms := prepushRanges(bytes.NewBufferString("refs/heads/a " + strings.Repeat("a", 40) + " refs/heads/a " + strings.Repeat("0", 40) + "\n(delete) " + strings.Repeat("0", 40) + " refs/heads/b " + strings.Repeat("b", 40) + "\n")); len(forms) != 1 || forms[0].From != "" {
		t.Fatalf("pre-push ranges %+v", forms)
	}
}

// TestGithooksOffWithoutAComponentsBlock: an install with no [components]
// block resolves every module active (P-011), but the opt-in git hooks
// stay off there; a block that adds them turns them on.
func TestGithooksOffWithoutAComponentsBlock(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, []byte("[observer]\nlog_level = \"info\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if githooksSelected(componentSnapshotFor(cfg)) {
		t.Fatal("selected with no [components] block")
	}
	if err := os.WriteFile(cfg, []byte("[components]\nadd = [\"security.githooks\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !githooksSelected(componentSnapshotFor(cfg)) {
		t.Fatal("not selected with [components] add = [\"security.githooks\"]")
	}
}

// TestGithooksUnderShE (lane sec-gate2 milestone 3): a developer hook that
// runs `set -e` before the block does not abort on observer's generic
// error, and a hook Observer created whole exits 0 when the check passes.
func TestGithooksUnderShE(t *testing.T) {
	dir, run := githookRepo(t)
	hooks := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	own := "#!/bin/sh\nset -e\necho strict-hook-ran >> \"$(git rev-parse --git-dir)/own.log\"\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte(own), 0o755); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(t.TempDir(), "observer")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'unknown command \"precommit\"' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tg, err := secsvc.ResolveGithookTarget(context.Background(), gitview.RunReadOnlyTimeout, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := secsvc.InstallGithooks(tg, fake); err != nil {
		t.Fatal(err)
	}
	// Put `set -e` ahead of the block, as a developer's strict hook does.
	b, _ := os.ReadFile(filepath.Join(hooks, "pre-commit"))
	strict := strings.Replace(string(b), "#!/bin/sh\n", "#!/bin/sh\nset -e\n", 1)
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte(strict), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("add", "a"); err != nil {
		t.Fatal(err)
	}
	if err := run("commit", "-q", "-m", "a"); err != nil {
		t.Fatalf("a `set -e` hook aborted on observer's generic error: %v", err)
	}
	if log, _ := os.ReadFile(filepath.Join(dir, ".git", "own.log")); !strings.Contains(string(log), "strict-hook-ran") {
		t.Fatalf("the developer's hook did not run after the block: %q", log)
	}
	// The pre-push hook Observer created whole: exit 0 when not refused.
	pp := filepath.Join(hooks, "pre-push")
	c := exec.Command("sh", pp, "origin", "url")
	c.Stdin = strings.NewReader("")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("an Observer-only pre-push hook failed with the check passing: %v %s", err, out)
	}
}

// TestGithooksPrePushChainsStdin (lane sec-gate2 milestone 3): a real push
// through the installed pre-push block with a developer hook below it in
// the git-lfs shape (it reads every ref line from stdin): the check and the
// developer's hook both read the full refs list, a refusal stops the push,
// and a passing check lets it through.
func TestGithooksPrePushChainsStdin(t *testing.T) {
	dir, run := githookRepo(t)
	remote := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("bare: %v %s", err, out)
	}
	if err := run("remote", "add", "origin", remote); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(dir, ".git")
	lfs := "#!/bin/sh\nwhile read local_ref local_sha remote_ref remote_sha; do\n  echo \"lfs $local_ref $remote_ref\" >> \"" + gitDir + "/lfs.log\"\ndone\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-push"), []byte(lfs), 0o755); err != nil {
		t.Fatal(err)
	}
	// The stand-in observer records what it read on stdin, then exits code.
	fake := filepath.Join(t.TempDir(), "observer")
	setFake := func(code string) {
		body := "#!/bin/sh\ncat >> \"" + gitDir + "/obs.log\"\nexit " + code + "\n"
		if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tg, err := secsvc.ResolveGithookTarget(context.Background(), gitview.RunReadOnlyTimeout, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := secsvc.InstallGithooks(tg, fake); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	setFake("0")
	if err := run("add", "a"); err != nil {
		t.Fatal(err)
	}
	if err := run("commit", "-q", "--no-verify", "-m", "a"); err != nil {
		t.Fatal(err)
	}
	setFake(strconv.Itoa(secgithooks.RefuseExit))
	if err := run("push", "-q", "origin", "HEAD:refs/heads/main"); err == nil {
		t.Fatal("the refusal status did not stop the push")
	}
	setFake("0")
	if err := run("push", "-q", "origin", "HEAD:refs/heads/main"); err != nil {
		t.Fatalf("a passing check stopped the push: %v", err)
	}
	obs, _ := os.ReadFile(filepath.Join(gitDir, "obs.log"))
	lfsLog, _ := os.ReadFile(filepath.Join(gitDir, "lfs.log"))
	if strings.Count(string(obs), "refs/heads/main") != 2 {
		t.Fatalf("the check did not read git's refs each time: %q", obs)
	}
	if strings.Count(string(lfsLog), "lfs ") != 1 || !strings.Contains(string(lfsLog), "refs/heads/main") {
		t.Fatalf("the developer's pre-push hook did not get git's stdin after the block: %q", lfsLog)
	}
}

// TestGithooksStatusShowsAnOlderBlockOutdated (lane sec-gate3 milestone
// 2d): a block an earlier release wrote (its refusal was exit 1, so an
// older binary's generic error blocked, and its pre-push swallowed git's
// stdin) reads as outdated, not installed, until an install replaces it.
func TestGithooksStatusShowsAnOlderBlockOutdated(t *testing.T) {
	hooks := t.TempDir()
	old := "#!/bin/sh\n# >>> superbased-observer security githook (remove with: observer security githooks uninstall) >>>\n" +
		"sbo_obs='/o'\nif [ -x \"$sbo_obs\" ]; then\n  \"$sbo_obs\" security precommit \"$@\"\n  [ $? -eq 1 ] && exit 1\nfi\n" +
		"# <<< superbased-observer security githook <<<\nnpm test\n"
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte(old), 0o755); err != nil {
		t.Fatal(err)
	}
	tg := secsvc.GithookTarget{HooksDir: hooks}
	st, err := secsvc.GithooksStatus(tg)
	if err != nil || len(st) != 2 || st[0].Installed || !st[0].Outdated || st[1].Installed || st[1].Outdated {
		t.Fatalf("status %+v %v, want pre-commit outdated and pre-push absent", st, err)
	}
	if err := secsvc.InstallGithooks(tg, "/o"); err != nil {
		t.Fatal(err)
	}
	st, _ = secsvc.GithooksStatus(tg)
	if !st[0].Installed || st[0].Outdated || !st[0].Foreign || !st[1].Installed {
		t.Fatalf("after install: %+v", st)
	}
}
