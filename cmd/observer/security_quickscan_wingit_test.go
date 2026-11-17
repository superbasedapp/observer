//go:build linux && !sbo_omit_security

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitroute"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
)

// windowsDriveScratch returns a fresh directory on a Windows drive as a WSL
// process sees it ($OBSERVER_TEST_WINDRIVE_DIR first, then a public
// location on C:), or skips.
func windowsDriveScratch(t *testing.T) string {
	t.Helper()
	bases := []string{os.Getenv("OBSERVER_TEST_WINDRIVE_DIR"), "/mnt/c/Users/Public/Documents", "/mnt/c/Windows/Temp"}
	for _, base := range bases {
		if base == "" || !strings.HasPrefix(base, "/mnt/") {
			continue
		}
		dir, err := os.MkdirTemp(base, "sbo-wingit-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}
	t.Skip("no writable directory on a Windows drive (set OBSERVER_TEST_WINDRIVE_DIR)")
	return ""
}

// TestQuickScanReadsAWindowsDriveWithWindowsGit is R3-86's live check: on a
// WSL host with interop and Git for Windows installed, a repository on a
// Windows drive is read by git.exe, a staged secret and a `commit -a`
// working-tree secret are both caught, and each scan is well inside the
// individual 2 s budget. It skips anywhere else.
func TestQuickScanReadsAWindowsDriveWithWindowsGit(t *testing.T) {
	const gitExe = "/mnt/c/Program Files/Git/cmd/git.exe"
	if _, err := os.Stat(gitExe); err != nil {
		t.Skip("no Git for Windows at " + gitExe)
	}
	if !wslInteropEnabled() {
		t.Skip("WSL interop is not enabled")
	}
	router := gitroute.NewRouter(securityGitRouteEnv())
	prev := securityGitRouter
	securityGitRouter = func() *gitroute.Router { return router }
	t.Cleanup(func() { securityGitRouter = prev })

	dir := windowsDriveScratch(t)
	plan := router.Plan(context.Background(), dir, []string{"diff", "--cached"})
	if plan.Route != gitroute.RouteWindowsGit {
		t.Fatalf("plan for %s = %+v, want git.exe", dir, plan)
	}
	winGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command(plan.Program, append([]string{"-C", plan.Dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "core.autocrlf=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git.exe %v: %v %s", args, err, out)
		}
	}
	winGit("init", "-q")
	winGit("config", "core.autocrlf", "false")
	if err := os.WriteFile(filepath.Join(dir, "ok.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	winGit("add", "ok.py")
	winGit("commit", "-q", "-m", "init")

	e := newSecurityQuickScanEngine(func(string, string) string { return "" })
	scan := func(form secquickscan.Form) secquickscan.Result {
		t.Helper()
		res := e.Scan(context.Background(), secquickscan.Request{Root: dir, Form: form, Budget: secquickscan.IndividualBudget})
		t.Logf("form %+v: %s (%s) via %q in %s", form, res.Verdict, res.Reason, res.GitRoute, res.Elapsed)
		if res.GitRoute != policy.QuickScanGitWindows {
			t.Fatalf("read via %q, want Windows git", res.GitRoute)
		}
		if res.Elapsed >= time.Second {
			t.Fatalf("scan took %s, want well under the 2 s budget", res.Elapsed)
		}
		return res
	}

	// Clean commit -a.
	if res := scan(secquickscan.Form{All: true}); res.Verdict != secquickscan.VerdictClean {
		t.Fatalf("clean tree: %+v", res)
	}
	// A staged secret.
	if err := os.WriteFile(filepath.Join(dir, "cfg.py"), []byte(secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	winGit("add", "cfg.py")
	if res := scan(secquickscan.Form{}); res.Verdict != secquickscan.VerdictBlocking {
		t.Fatalf("staged secret: %+v, want blocking", res)
	}
	// A secret only in the working tree, recorded by `commit -a`.
	winGit("reset", "-q")
	if err := os.WriteFile(filepath.Join(dir, "ok.py"), []byte("x = 1\n"+secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := scan(secquickscan.Form{All: true}); res.Verdict != secquickscan.VerdictBlocking {
		t.Fatalf("working-tree secret under commit -a: %+v, want blocking", res)
	}

	// A linked worktree Windows git made (its `.git` pointer is spelled
	// D:/..., which the WSL git cannot follow): git.exe reads its own index.
	wt := filepath.Join(windowsDriveScratch(t), "wt")
	wtPlan := router.Plan(context.Background(), wt, nil)
	winGit("worktree", "add", "-q", wtPlan.Dir)
	t.Cleanup(func() {
		_ = exec.Command(plan.Program, "-C", plan.Dir, "worktree", "remove", "--force", wtPlan.Dir).Run()
	})
	if err := os.WriteFile(filepath.Join(wt, "cfg.py"), []byte(secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(plan.Program, "-C", wtPlan.Dir, "add", "cfg.py").CombinedOutput(); err != nil {
		t.Fatalf("git.exe add in the worktree: %v %s", err, out)
	}
	dir = wt
	if res := scan(secquickscan.Form{}); res.Verdict != secquickscan.VerdictBlocking {
		t.Fatalf("staged secret in a Windows-made worktree: %+v, want blocking", res)
	}
}

// TestQuickScanLiveWindowsDriveTiming times the quick scan's `commit -a`
// read (`git diff HEAD`) of a real checkout on a Windows drive, read only
// (no index write: --no-optional-locks, GIT_OPTIONAL_LOCKS=0). It runs only
// when OBSERVER_TEST_QUICKSCAN_LIVE_ROOT names that checkout;
// OBSERVER_TEST_QUICKSCAN_LIVE_WSLGIT=1 also times the WSL git path.
func TestQuickScanLiveWindowsDriveTiming(t *testing.T) {
	root := os.Getenv("OBSERVER_TEST_QUICKSCAN_LIVE_ROOT")
	if root == "" {
		t.Skip("set OBSERVER_TEST_QUICKSCAN_LIVE_ROOT to a checkout on a Windows drive")
	}
	run := func(name string, env gitroute.Env, budget time.Duration) {
		router := gitroute.NewRouter(env)
		prev := securityGitRouter
		securityGitRouter = func() *gitroute.Router { return router }
		defer func() { securityGitRouter = prev }()
		start := time.Now()
		router.Prime(context.Background())
		prime := time.Since(start)
		e := newSecurityQuickScanEngine(func(string, string) string { return "" })
		for i := 0; i < 3; i++ {
			res := e.Scan(context.Background(), secquickscan.Request{Root: root, Form: secquickscan.Form{All: true}, Budget: budget})
			t.Logf("%s run %d: %s (%s) via %q, %d files, %s (resolve %s)", name, i+1, res.Verdict, res.Reason, res.GitRoute, res.Files, res.Elapsed, prime)
			if name == "windows" && (res.GitRoute != policy.QuickScanGitWindows || res.Elapsed >= secquickscan.IndividualBudget) {
				t.Errorf("windows path: via %q in %s, want git.exe under the budget", res.GitRoute, res.Elapsed)
			}
			if name != "windows" {
				break
			}
		}
	}
	run("windows", securityGitRouteEnv(), secquickscan.IndividualBudget)
	if os.Getenv("OBSERVER_TEST_QUICKSCAN_LIVE_WSLGIT") == "1" {
		env := securityGitRouteEnv()
		env.InteropEnabled = func() bool { return false }
		run("wsl", env, 120*time.Second)
	}
}

// winSideGitVars are the Windows-side git variables the R3-89 test plants:
// each would send git.exe to a repository or index that does not exist.
var winSideGitVars = []string{
	`GIT_DIR=C:\sbo-bogus-gitdir`,
	`GIT_WORK_TREE=C:\sbo-bogus-worktree`,
	`GIT_INDEX_FILE=C:\sbo-bogus-index`,
}

// TestQuickScanWindowsGitIgnoresWindowsSideGitVars is R3-89's live check: a
// git variable the Windows user set in their own environment (GIT_DIR,
// GIT_WORK_TREE, GIT_INDEX_FILE) does not reach the quick scan's git.exe. A
// WSL process cannot change its session's Windows-side environment, so the
// test re-runs itself in a NESTED WSL session started by wsl.exe with those
// variables in wsl.exe's own (Windows) environment: every Windows program the
// child starts through interop inherits them, as git.exe would under a
// developer who set them. The child first proves the hazard (a bare git.exe
// fails on the bogus GIT_DIR), then scans through the envelope, which must
// read the real repository with git.exe and catch its staged secret. It skips
// without Git for Windows, interop, or wsl.exe.
func TestQuickScanWindowsGitIgnoresWindowsSideGitVars(t *testing.T) {
	const gitExe = "/mnt/c/Program Files/Git/cmd/git.exe"
	if _, err := os.Stat(gitExe); err != nil {
		t.Skip("no Git for Windows at " + gitExe)
	}
	if !wslInteropEnabled() {
		t.Skip("WSL interop is not enabled")
	}
	if os.Getenv("SBO_TEST_WINSIDE_CHILD") == "1" {
		winSideChild(t, gitExe, os.Getenv("SBO_TEST_WINSIDE_DIR"))
		return
	}
	distro := os.Getenv("WSL_DISTRO_NAME")
	wslExe, err := exec.LookPath("wsl.exe")
	if err != nil {
		wslExe = "/mnt/c/Windows/System32/wsl.exe"
	}
	if _, err := os.Stat(wslExe); distro == "" || err != nil {
		t.Skip("not inside a WSL distribution with wsl.exe reachable")
	}

	router := gitroute.NewRouter(securityGitRouteEnv())
	dir := windowsDriveScratch(t)
	plan := router.Plan(context.Background(), dir, nil)
	if plan.Route != gitroute.RouteWindowsGit {
		t.Fatalf("plan for %s = %+v, want git.exe", dir, plan)
	}
	winGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command(plan.Program, append([]string{"-C", plan.Dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "core.autocrlf=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git.exe %v: %v %s", args, err, out)
		}
	}
	winGit("init", "-q")
	winGit("config", "core.autocrlf", "false")
	if err := os.WriteFile(filepath.Join(dir, "ok.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	winGit("add", "ok.py")
	winGit("commit", "-q", "-m", "init")
	if err := os.WriteFile(filepath.Join(dir, "cfg.py"), []byte(secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	winGit("add", "cfg.py")

	// The child inherits the planted variables from wsl.exe's Windows
	// environment (WSLENV hands them to wsl.exe, a Windows program).
	names := []string{"SBO_TEST_WINSIDE_CHILD", "SBO_TEST_WINSIDE_DIR"}
	env := []string{"PATH=" + os.Getenv("PATH"), "SBO_TEST_WINSIDE_CHILD=1", "SBO_TEST_WINSIDE_DIR=" + dir}
	for _, kv := range winSideGitVars {
		name, _, _ := strings.Cut(kv, "=")
		names = append(names, name)
		env = append(env, kv)
	}
	env = append(env, "WSLENV="+strings.Join(names, ":"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, wslExe, "-d", distro, "--cd", "/", "--exec", os.Args[0],
		"-test.run", "^TestQuickScanWindowsGitIgnoresWindowsSideGitVars$", "-test.v", "-test.count=1")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	t.Logf("nested session:\n%s", out)
	if err != nil {
		t.Fatalf("nested session failed: %v", err)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skip("the nested session could not reproduce the Windows-side environment")
	}
	if !strings.Contains(string(out), "--- PASS") {
		t.Fatal("the nested session did not report a pass")
	}
}

// winSideChild is the nested half of
// TestQuickScanWindowsGitIgnoresWindowsSideGitVars.
func winSideChild(t *testing.T, gitExe, dir string) {
	if dir == "" {
		t.Fatal("SBO_TEST_WINSIDE_DIR is empty")
	}
	// Drop the copies WSLENV also put in this Linux environment: only the
	// Windows side should carry them, as for a developer who set them there.
	for _, kv := range winSideGitVars {
		name, _, _ := strings.Cut(kv, "=")
		_ = os.Unsetenv(name)
	}
	_ = os.Unsetenv("WSLENV")
	router := gitroute.NewRouter(securityGitRouteEnv())
	plan := router.Plan(context.Background(), dir, nil)
	if plan.Route != gitroute.RouteWindowsGit {
		t.Fatalf("plan for %s = %+v, want git.exe", dir, plan)
	}
	// The hazard is real: a bare git.exe takes the Windows-side GIT_DIR.
	raw, err := exec.Command(gitExe, "-C", plan.Dir, "rev-parse", "--git-dir").CombinedOutput()
	if err == nil || !strings.Contains(string(raw), "sbo-bogus-gitdir") {
		t.Skipf("the Windows-side GIT_DIR did not reach a bare git.exe (err %v, %s)", err, raw)
	}
	prev := securityGitRouter
	securityGitRouter = func() *gitroute.Router { return router }
	t.Cleanup(func() { securityGitRouter = prev })
	e := newSecurityQuickScanEngine(func(string, string) string { return "" })
	res := e.Scan(context.Background(), secquickscan.Request{Root: dir, Form: secquickscan.Form{}, Budget: secquickscan.IndividualBudget})
	t.Logf("scan: %s (%s) via %q in %s", res.Verdict, res.Reason, res.GitRoute, res.Elapsed)
	if res.GitRoute != policy.QuickScanGitWindows {
		t.Fatalf("read via %q, want Windows git (a fallback means git.exe still saw the planted variables)", res.GitRoute)
	}
	if res.Verdict != secquickscan.VerdictBlocking {
		t.Fatalf("staged secret: %+v, want blocking", res)
	}
}
