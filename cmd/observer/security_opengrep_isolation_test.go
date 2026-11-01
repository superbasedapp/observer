//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep && !sbo_omit_isolation

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/isolation"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// security_opengrep_isolation_test.go is lane SEC-G2 milestone 4: the
// no-network run and the isolated run of a linked worktree, through the
// real isolation provider's bwrap plan (nothing is started: a fake
// executor records the plans).

// isolatedCodeRun scans checkout (project root) under the real one-shot
// provider and returns every plan handed to the executor.
func isolatedCodeRun(t *testing.T, root, checkout string) []extrun.Plan {
	t.Helper()
	home := t.TempDir()
	host := isolation.Host{Bwrap: "/usr/bin/bwrap", Home: home, ObserverDir: filepath.Join(home, ".observer")}
	cache := t.TempDir()
	pack, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := secengine.CompiledPin("linux", "amd64")
	bin := "/opt/opengrep/opengrep"
	ex := &extruntest.Executor{Facts: func(p extrun.Plan) extrun.ExecFacts {
		if slices.Contains(p.Args, "--version") {
			return extrun.ExecFacts{Stdout: []byte(secengine.TestedVersion + "\n"), PeakChildren: -1}
		}
		return extrun.ExecFacts{PeakChildren: -1}
	}}
	r := extruntest.NewRunner("linux", extruntest.Files{bin: {Digest: pin.SHA256}, "/usr/bin/git": {}}, ex, nil)
	r.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
		if slices.Contains(s.Names.Unix, "git") {
			return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/usr/bin/git"}
		}
		return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: bin}
	}
	d := opengrep.New(opengrep.Env{
		Runner: r, Pack: pack, PackDir: filepath.Join(cache, "pack"), CacheDir: filepath.Join(cache, "engine"), OutDir: filepath.Join(cache, "out"),
		ListTree: func(string) secengine.TreeListing { return secengine.TreeListing{Missing: true} },
		ReadFile: func(string, int64) ([]byte, error) { return nil, os.ErrNotExist },
		GOOS:     "linux", GOARCH: "amd64", LinkedCommonDir: codeLinkedCommonDir,
		Isolate: func(dirs extrun.OneShotDirs) (extrun.IsolationProvider, error) { return isolation.New(host, dirs) },
		IsolatedRunner: func(p extrun.IsolationProvider) *extrun.Runner {
			ir := extruntest.NewRunner("linux", extruntest.Files{bin: {Digest: pin.SHA256}, "/usr/bin/git": {}}, ex, nil)
			ir.Resolve, ir.Isolation = r.Resolve, p
			return ir
		},
	})
	if _, _, err := d.ScanFiles(context.Background(), secscan.Target{ProjectRoot: root, CheckoutRoot: checkout, Scope: policy.FindingScopeManual}); err != nil {
		t.Fatal(err)
	}
	return ex.Calls()
}

// TestCodeRunHasNoNetworkUnderIsolation: every Opengrep run under the
// isolation component is a bwrap one-shot with a private network namespace,
// the engine's version check off, and none of the flags that reach a
// registry.
func TestCodeRunHasNoNetworkUnderIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the isolation engine is Linux-only")
	}
	root := t.TempDir()
	plans := isolatedCodeRun(t, root, "")
	if len(plans) == 0 {
		t.Fatal("no run")
	}
	for _, p := range plans {
		if p.Path != "/usr/bin/bwrap" {
			t.Fatalf("a run escaped the isolation: %s %v", p.Path, p.Args)
		}
		if !slices.Contains(p.Args, "--unshare-net") {
			t.Fatalf("a run has the network: %v", p.Args)
		}
		joined := strings.Join(p.Args, " ")
		for _, never := range append([]string{"--metrics=on"}, opengrep.FlagsNever...) {
			if strings.Contains(joined, never) {
				t.Errorf("a refused flag %q", never)
			}
		}
		if !slices.Contains(p.Args, "--version") && !slices.Contains(p.Args, "--disable-version-check") {
			t.Errorf("the version check is not off: %v", p.Args)
		}
	}
}

// TestCodeRunOfALinkedWorktreeBindsTheMainGitReadOnly: a scan from a linked
// worktree, isolated, binds the main repository's .git read-only (git in
// the box reads the worktree's objects and refs there), never writable.
func TestCodeRunOfALinkedWorktreeBindsTheMainGitReadOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the isolation engine is Linux-only")
	}
	main := t.TempDir()
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"-c", "user.email=t@e", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init"}} {
		if out, err := runGitForTest(main, args...); err != nil {
			t.Skipf("git: %v %s", err, out)
		}
	}
	wt := filepath.Join(t.TempDir(), "wt")
	if err := git.WorktreeAdd(context.Background(), main, wt, "feature/x", "HEAD"); err != nil {
		t.Skipf("git worktree add: %v", err)
	}
	root, _ := git.FindRoot(wt)
	checkout, _ := git.FindCheckoutRoot(wt)
	common, ok := git.LinkedCommonDir(wt)
	if !ok || root == checkout {
		t.Fatalf("not a linked worktree: root %s checkout %s", root, checkout)
	}
	plans := isolatedCodeRun(t, root, checkout)
	if len(plans) == 0 {
		t.Fatal("no run")
	}
	args := plans[0].Args
	ro := false
	for i := 0; i+2 < len(args); i++ {
		if args[i+1] == common && args[i+2] == common {
			switch args[i] {
			case "--ro-bind-try", "--ro-bind":
				ro = true
			case "--bind", "--bind-try":
				t.Fatalf("the main .git is bound writable: %v", args)
			}
		}
	}
	if !ro {
		t.Fatalf("the main .git %s is not bound read-only: %v", common, args)
	}
}

// runGitForTest runs git in dir with no user or system config.
func runGitForTest(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	return cmd.CombinedOutput()
}
