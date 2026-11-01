package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestHookStampsRepoRootForR101 pins the hook half of D-MU10: a pre-tool
// event that carries only cwd gets the git working tree around it as
// RepoRoot (never ProjectRoot, never the bare cwd outside a tree), and
// R-101 then judges a recursive delete outside that repository as outside
// the project.
func TestHookStampsRepoRootForR101(t *testing.T) {
	root, cwd := projectHookRepo(t, "https://github.com/acme/demo.git")
	ev := policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Cwd: cwd, SessionID: "s1"}
	withProjectLookupRoot(nil)(&ev)
	if ev.RepoRoot != root || ev.ProjectRoot != "" {
		t.Fatalf("event %+v, want RepoRoot %s and an empty ProjectRoot", ev, root)
	}
	outside := policy.Event{Cwd: t.TempDir()}
	withProjectLookupRoot(nil)(&outside)
	if outside.RepoRoot != "" {
		t.Errorf("RepoRoot outside a working tree = %q, want empty", outside.RepoRoot)
	}
	host := policy.Event{Cwd: cwd, ProjectRoot: "/host/sent"}
	withProjectLookupRoot(nil)(&host)
	if host.RepoRoot != "" {
		t.Errorf("a host root makes RepoRoot unnecessary, got %q", host.RepoRoot)
	}

	home := "/home/u"
	eng, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	for cmd, want := range map[string]policy.Decision{
		"rm -rf /etc/nginx":                     policy.DecisionDeny,
		"rm -rf build":                          policy.DecisionAllow,
		"rm -rf " + filepath.Join(root, "dist"): policy.DecisionAllow,
	} {
		e := ev
		e.Target, e.Now = cmd, time.Now()
		v := eng.Evaluate(e)
		if want == policy.DecisionDeny && (v.Decision != policy.DecisionDeny || v.RuleID != "R-101") {
			t.Errorf("%s: %s/%s, want R-101/deny", cmd, v.RuleID, v.Decision)
		}
		if want == policy.DecisionAllow && v.RuleID == "R-101" {
			t.Errorf("%s: R-101 (%q), want no hit", cmd, v.Reason)
		}
	}
}

// linkedWorktreeOutside is a git repository and a linked worktree of it that
// lives outside the repository's own directory (~/sbo-scratch/wt-plans over
// ~/superbased-observer).
func linkedWorktreeOutside(t *testing.T) (mainRepo, wt string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mainRepo, wt = filepath.Join(base, "main"), filepath.Join(base, "wt")
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@x"}, args...)...) //nolint:gosec // G204: fixed git argv in a temp dir
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run(base, "init", "-q", "main")
	run(mainRepo, "commit", "-q", "--allow-empty", "-m", "x")
	run(mainRepo, "worktree", "add", "-q", "-b", "feat", wt)
	return mainRepo, wt
}

// TestHookRepoRootIsTheCheckoutInALinkedWorktree pins MACUSER merge H1:
// R-101 judges a delete against the checkout around cwd, so in a linked
// worktree outside its main repository `rm -rf build` is allowed, while
// `rm -rf ~/Desktop` from the same cwd stays denied and the main checkout
// is unchanged. On the relay path the run's checkout decides the same way.
func TestHookRepoRootIsTheCheckoutInALinkedWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	mainRepo, wt := linkedWorktreeOutside(t)
	// The home is outside /tmp: R-101's default /tmp/** exemption would
	// otherwise clear every absolute target under the test's temp dirs.
	const home = "/home/u"
	hookctx.SetProcess(nil)
	t.Cleanup(func() { hookctx.SetProcess(nil) })
	eng, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	judge := func(t *testing.T, ev policy.Event, rows map[string]bool) {
		t.Helper()
		for cmd, deny := range rows {
			e := ev
			e.Target, e.Now = cmd, time.Now()
			v := eng.Evaluate(e)
			if deny && (v.Decision != policy.DecisionDeny || v.RuleID != "R-101") {
				t.Errorf("cwd %s: %s: %s/%s, want R-101/deny", ev.Cwd, cmd, v.RuleID, v.Decision)
			}
			if !deny && v.RuleID == "R-101" {
				t.Errorf("cwd %s: %s: R-101 (%q), want no hit", ev.Cwd, cmd, v.Reason)
			}
		}
	}
	for _, tc := range []struct {
		name, cwd, wantRepo string
		rows                map[string]bool
	}{
		{"linked worktree outside the main repo", wt, wt, map[string]bool{
			"rm -rf build":                        false,
			"rm -rf " + filepath.Join(wt, "dist"): false,
			"rm -rf ~/Desktop":                    true,
			"rm -rf /etc/nginx":                   true,
		}},
		{"main checkout", mainRepo, mainRepo, map[string]bool{
			"rm -rf build":      false,
			"rm -rf ~/Desktop":  true,
			"rm -rf /etc/nginx": true,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Cwd: tc.cwd, SessionID: "s"}
			withProjectLookupRoot(nil)(&ev)
			if ev.RepoRoot != tc.wantRepo {
				t.Fatalf("RepoRoot = %q, want the checkout %q", ev.RepoRoot, tc.wantRepo)
			}
			if ev.ProjectLookupRoot != mainRepo {
				t.Errorf("ProjectLookupRoot = %q, want the main repository %q (F0-14)", ev.ProjectLookupRoot, mainRepo)
			}
			judge(t, ev, tc.rows)
		})
	}

	t.Run("relay path keys on the run's checkout", func(t *testing.T) {
		for _, ch := range []struct {
			name string
			ch   hookctx.Channel
			want string
		}{
			{"checkout given", hookctx.Channel{RunID: "r", ProjectRoot: mainRepo, CheckoutRoot: wt}, wt},
			{"checkout unknown", hookctx.Channel{RunID: "r", ProjectRoot: wt}, wt},
		} {
			hookctx.SetProcess(hookctx.Daemon(context.Background(), hookctx.Request{}, ch.ch, hookctx.DaemonProviders{}))
			ev := policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Cwd: wt, SessionID: "s"}
			withProjectLookupRoot(nil)(&ev)
			if ev.RepoRoot != ch.want {
				t.Errorf("%s: RepoRoot = %q, want %q", ch.name, ev.RepoRoot, ch.want)
			}
			judge(t, ev, map[string]bool{"rm -rf build": false, "rm -rf ~/Desktop": true})
		}
		hookctx.SetProcess(nil)
	})
}
