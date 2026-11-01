//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The tests in this file pin lane SEC-TRUST2 (plans decision log P-022):
// the daemon-started launches check the run's own repository, Arena
// worktrees honour the source repository's accepts, and the developer's own
// settings are quiet once accepted.

// untrustedHookRepo is a repository whose committed SessionStart hook
// nobody accepted: S-701, which asks in enforce mode.
var untrustedHookRepo = map[string]string{
	".claude/settings.json": `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"sh .github/boot.sh"}]}]}}`,
	".github/boot.sh":       "echo hi\n",
}

// daemonTrustSetup writes a config selecting security.trust under mode and
// points the process working directory (cliLaunchDir) at the daemon's own
// directory, which holds an untrusted repository: a check that read it
// would refuse.
func daemonTrustSetup(t *testing.T, mode string) (cfgPath, daemonCwd string) {
	t.Helper()
	t.Setenv(repoTrustCheckedEnv, "")
	_, dbPath := trustTestStore(t)
	cfgPath = trustTestConfig(t, t.TempDir(), dbPath, mode, true)
	daemonCwd = writeTrustRepo(t, untrustedHookRepo)
	old := cliLaunchDir
	t.Cleanup(func() { cliLaunchDir = old })
	cliLaunchDir = func() (string, error) { return daemonCwd, nil }
	return cfgPath, daemonCwd
}

// TestDaemonLaunchChecksTheRunsRepository (item a): a daemon-started launch
// checks its own directory, never the daemon's working directory; it never
// asks (an ask refuses and says where to accept); and the checked marker is
// returned for the child's environment, never set in the daemon's.
func TestDaemonLaunchChecksTheRunsRepository(t *testing.T) {
	ctx := context.Background()
	cfgPath, _ := daemonTrustSetup(t, "enforce")
	clean := writeTrustRepo(t, map[string]string{"README.md": "# x\n"})

	env, err := enforceDaemonStartedLaunch(ctx, cfgPath, "claude-code", budgetLaunchEvidence{}, daemonLaunch{dir: clean})
	if err != nil {
		t.Fatalf("clean run repository refused (the daemon's cwd was read?): %v", err)
	}
	want := repoTrustCheckedEnv + "=" + guard.HashProjectRoot(clean)
	if len(env) != 1 || env[0] != want {
		t.Fatalf("child env %v, want %s", env, want)
	}
	if got := os.Getenv(repoTrustCheckedEnv); got != "" {
		t.Fatalf("the daemon's own environment carries the marker %q", got)
	}

	untrusted := writeTrustRepo(t, untrustedHookRepo)
	env, err = enforceDaemonStartedLaunch(ctx, cfgPath, "claude-code", budgetLaunchEvidence{}, daemonLaunch{dir: untrusted})
	if err == nil || !strings.Contains(err.Error(), "S-701") || !strings.Contains(err.Error(), "started by Observer itself") || !strings.Contains(err.Error(), "observer security trust accept --all --dir "+untrusted) {
		t.Fatalf("untrusted run repository: %v, want an S-701 refusal saying where to accept", err)
	}
	if env != nil || os.Getenv(repoTrustCheckedEnv) != "" {
		t.Fatalf("a refused launch set the marker: %v %q", env, os.Getenv(repoTrustCheckedEnv))
	}

	// No directory of the run's own (the Arena judge): no trust check, and
	// never one of the daemon's working directory.
	if env, err := enforceDaemonStartedLaunch(ctx, cfgPath, "claude-code", budgetLaunchEvidence{}, daemonLaunch{}); err != nil || env != nil {
		t.Fatalf("no directory: %v %v", env, err)
	}

	// The row's dependencies never hold an ask: nothing reads the daemon's
	// stdin.
	r := daemonLaunchGateRun(ctx, cfgPath, "claude-code", budgetLaunchEvidence{}, daemonLaunch{dir: clean})
	t.Cleanup(r.close)
	if s := gateStateLoad(r); s.refuse != nil {
		t.Fatal(s.refuse)
	}
	deps := r.repoTrustFor(r)
	if deps == nil || deps.ask != nil || !deps.unattended {
		t.Fatalf("daemon deps %+v: want no ask, unattended", deps)
	}
}

// TestDaemonLaunchObserveWarns: in observe mode the daemon-started launch
// goes on and the marker still reaches only the child.
func TestDaemonLaunchObserveWarns(t *testing.T) {
	cfgPath, _ := daemonTrustSetup(t, "observe")
	untrusted := writeTrustRepo(t, untrustedHookRepo)
	env, err := enforceDaemonStartedLaunch(context.Background(), cfgPath, "claude-code", budgetLaunchEvidence{}, daemonLaunch{dir: untrusted})
	if err != nil || len(env) != 1 || !strings.HasPrefix(env[0], repoTrustCheckedEnv+"=") {
		t.Fatalf("observe: %v %v", env, err)
	}
	if os.Getenv(repoTrustCheckedEnv) != "" {
		t.Fatal("observe: the daemon's environment carries the marker")
	}
}

// openTrustTestDBFromConfig opens the database a trustTestConfig names.
func openTrustTestDBFromConfig(t *testing.T, cfgPath string) *store.Store {
	t.Helper()
	_, database, cleanup, err := loadConfigAndDB(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return store.New(database)
}

// TestOwnFileTriggersAskOnceThenQuiet (item g): each common setting a
// developer keeps in their own files raises the trust row before its
// accept (a warning in observe mode; an ask or refusal naming the accept in
// enforce mode) and, once accepted, the launch is quiet in both modes: no
// warning at every launch. A setting that runs or loads code (runs) keeps
// the S-705 warning at every launch after its accept instead, since its
// digest cannot cover what it loads (plans decision log P-029).
func TestOwnFileTriggersAskOnceThenQuiet(t *testing.T) {
	triggers := []struct {
		name, file, body string
		runs             bool
	}{
		{"dotenv PYTHONPATH", ".env", "PYTHONPATH=./src\n", true},
		{"dotenv NODE_OPTIONS", ".env", "NODE_OPTIONS=--max-old-space-size=4096\n", false},
		{"dotenv NODE_OPTIONS --require", ".env", "NODE_OPTIONS=--require ./tools/register.js\n", true},
		{"dotenv LD_LIBRARY_PATH", ".env", "LD_LIBRARY_PATH=/opt/oracle/lib\n", true},
		{"dotenv remote OPENAI_BASE_URL", ".env", "OPENAI_BASE_URL=https://gateway.corp.example/v1\n", false},
		{"settings.local enableAllProjectMcpServers", ".claude/settings.local.json", `{"enableAllProjectMcpServers":true}`, false},
		{"git core.sshCommand", ".git/config", "[core]\n\tsshCommand = ssh -i ~/.ssh/work_ed25519\n", false},
		{"husky core.hooksPath", ".git/config", "[core]\n\thooksPath = .husky/_\n", false},
	}
	for _, mode := range []string{"observe", "enforce"} {
		for _, tc := range triggers {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				t.Setenv(repoTrustCheckedEnv, "")
				_, dbPath := trustTestStore(t)
				cfgPath := trustTestConfig(t, t.TempDir(), dbPath, mode, true)
				root := writeTrustRepo(t, map[string]string{tc.file: tc.body})
				old := cliLaunchDir
				t.Cleanup(func() { cliLaunchDir = old })
				cliLaunchDir = func() (string, error) { return root, nil }
				r := cliLaunchGateRun(context.Background(), cfgPath, "claude-code", budgetLaunchEvidence{})
				r.markChecked = nil
				t.Cleanup(r.close)
				if s := gateStateLoad(r); s.refuse != nil {
					t.Fatal(s.refuse)
				}
				before := gateRepoTrust(r)
				if before.outcomes() == launchGateAllow {
					t.Fatalf("before the accept: quiet, want the row to raise it")
				}
				msg := before.warn
				if before.refuse != nil {
					msg = before.refuse.Error()
				}
				if !strings.Contains(msg, "accept") {
					t.Fatalf("before the accept: %q does not say how to accept", msg)
				}
				st := store.New(r.database)
				res, err := sectrust.Check(context.Background(), sectrust.OSFS(root), sectrust.Request{})
				if err != nil {
					t.Fatal(err)
				}
				items := secTrustItems(res)
				if len(items) != 1 || items[0].Scope != "project_local" {
					t.Fatalf("items %+v, want one local item", items)
				}
				if _, err := st.AcceptSecTrustItems(context.Background(), guard.HashProjectRoot(root), items, "cli:test", time.Now()); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 2; i++ {
					after := gateRepoTrust(r)
					switch {
					case tc.runs && (after.outcomes() != launchGateAllow|launchGateWarn || !strings.Contains(after.warn, "S-705")):
						t.Fatalf("launch %d after the accept: %+v, want the S-705 warning", i+1, after)
					case !tc.runs && after.outcomes() != launchGateAllow:
						t.Fatalf("launch %d after the accept: %+v, want quiet", i+1, after)
					}
				}
			})
		}
	}
}
