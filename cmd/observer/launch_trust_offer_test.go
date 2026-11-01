//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// TestTrustOfferedByDefault states what an install with NO [components]
// block sees now that security.trust is offered (lane SEC-TRUST2 milestone
// 2, plans decision log P-022; every launch path since lane SEC-TRUST4,
// P-037; offered by the orchestrator, P-044: no securityOptIn entry, and
// dist(out, on, off, on) in internal/components/catalog_node.go).
//
// In both guard modes (observe is the default):
//   - the daemon's opt-in rule selects security.trust, so the New Terminal
//     chip and its accept answer (GET and POST /api/security/trust), the
//     config baseline loop and the session-start flag run;
//   - a clean repository: nothing;
//   - only the developer's own files in normal use: nothing;
//   - a common own-file setting (core.sshCommand): raised until accepted,
//     then nothing, at every later launch;
//   - an own-file setting that loads code (.env PYTHONPATH): raised until
//     accepted, then the S-705 warning at every later launch (P-029);
//   - a fresh clone with a committed SessionStart hook: observe warns
//     (S-701); enforce asks, and a launch with no terminal refuses; at a
//     terminal, the answer "a" accepts the hook and launches, and the next
//     launch is the accepted S-705 warning with no question;
//   - an Arena run on that clone: observe goes on with a warning in the
//     daemon log; enforce refuses the candidate and says where to accept;
//     the judge, in its empty scratch directory, goes on;
//   - the rows trustOfferRows adds in the builds that hold their launch
//     path: a dashboard New Terminal on a fresh clone, whose launch goes on
//     in both modes (the ask is the inner launcher's, in the terminal), and
//     a dashboard GUI launch (launch_trust_offer_gui_test.go), a
//     benchmark attempt from a local and from a remote task
//     (launch_trust_offer_bench_test.go) and a sandboxed clone at the
//     relay gate (launch_trust_offer_relay_test.go).
func TestTrustOfferedByDefault(t *testing.T) {
	checkTrustOffered(t)
}

// trustOfferEnv is what a trustOfferRows row gets: one guard mode's test,
// the config with no [components] block, a fresh clone with the committed
// SessionStart hook nobody accepted, and the accept of every digest in a
// root.
type trustOfferEnv struct {
	t       *testing.T
	mode    string
	cfgPath string
	cfg     config.Config
	// newClone writes another repository with the committed hook.
	newClone func() string
	accept   func(root string)
}

// trustOfferRows are the launch paths a build-tag-gated file adds to
// TestTrustOfferedByDefault (each file appends in init); a build without
// the path's component leaves its row out.
var trustOfferRows []func(trustOfferEnv)

// trustOfferCommittedHook is a fresh clone's committed SessionStart hook.
var trustOfferCommittedHook = map[string]string{
	".claude/settings.json": `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node .github/setup.js"}]}]}}`,
	".github/setup.js":      "console.log(1)\n",
}

// checkTrustOffered is TestTrustOfferedByDefault's body.
func checkTrustOffered(t *testing.T) {
	committedHook := trustOfferCommittedHook
	ownNormal := map[string]string{
		".claude/settings.local.json": `{"permissions":{"allow":["Bash(npm test:*)"]}}`,
		".git/config":                 "[core]\n\tbare = false\n[branch \"main\"]\n\tremote = origin\n",
		".env":                        "PORT=3000\n",
	}
	ownSetting := map[string]string{".git/config": "[core]\n\tsshCommand = ssh -i ~/.ssh/work_ed25519\n"}
	ownLoads := map[string]string{".env": "PYTHONPATH=./src\n"}

	for _, mode := range []string{"observe", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv(repoTrustCheckedEnv, "")
			dir := t.TempDir()
			_, dbPath := trustTestStore(t)
			// No [components] block: componentstate.Legacy.
			cfgPath := filepath.Join(dir, "config.toml")
			body := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n[guard]\nenabled = true\nmode = " + strconv.Quote(mode) + "\n"
			if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
			if err != nil {
				t.Fatal(err)
			}
			snap := componentSnapshotForConfig(cfg)
			if snap.Configured {
				t.Fatal("the config has a [components] block")
			}
			// The managed edition leaves the security module inert with no
			// block (until the organization's policy allows it): trust is
			// not selected there, and nothing below applies.
			if securityInertByDefault() {
				if securitySelected(snap, repoTrustComponent) || repoTrustSelected(snap) {
					t.Fatal("security.trust is selected with no [components] block in an edition that leaves the module inert")
				}
				return
			}
			// The one opt-in rule selects it: the dashboard's trust route
			// (Options.SecuritySelected), the baseline loop and the
			// session-start flag follow it.
			if !securitySelected(snap, repoTrustComponent) || !repoTrustSelected(snap) {
				t.Fatal("security.trust is not selected with no [components] block")
			}
			old := cliLaunchDir
			t.Cleanup(func() { cliLaunchDir = old })

			// cliRowAnswering is the row of an `observer <tool>` launch in
			// root; answer, when set, stands in for the launch terminal.
			cliRowAnswering := func(root string, answer func(string) string) launchGateStep {
				cliLaunchDir = func() (string, error) { return root, nil }
				r := cliLaunchGateRun(context.Background(), cfgPath, "claude-code", budgetLaunchEvidence{})
				r.markChecked = nil
				t.Cleanup(r.close)
				if s := gateStateLoad(r); s.refuse != nil {
					t.Fatal(s.refuse)
				}
				if answer != nil {
					build := r.repoTrustFor
					r.repoTrustFor = func(r *launchGateRun) *repoTrustDeps {
						deps := build(r)
						if deps != nil {
							deps.ask, deps.answer = func(string) bool { return false }, answer
						}
						return deps
					}
				}
				return gateRepoTrust(r)
			}
			cliRow := func(root string) launchGateStep { return cliRowAnswering(root, nil) }
			acceptAll := func(root string) {
				res, err := sectrust.Check(context.Background(), sectrust.OSFS(root), sectrust.Request{})
				if err != nil {
					t.Fatal(err)
				}
				st := openTrustTestDBFromConfig(t, cfgPath)
				if _, err := st.AcceptSecTrustItems(context.Background(), guard.HashProjectRoot(root), secTrustItems(res), "cli:test", time.Now()); err != nil {
					t.Fatal(err)
				}
			}

			// A clean repository and the developer's own files in normal use.
			for name, files := range map[string]map[string]string{"clean": {"README.md": "# x\n"}, "own files, normal work": ownNormal} {
				if s := cliRow(writeTrustRepo(t, files)); s.outcomes() != launchGateAllow {
					t.Fatalf("%s: %+v, want nothing", name, s)
				}
			}

			// A common own-file setting: raised until accepted, then quiet.
			own := writeTrustRepo(t, ownSetting)
			if s := cliRow(own); s.outcomes() == launchGateAllow {
				t.Fatal("own setting before its accept: quiet")
			}
			acceptAll(own)
			for i := 0; i < 2; i++ {
				if s := cliRow(own); s.outcomes() != launchGateAllow {
					t.Fatalf("own setting after its accept, launch %d: %+v", i+1, s)
				}
			}

			// An own-file setting that loads code: after its accept, the
			// S-705 warning at every launch.
			loads := writeTrustRepo(t, ownLoads)
			if s := cliRow(loads); s.outcomes() == launchGateAllow {
				t.Fatal("own code-loading setting before its accept: quiet")
			}
			acceptAll(loads)
			for i := 0; i < 2; i++ {
				if s := cliRow(loads); s.outcomes() != launchGateAllow|launchGateWarn || !strings.Contains(s.warn, "S-705") {
					t.Fatalf("own code-loading setting after its accept, launch %d: %+v", i+1, s)
				}
			}

			// A fresh clone with a committed SessionStart hook.
			clone := writeTrustRepo(t, committedHook)
			s := cliRow(clone)
			switch mode {
			case "observe":
				if s.outcomes() != launchGateAllow|launchGateWarn || !strings.Contains(s.warn, "S-701") {
					t.Fatalf("committed hook, observe: %+v", s)
				}
			case "enforce":
				if s.refuse == nil || !strings.Contains(s.refuse.Error(), "S-701") {
					t.Fatalf("committed hook, enforce, no terminal: %+v", s)
				}
				// At a terminal: "a" accepts and launches; the next launch
				// warns with no question.
				answered := writeTrustRepo(t, committedHook)
				if s := cliRowAnswering(answered, func(string) string { return "a" }); s.outcomes() != launchGateAllow {
					t.Fatalf("committed hook, enforce, answer a: %+v", s)
				}
				if s := cliRowAnswering(answered, func(string) string { t.Fatal("asked again after the accept"); return "" }); s.outcomes() != launchGateAllow|launchGateWarn || !strings.Contains(s.warn, "S-705") {
					t.Fatalf("committed hook after the terminal accept: %+v", s)
				}
			}

			// An Arena run on that clone (its worktree has the same files).
			worktree := writeTrustRepo(t, committedHook)
			env, err := enforceDaemonStartedLaunch(context.Background(), cfgPath, "claude-code", budgetLaunchEvidence{}, daemonLaunch{dir: worktree, acceptDir: clone})
			switch mode {
			case "observe":
				if err != nil || len(env) != 1 {
					t.Fatalf("Arena, observe: %v %v", env, err)
				}
			case "enforce":
				if err == nil || !strings.Contains(err.Error(), "observer security trust accept --all --dir "+clone) {
					t.Fatalf("Arena, enforce: %v, want a refusal that says where to accept", err)
				}
			}
			// The Arena judge, in its empty scratch directory, goes on.
			if _, err := enforceDaemonStartedLaunch(context.Background(), cfgPath, "claude-code", budgetLaunchEvidence{}, daemonLaunch{dir: t.TempDir()}); err != nil {
				t.Fatalf("Arena judge: %v", err)
			}

			env2 := trustOfferEnv{
				t: t, mode: mode, cfgPath: cfgPath, cfg: cfg, accept: acceptAll,
				newClone: func() string { return writeTrustRepo(t, committedHook) },
			}
			for _, row := range trustOfferRows {
				row(env2)
			}
			if os.Getenv(repoTrustCheckedEnv) != "" {
				t.Fatal("the marker reached this process's environment")
			}
		})
	}
}
