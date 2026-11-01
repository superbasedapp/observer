//go:build !sbo_omit_terminals

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestSandboxFallbackAppliesToEveryLaunchPath pins T-497 (D-333): the org's
// "No sandbox available" choice is ONE node rule, so the
// dashboard's fresh launch and `observer <tool>` typed in a terminal reach
// the same answer for the same guard, tool and hook state. Before T-497 only
// the dashboard refused; the CLI rows below were red.
//
// The CLI goes through enforceBudgetControlledLaunch, the shared launch
// admission chokepoint every `observer <tool>` launcher calls, so the test
// proves the wiring as well as the decision.
func TestSandboxFallbackAppliesToEveryLaunchPath(t *testing.T) {
	proxied := firstTool(t, func(c integration.Capability) bool {
		return c.EnforcementChannel() == integration.EnforceSandbox && c.Proxy != nil
	})
	unproxied := firstTool(t, func(c integration.Capability) bool {
		return c.EnforcementChannel() == integration.EnforceSandbox && c.Proxy == nil
	})
	hookBlock := firstTool(t, func(c integration.Capability) bool {
		return c.EnforcementChannel() == integration.EnforceHookBlock
	})
	const disallow = "[fallbacks]\nsandbox_unavailable = \"org_disallow\"\n"
	cases := []struct {
		name      string
		tool      string
		mode      string
		bundle    string
		managed   bool
		gate      bool
		sandboxed bool // CLI only: running inside a sandbox the dashboard built
		refused   bool
	}{
		{"managed + org_disallow + proxied tool: refused", proxied.Tool, "enforce", disallow, true, false, false, true},
		{"managed + default: recorded acceptance", proxied.Tool, "enforce", "", true, false, false, false},
		{"individual + org_disallow: recorded acceptance", proxied.Tool, "enforce", disallow, false, false, false, false},
		{"managed + org_disallow + unproxied tool: recorded acceptance", unproxied.Tool, "enforce", disallow, true, false, false, false},
		{"managed + org_disallow + blocking-hook tool, gate current: unaffected", hookBlock.Tool, "enforce", disallow, true, true, false, false},
		{"managed + org_disallow + blocking-hook tool, gate not current: org choice", hookBlock.Tool, "enforce", disallow, true, false, false, hookBlock.Proxy != nil},
		{"managed + org_disallow, guard observes: unaffected", proxied.Tool, "observe", disallow, true, false, false, false},
		{"managed + org_disallow + per-rule enforce, guard observes: refused", proxied.Tool, "observe", disallow + "\n[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n", true, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			gcfg := config.Default().Guard
			gcfg.Enabled, gcfg.Mode = true, tc.mode
			gcfg.Rules.OrgBundle = filepath.Join(dir, "org-policy-bundle.json")
			gcfg.Rules.UserPolicy = ""
			pin := ""
			if tc.bundle != "" {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				writeFileT(t, gcfg.Rules.OrgBundle, signedGuardBundleJSON(t, priv, pub, 3, tc.bundle))
				pin = pinOf(pub)
			}
			managed := tc.managed
			gd, err := guard.New(guard.Options{Config: gcfg, Home: dir, OrgKeyPinHash: pin, ManagedTenancy: func() bool { return managed }})
			if err != nil {
				t.Fatal(err)
			}
			gateCurrent := tc.gate
			gate := func(string) nodeToolGateState { return nodeToolGateState{Current: gateCurrent} }

			// Path 1: the dashboard's fresh launch.
			lau := &recordingLauncher{}
			svc := termsvc.New(termsvc.Options{
				Recorder: assembledRecorder{},
				Launcher: lau,
				Policy:   termsvc.Policy{AllowFresh: true, AllowedTools: []string{tc.tool}, AllowedProjectRoots: []string{dir}},
			})
			a := &launchManagerAdapter{svc: svc, guard: gd, toolGate: gate}
			_, dashErr := a.CreateFresh(dashapi.FreshLaunchSpec{Tool: tc.tool, Subcommand: tc.tool, ProjectRoot: dir})

			// Path 2: `observer <tool>` through the shared admission chokepoint.
			cfgPath := writeSandboxGateConfig(t, dir, tc.mode)
			restore := setSandboxGateSeams(gd, gate, tc.sandboxed)
			cliErr := enforceBudgetControlledLaunch(context.Background(), cfgPath, tc.tool,
				budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
			restore()

			for _, p := range []struct {
				path string
				err  error
			}{{"dashboard", dashErr}, {"cli", cliErr}} {
				if tc.refused {
					if !errors.Is(p.err, dashapi.ErrLaunchSandboxRequired) {
						t.Fatalf("%s: err = %v, want the org sandbox refusal", p.path, p.err)
					}
					// Honest text: names the org setting by its label and value.
					for _, want := range []string{tc.tool, `"No sandbox available"`, "org_disallow"} {
						if !strings.Contains(p.err.Error(), want) {
							t.Errorf("%s: refusal %q does not name %s", p.path, p.err, want)
						}
					}
					continue
				}
				if p.err != nil {
					t.Fatalf("%s: launch = %v, want it to proceed", p.path, p.err)
				}
			}
			if tc.refused {
				if lau.last.Dir != "" {
					t.Fatal("a refused dashboard launch reached the spawner")
				}
				var vis launcherMessageError
				if !errors.As(cliErr, &vis) || !strings.Contains(vis.launcherMessage(), "org_disallow") {
					t.Fatalf("the CLI refusal is not shown at the terminal: %v", cliErr)
				}
			}
		})
	}
}

// TestSandboxFallbackCLIInsideDashboardSandbox: the dashboard upgraded the
// launch into a sandbox, so the inner `observer <tool>` it runs is contained
// and must not be refused by the same org choice.
func TestSandboxFallbackCLIInsideDashboardSandbox(t *testing.T) {
	proxied := firstTool(t, func(c integration.Capability) bool {
		return c.EnforcementChannel() == integration.EnforceSandbox && c.Proxy != nil
	})
	dir := t.TempDir()
	gcfg := config.Default().Guard
	gcfg.Enabled, gcfg.Mode = true, "enforce"
	gcfg.Rules.OrgBundle = filepath.Join(dir, "org-policy-bundle.json")
	gcfg.Rules.UserPolicy = ""
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeFileT(t, gcfg.Rules.OrgBundle, signedGuardBundleJSON(t, priv, pub, 3, "[fallbacks]\nsandbox_unavailable = \"org_disallow\"\n"))
	gd, err := guard.New(guard.Options{Config: gcfg, Home: dir, OrgKeyPinHash: pinOf(pub), ManagedTenancy: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := writeSandboxGateConfig(t, dir, "enforce")
	gate := func(string) nodeToolGateState { return nodeToolGateState{} }
	for _, sandboxed := range []bool{false, true} {
		restore := setSandboxGateSeams(gd, gate, sandboxed)
		err := enforceBudgetControlledLaunch(context.Background(), cfgPath, proxied.Tool,
			budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
		restore()
		if refused := errors.Is(err, dashapi.ErrLaunchSandboxRequired); refused == sandboxed {
			t.Fatalf("sandboxed=%v: err = %v", sandboxed, err)
		}
	}
}

// writeSandboxGateConfig writes a node config with the guard in mode and an
// unenrolled database, so the budget half of the chokepoint has nothing to
// refuse and only the sandbox decision is under test.
func writeSandboxGateConfig(t *testing.T, dir, mode string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "observer.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.toml")
	body := fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = true\nmode = %q\n", dbPath, mode)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// setSandboxGateSeams points the CLI's guard, hook-state and sandbox-marker
// seams at the test's values; the returned func restores them. Callers are
// never parallel.
func setSandboxGateSeams(gd *guard.Guard, gate func(string) nodeToolGateState, sandboxed bool) func() {
	prevGuard, prevGate, prevEnv, prevDir := cliLaunchGuard, cliLaunchToolGate, cliSandboxedEnv, cliLaunchDir
	cliLaunchGuard = func(context.Context, config.Config, *store.Store) *guard.Guard { return gd }
	cliLaunchToolGate = func(_, tool string) nodeToolGateState { return gate(tool) }
	cliSandboxedEnv = func() bool { return sandboxed }
	// No launch directory: the test process's own checkout must not decide.
	cliLaunchDir = func() (string, error) { return "", errors.New("no launch directory in this test") }
	return func() {
		cliLaunchGuard, cliLaunchToolGate, cliSandboxedEnv, cliLaunchDir = prevGuard, prevGate, prevEnv, prevDir
	}
}

// TestSandboxFallbackProjectHookSwitch (T-910): a blocking-hook tool whose
// hook is current on the node is NOT trusted for a launch in a project whose
// settings switch its hooks off, on both launch paths; the same project with
// the switch explicitly on launches as before.
func TestSandboxFallbackProjectHookSwitch(t *testing.T) {
	silenced := map[string]hookdisable.Switch{}
	for _, s := range hookdisable.Switches {
		// Only a key switch: the test writes the setting as a nested bool,
		// which a list-membership row (goose disabledPlugins) never reads.
		if s.Scope != hookdisable.ScopeProject || !s.KeySwitch() {
			continue
		}
		for _, tool := range s.Tools {
			if _, ok := silenced[tool]; !ok {
				silenced[tool] = s
			}
		}
	}
	hookBlock := firstTool(t, func(c integration.Capability) bool {
		_, ok := silenced[c.Tool]
		return ok && c.EnforcementChannel() == integration.EnforceHookBlock && c.Proxy != nil
	})
	row := silenced[hookBlock.Tool]
	for _, on := range []bool{true, false} {
		t.Run(fmt.Sprintf("switch set=%v", on), func(t *testing.T) {
			dir := t.TempDir()
			value := row.Off
			if !on {
				value = !row.Off
			}
			settings := filepath.Join(dir, filepath.FromSlash(row.ProjectRel))
			if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFileT(t, settings, nestedBoolJSON(row.Key, value))
			gcfg := config.Default().Guard
			gcfg.Enabled, gcfg.Mode = true, "enforce"
			gcfg.Rules.OrgBundle = filepath.Join(dir, "org-policy-bundle.json")
			gcfg.Rules.UserPolicy = ""
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			writeFileT(t, gcfg.Rules.OrgBundle, signedGuardBundleJSON(t, priv, pub, 3, "[fallbacks]\nsandbox_unavailable = \"org_disallow\"\n"))
			gd, err := guard.New(guard.Options{Config: gcfg, Home: dir, OrgKeyPinHash: pinOf(pub), ManagedTenancy: func() bool { return true }})
			if err != nil {
				t.Fatal(err)
			}
			gate := func(string) nodeToolGateState { return nodeToolGateState{Current: true, Reason: "registered"} }

			svc := termsvc.New(termsvc.Options{
				Recorder: assembledRecorder{},
				Launcher: &recordingLauncher{},
				Policy:   termsvc.Policy{AllowFresh: true, AllowedTools: []string{hookBlock.Tool}, AllowedProjectRoots: []string{dir}},
			})
			a := &launchManagerAdapter{svc: svc, guard: gd, toolGate: gate}
			_, dashErr := a.CreateFresh(dashapi.FreshLaunchSpec{Tool: hookBlock.Tool, Subcommand: hookBlock.Tool, ProjectRoot: dir})

			cfgPath := writeSandboxGateConfig(t, dir, "enforce")
			// This test isolates the hook.switch row. The repo.trust row runs
			// before it and, with security.trust on (developer and full
			// distros), refuses this hooks-off repository itself (S-703,
			// hooks_off_switch; TestRepoTrustRow), so it is removed here.
			appendFileT(t, cfgPath, "[components]\nremove = [\"security.trust\"]\n")
			restore := setSandboxGateSeams(gd, gate, false)
			cliLaunchDir = func() (string, error) { return dir, nil }
			cliErr := enforceBudgetControlledLaunch(context.Background(), cfgPath, hookBlock.Tool,
				budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
			restore()

			for _, p := range []struct {
				path string
				err  error
			}{{"dashboard", dashErr}, {"cli", cliErr}} {
				refused := errors.Is(p.err, dashapi.ErrLaunchSandboxRequired)
				if refused != on {
					t.Fatalf("%s (%s, %s): refused=%v err=%v", p.path, hookBlock.Tool, row.ID, refused, p.err)
				}
			}
		})
	}
}

// appendFileT appends body to path.
func appendFileT(t *testing.T, path, body string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
}

// nestedBoolJSON renders {"a":{"b":v}} for the dotted key "a.b".
func nestedBoolJSON(key string, v bool) string {
	segs := strings.Split(key, ".")
	out := fmt.Sprintf("%v", v)
	for i := len(segs) - 1; i >= 0; i-- {
		out = fmt.Sprintf("{%q:%s}", segs[i], out)
	}
	return out
}
