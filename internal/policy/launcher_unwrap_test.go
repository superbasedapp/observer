package policy

import (
	"strings"
	"testing"
	"time"
)

// unwrapEval evaluates one command line in ModeEnforce under the POSIX
// dialect (the shell the container/remote command runs under).
func unwrapEval(t *testing.T, line string) Verdict {
	t.Helper()
	e, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e.Evaluate(Event{
		Kind: KindShellExec, ActionType: "run_command",
		Target: line, Dialect: DialectPosix,
		Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", SessionID: "s1",
		Now: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
	})
}

// TestContainerExecUnwrap pins that docker/podman/nerdctl/compose `exec`
// surfaces the inner command to every rule. The worked case: a destructive
// SQL statement behind `docker exec` denies via R-120.
func TestContainerExecUnwrap(t *testing.T) {
	t.Parallel()
	hits := []struct{ name, cmd, rule string }{
		{"docker exec psql drop", `docker exec db psql -c "DROP TABLE x"`, "R-120"},
		{"docker exec with -it", `docker exec -it db psql -c "DROP TABLE users"`, "R-120"},
		{"docker exec skips valued -u/-w/-e", `docker exec -u root -w /app -e K=V db psql -c "DROP TABLE x"`, "R-120"},
		{"docker container exec", `docker container exec db psql -c "DROP TABLE x"`, "R-120"},
		{"docker compose exec service", `docker compose exec db psql -c "DROP TABLE x"`, "R-120"},
		{"docker-compose exec service", `docker-compose exec db psql -c "DROP TABLE x"`, "R-120"},
		{"podman exec", `podman exec db psql -c "DROP TABLE x"`, "R-120"},
		{"nerdctl exec", `nerdctl exec db psql -c "DROP TABLE x"`, "R-120"},
		{"docker exec rm -rf root", `docker exec box rm -rf /`, "R-101"},
		{"docker exec reaches metadata", `docker exec box curl http://169.254.169.254/`, "R-174"},
	}
	for _, tc := range hits {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if v := unwrapEval(t, tc.cmd); v.RuleID != tc.rule {
				t.Errorf("%q = %s/%s, want %s", tc.cmd, v.Decision, v.RuleID, tc.rule)
			}
		})
	}
	misses := []struct{ name, cmd string }{
		{"docker run is out of scope", `docker run alpine psql -c "DROP TABLE x"`},
		{"docker build", `docker build -t img .`},
		{"docker exec interactive shell only", `docker exec -it db`},
		{"docker ps", `docker ps -a`},
	}
	for _, tc := range misses {
		t.Run("miss/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := unwrapEval(t, tc.cmd); v.Decision != DecisionAllow {
				t.Errorf("%q = %s/%s, want allow", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
}

// TestKubectlExecUnwrap pins kubectl/oc `exec`, both the `--` form and the
// legacy no-terminator form.
func TestKubectlExecUnwrap(t *testing.T) {
	t.Parallel()
	hits := []struct{ name, cmd, rule string }{
		{"kubectl exec -- rm", `kubectl exec -n x pod -- rm -rf /`, "R-101"},
		{"kubectl exec -- psql", `kubectl exec pod -- psql -c "DROP TABLE x"`, "R-120"},
		{"kubectl exec valued flags skipped", `kubectl exec -n ns -c ctr pod -- rm -rf /`, "R-101"},
		{"kubectl exec legacy no --", `kubectl exec pod rm -rf /`, "R-101"},
		{"oc exec", `oc exec pod -- rm -rf /`, "R-101"},
	}
	for _, tc := range hits {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if v := unwrapEval(t, tc.cmd); v.RuleID != tc.rule {
				t.Errorf("%q = %s/%s, want %s", tc.cmd, v.Decision, v.RuleID, tc.rule)
			}
		})
	}
	misses := []struct{ name, cmd string }{
		{"kubectl get is not exec", `kubectl get pods`},
		{"kubectl exec attach only", `kubectl exec -it pod`},
		{"kubectl exec -- with nothing after", `kubectl exec pod --`},
	}
	for _, tc := range misses {
		t.Run("miss/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if v := unwrapEval(t, tc.cmd); v.Decision != DecisionAllow {
				t.Errorf("%q = %s/%s, want allow", tc.cmd, v.Decision, v.RuleID)
			}
		})
	}
}

// TestSSHReparseUnwrap pins that ssh's remote command is re-parsed as a shell
// line so every rule sees it.
func TestSSHReparseUnwrap(t *testing.T) {
	t.Parallel()
	hits := []struct{ name, cmd, rule string }{
		{"ssh remote curl metadata", `ssh host 'curl http://169.254.169.254/'`, "R-174"},
		{"ssh remote rm", `ssh user@host 'rm -rf /'`, "R-101"},
		{"ssh with options then remote rm", `ssh -p 2222 -i key.pem user@host 'rm -rf /'`, "R-101"},
		{"ssh remote pipeline", `ssh host 'curl http://169.254.169.254/ | tee out'`, "R-174"},
	}
	for _, tc := range hits {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if v := unwrapEval(t, tc.cmd); v.RuleID != tc.rule {
				t.Errorf("%q = %s/%s, want %s", tc.cmd, v.Decision, v.RuleID, tc.rule)
			}
		})
	}
	misses := []struct{ name, cmd string }{
		{"ssh interactive login", `ssh user@host`},
		{"ssh options only", `ssh -p 22`},
	}
	for _, tc := range misses {
		t.Run("miss/"+tc.name, func(t *testing.T) {
			t.Parallel()
			// A bare login names no remote command, so R-157 must not deny it.
			if v := unwrapEval(t, tc.cmd); v.RuleID == "R-157" {
				t.Errorf("%q wrongly denied as unanalysed (%s)", tc.cmd, v.Reason)
			}
		})
	}
}

// TestUnwrapWrapperNamesRecorded pins the wrapper names the new launchers
// record on the inner Command.
func TestUnwrapWrapperNamesRecorded(t *testing.T) {
	t.Parallel()
	for line, want := range map[string]string{
		`docker exec db psql -c "DROP TABLE x"`: "docker exec",
		`kubectl exec pod -- rm -rf /`:          "kubectl exec",
		`ssh host 'rm -rf /'`:                   "ssh",
	} {
		cmds := ParseCommand(line, DialectPosix)
		found := false
		for i := range cmds {
			if cmds[i].Depth == 0 {
				continue
			}
			found = true
			if !viaLauncher(&cmds[i]) || !hasWrapper(&cmds[i], want) {
				t.Errorf("%q: inner unit %q wrappers %q, want %q", line, cmds[i].Base, cmds[i].Wrappers, want)
			}
		}
		if !found {
			t.Errorf("%q: no launched unit produced", line)
		}
	}
}

// TestUnwrapFailsClosed pins R-157 on nesting past the depth limit: a stack
// of ssh reparses deeper than maxUnwrapDepth marks the inner line unanalysed
// and denies.
func TestUnwrapFailsClosed(t *testing.T) {
	t.Parallel()
	// Seven nested ssh hops; the innermost crontab is past maxUnwrapDepth.
	inner := "crontab -e"
	line := inner
	for i := 0; i < 7; i++ {
		line = "ssh host '" + strings.ReplaceAll(line, "'", `"`) + "'"
	}
	v := unwrapEval(t, line)
	if v.Decision != DecisionDeny {
		t.Fatalf("deep ssh nesting = %s/%s, want deny (R-157 fail-closed)", v.Decision, v.RuleID)
	}
	if v.RuleID != "R-157" {
		t.Logf("deep nesting denied via %s (acceptable if a rule fired before the limit)", v.RuleID)
	}
}

// unwrapCase is one engine-level row of the 2026-11-08 guard sweep: a
// line, and either the rule it must hit or "" for allow.
type unwrapCase struct{ name, cmd, rule string }

// runUnwrapCases evaluates each row in ModeEnforce. A row with a rule
// must hit exactly that rule; a row without one must allow.
func runUnwrapCases(t *testing.T, cases []unwrapCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := unwrapEval(t, tc.cmd)
			if tc.rule == "" {
				if v.Decision != DecisionAllow {
					t.Errorf("%q = %s/%s (%s), want allow", tc.cmd, v.Decision, v.RuleID, v.Reason)
				}
				return
			}
			if v.RuleID != tc.rule {
				t.Errorf("%q = %s/%s (%s), want %s", tc.cmd, v.Decision, v.RuleID, v.Reason, tc.rule)
			}
		})
	}
}

// TestLauncherGlobalFlagsBeforeSubcommand pins SH-1: a tool's global
// options before `exec` no longer stop the unwrap.
func TestLauncherGlobalFlagsBeforeSubcommand(t *testing.T) {
	t.Parallel()
	runUnwrapCases(t, []unwrapCase{
		{"kubectl -n before exec", `kubectl -n ns exec pod -- rm -rf /`, "R-101"},
		{"kubectl --context before exec", `kubectl --context prod exec pod -- rm -rf /`, "R-101"},
		{"kubectl --kubeconfig= inline", `kubectl --kubeconfig=/tmp/k exec pod -- rm -rf /`, "R-101"},
		{"oc --server before exec", `oc --server https://x exec pod -- rm -rf /`, "R-101"},
		{"docker --context before exec", `docker --context prod exec ctr rm -rf /`, "R-101"},
		{"docker -H before exec", `docker -H ssh://h exec ctr rm -rf /`, "R-101"},
		{"podman --log-level before exec", `podman --log-level debug exec ctr rm -rf /`, "R-101"},
		{"docker compose -f before exec", `docker compose -f x.yml exec svc rm -rf /`, "R-101"},
		{"docker compose -p before exec", `docker compose -p proj exec svc rm -rf /`, "R-101"},
		{"docker -H then compose -f", `docker -H ssh://h compose -f x.yml exec svc rm -rf /`, "R-101"},
		{"docker-compose -f before exec", `docker-compose -f x.yml exec svc rm -rf /`, "R-101"},
		{"docker-compose --project-directory", `docker-compose --project-directory . exec svc rm -rf /`, "R-101"},
		// SH-1 fail-closed arm: an unknown GLOBAL dashed token before a
		// recognisable `exec` cannot be located, so the unit is Unanalyzed
		// and R-157 denies (not R-101 — the inner command is unrecoverable).
		{"unknown global flag before exec is unanalysed", `kubectl --frobnicate exec pod rm -rf /`, "R-157"},
		{"unknown docker global flag before exec", `docker --frob x exec ctr rm -rf /`, "R-157"},
		// Ordinary non-exec lines stay allowed.
		{"kubectl -n get pods", `kubectl -n ns get pods`, ""},
		{"kubectl --context get", `kubectl --context prod get deploy`, ""},
		{"docker compose -f up", `docker compose -f x.yml up -d`, ""},
		{"docker-compose -f ps", `docker-compose -f x.yml ps`, ""},
		{"docker --context ps", `docker --context prod ps`, ""},
		{"docker -H images", `docker -H ssh://h images`, ""},
	})
}

// TestLauncherGlobalSwitches pins the SH-1 switch tables: a known global
// SWITCH is skipped rather than read as ambiguous, so ordinary use is not
// denied, a known valued global (incl. kubectl's -v) consumes its value, and
// an unknown token still fails closed.
func TestLauncherGlobalSwitches(t *testing.T) {
	t.Parallel()
	runUnwrapCases(t, []unwrapCase{
		// The coordinator's three pins.
		{"docker --tls exec benign", `docker --tls exec ctr ls`, ""},
		{"docker --debug compose -f exec rm", `docker --debug compose -f x.yml exec web rm -rf /`, "R-101"},
		{"kubectl -v 6 exec rm", `kubectl -v 6 exec pod -- rm -rf /`, "R-101"},
		// docker / podman / nerdctl switches and valued globals.
		{"docker -D exec rm", `docker -D exec ctr rm -rf /`, "R-101"},
		{"docker --tlsverify --tlscacert exec rm", `docker --tlsverify --tlscacert ca.pem exec ctr rm -rf /`, "R-101"},
		{"docker -l debug exec rm", `docker -l debug exec ctr rm -rf /`, "R-101"},
		{"docker -c ctx exec rm", `docker -c prod exec ctr rm -rf /`, "R-101"},
		{"podman --remote exec rm", `podman --remote exec ctr rm -rf /`, "R-101"},
		{"podman -r exec rm", `podman -r exec ctr rm -rf /`, "R-101"},
		{"nerdctl --debug-full exec rm", `nerdctl --debug-full exec ctr rm -rf /`, "R-101"},
		{"nerdctl --insecure-registry exec rm", `nerdctl --insecure-registry exec ctr rm -rf /`, "R-101"},
		// compose switches and valued globals.
		{"compose --dry-run exec rm", `docker compose --dry-run exec web rm -rf /`, "R-101"},
		{"compose --ansi never exec rm", `docker compose --ansi never exec web rm -rf /`, "R-101"},
		{"compose --progress plain exec rm", `docker compose --progress plain exec web rm -rf /`, "R-101"},
		{"docker-compose --compatibility --verbose exec rm", `docker-compose --compatibility --verbose exec web rm -rf /`, "R-101"},
		// kubectl: -v valued in every spelling, booleans are switches.
		{"kubectl -v6 attached exec rm", `kubectl -v6 exec pod -- rm -rf /`, "R-101"},
		{"kubectl --v=6 exec rm", `kubectl --v=6 exec pod -- rm -rf /`, "R-101"},
		{"kubectl --insecure-skip-tls-verify exec rm", `kubectl --insecure-skip-tls-verify exec pod -- rm -rf /`, "R-101"},
		{"kubectl --request-timeout exec rm", `kubectl --request-timeout 30s exec pod -- rm -rf /`, "R-101"},
		{"kubectl --as exec legacy rm", `kubectl --as admin exec pod rm -rf /`, "R-101"},
		// Ordinary use stays allowed.
		{"docker --debug ps", `docker --debug ps`, ""},
		{"docker -D exec benign", `docker -D exec ctr ls`, ""},
		{"compose --dry-run up", `docker compose --dry-run up`, ""},
		{"kubectl --insecure-skip-tls-verify get", `kubectl --insecure-skip-tls-verify get pods`, ""},
		{"kubectl -v 6 get", `kubectl -v 6 get pods`, ""},
		// Unknown still fails closed, including a switch with junk attached.
		{"docker -Dx unknown", `docker -Dx exec ctr rm -rf /`, "R-157"},
		{"compose unknown global", `docker compose --frob exec web rm -rf /`, "R-157"},
	})
}

// TestLauncherUnknownGlobalFlagFailsClosed pins SH-1's fail-closed arm: an
// unknown dashed token before a recognisable `exec` whose readings cannot
// reach a command still marks the unit Unanalyzed rather than passing.
func TestLauncherUnknownGlobalFlagFailsClosed(t *testing.T) {
	t.Parallel()
	for _, line := range []string{
		`kubectl --frobnicate exec`,
		`docker --frob exec`,
	} {
		cmds := ParseCommand(line, DialectPosix)
		if len(cmds) == 0 || cmds[0].Unanalyzed == "" {
			t.Errorf("%q: want the launcher unit marked Unanalyzed, got %+v", line, cmds)
		}
	}
}

// TestLauncherExecValuedFlags pins SH-2 and SA-6: exec's own valued flags
// no longer shift the container operand, an unknown dashed token yields
// both readings, and podman's --latest takes no container operand.
func TestLauncherExecValuedFlags(t *testing.T) {
	t.Parallel()
	runUnwrapCases(t, []unwrapCase{
		{"docker exec --detach-keys", `docker exec --detach-keys ctrl-p ctr rm -rf /`, "R-101"},
		{"kubectl exec --pod-running-timeout legacy", `kubectl exec --pod-running-timeout 1m pod rm -rf /`, "R-101"},
		{"docker exec unknown valued flag", `docker exec --newflag val ctr rm -rf /`, "R-101"},
		{"docker exec unknown switch", `docker exec --newswitch ctr rm -rf /`, "R-101"},
		{"kubectl exec unknown valued flag legacy", `kubectl exec --newflag v pod rm -rf /`, "R-101"},
		{"podman exec -l", `podman exec -l rm -rf /`, "R-101"},
		{"podman exec --latest", `podman exec --latest rm -rf /`, "R-101"},
		{"podman exec --preserve-fds", `podman exec --preserve-fds 1 ctr rm -rf /`, "R-101"},
		{"podman exec --preserve-fd", `podman exec --preserve-fd 3 ctr rm -rf /`, "R-101"},
		{"docker compose exec --index", `docker compose exec --index 2 web rm -rf /`, "R-101"},
		// Benign exec lines stay allowed.
		{"docker exec --detach-keys benign", `docker exec --detach-keys ctrl-p ctr ls -la`, ""},
		{"podman exec -l benign", `podman exec -l ls`, ""},
		{"compose exec --index benign", `docker compose exec --index 2 web ls`, ""},
	})
}

// TestSSHOptionsAfterDestination pins SA-5: OpenSSH re-reads options after
// the destination unless `--` ends them, and -P takes a value.
func TestSSHOptionsAfterDestination(t *testing.T) {
	t.Parallel()
	runUnwrapCases(t, []unwrapCase{
		{"ssh host -t cmd", `ssh host -t 'rm -rf /'`, "R-101"},
		{"ssh host -o value cmd", `ssh host -o BatchMode=yes rm -rf /`, "R-101"},
		{"ssh host -- cmd", `ssh host -- rm -rf /`, "R-101"},
		{"ssh -P tag host cmd", `ssh -P tag host rm -rf /`, "R-101"},
		{"ssh host -p port cmd", `ssh host -p 2222 'rm -rf /'`, "R-101"},
		{"ssh host -- dashed remote cmd", `ssh host -- -rm`, ""},
		{"ssh host benign", `ssh host -t uptime`, ""},
	})
}

// TestBusyboxApplets pins NET-5's parse half: a leading busybox/toybox is
// stripped so the applet is the base every rule family sees.
func TestBusyboxApplets(t *testing.T) {
	t.Parallel()
	runUnwrapCases(t, []unwrapCase{
		{"busybox rm", `busybox rm -rf /`, "R-101"},
		{"toybox rm", `toybox rm -rf /`, "R-101"},
		{"busybox sh -c", `busybox sh -c 'rm -rf /'`, "R-101"},
		{"sudo busybox rm", `sudo busybox rm -rf /`, "R-101"},
		{"path-qualified busybox", `/bin/busybox rm -rf /`, "R-101"},
		{"busybox benign applet", `busybox ls -la`, ""},
		{"busybox --list", `busybox --list`, ""},
	})
	for line, base := range map[string]string{
		`busybox wget http://example.com/`: "wget",
		`toybox cat x`:                     "cat",
	} {
		cmds := ParseCommand(line, DialectPosix)
		if len(cmds) == 0 || cmds[0].Base != base {
			t.Errorf("%q: base %q, want %q", line, cmdsBase(cmds), base)
		}
	}
}

// cmdsBase returns the first unit's base, or "" for none.
func cmdsBase(cmds []Command) string {
	if len(cmds) == 0 {
		return ""
	}
	return cmds[0].Base
}
