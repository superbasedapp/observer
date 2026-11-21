//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestSandboxSetupVerbsMeetTheGuardRows is the end-to-end refusal of the
// merged tree (P-253): every `observer sandbox setup` verb the real cobra
// tree registers (lane cli, verb before backend) is evaluated by the guard
// engine (lane guard's R-165 rows) in both modes. run, undo, update and
// repair are denied under enforce and flagged under observe; check asks in
// both; status and records stay allowed. The hosted connect verb is denied
// too. A verb the tree gains with no row here fails the test.
func TestSandboxSetupVerbsMeetTheGuardRows(t *testing.T) {
	want := map[string]policy.Decision{
		"run":     policy.DecisionDeny,
		"undo":    policy.DecisionDeny,
		"update":  policy.DecisionDeny,
		"repair":  policy.DecisionDeny,
		"check":   policy.DecisionAsk,
		"status":  0,
		"records": 0,
	}
	var setup *cobra.Command
	var find func(c *cobra.Command)
	find = func(c *cobra.Command) {
		if c.CommandPath() == "observer sandbox setup" {
			setup = c
			return
		}
		for _, sub := range c.Commands() {
			find(sub)
		}
	}
	find(newRootCmd())
	if setup == nil {
		t.Fatal("observer sandbox setup is not in the command tree")
	}
	evaluate := func(mode policy.Mode, line string) policy.Verdict {
		e, err := policy.New(policy.Config{Mode: mode, Home: "/home/u"})
		if err != nil {
			t.Fatal(err)
		}
		return e.Evaluate(policy.Event{Kind: policy.KindShellExec, Target: line, Cwd: "/home/u/p", ProjectRoot: "/home/u/p", SessionID: "s1"})
	}
	check := func(line string, d policy.Decision) {
		t.Helper()
		for _, mode := range []policy.Mode{policy.ModeObserve, policy.ModeEnforce} {
			v := evaluate(mode, line)
			switch {
			case d == 0:
				if v.RuleID == "R-165" {
					t.Errorf("%s (%s): got R-165/%s, want allowed", line, mode, v.Decision)
				}
			default:
				wantD := d
				if mode == policy.ModeObserve && d == policy.DecisionDeny {
					wantD = policy.DecisionFlag
				}
				if v.RuleID != "R-165" || v.Decision != wantD {
					t.Errorf("%s (%s): got %s/%s, want R-165/%s", line, mode, v.RuleID, v.Decision, wantD)
				}
			}
		}
	}
	seen := 0
	for _, sub := range setup.Commands() {
		verb := sub.Name()
		if verb == "help" || verb == "completion" {
			continue
		}
		d, ok := want[verb]
		if !ok {
			t.Errorf("sandbox setup %s has no guard expectation here: add its row (and its R-165 row if it changes the machine)", verb)
			continue
		}
		seen++
		line := strings.TrimSpace(sub.CommandPath() + " bwrap --step bwrap --yes")
		if verb == "records" {
			line = sub.CommandPath()
		}
		check(line, d)
	}
	if seen != len(want) {
		t.Errorf("walked %d setup verbs, want %d", seen, len(want))
	}
	check("observer sandbox hosted connect e2b", policy.DecisionDeny)
}
