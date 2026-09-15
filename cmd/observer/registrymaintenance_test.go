package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestLaunchGateMaintenanceSetsComeFromTheRegistry pins the one-owner rule: a
// launcher's budget maintenance vocabulary must BE the registry row's
// non-billable declaration, not a parallel copy of it, so the launch gate and
// the node process controller classify the same invocation identically.
func TestLaunchGateMaintenanceSetsComeFromTheRegistry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		tool        string
		subcommands map[string]bool
		flags       map[string]bool
	}{
		{tool: "muse", subcommands: museBudgetMaintenanceSubcommands, flags: museBudgetMaintenanceFlags},
		{tool: "cursor", subcommands: cursorBudgetMaintenanceSubcommands, flags: cursorBudgetMaintenanceFlags},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			t.Parallel()
			declared := integration.NonBillableLeadingArguments(tc.tool)
			if len(declared) == 0 {
				t.Fatalf("registry declares no non-billable arguments for %q", tc.tool)
			}
			var wantSubcommands, wantFlags []string
			for _, argument := range declared {
				if strings.HasPrefix(argument, "-") {
					wantFlags = append(wantFlags, argument)
					continue
				}
				wantSubcommands = append(wantSubcommands, argument)
			}
			assertSetEquals(t, "subcommands", tc.subcommands, wantSubcommands)
			assertSetEquals(t, "flags", tc.flags, wantFlags)
		})
	}
}

// TestLaunchGateMaintenanceKeepsModelBearingVerbsControlled guards the
// direction that matters for spend: a verb that submits a model request must
// never be inherited as maintenance from the universal set.
func TestLaunchGateMaintenanceKeepsModelBearingVerbsControlled(t *testing.T) {
	t.Parallel()

	for _, verb := range []string{"exec", "resume", "session-message", "sandbox"} {
		if museBudgetMaintenanceSubcommands[verb] {
			t.Errorf("muse maintenance set wrongly contains model-bearing verb %q", verb)
		}
		if museBudgetLaunchEvidence([]string{verb, "hello"}).Route != budgetLaunchRouteDirect {
			t.Errorf("muse %q launch escaped budget control", verb)
		}
	}
	for _, verb := range []string{"agent", "resume", "create-chat"} {
		if cursorBudgetMaintenanceSubcommands[verb] {
			t.Errorf("cursor maintenance set wrongly contains model-bearing verb %q", verb)
		}
		if cursorBudgetLaunchEvidence([]string{verb, "hello"}).Route != budgetLaunchRouteDirect {
			t.Errorf("cursor %q launch escaped budget control", verb)
		}
	}
}

func assertSetEquals(t *testing.T, label string, got map[string]bool, want []string) {
	t.Helper()
	have := make([]string, 0, len(got))
	for key, ok := range got {
		if ok {
			have = append(have, key)
		}
	}
	sort.Strings(have)
	sort.Strings(want)
	if len(have) != len(want) {
		t.Fatalf("%s = %v, want %v", label, have, want)
	}
	for i := range have {
		if have[i] != want[i] {
			t.Fatalf("%s = %v, want %v", label, have, want)
		}
	}
}
