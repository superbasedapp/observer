package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// onboarding_help_test.go pins Getting started v2's help surface: the old
// words for connecting stay working but are hidden from help, and
// `disconnect` is the visible undo of `connect`.

func findCmd(t *testing.T, root *cobra.Command, path ...string) *cobra.Command {
	t.Helper()
	c, _, err := root.Find(path)
	if err != nil || c == nil || c.Name() != path[len(path)-1] {
		t.Fatalf("command %v not found: %v", path, err)
	}
	return c
}

func TestOnboardingOldVerbsHiddenButWorking(t *testing.T) {
	root := newRootCmd()
	for _, path := range [][]string{{"enroll"}, {"org", "enroll"}} {
		if c := findCmd(t, root, path...); !c.Hidden {
			t.Errorf("%v is visible in help", path)
		}
	}
	// A build without cloud.intelligence has a compiled-out `cloud` stub
	// with no `login` under it: Find then returns the stub, not an error, so
	// the check keys on the command found, not on err alone.
	if c, _, err := root.Find([]string{"cloud", "login"}); err == nil && c != nil && c.Name() == "login" {
		if !c.Hidden {
			t.Error("cloud login is visible in help")
		}
		if strings.Contains(c.Short+c.Long, "WorkOS") {
			t.Errorf("cloud login help names a vendor: %q", c.Short+c.Long)
		}
	}
	for _, path := range [][]string{{"connect"}, {"disconnect"}, {"unenroll"}} {
		if c := findCmd(t, root, path...); c.Hidden {
			t.Errorf("%v is hidden", path)
		}
	}
}

func TestDisconnectIsTheLeaveCommand(t *testing.T) {
	c := newDisconnectCmd()
	if c.Use != "disconnect" {
		t.Fatalf("use = %q", c.Use)
	}
	for _, flag := range []string{"plan", "drop-unsent", "config"} {
		if c.Flags().Lookup(flag) == nil {
			t.Errorf("disconnect lacks the leave command's --%s", flag)
		}
	}
}
