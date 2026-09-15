package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSuppressedLauncherErrorRendersSafeMessageExactlyOnce(t *testing.T) {
	privateCause := errors.New("database /private/path: secret detail")
	returned := budgetLaunchStateFailure("muse", privateCause)
	root, child, output := executeLauncherError(t, true, returned)

	if output.Len() != 0 {
		t.Fatalf("Cobra wrote a silenced error before renderer: %q", output.String())
	}
	if !renderSuppressedLauncherError(output, root, child, returned) {
		t.Fatal("safe launcher error was not rendered")
	}
	got := output.String()
	want := "observer muse: cannot verify the managed-budget launch state; refusing to start the AI process\n"
	if got != want {
		t.Fatalf("rendered message = %q, want %q", got, want)
	}
	if strings.Contains(got, privateCause.Error()) || strings.Contains(got, "Usage:") {
		t.Fatalf("renderer exposed an internal cause or usage: %q", got)
	}
}

func TestLauncherErrorRendererDoesNotDuplicateCobraOrVendorExit(t *testing.T) {
	budgetErr := budgetLaunchRefusal("opencode", "this invocation's final model route is direct or cannot be verified")
	root, child, output := executeLauncherError(t, false, budgetErr)
	before := output.String()
	if !strings.Contains(before, budgetErr.Error()) {
		t.Fatalf("Cobra did not render ordinary error: %q", before)
	}
	if renderSuppressedLauncherError(output, root, child, budgetErr) {
		t.Fatal("renderer duplicated an error Cobra already displayed")
	}
	if got := output.String(); got != before || strings.Count(got, budgetErr.Error()) != 1 {
		t.Fatalf("ordinary error count changed: %q", got)
	}

	root, child, output = executeLauncherError(t, true, exitErr(17))
	if renderSuppressedLauncherError(output, root, child, exitErr(17)) || output.Len() != 0 {
		t.Fatalf("vendor exit code produced launcher text: %q", output.String())
	}
}

func TestBudgetLaunchRefusalCarriesExactSafeTerminalMessage(t *testing.T) {
	err := budgetLaunchRefusal("muse", "this tool has no verified Observer budget-admission route")
	if !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("refusal lost sentinel: %v", err)
	}
	root, child, output := executeLauncherError(t, true, err)
	if !renderSuppressedLauncherError(output, root, child, err) {
		t.Fatal("budget refusal was not rendered")
	}
	if got := output.String(); got != err.Error()+"\n" || strings.Count(got, "managed hard budget") != 1 {
		t.Fatalf("budget refusal output = %q", got)
	}
}

func TestManagedLauncherCommandsRenderRefusalWithoutStartingVendor(t *testing.T) {
	originalRuntimeDir := agentRuntimeDir
	originalLoginPathDirs := daemonLoginPathDirs
	agentRuntimeDir = func() string { return "" }
	daemonLoginPathDirs = func() []string { return nil }
	t.Cleanup(func() {
		agentRuntimeDir = originalRuntimeDir
		daemonLoginPathDirs = originalLoginPathDirs
	})

	cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
	marker := filepath.Join(t.TempDir(), "vendor-started")
	stub := filepath.Join(t.TempDir(), "vendor-stub")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ntouch \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		cmd  func() *cobra.Command
		args []string
	}{
		{
			name: "muse",
			cmd:  newMuseCmd,
			args: []string{"--config", cfgPath, "--muse-path", stub, "--no-attach", "--", marker},
		},
		{
			name: "opencode",
			cmd:  newOpencodeCmd,
			args: []string{"--config", cfgPath, "--opencode-path", stub, "--no-attach", "--proxy", "http://127.0.0.1:1", "--", marker},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := new(bytes.Buffer)
			root := &cobra.Command{Use: "observer", SilenceUsage: true}
			child := tc.cmd()
			root.AddCommand(child)
			root.SetArgs(append([]string{tc.name}, tc.args...))
			root.SetOut(output)
			root.SetErr(output)

			executed, err := root.ExecuteC()
			if !errors.Is(err, errBudgetLaunchUncontrolled) {
				t.Fatalf("ExecuteC error = %v, want managed-budget refusal", err)
			}
			if executed != child {
				t.Fatalf("executed command = %v, want %s", executed, tc.name)
			}
			if !renderSuppressedLauncherError(output, root, executed, err) {
				t.Fatal("managed-budget refusal was not rendered")
			}
			if got := output.String(); strings.Count(got, err.Error()) != 1 || strings.Contains(got, "Usage:") {
				t.Fatalf("terminal output did not contain one refusal: %q", got)
			}
			if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("vendor stub started: %v", statErr)
			}
		})
	}
}

// TestManagedLauncherRendersSpendRefusalWithoutStartingVendor is the
// exhausted-cap sibling of the test above, and the thing the launch boundary
// exists to do: a covered, correctly-routed launch over the org's cap is
// refused HERE, the developer is told which rule and who to ask, and the
// vendor process never starts (it used to start and be killed a reconcile
// cycle later with nothing said at the terminal).
func TestManagedLauncherRendersSpendRefusalWithoutStartingVendor(t *testing.T) {
	originalRuntimeDir := agentRuntimeDir
	originalLoginPathDirs := daemonLoginPathDirs
	agentRuntimeDir = func() string { return "" }
	daemonLoginPathDirs = func() []string { return nil }
	t.Cleanup(func() {
		agentRuntimeDir = originalRuntimeDir
		daemonLoginPathDirs = originalLoginPathDirs
	})

	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	exhaustManagedBudgetLaunchBudget(t, dbPath, "opencode")
	marker := filepath.Join(t.TempDir(), "vendor-started")
	stub := filepath.Join(t.TempDir(), "vendor-stub")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ntouch \"$1\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	output := new(bytes.Buffer)
	root := &cobra.Command{Use: "observer", SilenceUsage: true}
	child := newOpencodeCmd()
	root.AddCommand(child)
	// The proxy URL matches the configured one, so COVERAGE passes and the
	// refusal under test can only come from spend.
	root.SetArgs([]string{
		"opencode", "--config", cfgPath, "--opencode-path", stub, "--no-attach",
		"--proxy", "http://127.0.0.1:8820", "--", marker,
	})
	root.SetOut(output)
	root.SetErr(output)

	executed, err := root.ExecuteC()
	if !errors.Is(err, errBudgetLaunchDenied) {
		t.Fatalf("ExecuteC error = %v, want an exhausted-budget refusal", err)
	}
	if !renderSuppressedLauncherError(output, root, executed, err) {
		t.Fatal("spend refusal was not rendered")
	}
	got := output.String()
	for _, want := range []string{"B-623", "organization budget", "contact your org admin"} {
		if !strings.Contains(got, want) {
			t.Fatalf("terminal output %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "Usage:") {
		t.Fatalf("refusal printed usage: %q", got)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("vendor stub started over an exhausted cap: %v", statErr)
	}
}

func executeLauncherError(t *testing.T, silence bool, returned error) (*cobra.Command, *cobra.Command, *bytes.Buffer) {
	t.Helper()
	output := new(bytes.Buffer)
	root := &cobra.Command{Use: "observer", SilenceUsage: true}
	child := &cobra.Command{
		Use:           "tool",
		SilenceErrors: silence,
		RunE:          func(*cobra.Command, []string) error { return returned },
	}
	root.AddCommand(child)
	root.SetArgs([]string{"tool"})
	root.SetOut(output)
	root.SetErr(output)
	executed, err := root.ExecuteC()
	if !errors.Is(err, returned) {
		t.Fatalf("ExecuteC error = %v, want %v", err, returned)
	}
	if executed != child {
		t.Fatalf("executed command = %v, want child", executed)
	}
	return root, child, output
}
