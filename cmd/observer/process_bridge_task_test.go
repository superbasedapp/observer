//go:build !sbo_omit_processobs

package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/processbridge/setup"
)

// Nothing in this file executes a real schtasks.exe. Every probe goes through
// the setup.Env seam, so these tests are identical on CI (no
// Windows, no Task Scheduler) and on the WSL reference host — and they can
// never create, change or delete an operator's real Scheduled Task.

// fakeTaskEnv builds a setup.Env whose every side effect is
// recorded, plus counters proving which probes were reached.
type fakeTaskEnv struct {
	env           setup.Env
	schtasksCalls [][]string
	observerCalls int
	userCalls     int
}

// newFakeTaskEnv returns an env where schtasks.exe resolves, /Query answers
// with (out, err), and the Windows binary resolves to a /mnt path.
func newFakeTaskEnv(queryOut string, queryErr error) *fakeTaskEnv {
	f := &fakeTaskEnv{}
	f.env = setup.Env{
		LookPath: func(string) (string, error) { return `/mnt/c/Windows/system32/schtasks.exe`, nil },
		RunSchtasks: func(_ context.Context, exe string, args ...string) (string, error) {
			f.schtasksCalls = append(f.schtasksCalls, append([]string{exe}, args...))
			return queryOut, queryErr
		},
		ResolveObserver: func(string) (string, bool) {
			f.observerCalls++
			return "/mnt/c/Users/auzy_/bin/observer.exe", true
		},
		Distro:      "Ubuntu-20.04",
		WindowsUser: func() string { f.userCalls++; return "auzy_" },
	}
	return f
}

// etwConfig is a ProcessConfig with the ETW listener block set. It switches
// BOTH gates together — the master [observer.process].enabled and
// [observer.process.etw].enabled — because "the feed is on" is their
// conjunction: with the master off, runProcessObserver returns before the
// accept listener is ever constructed. The one-off-each combination is covered
// by setup.TestResolveInputsRequiresBothSwitches and by
// TestPrintPlanNamesTheMasterSwitch below.
func etwConfig(enabled bool) config.ProcessConfig {
	return config.ProcessConfig{
		Enabled: enabled,
		ETW: config.ProcessETWConfig{
			Enabled:    enabled,
			ListenAddr: "127.0.0.1:8823",
		},
	}
}

// TestPrintPlanNamesTheMasterSwitch: a config that READS as enabled but cannot
// capture — [observer.process.etw] on, [observer.process] off — must not be
// silent. It is the one skip that carries a reason, for the same cause
// selectProcessBackend warns about a bare `backend = "etw"`.
func TestPrintPlanNamesTheMasterSwitch(t *testing.T) {
	ctx := context.Background()
	f := newFakeTaskEnv(schtasksNotFound, errors.New("exit 1"))
	cfg := etwConfig(true)
	cfg.Enabled = false

	in := setup.ResolveInputs(ctx, cfg, "/home/u/.observer", f.env)
	plan := setup.PlanTask(in)
	if plan.Outcome != setup.OutcomeSkip {
		t.Fatalf("Outcome = %v, want skip (the card offers the toggle for this state)", plan.Outcome)
	}
	var buf bytes.Buffer
	printProcessBridgeTaskPlan(&buf, plan)
	out := buf.String()
	if !strings.Contains(out, "[observer.process].enabled") {
		t.Fatalf("the message must name the master switch: %q", out)
	}
	if strings.Contains(out, "/Create") {
		t.Fatalf("no command may be emitted for a feed that cannot run: %q", out)
	}
}

const schtasksNotFound = "ERROR: The system cannot find the file specified."

// TestResolveProcessBridgeTaskInputs covers the I/O layer's short-circuits:
// which probes run, and — just as important — which do NOT.
func TestResolveProcessBridgeTaskInputs(t *testing.T) {
	// The task is planned by a WSL (Linux) daemon for the Windows capturer;
	// the fixture is that daemon's POSIX observer dir (Windows 11 Pro rerun
	// 2026-10-25, D5 group 8).
	skipDriverOffHost(t, "the process bridge task planner (a WSL daemon)")
	ctx := context.Background()

	t.Run("disabled etw probes nothing", func(t *testing.T) {
		f := newFakeTaskEnv(schtasksNotFound, errors.New("exit 1"))
		in := setup.ResolveInputs(ctx, etwConfig(false), "/home/u/.observer", f.env)
		if len(f.schtasksCalls) != 0 || f.observerCalls != 0 || f.userCalls != 0 {
			t.Fatalf("disabled ETW must probe nothing: schtasks=%v observer=%d user=%d",
				f.schtasksCalls, f.observerCalls, f.userCalls)
		}
		if plan := setup.PlanTask(in); plan.Outcome != setup.OutcomeSkip {
			t.Fatalf("Outcome = %v, want skip", plan.Outcome)
		}
	})

	t.Run("no schtasks.exe skips silently and never probes", func(t *testing.T) {
		f := newFakeTaskEnv(schtasksNotFound, errors.New("exit 1"))
		f.env.LookPath = func(string) (string, error) { return "", errors.New("executable file not found in $PATH") }
		in := setup.ResolveInputs(ctx, etwConfig(true), "/home/u/.observer", f.env)
		if len(f.schtasksCalls) != 0 {
			t.Fatalf("a host without schtasks.exe must not exec anything: %v", f.schtasksCalls)
		}
		plan := setup.PlanTask(in)
		if plan.Outcome != setup.OutcomeSkip {
			t.Fatalf("Outcome = %v, want skip", plan.Outcome)
		}
		var buf bytes.Buffer
		printProcessBridgeTaskPlan(&buf, plan)
		if buf.Len() != 0 {
			t.Fatalf("skip must print NOTHING, got %q", buf.String())
		}
	})

	t.Run("existing task short-circuits every other probe", func(t *testing.T) {
		f := newFakeTaskEnv("TaskName: SuperBasedObserverETW", nil)
		in := setup.ResolveInputs(ctx, etwConfig(true), "/home/u/.observer", f.env)
		if len(f.schtasksCalls) != 1 {
			t.Fatalf("want exactly one schtasks call, got %v", f.schtasksCalls)
		}
		got := f.schtasksCalls[0]
		if got[1] != "/Query" || got[2] != "/TN" || got[3] != setup.TaskName {
			t.Fatalf("probe must be a read-only /Query for the frozen name, got %v", got)
		}
		if f.observerCalls != 0 || f.userCalls != 0 {
			t.Fatalf("an existing task must not resolve binary/user: observer=%d user=%d", f.observerCalls, f.userCalls)
		}
		plan := setup.PlanTask(in)
		if plan.Outcome != setup.OutcomePresent {
			t.Fatalf("Outcome = %v, want present", plan.Outcome)
		}
		var buf bytes.Buffer
		printProcessBridgeTaskPlan(&buf, plan)
		out := buf.String()
		if !strings.Contains(out, "already registered") {
			t.Fatalf("present output must say so: %q", out)
		}
		if strings.Contains(out, "/Create") {
			t.Fatalf("an existing task must NOT re-emit the create command: %q", out)
		}
	})

	t.Run("absent task resolves everything the command needs", func(t *testing.T) {
		f := newFakeTaskEnv(schtasksNotFound, errors.New("exit status 1"))
		in := setup.ResolveInputs(ctx, etwConfig(true), "/home/u/.observer", f.env)
		if in.Probe != setup.ProbeAbsent {
			t.Fatalf("Probe = %v, want absent", in.Probe)
		}
		if f.observerCalls != 1 || f.userCalls != 1 {
			t.Fatalf("absent task must resolve binary+user once each: observer=%d user=%d", f.observerCalls, f.userCalls)
		}
		if in.TokenPath != filepath.Join("/home/u/.observer", "process-bridge-token") {
			t.Fatalf("TokenPath = %q, want the daemon's generated token path", in.TokenPath)
		}
		plan := setup.PlanTask(in)
		if plan.Outcome != setup.OutcomeManual {
			t.Fatalf("Outcome = %v, want manual", plan.Outcome)
		}
	})
}

// TestPrintProcessBridgeTaskPlanHonesty is the honesty gate: the emitted text
// must never claim a registration happened, must say WHY the operator has to
// run it, and must name the exact blocker when blocked.
func TestPrintProcessBridgeTaskPlanHonesty(t *testing.T) {
	manual := setup.PlanTask(setup.Inputs{
		Enabled: true, SchtasksPath: "schtasks.exe", Probe: setup.ProbeAbsent,
		WindowsObserver: "/mnt/c/o/observer.exe", ListenAddr: "127.0.0.1:8823",
		TokenPath: "/home/u/.observer/process-bridge-token", Distro: "Ubuntu-20.04", WindowsUser: "auzy_",
	})
	var buf bytes.Buffer
	printProcessBridgeTaskPlan(&buf, manual)
	out := buf.String()

	for _, want := range []string{
		"is not registered",
		"observer cannot create it",
		"elevation",
		"ELEVATED",
		"schtasks.exe /Create",
		"verify:",
		"remove:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manual output missing %q:\n%s", want, out)
		}
	}
	for _, banned := range []string{"registered the task", "task registered", "successfully"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Errorf("manual output claims success it cannot verify (%q):\n%s", banned, out)
		}
	}

	blocked := setup.PlanTask(setup.Inputs{
		Enabled: true, SchtasksPath: "schtasks.exe", Probe: setup.ProbeAbsent,
		ListenAddr: "127.0.0.1:8823", TokenPath: "/home/u/.observer/tok", Distro: "Ubuntu-20.04",
	})
	buf.Reset()
	printProcessBridgeTaskPlan(&buf, blocked)
	if out := buf.String(); !strings.Contains(out, "windows_binary_path") || strings.Contains(out, "/Create") {
		t.Errorf("blocked output must name the missing dependency and emit no command:\n%s", out)
	}
}

// TestProcessBridgeTaskNotesNeverPrintTheToken is the secrecy gate.
//
// The notes tell the operator to CHECK the shared-token file, and that check
// must not DISCLOSE it: this product captures shell-output excerpts from
// observed shells into its own DB, and there is deliberately no --token flag
// for exactly the same reason (argv is world-readable). A readability check
// that prints the file's contents would reintroduce the leak the whole design
// avoids. Whatever check we emit must also survive BOTH shells the /Create
// line promises — `dir` is a cmd.exe builtin and a PowerShell alias for
// Get-ChildItem; `type` prints the secret in cmd.exe and `Get-Content`/`cat`
// print it in PowerShell.
func TestProcessBridgeTaskNotesNeverPrintTheToken(t *testing.T) {
	const tokenPath = `\\wsl.localhost\Ubuntu-20.04\home\u\.observer\process-bridge-token`
	notes := strings.Join(setup.TaskNotes(tokenPath, "auzy_"), "\n")

	// The check must exist and must be the listing form, in both shells.
	if !strings.Contains(notes, `dir "`+tokenPath+`"`) {
		t.Fatalf("notes must offer a non-disclosing `dir` reachability check:\n%s", notes)
	}
	for _, banned := range []string{
		"type \"", "type '", "Get-Content", "gc ", "cat ", "more <", "more \"",
		"certutil", "-hashfile", "$(", "echo %",
	} {
		if strings.Contains(notes, banned) {
			t.Errorf("notes contain %q - a command that prints (or digests) the token's CONTENTS:\n%s", banned, notes)
		}
	}

	// And the same gate through the real printer, which is what the operator
	// actually sees.
	var buf bytes.Buffer
	printProcessBridgeTaskPlan(&buf, setup.PlanTask(setup.Inputs{
		Enabled: true, SchtasksPath: "schtasks.exe", Probe: setup.ProbeAbsent,
		WindowsObserver: "/mnt/c/o/observer.exe", ListenAddr: "127.0.0.1:8823",
		TokenPath: "/home/u/.observer/process-bridge-token", Distro: "Ubuntu-20.04", WindowsUser: "auzy_",
	}))
	out := buf.String()
	for _, banned := range []string{"type \"", "Get-Content", "cat "} {
		if strings.Contains(out, banned) {
			t.Errorf("printed output tells the operator to print the token (%q):\n%s", banned, out)
		}
	}
	if !strings.Contains(out, "never prints the token") {
		t.Errorf("the check must say WHY it does not print the token:\n%s", out)
	}
}

// TestProcessBridgeTaskProbeZeroValueIsUnknown pins the tri-state's zero
// value. Absent is the state that makes the step emit a `/Create` command, so
// it must never be what a forgotten assignment defaults to.
func TestProcessBridgeTaskProbeZeroValueIsUnknown(t *testing.T) {
	// Errorf, not Fatalf: the CONSEQUENCE assertions below (no unhedged create
	// command from an unset probe) are the ones that matter operationally, and
	// they must still run — and still fail — when the ordering regresses.
	var zero setup.Probe
	if zero != setup.ProbeUnknown {
		t.Errorf("the zero value of setup.Probe is %v, want Unknown - "+
			"a forgotten assignment must not read as 'the task does not exist'", zero)
	}
	if setup.ProbeAbsent == 0 || setup.ProbePresent == 0 {
		t.Error("neither Absent nor Present may be the zero value")
	}

	// A wholly zero-valued input must be a silent skip, never a create command.
	plan := setup.PlanTask(setup.Inputs{})
	if plan.Outcome != setup.OutcomeSkip || plan.Command != "" {
		t.Fatalf("a zero-valued input must be a silent skip with no command, got %+v", plan)
	}
	var buf bytes.Buffer
	printProcessBridgeTaskPlan(&buf, plan)
	if strings.Contains(buf.String(), "/Create") {
		t.Fatalf("a zero-valued input must not print a create command:\n%s", buf.String())
	}

	// And with the gates open but the probe left unset, the outcome is the
	// hedged Unknown ("run it if the task is absent"), not a flat Absent.
	plan = setup.PlanTask(setup.Inputs{
		Enabled: true, SchtasksPath: "schtasks.exe",
		WindowsObserver: "/mnt/c/o/observer.exe", ListenAddr: "127.0.0.1:8823",
		TokenPath: "/home/u/.observer/process-bridge-token", Distro: "Ubuntu-20.04",
	})
	if plan.Outcome != setup.OutcomeUnknown {
		t.Fatalf("an unset probe must plan as Unknown, got %v", plan.Outcome)
	}
}

// TestPlanProcessBridgeTaskUnresolvedBinaryAdvice proves the two ways a
// Windows observer.exe can be missing give DIFFERENT advice: telling an
// operator to set the exact key they already set is a dead end, so the
// configured-but-missing message names the path it tried.
func TestPlanProcessBridgeTaskUnresolvedBinaryAdvice(t *testing.T) {
	base := setup.Inputs{
		Enabled: true, SchtasksPath: "schtasks.exe", Probe: setup.ProbeAbsent,
		ListenAddr: "127.0.0.1:8823", TokenPath: "/home/u/.observer/process-bridge-token",
		Distro: "Ubuntu-20.04",
	}

	unset := setup.PlanTask(base)
	configured := base
	configured.WindowsObserverHint = "/mnt/c/nope/observer.exe"
	configured.WindowsObserverHintSource = "[observer.process].windows_binary_path"
	missing := setup.PlanTask(configured)

	if unset.Outcome != setup.OutcomeBlocked || missing.Outcome != setup.OutcomeBlocked {
		t.Fatalf("both must block: unset=%v missing=%v", unset.Outcome, missing.Outcome)
	}
	if unset.Reason == missing.Reason {
		t.Fatalf("not-configured and configured-but-missing must NOT give the same advice: %q", unset.Reason)
	}
	if !strings.Contains(missing.Reason, "/mnt/c/nope/observer.exe") {
		t.Errorf("the configured-but-missing reason must NAME the path it tried: %q", missing.Reason)
	}
	if !strings.Contains(missing.Reason, "does not exist") {
		t.Errorf("the configured-but-missing reason must say the path does not exist: %q", missing.Reason)
	}
	if strings.Contains(missing.Reason, "empty path") {
		t.Errorf("a configured path must never be reported as empty: %q", missing.Reason)
	}
	if !strings.Contains(unset.Reason, "no Windows observer.exe is configured") {
		t.Errorf("the not-configured reason must say nothing is configured: %q", unset.Reason)
	}

	// The env var is the second knob, and it must be named when it is the one
	// that was set.
	viaEnv := base
	viaEnv.WindowsObserverHint = "/mnt/c/env/observer.exe"
	viaEnv.WindowsObserverHintSource = "$OBSERVER_WINDOWS_BINARY"
	if r := setup.PlanTask(viaEnv).Reason; !strings.Contains(r, "$OBSERVER_WINDOWS_BINARY") ||
		!strings.Contains(r, "/mnt/c/env/observer.exe") {
		t.Errorf("an env-configured path must name the env var and the path: %q", r)
	}

	// Both must reach the operator through the printer, with no half-resolved
	// command attached.
	for _, plan := range []setup.Plan{unset, missing} {
		var buf bytes.Buffer
		printProcessBridgeTaskPlan(&buf, plan)
		if out := buf.String(); !strings.Contains(out, plan.Reason) || strings.Contains(out, "/Create") {
			t.Errorf("blocked output must carry the reason and no command:\n%s", out)
		}
	}
}

// TestPrintProcessBridgeTaskPlanNamesTheShell proves the printed guidance
// tracks the quoting: portable commands say "either", the escaped variant
// names Command Prompt and rules PowerShell out.
func TestPrintProcessBridgeTaskPlanNamesTheShell(t *testing.T) {
	base := setup.Inputs{
		Enabled: true, SchtasksPath: "schtasks.exe", Probe: setup.ProbeAbsent,
		WindowsObserver: "/mnt/c/o/observer.exe", ListenAddr: "127.0.0.1:8823",
		TokenPath: "/home/u/.observer/process-bridge-token", Distro: "Ubuntu-20.04",
	}
	var buf bytes.Buffer
	printProcessBridgeTaskPlan(&buf, setup.PlanTask(base))
	if out := buf.String(); !strings.Contains(out, "Command Prompt or PowerShell") {
		t.Errorf("a portable command must say both shells work:\n%s", out)
	}

	spaced := base
	spaced.TokenPath = "/mnt/c/Users/John Doe/.observer/process-bridge-token"
	buf.Reset()
	printProcessBridgeTaskPlan(&buf, setup.PlanTask(spaced))
	if out := buf.String(); !strings.Contains(out, "not PowerShell") {
		t.Errorf("the escaped variant must name the shell it needs:\n%s", out)
	}
}
