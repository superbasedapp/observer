//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

// sandbox_setup_cmd.go is `observer sandbox setup` (sandbox installation
// lifecycle plan section 3.6, lane sbxinstall-cli): the CLI face of the same
// dashapi.SandboxSetup seam the dashboard's setup routes call, built
// in-process with Surface "cli" and a foreground runner, so a terminal or
// elevated step runs as a child on the person's own terminal. The verb comes
// before the backend so the guard's word-path table can match
// `sandbox setup run` and the rest without reading a positional.
//
// Every step is the person's own answer: `run` asks y/N before EACH step,
// never one consent for all, and --yes answers that prompt only, never an
// elevated step's password (sudo or UAC asks on its own). Guide steps print
// the command to copy and never-steps print the words and the docs anchor;
// neither runs anything. The `observer doctor` rows of this file
// (sandboxSetupDoctorChecks) read the passive plan only.

// The exit codes of `observer sandbox setup` (documented in its Long text).
const (
	sandboxSetupExitOK      = 0
	sandboxSetupExitFailed  = 1
	sandboxSetupExitUsage   = 2
	sandboxSetupExitBlocked = 3
	sandboxSetupExitRefused = 4
)

// sandboxSetupMaxReplans bounds how often one step is asked again after a
// plan_changed answer.
const sandboxSetupMaxReplans = 3

// sandboxSetupOpPoll is how often an in-process operation is polled.
const sandboxSetupOpPoll = 250 * time.Millisecond

// sandboxSetupSpawnFunc is sandboxSetupOptions.Spawn's shape.
type sandboxSetupSpawnFunc = func(ctx context.Context, argv []string, label string) (handle string, exitCode int, err error)

// sandboxSetupStdio is the terminal a foreground step inherits.
type sandboxSetupStdio struct {
	In       io.Reader
	Out, Err io.Writer
}

// sandboxSetupCmdDeps are the command's injected seams (tests replace them).
type sandboxSetupCmdDeps struct {
	// open builds the seam with spawn as its foreground runner. The returned
	// func releases what open acquired.
	open func(ctx context.Context, cfgPath string, spawn sandboxSetupSpawnFunc) (dashapi.SandboxSetup, func(), error)
	// foreground runs one argv as a child on the person's terminal and
	// returns its exit code.
	foreground func(ctx context.Context, argv []string, stdio sandboxSetupStdio) (int, error)
	// isTTY reports whether in is an interactive terminal.
	isTTY func(in io.Reader) bool
	// sleep waits between op polls (ctx aware).
	sleep func(ctx context.Context, d time.Duration) error
}

// defaultSandboxSetupCmdDeps are the production seams.
func defaultSandboxSetupCmdDeps() sandboxSetupCmdDeps {
	return sandboxSetupCmdDeps{
		open:       sandboxSetupOpenDefault,
		foreground: sandboxSetupForeground,
		isTTY:      sandboxSetupIsTTY,
		sleep:      sandboxSetupSleep,
	}
}

// sandboxSetupLong is the setup command's help, including the exit codes.
const sandboxSetupLong = `Set up, check, update, repair and undo what a sandbox backend needs on this
machine: the same steps as the New Terminal dialog's setup panel and
Settings > Terminals > Sandbox isolation.

  status [<backend>]      every offered backend on this host (ready, blocked,
                          or the next step), or one backend's plan
  check <backend>         run the active check of this machine (the backend's
                          own probe, once), then show the plan
  run <backend>           walk the plan's steps in order, asking before EACH
                          step; --step runs one step
  undo|update|repair <backend> --step <id>
                          act on one step Observer did
  records                 the sandbox setup records

A terminal or elevated step runs as a child on this terminal, in your home
directory. An elevated step asks for your password itself (sudo, or the
Windows UAC prompt); --yes answers Observer's per-step question only, never a
password. Without a terminal on stdin the run, undo, update and repair verbs
refuse unless --yes is given. A guide step prints the command for you to run;
a step Observer must never touch prints what to do and where the docs are.

Exit codes:
  0  done, or nothing to do
  1  a step failed (or could not be done now)
  2  usage (an unknown backend or step, a missing --step, no terminal and no --yes)
  3  blocked on this host (the backend cannot run here, or setup is not in this build)
  4  refused by a switch or the organization ([terminal.launch].allow_install,
     [terminal.sandbox.setup].allow_elevated, allowed backends, live sandboxed runs)`

// newSandboxSetupCmd is `observer sandbox setup` with the production seams.
func newSandboxSetupCmd() *cobra.Command {
	return newSandboxSetupCmdWith(defaultSandboxSetupCmdDeps())
}

// newSandboxSetupCmdWith builds the command tree over deps.
func newSandboxSetupCmdWith(deps sandboxSetupCmdDeps) *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up what a sandbox backend needs on this machine, one step at a time",
		Long:  sandboxSetupLong,
	}
	cmd.PersistentFlags().StringVar(&cfgPath, "config", "", "config file (default ~/.observer/config.toml)")
	// A flag error is a usage error (exit 2), said once.
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		fmt.Fprintf(c.ErrOrStderr(), "observer sandbox setup: %v\n", err)
		return exitErr(sandboxSetupExitUsage)
	})
	cfg := func() string { return cfgPath }
	cmd.AddCommand(
		sandboxSetupStatusCmd(deps, cfg),
		sandboxSetupCheckCmd(deps, cfg),
		sandboxSetupRunCmd(deps, cfg),
		sandboxSetupActionCmd(deps, cfg, dashapi.SandboxSetupActionUndo, "Undo one step Observer did (only what Observer did; a shared prerequisite another set-up backend uses stays)"),
		sandboxSetupActionCmd(deps, cfg, dashapi.SandboxSetupActionUpdate, "Update one step to the version this Observer pins"),
		sandboxSetupActionCmd(deps, cfg, dashapi.SandboxSetupActionRepair, "Repair one step whose check now fails (run it again)"),
		sandboxSetupRecordsCmd(deps, cfg),
	)
	return cmd
}

// sandboxSetupSub fills what every setup verb shares: Cobra prints nothing
// on its own (the verb said it and returns an exitErr) and a usage line is
// not dumped on a failed step.
func sandboxSetupSub(c *cobra.Command) *cobra.Command {
	c.SilenceErrors = true
	c.SilenceUsage = true
	c.Long = c.Short + "\n\n" + sandboxSetupExitCodesHelp
	return c
}

// sandboxSetupExitCodesHelp is the exit-code block every verb's help repeats.
const sandboxSetupExitCodesHelp = `Exit codes: 0 done or nothing to do, 1 a step failed, 2 usage,
3 blocked on this host, 4 refused by a switch or the organization.
See observer sandbox setup --help.`

// sandboxSetupFail prints msg on stderr and returns exitErr(code) (nil for
// code 0).
func sandboxSetupFail(c *cobra.Command, code int, format string, args ...any) error {
	fmt.Fprintf(c.ErrOrStderr(), "observer sandbox setup: "+format+"\n", args...)
	return sandboxSetupExit(code)
}

// sandboxSetupExit is exitErr(code), nil for 0.
func sandboxSetupExit(code int) error {
	if code == sandboxSetupExitOK {
		return nil
	}
	return exitErr(code)
}

// sandboxSetupArgs is an Args validator answering a usage error (exit 2).
func sandboxSetupArgs(min, max int, what string) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error {
		if len(args) < min || len(args) > max {
			return sandboxSetupFail(c, sandboxSetupExitUsage, "usage: observer sandbox setup %s %s", c.Name(), what)
		}
		return nil
	}
}

// sandboxSetupValidBackend checks id against the registry's offered rows
// (a usage error names them).
func sandboxSetupValidBackend(c *cobra.Command, id string) error {
	if row, ok := sandboxbackend.Get(id); ok && row.Offered() {
		return nil
	}
	var ids []string
	for _, row := range sandboxbackend.Offered() {
		ids = append(ids, row.ID)
	}
	return sandboxSetupFail(c, sandboxSetupExitUsage, "no backend %q (backends: %s)", id, strings.Join(ids, ", "))
}

// sandboxSetupSession is one verb's run: the seam, the terminal and the
// answers given so far.
type sandboxSetupSession struct {
	c     *cobra.Command
	s     dashapi.SandboxSetup
	deps  sandboxSetupCmdDeps
	out   io.Writer
	errw  io.Writer
	in    *bufio.Reader
	tty   bool
	yes   bool
	spawn *sandboxSetupSpawnRecord
}

// sandboxSetupSpawnRecord is what the foreground runner saw during one Run
// call (the seam's answer carries no exit code for a foreground step).
type sandboxSetupSpawnRecord struct {
	spawned bool
	exit    int
}

// openSession builds the seam and the session. The returned error is
// already an exit error for the command.
func openSandboxSetupSession(c *cobra.Command, deps sandboxSetupCmdDeps, cfgPath string, yes bool) (*sandboxSetupSession, func(), error) {
	ss := &sandboxSetupSession{
		c: c, deps: deps, out: c.OutOrStdout(), errw: c.ErrOrStderr(),
		in: bufio.NewReader(c.InOrStdin()), tty: deps.isTTY(c.InOrStdin()), yes: yes,
		spawn: &sandboxSetupSpawnRecord{},
	}
	stdio := sandboxSetupStdio{In: c.InOrStdin(), Out: c.OutOrStdout(), Err: c.ErrOrStderr()}
	spawn := func(ctx context.Context, argv []string, label string) (string, int, error) {
		if label != "" {
			fmt.Fprintf(ss.errw, "%s\n", label)
		}
		fmt.Fprintf(ss.errw, "Running: %s\n", sandboxSetupShellJoin(argv))
		code, err := deps.foreground(ctx, argv, stdio)
		ss.spawn.spawned = true
		ss.spawn.exit = code
		if err != nil {
			return "", -1, fmt.Errorf("sandbox setup: run %s: %w", label, err)
		}
		return "", code, nil
	}
	s, release, err := deps.open(c.Context(), cfgPath, spawn)
	if release == nil {
		release = func() {}
	}
	if err == nil && s == nil {
		err = dashapi.ErrSandboxSetupNotInBuild
	}
	if err != nil {
		release()
		code := sandboxSetupExitFailed
		if errors.Is(err, dashapi.ErrSandboxSetupNotInBuild) {
			code = sandboxSetupExitBlocked
		}
		return nil, func() {}, sandboxSetupFail(c, code, "%v", err)
	}
	ss.s = s
	return ss, release, nil
}

// seamFail turns a seam error into the command's exit.
func (ss *sandboxSetupSession) seamFail(what string, err error) error {
	code := sandboxSetupErrCode(err)
	return sandboxSetupFail(ss.c, sandboxSetupExitForCode(code), "%s: %v", what, err)
}

func sandboxSetupStatusCmd(deps sandboxSetupCmdDeps, cfg func() string) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "status [<backend>]",
		Short: "Show every offered backend on this host (ready, blocked, or the next step), or one backend's plan",
		Args:  sandboxSetupArgs(0, 1, "[<backend>] [--json]"),
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 1 {
				if err := sandboxSetupValidBackend(c, args[0]); err != nil {
					return err
				}
			}
			ss, release, err := openSandboxSetupSession(c, deps, cfg(), false)
			if err != nil {
				return err
			}
			defer release()
			ctx := c.Context()
			if len(args) == 0 {
				sums, err := ss.s.Summary(ctx)
				if err != nil {
					return ss.seamFail("status", err)
				}
				if asJSON {
					return sandboxSetupJSON(ss.out, map[string]any{"backends": sandboxSetupNonNil(sums)})
				}
				return renderSandboxSetupSummaries(ss.out, sums)
			}
			plan, err := ss.s.Plan(ctx, args[0])
			if err != nil {
				return ss.seamFail("status "+args[0], err)
			}
			if asJSON {
				return sandboxSetupJSON(ss.out, plan)
			}
			return renderSandboxSetupPlan(ss.out, plan)
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print JSON (the dashboard's wire shape)")
	return sandboxSetupSub(c)
}

func sandboxSetupCheckCmd(deps sandboxSetupCmdDeps, cfg func() string) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "check <backend>",
		Short: "Run the active check of this machine for one backend (its own probe, once), then show the plan",
		Args:  sandboxSetupArgs(1, 1, "<backend> [--json]"),
		RunE: func(c *cobra.Command, args []string) error {
			if err := sandboxSetupValidBackend(c, args[0]); err != nil {
				return err
			}
			ss, release, err := openSandboxSetupSession(c, deps, cfg(), false)
			if err != nil {
				return err
			}
			defer release()
			plan, err := ss.s.Check(c.Context(), args[0])
			if err != nil {
				return ss.seamFail("check "+args[0], err)
			}
			if asJSON {
				return sandboxSetupJSON(ss.out, plan)
			}
			return renderSandboxSetupPlan(ss.out, plan)
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print JSON (the dashboard's wire shape)")
	return sandboxSetupSub(c)
}

func sandboxSetupRunCmd(deps sandboxSetupCmdDeps, cfg func() string) *cobra.Command {
	var (
		step     string
		yes      bool
		fromFile string
	)
	c := &cobra.Command{
		Use:   "run <backend>",
		Short: "Walk a backend's setup steps in order, asking before each one (or run one step with --step)",
		Args:  sandboxSetupArgs(1, 1, "<backend> [--step <id>] [--yes] [--from-file <path>]"),
		RunE: func(c *cobra.Command, args []string) error {
			backend := args[0]
			if err := sandboxSetupValidBackend(c, backend); err != nil {
				return err
			}
			if fromFile != "" {
				abs, err := filepath.Abs(fromFile)
				if err != nil {
					return sandboxSetupFail(c, sandboxSetupExitUsage, "--from-file %q: %v", fromFile, err)
				}
				fromFile = abs
			}
			ss, release, err := openSandboxSetupSession(c, deps, cfg(), yes)
			if err != nil {
				return err
			}
			defer release()
			if step != "" {
				return sandboxSetupExit(ss.runOne(backend, step, dashapi.SandboxSetupActionRun, fromFile))
			}
			return sandboxSetupExit(ss.walk(backend, fromFile))
		},
	}
	c.Flags().StringVar(&step, "step", "", "run this one step (a prerequisite id from `observer sandbox setup status <backend>`)")
	c.Flags().BoolVar(&yes, "yes", false, "answer yes to each step's question (never to a password prompt)")
	c.Flags().StringVar(&fromFile, "from-file", "", "a download step: use this file already on the machine (checked against the pinned sha256 and size); a hosted consent step: the folder the consent is for (default: the Observer default workspace, when it is set up)")
	return sandboxSetupSub(c)
}

// sandboxSetupActionCmd is undo, update or repair: one named step.
func sandboxSetupActionCmd(deps sandboxSetupCmdDeps, cfg func() string, action, short string) *cobra.Command {
	var (
		step string
		yes  bool
	)
	c := &cobra.Command{
		Use:   action + " <backend> --step <id>",
		Short: short,
		Args:  sandboxSetupArgs(1, 1, "<backend> --step <id> [--yes]"),
		RunE: func(c *cobra.Command, args []string) error {
			backend := args[0]
			if err := sandboxSetupValidBackend(c, backend); err != nil {
				return err
			}
			if step == "" {
				return sandboxSetupFail(c, sandboxSetupExitUsage, "%s needs --step <id> (see observer sandbox setup status %s)", action, backend)
			}
			ss, release, err := openSandboxSetupSession(c, deps, cfg(), yes)
			if err != nil {
				return err
			}
			defer release()
			return sandboxSetupExit(ss.runOne(backend, step, action, ""))
		},
	}
	c.Flags().StringVar(&step, "step", "", "the step (a prerequisite id from `observer sandbox setup status <backend>`)")
	c.Flags().BoolVar(&yes, "yes", false, "answer yes to the step's question (never to a password prompt)")
	return sandboxSetupSub(c)
}

func sandboxSetupRecordsCmd(deps sandboxSetupCmdDeps, cfg func() string) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "records",
		Short: "List the sandbox setup records (what Observer did for each backend's steps)",
		Args:  sandboxSetupArgs(0, 0, "[--json]"),
		RunE: func(c *cobra.Command, _ []string) error {
			ss, release, err := openSandboxSetupSession(c, deps, cfg(), false)
			if err != nil {
				return err
			}
			defer release()
			recs, err := ss.records()
			if err != nil {
				return ss.seamFail("records", err)
			}
			if asJSON {
				return sandboxSetupJSON(ss.out, map[string]any{"records": sandboxSetupNonNil(recs)})
			}
			return renderSandboxSetupRecords(ss.out, recs)
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print JSON (the dashboard's record shape)")
	return sandboxSetupSub(c)
}

// records gathers the latest record of every step of every offered row on
// this host, through the seam's plans (the seam has no list method), one per
// record id, oldest first.
func (ss *sandboxSetupSession) records() ([]dashapi.ToolInstallRecord, error) {
	ctx := ss.c.Context()
	sums, err := ss.s.Summary(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[int64]bool{}
	var out []dashapi.ToolInstallRecord
	for _, sum := range sums {
		plan, err := ss.s.Plan(ctx, sum.Backend)
		if err != nil {
			return nil, err
		}
		for _, st := range plan.Steps {
			if st.Record == nil || seen[st.Record.ID] {
				continue
			}
			seen[st.Record.ID] = true
			rec := *st.Record
			if rec.Backend == "" {
				rec.Backend = plan.Backend
			}
			out = append(out, rec)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// sandboxSetupStepDone reports whether a step needs nothing.
func sandboxSetupStepDone(st dashapi.SandboxSetupStep) bool {
	return st.State == "done" || st.State == "not_applicable"
}

// walk is `run <backend>` without --step: the plan's steps in order, each
// asked on its own, the plan read again after every step (its fingerprint
// moves). A failed or refused step stops the walk.
func (ss *sandboxSetupSession) walk(backend, fromFile string) int {
	ctx := ss.c.Context()
	handled := map[string]bool{}
	outcome := sandboxSetupExitOK
	for {
		plan, err := ss.s.Plan(ctx, backend)
		if err != nil {
			_ = ss.seamFail("run "+backend, err)
			return sandboxSetupExitForCode(sandboxSetupErrCode(err))
		}
		if plan.Blocked != "" {
			fmt.Fprintf(ss.out, "%s cannot be set up on this machine: %s\n", sandboxSetupPlanName(plan), plan.Blocked)
			return sandboxSetupExitBlocked
		}
		idx := sandboxSetupWalkNext(plan, handled)
		if idx >= 0 && plan.Steps[idx].State == "unknown" {
			// Only the active check can judge this step: running the walk
			// is the opt-in for one check of this row (ruling R1).
			checked, cerr := ss.s.Check(ctx, backend)
			if cerr != nil {
				_ = ss.seamFail("check "+backend, cerr)
				return sandboxSetupExitForCode(sandboxSetupErrCode(cerr))
			}
			plan = checked
			// Steps the check found done stay handled for the rest of the
			// walk, so a later passive read does not check them again.
			for _, st := range plan.Steps {
				if sandboxSetupStepDone(st) {
					handled[st.Prereq] = true
				}
			}
			idx = sandboxSetupWalkNext(plan, handled)
		}
		if idx < 0 {
			ss.walkSummary(plan)
			return outcome
		}
		st := plan.Steps[idx]
		handled[st.Prereq] = true
		var code int
		if st.CanRun {
			code = ss.runStep(backend, plan, idx, dashapi.SandboxSetupActionRun, fromFile)
		} else {
			code = ss.describeNotRunnable(backend, plan, idx)
		}
		switch code {
		case sandboxSetupExitOK:
		case sandboxSetupExitFailed, sandboxSetupExitUsage, sandboxSetupExitRefused:
			return code
		default:
			// Blocked steps stay visible; later steps are listed so the
			// person sees the whole of what is left.
			if outcome == sandboxSetupExitOK {
				outcome = code
			}
		}
	}
}

// sandboxSetupWalkNext is the walk's next step: the first not done and not
// handled yet (-1: none).
func sandboxSetupWalkNext(plan dashapi.SandboxSetupPlan, handled map[string]bool) int {
	for i, st := range plan.Steps {
		if !sandboxSetupStepDone(st) && !handled[st.Prereq] {
			return i
		}
	}
	return -1
}

// walkSummary is the walk's closing line from the final plan.
func (ss *sandboxSetupSession) walkSummary(plan dashapi.SandboxSetupPlan) {
	if plan.Ready {
		fmt.Fprintf(ss.out, "%s is set up and ready.\n", sandboxSetupPlanName(plan))
		return
	}
	if plan.Unconfirmed {
		fmt.Fprintf(ss.out, "%s is set up as far as Observer can see; observer sandbox setup check %s confirms it runs here.\n", sandboxSetupPlanName(plan), plan.Backend)
		return
	}
	var left []string
	for _, st := range plan.Steps {
		if !sandboxSetupStepDone(st) {
			left = append(left, st.Label)
		}
	}
	if len(left) == 0 {
		fmt.Fprintf(ss.out, "%s: every step is done; the backend's own check has not passed yet (observer sandbox setup check %s).\n", sandboxSetupPlanName(plan), plan.Backend)
		return
	}
	fmt.Fprintf(ss.out, "%s still needs: %s\n", sandboxSetupPlanName(plan), strings.Join(left, "; "))
}

// runOne is `run --step`, undo, update and repair: one named step.
func (ss *sandboxSetupSession) runOne(backend, prereq, action, fromFile string) int {
	plan, err := ss.s.Plan(ss.c.Context(), backend)
	if err != nil {
		_ = ss.seamFail(action+" "+backend, err)
		return sandboxSetupExitForCode(sandboxSetupErrCode(err))
	}
	if plan.Blocked != "" {
		fmt.Fprintf(ss.out, "%s cannot be set up on this machine: %s\n", sandboxSetupPlanName(plan), plan.Blocked)
		return sandboxSetupExitBlocked
	}
	idx := sandboxSetupStepIndex(plan, prereq)
	if idx < 0 {
		var ids []string
		for _, st := range plan.Steps {
			ids = append(ids, st.Prereq)
		}
		_ = sandboxSetupFail(ss.c, sandboxSetupExitUsage, "%s has no step %q (steps: %s)", backend, prereq, strings.Join(ids, ", "))
		return sandboxSetupExitUsage
	}
	if plan.Steps[idx].State == "unknown" {
		// Only the active check can judge this step: naming it is the
		// opt-in for one check of this row (ruling R1).
		checked, cerr := ss.s.Check(ss.c.Context(), backend)
		if cerr != nil {
			_ = ss.seamFail("check "+backend, cerr)
			return sandboxSetupExitForCode(sandboxSetupErrCode(cerr))
		}
		plan = checked
		if idx = sandboxSetupStepIndex(plan, prereq); idx < 0 {
			_ = sandboxSetupFail(ss.c, sandboxSetupExitFailed, "the step %q is no longer in %s's plan", prereq, backend)
			return sandboxSetupExitFailed
		}
	}
	st := plan.Steps[idx]
	switch action {
	case dashapi.SandboxSetupActionRun:
		if !st.CanRun {
			return ss.describeNotRunnable(backend, plan, idx)
		}
	case dashapi.SandboxSetupActionUndo:
		if !st.CanUndo {
			return sandboxSetupDescribeNoUndo(ss.out, st)
		}
	}
	return ss.runStep(backend, plan, idx, action, fromFile)
}

// sandboxSetupNoUndo is the ordered table of what an undo the plan does not
// offer prints and exits with, walked top-down (first match wins): a refusal
// (a live run, an unanswered daemon, a switch) is exit 4 with its reason;
// anything else has nothing Observer can undo (exit 1).
var sandboxSetupNoUndo = []struct {
	name  string
	match func(st dashapi.SandboxSetupStep) bool
	exit  int
	print func(w io.Writer, st dashapi.SandboxSetupStep)
}{
	{"refused", func(st dashapi.SandboxSetupStep) bool { return st.UndoRefused != "" }, sandboxSetupExitRefused, func(w io.Writer, st dashapi.SandboxSetupStep) {
		// The refusal's own sentence says why Observer does not undo it,
		// so the line says it once.
		if st.Reason != "" {
			fmt.Fprintf(w, "%s: refused. %s\n", st.Label, st.Reason)
			return
		}
		fmt.Fprintf(w, "%s: refused, Observer does not undo this step now.\n", st.Label)
	}},
	{"nothing_to_undo", func(dashapi.SandboxSetupStep) bool { return true }, sandboxSetupExitFailed, func(w io.Writer, st dashapi.SandboxSetupStep) {
		fmt.Fprintf(w, "%s: there is nothing Observer can undo for this step", st.Label)
		if st.Reason != "" {
			fmt.Fprintf(w, " (%s)", st.Reason)
		}
		fmt.Fprintln(w, ".")
	}},
}

// sandboxSetupDescribeNoUndo prints an undo the plan does not offer and
// returns its exit. Nothing runs.
func sandboxSetupDescribeNoUndo(w io.Writer, st dashapi.SandboxSetupStep) int {
	for _, row := range sandboxSetupNoUndo {
		if row.match(st) {
			row.print(w, st)
			return row.exit
		}
	}
	return sandboxSetupExitFailed
}

// sandboxSetupStepIndex is prereq's index in plan (-1: none).
func sandboxSetupStepIndex(plan dashapi.SandboxSetupPlan, prereq string) int {
	for i, st := range plan.Steps {
		if st.Prereq == prereq {
			return i
		}
	}
	return -1
}

// sandboxSetupNotRunnable is the ordered table of what a step that cannot
// run prints and exits with, walked top-down (first match wins).
var sandboxSetupNotRunnable = []struct {
	name  string
	match func(st dashapi.SandboxSetupStep) bool
	exit  int
	print func(w io.Writer, backend string, st dashapi.SandboxSetupStep)
}{
	{"done", sandboxSetupStepDone, sandboxSetupExitOK, func(w io.Writer, _ string, st dashapi.SandboxSetupStep) {
		fmt.Fprintf(w, "%s: already done.\n", st.Label)
	}},
	{"not_allowed", func(st dashapi.SandboxSetupStep) bool { return st.State == "not_allowed" }, sandboxSetupExitRefused, func(w io.Writer, _ string, st dashapi.SandboxSetupStep) {
		fmt.Fprintf(w, "%s: not allowed by your organization.%s\n", st.Label, sandboxSetupSuffix(st.Reason))
	}},
	{"never", func(st dashapi.SandboxSetupStep) bool { return st.State == "blocked" || st.Class == "never" }, sandboxSetupExitBlocked, sandboxSetupPrintNever},
	{"in_flight", func(st dashapi.SandboxSetupStep) bool { return st.State == "in_flight" }, sandboxSetupExitOK, func(w io.Writer, backend string, st dashapi.SandboxSetupStep) {
		fmt.Fprintf(w, "%s: already in progress; check again when it finishes (observer sandbox setup status %s).\n", st.Label, backend)
	}},
	{"guide", func(st dashapi.SandboxSetupStep) bool { return st.Class == "guide" }, sandboxSetupExitOK, sandboxSetupPrintGuide},
	{"unknown", func(st dashapi.SandboxSetupStep) bool { return st.State == "unknown" }, sandboxSetupExitOK, func(w io.Writer, backend string, st dashapi.SandboxSetupStep) {
		fmt.Fprintf(w, "%s: the check of this machine could not tell whether this is done (observer sandbox setup check %s shows what it found).\n", st.Label, backend)
	}},
	{"other", func(dashapi.SandboxSetupStep) bool { return true }, sandboxSetupExitFailed, func(w io.Writer, _ string, st dashapi.SandboxSetupStep) {
		fmt.Fprintf(w, "%s: cannot run now (%s).%s\n", st.Label, st.State, sandboxSetupSuffix(st.Reason))
	}},
}

// describeNotRunnable prints a step that cannot run and returns its exit.
// Nothing runs.
func (ss *sandboxSetupSession) describeNotRunnable(backend string, plan dashapi.SandboxSetupPlan, idx int) int {
	st := plan.Steps[idx]
	for _, row := range sandboxSetupNotRunnable {
		if row.match(st) {
			fmt.Fprintf(ss.out, "Step %d of %d: ", idx+1, len(plan.Steps))
			row.print(ss.out, backend, st)
			return row.exit
		}
	}
	return sandboxSetupExitFailed
}

// sandboxSetupPrintGuide prints a guide step: the command to copy.
func sandboxSetupPrintGuide(w io.Writer, _ string, st dashapi.SandboxSetupStep) {
	fmt.Fprintf(w, "%s: Observer does not run this step; run it yourself:\n", st.Label)
	if st.Display != "" {
		fmt.Fprintf(w, "    %s\n", st.Display)
	}
	if st.Reason != "" {
		fmt.Fprintf(w, "  %s\n", st.Reason)
	}
	if st.Disclosure != "" {
		fmt.Fprintf(w, "  Note: %s\n", st.Disclosure)
	}
	sandboxSetupPrintAfter(w, st)
	if st.Docs != "" {
		fmt.Fprintf(w, "  Docs: %s\n", sandboxSetupDocsLink(st.Docs))
	}
}

// sandboxSetupPublicDocs is the public page about sandboxed terminals. A
// step's Docs value is an anchor into the repository's own sandbox notes
// (pinned by internal/sandboxsetup's TestRemedyDocsAnchorsResolve and used by
// the dashboard to pick a help entry); users cannot open that file, so the
// CLI points at the public page instead (SR-29).
const sandboxSetupPublicDocs = "https://superbased.app/docs/guides/terminals"

// sandboxSetupDocsLink is what the CLI prints for a step's Docs anchor.
func sandboxSetupDocsLink(anchor string) string {
	if anchor == "" {
		return ""
	}
	return sandboxSetupPublicDocs + " (Sandboxed terminals)"
}

// sandboxSetupPrintNever prints a step Observer must never touch: the words
// and the docs anchor.
func sandboxSetupPrintNever(w io.Writer, _ string, st dashapi.SandboxSetupStep) {
	fmt.Fprintf(w, "%s: Observer does not change this; it is yours to decide.\n", st.Label)
	if st.Reason != "" {
		fmt.Fprintf(w, "  %s\n", st.Reason)
	}
	if st.Display != "" {
		fmt.Fprintf(w, "  %s\n", st.Display)
	}
	if st.Docs != "" {
		fmt.Fprintf(w, "  Docs: %s\n", sandboxSetupDocsLink(st.Docs))
	}
}

// sandboxSetupAfterText is what the person must do after a step.
var sandboxSetupAfterText = map[string]string{
	"relogin":        "Afterwards: sign out and back in (or start a new login shell) so the change applies.",
	"reboot":         "Afterwards: restart the computer.",
	"engine_restart": "Afterwards: restart the container engine.",
	"daemon_restart": "Afterwards: restart Observer (`observer service restart` when it runs as a service, otherwise stop `observer start` and run it again).",
}

func sandboxSetupPrintAfter(w io.Writer, st dashapi.SandboxSetupStep) {
	if st.After == "" {
		return
	}
	if t, ok := sandboxSetupAfterText[st.After]; ok {
		fmt.Fprintf(w, "  %s\n", t)
		return
	}
	fmt.Fprintf(w, "  Afterwards: %s\n", st.After)
}

// sandboxSetupSuffix is " reason" or "".
func sandboxSetupSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " " + reason
}

// sandboxSetupConsentLine is a pinned download's consent line: version,
// size, the first 12 of the sha256 and the source.
func sandboxSetupConsentLine(c *dashapi.SandboxSetupConsent) string {
	sha := c.SHA256
	if len(sha) > 12 {
		sha = sha[:12]
	}
	source := c.Source
	if source == "from_file" {
		source = "a file already on this machine (--from-file)"
	}
	line := fmt.Sprintf("Download: v%s, %s, sha256 %s, from %s", strings.TrimPrefix(c.Version, "v"), sandboxSetupMB(c.Bytes), sha, source)
	if c.URL != "" {
		line += " (" + c.URL + ")"
	}
	return line
}

// sandboxSetupMB is a byte count for the consent line.
func sandboxSetupMB(n int64) string {
	switch {
	case n <= 0:
		return "size unknown"
	case n < 1_000_000:
		return "less than 1 MB"
	}
	return fmt.Sprintf("about %d MB", (n+500_000)/1_000_000)
}

// sandboxSetupActionVerb is how a step's question names the action.
var sandboxSetupActionVerb = map[string]string{
	dashapi.SandboxSetupActionRun:    "Run this step",
	dashapi.SandboxSetupActionUndo:   "Undo this step",
	dashapi.SandboxSetupActionUpdate: "Update this step",
	dashapi.SandboxSetupActionRepair: "Repair this step",
}

// printStep prints a step before its question: its sentence, disclosure,
// the elevation note and, for a download, the consent line.
func (ss *sandboxSetupSession) printStep(plan dashapi.SandboxSetupPlan, idx int, action string) {
	st := plan.Steps[idx]
	w := ss.out
	fmt.Fprintf(w, "Step %d of %d: %s", idx+1, len(plan.Steps), st.Label)
	if action != dashapi.SandboxSetupActionRun {
		fmt.Fprintf(w, " (%s)", action)
	}
	fmt.Fprintln(w)
	if st.Display != "" {
		fmt.Fprintf(w, "  %s\n", st.Display)
	}
	if st.Reason != "" {
		fmt.Fprintf(w, "  %s\n", st.Reason)
	}
	if st.Disclosure != "" {
		fmt.Fprintf(w, "  Note: %s\n", st.Disclosure)
	}
	if st.Class == "elevated" {
		fmt.Fprintln(w, "  This step asks for your password itself (sudo, or the Windows UAC prompt); --yes never answers it.")
	}
	if st.Consent != nil {
		fmt.Fprintf(w, "  %s\n", sandboxSetupConsentLine(st.Consent))
	}
	sandboxSetupPrintAfter(w, st)
	if st.Docs != "" {
		fmt.Fprintf(w, "  Docs: %s\n", sandboxSetupDocsLink(st.Docs))
	}
}

// errNoTTY is the refusal of a question with no terminal and no --yes.
var errNoTTY = errors.New("stdin is not a terminal; pass --yes to answer each step's question (it never answers a password prompt)")

// confirm asks the step's question. --yes answers it; without a terminal
// and without --yes it refuses.
func (ss *sandboxSetupSession) confirm(action string) (bool, error) {
	q := sandboxSetupActionVerb[action]
	if q == "" {
		q = "Continue"
	}
	if ss.yes {
		fmt.Fprintf(ss.out, "%s? yes (--yes)\n", q)
		return true, nil
	}
	if !ss.tty {
		return false, errNoTTY
	}
	fmt.Fprintf(ss.out, "%s? [y/N] ", q)
	line, err := ss.in.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(ss.out)
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// runStep asks, then carries out plan.Steps[idx] through the seam. A
// plan_changed answer reads the plan again and asks again.
func (ss *sandboxSetupSession) runStep(backend string, plan dashapi.SandboxSetupPlan, idx int, action, fromFile string) int {
	ctx := ss.c.Context()
	prereq := plan.Steps[idx].Prereq
	for attempt := 0; attempt <= sandboxSetupMaxReplans; attempt++ {
		st := plan.Steps[idx]
		ss.printStep(plan, idx, action)
		ok, err := ss.confirm(action)
		if err != nil {
			_ = sandboxSetupFail(ss.c, sandboxSetupExitUsage, "%v", err)
			return sandboxSetupExitUsage
		}
		if !ok {
			fmt.Fprintf(ss.out, "Skipped: %s\n", st.Label)
			return sandboxSetupExitOK
		}
		req := dashapi.SandboxSetupRunRequest{
			Step:        st.Prereq,
			Action:      action,
			Fingerprint: plan.Fingerprint,
			Consent:     st.Consent,
		}
		// The offline file belongs to a download step only (dispatch on the
		// step's channel, never a backend).
		if st.Channel == "pinned_download" {
			req.FromFile = fromFile
		}
		*ss.spawn = sandboxSetupSpawnRecord{}
		started, err := ss.s.Run(ctx, backend, req, "cli")
		if err != nil {
			code := sandboxSetupErrCode(err)
			if code == dashapi.SandboxSetupCodePlanChanged {
				fmt.Fprintln(ss.out, "The plan changed since it was read; reading it again.")
				// The refusal carries the fresh plan (the checked one when
				// the run checked); read it again only when it does not.
				var carrier interface {
					FreshPlan() *dashapi.SandboxSetupPlan
				}
				if errors.As(err, &carrier) && carrier.FreshPlan() != nil {
					plan = *carrier.FreshPlan()
				} else {
					fresh, perr := ss.s.Plan(ctx, backend)
					if perr != nil {
						_ = ss.seamFail(action+" "+backend, perr)
						return sandboxSetupExitForCode(sandboxSetupErrCode(perr))
					}
					plan = fresh
				}
				idx = sandboxSetupStepIndex(plan, prereq)
				if idx < 0 {
					_ = sandboxSetupFail(ss.c, sandboxSetupExitFailed, "the step %q is no longer in %s's plan", prereq, backend)
					return sandboxSetupExitFailed
				}
				if plan.Blocked != "" {
					fmt.Fprintf(ss.out, "%s cannot be set up on this machine: %s\n", sandboxSetupPlanName(plan), plan.Blocked)
					return sandboxSetupExitBlocked
				}
				if action == dashapi.SandboxSetupActionRun && !plan.Steps[idx].CanRun {
					return ss.describeNotRunnable(backend, plan, idx)
				}
				continue
			}
			_ = sandboxSetupFail(ss.c, sandboxSetupExitForCode(code), "%s: %v", st.Label, err)
			return sandboxSetupExitForCode(code)
		}
		return ss.settle(backend, prereq, st.Label, started)
	}
	_ = sandboxSetupFail(ss.c, sandboxSetupExitFailed, "the plan kept changing; run observer sandbox setup status %s and try again", backend)
	return sandboxSetupExitFailed
}

// sandboxSetupFailedStatus are the record statuses a finished step failed
// with.
var sandboxSetupFailedStatus = map[string]bool{
	string(toolinstall.StatusInstallFailed):        true,
	string(toolinstall.StatusInstallInterrupted):   true,
	string(toolinstall.StatusUninstallFailed):      true,
	string(toolinstall.StatusUninstallInterrupted): true,
}

// settle judges a started step: a foreground child's exit code, an
// in-process op's final status, then the step's fresh record.
func (ss *sandboxSetupSession) settle(backend, prereq, label string, started dashapi.SandboxSetupStarted) int {
	ctx := ss.c.Context()
	if ss.spawn.spawned && ss.spawn.exit != 0 {
		_ = sandboxSetupFail(ss.c, sandboxSetupExitFailed, "%s failed (exit code %d)", label, ss.spawn.exit)
		return sandboxSetupExitFailed
	}
	if started.Kind == dashapi.SandboxSetupStartedOp && started.OpID != "" {
		if code := ss.waitOp(started.OpID, label); code != sandboxSetupExitOK {
			return code
		}
	}
	if started.Kind == dashapi.SandboxSetupStartedTerminal && started.Handle != "" {
		// A seam that opened a dashboard terminal instead of the foreground
		// child (it should not on this surface): say where it runs.
		fmt.Fprintf(ss.out, "%s is running in a dashboard terminal (%s).\n", label, started.Handle)
		return sandboxSetupExitOK
	}
	plan := started.Plan
	if plan == nil {
		fresh, err := ss.s.Plan(ctx, backend)
		if err == nil {
			plan = &fresh
		}
	}
	if plan != nil {
		if i := sandboxSetupStepIndex(*plan, prereq); i >= 0 {
			if rec := plan.Steps[i].Record; rec != nil && sandboxSetupFailedStatus[rec.Status] {
				msg := fmt.Sprintf("%s failed (%s", label, rec.Status)
				if rec.ExitCode != nil {
					msg += fmt.Sprintf(", exit code %d", *rec.ExitCode)
				}
				_ = sandboxSetupFail(ss.c, sandboxSetupExitFailed, "%s)", msg)
				return sandboxSetupExitFailed
			}
		}
	}
	fmt.Fprintf(ss.out, "Done: %s\n", label)
	if started.Note != "" {
		fmt.Fprintf(ss.out, "  %s\n", started.Note)
	}
	return sandboxSetupExitOK
}

// waitOp polls an in-process operation (a pinned download) to its end.
func (ss *sandboxSetupSession) waitOp(id, label string) int {
	ctx := ss.c.Context()
	fmt.Fprintf(ss.out, "%s: working...\n", label)
	for {
		op, ok := ss.s.Op(ctx, id)
		if !ok {
			return sandboxSetupExitOK
		}
		if !toolinstall.InFlight(toolinstall.Status(op.Status)) {
			if sandboxSetupFailedStatus[op.Status] || op.Error != "" {
				_ = sandboxSetupFail(ss.c, sandboxSetupExitFailed, "%s failed (%s)%s", label, op.Status, sandboxSetupSuffix(op.Error))
				return sandboxSetupExitFailed
			}
			if op.Total > 0 {
				fmt.Fprintf(ss.out, "%s: %s placed.\n", label, sandboxSetupMB(op.Total))
			}
			return sandboxSetupExitOK
		}
		if err := ss.deps.sleep(ctx, sandboxSetupOpPoll); err != nil {
			_ = sandboxSetupFail(ss.c, sandboxSetupExitFailed, "%s: %v", label, err)
			return sandboxSetupExitFailed
		}
	}
}

// sandboxSetupCodeExits maps every closed seam error code to the command's
// exit (one row per dashapi.SandboxSetupCodes entry, pinned by a test).
var sandboxSetupCodeExits = map[string]int{
	dashapi.SandboxSetupCodePlanChanged:         sandboxSetupExitFailed,
	dashapi.SandboxSetupCodeNotAllowedByOrg:     sandboxSetupExitRefused,
	dashapi.SandboxSetupCodeInstallDisabled:     sandboxSetupExitRefused,
	dashapi.SandboxSetupCodeElevationDisabled:   sandboxSetupExitRefused,
	dashapi.SandboxSetupCodeConsentRequired:     sandboxSetupExitFailed,
	dashapi.SandboxSetupCodeLiveRuns:            sandboxSetupExitRefused,
	dashapi.SandboxSetupCodeStepNotRunnable:     sandboxSetupExitFailed,
	dashapi.SandboxSetupCodeUnknownStep:         sandboxSetupExitUsage,
	dashapi.SandboxSetupCodeNotInBuild:          sandboxSetupExitBlocked,
	dashapi.SandboxSetupCodeTerminalUnavailable: sandboxSetupExitFailed,
}

// sandboxSetupExitForCode is the exit of a seam error code ("" or an
// unknown code: a failure).
func sandboxSetupExitForCode(code string) int {
	if e, ok := sandboxSetupCodeExits[code]; ok {
		return e
	}
	return sandboxSetupExitFailed
}

// sandboxSetupCoded is an error carrying one of the closed setup codes.
type sandboxSetupCoded interface{ Code() string }

// sandboxSetupErrCode reads the closed code off a seam error: the not-in-build
// sentinel, an error with a Code() method, or (last) a closed code named as
// a word in the message. "" when none.
func sandboxSetupErrCode(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, dashapi.ErrSandboxSetupNotInBuild) {
		return dashapi.SandboxSetupCodeNotInBuild
	}
	var coded sandboxSetupCoded
	if errors.As(err, &coded) {
		if _, ok := sandboxSetupCodeExits[coded.Code()]; ok {
			return coded.Code()
		}
	}
	msg := err.Error()
	for _, code := range dashapi.SandboxSetupCodes() {
		if sandboxSetupHasWord(msg, code) {
			return code
		}
	}
	return ""
}

// sandboxSetupHasWord reports whether word occurs in s bounded by
// non-identifier characters.
func sandboxSetupHasWord(s, word string) bool {
	isID := func(b byte) bool {
		return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
	}
	for from := 0; ; {
		i := strings.Index(s[from:], word)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(word)
		if (i == 0 || !isID(s[i-1])) && (end == len(s) || !isID(s[end])) {
			return true
		}
		from = i + 1
	}
}

// sandboxSetupPlanName is "Label (backend)".
func sandboxSetupPlanName(plan dashapi.SandboxSetupPlan) string {
	if plan.Label == "" || plan.Label == plan.Backend {
		return plan.Backend
	}
	return plan.Label + " (" + plan.Backend + ")"
}

// sandboxSetupNextCommand is the command that does a step: the setup verb
// when Observer can run it, the copyable command of a guide step, "" for a
// step Observer never touches.
func sandboxSetupNextCommand(backend string, st dashapi.SandboxSetupStep) string {
	switch {
	case st.State == "unknown":
		// Only the active check can judge it (it may well be done).
		return "observer sandbox setup check " + backend
	case st.CanRun:
		return "observer sandbox setup run " + backend + " --step " + st.Prereq
	case st.Class == "guide":
		return st.Display
	}
	return ""
}

// renderSandboxSetupSummaries is `setup status` without a backend.
func renderSandboxSetupSummaries(w io.Writer, sums []dashapi.SandboxSetupSummary) error {
	if len(sums) == 0 {
		_, err := fmt.Fprintln(w, "No sandbox backend is offered on this host.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "BACKEND\tSTATE\tDETAIL")
	for _, s := range sums {
		state, detail := "not set up", ""
		switch {
		case s.Ready:
			state = "ready"
		case s.Unconfirmed:
			state, detail = "set up", "not checked: observer sandbox setup check "+s.Backend+" confirms it"
		case s.Blocked != "":
			state, detail = "blocked", s.Blocked
		case s.Next != "":
			detail = "next: " + s.Next
		}
		label := s.Backend
		if s.Label != "" && s.Label != s.Backend {
			label += " (" + s.Label + ")"
		}
		if s.Beta != "" {
			label += " (beta)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", label, state, detail)
		if s.Beta != "" {
			// No tab: a cell-less line does not widen the columns.
			fmt.Fprintf(tw, "  %s\n", s.Beta)
		}
	}
	return tw.Flush()
}

// renderSandboxSetupPlan is one backend's plan in plain text.
func renderSandboxSetupPlan(w io.Writer, plan dashapi.SandboxSetupPlan) error {
	head := sandboxSetupPlanName(plan)
	if plan.Beta != "" {
		head += " (beta)"
	}
	head += ": "
	switch {
	case plan.Ready:
		head += "ready"
	case plan.Unconfirmed:
		head += "set up as far as Observer can see"
	case plan.Blocked != "":
		head += "cannot be set up here: " + plan.Blocked
	default:
		head += "not ready"
	}
	if plan.Checked {
		head += " (this machine was checked)"
	} else {
		head += " (from what Observer can see without running anything; observer sandbox setup check " + plan.Backend + " runs the full check)"
	}
	fmt.Fprintln(w, head)
	if plan.Beta != "" {
		fmt.Fprintf(w, "  %s\n", plan.Beta)
	}
	for i, st := range plan.Steps {
		fmt.Fprintf(w, "  %d. [%s] %s (%s)\n", i+1, st.State, st.Label, st.Class)
		if st.Display != "" {
			fmt.Fprintf(w, "       %s\n", st.Display)
		}
		if st.Reason != "" {
			fmt.Fprintf(w, "       %s\n", st.Reason)
		}
		if st.Disclosure != "" {
			fmt.Fprintf(w, "       Note: %s\n", st.Disclosure)
		}
		if st.Consent != nil {
			fmt.Fprintf(w, "       %s\n", sandboxSetupConsentLine(st.Consent))
		}
		if st.Record != nil {
			fmt.Fprintf(w, "       Record: %s on %s\n", st.Record.Status, st.Record.InstalledAt.Format("2006-01-02 15:04"))
		}
		if st.Docs != "" && (st.Class == "never" || st.Class == "guide") {
			fmt.Fprintf(w, "       Docs: %s\n", sandboxSetupDocsLink(st.Docs))
		}
	}
	if plan.Blocked == "" && !plan.Ready && plan.Next >= 0 && plan.Next < len(plan.Steps) {
		fmt.Fprintf(w, "Next: %s\n", sandboxSetupNextLine(plan.Backend, plan.Steps[plan.Next]))
	}
	return nil
}

// sandboxSetupNextLines is the ordered table of what the Next line says
// about the plan's next step, walked top-down (first match wins).
var sandboxSetupNextLines = []struct {
	name  string
	match func(backend string, st dashapi.SandboxSetupStep) (string, bool)
}{
	// A step Observer is running now says so, never that Observer does not
	// do it.
	{"in_flight", func(_ string, st dashapi.SandboxSetupStep) (string, bool) {
		return st.Label + " (running now)", st.State == "in_flight"
	}},
	{"command", func(backend string, st dashapi.SandboxSetupStep) (string, bool) {
		cmd := sandboxSetupNextCommand(backend, st)
		return cmd, cmd != ""
	}},
	{"not_ours", func(_ string, st dashapi.SandboxSetupStep) (string, bool) {
		return st.Label + " (Observer does not do this step)", true
	}},
}

// sandboxSetupNextLine is the Next line's text for st.
func sandboxSetupNextLine(backend string, st dashapi.SandboxSetupStep) string {
	for _, row := range sandboxSetupNextLines {
		if line, ok := row.match(backend, st); ok {
			return line
		}
	}
	return st.Label
}

// renderSandboxSetupRecords is `setup records` in plain text.
func renderSandboxSetupRecords(w io.Writer, recs []dashapi.ToolInstallRecord) error {
	if len(recs) == 0 {
		_, err := fmt.Fprintln(w, "No sandbox setup records.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tBACKEND\tSTEP\tSTATUS\tWHEN\tCOMMAND")
	for _, r := range recs {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Backend, r.Tool, r.Status, r.InstalledAt.Format("2006-01-02 15:04"), r.Command)
	}
	return tw.Flush()
}

// sandboxSetupJSON writes v indented.
func sandboxSetupJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("sandbox setup: encode JSON: %w", err)
	}
	return nil
}

// sandboxSetupNonNil keeps an empty list a JSON [] rather than null.
func sandboxSetupNonNil[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return xs
}

// sandboxSetupShellJoin renders argv for the "Running:" line.
func sandboxSetupShellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\"'$`\\") {
			parts[i] = fmt.Sprintf("%q", a)
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}

// sandboxSetupOpenDefault builds the production seam for the CLI: the
// config at cfgPath, the install ledger over the node database (nil when it
// cannot be opened; the plan then shows no records) and spawn as the
// foreground runner.
func sandboxSetupOpenDefault(ctx context.Context, cfgPath string, spawn sandboxSetupSpawnFunc) (dashapi.SandboxSetup, func(), error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		return nil, nil, fmt.Errorf("sandbox setup: load config: %w", err)
	}
	release := func() {}
	var ledger *toolInstallLedger
	if database, derr := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath}); derr == nil {
		ledger = newToolInstallLedgerFor(database, logger)
		if ledger != nil {
			// This is a CLI process: a record a live daemon may own (a
			// setup terminal the dashboard started) is never settled here.
			ledger.daemonListening = sandboxSetupDaemonListening(daemonDashboardAddr(cfgPath))
		}
		release = func() { _ = database.Close() }
	} else {
		logger.Warn("sandbox setup: the node database could not be opened; records are not shown", "err", derr)
	}
	s := newSandboxSetup(sandboxSetupOptions{
		ConfigPath: cfgPath,
		Surface:    "cli",
		Spawn:      spawn,
		Ledger:     ledger,
		Logger:     logger,
		Now:        time.Now,
	})
	return s, release, nil
}

// sandboxSetupDaemonListenTimeout bounds the one dial that asks whether a
// daemon listens.
const sandboxSetupDaemonListenTimeout = 2 * time.Second

// sandboxSetupDaemonListening reports whether something listens on the
// daemon's dashboard address. Only a refused connection means no daemon;
// any other failure (a stopped daemon still holding its socket, a timeout)
// reads as listening, so a CLI never settles a record a daemon may own.
func sandboxSetupDaemonListening(addr string) func(ctx context.Context) bool {
	return func(ctx context.Context) bool {
		d := net.Dialer{Timeout: sandboxSetupDaemonListenTimeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return !isConnRefused(err)
		}
		_ = conn.Close()
		return true
	}
}

// sandboxSetupForeground runs argv as a child on the person's own terminal
// (stdin, stdout and stderr inherited), in the home directory (D-050), and
// returns its exit code. While it runs, an interrupt goes to the child (the
// terminal's process group) and does not end Observer, so the step's result
// is still recorded.
func sandboxSetupForeground(ctx context.Context, argv []string, stdio sandboxSetupStdio) (int, error) {
	if len(argv) == 0 {
		return -1, errors.New("sandboxSetupForeground: empty argv")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return -1, fmt.Errorf("sandboxSetupForeground: home directory: %w", err)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	defer signal.Stop(sigs)
	// argv is the planner's server-derived constant (or toolinstall's
	// derivation from one), never request data.
	c := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: server-derived constant argv
	c.Dir = home
	c.Stdin, c.Stdout, c.Stderr = stdio.In, stdio.Out, stdio.Err
	err = c.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return -1, fmt.Errorf("sandboxSetupForeground: %w", err)
	}
	return 0, nil
}

// sandboxSetupIsTTY reports whether in is an interactive terminal.
func sandboxSetupIsTTY(in io.Reader) bool {
	f, ok := in.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) //nolint:gosec // G115: a descriptor number
}

// sandboxSetupSleep waits d or until ctx ends.
func sandboxSetupSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("sandbox setup: %w", ctx.Err())
	case <-t.C:
		return nil
	}
}

// sandboxSetupDoctorSeam builds the seam doctor reads (passive plans only;
// no runner, no ledger). Tests replace it.
var sandboxSetupDoctorSeam = func(configPath string) dashapi.SandboxSetup {
	return newSandboxSetup(sandboxSetupOptions{
		ConfigPath: configPath,
		Surface:    "cli",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        time.Now,
	})
}

// sandboxSetupDoctorChecks is doctor's `sandbox.setup.<backend>` rows: one
// per offered row that runs on host, OK when ready (or when it can never be
// set up here, saying why), WARN naming the next step and the exact command
// that does it. It reads passive plans only (never the active check) and
// adds nothing when setup is not in this build.
func sandboxSetupDoctorChecks(ctx context.Context, s dashapi.SandboxSetup, host sandboxbackend.HostKind) []diag.Check {
	if s == nil {
		return nil
	}
	sums, err := s.Summary(ctx)
	if errors.Is(err, dashapi.ErrSandboxSetupNotInBuild) {
		return nil
	}
	if err != nil {
		return []diag.Check{{Name: "sandbox.setup", Status: diag.StatusWarn, Message: "could not read the sandbox setup plans: " + err.Error()}}
	}
	var out []diag.Check
	for _, sum := range sums {
		row, ok := sandboxbackend.Get(sum.Backend)
		if !ok || !row.Offered() || !row.RunsOn(host) {
			continue
		}
		label := sum.Label
		if label == "" {
			label = sum.Backend
		}
		c := diag.Check{Name: "sandbox.setup." + sum.Backend}
		if sum.Beta != "" {
			// A label only (ruling P-256): the status stays what the plan says.
			label += " (beta)"
			c.Details = append(c.Details, sum.Beta)
		}
		switch {
		case sum.Ready:
			c.Status, c.Message = diag.StatusOK, label+" is set up"
		case sum.Unconfirmed:
			// Doctor reads passive plans only: it can say every step it sees
			// is done, never that the backend's own check passes.
			c.Status, c.Message = diag.StatusOK, label+" is set up (not checked; observer sandbox setup check "+sum.Backend+" confirms it)"
		case sum.Blocked != "":
			c.Status, c.Message = diag.StatusOK, label+" cannot be set up here: "+sum.Blocked
		default:
			c.Status = diag.StatusWarn
			plan, perr := s.Plan(ctx, sum.Backend)
			if perr != nil {
				c.Message = label + " is not set up: " + perr.Error()
				break
			}
			if plan.Next < 0 || plan.Next >= len(plan.Steps) {
				c.Message = label + " is not set up: its check has not passed yet"
				c.Details = append(c.Details, "run: observer sandbox setup check "+sum.Backend)
				break
			}
			next := plan.Steps[plan.Next]
			c.Message = label + " is not set up: next step " + next.Label
			if cmd := sandboxSetupNextCommand(sum.Backend, next); cmd != "" {
				c.Details = append(c.Details, "run: "+cmd)
			} else {
				if next.Reason != "" {
					c.Details = append(c.Details, next.Reason)
				}
				c.Details = append(c.Details, "Observer does not do this step")
				if next.Docs != "" {
					c.Details = append(c.Details, "docs: "+sandboxSetupDocsLink(next.Docs))
				}
			}
		}
		out = append(out, c)
	}
	return out
}
