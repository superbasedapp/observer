//go:build !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// launch_cli.go is `observer launch` and `observer terminals` (decision
// P-228, phase 1b): a scriptable, headless front over the daemon's terminal
// service, reached through the owner-only attach endpoint's control ops
// (internal/attachsock/control.go). Nothing here spawns a process: the
// daemon validates the request with the same rows (internal/agentlaunch),
// walks the dashboard's launch gates and calls termsvc.LaunchFresh. The
// existing launcher verbs (`observer claude`, `--observer-sandbox`) are
// untouched.

// Exit codes of the launch and terminals verbs.
const (
	launchExitOK          = 0
	launchExitFailed      = 1
	launchExitUsage       = 2
	launchExitUnavailable = 3
	launchExitTimeout     = 4
	// launchExitRunFailed: without --detach, the run ended with a non-zero
	// (or unknown) exit code. The tool's own code is in the output
	// (exit_code), never the process's exit status, so it can never be
	// read as one of the codes above.
	launchExitRunFailed = 5
	// launchExitPending: an agent asked for the launch, so the daemon holds
	// it for a human's confirm and nothing runs yet (lane cli-2 fixes-1).
	// The output names the hold's id and the confirm command.
	launchExitPending = 6
	// launchExitInterrupted: Ctrl-C stopped the run (128 + SIGINT).
	launchExitInterrupted = 130
)

// launchExitCodes maps a refusal code onto an exit code; an unlisted code
// is a plain failure.
var launchExitCodes = map[string]int{
	agentlaunch.CodeInvalid:            launchExitUsage,
	attachsock.CodeProtocol:            launchExitUsage,
	attachsock.CodeAmbiguousRun:        launchExitUsage,
	agentlaunch.CodeNotLaunchable:      launchExitUnavailable,
	agentlaunch.CodeSandboxUnavailable: launchExitUnavailable,
	agentlaunch.CodeRefused:            launchExitUnavailable,
	agentlaunch.CodeTooMany:            launchExitUnavailable,
	attachsock.CodeUnsupported:         launchExitUnavailable,
	attachsock.CodeNotFound:            launchExitUnavailable,
	attachsock.CodeNotStoppable:        launchExitUnavailable,
	attachsock.CodeBusy:                launchExitUnavailable,
	codeDaemonUnreachable:              launchExitUnavailable,
	codeDaemonTooOld:                   launchExitUnavailable,
	codeDaemonUnverified:               launchExitUnavailable,
	agentlaunch.CodeConfirmRequired:    launchExitPending,
	agentlaunch.CodeConfirmRefused:     launchExitUnavailable,
	agentlaunch.CodePendingNotFound:    launchExitUnavailable,
	agentlaunch.CodeTooManyPending:     launchExitUnavailable,
	agentlaunch.CodeCallerGone:         launchExitUnavailable,
}

// Client-side codes (no daemon answered).
const (
	codeDaemonUnreachable = "daemon_unreachable"
	codeDaemonTooOld      = "daemon_too_old"
	// codeDaemonUnverified: the endpoint's server is not this user's
	// daemon (Windows pipe identity check, ATT-1); nothing was sent.
	codeDaemonUnverified = "daemon_unverified"
)

// controlCall is the one seam the verbs dial through (tests swap it).
var controlCall = func(ctx context.Context, configPath string, req attachsock.ControlRequest) (attachsock.ControlResult, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return attachsock.ControlResult{}, fmt.Errorf("load config: %w", err)
	}
	endpoint, err := attachEndpoint(cfg.Observer.DBPath)
	if err != nil {
		return attachsock.ControlResult{}, err
	}
	return attachsock.ControlCall(ctx, endpoint, req)
}

// launchOutput is the shared output of the two verbs: a JSON document on
// stdout with --json, else text on stdout and refusals on stderr.
type launchOutput struct {
	json   bool
	stdout io.Writer
	stderr io.Writer
	verb   string
}

// launchErrorJSON is the --json shape of a refusal.
type launchErrorJSON struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// runResultJSON is the --json shape of one run (wait adds timed_out).
type runResultJSON struct {
	attachsock.RunInfo
	TimedOut bool `json:"timed_out,omitempty"`
}

// fail reports err and returns its exit code as an exitErr.
func (o launchOutput) fail(err error) error {
	code, msg := classifyControlErr(err)
	if o.json {
		var e launchErrorJSON
		e.Error.Code, e.Error.Message = code, msg
		o.writeJSON(e)
	} else {
		fmt.Fprintf(o.stderr, "observer %s: %s\n", o.verb, msg)
	}
	if n, ok := launchExitCodes[code]; ok {
		return exitErr(n)
	}
	return exitErr(launchExitFailed)
}

func (o launchOutput) writeJSON(v any) {
	enc := json.NewEncoder(o.stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// classifyControlErr names the closed code and the line of a control error.
func classifyControlErr(err error) (code, msg string) {
	var ce *attachsock.ControlError
	switch {
	case errors.As(err, &ce):
		return ce.Code, ce.Message
	case errors.Is(err, attachsock.ErrServerUnverified):
		return codeDaemonUnverified, err.Error() + "; nothing was sent"
	case errors.Is(err, attachsock.ErrDaemonTooOld):
		return codeDaemonTooOld, err.Error()
	case errors.Is(err, attachsock.ErrDaemonUnreachable):
		return codeDaemonUnreachable, "the observer daemon is not reachable on its attach endpoint; run `observer start` (with [terminal.attach].enabled = true, the default)"
	}
	if c := agentlaunch.CodeOf(err); c != "" {
		return c, err.Error()
	}
	return attachsock.CodeControlFailed, err.Error()
}

// newLaunchCmd builds `observer launch <tool>`.
func newLaunchCmd() *cobra.Command {
	var (
		spec       attachsock.LaunchSpec
		configPath string
		detach     bool
		asJSON     bool
		waitFor    string
		timeout    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "launch <tool>",
		Short: "Launch an agent through the daemon, optionally sandboxed (headless, JSON output)",
		Long: "Launch an AI coding agent as a daemon-owned terminal run, the same launch the\n" +
			"dashboard's New Terminal makes: [terminal.launch] (allow_fresh_agent,\n" +
			"allowed_tools, allowed_project_roots), the organization's terminal and sandbox\n" +
			"policy and the launch gates all apply. <tool> is a tool id (claude-code) or\n" +
			"its launcher verb (claude).\n\n" +
			"--sandbox auto takes an offered, non-beta backend; --sandbox <id> names any\n" +
			"offered backend (see `observer sandbox status`). A requested sandbox that\n" +
			"cannot be built refuses the launch; nothing ever runs unsandboxed instead.\n\n" +
			"With --detach it returns at once with the run id (and the session id once\n" +
			"--wait session sees it). Without --detach it waits for the run to end; Ctrl-C\n" +
			"stops the run. The tool's own exit code is printed (exit_code), and the\n" +
			"command exits 5 when it was not 0. To type into the run,\n" +
			"open it from the dashboard's Terminals page. For an interactive terminal in\n" +
			"this window use `observer <tool>` (and --observer-sandbox) instead.\n\n" +
			"Run by an agent (its process descends from an agent session, or carries\n" +
			"its session marker), the launch is held for a human instead: the command\n" +
			"prints the hold's id and exits 6; a human runs `observer terminals confirm\n" +
			"<id>` (or confirms it on the dashboard's Terminals page) within 10 minutes.\n\n" +
			"Exit codes: 0 launched (or, without --detach, the tool exited 0), 2 usage,\n" +
			"3 refused or not available, 4 wait timed out, 5 the tool exited non-zero or\n" +
			"its exit code is unknown, 6 held for a human's confirm, 130 Ctrl-C stopped\n" +
			"the run, 1 other failure.",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := launchOutput{json: asJSON, stdout: cmd.OutOrStdout(), stderr: cmd.ErrOrStderr(), verb: "launch"}
			spec.Tool = args[0]
			if spec.Project == "" {
				wd, err := os.Getwd()
				if err != nil {
					return out.fail(err)
				}
				spec.Project = wd
			}
			if abs, err := filepath.Abs(spec.Project); err == nil {
				spec.Project = abs
			}
			if waitFor != "" && waitFor != attachsock.WaitSession && waitFor != attachsock.WaitExit {
				return out.fail(&agentlaunch.Error{Code: agentlaunch.CodeInvalid, Field: "wait", Message: "--wait takes session or exit"})
			}
			// The same rows the daemon walks, before dialing it.
			if _, err := agentlaunch.Normalize(agentlaunch.Request{
				Tool: spec.Tool, Project: spec.Project, Sandbox: spec.Sandbox, Workspace: spec.Workspace,
				Remote: spec.Remote, Branch: spec.Branch, Model: spec.Model,
			}); err != nil {
				return out.fail(err)
			}
			// The agent-session hint (lane cli-2): only the allowlisted
			// session-id variable is read. The daemon also judges this
			// process's ancestry itself.
			spec.AgentEnv, spec.AgentEnvSession = agentSessionEnv(os.Getenv)
			return runLaunch(cmd.Context(), out, configPath, spec, detach, waitFor, timeout)
		},
	}
	f := cmd.Flags()
	f.StringVar(&spec.Sandbox, "sandbox", "", "sandbox backend: auto, none, or an offered backend id (default: none)")
	f.StringVar(&spec.Workspace, "workspace", "", "workspace source for a sandboxed run: live (default), clone-local, clone-remote or worktree")
	f.StringVar(&spec.Remote, "remote", "", "clone URL for --workspace clone-remote")
	f.StringVar(&spec.Branch, "branch", "", "branch to check out in a clone or worktree workspace")
	f.StringVar(&spec.Project, "project", "", "project directory (default: the current directory)")
	f.StringVar(&spec.Model, "model", "", "model id for the tool, when it takes one")
	f.BoolVar(&detach, "detach", false, "return as soon as the run starts")
	f.StringVar(&waitFor, "wait", "", "with --detach, wait for the run's session or exit before returning (session|exit)")
	f.DurationVar(&timeout, "timeout", 0, "bound --wait (and the wait without --detach); 0 waits up to the daemon's ceiling (24h)")
	f.BoolVar(&asJSON, "json", false, "print the run as JSON")
	f.StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	return cmd
}

// runLaunch sends the launch, then waits as asked.
func runLaunch(ctx context.Context, out launchOutput, configPath string, spec attachsock.LaunchSpec, detach bool, waitFor string, timeout time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := controlCall(ctx, configPath, attachsock.ControlRequest{Op: "launch", Launch: &spec})
	if err != nil {
		return out.fail(err)
	}
	run := *res.Run
	// An agent's launch is held for a human (lane cli-2 fixes-1): say how a
	// human confirms it and stop; there is nothing to wait on yet.
	if run.State == attachsock.StatePending {
		printRun(out, run, false)
		if !out.json {
			fmt.Fprintf(out.stderr, "observer launch: an agent asked for this launch, so it waits for a human: run `observer terminals confirm %s` in your own terminal, or confirm it on the dashboard's Terminals page, before %s\n", run.PendingID, run.ExpiresAt)
		}
		return exitErr(launchExitPending)
	}
	if detach && waitFor == "" {
		printRun(out, run, false)
		return nil
	}
	if !detach {
		waitFor = attachsock.WaitExit
		if !out.json {
			fmt.Fprintf(out.stderr, "observer launch: run %s started (%s); waiting for it to end, Ctrl-C stops it\n", run.RunID, describeSandbox(run))
		}
		// Ctrl-C stops the run this verb started, then returns.
		sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt)
		defer stop()
		ctx = sigCtx
	}
	wres, werr := controlCall(ctx, configPath, attachsock.ControlRequest{Op: "wait", Run: run.RunID, For: waitFor, Timeout: timeout})
	if werr != nil {
		if !detach && ctx.Err() != nil {
			return stopAfterInterrupt(out, configPath, run)
		}
		return out.fail(werr)
	}
	run = *wres.Run
	printRun(out, run, wres.TimedOut)
	switch {
	case wres.TimedOut:
		return exitErr(launchExitTimeout)
	case !detach && (run.ExitCode == nil || *run.ExitCode != 0):
		return exitErr(launchExitRunFailed)
	}
	return nil
}

// stopAfterInterrupt stops the run after Ctrl-C and reports it.
func stopAfterInterrupt(out launchOutput, configPath string, run attachsock.RunInfo) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := controlCall(ctx, configPath, attachsock.ControlRequest{Op: "stop", Run: run.RunID})
	if err != nil {
		return out.fail(err)
	}
	printRun(out, *res.Run, false)
	return exitErr(launchExitInterrupted)
}

// describeSandbox is the short isolation phrase of a run.
func describeSandbox(r attachsock.RunInfo) string {
	if !r.Sandboxed {
		return "unsandboxed"
	}
	if r.Backend != "" {
		return "sandboxed: " + r.Backend
	}
	return "sandboxed"
}

// printRun prints one run as JSON or as a few labelled lines.
func printRun(out launchOutput, r attachsock.RunInfo, timedOut bool) {
	if out.json {
		out.writeJSON(runResultJSON{RunInfo: r, TimedOut: timedOut})
		return
	}
	tw := tabwriter.NewWriter(out.stdout, 0, 0, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(tw, "%s\t%s\n", k, v)
		}
	}
	row("run", r.RunID)
	row("pending", r.PendingID)
	row("held launch", r.PendingWhat)
	row("confirm before", r.ExpiresAt)
	// Every field the held launch is bound to (fixes-2, M-B).
	for _, d := range r.PendingDetails {
		row("  "+d.Label, pendingDetailValue(d))
	}
	row("handle", r.Handle)
	row("tool", r.Tool)
	row("state", r.State)
	row("session", runCell(r.SessionID))
	row("sandbox", describeSandbox(r))
	row("isolation", r.Isolation)
	row("capture", r.Capture)
	if r.ExitCode != nil {
		row("exit code", fmt.Sprint(*r.ExitCode))
	}
	row("end reason", r.EndReason)
	row("started by", describeInitiator(r))
	row("parent session", r.ParentSessionID)
	row("launched", r.LaunchedAt)
	row("ended", r.EndedAt)
	if timedOut {
		row("wait", "timed out")
	}
	_ = tw.Flush()
}

// initiatorWords are the short phrases of the recorded initiators (lane
// cli-2, migration 220).
var initiatorWords = map[string]string{
	string(termrun.InitiatorHumanDashboard): "you (dashboard)",
	string(termrun.InitiatorHumanCLI):       "you (cli)",
	string(termrun.InitiatorAgent):          "agent",
	string(termrun.InitiatorUnknown):        "unknown",
}

// describeInitiator is who started a run, "" when not recorded.
func describeInitiator(r attachsock.RunInfo) string {
	if w, ok := initiatorWords[r.Initiator]; ok {
		return w
	}
	return r.Initiator
}

// pendingDetailValue is a held launch's detail as the CLI prints it; a
// field to look at twice is marked.
func pendingDetailValue(d attachsock.PendingDetail) string {
	if d.Warn {
		return "! " + d.Value
	}
	return d.Value
}

// runCell renders an empty cell as a hyphen.
func runCell(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// newTerminalsCmd builds `observer terminals ls|show|stop|wait`.
func newTerminalsCmd() *cobra.Command {
	var (
		configPath string
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "terminals",
		Short: "List, inspect, wait on and stop terminal runs (headless, JSON output)",
		Long: "The daemon's terminal runs: the terminals it owns (dashboard New Terminal,\n" +
			"`observer launch`, `observer <tool> --attach`) and the recent run history.\n" +
			"A launch an agent asked for is held for a human (state pending_confirm):\n" +
			"`confirm <pending-id>` starts it, `reject <pending-id>` drops it; a hold is\n" +
			"single use and expires after 10 minutes, and an agent may not confirm.\n" +
			"A run is named by its run id, a unique run-id prefix of at least 6\n" +
			"characters, or its terminal handle.\n\n" +
			"Exit codes: 0 ok, 2 usage, 3 not found or not available, 4 wait timed out,\n" +
			"1 other failure.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.PersistentFlags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	output := func(c *cobra.Command) launchOutput {
		return launchOutput{json: asJSON, stdout: c.OutOrStdout(), stderr: c.ErrOrStderr(), verb: "terminals " + c.Name()}
	}

	var liveOnly bool
	ls := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List terminal runs, live first",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			out := output(c)
			res, err := controlCall(ctxOf(c), configPath, attachsock.ControlRequest{Op: "list"})
			if err != nil {
				return out.fail(err)
			}
			runs := res.Runs
			if liveOnly {
				kept := runs[:0]
				for _, r := range runs {
					if r.Live() {
						kept = append(kept, r)
					}
				}
				runs = kept
			}
			if runs == nil {
				runs = []attachsock.RunInfo{}
			}
			if out.json {
				out.writeJSON(struct {
					Runs []attachsock.RunInfo `json:"runs"`
				}{runs})
				return nil
			}
			printRunTable(out.stdout, runs)
			return nil
		},
	}
	ls.Flags().BoolVar(&liveOnly, "live", false, "only runs whose process is running")

	one := func(use, short, op string) *cobra.Command {
		return &cobra.Command{
			Use:   use + " <run>",
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(c *cobra.Command, args []string) error {
				out := output(c)
				req := attachsock.ControlRequest{Op: op, Run: args[0]}
				// The agent-session hint rides on every op (a confirm is
				// judged like a launch; fixes-2, H-A).
				req.AgentEnv, req.AgentEnvSession = agentSessionEnv(os.Getenv)
				res, err := controlCall(ctxOf(c), configPath, req)
				if err != nil {
					return out.fail(err)
				}
				printRun(out, *res.Run, false)
				return nil
			},
		}
	}
	show := one("show", "Show one run", "show")
	stop := one("stop", "Stop a running terminal this daemon owns (its end records cli_stop)", "stop")
	// Lane cli-2 fixes-1: a launch an agent asked for waits for a human.
	confirm := one("confirm", "Start a launch an agent asked for (a human runs this; an agent is refused)", "confirm")
	confirm.Use = "confirm <pending-id>"
	reject := one("reject", "Drop a launch an agent asked for without starting it", "reject")
	reject.Use = "reject <pending-id>"

	var (
		waitFor string
		timeout time.Duration
	)
	wait := &cobra.Command{
		Use:   "wait <run>",
		Short: "Wait until a run has a session (--for session) or has ended (--for exit, the default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			out := output(c)
			if waitFor != attachsock.WaitSession && waitFor != attachsock.WaitExit {
				return out.fail(&agentlaunch.Error{Code: agentlaunch.CodeInvalid, Field: "for", Message: "--for takes session or exit"})
			}
			res, err := controlCall(ctxOf(c), configPath, attachsock.ControlRequest{Op: "wait", Run: args[0], For: waitFor, Timeout: timeout})
			if err != nil {
				return out.fail(err)
			}
			printRun(out, *res.Run, res.TimedOut)
			if res.TimedOut {
				return exitErr(launchExitTimeout)
			}
			return nil
		},
	}
	wait.Flags().StringVar(&waitFor, "for", attachsock.WaitExit, "session or exit")
	wait.Flags().DurationVar(&timeout, "timeout", 0, "give up after this long (exit 4); 0 waits up to the daemon's ceiling (24h)")

	cmd.AddCommand(ls, show, stop, wait, confirm, reject)
	return cmd
}

func ctxOf(c *cobra.Command) context.Context {
	if ctx := c.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// printRunTable prints the run list as a table.
func printRunTable(w io.Writer, runs []attachsock.RunInfo) {
	if len(runs) == 0 {
		fmt.Fprintln(w, "no terminal runs")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN\tTOOL\tKIND\tSTATE\tSANDBOX\tSTARTED BY\tPARENT\tSESSION\tLAUNCHED")
	for _, r := range runs {
		id := r.RunID
		if r.PendingID != "" {
			id = r.PendingID
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", runCell(id), r.Tool, runCell(r.Kind), r.State, describeSandbox(r),
			runCell(describeInitiator(r)), runCell(r.ParentSessionID), runCell(r.SessionID), runCell(r.LaunchedAt))
	}
	_ = tw.Flush()
	// What each held launch would run, whole (fixes-2, M-B).
	for _, r := range runs {
		if r.PendingID == "" {
			continue
		}
		fmt.Fprintf(w, "\n%s waits for a human: %s\n", r.PendingID, r.PendingWhat)
		for _, d := range r.PendingDetails {
			fmt.Fprintf(w, "  %s: %s\n", d.Label, pendingDetailValue(d))
		}
		fmt.Fprintf(w, "  confirm: observer terminals confirm %s (before %s)\n", r.PendingID, r.ExpiresAt)
	}
}
