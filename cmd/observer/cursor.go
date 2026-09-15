// cursor.go — `observer cursor` launcher subcommand.

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// cursorSubcommands are the cursor-agent argv tokens that are subcommands
// (from `cursor-agent --help` Commands:), not an initial prompt — so the
// two-prompt collision check does not misread `cursor-agent status` (and
// friends) as a forwarded positional prompt.
var cursorSubcommands = map[string]bool{
	"acp":                         true,
	"automations":                 true,
	"bedrock":                     true,
	"cleanup-install-versions":    true,
	"cloud":                       true,
	"dev":                         true,
	"dev-login":                   true,
	"env":                         true,
	"get-channel":                 true,
	"install-shell-integration":   true,
	"install":                     true,
	"local-worker":                true,
	"uninstall-shell-integration": true,
	"login":                       true,
	"logout":                      true,
	"mcp":                         true,
	"plugin":                      true,
	"record":                      true,
	"repaint-debug":               true,
	"repo":                        true,
	"sandbox":                     true,
	"set-channel":                 true,
	"shell-integration":           true,
	"worker":                      true,
	"worker-server":               true,
	"status":                      true,
	"whoami":                      true,
	"models":                      true,
	"about":                       true,
	"update":                      true,
	"upgrade":                     true,
	"create-chat":                 true,
	"generate-rule":               true,
	"rule":                        true,
	"agent":                       true,
	"gpt-5":                       true,
	"gpt5":                        true,
	"opus":                        true,
	"sonnet":                      true,
	"ls":                          true,
	"resume":                      true,
	"help":                        true,
}

// cursorBudgetMaintenanceSubcommands and cursorBudgetMaintenanceFlags are the
// grounded cursor-agent verbs and flags that do not submit a model request.
// They are DERIVED from the cursor intervention registry row
// (integration.NonBillableLeadingArguments) so this launch gate and the node
// process controller classify one invocation identically. Chat execution,
// resume, worker, rule generation, and agent verbs remain controlled because
// their selected backend cannot pass through Observer's proxy.
var cursorBudgetMaintenanceSubcommands, cursorBudgetMaintenanceFlags = registryMaintenanceVocabulary("cursor")

func cursorBudgetLaunchEvidence(args []string) budgetLaunchEvidence {
	if len(args) == 1 && cursorBudgetMaintenanceFlags[args[0]] {
		return budgetLaunchEvidence{Route: budgetLaunchRouteMaintenance}
	}
	if len(args) > 0 && cursorBudgetMaintenanceSubcommands[args[0]] {
		return budgetLaunchEvidence{Route: budgetLaunchRouteMaintenance}
	}
	return budgetLaunchEvidence{Route: budgetLaunchRouteDirect}
}

// newCursorCmd implements `observer cursor` — a PURE SEEDING wrapper around
// the `cursor-agent` CLI. It does NOT route traffic through the observer
// proxy: cursor talks to its own backend (registry Proxy:nil,
// RouteStatusProbeRequired), so the child inherits the ambient environment
// unchanged (child.Env = os.Environ()). Token capture for cursor is via the
// watcher + chats/store.db adapter + the cursor hook (registered by
// `observer init --cursor`), not the proxy — seeding is orthogonal to
// capture.
//
// With --continue-from <session-id> the launcher distills a handover from
// that session and seeds it as cursor-agent's FIRST interactive prompt via a
// trailing positional: `cursor-agent <args> "<handover>"`. Interactive is
// cursor-agent's default; the headless switch is -p/--print, which this
// launcher never emits, so a bare trailing positional starts a seeded
// interactive session (delivery=inject_prompt). See docs/session-handoff.md.
func newCursorCmd() *cobra.Command {
	var (
		configPath   string
		binPath      string
		continueFrom string
		carry        string
		fromMessage  int
		fromTime     string
		attach       *bool
		noAttach     *bool
		resume       *string
	)
	cmd := &cobra.Command{
		Use:   "cursor [-- cursor-agent-args...]",
		Short: "Launch cursor-agent, optionally seeded with a distilled handover",
		Long: "Wraps the `cursor-agent` CLI as a pure SEEDING launcher. NO proxy\n" +
			"routing — cursor talks to its own backend, so the child inherits\n" +
			"your environment unchanged. Token capture for cursor is via the\n" +
			"cursor hook + the chats/store.db watcher adapter (registered by\n" +
			"`observer init --cursor`), not the proxy.\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it as cursor-agent's first interactive\n" +
			"prompt via a trailing positional (delivery=inject_prompt). cursor's\n" +
			"interactive mode is the default; the headless -p/--print switch is\n" +
			"never emitted. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to cursor-agent.\n" +
			"Use `--` to separate observer flags from cursor-agent flags.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach-by-default (attach-all-launchers): hand the PTY to the
			// daemon when attach resolves. cursor is a PURE SEEDING wrapper with
			// NO proxy routing, so proxyFlag is "" (no proxy override forwarded),
			// attachEnv nil, and no --no-proxy-route flag exists (noProxyRoute
			// nil) — capture stays on the cursor hook + store.db watcher adapter.
			// A -p/--print headless one-shot, a leading utility subcommand
			// (login/status/…), or the continue-from family forces the bare path.
			// toolArgs is the RAW operator remainder.
			outcome, aerr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "cursor",
				configPath:   configPath,
				proxyFlag:    "",
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsContainHeadlessFlag(args, "-p", "--print") ||
					argsLeadWithSubcommand(args, cursorSubcommands),
				passthrough: append(cursorAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aerr
			}

			// Native resume: `--resume <id>` → `cursor-agent --resume <id>`
			// (bare path). The chatId is our SessionID verbatim — no transform.
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "cursor", label: "cursor", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("cursor", binPath, "--cursor-agent-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "cursor",
					label:       "cursor",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// cursor-agent `[prompt...]` seeds an interactive session;
					// the headless path is the explicit -p/--print flag, which
					// this launcher never emits.
					inject: promptInjection{
						Kind:        injectTrailingPositional,
						Subcommands: cursorSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer cursor: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}
			// The maintenance classification above decides WHETHER the gate
			// runs; the executable and argv decide whether a controlled
			// launch can be recovered when it does. cursor-agent has no
			// provable proxy route, so the daemon's attested cutoff over this
			// exact installed surface is its only admission path.
			cursorEvidence := cursorBudgetLaunchEvidence(args)
			cursorEvidence.Executable, cursorEvidence.Arguments = bin, args
			if err := enforceBudgetControlledLaunch(cmd.Context(), configPath, "cursor",
				cursorEvidence); err != nil {
				return err
			}

			allocatedSessionID := ""
			if !continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) {
				var allocationErr error
				args, allocatedSessionID, allocationErr = allocateCursorFreshSession(
					cmd.Context(), bin, continueDir, args,
				)
				if allocationErr != nil {
					return fmt.Errorf("observer cursor: %w", allocationErr)
				}
			}

			child := exec.Command(bin, args...)
			// PURE SEEDING WRAPPER: no proxy env injection. cursor uses its
			// own backend, so the child inherits the ambient environment
			// unchanged.
			child.Env = scrubOOBEnv(os.Environ()) // strip the trusted OOB channel env
			child.Dir = continueDir               // "" inherits the caller's cwd; set by --continue-from to the source project root
			child.Stdin = os.Stdin
			child.Stdout = os.Stdout
			child.Stderr = os.Stderr
			discovery := prepareGenericDiscovery(cmd.Context(), "cursor", continueDir)
			if startErr := child.Start(); startErr != nil {
				return fmt.Errorf("exec cursor-agent: %w", startErr)
			}
			if allocatedSessionID != "" {
				announceOOBSession(allocatedSessionID)
			}
			// Direct process attribution (migration 086): record the child pid
			// now that Start has made it knowable; retract the seed when the
			// child is reaped. Best-effort both ways — a seeding failure never
			// affects the launch (see cmd/observer/launchseed.go).
			dbPath := ""
			if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
				dbPath = cfg.Observer.DBPath
			}
			recordLaunchSeed(dbPath, "cursor", continueDir, child.Process.Pid, cmd.ErrOrStderr())
			// Best-effort generic post-launch session discovery (WS-DISCOVERY):
			// a no-op unless the trusted OOB channel is active AND "cursor"
			// resolves to an adapter that declares session-file watch roots.
			// Cancel the instant the child exits so a window cut short by exit
			// never announces a candidate that only looked unique because the
			// scan stopped early.
			discoverCancel := discovery.start()
			if discoverCancel != nil {
				defer discoverCancel()
			}
			if runErr := child.Wait(); runErr != nil {
				var ee *exec.ExitError
				if errors.As(runErr, &ee) {
					return exitErr(ee.ExitCode())
				}
				return fmt.Errorf("exec cursor-agent: %w", runErr)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&binPath, "cursor-agent-path", "", "Path to the cursor-agent binary (default: resolve `cursor-agent` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as cursor-agent's first prompt (delivery=inject_prompt). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "cursor")
	resume = registerResumeFlag(cmd, "cursor")
	return cmd
}

// cursorAttachPassthrough forwards --cursor-agent-path to the daemon-spawned
// inner `observer cursor` launcher when the operator overrode the binary path;
// nil otherwise.
func cursorAttachPassthrough(binPath string) []string {
	if binPath != "" {
		return []string{"--cursor-agent-path", binPath}
	}
	return nil
}
