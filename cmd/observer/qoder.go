// qoder.go — `observer qoder` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newQoderCmd implements `observer qoder` — launches Alibaba's Qoder CLI
// (binary `qodercli`). Its primary purpose is `--continue-from`: distill a
// handover from a source session and seed it via qoder's
// `-i/--prompt-interactive <text>` flag (verified live 2026-07-09: executes
// the prompt, then stays interactive).
//
// NON-PROXIED on purpose. Qoder talks to the hardcoded api.qoder.com with
// PAT auth and has NO base-URL knob (registry RouteStatusNativeExempt), so
// there is no proxy lane to point at. Session capture happens via observer's
// local qoder adapter (~/.qoder/projects CC-shaped JSONL); note the local
// stores carry no model/token data — that gap is qoder-side, not ours. The
// launcher never touches API keys or auth state.
func newQoderCmd() *cobra.Command {
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
		Use:   "qoder [-- qoder-args...]",
		Short: "Launch Qoder CLI; with --continue-from, seed a handover via qoder's -i flag",
		Long: "Wraps Alibaba's Qoder CLI (binary `qodercli`). This launcher is\n" +
			"NON-PROXIED — qoder has no base-URL knob (hardcoded api.qoder.com),\n" +
			"so there is no proxy lane. Session capture happens via observer's\n" +
			"local qoder adapter; qoder's local stores carry no model or token\n" +
			"data (server-side only).\n\n" +
			"qoder supports a top-level `--model` flag to select which model\n" +
			"the session uses (pass it after `--` with your other qoder args).\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via qoder's -i/--prompt-interactive\n" +
			"flag (delivery=inject_prompt), so Qoder executes the mission prompt\n" +
			"and stays interactive. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to qodercli. Use\n" +
			"`--` to separate observer flags from qoder flags. NEVER touches API\n" +
			"keys or auth state.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (qoder is native-exempt — no proxy
			// env, no escape-hatch flag); incompatible when a handoff fork is
			// engaged or qoder's headless one-shot form is forwarded. Grounded
			// headless spelling here is -p/--print (matching this launcher's
			// ConflictFlags), NOT the -p/--prompt the plan table named.
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "qoder",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsContainHeadlessFlag(args, "-p", "--print"),
				passthrough: append(qoderAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `qodercli --resume <id>` (bare path).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "qoder", label: "qoder", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("qoder", binPath, "--qoder-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "qoder",
					label:       "qoder",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// qoder -i/--prompt-interactive takes the initial prompt
					// as its value; -p/--print is the headless one-shot form —
					// flag all four as conflicts. Qoder's bare positional
					// `[query...]` is ALSO an initial prompt, so a forwarded
					// positional competes with the seed — except the CC-style
					// management verbs (mcp/login/...), which the subcommand
					// map exempts from the collision check.
					inject: promptInjection{
						Kind:                   injectFlagValue,
						Flag:                   "-i",
						ConflictFlags:          []string{"-i", "--prompt-interactive", "-p", "--print"},
						BarePositionalIsPrompt: true,
						Subcommands:            qoderSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer qoder: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}

			// Best-effort attribution config: a load failure just disables
			// the launch seed (recordLaunchSeed treats "" as off).
			dbPath := ""
			if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
				dbPath = cfg.Observer.DBPath
			}
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "qoder", "qoder", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "qoder-path", "", "Path to the qodercli binary (default: resolve `qodercli` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via qoder's -i flag (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "qoder")
	resume = registerResumeFlag(cmd, "qoder")
	return cmd
}

// qoderAttachPassthrough forwards the --qoder-path wrapper flag to the
// daemon-spawned inner `observer qoder` launcher when set (nil otherwise).
func qoderAttachPassthrough(qoderPath string) []string {
	if qoderPath != "" {
		return []string{"--qoder-path", qoderPath}
	}
	return nil
}

// qoderSubcommands are the qodercli argv tokens that are subcommands, not a
// prompt — so forwardedPromptConflict does not misread a forwarded verb
// (e.g. `qoder mcp`) as a competing positional prompt.
var qoderSubcommands = map[string]bool{
	"mcp": true, "plugins": true, "plugin": true, "skills": true,
	"skill": true, "hooks": true, "hook": true, "agents": true,
	"agent": true, "login": true, "commit": true, "rollback": true,
	"update": true, "external": true, "remote-control": true,
	"status": true, "feedback": true, "wiki": true, "help": true,
}
