// zcode.go — `observer zcode` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newZcodeCmd implements `observer zcode` — launches the zcode CLI (binary
// `zcode`, a Z.AI product; an OpenCode fork). Its primary purposes are to
// start/resume a zcode session the dashboard can attach to, and
// `--continue-from`: distill a handover from a source session and seed it via
// zcode's `--prompt` flag.
//
// NON-PROXIED on purpose. zcode authenticates model access via Z.AI OAuth
// (`zcode login`) and exposes no OpenAI-style base-URL env knob (verified
// against `zcode --help`, zcode 0.16.3), so pointing it at the observer proxy
// would be a guess this build does not make (the registry's
// RouteStatusProbeRequired note). The launcher execs `zcode` with the caller's
// own environment; token capture happens via observer's local zcode adapter
// (the model_usage table in ~/.zcode/cli/db/db.sqlite — see
// internal/adapter/zcode). It never touches zcode's stored credentials.
func newZcodeCmd() *cobra.Command {
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
		Use:   "zcode [-- zcode-args...]",
		Short: "Launch the zcode CLI; with --continue-from, seed a handover via zcode's --prompt flag",
		Long: "Wraps the zcode CLI (`zcode`, a Z.AI product; an OpenCode fork).\n" +
			"This launcher is NON-PROXIED — zcode authenticates via Z.AI OAuth\n" +
			"and exposes no OpenAI base-URL knob, so routing it through the\n" +
			"proxy would be a guess. Token capture happens via observer's local\n" +
			"zcode adapter (the model_usage table in the CLI's SQLite store).\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via zcode's --prompt flag\n" +
			"(delivery=inject_prompt). See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to zcode. Use `--`\n" +
			"to separate observer flags from zcode flags:\n" +
			"    observer zcode -- --resume sess_...\n\n" +
			"NEVER touches zcode's stored credentials.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the
			// PTY to the daemon so the dashboard can view/drive this SAME live
			// zcode session. Seed-only spec (non-proxied — no proxy env, no
			// escape-hatch flag). Incompatible when a handoff fork is engaged or
			// the launch is headless / a non-interactive subcommand (login,
			// doctor, version, …) that opens no interactive PTY to attach.
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "zcode",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					zcodeHeadless(args),
				passthrough: append(zcodeAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `zcode --resume <sessionId>` — a
			// FLAG whose value is the session id verbatim (our stored
			// SessionID, zcode's own `sess_<uuid>`). The mapping is registry-
			// driven (ResumeSpec.IDMechanism "flag:--resume").
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "zcode", label: "zcode", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("zcode", binPath, "--zcode-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				// A forwarded non-interactive verb (login/doctor/version/…) or a
				// headless --prompt collides with the seeded interactive launch;
				// fail fast before the (comparatively expensive) handoff render.
				if zcodeHeadless(args) {
					err := fmt.Errorf("--continue-from seeds an INTERACTIVE zcode session, but you forwarded a headless flag/subcommand (e.g. --prompt or `login`) — drop it")
					fmt.Fprintf(cmd.ErrOrStderr(), "observer zcode: %v\n", err)
					return err
				}
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "zcode",
					label:       "zcode",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// zcode's initial prompt is the `--prompt <text>` flag
					// (`zcode --help`: "Run a single prompt without opening the
					// TUI"). The bare command with no prompt opens the TUI, so
					// --prompt is the only conflicting seed target.
					inject: promptInjection{
						Kind:          injectFlagValue,
						Flag:          "--prompt",
						ConflictFlags: []string{"--prompt", "-p", "--print"},
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer zcode: continue-from failed: %v\n", cerr)
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
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "zcode", "zcode", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "zcode-path", "", "Path to the zcode binary (default: resolve `zcode` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via zcode's --prompt flag (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "zcode")
	resume = registerResumeFlag(cmd, "zcode")
	return cmd
}

// zcodeAttachPassthrough forwards the --zcode-path wrapper flag to the
// daemon-spawned inner `observer zcode` launcher when set (nil otherwise).
func zcodeAttachPassthrough(binPath string) []string {
	if binPath != "" {
		return []string{"--zcode-path", binPath}
	}
	return nil
}

// zcodeNonInteractiveSubcommands are zcode's leading verbs that open no
// interactive TUI to attach to (read verbatim off `zcode --help`, zcode
// 0.16.3). `tui` is DELIBERATELY excluded — it opens the interactive UI, so a
// leading `tui` stays attach-compatible.
var zcodeNonInteractiveSubcommands = map[string]bool{
	"app-server": true, "commands": true, "doctor": true,
	"login": true, "logout": true, "plugins": true,
	"skills": true, "version": true,
}

// zcodeHeadless reports whether a forwarded argv opens no fresh interactive
// session — either it leads with a non-interactive subcommand, or it carries a
// headless one-shot prompt flag (`--prompt`, `-p`, `--print`). Such launches
// are attach-incompatible and continue-from-incompatible.
func zcodeHeadless(args []string) bool {
	for _, a := range args {
		switch a {
		case "--prompt", "-p", "--print":
			return true
		}
	}
	for _, a := range args {
		if a == "" || a[0] == '-' {
			continue
		}
		return zcodeNonInteractiveSubcommands[a]
	}
	return false
}
