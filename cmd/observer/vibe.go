// vibe.go — `observer vibe` launcher subcommand (Mistral Code, tool key
// "mistral-code").

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newVibeCmd implements `observer vibe` — launches Mistral Code (binary
// `vibe`). Its primary purposes are to start/resume a session the dashboard
// can attach to, and `--continue-from`: distill a handover from a source
// session and seed it as vibe's bare positional [PROMPT].
//
// NON-PROXIED on purpose. vibe authenticates to the Mistral API via an API
// key (browser sign-in on first launch); its `--base-url`/provider api_base
// override has not been driven through the observer proxy live, so routing it
// there would be a guess. Token capture happens via observer's local
// mistral-code adapter (session_* token stats in meta.json — see
// internal/adapter/mistralcode). It never touches vibe's stored credentials.
func newVibeCmd() *cobra.Command {
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
		Use:   "vibe [-- vibe-args...]",
		Short: "Launch Mistral Code (vibe); with --continue-from, seed a handover as vibe's positional prompt",
		Long: "Wraps Mistral Code (`vibe`). This launcher is NON-PROXIED —\n" +
			"vibe authenticates to the Mistral API via an API key and its\n" +
			"base-url override has never been driven live through the proxy,\n" +
			"so routing it there would be a guess. Token capture happens via\n" +
			"observer's local mistral-code adapter (the session token stats in\n" +
			"meta.json).\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it as vibe's bare positional [PROMPT]\n" +
			"(delivery=inject_prompt). See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to vibe. Use `--`\n" +
			"to separate observer flags from vibe flags:\n" +
			"    observer vibe -- --resume 088a17fc\n\n" +
			"NEVER touches vibe's stored credentials.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the
			// PTY to the daemon so the dashboard can view/drive this SAME live
			// vibe session. Seed-only (non-proxied). Incompatible when a handoff
			// fork is engaged or the launch is headless (`-p`/`--prompt`
			// programmatic mode, or a one-shot management flag) — no fresh
			// interactive PTY to attach.
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "mistral-code",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					vibeHeadless(args),
				passthrough: append(vibeAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `vibe --resume <8hex>` — a FLAG
			// whose value is the session id verbatim (our stored SessionID, the
			// session dir's 8-hex suffix). Registry-driven (ResumeSpec
			// IDMechanism "flag:--resume").
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "vibe", label: "vibe", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("vibe", binPath, "--vibe-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				if vibeHeadless(args) {
					err := fmt.Errorf("--continue-from seeds an INTERACTIVE vibe session, but you forwarded a headless flag (e.g. -p/--prompt) — drop it")
					fmt.Fprintf(cmd.ErrOrStderr(), "observer vibe: %v\n", err)
					return err
				}
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "mistral-code",
					label:       "vibe",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// vibe's initial prompt is a bare trailing positional
					// (`vibe [OPTIONS] [PROMPT]`); the headless one-shot lane is
					// the `-p`/`--prompt` FLAG (handled above), so there is no
					// positional subcommand set to exclude.
					inject: promptInjection{
						Kind: injectTrailingPositional,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer vibe: continue-from failed: %v\n", cerr)
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
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "mistral-code", "vibe", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "vibe-path", "", "Path to the vibe binary (default: resolve `vibe` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as vibe's positional prompt (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "mistral-code")
	resume = registerResumeFlag(cmd, "mistral-code")
	return cmd
}

// vibeAttachPassthrough forwards the --vibe-path wrapper flag to the
// daemon-spawned inner `observer vibe` launcher when set (nil otherwise).
func vibeAttachPassthrough(binPath string) []string {
	if binPath != "" {
		return []string{"--vibe-path", binPath}
	}
	return nil
}

// vibeHeadless reports whether a forwarded argv runs vibe non-interactively
// (the `-p`/`--prompt` programmatic mode, a one-shot management flag, or the
// `mcp` subcommand) — no fresh interactive PTY, so attach- and
// continue-from-incompatible. vibe DOES have one real subcommand: `vibe mcp
// {add,remove}` (confirmed live 2026-08-25 via `vibe mcp --help`), a bare
// positional token rather than a flag, so it needs its own check alongside
// the flag scan.
func vibeHeadless(args []string) bool {
	if len(args) > 0 && args[0] == "mcp" {
		return true
	}
	for _, a := range args {
		switch a {
		case "-p", "--prompt", "--setup", "--check-upgrade", "-v", "--version", "-h", "--help":
			return true
		}
	}
	return false
}
