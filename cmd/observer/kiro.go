// kiro.go — `observer kiro` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// kiroContinueSubcommand is the subcommand the `--continue-from` launch
// targets: `kiro-cli chat [INPUT]` is the interactive session, and the
// positional INPUT seeds its first prompt (it lands as the first
// `{"kind":"Prompt"}` record of the flat session bundle — verified live
// 2026-07-09). The launcher ensures this leading subcommand so a seeded
// launch always opens the chat session rather than the top-level command.
const kiroContinueSubcommand = "chat"

// newKiroCmd implements `observer kiro` — launches AWS Kiro CLI
// (`kiro-cli`). Its primary purpose is `--continue-from`: distill a handover
// from a source session and seed it via `kiro-cli chat "<handover>"` (the
// chat subcommand's positional INPUT), so a migration INTO Kiro opens the
// interactive session pre-loaded with the mission.
//
// NON-PROXIED on purpose. Kiro talks to SigV4-signed AWS endpoints with no
// base-URL / BYOK surface (a grounded negative in the integration registry —
// Proxy: nil / RouteStatusNativeExempt); there is nothing to redirect, and
// token capture happens via observer's local kiro-cli dual-store adapter
// (flat session bundles + the conversations_v2 SQLite table), not the proxy.
// So the launcher execs `kiro-cli` with the caller's own environment — it
// never sets an API key or a base URL.
func newKiroCmd() *cobra.Command {
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
		Use:     "kiro [-- kiro-cli-args...]",
		Aliases: []string{"kiro-cli"},
		Short:   "Launch Kiro CLI (kiro-cli); with --continue-from, seed a handover via kiro-cli chat",
		Long: "Wraps AWS's Kiro CLI (`kiro-cli`). Kiro talks to SigV4-signed AWS\n" +
			"endpoints with no base-URL knob, so this launcher is NON-PROXIED —\n" +
			"token capture happens via observer's local kiro-cli dual-store\n" +
			"adapter, not the proxy.\n\n" +
			"Model selection is scoped to the `chat` subcommand: pass\n" +
			"`-- chat --model <m>` to select which model the chat session uses.\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via `kiro-cli chat \"<handover>\"`\n" +
			"(the chat subcommand's positional prompt, delivery=inject_prompt),\n" +
			"so Kiro opens pre-loaded with the mission. See\n" +
			"docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to kiro-cli. Use\n" +
			"`--` to separate observer flags from kiro-cli flags. NEVER touches\n" +
			"API keys or AWS credentials.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (kiro-cli is native-exempt — no proxy
			// env, no escape-hatch flag); kiro's chat is interactive with no
			// headless one-shot leading verb, so the handoff-fork family is the
			// only incompatible mode (the both-TTY guard covers scripted runs).
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "kiro-cli",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime),
				passthrough:  append(kiroAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:     args,
				stderr:       cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `kiro-cli chat --resume-id <id>`
			// (the resume flag lives on the `chat` subcommand).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "kiro", label: "kiro", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("kiro-cli", binPath, "--kiro-cli-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				// A forwarded --no-interactive collides with the seeded launch:
				// it turns `chat [INPUT]` into a headless one-shot that answers
				// and exits instead of opening the session seeded. Fail fast,
				// before the (comparatively expensive) handoff render.
				if forwardedFlagConflict(args, "--no-interactive") {
					err := fmt.Errorf("--continue-from opens an interactive seeded session, but you forwarded --no-interactive — drop it (use `observer handoff` for a file-only carry)")
					fmt.Fprintf(cmd.ErrOrStderr(), "observer kiro: %v\n", err)
					return err
				}
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "kiro-cli",
					label:       "kiro",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// kiro-cli chat takes the seed as its positional INPUT —
					// appended after the forwarded flags. `chat` itself (and
					// its sibling subcommands a user might forward) must not
					// be misread as a competing prompt.
					inject: promptInjection{
						Kind:        injectTrailingPositional,
						Subcommands: kiroSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer kiro: continue-from failed: %v\n", cerr)
					return cerr
				}
				// Ensure the `chat` subcommand leads the argv so the seeded
				// positional opens the interactive session rather than the
				// top-level command.
				args = ensureLeadingSubcommand(seeded, kiroContinueSubcommand)
				continueDir = cwd
			}

			// Best-effort attribution config: a load failure just disables
			// the launch seed (recordLaunchSeed treats "" as off).
			dbPath := ""
			if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
				dbPath = cfg.Observer.DBPath
			}
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "kiro-cli", "kiro-cli", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "kiro-cli-path", "", "Path to the kiro-cli binary (default: resolve `kiro-cli` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via `kiro-cli chat \"<handover>\"` (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "kiro-cli")
	resume = registerResumeFlag(cmd, "kiro-cli")
	return cmd
}

// kiroAttachPassthrough forwards the --kiro-cli-path wrapper flag to the
// daemon-spawned inner `observer kiro` launcher when set (nil otherwise).
func kiroAttachPassthrough(kiroPath string) []string {
	if kiroPath != "" {
		return []string{"--kiro-cli-path", kiroPath}
	}
	return nil
}

// kiroSubcommands are the kiro-cli argv tokens that are subcommands, not a
// prompt — so forwardedPromptConflict does not misread a forwarded `chat`
// (or a sibling verb) as a competing positional prompt.
var kiroSubcommands = map[string]bool{
	"chat": true, "login": true, "logout": true, "whoami": true,
	"profile": true, "settings": true, "diagnostic": true, "doctor": true,
	"issue": true, "update": true, "user": true, "integrations": true,
	"translate": true, "inline": true, "version": true, "help": true,
	"mcp": true, "agent": true,
}
