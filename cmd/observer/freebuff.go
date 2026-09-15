// freebuff.go — `observer freebuff` launcher subcommand (Freebuff /
// CodebuffAI, tool key "freebuff").

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newFreebuffCmd implements `observer freebuff` — launches Freebuff (npm
// `freebuff`, the Manicode -> Codebuff -> Freebuff lineage). Its purpose is to
// start/resume a session the dashboard can attach to, and (doc-assisted)
// `--continue-from`.
//
// There is NO --continue-from PROMPT-SEED lane. `freebuff --help`
// (2026-08-18) exposes only a `login` subcommand and `--continue
// [conversation-id]`; there is no positional prompt or `-p` one-shot the
// launcher could inject a distilled handover into (registry Handoff.Inject
// is InjectFile only). So --continue-from is DOC-ASSISTED (the kimi-code /
// hermes precedent): the launcher writes the handover doc to disk and opens
// the freebuff TUI, and you paste the doc as your first message — freebuff
// has no headless one-shot to offer as an alternative either.
//
// NON-PROXIED on purpose. freebuff authenticates to the CodebuffAI backend
// (`freebuff login`) and has no grounded base-URL override reaching the
// observer proxy, so routing it there would be a guess. Token capture is moot:
// Freebuff records no billable usage (see internal/adapter/freebuff), so the
// local adapter emits sessions + actions only. It never touches freebuff's
// stored credentials.
func newFreebuffCmd() *cobra.Command {
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
		Use:   "freebuff [-- freebuff-args...]",
		Short: "Launch Freebuff (CodebuffAI); with --continue-from, write a handover doc and open the TUI (doc-assisted)",
		Long: "Wraps Freebuff (`freebuff`, the CodebuffAI agent). This launcher\n" +
			"is NON-PROXIED — freebuff authenticates to the CodebuffAI backend\n" +
			"and has no grounded base-URL override, so routing it through the\n" +
			"proxy would be a guess. Freebuff records no billable token usage,\n" +
			"so capture is sessions + actions only via observer's local freebuff\n" +
			"adapter.\n\n" +
			"There is NO --continue-from PROMPT-SEED lane: freebuff takes no\n" +
			"positional prompt or one-shot flag to inject a distilled handover\n" +
			"into. With --continue-from <session-id> the launch is DOC-ASSISTED\n" +
			"instead: the launcher writes the handover doc, prints its path for\n" +
			"you to paste, and opens the interactive TUI in the source session's\n" +
			"project root. See docs/session-handoff.md.\n\n" +
			"Use --resume <conversation-id> for freebuff's own native resume.\n\n" +
			"All arguments after the subcommand are forwarded to freebuff. Use\n" +
			"`--` to separate observer flags from freebuff flags:\n" +
			"    observer freebuff -- --continue 2026-08-11T07-07-38.552Z\n\n" +
			"NEVER touches freebuff's stored credentials.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the
			// PTY to the daemon so the dashboard can view/drive this SAME live
			// freebuff session. Incompatible when the launch is headless (the
			// `login` subcommand or a management flag), or when the handoff-fork
			// family is engaged (doc-assisted — no seeded prompt, but still its
			// own family of flags incompatible with a plain attach gate).
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "freebuff",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					freebuffHeadless(args),
				passthrough: append(freebuffAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `freebuff --continue=<id>` — a
			// commander.js OPTIONAL-value flag (joined `=` spelling), the id our
			// stored SessionID verbatim (the chat dir's RFC3339 name).
			// Registry-driven (ResumeSpec IDMechanism "flag:--continue").
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "freebuff", label: "freebuff", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("freebuff", binPath, "--freebuff-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				fork, ferr := forkFromFlags(fromMessage, fromTime)
				if ferr != nil {
					return ferr
				}
				out, cerr := resolveContinueFromDoc(cmd.Context(), configPath, continueFrom, "freebuff", carry, fork)
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer freebuff: continue-from failed: %v\n", cerr)
					return cerr
				}
				fmt.Fprintf(cmd.ErrOrStderr(),
					"observer freebuff: freebuff has no initial-prompt seed — handover written to %s\n", out.DocPath)
				fmt.Fprintf(cmd.ErrOrStderr(),
					"observer freebuff: paste it as your first message in the TUI\n")
				if out.Note != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer freebuff: %s\n", out.Note)
				}
				continueDir = launchDir(out.ProjectRoot)
				if continueDir != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer freebuff: continuing in %s\n", continueDir)
				}
			}

			// Best-effort attribution config: a load failure just disables
			// the launch seed (recordLaunchSeed treats "" as off).
			dbPath := ""
			if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
				dbPath = cfg.Observer.DBPath
			}
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "freebuff", "freebuff", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "freebuff-path", "", "Path to the freebuff binary (default: resolve `freebuff` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover, write it to disk, and open the freebuff TUI (doc-assisted — freebuff has no initial-prompt seed). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "freebuff")
	resume = registerResumeFlag(cmd, "freebuff")
	return cmd
}

// freebuffAttachPassthrough forwards the --freebuff-path wrapper flag to the
// daemon-spawned inner `observer freebuff` launcher when set (nil otherwise).
func freebuffAttachPassthrough(binPath string) []string {
	if binPath != "" {
		return []string{"--freebuff-path", binPath}
	}
	return nil
}

// freebuffHeadless reports whether a forwarded argv runs freebuff
// non-interactively — the `login` management subcommand, or a version/help
// flag. `freebuff --help` (2026-08-18) exposes no `-p`/`--prompt` one-shot, so
// this is a leading-subcommand + flag scan.
func freebuffHeadless(args []string) bool {
	for i, a := range args {
		if a == "--" {
			return false // everything after -- is a positional, not a verb
		}
		switch a {
		case "-h", "--help", "-v", "--version":
			return true
		case "login":
			// Only when it LEADS (the first non-flag operand) — a value forwarded
			// to an earlier flag is not the subcommand.
			if i == 0 {
				return true
			}
		}
	}
	return false
}
