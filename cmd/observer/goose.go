// goose.go — `observer goose` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// gooseContinueSubcommand is the subcommand the `--continue-from` launch
// targets: `goose run -t "<text>" -s` executes the seeded prompt and then
// stays interactive (`-s/--interactive`, verified live 2026-07-09 on a
// keyed run — the seed landed as the session's first user message). The
// launcher ensures this leading subcommand so a seeded launch always opens
// the run lane rather than the top-level command.
const gooseContinueSubcommand = "run"

// newGooseCmd implements `observer goose` — launches Block's goose agent
// (binary `goose`). Its primary purpose is `--continue-from`: distill a
// handover from a source session and seed it via `goose run -t "<handover>"
// -s` (the run subcommand's --text value, kept interactive by -s).
//
// NON-PROXIED BY DEFAULT. Goose's override surface is OPENAI_HOST (plus
// per-provider host settings in config.yaml), NOT OPENAI_BASE_URL — and
// goose may be pre-configured to a non-OpenAI provider (e.g. openrouter), so
// setting OPENAI_HOST unconditionally would silently redirect that
// provider's traffic. So routing stays opt-in: pass `--proxy` to inject
// OPENAI_HOST at the observer proxy's OpenAI-compatible root (goose appends
// /v1 itself). Without `--proxy`, token capture happens via observer's local
// goose adapter (session-level counts in sessions.db). The launcher never
// touches API keys or ~/.config/goose/secrets.yaml.
func newGooseCmd() *cobra.Command {
	var (
		configPath   string
		binPath      string
		continueFrom string
		carry        string
		fromMessage  int
		fromTime     string
		useProxy     bool
		attach       *bool
		noAttach     *bool
		resume       *string
	)
	cmd := &cobra.Command{
		Use:   "goose [-- goose-args...]",
		Short: "Launch goose; with --continue-from, seed a handover via goose run -t … -s",
		Long: "Wraps Block's goose agent (binary `goose`). NON-PROXIED BY\n" +
			"DEFAULT — token capture happens via observer's local goose\n" +
			"adapter (session-level counts in sessions.db), not the proxy.\n\n" +
			"Pass --proxy to opt in: this sets OPENAI_HOST at the observer\n" +
			"proxy's root (goose appends /v1 itself). WARNING: goose may\n" +
			"already be configured to a non-OpenAI provider (e.g. openrouter)\n" +
			"in config.yaml — --proxy overrides OPENAI_HOST unconditionally\n" +
			"(unless you've already exported it yourself), which redirects\n" +
			"that provider's traffic to the proxy's OpenAI-compatible\n" +
			"upstream. Only pass --proxy when you want goose on OpenAI\n" +
			"through observer.\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via `goose run -t \"<handover>\" -s`\n" +
			"(delivery=inject_prompt), so goose executes the mission prompt and\n" +
			"stays interactive. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to goose. Use\n" +
			"`--` to separate observer flags from goose flags. NEVER touches\n" +
			"API keys or ~/.config/goose/secrets.yaml.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (goose is launched non-proxied — no
			// proxy env, no escape-hatch flag); incompatible when a handoff fork
			// is engaged or a leading `run` subcommand is the headless one-shot
			// form.
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "goose",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsLeadWithSubcommand(args, gooseAttachHeadlessSubcommands),
				passthrough: append(gooseAttachPassthrough(binPath, useProxy), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `goose session --resume
			// --session-id <raw>` (the scoped observer id is stripped to goose's
			// own id by the shared translation).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "goose", label: "goose", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("goose", binPath, "--goose-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				// A forwarded --no-session collides with the seeded launch: it
				// runs the prompt WITHOUT persisting a session, so observer's
				// goose adapter would capture nothing of the continued work.
				// Fail fast, before the (comparatively expensive) handoff
				// render.
				if forwardedFlagConflict(args, "--no-session") {
					err := fmt.Errorf("--continue-from opens a session-persisted seeded run, but you forwarded --no-session — drop it (observer's goose adapter captures via sessions.db)")
					fmt.Fprintf(cmd.ErrOrStderr(), "observer goose: %v\n", err)
					return err
				}
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "goose",
					label:       "goose",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// goose run -t/--text takes the seed as its value; a
					// forwarded -i/--instructions file or --recipe is a
					// competing instruction source. `goose run` takes NO bare
					// positional prompt, so a forwarded positional is not a
					// collision; the subcommand map keeps forwarded top-level
					// verbs legible to the conflict check regardless.
					inject: promptInjection{
						Kind:          injectFlagValue,
						Flag:          "-t",
						ConflictFlags: []string{"-t", "--text", "-i", "--instructions", "--recipe"},
						Subcommands:   gooseSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer goose: continue-from failed: %v\n", cerr)
					return cerr
				}
				// Ensure the `run` subcommand leads the argv, and keep the
				// seeded run interactive (-s) unless the user already
				// forwarded the flag themselves.
				args = ensureLeadingSubcommand(seeded, gooseContinueSubcommand)
				if !forwardedFlagConflict(args, "-s", "--interactive") {
					args = append(args, "-s")
				}
				continueDir = cwd
			}

			if !useProxy {
				// Best-effort attribution config: a load failure just disables
				// the launch seed (recordLaunchSeed treats "" as off).
				dbPath := ""
				if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
					dbPath = cfg.Observer.DBPath
				}
				return runSeedOnlyLaunchSeeded(configPath, dbPath, "goose", "goose", bin, args, continueDir)
			}
			cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath})
			if cErr != nil {
				return fmt.Errorf("load config: %w", cErr)
			}
			resolved := resolveProxyURL(cfg.Proxy.Port, "")
			return runEnvLauncher(envLauncherSpec{
				tool:       "goose",
				bin:        bin,
				args:       args,
				configPath: configPath,
				dir:        continueDir,
				proxyURL:   resolved,
				// Goose wants the HOST ROOT — it appends /v1 itself.
				env:    map[string]string{"OPENAI_HOST": resolved},
				dbPath: cfg.Observer.DBPath,
				stderr: cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "goose-path", "", "Path to the goose binary (default: resolve `goose` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via `goose run -t \"<handover>\" -s` (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	cmd.Flags().BoolVar(&useProxy, "proxy", false, "Opt in to routing goose's traffic through the observer proxy (sets OPENAI_HOST at the proxy's OpenAI-compatible root; goose appends /v1 itself). WARNING: goose may be pre-configured to a non-OpenAI provider (e.g. openrouter) — this overrides OPENAI_HOST unconditionally (unless already set in your env) and redirects that provider's traffic to the proxy. Default off.")
	attach, noAttach = registerAttachFlags(cmd, "goose")
	resume = registerResumeFlag(cmd, "goose")
	return cmd
}

// gooseAttachHeadlessSubcommands are the leading goose subcommands whose
// headless one-shot form cannot compose with attach (`goose run` executes and
// exits, so an attach notice + daemon-owned PTY would be spam).
var gooseAttachHeadlessSubcommands = map[string]bool{"run": true}

// gooseAttachPassthrough forwards the --goose-path wrapper flag (when set)
// and the opt-in --proxy flag (when engaged) to the daemon-spawned inner
// `observer goose` launcher, so an attached session honors the same routing
// choice as the operator's original invocation.
func gooseAttachPassthrough(goosePath string, useProxy bool) []string {
	var out []string
	if goosePath != "" {
		out = append(out, "--goose-path", goosePath)
	}
	if useProxy {
		out = append(out, "--proxy")
	}
	return out
}

// gooseSubcommands are the goose argv tokens that are subcommands, not a
// prompt — so forwardedPromptConflict does not misread a forwarded verb
// (e.g. `goose session`) as a competing positional prompt.
var gooseSubcommands = map[string]bool{
	"configure": true, "info": true, "doctor": true, "mcp": true,
	"acp": true, "serve": true, "session": true, "s": true,
	"project": true, "p": true, "projects": true, "ps": true,
	"run": true, "recipe": true, "skills": true, "plugin": true,
	"schedule": true, "sched": true, "gateway": true, "gw": true,
	"update": true, "term": true, "tui": true, "local-models": true,
	"lm": true, "completion": true, "review": true, "help": true,
}
