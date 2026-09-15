// grok.go — `observer grok` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newGrokCmd implements `observer grok` — launches xAI's Grok Build terminal
// agent (binary `grok`). Its primary purpose is `--continue-from`: distill a
// handover from a source session and seed it as grok's trailing positional
// prompt (`grok "<handover>"` opens an interactive session pre-loaded with
// the mission — seed lane verified live 2026-07-09).
//
// NON-PROXIED BY DEFAULT. Grok speaks OpenAI-Responses-shaped traffic to a
// non-default host (cli-chat-proxy.grok.com) via the observer proxy's
// `/up/grok` upstream seam — a live, working route (RouteStatusRoutableNow
// in the integration registry: an observer-routed turn landed a real
// api_turns row, id 23025). The launcher itself stays non-proxied by
// default — exec inherits the caller's environment unmodified, no base URL
// is set — because routing is opt-in: pass `--proxy` to inject
// GROK_CLI_CHAT_PROXY_BASE_URL and route through the proxy instead. Without
// `--proxy`, token capture happens via observer's local grok adapter (the
// sid-correlated ~/.grok/logs/unified.jsonl splits). It never sets an API
// key.
func newGrokCmd() *cobra.Command {
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
		Use:   "grok [-- grok-args...]",
		Short: "Launch Grok Build; with --continue-from, seed a handover as grok's positional prompt",
		Long: "Wraps xAI's Grok Build terminal agent (`grok`). NON-PROXIED BY\n" +
			"DEFAULT — token capture happens via observer's local grok adapter\n" +
			"(session bundles + the sid-correlated unified.jsonl token log), not\n" +
			"the proxy. Pass --proxy to opt in: this injects\n" +
			"GROK_CLI_CHAT_PROXY_BASE_URL pointed at the observer proxy's\n" +
			"/up/grok upstream (a live, verified route — api_turns id 23025) so\n" +
			"grok's traffic to cli-chat-proxy.grok.com is captured + compressed.\n\n" +
			"grok supports a top-level `--model` flag to select which model\n" +
			"the session uses (pass it after `--` with your other grok args).\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it as grok's trailing positional prompt\n" +
			"(delivery=inject_prompt), so Grok opens an interactive session\n" +
			"pre-loaded with the mission. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to grok. Use `--`\n" +
			"to separate observer flags from grok flags. NEVER touches API keys.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (grok is launched non-proxied — no
			// proxy env, no escape-hatch flag); grok's headless surface is
			// unverified, so the handoff-fork family is the only incompatible mode
			// (the both-TTY guard covers scripted runs).
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "grok",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime),
				passthrough:  append(grokAttachPassthrough(binPath, useProxy), resumeAttachPassthrough(*resume)...),
				toolArgs:     args,
				stderr:       cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `grok --resume <id>` (bare path).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "grok", label: "grok", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("grok", binPath, "--grok-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "grok",
					label:       "grok",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// grok takes the initial prompt as a bare positional
					// (verified live: `grok "<seed>"` opened a seeded
					// interactive session); -p/--prompt is the headless
					// one-shot form and would collide with the seed.
					inject: promptInjection{
						Kind:          injectTrailingPositional,
						ConflictFlags: []string{"-p", "--prompt"},
						Subcommands:   grokSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer grok: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}

			if !useProxy {
				// Best-effort attribution config: a load failure just disables
				// the launch seed (recordLaunchSeed treats "" as off).
				dbPath := ""
				if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
					dbPath = cfg.Observer.DBPath
				}
				return runSeedOnlyLaunchSeeded(configPath, dbPath, "grok", "grok", bin, args, continueDir)
			}
			cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath})
			if cErr != nil {
				return fmt.Errorf("load config: %w", cErr)
			}
			resolved := resolveProxyURL(cfg.Proxy.Port, "")
			return runEnvLauncher(envLauncherSpec{
				tool:       "grok",
				bin:        bin,
				args:       args,
				configPath: configPath,
				dir:        continueDir,
				proxyURL:   resolved,
				env:        map[string]string{"GROK_CLI_CHAT_PROXY_BASE_URL": resolved + "/up/grok/v1"},
				dbPath:     cfg.Observer.DBPath,
				stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "grok-path", "", "Path to the grok binary (default: resolve `grok` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as grok's positional prompt (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	cmd.Flags().BoolVar(&useProxy, "proxy", false, "Opt in to routing grok's traffic through the observer proxy (sets GROK_CLI_CHAT_PROXY_BASE_URL at the proxy's /up/grok upstream). Default off: grok runs with your own environment unmodified and token capture uses the local grok adapter instead.")
	attach, noAttach = registerAttachFlags(cmd, "grok")
	resume = registerResumeFlag(cmd, "grok")
	return cmd
}

// grokAttachPassthrough forwards the --grok-path wrapper flag (when set) and
// the opt-in --proxy flag (when engaged) to the daemon-spawned inner
// `observer grok` launcher, so an attached session honors the same routing
// choice as the operator's original invocation.
func grokAttachPassthrough(grokPath string, useProxy bool) []string {
	var out []string
	if grokPath != "" {
		out = append(out, "--grok-path", grokPath)
	}
	if useProxy {
		out = append(out, "--proxy")
	}
	return out
}

// grokSubcommands are the grok argv tokens that are subcommands, not a
// prompt — so forwardedPromptConflict does not misread a forwarded verb
// (e.g. `grok inspect`) as a competing positional prompt.
var grokSubcommands = map[string]bool{
	"inspect": true, "login": true, "logout": true, "mcp": true,
	"sessions": true, "help": true, "version": true, "update": true,
}
