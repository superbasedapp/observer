// copilotcli.go — `observer copilot-cli` launcher subcommand.

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newCopilotCLICmd implements `observer copilot-cli` — launches GitHub Copilot
// CLI, routing it through the observer proxy when the developer uses its BYOK
// (bring-your-own-key) custom-provider lane, then execs `copilot`.
//
// The route is conditional (registry ProxyRoute.Gate, resolveGatedRoute):
//   - no provider key in the environment: the developer is on their GitHub
//     Copilot sign-in, which no base URL can route (COPILOT_PROVIDER_BASE_URL
//     switches Copilot INTO BYOK mode). Launch unrouted, set no
//     COPILOT_PROVIDER_* variable, say so in one line; capture rides the
//     copilot-cli watcher adapter.
//   - a provider key is present: set COPILOT_PROVIDER_TYPE=openai and
//     COPILOT_PROVIDER_BASE_URL=<proxy>/v1. BYOK requires an explicit model
//     (--model, COPILOT_MODEL or COPILOT_PROVIDER_MODEL_ID); without one the
//     launch is refused with a message naming the fix.
//   - COPILOT_PROVIDER_BASE_URL already set to the developer's own endpoint:
//     left alone, unrouted.
//   - COPILOT_PROVIDER_TYPE (or --provider-type) set to anything but openai:
//     the key belongs to that provider, and the route is the proxy's OpenAI
//     lane, so the launch stays unrouted on the developer's own provider
//     settings (pass-2 review C156-19).
//
// It never sets or reads the key's value (implementation rule: a launcher
// writes only base-URL fields, never keys).
func newCopilotCLICmd() *cobra.Command {
	var (
		configPath   string
		proxyURL     string
		binPath      string
		model        string
		continueFrom string
		carry        string
		fromMessage  int
		fromTime     string
		attach       *bool
		noAttach     *bool
		resume       *string
	)
	cmd := &cobra.Command{
		Use:   "copilot-cli [-- copilot-args...]",
		Short: "Launch GitHub Copilot CLI; routes BYOK traffic through the observer proxy",
		Long: "Wraps `copilot` (GitHub Copilot CLI).\n\n" +
			"On your GitHub Copilot sign-in (no provider key set) Copilot runs\n" +
			"UNROUTED: GitHub-hosted traffic cannot be proxied, and the session\n" +
			"is captured from Copilot's own session files instead.\n\n" +
			"With your own provider key in the environment\n" +
			"(COPILOT_PROVIDER_API_KEY, _API_KEY_COMMAND or _BEARER_TOKEN) the\n" +
			"launcher routes Copilot's BYOK lane through the proxy: it sets\n" +
			"COPILOT_PROVIDER_TYPE=openai and COPILOT_PROVIDER_BASE_URL to the\n" +
			"proxy's OpenAI-compatible endpoint (…/v1). BYOK needs an explicit\n" +
			"model: pass --model (sets COPILOT_MODEL) or export COPILOT_MODEL.\n" +
			"A COPILOT_PROVIDER_TYPE other than openai (anthropic, azure, ...)\n" +
			"launches unrouted, so that provider's key never reaches the\n" +
			"proxy's OpenAI lane.\n" +
			"This launcher never sets, reads or moves the key itself.\n\n" +
			"All arguments after the subcommand are forwarded to copilot. Use\n" +
			"`--` to separate observer flags from copilot flags. Requires a\n" +
			"running observer proxy (`observer start`).",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach-by-default (attach-all-launchers): hand the PTY to the
			// daemon when attach resolves. copilot-cli self-routes via the
			// COPILOT_PROVIDER_* env the daemon-spawned inner launcher sets, so
			// forward NO proxy env (attachEnv nil) and no --no-proxy-route flag
			// exists (noProxyRoute nil). A -p/--prompt headless one-shot, a
			// leading utility subcommand (login/mcp/…), or the continue-from
			// family forces the bare path. toolArgs is the RAW operator remainder
			// — the inner launcher re-applies its own env + --model.
			outcome, err := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:          "copilot-cli",
				configPath:    configPath,
				proxyOverride: proxyURL,
				proxyFlag:     "--proxy",
				flagAttach:    *attach,
				flagNoAttach:  *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsContainHeadlessFlag(args, "-p", "--prompt") ||
					argsLeadWithSubcommand(args, copilotSubcommands),
				passthrough: append(copilotAttachPassthrough(binPath, model), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return err
			}
			// Native resume: `--resume <id>` → `copilot --session-id <id>` (bare path).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "copilot-cli", label: "copilot-cli", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			resolved := resolveProxyURL(cfg.Proxy.Port, proxyURL)
			bin, err := resolveToolBin("copilot-cli", binPath, "--copilot-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			// The route is CONDITIONAL (registry ProxyRoute.Gate): the
			// COPILOT_PROVIDER_* lane is BYOK, and setting its base URL
			// switches Copilot off the developer's GitHub sign-in. Without a
			// provider key the launch runs unrouted on that sign-in (capture
			// rides the watcher); with one, a model is required. Presence only:
			// the key's value is never read.
			route := resolveGatedRoute("copilot-cli", "copilot-cli", resolved, model, args, os.Environ())
			if route.err != nil {
				return route.err
			}
			if route.notice != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), route.notice)
			}
			env := copilotLaunchEnv(route.routed, resolved, model)
			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "copilot-cli",
					label:       "copilot",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// copilot -i/--interactive <prompt>: "Start interactive
					// mode and automatically execute this prompt." -p/--prompt
					// is the headless non-interactive form — flag both as
					// conflicts. The prompt rides as the -i VALUE, so no bare
					// positional handling is needed.
					inject: promptInjection{
						Kind:          injectFlagValue,
						Flag:          "-i",
						ConflictFlags: []string{"-i", "--interactive", "-p", "--prompt"},
						Subcommands:   copilotSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer copilot: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}
			return runEnvLauncher(envLauncherSpec{
				tool:       "copilot-cli",
				bin:        bin,
				args:       args,
				configPath: configPath,
				dir:        continueDir,
				proxyURL:   resolved,
				env:        env,
				dbPath:     cfg.Observer.DBPath,
				unrouted:   !route.routed, // the notice above already said why
				stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "Override the observer proxy URL (default: http://127.0.0.1:<cfg.proxy.port>)")
	cmd.Flags().StringVar(&binPath, "copilot-path", "", "Path to the copilot binary (default: resolve `copilot` on PATH)")
	cmd.Flags().StringVar(&model, "model", "", "Set COPILOT_MODEL (the agent model; required for a routed BYOK launch)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via copilot's -i/--interactive flag (delivery=inject_prompt). See observer handoff --help.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "copilot-cli")
	resume = registerResumeFlag(cmd, "copilot-cli")
	return cmd
}

// copilotLaunchEnv is the env the launcher injects (user values still win in
// applyBaseURLEnv). A routed launch gets the BYOK base URL and provider type;
// an unrouted one gets NO COPILOT_PROVIDER_* variable at all, since any of
// them would pull Copilot off the developer's own sign-in. COPILOT_MODEL is
// Copilot's general agent-model variable (`copilot help environment`), so a
// --model value applies on both lanes. Never a key.
func copilotLaunchEnv(routed bool, proxyURL, model string) map[string]string {
	env := map[string]string{}
	if routed {
		env["COPILOT_PROVIDER_TYPE"] = "openai"
		env["COPILOT_PROVIDER_BASE_URL"] = strings.TrimRight(proxyURL, "/") + "/v1"
	}
	if model != "" {
		env["COPILOT_MODEL"] = model
	}
	return env
}

// copilotAttachPassthrough forwards --copilot-path and --model to the
// daemon-spawned inner `observer copilot-cli` launcher when the operator set
// them; nil when neither is set.
func copilotAttachPassthrough(binPath, model string) []string {
	var p []string
	if binPath != "" {
		p = append(p, "--copilot-path", binPath)
	}
	if model != "" {
		p = append(p, "--model", model)
	}
	return p
}

// copilotSubcommands are the copilot argv tokens that are subcommands, not a
// prompt — so continue-from's injection detector does not mistake them for a
// forwarded prompt. Sourced from `copilot --help`.
var copilotSubcommands = map[string]bool{
	"completion": true,
	"help":       true,
	"init":       true,
	"login":      true,
	"logout":     true,
	"mcp":        true,
	"plugin":     true,
	"skill":      true,
	"update":     true,
	"version":    true,
}
