// gemini.go — `observer gemini` launcher subcommand.

package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// newGeminiCmd implements `observer gemini` — sets GOOGLE_GEMINI_BASE_URL to
// the observer proxy root and execs `gemini` (Google Gemini CLI) so its
// generateContent traffic flows through the proxy for token capture.
//
// Unlike the OpenAI-compatible launchers, the env var points at the proxy
// ROOT (no /v1 suffix): gemini-cli appends the full
// /v1beta/models/<model>:generateContent path itself. The proxy's Phase-E
// Gemini bridge (internal/proxy: providerForPath → ProviderGoogle, the
// generativelanguage upstream, parseGeminiResponse) recognizes that path,
// forwards to generativelanguage.googleapis.com, and parses usageMetadata.
//
// GROUNDED (2026-06-27, live install): gemini-cli honors GOOGLE_GEMINI_BASE_URL
// (confirmed in the @google/gemini-cli module). NEVER touches the API key —
// it rides the request (header / ?key=) untouched.
func newGeminiCmd() *cobra.Command {
	var (
		configPath   string
		proxyURL     string
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
		Use:   "gemini [-- gemini-args...]",
		Short: "Launch Gemini CLI with traffic routed through the observer proxy (probe)",
		Long: "Wraps `gemini` (Google Gemini CLI) with GOOGLE_GEMINI_BASE_URL\n" +
			"pointed at the observer proxy root. The proxy's Gemini bridge\n" +
			"recognizes the generateContent path, forwards to Google, and\n" +
			"captures usageMetadata as accurate token counts.\n\n" +
			"PROBE: confirm a turn lands an api_turns row (provider=google).\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via gemini's -i/--prompt-interactive\n" +
			"flag (delivery=inject_prompt). See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to gemini. Use\n" +
			"`--` to separate observer flags from gemini flags. NEVER touches\n" +
			"the API key. Requires a running observer proxy (`observer start`).",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach-by-default (attach-all-launchers): hand the PTY to the
			// daemon when attach resolves. gemini-cli self-routes via
			// GOOGLE_GEMINI_BASE_URL in the daemon-spawned inner launcher, so
			// forward NO proxy env (attachEnv nil) and no --no-proxy-route flag
			// exists to forward (noProxyRoute nil). A -p/--prompt headless
			// one-shot or the continue-from family forces the bare path. toolArgs
			// is the RAW operator remainder — the inner launcher re-applies its
			// own base-URL injection.
			outcome, err := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:          "gemini-cli",
				configPath:    configPath,
				proxyOverride: proxyURL,
				proxyFlag:     "--proxy",
				flagAttach:    *attach,
				flagNoAttach:  *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsContainHeadlessFlag(args, "-p", "--prompt"),
				passthrough: append(geminiAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return err
			}
			// Native resume: `--resume <id>` → `gemini --resume <uuid>` (bare path;
			// full session UUID honored — verified live v0.49.0).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "gemini", label: "gemini", configPath: configPath, id: *resume,
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
			bin, err := resolveToolBin("gemini-cli", binPath, "--gemini-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "gemini-cli",
					label:       "gemini",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// gemini -i/--prompt-interactive: "Execute the provided
					// prompt and continue in interactive mode." -p/--prompt is
					// the headless one-shot form — flag both as conflicts, plus
					// gemini's bare positional `query` (an initial prompt).
					inject: promptInjection{
						Kind:          injectFlagValue,
						Flag:          "-i",
						ConflictFlags: []string{"-i", "--prompt-interactive", "-p", "--prompt"},
						// gemini's bare positional `query` is itself an initial
						// prompt, so a forwarded positional competes with the
						// seeded handover and must trip the collision check.
						BarePositionalIsPrompt: true,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer gemini: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}
			return runEnvLauncher(envLauncherSpec{
				tool:       "gemini",
				bin:        bin,
				args:       args,
				configPath: configPath,
				dir:        continueDir,
				proxyURL:   resolved,
				// Gemini base URL is the host ROOT (no /v1) — the CLI appends
				// the /v1beta/models/<model>:generateContent path itself.
				env:      map[string]string{"GOOGLE_GEMINI_BASE_URL": strings.TrimRight(resolved, "/")},
				dbPath:   cfg.Observer.DBPath,
				seedTool: models.ToolGeminiCLI, // stderr label is "gemini"; sessions.tool stores "gemini-cli"
				stderr:   cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "Override the observer proxy URL (default: http://127.0.0.1:<cfg.proxy.port>)")
	cmd.Flags().StringVar(&binPath, "gemini-path", "", "Path to the gemini binary (default: resolve `gemini` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via gemini's -i flag (delivery=inject_prompt). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "gemini-cli")
	resume = registerResumeFlag(cmd, "gemini-cli")
	return cmd
}

// geminiAttachPassthrough forwards --gemini-path to the daemon-spawned inner
// `observer gemini` launcher when the operator overrode the binary path; nil
// otherwise.
func geminiAttachPassthrough(binPath string) []string {
	if binPath != "" {
		return []string{"--gemini-path", binPath}
	}
	return nil
}
