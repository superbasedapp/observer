// gemini.go — `observer gemini` launcher subcommand.

package main

import (
	"fmt"
	"os"
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
//
// CONDITIONAL since 2026-10-04 (T-345): only the API-key and "gateway" auth
// types read GOOGLE_GEMINI_BASE_URL; Google sign-in goes to the Code Assist
// endpoint and Vertex reads GOOGLE_VERTEX_BASE_URL (installed 0.62.0 bundle).
// The registry gate routes only with GEMINI_API_KEY in the environment.
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
		Short: "Launch Gemini CLI; routes API-key sessions through the observer proxy",
		Long: "Wraps `gemini` (Google Gemini CLI).\n\n" +
			"With GEMINI_API_KEY exported, the launcher points\n" +
			"GOOGLE_GEMINI_BASE_URL at the observer proxy root. The proxy's\n" +
			"Gemini bridge recognizes the generateContent path, forwards to\n" +
			"Google, and captures usageMetadata as accurate token counts.\n\n" +
			"Without GEMINI_API_KEY, Gemini uses your Google sign-in (or\n" +
			"Vertex AI), which never reads that variable, so the launch runs\n" +
			"UNROUTED and says so; the session is captured from Gemini's own\n" +
			"session files instead.\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via gemini's -i/--prompt-interactive\n" +
			"flag (delivery=inject_prompt). See `observer handoff --help`.\n\n" +
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
			// The route is CONDITIONAL (registry ProxyRoute.Gate, T-345):
			// Gemini's Google sign-in and Vertex lanes never read
			// GOOGLE_GEMINI_BASE_URL, and setting it with no key makes a fresh
			// install pick a keyless "gateway" auth instead of offering Google
			// sign-in. Without GEMINI_API_KEY in the environment the launch
			// runs unrouted and says so; presence only, the key is never read.
			route := resolveGatedRoute("gemini-cli", "gemini", resolved, "", args, os.Environ())
			if route.err != nil {
				return route.err
			}
			if route.notice != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), route.notice)
			}
			return runEnvLauncher(envLauncherSpec{
				tool:        "gemini",
				bin:         bin,
				args:        args,
				configPath:  configPath,
				dir:         continueDir,
				proxyURL:    resolved,
				env:         geminiLaunchEnv(route.routed, resolved),
				dbPath:      cfg.Observer.DBPath,
				seedTool:    models.ToolGeminiCLI, // stderr label is "gemini"; sessions.tool stores "gemini-cli"
				unrouted:    !route.routed,        // the notice above already said why
				routeCaveat: route.caveat,
				stderr:      cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "Override the observer proxy URL (default: http://127.0.0.1:<cfg.proxy.port>)")
	cmd.Flags().StringVar(&binPath, "gemini-path", "", "Path to the gemini binary (default: resolve `gemini` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via gemini's -i flag (delivery=inject_prompt). See observer handoff --help.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "gemini-cli")
	resume = registerResumeFlag(cmd, "gemini-cli")
	return cmd
}

// geminiLaunchEnv is the env the launcher injects (a user's own value still
// wins in applyBaseURLEnv). A routed launch points GOOGLE_GEMINI_BASE_URL at
// the proxy ROOT (no /v1: the CLI appends /v1beta/models/<model>:
// generateContent itself); an unrouted one sets nothing, so Gemini keeps its
// own sign-in. Never a key.
func geminiLaunchEnv(routed bool, proxyURL string) map[string]string {
	if !routed {
		return map[string]string{}
	}
	return map[string]string{"GOOGLE_GEMINI_BASE_URL": strings.TrimRight(proxyURL, "/")}
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
