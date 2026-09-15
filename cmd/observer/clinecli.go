// clinecli.go — `observer cline-cli` launcher subcommand.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// clineCompatProvider is the cline provider id whose base URL IS configurable
// (the native "openai" provider hardcodes api.openai.com and ignores
// OPENAI_BASE_URL — live-confirmed 2026-06-27; see docs/proxy-routing-blockers.md).
const clineCompatProvider = "openai-compatible"

// newClineCLICmd implements `observer cline-cli` — sets OPENAI_BASE_URL to
// the observer proxy's OpenAI-compatible endpoint and execs the user's
// `cline` (npm `cline` 3.x CLI) binary so its model traffic flows through
// the proxy.
//
// PROBE STATUS (2026-06-26): the live install's providers.json has no
// base-URL key and no config chokepoint to write — but a launch-time
// OPENAI_BASE_URL env MAY redirect it (integration registry: cline-cli
// Routability=probe_required). This launcher is the convenience that lets
// the operator run that probe in one command. Until a live turn confirms an
// api_turns row, the adapter matrix keeps cline-cli's PROXY cell empty
// (SURFACE=probe) — the launcher existing does NOT claim verified routing.
func newClineCLICmd() *cobra.Command {
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
		Use:   "cline-cli [-- cline-args...]",
		Short: "Launch Cline CLI with traffic routed through the observer proxy (probe)",
		Long: "Wraps `cline` (the npm Cline CLI) with OPENAI_BASE_URL pointed at\n" +
			"the observer proxy's OpenAI-compatible endpoint (…/v1).\n\n" +
			"PROBE: cline-cli's honoring of OPENAI_BASE_URL is unconfirmed on a\n" +
			"live install. Run one turn through this launcher, then check that a\n" +
			"new api_turns row appeared (`observer doctor cline-cli` or the\n" +
			"dashboard). The adapter matrix keeps cline-cli's PROXY cell empty\n" +
			"until that verification.\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via cline's -i/--tui interactive\n" +
			"flag (delivery=inject_prompt). See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to cline. Use `--`\n" +
			"to separate observer flags from cline flags. NEVER touches API keys\n" +
			"— your provider credentials must already be in the environment.\n\n" +
			"Requires a running observer proxy (`observer start`).",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach-by-default (attach-all-launchers): hand the PTY to the
			// daemon when attach resolves. cline-cli routes via the
			// openai-compatible provider's persisted baseUrl (applied by the
			// daemon-spawned inner launcher), so forward NO proxy env (attachEnv
			// nil) and no --no-proxy-route flag exists (noProxyRoute nil). A
			// leading utility subcommand (auth/config/…) or the continue-from
			// family forces the bare path — cline's `-p` is `--plan`, NOT a
			// headless-prompt flag, so it is deliberately NOT an incompatible
			// predicate. toolArgs is the RAW operator remainder — the inner
			// launcher re-applies the `-P openai-compatible` provider prepend.
			outcome, err := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:          "cline-cli",
				configPath:    configPath,
				proxyOverride: proxyURL,
				proxyFlag:     "--proxy",
				flagAttach:    *attach,
				flagNoAttach:  *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsLeadWithSubcommand(args, clineSubcommands),
				passthrough: append(clineAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return err
			}
			// Native resume: `--resume <id>` → `cline --id <id>` (LEADS the user
			// args; the `-P openai-compatible` provider select is prepended below).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "cline-cli", label: "cline-cli", configPath: configPath, id: *resume,
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
			bin, err := resolveToolBin("cline-cli", binPath, "--cline-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if err := ensureClineCompatBaseURL(strings.TrimRight(resolved, "/") + "/v1"); err != nil {
				return err
			}
			// Seed the handover onto the RAW user args FIRST, before the
			// `-P openai-compatible` provider selection is prepended. If we
			// injected after the prepend, the bare value `openai-compatible`
			// would trip forwardedPromptConflict and raise a false collision.
			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "cline-cli",
					label:       "cline",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// cline `-i`/`--tui` is a BOOLEAN flag that opens the
					// interactive TUI seeded with the (separate positional)
					// prompt, auto-submitted. `injectFlagValue` emits `-i`
					// then the handover positional. cline's `-p` is `--plan`
					// (NOT a headless-prompt flag) so it is NOT a conflict.
					inject: promptInjection{
						Kind:          injectFlagValue,
						Flag:          "-i",
						ConflictFlags: []string{"-i", "--tui"},
						Subcommands:   clineSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer cline: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}
			// cline routes via the openai-compatible provider's persisted
			// baseUrl, NOT an env var — so select that provider and forward the
			// (possibly seeded) user's args. No env injection.
			return runEnvLauncher(envLauncherSpec{
				tool:       "cline-cli",
				bin:        bin,
				args:       append([]string{"-P", clineCompatProvider}, args...),
				configPath: configPath,
				dir:        continueDir,
				proxyURL:   resolved,
				env:        nil,
				dbPath:     cfg.Observer.DBPath,
				stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "Override the observer proxy URL (default: http://127.0.0.1:<cfg.proxy.port>)")
	cmd.Flags().StringVar(&binPath, "cline-path", "", "Path to the cline binary (default: resolve `cline` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via cline's -i/--tui interactive flag (delivery=inject_prompt). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "cline-cli")
	resume = registerResumeFlag(cmd, "cline-cli")
	return cmd
}

// clineAttachPassthrough forwards --cline-path to the daemon-spawned inner
// `observer cline-cli` launcher when the operator overrode the binary path;
// nil otherwise.
func clineAttachPassthrough(binPath string) []string {
	if binPath != "" {
		return []string{"--cline-path", binPath}
	}
	return nil
}

// clineSubcommands are the cline argv tokens that are subcommands, not a
// forwarded positional prompt — so forwardedPromptConflict does not misread
// e.g. `cline auth` as a two-prompt collision with the seeded handover.
var clineSubcommands = map[string]bool{
	"auth": true, "config": true, "plugin": true, "skill": true,
	"connect": true, "mcp": true, "doctor": true, "history": true,
	"hook": true, "schedule": true, "hub": true, "dashboard": true,
	"update": true, "version": true, "kanban": true,
}

// ensureClineCompatBaseURL points the openai-compatible provider's persisted
// baseUrl at the proxy in ~/.cline/data/settings/providers.json, preserving
// every other field — including the api key, which it NEVER writes. When the
// provider/key isn't set up yet, it returns guidance to run `cline auth` once,
// since the launcher must not supply a secret.
func ensureClineCompatBaseURL(baseURL string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".cline", "data", "settings", "providers.json")
	authHint := fmt.Sprintf("run `cline auth %s -k <key> -m <model> -b %s` once first", clineCompatProvider, baseURL)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cline providers.json not found (%s) — %s", path, authHint)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	providers, _ := root["providers"].(map[string]any)
	entry, _ := providers[clineCompatProvider].(map[string]any)
	if entry == nil {
		return fmt.Errorf("the %q cline provider is not configured — %s", clineCompatProvider, authHint)
	}
	settings, _ := entry["settings"].(map[string]any)
	if settings == nil {
		settings = map[string]any{}
		entry["settings"] = settings
	}
	if settings["baseUrl"] == baseURL {
		return nil // already pointed at the proxy
	}
	settings["baseUrl"] = baseURL
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
