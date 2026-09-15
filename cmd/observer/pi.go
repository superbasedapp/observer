// pi.go — `observer pi` launcher subcommand.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// piProviderName is the custom pi provider entry the launcher ensures in
// models.json. Distinct name so it never collides with pi's built-in
// "openai" provider (which hardcodes api.openai.com and ignores
// OPENAI_BASE_URL — see docs/proxy-routing-blockers.md).
const piProviderName = "observer"

// newPiCmd implements `observer pi` — routes pi (@mariozechner/pi-coding-agent)
// through the observer proxy.
//
// Unlike the env-based launchers (opencode / cline-cli), pi's built-in
// providers IGNORE OPENAI_BASE_URL — confirmed live 2026-06-27 (a dead-port
// base URL still reached OpenAI). pi's documented route is a CUSTOM PROVIDER
// in ~/.pi/agent/models.json carrying an explicit `baseUrl` (docs/models.md).
// This launcher ensures an "observer" provider pointed at the proxy's
// OpenAI-compatible endpoint, then execs `pi --provider observer`. A live
// turn through it lands an api_turns row (verified 2026-06-27, gpt-4o).
//
// NEVER writes a secret: the provider's `apiKey` is the NAME of an env var
// (`OPENAI_API_KEY`), which pi resolves at runtime — the key stays in your
// environment. Provide it via `OPENAI_API_KEY` or pi's `--api-key` flag.
func newPiCmd() *cobra.Command {
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
		Use:   "pi [-- pi-args...]",
		Short: "Launch pi with traffic routed through the observer proxy",
		Long: "Wraps `pi` (@mariozechner/pi-coding-agent) so its model traffic\n" +
			"flows through the observer proxy. pi's built-in providers ignore\n" +
			"OPENAI_BASE_URL, so observer routes it via a custom provider in\n" +
			"~/.pi/agent/models.json (an `observer` provider whose baseUrl is the\n" +
			"proxy's OpenAI-compatible endpoint), then runs `pi --provider " + piProviderName + "`.\n\n" +
			"The provider entry is merged in idempotently — your other pi\n" +
			"providers are preserved. NEVER writes a secret: the provider's\n" +
			"apiKey is the NAME `OPENAI_API_KEY`, which pi resolves from your\n" +
			"environment at runtime. Provide your key via OPENAI_API_KEY or pi's\n" +
			"--api-key flag.\n\n" +
			"All arguments after the subcommand are forwarded to pi. Use `--` to\n" +
			"separate observer flags from pi flags. Requires a running observer\n" +
			"proxy (`observer start`).",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach-by-default (attach-all-launchers): hand the PTY to the
			// daemon when attach resolves. pi routes via the `observer` provider
			// in ~/.pi/agent/models.json (written by the daemon-spawned inner
			// launcher), so forward NO proxy env (attachEnv nil) and no
			// --no-proxy-route flag exists (noProxyRoute nil). pi registers
			// --proxy-url (NOT --proxy), so proxyFlag is "--proxy-url". A
			// -p/--print headless one-shot or the continue-from family forces the
			// bare path. toolArgs is the RAW operator remainder — the inner
			// launcher re-applies the `--provider observer` prepend.
			outcome, err := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:          "pi",
				configPath:    configPath,
				proxyOverride: proxyURL,
				proxyFlag:     "--proxy-url",
				flagAttach:    *attach,
				flagNoAttach:  *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsContainHeadlessFlag(args, "-p", "--print"),
				passthrough: append(piAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return err
			}
			// Native resume: `--resume <id>` → `pi --session <id>` (LEADS the user
			// args; the `--provider observer` select is prepended below).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "pi", label: "pi", configPath: configPath, id: *resume,
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
			bin, err := resolveToolBin("pi", binPath, "--pi-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if err := ensurePiObserverProvider(resolved + "/v1"); err != nil {
				return fmt.Errorf("ensure pi provider: %w", err)
			}
			// Seed the handover into the USER args as a trailing positional
			// BEFORE prepending --provider, so the conflict check sees only
			// the user's own argv (not the injected "--provider observer").
			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "pi",
					label:       "pi",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// pi `[messages...]` seed an interactive session; the
					// headless path is the explicit -p/--print flag.
					inject: promptInjection{Kind: injectTrailingPositional},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer pi: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}
			// Prepend the provider selection; the user's args (plus any
			// seeded prompt) follow (and may override --model / --api-key).
			forwarded := append([]string{"--provider", piProviderName}, args...)
			return runEnvLauncher(envLauncherSpec{
				tool:       "pi",
				bin:        bin,
				args:       forwarded,
				configPath: configPath,
				dir:        continueDir,
				proxyURL:   resolved,
				env:        nil, // pi routes via models.json, not an env var
				dbPath:     cfg.Observer.DBPath,
				stderr:     os.Stderr,
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to observer config.toml")
	cmd.Flags().StringVar(&proxyURL, "proxy-url", "", "override the proxy base URL (default from config)")
	cmd.Flags().StringVar(&binPath, "pi-path", "", "path to the pi binary (default: looked up on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as pi's first prompt (delivery=inject_prompt). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "pi")
	resume = registerResumeFlag(cmd, "pi")
	return cmd
}

// piAttachPassthrough forwards --pi-path to the daemon-spawned inner
// `observer pi` launcher when the operator overrode the binary path; nil
// otherwise.
func piAttachPassthrough(binPath string) []string {
	if binPath != "" {
		return []string{"--pi-path", binPath}
	}
	return nil
}

// ensurePiObserverProvider idempotently writes/merges the `observer` provider
// into ~/.pi/agent/models.json with the given OpenAI-compatible base URL. Any
// existing providers are preserved; only the observer entry is (re)written, so
// repeated runs and a changed proxy port both converge. The apiKey is the env
// var NAME, never a literal key.
func ensurePiObserverProvider(baseURL string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".pi", "agent")
	path := filepath.Join(dir, "models.json")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	root := map[string]any{}
	if data, rerr := os.ReadFile(path); rerr == nil && len(data) > 0 {
		if jerr := json.Unmarshal(data, &root); jerr != nil {
			return fmt.Errorf("parse existing %s: %w", path, jerr)
		}
	} else if rerr != nil && !os.IsNotExist(rerr) {
		return rerr
	}

	providers, _ := root["providers"].(map[string]any)
	if providers == nil {
		providers = map[string]any{}
	}
	providers[piProviderName] = map[string]any{
		"baseUrl": baseURL,
		"api":     "openai-completions",
		"apiKey":  "OPENAI_API_KEY", // env var NAME — pi resolves it; no secret on disk
		"models": []any{
			piModel("gpt-4o", "gpt-4o (observer proxy)"),
			piModel("gpt-4o-mini", "gpt-4o-mini (observer proxy)"),
		},
	}
	root["providers"] = providers

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	// Atomic-ish write: temp + rename so a crash can't truncate the file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// piModel builds one model entry for the observer provider's models list.
func piModel(id, name string) map[string]any {
	return map[string]any{
		"id":            id,
		"name":          name,
		"reasoning":     false,
		"input":         []any{"text"},
		"contextWindow": 128000,
		"maxTokens":     16384,
	}
}
