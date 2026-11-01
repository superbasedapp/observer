// pi.go — `observer pi` launcher subcommand.

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
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
			"The provider entry is merged in for the session and removed again\n" +
			"when pi exits; your other pi providers are preserved. It is not\n" +
			"written over your own provider named `observer`, nor when no key\n" +
			"is available (pi then starts unrouted). NEVER writes a secret: the provider's\n" +
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
			// Sol A5-08: the `observer` provider is session-scoped. It is
			// written only when the child will have a key for it and the
			// name is not the operator's own provider, and it is removed
			// again after pi exits.
			prov, err := preparePiObserverProvider(resolved+"/v1", launcherHasOpenAIKey(args))
			if err != nil {
				return err
			}
			if prov.note != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), prov.note)
			}
			if prov.restore != nil {
				defer func() {
					if rerr := prov.restore(); rerr != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "observer pi: could not remove the session %q provider from %s; remove it by hand if pi lists it\n",
							piProviderName, piModelsDisplay)
					}
				}()
			}
			// T-035: on a managed node, every built-in provider the registry
			// row can cover is pointed at its proxy lane for the session too,
			// so a mid-session provider switch stays on the proxy.
			restoreOverrides, err := applyManagedProviderOverrides(cmd.Context(), configPath, providerOverridesSpec{
				tool: "pi", path: filepath.Join(piAgentDir(), "models.json"), display: piModelsDisplay,
				proxyRoot: resolved, ownName: piProviderName, overrides: integration.ProviderOverridesFor("pi"),
			}, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if restoreOverrides != nil {
				defer restoreOverrides()
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
			// Two decisions, in order. (1) Sol A5-08 above: is the
			// session-scoped `observer` provider in place at all? If not
			// (no key, or the operator's own provider of that name), pi keeps
			// its own selection and the user's args go through untouched.
			// (2) Only when it is: select the observer provider AND a model,
			// because pi refuses `--provider` without `--model` ("--provider
			// requires --model", pi 1.0); the routing decision table picks
			// one or says why it could not (pi_route.go).
			forwarded, routed := args, false
			if prov.routed {
				defProvider, defModel := readPiDefaults(piAgentDir())
				route := piRouteFor(piRouteInputs{
					args:            args,
					defaultProvider: defProvider,
					defaultModel:    defModel,
					providerModels:  piObserverModelIDs(),
				})
				if route.notice != "" {
					fmt.Fprintln(cmd.ErrOrStderr(), "observer pi: "+route.notice)
				}
				forwarded, routed = route.args, route.routed
			}
			return runEnvLauncher(envLauncherSpec{
				tool:       "pi",
				bin:        bin,
				args:       forwarded,
				unrouted:   !routed, // the notice above already said why
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

// piModelsDisplay is how the launcher names pi's models file in terminal
// text: a fixed home-relative spelling, never the resolved absolute path.
const piModelsDisplay = "~/.pi/agent/models.json"

// preparePiObserverProvider puts the session-scoped `observer` provider into
// ~/.pi/agent/models.json (see prepareObserverModelsProvider for the rules:
// only with a credential, never over the operator's own provider of that
// name, removed again after the session). Every other provider is preserved.
// The apiKey is the env var NAME, never a literal key.
// The model list is piObserverModelEntries (pi_route.go), the same list the
// routing decision table picks a model from, default first.
func preparePiObserverProvider(baseURL string, hasCredential bool) (observerModelsRoute, error) {
	dir, derr := piAgentDirErr()
	if derr != nil || dir == "" {
		if derr == nil {
			derr = errors.New("cannot resolve the home directory")
		}
		return observerModelsRoute{}, newVisibleLauncherError(derr,
			"observer pi: cannot locate pi's agent directory to configure its provider ("+derr.Error()+")")
	}
	return prepareObserverModelsProvider(observerModelsProviderSpec{
		tool:          "pi",
		path:          filepath.Join(dir, "models.json"),
		display:       piModelsDisplay,
		name:          piProviderName,
		baseURL:       baseURL,
		models:        piObserverModelEntries(),
		hasCredential: hasCredential,
	})
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
