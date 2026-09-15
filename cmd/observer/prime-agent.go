// prime-agent.go — `observer prime-agent` launcher subcommand.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// primeAgentProviderName is the custom prime-agent provider entry the
// launcher ensures in models.json. Distinct name so it never collides with
// prime-agent's built-in providers.
const primeAgentProviderName = "observer"

// newPrimeAgentCmd implements `observer prime-agent` — routes Prime
// Intellect's Prime Agent CLI (npm package `prime-agent`) through the
// observer proxy.
//
// Prime Agent is a HARD FORK of the same pi-mono upstream `pi` (@mariozechner/
// pi-coding-agent) already routes through cmd/observer/pi.go, and inherited
// the same `~/.prime/agent/models.json` custom-provider file schema (vendor
// docs/models.md: "Add custom providers and models (Ollama, vLLM, LM
// Studio, proxies) via ~/.prime/agent/models.json", with `"api":
// "openai-completions"`) plus the same `--provider <name>` selection flag
// (confirmed in `prime-agent --help`). This launcher writes an "observer"
// provider pointed at the proxy's OpenAI-compatible endpoint, then execs
// `prime-agent --provider observer` — modelled 1:1 on pi.go.
//
// No live turn through this route has landed an api_turns row yet, so the
// internal/integration registry's Proxy cell stays nil until one does
// (checklist §10.1f); this launcher is the grounded structural half of that
// follow-up.
//
// NEVER writes a secret to disk: the observer provider's `apiKey` is the NAME of an env var
// (`OPENAI_API_KEY`), which prime-agent resolves at runtime — the key stays
// in your environment. Provide it via `OPENAI_API_KEY` or prime-agent's
// `--api-key` flag.
func newPrimeAgentCmd() *cobra.Command {
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
		Use:   "prime-agent [-- prime-agent-args...]",
		Short: "Launch Prime Intellect's Prime Agent CLI with traffic routed through the observer proxy",
		Long: "Wraps `prime-agent` (Prime Intellect's Prime Agent CLI) so its\n" +
			"model traffic flows through the observer proxy. Prime Agent is a\n" +
			"hard fork of the pi-mono upstream `pi` already routes through, and\n" +
			"inherited the same custom-provider file schema: observer writes an\n" +
			"`observer` provider into ~/.prime/agent/models.json (baseUrl = the\n" +
			"proxy's OpenAI-compatible endpoint), then runs `prime-agent\n" +
			"--provider " + primeAgentProviderName + "`.\n\n" +
			"The provider entry is merged in idempotently — your other\n" +
			"prime-agent providers are preserved. Never writes a secret directly:\n" +
			"the observer provider's apiKey is the NAME `OPENAI_API_KEY`, which\n" +
			"prime-agent resolves from your environment at runtime. Provide your\n" +
			"key via OPENAI_API_KEY or prime-agent's --api-key flag.\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it as prime-agent's trailing positional\n" +
			"message (delivery=inject_prompt). See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to prime-agent.\n" +
			"Use `--` to separate observer flags from prime-agent flags.\n" +
			"Requires a running observer proxy (`observer start`).",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. prime-agent routes via the `observer` provider in
			// ~/.prime/agent/models.json (written by the daemon-spawned inner
			// launcher), so forward NO proxy env (attachEnv nil) and no
			// --no-proxy-route flag exists (noProxyRoute nil). This launcher
			// registers its own --proxy-url (mirroring pi), so proxyFlag is
			// "--proxy-url". A -p/--print headless one-shot, the continue-from
			// family, or a leading management subcommand
			// (list/attach/stop/…/config) forces the bare path.
			outcome, err := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:          "prime-agent",
				configPath:    configPath,
				proxyOverride: proxyURL,
				proxyFlag:     "--proxy-url",
				flagAttach:    *attach,
				flagNoAttach:  *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsContainHeadlessFlag(args, "-p", "--print") ||
					primeAgentHeadlessScan.leads(args),
				passthrough: append(primeAgentAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return err
			}
			// Native resume: `--resume <id>` → `prime-agent --resume <id>`.
			// `-r, --resume <path|id>` is a REQUIRED-value spelling (angle
			// brackets, not `[path|id]`), so the plain two-token form is
			// unambiguous — no `joined` spelling needed. The id is our stored
			// SessionID verbatim (the `<uuid>.jsonl` filename stem), so no
			// transform. The `--provider observer` select is prepended below.
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "prime-agent", label: "prime-agent", configPath: configPath, id: *resume,
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
			bin, err := resolveToolBin("prime-agent", binPath, "--prime-agent-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if err := ensurePrimeAgentObserverProvider(resolved + "/v1"); err != nil {
				return fmt.Errorf("ensure prime-agent provider: %w", err)
			}
			// Seed the handover into the USER args as a trailing positional
			// BEFORE prepending --provider, so the conflict check sees only
			// the user's own argv (not the injected "--provider observer").
			var continueDir string
			if continueFrom != "" {
				// The headless -p/--print one-shot answers and EXITS, which is
				// the opposite of a seeded interactive continue. The shared
				// two-prompt check only inspects POSITIONALS for the positional
				// injection kinds, so this flag case is the launcher's own
				// guard (the pi/commandcode -p/--print precedent).
				if argsContainHeadlessFlag(args, "-p", "--print") {
					err := fmt.Errorf("--continue-from seeds an INTERACTIVE prime-agent session, but you forwarded the headless -p/--print one-shot — drop it (or run the handover through `prime-agent -p` yourself)")
					fmt.Fprintf(cmd.ErrOrStderr(), "observer prime-agent: %v\n", err)
					return err
				}
				// A forwarded management subcommand (status/doctor/config/…)
				// collides the same way: none of them accepts a fresh message
				// positional the way the bare command does. Fail fast, before
				// the (comparatively expensive) handoff render.
				if verb, bad := primeAgentHeadlessScan.leadingVerb(args); bad {
					err := fmt.Errorf("--continue-from seeds an INTERACTIVE prime-agent session, but you forwarded the subcommand %q — drop it, or run `prime-agent %s` yourself", verb, verb)
					fmt.Fprintf(cmd.ErrOrStderr(), "observer prime-agent: %v\n", err)
					return err
				}
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "prime-agent",
					label:       "prime-agent",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// prime-agent `[message...]` seed an interactive session;
					// the headless path is the explicit -p/--print flag. The
					// subcommand map keeps forwarded management verbs
					// (status/doctor/config/…) legible to the two-prompt check.
					inject: promptInjection{
						Kind:          injectTrailingPositional,
						ConflictFlags: []string{"-p", "--print"},
						Subcommands:   primeAgentSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer prime-agent: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}
			// Prepend the provider selection; the user's args (plus any
			// seeded prompt) follow (and may override --model / --api-key).
			forwarded := append([]string{"--provider", primeAgentProviderName}, args...)
			return runEnvLauncher(envLauncherSpec{
				tool:       "prime-agent",
				bin:        bin,
				args:       forwarded,
				configPath: configPath,
				dir:        continueDir,
				proxyURL:   resolved,
				env:        nil, // prime-agent routes via models.json, not an env var
				dbPath:     cfg.Observer.DBPath,
				stderr:     os.Stderr,
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to observer config.toml")
	cmd.Flags().StringVar(&proxyURL, "proxy-url", "", "override the proxy base URL (default from config)")
	cmd.Flags().StringVar(&binPath, "prime-agent-path", "", "path to the prime-agent binary (default: looked up on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as prime-agent's first message (delivery=inject_prompt). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "prime-agent")
	resume = registerResumeFlag(cmd, "prime-agent")
	return cmd
}

// primeAgentAttachPassthrough forwards --prime-agent-path to the
// daemon-spawned inner `observer prime-agent` launcher when the operator
// overrode the binary path; nil otherwise.
func primeAgentAttachPassthrough(binPath string) []string {
	if binPath != "" {
		return []string{"--prime-agent-path", binPath}
	}
	return nil
}

// ensurePrimeAgentObserverProvider idempotently writes/merges the
// `observer` provider into ~/.prime/agent/models.json with the given
// OpenAI-compatible base URL. Any existing providers are preserved; only
// the observer entry is (re)written, so repeated runs and a changed proxy
// port both converge. The apiKey is the env var NAME, never a literal key.
// Structurally identical to pi.go's ensurePiObserverProvider — same
// upstream file schema.
func ensurePrimeAgentObserverProvider(baseURL string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".prime", "agent")
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
	providers[primeAgentProviderName] = map[string]any{
		"baseUrl": baseURL,
		"api":     "openai-completions",
		"apiKey":  "OPENAI_API_KEY", // env var NAME — prime-agent resolves it; no secret on disk
		"models": []any{
			primeAgentModel("gpt-4o", "gpt-4o (observer proxy)"),
			primeAgentModel("gpt-4o-mini", "gpt-4o-mini (observer proxy)"),
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

// primeAgentModel builds one model entry for the observer provider's models
// list.
func primeAgentModel(id, name string) map[string]any {
	return map[string]any{
		"id":            id,
		"name":          name,
		"reasoning":     false,
		"input":         []any{"text"},
		"contextWindow": 128000,
		"maxTokens":     16384,
	}
}

// primeAgentSubcommands are prime-agent's argv tokens that are subcommands,
// not a message (the `prime-agent --help` Commands block), so
// forwardedPromptConflict does not misread a forwarded verb (e.g.
// `prime-agent status`) as a competing positional message. It is also the
// leading-verb set that makes a launch attach- and continue-from-
// incompatible: `help`/`list`/`stop`/`rename`/`send`/`schedule`/`status`/
// `doctor`/`shutdown`/`package`/`update`/`model`/`session`/`config` are
// one-shot management verbs. `attach` (prime-agent's OWN "attach the
// interactive UI to a background agent" verb — distinct from observer's
// `--attach` flag) and `agents` ("search and open sessions") are grouped
// here too even though they may open an interactive UI: neither accepts a
// FRESH message the way the bare command does, so seeding would not compose
// with them either way.
var primeAgentSubcommands = map[string]bool{
	"help": true, "agents": true, "list": true, "attach": true,
	"stop": true, "rename": true, "send": true, "schedule": true,
	"status": true, "doctor": true, "shutdown": true, "package": true,
	"update": true, "model": true, "session": true, "config": true,
}

// primeAgentValueFlags are prime-agent's SPLIT-value top-level options —
// the `<value>`-REQUIRED spellings, which always consume the following
// token. Read verbatim off `prime-agent --help` (v0.7.0, live install,
// 2026-08-06):
//
//	--mode <text|json|rpc|acp|daemon>  --cwd <dir>  --daemon-socket <path>
//	--provider <name>  --model <id>  --api-key <key>  --models <patterns>
//	--thinking <level>  -r/--resume <path|id>  --fork <path|id>
//	--session-dir <dir>  --goal <objective>  --goal-token-budget <n>
//	-t/--tools <list>  -e/--extension <source>  --skill <path>
//	--prompt-template <path>  --theme <path>  --system-prompt <text>
//	--append-system-prompt <text>  --autonomous-gate <command>
//	--autonomous-gate-retries <n>  --autonomous-gate-timeout-ms <n>
//	--autonomous-max-continuations <n>  --autonomous-max-turns <n>
//	--autonomous-max-tokens <n>  --autonomous-timeout-ms <n>
//
// Without this table the leading-verb guard reads a split VALUE as the
// operand and lets a following subcommand through (see leadingVerbScan).
var primeAgentValueFlags = map[string]bool{
	"--mode": true, "--cwd": true, "--daemon-socket": true,
	"--provider": true, "--model": true, "--api-key": true,
	"--models": true, "--thinking": true, "-r": true, "--resume": true,
	"--fork": true, "--session-dir": true, "--goal": true,
	"--goal-token-budget": true, "-t": true, "--tools": true,
	"-e": true, "--extension": true, "--skill": true,
	"--prompt-template": true, "--theme": true, "--system-prompt": true,
	"--append-system-prompt": true, "--autonomous-gate": true,
	"--autonomous-gate-retries": true, "--autonomous-gate-timeout-ms": true,
	"--autonomous-max-continuations": true, "--autonomous-max-turns": true,
	"--autonomous-max-tokens": true, "--autonomous-timeout-ms": true,
}

// primeAgentBoolFlags are prime-agent's switches — declared with no value
// at all, so they consume nothing (`prime-agent --help`, v0.7.0):
//
//	-p/--print  --offline  --verbose  -nt/--no-tools  -nbt/--no-builtin-tools
//	-ne/--no-extensions  -ns/--no-skills  -np/--no-prompt-templates
//	--no-themes  -nc/--no-context-files  -c/--continue  --no-session
//	--autonomous  -v/--version  -h/--help
var primeAgentBoolFlags = map[string]bool{
	"-p": true, "--print": true, "--offline": true, "--verbose": true,
	"-nt": true, "--no-tools": true, "-nbt": true, "--no-builtin-tools": true,
	"-ne": true, "--no-extensions": true, "-ns": true, "--no-skills": true,
	"-np": true, "--no-prompt-templates": true, "--no-themes": true,
	"-nc": true, "--no-context-files": true, "-c": true, "--continue": true,
	"--no-session": true, "--autonomous": true, "-v": true,
	"--version": true, "-h": true, "--help": true,
}

// primeAgentHeadlessScan is prime-agent's grounded leading-verb guard: the
// subcommand set plus the flag grammar above, so a split-value flag can no
// longer hide a following subcommand in the operand position.
var primeAgentHeadlessScan = leadingVerbScan{
	subs:       primeAgentSubcommands,
	valueFlags: primeAgentValueFlags,
	boolFlags:  primeAgentBoolFlags,
}
