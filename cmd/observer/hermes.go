// hermes.go — `observer hermes` launcher subcommand.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// hermesProviderName is the user-config provider entry the launcher ensures
// in ~/.hermes/config.yaml. A distinct name so it never collides with
// hermes' built-in providers (openrouter/nous/custom — see
// docs/proxy-routing-blockers.md). Selected per-invocation via hermes'
// top-level `--provider` flag, which accepts a name from the config's
// `providers:` section (hermes_cli/_parser.py).
const hermesProviderName = "observer"

// hermesDefaultUpstream is the `[proxy.upstreams]` id the observer provider's
// base URL routes through by default. Hermes' canonical aggregator is
// OpenRouter (the operator's live default), and the proxy forwards
// /up/openrouter/api/v1 → https://openrouter.ai (config.toml
// [proxy.upstreams] openrouter). Override with --upstream for a different
// upstream you have wired in observer's config.
const hermesDefaultUpstream = "openrouter"

// hermesDefaultKeyEnv is the env var NAME the observer provider's `key_env`
// points at. hermes reads the actual credential from this env var at
// runtime — the launcher NEVER writes a key to disk. OpenRouter-bound hermes
// reads its key from OPENROUTER_API_KEY by convention; override with
// --key-env to name a different env var.
const hermesDefaultKeyEnv = "OPENROUTER_API_KEY"

// newHermesCmd implements `observer hermes` — routes Hermes Agent (Nous
// Research) through the observer proxy.
//
// Unlike the env-based launchers (opencode / copilot-cli), hermes' NAMED
// providers (openrouter / nous) hardcode their endpoint and IGNORE
// model.base_url / OPENAI_BASE_URL — confirmed live 2026-06-27. hermes'
// routable mechanism is a user-config provider in ~/.hermes/config.yaml's
// `providers:` section carrying an explicit `base_url`, selected per
// invocation via hermes' `--provider` flag. This launcher ensures an
// "observer" provider whose base URL is the proxy's /up/<upstream>/api/v1
// endpoint (so OpenRouter-bound, OpenAI-shaped traffic is captured +
// compressed), then execs `hermes --provider observer`. A live turn through
// the equivalent config landed an api_turns row (verified 2026-06-27,
// provider=openai, nvidia/nemotron-…:free, HTTP 200).
//
// NEVER writes a secret; the provider's `key_env` is the NAME of an env
// var (default OPENROUTER_API_KEY), which hermes resolves at runtime — the
// key stays in your environment. The write is ADDITIVE: only the
// `providers.observer` entry is touched, so your top-level `model:` block
// (default provider/model) is left exactly as-is.
func newHermesCmd() *cobra.Command {
	var (
		configPath   string
		proxyURL     string
		binPath      string
		upstream     string
		keyEnv       string
		continueFrom string
		carry        string
		fromMessage  int
		fromTime     string
		attach       *bool
		noAttach     *bool
		resume       *string
	)
	cmd := &cobra.Command{
		Use:   "hermes [-- hermes-args...]",
		Short: "Launch Hermes Agent with traffic routed through the observer proxy",
		Long: "Wraps `hermes` (Hermes Agent, Nous Research) so its model traffic\n" +
			"flows through the observer proxy. hermes' named providers ignore\n" +
			"model.base_url / OPENAI_BASE_URL, so observer routes it via a\n" +
			"user-config provider in ~/.hermes/config.yaml (an `observer` provider\n" +
			"whose base_url is the proxy's /up/<upstream>/api/v1 endpoint), then\n" +
			"runs `hermes --provider " + hermesProviderName + "`.\n\n" +
			"Because hermes REFUSES a `--provider` without a model on its `-z`\n" +
			"one-shot path, the launcher also supplies `--model` — your own\n" +
			"`model.default` from your hermes config.yaml — unless you passed a\n" +
			"model yourself (`--model`/`-m`/" + hermesEnvModel + "). If no model\n" +
			"can be resolved, the launch runs UNROUTED with a warning rather than\n" +
			"exec'ing an invocation hermes is guaranteed to reject.\n\n" +
			"Which config.yaml? The one hermes itself would open: `HERMES_HOME`\n" +
			"and a `--profile`/`-p <name>` in your hermes args are both honoured,\n" +
			"so the file read and the file written are always the same one.\n\n" +
			"On the `chat` subcommand the two flags are placed AFTER `chat`,\n" +
			"because chat's own parser re-declares `--model`/`--provider` and\n" +
			"would otherwise discard top-level values.\n\n" +
			"The provider entry is merged in ADDITIVELY — your top-level `model:`\n" +
			"block and other providers are preserved. NEVER writes a secret; the " +
			"provider's `key_env` is the NAME `" + hermesDefaultKeyEnv + "` (override\n" +
			"with --key-env), which hermes resolves from your environment at\n" +
			"runtime. Export your OpenRouter key under that name before running.\n\n" +
			"Routing requires a matching `[proxy.upstreams]` entry in observer's\n" +
			"config.toml (default upstream `" + hermesDefaultUpstream + "`). All\n" +
			"arguments after the subcommand are forwarded to hermes. Use `--` to\n" +
			"separate observer flags from hermes flags. Requires a running\n" +
			"observer proxy (`observer start`).",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach-by-default (attach-all-launchers): hand the PTY to the
			// daemon when attach resolves. hermes routes via the `observer`
			// provider in ~/.hermes/config.yaml (written by the daemon-spawned
			// inner launcher), so forward NO proxy env (attachEnv nil) and no
			// --no-proxy-route flag exists (noProxyRoute nil). hermes registers
			// --proxy-url (NOT --proxy), so proxyFlag is "--proxy-url"; the inner
			// launcher's --upstream/--key-env are forwarded only when overridden
			// off their defaults. A -z headless one-shot or the continue-from
			// family (a DocAssisted TUI open) forces the bare path. toolArgs is
			// the RAW operator remainder — the inner launcher re-applies the
			// `--provider observer` prepend.
			outcome, err := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:          "hermes",
				configPath:    configPath,
				proxyOverride: proxyURL,
				proxyFlag:     "--proxy-url",
				flagAttach:    *attach,
				flagNoAttach:  *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					hermesArgsAreHeadless(args),
				passthrough: append(hermesAttachPassthrough(binPath, upstream, keyEnv), resumeAttachPassthrough(*resume)...),
				// hermes' credential-env NAME is DYNAMIC (`--key-env`): the
				// registry AuthEnv row carries only the OPENROUTER_API_KEY
				// default, so a non-default --key-env NAME is forwarded as an
				// extra key here. mergeAuthKeys dedupes, so the default value is
				// a harmless no-op (already in the row).
				authEnvExtra: hermesAuthEnvExtra(keyEnv),
				toolArgs:     args,
				stderr:       cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return err
			}
			// Native resume: `--resume <id>` → `hermes --resume <id>` (LEADS the
			// user args; the `--provider observer` route select is prepended
			// below, so resume composes with proxy routing).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "hermes", label: "hermes", configPath: configPath, id: *resume,
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
			bin, err := resolveToolBin("hermes", binPath, "--hermes-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			// Resolve hermes' OWN home the way hermes does (HERMES_HOME →
			// `--profile`/`-p` → sticky active_profile → platform default —
			// hermesResolveHome) so the config we READ the default model from
			// and the one we WRITE providers.observer into are the SAME file
			// hermes will open. Resolved ONCE here and threaded to both call
			// sites; resolving twice is how they could drift.
			cfgPath, cfgPathErr := hermesConfigPath(args)
			// A read failure is not fatal: it degrades to the unrouted row,
			// which warns and launches.
			cfgModel := ""
			if cfgPathErr == nil {
				if m, merr := hermesConfiguredModel(cfgPath); merr == nil {
					cfgModel = m
				}
			}
			route := hermesRouteFor(hermesRouteInputs{
				args:        args,
				envModel:    os.Getenv(hermesEnvModel),
				configModel: cfgModel,
			})
			if route.notice != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "observer hermes: %s\n", route.notice)
			}
			if !route.routed {
				// runEnvLauncher prints "routing via <proxy>" when the proxy is
				// reachable and a not-reachable warning when it is not — so the
				// disclaimer must not promise a specific line is coming. State
				// the fact instead: whatever follows, THIS launch does not use
				// the proxy.
				fmt.Fprintf(cmd.ErrOrStderr(),
					"observer hermes: this run is NOT proxy-routed — any proxy address named below is observer's configured proxy, not a route this launch takes\n")
			}
			if route.ensureProvider {
				if cfgPathErr != nil {
					return fmt.Errorf("resolve hermes config path: %w", cfgPathErr)
				}
				providerBase := strings.TrimRight(resolved, "/") + "/up/" + upstream + "/api/v1"
				if err := ensureHermesObserverProvider(cfgPath, providerBase, keyEnv); err != nil {
					return fmt.Errorf("ensure hermes provider: %w", err)
				}
			}
			forwarded := route.args

			// --continue-from: hermes' TUI takes NO initial-prompt seed (its
			// only prompt entry points, -z/--oneshot and `chat -q`, are
			// headless one-shots — upstream gap, Issue #19675). So this is a
			// DocAssisted launch: write the handover doc (file lane), print a
			// pointer, and open the interactive TUI (`--tui`) for the user to
			// reference/paste. The launch stays proxy-routed (hermes routes
			// via config.yaml, no --local stall like openclaw).
			var continueDir string
			if continueFrom != "" {
				fork, ferr := forkFromFlags(fromMessage, fromTime)
				if ferr != nil {
					return ferr
				}
				out, cerr := resolveContinueFromDoc(cmd.Context(), configPath, continueFrom, "hermes", carry, fork)
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer hermes: continue-from failed: %v\n", cerr)
					return cerr
				}
				fmt.Fprintf(cmd.ErrOrStderr(),
					"observer hermes: TUI has no initial-prompt seed — handover written to %s\n", out.DocPath)
				fmt.Fprintf(cmd.ErrOrStderr(),
					"observer hermes: paste it as your first message in the TUI, or run `hermes -z \"$(cat %s)\"` for a headless one-shot\n", out.DocPath)
				if out.Note != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer hermes: %s\n", out.Note)
				}
				forwarded = ensureHermesTUIFlag(forwarded)
				continueDir = launchDir(out.ProjectRoot)
				if continueDir != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer hermes: continuing in %s\n", continueDir)
				}
			}
			return runEnvLauncher(envLauncherSpec{
				tool:       "hermes",
				bin:        bin,
				args:       forwarded,
				configPath: configPath,
				dir:        continueDir,
				proxyURL:   resolved,
				env:        nil, // hermes routes via config.yaml, not an env var
				dbPath:     cfg.Observer.DBPath,
				stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to observer config.toml")
	cmd.Flags().StringVar(&proxyURL, "proxy-url", "", "override the proxy base URL (default from config)")
	cmd.Flags().StringVar(&binPath, "hermes-path", "", "path to the hermes binary (default: looked up on PATH)")
	cmd.Flags().StringVar(&upstream, "upstream", hermesDefaultUpstream, "the [proxy.upstreams] id to route through")
	cmd.Flags().StringVar(&keyEnv, "key-env", hermesDefaultKeyEnv, "env var NAME hermes reads the provider key from (never written to disk)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover, write it to disk, and open `hermes --tui` (doc-assisted — hermes' TUI has no initial-prompt seed). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "hermes")
	resume = registerResumeFlag(cmd, "hermes")
	return cmd
}

// hermesAttachPassthrough forwards the hermes wrapper flags to the
// daemon-spawned inner `observer hermes` launcher: --hermes-path when the
// operator overrode the binary path, and --upstream/--key-env only when they
// differ from their defaults (so an unchanged default is not re-asserted).
func hermesAttachPassthrough(binPath, upstream, keyEnv string) []string {
	var p []string
	if binPath != "" {
		p = append(p, "--hermes-path", binPath)
	}
	if upstream != hermesDefaultUpstream {
		p = append(p, "--upstream", upstream)
	}
	if keyEnv != hermesDefaultKeyEnv {
		p = append(p, "--key-env", keyEnv)
	}
	return p
}

// hermesAuthEnvExtra returns the DYNAMIC credential-env NAME to forward for an
// attach launch: the operator's `--key-env NAME` when it differs from the
// OPENROUTER_API_KEY default (which the static registry AuthEnv row already
// carries), else nil. mergeAuthKeys dedupes, so returning the default here would
// be a no-op too — this just keeps the intent explicit and the extra slice
// minimal.
func hermesAuthEnvExtra(keyEnv string) []string {
	if keyEnv == "" || keyEnv == hermesDefaultKeyEnv {
		return nil
	}
	// Defense in depth: a malformed NAME (containing '=' or whitespace) can
	// never match a real environ key, so forwarding it would be a silent
	// no-op anyway — refuse it here so the extra slice stays names-only like
	// the registry rows TestAuthEnvWellFormed pins.
	if strings.ContainsAny(keyEnv, "= \t") {
		return nil
	}
	return []string{keyEnv}
}

// ensureHermesTUIFlag appends `--tui` to args unless it (or the HERMES_TUI
// env override's flag form) is already present, so a DocAssisted
// --continue-from launch opens the interactive terminal UI rather than
// dropping to hermes' default non-TUI mode.
func ensureHermesTUIFlag(args []string) []string {
	for _, a := range args {
		if a == "--tui" {
			return args
		}
	}
	return append(args, "--tui")
}

// hermesEnvModel is the env var hermes itself accepts as a model override
// (hermes_cli/_parser.py: "--model … Also settable via HERMES_INFERENCE_MODEL").
// When the operator has exported it, hermes already has a model and the
// launcher must NOT inject a second one.
const hermesEnvModel = "HERMES_INFERENCE_MODEL"

// hermesRouteInputs are the injected facts hermesRouteFor walks. Pure values —
// the config read and the env lookup happen in the caller so the decision stays
// testable without touching the operator's real ~/.hermes.
type hermesRouteInputs struct {
	// args is the operator's raw `--` remainder, forwarded to hermes.
	args []string
	// envModel is the caller's HERMES_INFERENCE_MODEL ("" = unset).
	envModel string
	// configModel is hermes' own configured default (model.default in
	// hermes' config.yaml; "" = unresolvable).
	configModel string

	// scanArgs is the sub-slice of args whose --model/--provider tokens
	// argparse actually honours, and injectAt the index they must be spliced
	// in at. Both are derived by normalized() and are ONLY non-trivial for a
	// `chat` subcommand: chat's subparser RE-DECLARES -m/--model and
	// --provider with plain None defaults, so a top-level value placed BEFORE
	// the `chat` token is silently overwritten with None (proven against
	// hermes' real parser: `--provider observer --model D chat -q hi` →
	// model=None provider=None). For chat, only tokens AFTER `chat` count and
	// injection must land after it too.
	scanArgs []string
	injectAt int
}

// normalized resolves the scan window + injection point (see the scanArgs
// field comment) and returns a copy. Called once at the top of hermesRouteFor
// so every rule sees the same argparse-faithful view.
func (in hermesRouteInputs) normalized() hermesRouteInputs {
	in.scanArgs, in.injectAt = in.args, 0
	if ci := hermesChatIndex(in.args); ci >= 0 {
		in.scanArgs, in.injectAt = in.args[ci+1:], ci+1
	}
	return in
}

// hermesRoute is the resolved per-invocation routing decision: the exact argv
// handed to hermes, whether the `providers.observer` entry must be written, and
// an optional one-line stderr notice.
type hermesRoute struct {
	args           []string // full argv for hermes (provider/model prepends + operator args)
	ensureProvider bool     // write providers.observer into ~/.hermes/config.yaml
	routed         bool     // this launch flows through the observer provider
	notice         string   // one stderr line; "" = silent
}

// hermesRouteRule is one row of the ordered decision table below.
type hermesRouteRule struct {
	name string
	when func(hermesRouteInputs) bool
	then func(hermesRouteInputs) hermesRoute
}

// hermesRouteRules is the ordered routing-decision table (CLAUDE.md #5 — a data
// table walked top-down, first match wins), fixing the bug where the launcher
// injected `--provider observer` with NO model:
//
//	hermes -z: --provider requires --model (or HERMES_INFERENCE_MODEL).
//	Pass both explicitly, or neither to use your configured defaults.
//
// enforced in hermes_cli/oneshot.py::run_oneshot. Natively the operator passes
// NEITHER flag, so hermes uses its configured defaults — which is exactly why
// "works natively, fails wrapped".
//
//  0. operator passed their OWN --provider (foreign, or blank/valueless)
//     → forward untouched, NOT routed, notice
//  1. a model is already supplied (--model / -m / HERMES_INFERENCE_MODEL)
//     → inject --provider only, routed
//  2. a model flag with a BLANK value and no env model
//     → forward untouched, NOT routed, notice (argparse last-wins makes it
//     unfixable by injection — see the row)
//  3. hermes' configured default resolves → inject --provider AND --model <default>, routed
//  4. otherwise (no model resolvable)      → forward untouched, NOT routed, notice
//
// "Inject" is a splice, not always a prepend: on the `chat` subcommand the
// flags go AFTER the `chat` token, because chat's subparser re-declares
// -m/--model and --provider with plain None defaults and would discard
// top-level values (see hermesRouteInputs.scanArgs).
//
// Rows 2 and 4 are the deliberate FAIL-OPEN choice: injecting `--provider` without a
// model is a launch that is GUARANTEED to fail on the -z path, and refusing to
// launch would break an invocation that works natively. So the launcher drops
// its own routing (reproducing the native command exactly) and says so loudly —
// the operator loses proxy capture for that run, not the run itself. This
// mirrors the launcher discipline elsewhere (attach gate fails open; an
// unreachable proxy warns and still execs).
//
// `--model` is chosen over exporting HERMES_INFERENCE_MODEL because it is the
// more deterministic lever: on the -z path oneshot.py reads `model or env`, and
// on the --tui path main.py::_launch_tui copies `--model` INTO
// HERMES_MODEL/HERMES_INFERENCE_MODEL anyway — so the flag subsumes the env var,
// while the reverse is not true (tui_gateway/server.py::_config_model_target,
// the per-turn config sync, reads config.yaml and ignores the env var).
var hermesRouteRules = []hermesRouteRule{
	{
		name: "provider-supplied",
		when: func(in hermesRouteInputs) bool {
			f := hermesFlagValue(in.scanArgs, "--provider")
			return f.present && strings.TrimSpace(f.value) != hermesProviderName
		},
		then: func(in hermesRouteInputs) hermesRoute {
			name := strings.TrimSpace(hermesFlagValue(in.scanArgs, "--provider").value)
			if name == "" {
				// A bare/blank `--provider` (a typo, or `--provider ""`). It is
				// NOT a foreign provider selection, so don't name one: argparse
				// either refuses the invocation outright (no value to consume)
				// or hands hermes an empty string that falls back to the
				// configured provider. Either way observer is not selected.
				return hermesRoute{
					args: in.args,
					notice: "`--provider` supplied with no value — hermes will either reject the invocation or fall " +
						"back to your configured provider, so this run is NOT proxy-routed; drop it to route through observer",
				}
			}
			return hermesRoute{
				args: in.args,
				notice: "--provider " + name + " supplied — leaving it alone; this run is NOT proxy-routed " +
					"(drop --provider to route through observer)",
			}
		},
	},
	{
		name: "model-supplied",
		when: func(in hermesRouteInputs) bool {
			return hermesHasModelArg(in.scanArgs) || strings.TrimSpace(in.envModel) != ""
		},
		then: func(in hermesRouteInputs) hermesRoute {
			return hermesRoute{
				args:           hermesInject(in.args, in.injectAt, hermesProviderFlags(in)...),
				ensureProvider: true,
				routed:         true,
			}
		},
	},
	{
		// A model flag WITH A BLANK VALUE, and no HERMES_INFERENCE_MODEL to
		// stand in for it. hermes' guard tests `(model or "").strip()`, so the
		// blank is as good as absent to hermes — but we cannot fix it by
		// injecting a real model either: argparse is LAST-WINS and the blank
		// comes after our prepend (proven: `--provider observer --model D
		// --model "" -z hi` → model=''), which is precisely the `exit 2` this
		// table exists to prevent. Rewriting the operator's own tokens is not
		// something a launcher should do, so take the same fail-open row as
		// "no-model": reproduce the native command (which works — with no
		// provider selected, hermes resolves the blank to its own default) and
		// say loudly that this one is not captured.
		name: "blank-model",
		when: func(in hermesRouteInputs) bool {
			f := hermesFlagValue(in.scanArgs, "--model", "-m")
			return f.present && strings.TrimSpace(f.value) == ""
		},
		then: func(in hermesRouteInputs) hermesRoute {
			return hermesRoute{
				args: in.args,
				notice: "an EMPTY `--model`/`-m` value was supplied — hermes rejects a provider paired with a blank " +
					"model, and argparse's last-wins means observer cannot substitute one, so this run is NOT " +
					"proxy-routed; drop the empty flag (or give it a real model id) to route it",
			}
		},
	},
	{
		name: "config-default",
		when: func(in hermesRouteInputs) bool { return strings.TrimSpace(in.configModel) != "" },
		then: func(in hermesRouteInputs) hermesRoute {
			flags := append(hermesProviderFlags(in), "--model", strings.TrimSpace(in.configModel))
			return hermesRoute{
				args:           hermesInject(in.args, in.injectAt, flags...),
				ensureProvider: true,
				routed:         true,
			}
		},
	},
	{
		name: "no-model",
		when: func(hermesRouteInputs) bool { return true },
		then: func(in hermesRouteInputs) hermesRoute {
			return hermesRoute{
				args: in.args,
				notice: "could not resolve a model (no --model, no " + hermesEnvModel +
					", no model.default in hermes' config.yaml) — hermes needs one whenever a provider is " +
					"selected, so this run is NOT proxy-routed; pass `--model <id>` (or run `hermes setup`) to route it",
			}
		},
	},
}

// hermesRouteFor walks hermesRouteRules top-down and returns the first matching
// row's route. The final row matches unconditionally, so a route is always
// returned.
func hermesRouteFor(in hermesRouteInputs) hermesRoute {
	in = in.normalized()
	for _, rule := range hermesRouteRules {
		if rule.when(in) {
			return rule.then(in)
		}
	}
	return hermesRoute{args: in.args}
}

// hermesProviderFlags returns the `--provider observer` pair to inject, or nil
// when the operator already selected that same provider themselves in the
// window argparse honours (no duplicate flag).
func hermesProviderFlags(in hermesRouteInputs) []string {
	if f := hermesFlagValue(in.scanArgs, "--provider"); f.present && strings.TrimSpace(f.value) == hermesProviderName {
		return nil
	}
	return []string{"--provider", hermesProviderName}
}

// hermesInject splices flags into args at index at, returning a NEW slice (the
// operator's own args are never aliased or mutated). at is 0 for a normal
// invocation — the flags lead, exactly as before — and the index just past a
// `chat` subcommand token when one is present, because chat's subparser
// overwrites any value it did not parse itself (see hermesRouteInputs.scanArgs).
func hermesInject(args []string, at int, flags ...string) []string {
	if at < 0 || at > len(args) {
		at = 0
	}
	out := make([]string, 0, len(args)+len(flags))
	out = append(out, args[:at]...)
	out = append(out, flags...)
	out = append(out, args[at:]...)
	return out
}

// hermesHasModelArg reports whether the operator already passed hermes a model
// flag WITH A USABLE VALUE, in any spelling argparse accepts (`--model X`,
// `--model=X`, `-m X`, an unambiguous abbreviation like `--mod X`).
//
// A blank value (`--model ""`, `--model=`, a trailing `--model` with nothing
// after it) counts as ABSENT: hermes' one-shot guard tests
// `(model or "").strip()`, so a blank model with a provider selected is the
// exact `exit 2` this whole decision table exists to prevent
// (hermes_cli/oneshot.py::run_oneshot). Treating it as absent lets the
// config-default row supply a real model instead. This matches how envModel /
// configModel are already TrimSpace'd.
func hermesHasModelArg(args []string) bool {
	f := hermesFlagValue(args, "--model", "-m")
	return f.present && strings.TrimSpace(f.value) != ""
}

// hermesArgsAreHeadless reports whether the operator's args select a
// NON-INTERACTIVE hermes run, which must never be handed to a daemon-owned
// PTY by the attach gate. Two shapes: the top-level one-shot in either
// spelling (`-z` / `--oneshot`, incl. the `=`-joined form — the long alias
// used to slip through and a scripted `observer hermes -- --oneshot "…"` got
// attached), and `chat -q/--query`, chat's own single-query mode.
func hermesArgsAreHeadless(args []string) bool {
	if argsContainHeadlessFlag(args, "-z", "--oneshot") {
		return true
	}
	if ci := hermesChatIndex(args); ci >= 0 {
		return hermesFlagValue(args[ci+1:], "--query", "-q").present
	}
	return false
}

// hermesLongOptions are the long options hermes' top-level and `chat` parsers
// register (probed live against hermes_cli/_parser.py::build_top_level_parser,
// 2026-07-25). The list exists for ONE purpose: deciding whether an
// ABBREVIATION is unambiguous. argparse accepts any unambiguous prefix of a
// long option, so `--prov openrouter` really does set provider=openrouter
// (proven). A scanner matching only the full spelling let such a run escape the
// provider-supplied guard, get `--provider observer` injected anyway, and then
// lose to argparse's last-wins — "routing via" printed, nothing captured.
//
// `--profile` is deliberately ABSENT: hermes strips it BEFORE argparse
// (hermes_cli/main.py::_apply_profile_override matches only the exact
// spellings), so argparse never sees it and it can never make a `--pro…`
// prefix ambiguous. Listing it here would resurrect exactly the escape this
// guards against.
var hermesLongOptions = []string{
	"--accept-hooks", "--checkpoints", "--cli", "--continue", "--dev", "--help",
	"--ignore-rules", "--ignore-user-config", "--image", "--max-turns", "--model",
	"--oneshot", "--pass-session-id", "--provider", "--query", "--quiet",
	"--resume", "--safe-mode", "--skills", "--source", "--toolsets", "--tui",
	"--verbose", "--version", "--worktree", "--yolo",
}

// hermesFlag is one recognised flag occurrence.
type hermesFlag struct {
	present  bool   // the flag appeared at all
	value    string // its value ("" when hasValue is false)
	hasValue bool   // a value token or `=` payload followed it
}

// hermesFlagValue scans args for a long option — spelled in full, `=`-joined,
// or as an unambiguous argparse abbreviation — plus any short aliases, and
// returns the LAST occurrence (argparse is last-wins). A flag with nothing
// after it reports present with hasValue false. Scanning STOPS at a bare `--`:
// tokens after it are positional prompt text, not flags (mirrors
// argsContainHeadlessFlag).
func hermesFlagValue(args []string, long string, shorts ...string) hermesFlag {
	var out hermesFlag
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, joined, hasJoin := strings.Cut(a, "=")
		matched := false
		if strings.HasPrefix(name, "--") {
			matched = name == long || hermesIsAbbrevOf(name, long)
		} else {
			for _, s := range shorts {
				if name == s {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}
		switch {
		case hasJoin:
			out = hermesFlag{present: true, value: joined, hasValue: true}
		case i+1 < len(args) && !strings.HasPrefix(args[i+1], "-"):
			// argparse refuses to swallow an option-looking token as a value
			// ("expected one argument"), so neither do we: `--provider -z hi`
			// is a VALUELESS --provider, not a provider named "-z".
			out = hermesFlag{present: true, value: args[i+1], hasValue: true}
			i++ // consume the value so it is never re-read as a flag
		default:
			out = hermesFlag{present: true}
		}
	}
	return out
}

// hermesIsAbbrevOf reports whether name is an argparse-legal abbreviation of
// long: a strict prefix that no OTHER known long option also prefixes. An
// ambiguous prefix (`--p` → --pass-session-id / --provider) matches nothing,
// exactly as argparse refuses it.
func hermesIsAbbrevOf(name, long string) bool {
	if len(name) <= len("--") || !strings.HasPrefix(long, name) {
		return false
	}
	for _, o := range hermesLongOptions {
		if o != long && strings.HasPrefix(o, name) {
			return false
		}
	}
	return true
}

// hermesValueFlags mirrors hermes_cli/main.py::_apply_profile_override's
// `value_flags`: flags whose VALUE token must be skipped when walking argv
// looking for a `--profile`/`-p` selector or a subcommand, so a value is never
// misread as either.
var hermesValueFlags = map[string]bool{
	"-z":         true,
	"--oneshot":  true,
	"-m":         true,
	"--model":    true,
	"--provider": true,
	"-t":         true,
	"--toolsets": true,
	"-r":         true,
	"--resume":   true,
	"-s":         true,
	"--skills":   true,
}

// hermesOptionalValueFlags mirrors the same function's `optional_value_flags`
// — flags whose next token is a value only when it does not itself look like a
// flag.
var hermesOptionalValueFlags = map[string]bool{"-c": true, "--continue": true}

// hermesSkipValue reports how many tokens to advance past args[i] when it is a
// value-taking flag (2), else 1 — the shared walk step of the profile and
// subcommand scanners.
func hermesSkipValue(args []string, i int) int {
	a := args[i]
	if strings.Contains(a, "=") || i+1 >= len(args) {
		return 1
	}
	if hermesValueFlags[a] {
		return 2
	}
	if hermesOptionalValueFlags[a] && !strings.HasPrefix(args[i+1], "-") {
		return 2
	}
	return 1
}

// hermesChatIndex returns the index of a `chat` SUBCOMMAND token in args, or
// -1 when the invocation has no subcommand or a different one. The walk skips
// value-taking flags (so `-z chat` is a PROMPT, not a subcommand) and stops at
// a bare `--`.
func hermesChatIndex(args []string) int {
	for i := 0; i < len(args); {
		a := args[i]
		if a == "--" {
			return -1
		}
		if strings.HasPrefix(a, "-") {
			if a == "-p" || a == "--profile" {
				// The profile selector takes a value too; it is not in
				// hermesValueFlags because that set exists to find IT.
				if !strings.Contains(a, "=") && i+1 < len(args) {
					i += 2
					continue
				}
			}
			i += hermesSkipValue(args, i)
			continue
		}
		if a == "chat" {
			return i
		}
		return -1 // some other subcommand
	}
	return -1
}

// hermesProfileIDRe mirrors hermes_cli/profiles.py::_PROFILE_ID_RE.
var hermesProfileIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// hermesProfileArg returns the profile name the operator selected with
// `--profile <name>` / `-p <name>` / `--profile=<name>`, or "".
//
// It mirrors hermes_cli/main.py::_apply_profile_override, which pre-parses
// these out of sys.argv BEFORE argparse and points HERMES_HOME at
// <root>/profiles/<name>. Same walk, same first-match-wins break, same
// value-flag skipping, same `mcp add --args` passthrough carve-out, and the
// same rejection of a `-p <value>` that cannot be a profile id.
func hermesProfileArg(args []string) string {
	for i := 0; i < len(args); {
		a := args[i]
		if a == "--" {
			return ""
		}
		if a == "--args" && hermesInsideMCPAdd(args, i) {
			return "" // command-argv passthrough: flags past here are the child's
		}
		if (a == "--profile" || a == "-p") && i+1 < len(args) {
			name := args[i+1]
			if !hermesProfileIDRe.MatchString(name) {
				return "" // hermes drops it too, and does NOT resume scanning
			}
			return name
		}
		if strings.HasPrefix(a, "--profile=") {
			return strings.TrimPrefix(a, "--profile=")
		}
		i += hermesSkipValue(args, i)
	}
	return ""
}

// hermesInsideMCPAdd reports whether args reaches `mcp add … --args` by index
// idx, mirroring _apply_profile_override's _inside_mcp_add_args carve-out.
func hermesInsideMCPAdd(args []string, idx int) bool {
	mcp := -1
	for i := 0; i < idx && i < len(args); i++ {
		if args[i] == "mcp" {
			mcp = i
			break
		}
	}
	if mcp < 0 {
		return false
	}
	for i := mcp + 1; i < idx && i < len(args); i++ {
		if args[i] == "add" {
			return true
		}
	}
	return false
}

// hermesHomeEnv is the env var hermes resolves its home directory from
// (hermes_constants.get_hermes_home).
const hermesHomeEnv = "HERMES_HOME"

// hermesHomeInputs are the injected facts hermesResolveHome walks — the env,
// the user's home, and the operator's args. Injected rather than read inline
// so the resolution is testable without touching the operator's real
// ~/.hermes.
type hermesHomeInputs struct {
	args         []string // the operator's `--` remainder (scanned for --profile/-p)
	env          string   // HERMES_HOME as-set ("" = unset)
	userHome     string   // os.UserHomeDir()
	localAppData string   // %LOCALAPPDATA% (Windows only)
	windows      bool     // runtime.GOOS == "windows"
}

// hermesPlatformDefaultHome mirrors
// hermes_constants._get_platform_default_hermes_home: ~/.hermes on POSIX,
// %LOCALAPPDATA%\hermes (falling back to ~/AppData/Local/hermes) on Windows.
func hermesPlatformDefaultHome(in hermesHomeInputs) string {
	if in.windows {
		base := strings.TrimSpace(in.localAppData)
		if base == "" {
			base = filepath.Join(in.userHome, "AppData", "Local")
		}
		return filepath.Join(base, "hermes")
	}
	return filepath.Join(in.userHome, ".hermes")
}

// hermesDefaultRoot mirrors hermes_constants.get_default_hermes_root — the
// directory profiles live under. It is the platform default unless HERMES_HOME
// points OUTSIDE it (a Docker/custom deployment), in which case HERMES_HOME is
// the root — or its grandparent when HERMES_HOME is itself a
// <root>/profiles/<name> path.
func hermesDefaultRoot(in hermesHomeInputs) string {
	native := hermesPlatformDefaultHome(in)
	if in.env == "" {
		return native
	}
	if hermesPathUnder(in.env, native) {
		return native
	}
	if filepath.Base(filepath.Dir(in.env)) == "profiles" {
		return filepath.Dir(filepath.Dir(in.env))
	}
	return in.env
}

// hermesResolveHome resolves hermes' home directory the way hermes itself does
// — hermes_cli/main.py::_apply_profile_override followed by
// hermes_constants.get_hermes_home:
//
//  1. an explicit `--profile`/`-p` in the args wins;
//  2. else an HERMES_HOME that already points AT a profile dir
//     (<…>/profiles/<name>) is trusted as-is;
//  3. else the sticky <root>/active_profile marker selects a profile;
//  4. else HERMES_HOME if set;
//  5. else the platform default.
//
// Getting this wrong is not cosmetic: the launcher would READ the default
// home's model and WRITE providers.observer there while hermes opened a
// different config — so the run went direct-and-uncaptured under a "routing
// via …" banner, with the OTHER home's model silently substituted.
func hermesResolveHome(in hermesHomeInputs) string {
	profile := hermesProfileArg(in.args)
	env := strings.TrimSpace(in.env)
	if profile == "" && in.env != "" && filepath.Base(filepath.Dir(in.env)) == "profiles" {
		return env
	}
	root := hermesDefaultRoot(in)
	if profile == "" {
		// Sticky profile: `hermes profile use <name>` writes this marker, and
		// every later bare `hermes` invocation follows it.
		if b, err := os.ReadFile(filepath.Join(root, "active_profile")); err == nil { //nolint:gosec // path derived from the operator's own home
			if name := strings.TrimSpace(string(b)); name != "" && !strings.EqualFold(name, "default") {
				profile = name
			}
		}
	}
	if canon, ok := hermesCanonProfile(profile); ok {
		if canon == "default" {
			return root
		}
		return filepath.Join(root, "profiles", canon)
	}
	if env != "" {
		return env
	}
	return hermesPlatformDefaultHome(in)
}

// hermesCanonProfile normalizes a profile name the way
// hermes_cli/profiles.py::normalize_profile_name + validate_profile_name do
// (trim, case-fold `default`, lowercase, id regex). ok is false for "" or a
// name hermes itself would refuse.
func hermesCanonProfile(name string) (string, bool) {
	s := strings.TrimSpace(name)
	if s == "" {
		return "", false
	}
	if strings.EqualFold(s, "default") {
		return "default", true
	}
	s = strings.ToLower(s)
	if !hermesProfileIDRe.MatchString(s) {
		return "", false
	}
	return s, true
}

// hermesPathUnder reports whether child is parent or lives beneath it,
// mirroring pathlib's `resolve().relative_to()` test.
func hermesPathUnder(child, parent string) bool {
	rel, err := filepath.Rel(hermesResolvePath(parent), hermesResolvePath(child))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// hermesResolvePath best-effort canonicalizes p (symlinks then absolute),
// degrading to a lexical clean for paths that do not exist yet.
func hermesResolvePath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

// hermesConfigPathFor returns the config.yaml inside a resolved hermes home.
func hermesConfigPathFor(home string) string {
	return filepath.Join(home, "config.yaml")
}

// hermesConfigPath returns the path to the hermes config.yaml THIS invocation
// will use, honouring HERMES_HOME and a `--profile`/`-p` in args
// (hermesResolveHome). args is the operator's `--` remainder.
func hermesConfigPath(args []string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("hermesConfigPath: %w", err)
	}
	return hermesConfigPathFor(hermesResolveHome(hermesHomeInputs{
		args:         args,
		env:          os.Getenv(hermesHomeEnv),
		userHome:     home,
		localAppData: os.Getenv("LOCALAPPDATA"),
		windows:      runtime.GOOS == "windows",
	})), nil
}

// hermesConfiguredModel reads hermes' own configured default model out of the
// config.yaml at path, mirroring hermes_cli/oneshot.py's resolution order:
// `model.default` → `model.model` → a scalar `model:` string. Returns "" with a
// nil error when the file parses but carries no default, so the caller can take
// the unrouted row rather than treat it as a failure.
func hermesConfiguredModel(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator's own config path
	if err != nil {
		return "", fmt.Errorf("hermesConfiguredModel: %w", err)
	}
	var doc struct {
		Model any `yaml:"model"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("hermesConfiguredModel: parse %s: %w", path, err)
	}
	switch m := doc.Model.(type) {
	case string:
		return strings.TrimSpace(m), nil
	case map[string]any:
		for _, key := range []string{"default", "model"} {
			if s, ok := m[key].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s), nil
			}
		}
	}
	return "", nil
}

// ensureHermesObserverProvider idempotently adds/merges the `observer`
// provider into the config.yaml at path (resolved ONCE by the caller via
// hermesConfigPath so the file written is the same one the model was read
// from — and the same one hermes will open). The edit is ADDITIVE — only
// the providers.observer entry is written; every other key (the top-level
// model block, other providers) is preserved, so repeated runs and a changed
// proxy port both converge without disturbing the operator's defaults. The
// config is reserialized via yaml.v3 (a whole-file rewrite, same discipline
// this function established), backed up to config.yaml.bak first. The
// key_env value is the env var NAME, never a literal key.
func ensureHermesObserverProvider(path, baseURL, keyEnv string) error {
	data, rerr := os.ReadFile(path) //nolint:gosec // operator's own config path
	if rerr != nil {
		// hermes must be configured first — we don't author a fresh config
		// (it would lack the operator's model/provider defaults).
		return fmt.Errorf("hermes config.yaml not found (%s) — run `hermes setup` once first: %w", path, rerr)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}

	providers, _ := doc["providers"].(map[string]any)
	if providers == nil {
		providers = map[string]any{}
	}
	providers[hermesProviderName] = map[string]any{
		"name":      "Observer Proxy",
		"base_url":  baseURL,
		"key_env":   keyEnv, // env var NAME — hermes resolves it; no secret on disk
		"transport": "openai_chat",
	}
	doc["providers"] = providers

	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	// Back up before the rewrite (yaml reserialization is lossier than JSON;
	// same .bak-before-overwrite discipline used elsewhere) so the
	// operator's prior config is recoverable.
	if err := os.WriteFile(path+".bak", data, 0o600); err != nil {
		return fmt.Errorf("backup %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return os.Rename(tmp, path)
}
