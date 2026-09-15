// openinterpreter.go — `observer open-interpreter` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newOpenInterpreterCmd implements `observer open-interpreter` (alias
// `interpreter`) — launches Open Interpreter (binary `interpreter`), a
// rebadged OpenAI Codex CLI Rust build installed under ~/.openinterpreter.
// Its primary purpose is `--continue-from`: distill a handover from a source
// session and seed it as the trailing positional prompt (`interpreter
// "<handover>"`), the codex-shaped contract this fork's OWN help confirms:
// `Usage: interpreter [OPTIONS] [PROMPT]` / `[PROMPT]  Optional user prompt
// to start the session`.
//
// NON-PROXIED on purpose — and deliberately NOT a copy of `observer codex`'s
// argv `-c openai_base_url=…` injection. The fork's config schema carries the
// same base_url/wire_api strings, but no observer-routed turn has confirmed
// api_turns capture on it (RouteStatusProbeRequired in the integration
// registry), and injecting a base URL that has never been probed would
// silently break a working session. So the launcher execs `interpreter` with
// the caller's own environment; token capture happens via observer's local
// open-interpreter adapter (the codex parser retagged over
// ~/.openinterpreter/sessions rollouts). It never touches API keys or
// ~/.openinterpreter/auth.json.
func newOpenInterpreterCmd() *cobra.Command {
	var (
		configPath   string
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
		Use:     "open-interpreter [-- interpreter-args...]",
		Aliases: []string{"interpreter"},
		Short:   "Launch Open Interpreter; with --continue-from, seed a handover as its positional prompt",
		Long: "Wraps Open Interpreter (binary `interpreter`), a rebadged OpenAI\n" +
			"Codex CLI build under ~/.openinterpreter. This launcher is\n" +
			"NON-PROXIED — unlike `observer codex` it injects NO base-URL\n" +
			"override, because the fork's proxy lane is unprobed. Token capture\n" +
			"happens via observer's local open-interpreter adapter (the codex\n" +
			"rollout parser retagged), not the proxy.\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it as the trailing positional prompt\n" +
			"(delivery=inject_prompt), so Open Interpreter opens pre-loaded with\n" +
			"the mission. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to interpreter.\n" +
			"Use `--` to separate observer flags from interpreter flags. NEVER\n" +
			"touches API keys or stored auth.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (launched non-proxied — no proxy env,
			// no escape-hatch flag); incompatible when a handoff fork is engaged
			// or a leading non-interactive run subcommand is forwarded (`exec` /
			// `review`, the codex-shaped scripted lanes).
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "open-interpreter",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					openInterpreterHeadlessScan.leads(args),
				passthrough: append(openInterpreterAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `interpreter resume <id>` (the
			// codex subcommand-with-positional shape; the shared translation
			// table owns it).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "open-interpreter", label: "open-interpreter", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("open-interpreter", binPath, "--interpreter-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "open-interpreter",
					label:       "open-interpreter",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// The initial prompt is the trailing positional
					// `[PROMPT]` on both the default TUI command and the
					// `exec` subcommand — the codex contract verbatim, so
					// the subcommand map mirrors codex's (a forwarded verb
					// is not misread as a competing prompt).
					inject: promptInjection{
						Kind:        injectTrailingPositional,
						Subcommands: openInterpreterSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer open-interpreter: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}

			// Best-effort attribution config: a load failure just disables
			// the launch seed (recordLaunchSeed treats "" as off).
			dbPath := ""
			if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
				dbPath = cfg.Observer.DBPath
			}
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "open-interpreter", "open-interpreter", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "interpreter-path", "", "Path to the interpreter binary (default: resolve `interpreter` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as interpreter's positional prompt (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "open-interpreter")
	resume = registerResumeFlag(cmd, "open-interpreter")
	return cmd
}

// openInterpreterAttachPassthrough forwards the --interpreter-path wrapper
// flag to the daemon-spawned inner launcher when set (nil otherwise).
func openInterpreterAttachPassthrough(interpreterPath string) []string {
	if interpreterPath != "" {
		return []string{"--interpreter-path", interpreterPath}
	}
	return nil
}

// openInterpreterAttachHeadlessSubcommands are the leading subcommands whose
// non-interactive form cannot compose with attach: `exec` (+ its `e` alias)
// is "Run Codex non-interactively" and `review` is "Run a code review
// non-interactively" (`interpreter --help`). Mirrors codex's own
// exec-is-incompatible rule.
var openInterpreterAttachHeadlessSubcommands = map[string]bool{
	"exec": true, "e": true, "review": true,
}

// openInterpreterValueFlags are the fork's SPLIT-value options — clap
// `<VALUE>`-required spellings, which always consume the following token.
// Read verbatim off `interpreter --help` (live install, 2026-07-29):
//
//	-c, --config <key=value>              Override a configuration value
//	    --enable <FEATURE>                Enable a feature (repeatable)
//	    --disable <FEATURE>               Disable a feature (repeatable)
//	    --remote <ADDR>                   Connect the TUI to a remote …
//	    --remote-auth-token-env <ENV_VAR> Name of the environment variable …
//	-m, --model <MODEL>                   Model the agent should use
//	    --local-provider <OSS_PROVIDER>   lmstudio or ollama
//	-p, --profile <CONFIG_PROFILE_V2>     Layer $CODEX_HOME/<name>.config.toml
//	-s, --sandbox <SANDBOX_MODE>          Sandbox policy
//	-C, --cd <DIR>                        Working root
//	    --add-dir <DIR>                   Additional writable directories
//	-a, --ask-for-approval <APPROVAL_POLICY>
//
// NOTE `-p` here is clap's `--profile`, NOT a headless print flag — the
// fork's non-interactive lanes are the `exec`/`review` SUBCOMMANDS.
var openInterpreterValueFlags = map[string]bool{
	"-c": true, "--config": true, "--enable": true, "--disable": true,
	"--remote": true, "--remote-auth-token-env": true,
	"-m": true, "--model": true, "--local-provider": true,
	"-p": true, "--profile": true, "-s": true, "--sandbox": true,
	"-C": true, "--cd": true, "--add-dir": true,
	"-a": true, "--ask-for-approval": true,
}

// openInterpreterBoolFlags are the fork's clap switches — declared with no
// value at all, so they consume nothing (`interpreter --help`, 2026-07-29):
//
//	--strict-config, --oss, --search, --no-alt-screen,
//	--dangerously-bypass-approvals-and-sandbox,
//	--dangerously-bypass-hook-trust, -h/--help, -V/--version
//
// `-i, --image <FILE>...` is DELIBERATELY in NEITHER set: it is VARIADIC, so
// no fixed skip count is correct — it falls through to the conservative
// ambiguous branch (see leadingVerbScan).
var openInterpreterBoolFlags = map[string]bool{
	"--strict-config": true, "--oss": true, "--search": true,
	"--no-alt-screen": true, "--dangerously-bypass-approvals-and-sandbox": true,
	"--dangerously-bypass-hook-trust": true,
	"-h":                              true, "--help": true, "-V": true, "--version": true,
}

// openInterpreterHeadlessScan is the fork's grounded leading-verb guard: the
// headless subcommand set plus the flag grammar above, so `-m gpt-5 exec` is
// no longer read as the operand `gpt-5` with `exec` slipping through.
var openInterpreterHeadlessScan = leadingVerbScan{
	subs:       openInterpreterAttachHeadlessSubcommands,
	valueFlags: openInterpreterValueFlags,
	boolFlags:  openInterpreterBoolFlags,
}

// openInterpreterSubcommands are the interpreter argv tokens that are
// subcommands, not a prompt — so forwardedPromptConflict does not misread a
// forwarded verb (e.g. `interpreter mcp`) as a competing positional prompt.
// Read verbatim off this fork's `--help` Commands block (a superset of
// codexSubcommands: the fork ships resume/fork/archive/plugin/features/… on
// top of codex's list).
var openInterpreterSubcommands = map[string]bool{
	"exec": true, "e": true, "review": true, "login": true, "logout": true,
	"mcp": true, "plugin": true, "mcp-server": true, "acp": true,
	"app-server": true, "remote-control": true, "completion": true,
	"update": true, "doctor": true, "sandbox": true, "debug": true,
	"apply": true, "a": true, "resume": true, "archive": true,
	"delete": true, "unarchive": true, "fork": true, "cloud": true,
	"exec-server": true, "features": true, "help": true,
	// codex ships `proto` without listing it in the visible help; the fork
	// almost certainly inherits it. Listing it is defensive only — the map's
	// sole job is to keep a forwarded VERB from reading as a prompt.
	"proto": true,
}
