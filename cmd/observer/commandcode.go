// commandcode.go — `observer command-code` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newCommandCodeCmd implements `observer command-code` (alias `commandcode`)
// — launches Command Code (commandcode.ai's `command-code` npm package,
// invoked as `commandcode`). Its primary purpose is `--continue-from`:
// distill a handover from a source session and seed it as the trailing
// positional message, the contract the tool's own `--help` states verbatim:
// `commandcode "message"   Start with initial message`.
//
// NON-PROXIED on purpose. Command Code's COMMANDCODE_API_URL /
// COMMAND_CODE_API_KEY knobs point at its OWN closed gateway rather than an
// Anthropic/OpenAI-shaped BYOK endpoint, so capturing it would need a bridge,
// not a base-URL redirect (RouteStatusAfterBridge in the integration
// registry). The launcher execs `commandcode` with the caller's own
// environment; token capture happens via observer's local command-code
// adapter (~/.commandcode/projects CC-shaped JSONL, per-message usage
// envelope). It never touches ~/.commandcode/auth.json or any API key.
func newCommandCodeCmd() *cobra.Command {
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
		Use:     "command-code [-- commandcode-args...]",
		Aliases: []string{"commandcode"},
		Short:   "Launch Command Code; with --continue-from, seed a handover as its initial message",
		Long: "Wraps Command Code (`commandcode`, npm package `command-code`).\n" +
			"This launcher is NON-PROXIED — Command Code's API-URL knob points at\n" +
			"its own closed gateway, so there is no Anthropic/OpenAI-shaped lane\n" +
			"to redirect. Token capture happens via observer's local command-code\n" +
			"adapter (per-message usage envelope in the session JSONL).\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it as the initial message positional\n" +
			"(delivery=inject_prompt), so Command Code opens an interactive\n" +
			"session pre-loaded with the mission. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to commandcode.\n" +
			"Use `--` to separate observer flags from commandcode flags. NEVER\n" +
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
			// no escape-hatch flag); incompatible when a handoff fork is engaged,
			// when the headless `-p/--print` one-shot is forwarded, or when a
			// leading management subcommand (info/status/mcp/…) is.
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "command-code",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsContainHeadlessFlag(args, "-p", "--print") ||
					commandCodeHeadlessScan.leads(args),
				passthrough: append(commandCodeAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `commandcode --session <id>`.
			// `--session <path|id>` is the REQUIRED-value spelling ("Resume a
			// session by transcript path (.jsonl) or a unique session-id
			// prefix"), deliberately preferred over the OPTIONAL-value
			// `-r/--resume [name]`.
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "command-code", label: "command-code", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("command-code", binPath, "--commandcode-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				// A forwarded --no-session collides with the seeded launch:
				// it keeps the session in memory only ("Don't persist this
				// session to disk"), so observer's command-code adapter —
				// which reads the on-disk JSONL — would capture nothing of
				// the continued work. Fail fast, before the handoff render
				// (the goose --no-session precedent).
				if forwardedFlagConflict(args, "--no-session") {
					err := fmt.Errorf("--continue-from opens a session-persisted seeded run, but you forwarded --no-session — drop it (observer's command-code adapter captures from the on-disk session JSONL)")
					fmt.Fprintf(cmd.ErrOrStderr(), "observer command-code: %v\n", err)
					return err
				}
				// The headless `-p/--print` one-shot answers and EXITS, which
				// is the opposite of a seeded interactive continue. The shared
				// two-prompt check only inspects POSITIONALS for the
				// positional injection kinds, so this flag case is the
				// launcher's own guard (the goose --no-session shape).
				if argsContainHeadlessFlag(args, "-p", "--print") {
					err := fmt.Errorf("--continue-from seeds an INTERACTIVE Command Code session, but you forwarded the headless -p/--print one-shot — drop it (or run the handover through `commandcode -p` yourself)")
					fmt.Fprintf(cmd.ErrOrStderr(), "observer command-code: %v\n", err)
					return err
				}
				// A forwarded MANAGEMENT verb is the same class of collision,
				// and a worse one: `commandcode status`, `mcp`, `login`, …
				// print and EXIT, and none of them takes a message
				// positional, so seeding would append the handover as an
				// ignored extra argument (empirically confirmed on v1.4.5:
				// the verb accepts and ignores it) and the operator would
				// watch the tool exit instead of opening the seeded session.
				// The subcommand map deliberately keeps these verbs legible
				// to the generic two-prompt check, which makes THIS the check
				// that owns the case — the droid `exec` precedent. Fail fast,
				// before the (comparatively expensive) handoff render.
				if verb, bad := commandCodeHeadlessScan.leadingVerb(args); bad {
					err := fmt.Errorf("--continue-from seeds an INTERACTIVE Command Code session, but you forwarded the management subcommand %q, which prints and exits — drop it, or run `commandcode %s` yourself", verb, verb)
					fmt.Fprintf(cmd.ErrOrStderr(), "observer command-code: %v\n", err)
					return err
				}
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "command-code",
					label:       "command-code",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// The initial message is a bare positional on the
					// default TUI command (`commandcode "message"`).
					// `-p/--print [query]` is the headless one-shot and
					// would collide with the seed; the subcommand map keeps
					// forwarded management verbs (`mcp`, `status`, …)
					// legible to the two-prompt check.
					inject: promptInjection{
						Kind:          injectTrailingPositional,
						ConflictFlags: []string{"-p", "--print"},
						Subcommands:   commandCodeSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer command-code: continue-from failed: %v\n", cerr)
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
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "command-code", "command-code", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "commandcode-path", "", "Path to the commandcode binary (default: resolve `commandcode` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as commandcode's initial message (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "command-code")
	resume = registerResumeFlag(cmd, "command-code")
	return cmd
}

// commandCodeAttachPassthrough forwards the --commandcode-path wrapper flag
// to the daemon-spawned inner launcher when set (nil otherwise).
func commandCodeAttachPassthrough(commandcodePath string) []string {
	if commandcodePath != "" {
		return []string{"--commandcode-path", commandcodePath}
	}
	return nil
}

// commandCodeSubcommands are the commandcode argv tokens that are
// subcommands, not a prompt (the `--help` Commands block) — so
// forwardedPromptConflict does not misread a forwarded verb (e.g.
// `commandcode mcp`) as a competing positional message. They are also the
// leading-verb set that makes a launch attach-incompatible: every one of them
// prints and exits rather than opening the TUI.
var commandCodeSubcommands = map[string]bool{
	"info": true, "status": true, "help": true, "whoami": true,
	"update": true, "feedback": true, "taste": true, "learn-taste": true,
	"mcp": true, "skills": true, "mods": true, "login": true, "logout": true,
}

// commandCodeValueFlags are Command Code's SPLIT-value options — the
// `<value>`-REQUIRED spellings, which always consume the following token.
// Read verbatim off `commandcode --help` (v1.4.5, live install, 2026-07-29):
//
//	--session <path|id>        --name/-n <name>       --max-turns <number>
//	--output-format <format>   --model/-m <model>     --effort <level>
//	--theme <theme>            --config <key=value>   --permission-mode <mode>
//	--add-dir <directory>      --mod <path>           --mod-option <name=value>
//	--skill <path>
//
// Without this table the leading-verb guard reads a split VALUE as the
// operand and lets a following management verb through (see leadingVerbScan).
var commandCodeValueFlags = map[string]bool{
	"--session": true, "-n": true, "--name": true, "--max-turns": true,
	"--output-format": true, "-m": true, "--model": true, "--effort": true,
	"--theme": true, "--config": true, "--permission-mode": true,
	"--add-dir": true, "--mod": true, "--mod-option": true, "--skill": true,
}

// commandCodeBoolFlags are Command Code's switches — declared with no value at
// all, so they consume nothing (`commandcode --help`, v1.4.5):
//
//	-c/--continue  --fork-session  --no-session  -t/--trust  --list-models
//	--plan  --auto-accept  --yolo (alias --dangerously-skip-permissions)
//	--no-skills  --skip-onboarding  --ide-setup  --no-auto-update
//	-v/--version  -h/--help
//
// The OPTIONAL-value options `-r, --resume [name]`, `-p, --print [query]` and
// `-w, --worktree [name]` are DELIBERATELY in NEITHER set: whether they eat
// the following token depends on what that token looks like, which the guard
// cannot replicate — so they fall through to the conservative ambiguous
// branch rather than being misclassified in either direction.
var commandCodeBoolFlags = map[string]bool{
	"-c": true, "--continue": true, "--fork-session": true,
	"--no-session": true, "-t": true, "--trust": true, "--list-models": true,
	"--plan": true, "--auto-accept": true, "--yolo": true,
	"--dangerously-skip-permissions": true, "--no-skills": true,
	"--skip-onboarding": true, "--ide-setup": true, "--no-auto-update": true,
	"-v": true, "--version": true, "-h": true, "--help": true,
}

// commandCodeHeadlessScan is Command Code's grounded leading-verb guard: the
// management-subcommand set plus the flag grammar above, so a split-value
// flag can no longer hide a following `status` in the operand position.
var commandCodeHeadlessScan = leadingVerbScan{
	subs:       commandCodeSubcommands,
	valueFlags: commandCodeValueFlags,
	boolFlags:  commandCodeBoolFlags,
}
