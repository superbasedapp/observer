// droid.go — `observer droid` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newDroidCmd implements `observer droid` — launches Factory AI's droid CLI
// (binary `droid`). Its primary purpose is `--continue-from`: distill a
// handover from a source session and seed it as droid's trailing positional
// prompt (`droid "<handover>"` — droid's own `--help` documents the shape
// verbatim: `Usage: droid [options] [command] [prompt...]` with the example
// `droid "review app.tsx"   Start with an initial prompt`).
//
// NON-PROXIED on purpose. droid's built-in-model path talks to Factory's own
// gateway with no base-URL knob found in `--help`; the BYOK custom-model path
// calls the underlying provider directly and is the only near-routable
// candidate, but no observer-routed turn has confirmed api_turns capture
// (RouteStatusProbeRequired in the integration registry). So the launcher
// execs `droid` with the caller's own environment; token capture happens via
// observer's local droid adapter (~/.factory/sessions JSONL + the
// `<uuid>.settings.json` sidecar), not the proxy. It never touches
// FACTORY_API_KEY or ~/.factory/auth.v2.*.
func newDroidCmd() *cobra.Command {
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
		Use:   "droid [-- droid-args...]",
		Short: "Launch Factory's droid; with --continue-from, seed a handover as droid's positional prompt",
		Long: "Wraps Factory AI's droid CLI (`droid`). This launcher is NON-PROXIED\n" +
			"— droid's built-in-model path has no base-URL knob and its BYOK lane\n" +
			"is unprobed, so pointing it at the proxy would be a guess. Token\n" +
			"capture happens via observer's local droid adapter (session JSONL +\n" +
			"the settings.json sidecar's session-level cumulative counts).\n\n" +
			"droid's `--model` flag is only available on the headless `droid exec`\n" +
			"subcommand; the interactive session has no model selection.\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it as droid's trailing positional prompt\n" +
			"(delivery=inject_prompt), so droid opens an interactive session\n" +
			"pre-loaded with the mission. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to droid. Use `--`\n" +
			"to separate observer flags from droid flags. NEVER touches\n" +
			"FACTORY_API_KEY or stored auth.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (droid is launched non-proxied — no
			// proxy env, no escape-hatch flag); incompatible when a handoff fork
			// is engaged or a leading non-interactive subcommand is forwarded
			// (`droid exec` and friends run and exit, so an attach notice +
			// daemon-owned PTY would be spam).
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "droid",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					droidHeadlessScan.leads(args),
				passthrough: append(droidAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `droid --resume=<id>` (the
			// JOINED spelling — droid declares `-r, --resume [sessionId]`
			// with an OPTIONAL value, the commander.js shape that does not
			// reliably consume the following token; same case as cursor).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "droid", label: "droid", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("droid", binPath, "--droid-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				// A forwarded `exec` (or any other non-interactive verb)
				// collides with the seeded launch: droid would run the
				// handover as a scripted one-shot and exit instead of
				// opening the seeded interactive session. Fail fast, before
				// the (comparatively expensive) handoff render — the
				// subcommand map deliberately lists `exec` so the generic
				// two-prompt check does not misread it, which makes THIS
				// the check that owns the case.
				if droidHeadlessScan.leads(args) {
					err := fmt.Errorf("--continue-from seeds an INTERACTIVE droid session, but you forwarded a non-interactive subcommand (e.g. `exec`) — drop it, or run the handover through `droid exec` yourself")
					fmt.Fprintf(cmd.ErrOrStderr(), "observer droid: %v\n", err)
					return err
				}
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "droid",
					label:       "droid",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// droid takes the initial prompt as a bare positional on
					// its DEFAULT (TUI) command — `droid "review app.tsx"`
					// is the vendor's own worked example in `--help`. The
					// non-interactive lane is the `exec` SUBCOMMAND (handled
					// above), so there is no headless prompt FLAG to list as
					// a conflict; --append-system-prompt is a system-prompt
					// suffix, not a user prompt, so it is not a collision.
					inject: promptInjection{
						Kind:        injectTrailingPositional,
						Subcommands: droidSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer droid: continue-from failed: %v\n", cerr)
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
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "droid", "droid", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "droid-path", "", "Path to the droid binary (default: resolve `droid` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as droid's positional prompt (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "droid")
	resume = registerResumeFlag(cmd, "droid")
	return cmd
}

// droidAttachPassthrough forwards the --droid-path wrapper flag to the
// daemon-spawned inner `observer droid` launcher when set (nil otherwise).
func droidAttachPassthrough(droidPath string) []string {
	if droidPath != "" {
		return []string{"--droid-path", droidPath}
	}
	return nil
}

// droidAttachHeadlessSubcommands are the leading droid subcommands that run
// and exit rather than opening the TUI (`droid --help` Commands block), so
// they cannot compose with attach and must not be seeded. `exec` is the
// scripted one-shot ("Run non-interactively (for scripts/automation)");
// `daemon`/`search`/`find`/`update`/`mcp`/`plugin`/`computer` are management
// verbs.
var droidAttachHeadlessSubcommands = map[string]bool{
	"exec": true, "daemon": true, "search": true, "find": true,
	"update": true, "mcp": true, "plugin": true, "computer": true,
	"help": true,
}

// droidSubcommands are the droid argv tokens that are subcommands, not a
// prompt — so forwardedPromptConflict does not misread a forwarded verb
// (e.g. `droid mcp`) as a competing positional prompt. It is the same set as
// droidAttachHeadlessSubcommands because every droid subcommand is a
// non-interactive verb; the seeded path rejects them explicitly rather than
// through the generic two-prompt check.
var droidSubcommands = droidAttachHeadlessSubcommands

// droidValueFlags are droid's SPLIT-value options — commander.js `<...>`
// REQUIRED-argument spellings, which always consume the following token.
// Read verbatim off `droid --help` (v0.181.0, live install, 2026-07-29):
//
//	--settings <path>                   Path to runtime settings file …
//	--append-system-prompt <text>       Append custom text …
//	--append-system-prompt-file <path>  Append file contents …
//	--fork <sessionId>                  Fork and resume a session
//	--cwd <path>                        Working directory path
//	--worktree-dir <path>               Directory for worktree creation
//	--auto <level>                      Autonomy level: low|medium|high
//
// Without this table the leading-verb guard reads a split VALUE as the
// operand and lets a following `exec` through (see leadingVerbScan).
var droidValueFlags = map[string]bool{
	"--settings": true, "--append-system-prompt": true,
	"--append-system-prompt-file": true, "--fork": true,
	"--cwd": true, "--worktree-dir": true, "--auto": true,
}

// droidBoolFlags are droid's switches — commander.js options declared with no
// argument at all, so they consume nothing (`droid --help`, v0.181.0):
//
//	-v, --version              output the version number
//	--use-spec                 Start in spec mode
//	--disable-builtin-skills   Disable Factory-provided builtin skills
//	-h, --help                 display help for command
//
// The OPTIONAL-value options `-r, --resume [sessionId]` and
// `-w, --worktree [name]` are DELIBERATELY in NEITHER set: commander consumes
// the following token for `[value]` options only when it is not option-like,
// which the guard cannot replicate — so they fall through to the conservative
// ambiguous branch rather than being misclassified in either direction.
var droidBoolFlags = map[string]bool{
	"-v": true, "--version": true, "--use-spec": true,
	"--disable-builtin-skills": true, "-h": true, "--help": true,
}

// droidHeadlessScan is droid's grounded leading-verb guard: the headless
// subcommand set plus the flag grammar above, so a split-value flag can no
// longer hide a following `exec` in the operand position.
var droidHeadlessScan = leadingVerbScan{
	subs:       droidAttachHeadlessSubcommands,
	valueFlags: droidValueFlags,
	boolFlags:  droidBoolFlags,
}
