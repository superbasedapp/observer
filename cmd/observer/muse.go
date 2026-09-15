// muse.go — `observer muse` launcher subcommand.

package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newMuseCmd implements `observer muse` — launches Meta's Muse Code CLI
// (binary `muse`). Its primary purpose is `--continue-from`: distill a
// handover from a source session and seed it as muse's trailing positional
// prompt, the contract muse's own `--help` states verbatim: `Usage: muse
// [OPTIONS] [PROMPT]` — "pass a prompt to start a session".
//
// NON-PROXIED on purpose. A fresh local refusal probe proved that Muse honors
// `--base-url <URL>` and sends an OpenAI Responses-shaped POST to
// `<URL>/v1/responses`. No successful upstream turn or Observer capture has
// been verified, so the registry still has no verified Proxy capability and
// this launcher does not inject the flag. A managed hard-budget node therefore
// refuses this launch pending a verified request route. Outside that posture,
// token capture remains the local muse adapter (session.jsonl under
// ~/.local/state or ~/.cache muse dirs - see internal/adapter/muse). It never
// touches Muse's stored provider credentials.
func newMuseCmd() *cobra.Command {
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
		Use:   "muse [-- muse-args...]",
		Short: "Launch Meta's Muse Code CLI; with --continue-from, seed a handover as muse's positional prompt",
		Long: "Wraps Meta's Muse Code CLI (`muse`). This launcher is non-proxied.\n" +
			"A local refusal probe confirmed that `--base-url` sends OpenAI Responses\n" +
			"requests to `<URL>/v1/responses`, but a successful upstream and Observer\n" +
			"capture turn have not been verified. Managed hard-budget nodes refuse\n" +
			"this launch pending that verified route. Otherwise token capture uses\n" +
			"Observer's local Muse session.jsonl adapter.\n\n" +
			"muse supports a top-level `--model` flag to select which model\n" +
			"the session uses (pass it after `--` with your other muse args).\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it as muse's trailing positional prompt\n" +
			"(delivery=inject_prompt), so muse opens an interactive session\n" +
			"pre-loaded with the mission. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to muse. Use `--`\n" +
			"to separate observer flags from muse flags. NEVER touches muse's\n" +
			"stored provider credentials.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (muse is launched non-proxied — no
			// proxy env, no escape-hatch flag); incompatible when a handoff fork
			// is engaged or a leading muse subcommand (exec/resume/export/…) is
			// forwarded — none of them open a fresh interactive session a
			// daemon-owned PTY attach notice would make sense for.
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "muse",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					museHeadlessScan.leads(args),
				passthrough: append(museAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `muse resume <id>` — a
			// SUBCOMMAND whose positional argument is the session uuid
			// (`muse resume --help`: `Usage: muse resume` / `muse resume
			// --last` / `muse resume <session-uuid>`). The id is our stored
			// SessionID verbatim (muse's own directory-name uuid), so no
			// transform.
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "muse", label: "muse", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("muse", binPath, "--muse-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				// A forwarded muse subcommand (exec/resume/export/…) collides
				// with the seeded launch: none of them accepts a fresh
				// interactive prompt the way the bare command does — `exec`
				// runs one prompt headlessly and exits, `resume` reattaches an
				// EXISTING session instead of starting one, and the rest are
				// one-shot management verbs. Fail fast, before the
				// (comparatively expensive) handoff render — the droid `exec`
				// precedent.
				if museHeadlessScan.leads(args) {
					err := fmt.Errorf("--continue-from seeds an INTERACTIVE muse session, but you forwarded a muse subcommand (e.g. `exec`) — drop it, or run the handover through `muse exec` yourself")
					fmt.Fprintf(cmd.ErrOrStderr(), "observer muse: %v\n", err)
					return err
				}
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "muse",
					label:       "muse",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// muse takes the initial prompt as a bare positional on
					// its default (TUI) command — `Usage: muse [OPTIONS]
					// [PROMPT]`. The non-interactive lane is the `exec`
					// SUBCOMMAND (handled above), so there is no headless
					// prompt FLAG to list as a conflict.
					inject: promptInjection{
						Kind:        injectTrailingPositional,
						Subcommands: museSubcommands,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer muse: continue-from failed: %v\n", cerr)
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
			return runSeedOnlyLaunchSeededWithEvidence(configPath, dbPath, "muse", "muse", bin, args, continueDir,
				museBudgetLaunchEvidence(args))
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "muse-path", "", "Path to the muse binary (default: resolve `muse` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as muse's positional prompt (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "muse")
	resume = registerResumeFlag(cmd, "muse")
	return cmd
}

// museAttachPassthrough forwards the --muse-path wrapper flag to the
// daemon-spawned inner `observer muse` launcher when set (nil otherwise).
func museAttachPassthrough(musePath string) []string {
	if musePath != "" {
		return []string{"--muse-path", musePath}
	}
	return nil
}

// museSubcommands are muse's argv tokens that are subcommands, not a prompt
// (the `muse --help` Commands block), so forwardedPromptConflict does not
// misread a forwarded verb (e.g. `muse skills`) as a competing positional
// prompt. It is also the leading-verb set that makes a launch
// attach-incompatible and continue-from-incompatible: `exec` runs headlessly
// and exits; `export`/`trace`/`skills`/`sandbox`/`session-message`/`auth`/
// `login`/`logout`/`init` are one-shot management verbs. `resume` is grouped
// here too even though it can reopen an interactive TUI (reattaching an
// EXISTING session) — it never accepts a FRESH prompt the way the bare
// command does, and observer's own native --resume flag already covers the
// resume-into-attach path via resumeAttachPassthrough, so a raw forwarded
// `-- resume …` does not need attach/seed compatibility guaranteed.
var museSubcommands = map[string]bool{
	"resume": true, "exec": true, "export": true, "trace": true,
	"skills": true, "sandbox": true, "session-message": true,
	"auth": true, "login": true, "logout": true, "init": true,
}

// museBudgetMaintenanceSubcommands and museBudgetMaintenanceFlags are the
// grounded Muse verbs and flags that perform local/account management without
// submitting a model request. They are DERIVED from the muse intervention
// registry row (integration.NonBillableLeadingArguments) so this launch gate
// and the node process controller classify one invocation identically — the
// registry row is the single owner of that vocabulary, and a verb added there
// reaches both. The model-bearing exec/resume/session-message verbs stay
// subject to admission; sandbox is also excluded because its child-command
// behavior is broader than a maintenance operation.
var museBudgetMaintenanceSubcommands, museBudgetMaintenanceFlags = registryMaintenanceVocabulary("muse")

// museBudgetLaunchEvidence recognizes only exact vendor info flags and a
// grounded maintenance subcommand reached through Muse's known top-level flag
// grammar. Unknown or optional-value flags keep the invocation direct because
// their effect on command selection cannot be proved.
func museBudgetLaunchEvidence(args []string) budgetLaunchEvidence {
	direct := budgetLaunchEvidence{Route: budgetLaunchRouteDirect}
	if len(args) == 1 && museBudgetMaintenanceFlags[args[0]] {
		return budgetLaunchEvidence{Route: budgetLaunchRouteMaintenance}
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return direct
		}
		if !strings.HasPrefix(arg, "-") {
			if museBudgetMaintenanceSubcommands[arg] {
				return budgetLaunchEvidence{Route: budgetLaunchRouteMaintenance}
			}
			return direct
		}

		name := arg
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
			if !museValueFlags[name] && !museBoolFlags[name] {
				return direct
			}
			continue
		}
		switch {
		case museValueFlags[name]:
			if i+1 >= len(args) {
				return direct
			}
			i++
		case museBoolFlags[name]:
			continue
		default:
			return direct
		}
	}
	return direct
}

// museValueFlags are muse's SPLIT-value top-level options — the
// `<value>`-REQUIRED spellings, which always consume the following token.
// Read verbatim off `muse --help` (Muse Code 0.1.0 (0.1.0-R708.1), live
// install, 2026-08-06):
//
//	--agents <JSON>  --provider <MODE>  --preset <NAME>  --model <MODEL>
//	--reasoning-effort <EFFORT>  --base-url <URL>  --image <PATH>
//	--workspace <PATH>  --worktree-base <REF>  --worktree-existing <PATH>
//	--approval-mode <MODE>  --approval-judge <off|on>  --echo-delay-ms <MS>
//	--sandbox-network <MODE>
//
// Without this table the leading-verb guard reads a split VALUE as the
// operand and lets a following subcommand through (see leadingVerbScan).
var museValueFlags = map[string]bool{
	"--agents": true, "--provider": true, "--preset": true, "--model": true,
	"--reasoning-effort": true, "--base-url": true, "--image": true,
	"--workspace": true, "--worktree-base": true, "--worktree-existing": true,
	"--approval-mode": true, "--approval-judge": true, "--echo-delay-ms": true,
	"--sandbox-network": true,
}

// museBoolFlags are muse's top-level switches — declared with no value at
// all, so they consume nothing (`muse --help`):
//
//	-h/--help  -V/--version  --parallel-tool-calls  --no-parallel-tool-calls
//	--subagent-worktree-isolation  --no-session-log  --yolo
//	--trust-workspace  --disable-approval  --disable-sandbox
//	--disable-write  --disable-shell  --enable-shell-tool
//
// The OPTIONAL-value option `-w, --worktree [<MODE>]` is DELIBERATELY in
// NEITHER set: whether it eats the following token depends on what that
// token looks like, which the guard cannot replicate — so it falls through
// to the conservative ambiguous branch rather than being misclassified in
// either direction.
var museBoolFlags = map[string]bool{
	"-h": true, "--help": true, "-V": true, "--version": true,
	"--parallel-tool-calls": true, "--no-parallel-tool-calls": true,
	"--subagent-worktree-isolation": true, "--no-session-log": true,
	"--yolo": true, "--trust-workspace": true, "--disable-approval": true,
	"--disable-sandbox": true, "--disable-write": true,
	"--disable-shell": true, "--enable-shell-tool": true,
}

// museHeadlessScan is muse's grounded leading-verb guard: the subcommand set
// plus the flag grammar above, so a split-value flag can no longer hide a
// following subcommand in the operand position.
var museHeadlessScan = leadingVerbScan{
	subs:       museSubcommands,
	valueFlags: museValueFlags,
	boolFlags:  museBoolFlags,
}
