// qwen.go — `observer qwen` launcher subcommand.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newQwenCmd implements `observer qwen` — launches Qwen Code (`qwen`). Its
// primary purpose is `--continue-from`: distill a handover from a source
// session and seed it via `qwen -i "<handover>"` (`-i` ≡
// `--prompt-interactive`: "execute the provided prompt and continue in
// interactive mode"), so a migration INTO Qwen Code opens the interactive
// session pre-loaded with the mission.
//
// NON-PROXIED on purpose. Qwen Code's OpenAI-compatible base-URL lane is
// PROMOTED in the integration registry (routable_now, live-verified
// 2026-07-09, api_turns 23728-23730) — but it routes via the
// `observer init` config writer (~/.qwen/settings.json model.baseUrl +
// matching modelProviders entry), NOT via this launcher: OPENAI_BASE_URL is
// INERT for qwen (the id,baseUrl pair resolution wins), so injecting it here
// would silently do nothing. This launcher execs `qwen` with the caller's own
// environment; token capture happens via observer's local qwen-code
// transcript adapter (in-transcript ui_telemetry records), not the proxy.
// It never sets an API key or a base URL.
func newQwenCmd() *cobra.Command {
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
		Use:   "qwen [-- qwen-args...]",
		Short: "Launch Qwen Code; with --continue-from, seed a handover via qwen -i",
		Long: "Wraps `qwen` (Qwen Code). This launcher is NON-PROXIED — Qwen Code's\n" +
			"OpenAI-compatible base-URL lane is unprobed, and overriding it would\n" +
			"redirect an already-configured provider. Token capture happens via\n" +
			"observer's local qwen-code transcript adapter, not the proxy.\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via qwen's -i/--prompt-interactive\n" +
			"flag (delivery=inject_prompt), so Qwen Code opens pre-loaded with\n" +
			"the mission. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to qwen. Use `--`\n" +
			"to separate observer flags from qwen flags. NEVER touches API keys.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (qwen is launched non-proxied — no
			// proxy env, no escape-hatch flag); incompatible when a handoff fork
			// is engaged or a headless -p/--prompt one-shot is forwarded.
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "qwen-code",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsContainHeadlessFlag(args, "-p", "--prompt"),
				passthrough: append(qwenAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `qwen --resume <id>` (bare path).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "qwen", label: "qwen", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("qwen-code", binPath, "--qwen-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "qwen-code",
					label:       "qwen",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// qwen -i/--prompt-interactive takes the initial prompt as
					// its value; -p/--prompt is the headless one-shot form —
					// flag all four as conflicts. Qwen Code is a Gemini-CLI
					// fork whose bare positional is also an initial prompt, so
					// a forwarded positional competes with the seed and must
					// trip the collision check.
					inject: promptInjection{
						Kind:                   injectFlagValue,
						Flag:                   "-i",
						ConflictFlags:          []string{"-i", "--prompt-interactive", "-p", "--prompt"},
						BarePositionalIsPrompt: true,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer qwen: continue-from failed: %v\n", cerr)
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
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "qwen-code", "qwen", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "qwen-path", "", "Path to the qwen binary (default: resolve `qwen` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via qwen's -i flag (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "qwen-code")
	resume = registerResumeFlag(cmd, "qwen-code")
	return cmd
}

// qwenAttachPassthrough forwards the --qwen-path wrapper flag to the
// daemon-spawned inner `observer qwen` launcher when set (nil otherwise).
func qwenAttachPassthrough(qwenPath string) []string {
	if qwenPath != "" {
		return []string{"--qwen-path", qwenPath}
	}
	return nil
}

// runSeedOnlyLaunchSeeded execs a tool non-proxied and adds best-effort direct
// process attribution (migration 086): when dbPath and tool are set it records a
// launch_seeds row for the successfully started child so the daemon's
// correlation sweep can bind it to the ingested session, retracting the seed
// when the child is reaped. A seeding failure never affects the launch (see
// cmd/observer/launchseed.go); empty dbPath/tool disable seeding entirely.
func runSeedOnlyLaunchSeeded(configPath, dbPath, tool, label, bin string, args []string, dir string) error {
	return runSeedOnlyLaunchSeededWithEvidence(configPath, dbPath, tool, label, bin, args, dir,
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
}

// runSeedOnlyLaunchSeededWithEvidence is the admission-aware implementation
// behind runSeedOnlyLaunchSeeded. The separate entry point lets a launcher
// with grounded non-model subcommands identify them without weakening the
// direct default shared by every other seed-only launcher.
func runSeedOnlyLaunchSeededWithEvidence(configPath, dbPath, tool, label, bin string, args []string, dir string, evidence budgetLaunchEvidence) error {
	evidence.Executable = bin
	evidence.Arguments = args
	if err := enforceBudgetControlledLaunch(context.Background(), configPath, tool, evidence); err != nil {
		return err
	}
	child := exec.Command(bin, args...)   //nolint:gosec // user-launched tool; argv is the seeded handover + forwarded args
	child.Env = scrubOOBEnv(os.Environ()) // strip the trusted OOB channel env
	child.Dir = dir
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	discovery := prepareGenericDiscovery(context.Background(), tool, dir)
	if err := child.Start(); err != nil {
		return fmt.Errorf("exec %s: %w", label, err)
	}
	recordLaunchSeed(dbPath, tool, dir, child.Process.Pid, os.Stderr)
	// Best-effort generic post-launch session discovery (WS-DISCOVERY): a
	// no-op unless the trusted OOB channel is active AND tool resolves to an
	// adapter that declares session-file watch roots. Cancel the instant the
	// child exits so a window cut short by exit never announces a candidate
	// that only looked unique because the scan stopped early.
	discoverCancel := discovery.start()
	if discoverCancel != nil {
		defer discoverCancel()
	}
	if err := child.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitErr(ee.ExitCode())
		}
		return fmt.Errorf("exec %s: %w", label, err)
	}
	return nil
}
