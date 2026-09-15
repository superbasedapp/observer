// kimi.go — `observer kimi` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newKimiCmd implements `observer kimi` — launches Moonshot AI's kimi-code
// CLI (binary `kimi`). Its primary purpose is `--continue-from`, which is a
// **DocAssisted** launch (the hermes precedent): kimi-code's `-p` prints and
// EXITS (a headless one-shot, not a seed) and its interactive TUI takes no
// initial-prompt flag — live-verified 2026-07-09 — so there is no
// inject_prompt lane. The launcher writes the handover doc (file lane),
// prints a pointer to paste, and opens the interactive TUI in the source
// session's project root.
//
// NON-PROXIED on purpose. kimi-code's openai-compat endpoint lives in
// ~/.kimi-code/config.toml (a NEVER-READ file — plaintext API key) and is
// PROMOTED in the integration registry (routable_now, live-verified
// 2026-07-09): routing flows through the `observer init` config writer's
// additive [providers.openai].base_url entry, NOT through this launcher.
// Token capture happens via observer's local kimi-code wire.jsonl adapter,
// not the proxy. The launcher execs `kimi` with the caller's own
// environment — it never sets an API key or base URL.
func newKimiCmd() *cobra.Command {
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
		Use:     "kimi [-- kimi-args...]",
		Aliases: []string{"kimi-code"},
		Short:   "Launch kimi-code; with --continue-from, write a handover doc and open the TUI (doc-assisted)",
		Long: "Wraps Moonshot AI's kimi-code CLI (`kimi`). This launcher is\n" +
			"NON-PROXIED — kimi-code's endpoint config lives in its never-read\n" +
			"config.toml, and no live routed turn has confirmed proxy capture.\n" +
			"Token capture happens via observer's local kimi-code wire.jsonl\n" +
			"adapter, not the proxy.\n\n" +
			"kimi-code supports a top-level `--model` flag to select which model\n" +
			"the session uses (pass it after `--` with your other kimi args).\n\n" +
			"With --continue-from <session-id> the launch is DOC-ASSISTED:\n" +
			"kimi-code has no initial-prompt seed lane (`-p` prints and exits;\n" +
			"the TUI takes no seed flag), so the launcher writes the handover\n" +
			"doc, prints its path for you to paste, and opens the interactive\n" +
			"TUI in the source session's project root. See\n" +
			"docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to kimi. Use `--`\n" +
			"to separate observer flags from kimi flags. NEVER touches API keys.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (kimi is launched non-proxied — no
			// proxy env, no escape-hatch flag). kimi-code is DocAssisted, so
			// --continue-from writes a doc + opens the TUI rather than seeding a
			// prompt — but that lives under the handoff-fork family (incompatible)
			// anyway; plain attach launches the TUI with no seed. The both-TTY
			// guard covers scripted runs.
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "kimi-code",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				// `-p` is a genuine headless one-shot (kimi-code's `-p` prints
				// and EXITS — the registry note), so guard it: attaching a
				// print-and-exit run would be spam.
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsContainHeadlessFlag(args, "-p"),
				passthrough: append(kimiAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `kimi --session <id>` (bare path).
			// kimi requires the PREFIXED `session_<uuid>` id; the shared transform
			// ensures it (our adapter already stores that form). Distinct from the
			// DocAssisted --continue-from below (kimi-code has no seed lane).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "kimi", label: "kimi", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("kimi-code", binPath, "--kimi-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				fork, ferr := forkFromFlags(fromMessage, fromTime)
				if ferr != nil {
					return ferr
				}
				out, cerr := resolveContinueFromDoc(cmd.Context(), configPath, continueFrom, "kimi-code", carry, fork)
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer kimi: continue-from failed: %v\n", cerr)
					return cerr
				}
				fmt.Fprintf(cmd.ErrOrStderr(),
					"observer kimi: kimi-code has no initial-prompt seed — handover written to %s\n", out.DocPath)
				fmt.Fprintf(cmd.ErrOrStderr(),
					"observer kimi: paste it as your first message in the TUI, or run `kimi -p \"$(cat %s)\"` for a headless one-shot\n", out.DocPath)
				if out.Note != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer kimi: %s\n", out.Note)
				}
				continueDir = launchDir(out.ProjectRoot)
				if continueDir != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer kimi: continuing in %s\n", continueDir)
				}
			}

			// Best-effort attribution config: a load failure just disables
			// the launch seed (recordLaunchSeed treats "" as off).
			dbPath := ""
			if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
				dbPath = cfg.Observer.DBPath
			}
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "kimi-code", "kimi", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "kimi-path", "", "Path to the kimi binary (default: resolve `kimi` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover, write it to disk, and open the kimi TUI (doc-assisted — kimi-code has no initial-prompt seed). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "kimi-code")
	resume = registerResumeFlag(cmd, "kimi-code")
	return cmd
}

// kimiAttachPassthrough forwards the --kimi-path wrapper flag to the
// daemon-spawned inner `observer kimi` launcher when set (nil otherwise).
func kimiAttachPassthrough(kimiPath string) []string {
	if kimiPath != "" {
		return []string{"--kimi-path", kimiPath}
	}
	return nil
}
