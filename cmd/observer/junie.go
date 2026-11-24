// junie.go — `observer junie` launcher subcommand (JetBrains Junie CLI).

package main

import (
	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newJunieCmd implements `observer junie`: it launches the standalone JetBrains
// Junie CLI (binary `junie`, junie.jetbrains.com/docs/junie-cli.html) so the
// dashboard can start and attach to a Junie session in a PTY.
//
// DOC-ASSISTED --continue-from. Junie documents `--prompt` as an interactive
// seed, but that lane is not live-verified, and a positional argument or
// `--task` runs HEADLESS and exits (junie.jetbrains.com/docs/parameters.html),
// so the launcher writes the handover doc and opens the TUI instead.
//
// NON-PROXIED. Junie authenticates with a JetBrains account, JUNIE_API_KEY or
// its own BYOK keys, and its endpoint knobs (JUNIE_LITELLM_URL, custom model
// profiles, config proxies) have no live routed proof, so the launcher execs
// `junie` with the caller's own environment. Capture is the junie adapter's
// ${JUNIE_HOME:-~/.junie}/sessions reader. It never reads or writes a key.
func newJunieCmd() *cobra.Command {
	var (
		configPath string
		binPath    string
		fork       docAssistedFlags
		attach     *bool
		noAttach   *bool
	)
	cmd := &cobra.Command{
		Use:   "junie [-- junie-args...]",
		Short: "Launch the JetBrains Junie CLI; with --continue-from, write a handover doc and open the TUI (doc-assisted)",
		Long: "Wraps the standalone JetBrains Junie CLI (`junie`). This launcher is\n" +
			"NON-PROXIED: Junie signs in with a JetBrains account, JUNIE_API_KEY or\n" +
			"its own BYOK keys, and observer captures its sessions from\n" +
			"${JUNIE_HOME:-~/.junie}/sessions.\n\n" +
			"With --continue-from <session-id> the launch is DOC-ASSISTED: the\n" +
			"launcher writes the handover doc, prints its path for you to paste,\n" +
			"and opens the interactive TUI in the source session's project root.\n" +
			"See `observer handoff --help`.\n\n" +
			"All arguments after the subcommand are forwarded to junie. Use `--`\n" +
			"to separate observer flags from junie flags. A positional task or\n" +
			"--task runs junie headless (it exits when done). NEVER touches keys.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate: default-on attach hands the PTY to the daemon. A
			// headless run (positional task, --task, --acp, an output format,
			// help/version) or the handoff-fork family takes the bare path.
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "junie",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: fork.engaged() || junieHeadless(args),
				passthrough:  binPathPassthrough("--junie-path", binPath),
				toolArgs:     args,
				stderr:       cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			bin, err := resolveToolBin("junie", binPath, "--junie-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			dir, err := docAssistedContinue(cmd.Context(), cmd.ErrOrStderr(), configPath, "junie", "junie", fork)
			if err != nil {
				return err
			}
			// Best-effort attribution config: a load failure just disables the
			// launch seed (recordLaunchSeed treats "" as off).
			dbPath := ""
			if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
				dbPath = cfg.Observer.DBPath
			}
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "junie", "junie", bin, args, dir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "junie-path", "", "Path to the junie binary (default: resolve `junie` on PATH)")
	registerDocAssistedFlags(cmd, "junie", &fork)
	attach, noAttach = registerAttachFlags(cmd, "junie")
	return cmd
}

// junieValueFlags are the junie flags documented as taking a separate value
// (junie.jetbrains.com/docs/parameters.html, 2026-10-03), so their value is
// never mistaken for a positional task.
var junieValueFlags = map[string]bool{
	"--model": true, "-p": true, "--project": true, "--session-id": true,
	"--auth": true, "-a": true, "--provider": true, "--channel": true,
	"--use-version": true, "--prompt": true,
}

// junieHeadless reports whether a forwarded argv runs junie non-interactively:
// a positional task or --task (headless, exits when done), --acp (an ACP
// server, not a TUI), an --output-format (scripted output), or help/version.
func junieHeadless(args []string) bool {
	if argsContainHeadlessFlag(args, "--task", "--acp", "--output-format", "-h", "--help", "--version") {
		return true
	}
	return argsHaveUndeclaredPositional(args, junieValueFlags)
}

// binPathPassthrough forwards a --<tool>-path wrapper flag to the
// daemon-spawned inner launcher when the operator set one (nil otherwise).
func binPathPassthrough(flag, binPath string) []string {
	if binPath != "" {
		return []string{flag, binPath}
	}
	return nil
}
