// pool.go — `observer pool` launcher subcommand (Poolside's `pool` CLI, tool
// key "poolside").

package main

import (
	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// poolHeadlessSubcommands are the `pool` verbs that do not open the
// interactive TUI (docs.poolside.ai/cli/cli-reference.md, 2026-10-03): `exec`
// runs one prompt and exits, `acp` serves the Agent Client Protocol to an IDE,
// and `login` is the sign-in flow.
var poolHeadlessSubcommands = map[string]bool{"exec": true, "acp": true, "login": true}

// newPoolCmd implements `observer pool`: it launches Poolside's standalone
// `pool` CLI, which "starts an interactive session by default", so the
// dashboard can start and attach to it in a PTY.
//
// DOC-ASSISTED --continue-from. `pool -q/--prompt-queue` is documented as the
// interactive seed but is not live-verified, so the launcher writes the
// handover doc and opens the TUI instead.
//
// NON-PROXIED. `pool` signs in with `pool login` or POOLSIDE_API_KEY; its
// POOLSIDE_STANDALONE_BASE_URL is an alternative-provider mode with no routed
// proof, so the launcher execs `pool` with the caller's own environment.
func newPoolCmd() *cobra.Command {
	var (
		configPath string
		binPath    string
		fork       docAssistedFlags
		attach     *bool
		noAttach   *bool
	)
	cmd := &cobra.Command{
		Use:     "pool [-- pool-args...]",
		Aliases: []string{"poolside"},
		Short:   "Launch Poolside's pool CLI; with --continue-from, write a handover doc and open the TUI (doc-assisted)",
		Long: "Wraps Poolside's standalone CLI (`pool`). This launcher is\n" +
			"NON-PROXIED: pool signs in with `pool login` or POOLSIDE_API_KEY.\n\n" +
			"With --continue-from <session-id> the launch is DOC-ASSISTED: the\n" +
			"launcher writes the handover doc, prints its path for you to paste,\n" +
			"and opens the interactive TUI in the source session's project root.\n" +
			"See `observer handoff --help`.\n\n" +
			"All arguments after the subcommand are forwarded to pool. Use `--`\n" +
			"to separate observer flags from pool flags. NEVER touches keys.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "poolside",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: fork.engaged() ||
					argsLeadWithSubcommand(args, poolHeadlessSubcommands) ||
					argsContainHeadlessFlag(args, "-h", "--help", "--version"),
				passthrough: binPathPassthrough("--pool-path", binPath),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			bin, err := resolveToolBin("poolside", binPath, "--pool-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			dir, err := docAssistedContinue(cmd.Context(), cmd.ErrOrStderr(), configPath, "poolside", "pool", fork)
			if err != nil {
				return err
			}
			dbPath := ""
			if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath}); cErr == nil {
				dbPath = cfg.Observer.DBPath
			}
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "poolside", "pool", bin, args, dir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "pool-path", "", "Path to the pool binary (default: resolve `pool` on PATH)")
	registerDocAssistedFlags(cmd, "pool", &fork)
	attach, noAttach = registerAttachFlags(cmd, "poolside")
	return cmd
}
