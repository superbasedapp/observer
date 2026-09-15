// aider.go — `observer aider` launcher subcommand.

package main

import (
	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newAiderCmd implements `observer aider` — launches Aider (binary `aider`),
// routed through the observer proxy by injecting OPENAI_API_BASE (unless the
// operator already set it). This is a MINIMAL launcher: no --attach, no
// --resume, no --continue-from wiring. Aider's own capture path is its
// per-repo .aider.chat.history.md transcript, watched independently of the
// proxy — the proxy route exists purely to land accurate api_turns rows and
// enable conversation compression, same as opencode/cline-cli/pi.
//
// It never touches API keys — only the base URL.
func newAiderCmd() *cobra.Command {
	var (
		configPath string
		binPath    string
	)
	cmd := &cobra.Command{
		Use:   "aider [-- aider-args...]",
		Short: "Launch Aider, routed through the observer proxy",
		Long: "Wraps Aider (`aider`), routing its traffic through the observer\n" +
			"proxy by injecting OPENAI_API_BASE at the proxy's OpenAI-compatible\n" +
			"root (unless you've already set it yourself — your value always\n" +
			"wins). This is a minimal launcher: no --attach, --resume, or\n" +
			"--continue-from. Aider's own .aider.chat.history.md transcript is\n" +
			"observer's local capture path regardless of the proxy route.\n\n" +
			"All arguments after the subcommand are forwarded to aider. Use `--`\n" +
			"to separate observer flags from aider flags. NEVER touches API keys.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}

			bin, err := resolveToolBin("aider", binPath, "--aider-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath})
			if cErr != nil {
				return cErr
			}
			resolved := resolveProxyURL(cfg.Proxy.Port, "")
			return runEnvLauncher(envLauncherSpec{
				tool:       "aider",
				bin:        bin,
				args:       args,
				configPath: configPath,
				proxyURL:   resolved,
				env:        map[string]string{"OPENAI_API_BASE": resolved + "/v1"},
				dbPath:     cfg.Observer.DBPath,
				stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&binPath, "aider-path", "", "Path to the aider binary (default: resolve `aider` on PATH)")
	return cmd
}
