// crush.go — `observer crush` launcher subcommand.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// newCrushCmd implements `observer crush` — applies the SAME additive
// providers.openai.base_url write to crush.json that `observer init` uses
// (proxyroute.RegisterCrush, idempotent, never a key) and then execs the
// user's `crush` binary, so its model traffic flows through the observer
// proxy for accurate token capture.
//
// Crush routes via a CONFIG FILE, not an env var (registry RouteProviderJSON,
// live-verified 2026-07-09 via api_turns 23081/23080) — so unlike the env
// launchers there is nothing to inject at exec time; this launcher's value is
// ensuring the route exists before every launch, not only at init.
//
// Fail-open: a missing crush.json (ConfigMissing) or a foreign base_url the
// writer refuses to overwrite (Error) prints a one-line notice and launches
// anyway with the caller's own environment — identical posture to running
// bare `crush`. It never touches an API key.
func newCrushCmd() *cobra.Command {
	var (
		configPath string
		crushPath  string
	)
	cmd := &cobra.Command{
		Use:   "crush [-- crush-args...]",
		Short: "Launch Crush with its OpenAI provider routed through the observer proxy",
		Long: "Applies the additive providers.openai.base_url route to crush.json\n" +
			"(the same write `observer init` performs — never reads or moves an API\n" +
			"key) and then execs `crush` with your own environment. Use `--` to\n" +
			"separate observer flags from crush flags.\n\n" +
			"If crush.json is absent or already points at a foreign base URL, the\n" +
			"launcher says so and launches unproxied — token capture then falls back\n" +
			"to observer's local crush adapter.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			cfg, cErr := config.Load(config.LoadOptions{GlobalPath: configPath})
			if cErr != nil {
				return fmt.Errorf("load config: %w", cErr)
			}
			if reg, rErr := proxyroute.NewRegistrar(proxyroute.RegisterOptions{
				ProxyPort: cfg.Proxy.Port,
			}); rErr == nil {
				res := reg.RegisterCrush()
				switch {
				case res.ConfigMissing:
					fmt.Fprintln(cmd.ErrOrStderr(),
						"observer crush: no crush.json found — launching unproxied (run `observer init --skip-hooks=false` after creating one to route)")
				case res.Error != nil:
					fmt.Fprintf(cmd.ErrOrStderr(),
						"observer crush: route write refused (%v) — launching unproxied\n", res.Error)
				case res.Added:
					fmt.Fprintf(cmd.ErrOrStderr(),
						"observer crush: routed providers.openai.base_url → %s (in %s)\n", res.BaseURL, res.ConfigPath)
				case res.AlreadySet:
					fmt.Fprintln(cmd.ErrOrStderr(), "observer crush: crush.json already routed through the observer proxy")
				}
			}
			bin, err := resolveToolBin("crush", crushPath, "--crush-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			return runSeedOnlyLaunchSeeded(configPath, cfg.Observer.DBPath, "crush", "crush", bin, args, "")
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&crushPath, "crush-path", "", "Path to the crush binary (default: resolve `crush` on PATH)")
	return cmd
}
