// antigravity.go — `observer antigravity` launcher subcommand.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newAntigravityCmd implements `observer antigravity-cli` — launches Google's
// Antigravity CLI (`agy`). Its primary purpose is `--continue-from`: distill a
// handover from a source session and seed it via `agy -i "<handover>"`
// (`-i` ≡ `--prompt-interactive`: "execute the provided prompt and continue in
// interactive mode"), so a migration INTO Antigravity opens the interactive
// session pre-loaded with the mission.
//
// Proxy routing depends on agy's auth mode (audit P2). In Google sign-in
// mode (the default) agy talks to its own backend with no base-URL knob:
// nothing to redirect, and token capture happens via observer's local
// Antigravity `.db` adapter (clidb.go). In API-key mode (settings.json
// modelProvider "gemini" + GEMINI_API_KEY) agy honours
// GOOGLE_GEMINI_BASE_URL (vendor install doc), so the launcher points it at
// the proxy's Gemini lane, which gives the prompt rules a pre-send seam
// (ask, deny). It never sets or reads an API key.
func newAntigravityCmd() *cobra.Command {
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
		Use:     "antigravity-cli [-- agy-args...]",
		Aliases: []string{"antigravity", "agy"},
		Short:   "Launch Antigravity CLI (agy); with --continue-from, seed a handover via agy -i",
		Long: "Wraps Google's Antigravity CLI (`agy`). In API-key mode\n" +
			"(settings.json modelProvider \"gemini\") it sets GOOGLE_GEMINI_BASE_URL\n" +
			"to the observer proxy, so prompt rules can act before send. Google\n" +
			"sign-in mode has no base-URL knob and stays non-proxied (capture via\n" +
			"observer's local Antigravity `.db` adapter).\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via agy's -i/--prompt-interactive\n" +
			"flag (delivery=inject_prompt), so Antigravity opens pre-loaded with\n" +
			"the mission. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to agy. Use `--`\n" +
			"to separate observer flags from agy flags. NEVER touches API keys.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach gate (attach-all-launchers): default-on attach hands the PTY
			// to the daemon. Seed-only spec (no escape-hatch flag; the API-key
			// mode base-URL env below is process-local). No -p/--prompt headless predicate: this
			// launcher only grounds -i/--prompt-interactive + a bare positional
			// seed, so a headless one-shot flag is NOT grounded here — the
			// handoff-fork family is the only incompatible mode (both-TTY guard
			// covers scripted runs).
			outcome, aErr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:         "antigravity-cli",
				configPath:   configPath,
				flagAttach:   *attach,
				flagNoAttach: *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime),
				passthrough:  append(antigravityAttachPassthrough(binPath), resumeAttachPassthrough(*resume)...),
				toolArgs:     args,
				stderr:       cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aErr
			}

			// Native resume: `--resume <id>` → `agy --conversation <id>` (bare path).
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "antigravity-cli", label: "antigravity-cli", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs

			bin, err := resolveToolBin("antigravity-cli", binPath, "--agy-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "antigravity-cli",
					label:       "antigravity-cli",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// agy -i/--prompt-interactive takes the initial prompt as
					// its value; flag both spellings as conflicts. agy is a
					// Gemini-family CLI whose bare positional is also an initial
					// prompt, so a forwarded positional competes with the seed
					// and must trip the collision check.
					inject: promptInjection{
						Kind:                   injectFlagValue,
						Flag:                   "-i",
						ConflictFlags:          []string{"-i", "--prompt-interactive"},
						BarePositionalIsPrompt: true,
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer antigravity-cli: continue-from failed: %v\n", cerr)
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
				// API-key mode only: route through the proxy (audit P2).
				home, _ := os.UserHomeDir()
				routeAgyAPIKeyMode(os.Environ(), home, resolveProxyURL(cfg.Proxy.Port, ""), os.Setenv, cmd.ErrOrStderr())
			}
			return runSeedOnlyLaunchSeeded(configPath, dbPath, "antigravity-cli", "agy", bin, args, continueDir)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml); used to resolve the source session for --continue-from")
	cmd.Flags().StringVar(&binPath, "agy-path", "", "Path to the agy binary (default: resolve `agy` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via agy's -i flag (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "antigravity-cli")
	resume = registerResumeFlag(cmd, "antigravity-cli")
	return cmd
}

// agySettings is the non-secret part of agy's settings.json the launcher
// reads to tell the auth mode.
type agySettings struct {
	ModelProvider string `json:"modelProvider"`
}

// agyAPIKeyMode reports whether agy runs in API-key mode: the vendor's
// documented switch is settings.json modelProvider "gemini" (with the key
// in GEMINI_API_KEY). Without it agy uses Google sign-in.
func agyAPIKeyMode(home string) bool {
	raw, err := os.ReadFile(filepath.Join(home, ".gemini", "antigravity-cli", "settings.json"))
	if err != nil {
		return false
	}
	var s agySettings
	return json.Unmarshal(raw, &s) == nil && s.ModelProvider == "gemini"
}

// routeAgyAPIKeyMode sets GOOGLE_GEMINI_BASE_URL to the proxy when agy is
// in API-key mode and the caller did not set it, and says which mode it
// saw (audit P2). In Google sign-in mode there is nothing to route: the
// prompt rules then warn or stop the turn before the main model call
// (PreInvocation hook; agy's title request is sent before any hook) and
// flag after send. Reports whether it set the variable.
func routeAgyAPIKeyMode(env []string, home, proxyURL string, setenv func(k, v string) error, stderr io.Writer) bool {
	if !agyAPIKeyMode(home) {
		fmt.Fprintln(stderr, "observer antigravity-cli: Google sign-in mode: not proxy-routable; prompt rules warn or stop the turn before the main model call (the title request is sent first) and flag after send.")
		return false
	}
	if cur := envValue(env, "GOOGLE_GEMINI_BASE_URL"); cur != "" {
		fmt.Fprintf(stderr, "observer antigravity-cli: API-key mode: GOOGLE_GEMINI_BASE_URL already set (%s); leaving it.\n", cur)
		return false
	}
	target := strings.TrimRight(proxyURL, "/")
	if err := setenv("GOOGLE_GEMINI_BASE_URL", target); err != nil {
		fmt.Fprintf(stderr, "observer antigravity-cli: API-key mode: could not set GOOGLE_GEMINI_BASE_URL: %v\n", err)
		return false
	}
	fmt.Fprintf(stderr, "observer antigravity-cli: API-key mode: routing via %s\n", redactRouteURL(target))
	return true
}

// antigravityAttachPassthrough forwards the --agy-path wrapper flag to the
// daemon-spawned inner `observer antigravity-cli` launcher when set (nil
// otherwise).
func antigravityAttachPassthrough(agyPath string) []string {
	if agyPath != "" {
		return []string{"--agy-path", agyPath}
	}
	return nil
}
