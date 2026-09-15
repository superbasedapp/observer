// openclaw.go — `observer openclaw` launcher subcommand.

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// openclawContinueSubcommand is the subcommand the `--continue-from` launch
// targets: `openclaw chat` (an alias for `tui --local`) is the interactive
// terminal UI, and `--message` sends the handover as its first message. The
// launcher ensures this leading subcommand so a seeded launch always opens
// the TUI rather than the top-level command.
const openclawContinueSubcommand = "chat"

// newOpenclawCmd implements `observer openclaw` — sets OPENAI_BASE_URL to the
// observer proxy's OpenAI-compatible endpoint and execs `openclaw` so its
// `openai`-provider model traffic flows through the proxy.
//
// GROUNDED (2026-06-26, live WSL install): OpenClaw's bundled `openai` plugin
// reads OPENAI_BASE_URL / OPENAI_API_BASE
// (plugin-runtime-deps/.../extensions/openai), and the operator's default
// model is on the `openai` provider — so the env redirect routes real
// traffic. The `openai-codex` provider is OAuth (ChatGPT-backed) and is NOT
// affected by this env. OpenClaw also fronts model calls with its own local
// gateway; confirm a live turn lands an api_turns row before relying on it,
// hence the PROBE label.
//
// With --continue-from <session-id> the launcher distills a handover and
// seeds it via `openclaw chat --message "<handover>"` (chat ≡ tui --local).
// That path runs NON-PROXIED on purpose: `--local` stalls when routed through
// the observer proxy (project_openclaw_runtime_block), and the handover seed
// is orthogonal to token capture (which stays on openclaw's trajectory
// adapter). So a seeded launch opens the interactive TUI without the stall.
func newOpenclawCmd() *cobra.Command {
	var (
		configPath   string
		proxyURL     string
		binPath      string
		continueFrom string
		carry        string
		fromMessage  int
		fromTime     string
		attach       *bool
		noAttach     *bool
	)
	cmd := &cobra.Command{
		Use:   "openclaw [-- openclaw-args...]",
		Short: "Launch OpenClaw with openai-provider traffic routed through the observer proxy (probe)",
		Long: "Wraps `openclaw` with OPENAI_BASE_URL pointed at the observer\n" +
			"proxy's OpenAI-compatible endpoint (…/v1). OpenClaw's `openai`\n" +
			"plugin honors OPENAI_BASE_URL, so traffic on the `openai` provider\n" +
			"routes through the proxy. The `openai-codex` (OAuth) provider is\n" +
			"unaffected.\n\n" +
			"PROBE: confirm a turn lands an api_turns row before relying on it\n" +
			"(OpenClaw fronts calls with its own local gateway).\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"and seeds it via `openclaw chat --message \"<handover>\"` (the\n" +
			"interactive TUI). That path runs NON-PROXIED to avoid the known\n" +
			"`--local` proxy-routing stall; token capture stays on openclaw's\n" +
			"own adapter. See docs/session-handoff.md.\n\n" +
			"All arguments after the subcommand are forwarded to openclaw. Use\n" +
			"`--` to separate observer flags from openclaw flags. NEVER touches\n" +
			"API keys. Requires a running observer proxy (`observer start`).",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach-by-default (attach-all-launchers): hand the PTY to the
			// daemon when attach resolves. openclaw self-routes via
			// OPENAI_BASE_URL in the daemon-spawned inner launcher, so forward NO
			// proxy env (attachEnv nil) and no --no-proxy-route flag exists
			// (noProxyRoute nil). ONLY the continue-from family forces the bare
			// path (its non-proxied `chat --message` seed is continue-from-gated
			// and never reached under a plain attach). toolArgs is the RAW
			// operator remainder — the inner launcher re-applies OPENAI_BASE_URL.
			outcome, aerr := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:          "openclaw",
				configPath:    configPath,
				proxyOverride: proxyURL,
				proxyFlag:     "--proxy",
				flagAttach:    *attach,
				flagNoAttach:  *noAttach,
				incompatible:  continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime),
				passthrough:   openclawAttachPassthrough(binPath),
				toolArgs:      args,
				stderr:        cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return aerr
			}

			bin, err := resolveToolBin("openclaw", binPath, "--openclaw-path", configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			// --continue-from: seed the handover into the interactive TUI via
			// `chat --message`, launched NON-PROXIED (see the doc comment).
			if continueFrom != "" {
				return runOpenclawContinue(cmd, openclawContinueParams{
					bin:         bin,
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					forwarded:   args,
				})
			}

			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			resolved := resolveProxyURL(cfg.Proxy.Port, proxyURL)
			return runEnvLauncher(envLauncherSpec{
				tool:       "openclaw",
				bin:        bin,
				args:       args,
				configPath: configPath,
				proxyURL:   resolved,
				env:        map[string]string{"OPENAI_BASE_URL": strings.TrimRight(resolved, "/") + "/v1"},
				dbPath:     cfg.Observer.DBPath,
				stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "Override the observer proxy URL (default: http://127.0.0.1:<cfg.proxy.port>)")
	cmd.Flags().StringVar(&binPath, "openclaw-path", "", "Path to the openclaw binary (default: resolve `openclaw` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via `openclaw chat --message` (delivery=inject_prompt, launched non-proxied). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "openclaw")
	return cmd
}

// openclawAttachPassthrough forwards --openclaw-path to the daemon-spawned
// inner `observer openclaw` launcher when the operator overrode the binary
// path; nil otherwise.
func openclawAttachPassthrough(binPath string) []string {
	if binPath != "" {
		return []string{"--openclaw-path", binPath}
	}
	return nil
}

// openclawContinueParams carries what runOpenclawContinue needs to seed and
// launch a non-proxied openclaw TUI from a source session.
type openclawContinueParams struct {
	bin         string
	configPath  string
	sessionID   string
	carry       string
	fromMessage int
	fromTime    string
	forwarded   []string
}

// runOpenclawContinue distills the handover, seeds it via
// `openclaw chat --message "<handover>"`, and execs openclaw NON-PROXIED
// (child inherits os.Environ() with no OPENAI_BASE_URL redirect) so the
// `--local` TUI starts without the known proxy-routing stall.
func runOpenclawContinue(cmd *cobra.Command, p openclawContinueParams) error {
	seeded, cwd, err := continueFromArgs(cmd.Context(), continueFromParams{
		tool:        "openclaw",
		label:       "openclaw",
		configPath:  p.configPath,
		sessionID:   p.sessionID,
		carry:       p.carry,
		fromMessage: p.fromMessage,
		fromTime:    p.fromTime,
		args:        p.forwarded,
		// openclaw's TUI seed is the `--message` flag value; --message-file is
		// its file-valued sibling (a competing seed). A bare positional here
		// is a subcommand/flag value, not a prompt (BarePositionalIsPrompt
		// stays false).
		inject: promptInjection{Kind: injectFlagValue, Flag: "--message", ConflictFlags: []string{"--message", "--message-file"}},
		stderr: cmd.ErrOrStderr(),
	})
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "observer openclaw: continue-from failed: %v\n", err)
		return err
	}
	// Ensure the interactive `chat` subcommand leads the argv so the seed
	// opens the TUI (chat ≡ tui --local) rather than the top-level command.
	launchArgs := ensureLeadingSubcommand(seeded, openclawContinueSubcommand)

	fmt.Fprintf(cmd.ErrOrStderr(),
		"observer openclaw: launching non-proxied `openclaw %s` (seed avoids the --local proxy stall; token capture via the openclaw adapter)\n",
		openclawContinueSubcommand)
	// The executable and argv are the process-cutoff recovery evidence: a
	// direct launch is admissible when the daemon attests live cutoff over
	// this exact installed surface (budgetlaunch_direct_linux.go), and without
	// them it could never be, however well covered the node is.
	if err := enforceBudgetControlledLaunch(cmd.Context(), p.configPath, "openclaw",
		budgetLaunchEvidence{
			Route: budgetLaunchRouteDirect, Executable: p.bin, Arguments: launchArgs,
		}); err != nil {
		return err
	}

	child := exec.Command(p.bin, launchArgs...) //nolint:gosec // user-launched tool; argv is the seeded handover + forwarded args
	child.Env = scrubOOBEnv(os.Environ())       // strip the trusted OOB channel env
	child.Dir = cwd                             // "" inherits the caller's cwd; set by --continue-from to the source project root
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if rErr := child.Start(); rErr != nil {
		return fmt.Errorf("exec openclaw: %w", rErr)
	}
	// Direct process attribution (migration 086): record the child pid now
	// that Start has made it knowable; retract the seed when the child is
	// reaped. Best-effort both ways — a seeding failure never affects the
	// launch (see cmd/observer/launchseed.go).
	dbPath := ""
	if cfg, cErr := config.Load(config.LoadOptions{GlobalPath: p.configPath}); cErr == nil {
		dbPath = cfg.Observer.DBPath
	}
	recordLaunchSeed(dbPath, "openclaw", cwd, child.Process.Pid, cmd.ErrOrStderr())
	if rErr := child.Wait(); rErr != nil {
		var ee *exec.ExitError
		if errors.As(rErr, &ee) {
			return exitErr(ee.ExitCode())
		}
		return fmt.Errorf("exec openclaw: %w", rErr)
	}
	return nil
}

// ensureLeadingSubcommand returns args with sub prepended unless it is
// already the first token (so a user who forwarded `chat …` themselves isn't
// double-prefixed).
func ensureLeadingSubcommand(args []string, sub string) []string {
	if len(args) > 0 && args[0] == sub {
		return args
	}
	return append([]string{sub}, args...)
}
