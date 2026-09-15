// opencode.go — `observer opencode` launcher subcommand.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newOpencodeCmd implements `observer opencode` — sets OPENAI_BASE_URL
// to the observer proxy's OpenAI-compatible endpoint and execs the
// user's `opencode` binary so its model traffic flows through the proxy
// for accurate token capture + compression.
//
// Unlike `observer codex` (which must inject `-c openai_base_url`
// because codex's inner app-server ignores the env var — the V6-2
// gotcha), OpenCode is a plain OpenAI-compatible client that honors
// OPENAI_BASE_URL directly (verified in docs/audits/vultr-teams-
// opencode.md). So this launcher is the simple env-injection shape.
func newOpencodeCmd() *cobra.Command {
	var (
		configPath   string
		proxyURL     string
		opencodePath string
		continueFrom string
		carry        string
		fromMessage  int
		fromTime     string
		attach       *bool
		noAttach     *bool
		resume       *string
	)
	cmd := &cobra.Command{
		Use:   "opencode [-- opencode-args...]",
		Short: "Launch OpenCode with traffic routed through the observer proxy",
		Long: "Wraps `opencode` with OPENAI_BASE_URL pointed at the observer\n" +
			"proxy's OpenAI-compatible endpoint (…/v1). OpenCode honors\n" +
			"OPENAI_BASE_URL directly, so no config-file injection is needed\n" +
			"(unlike `observer codex`).\n\n" +
			"All arguments after the subcommand are forwarded to opencode.\n" +
			"Use `--` to separate observer flags from opencode flags:\n" +
			"    observer opencode -- run \"summarize the diff\"\n\n" +
			"With --continue-from <session-id> the launcher distills a handover\n" +
			"from that session and seeds it via opencode's --prompt flag\n" +
			"(delivery=inject_prompt). See docs/session-handoff.md.\n\n" +
			"Caveat: an Azure-direct provider configured in OpenCode may\n" +
			"bypass OPENAI_BASE_URL (observer then sees local activity but no\n" +
			"proxy-level api_turns). Run `observer doctor opencode` to check.\n\n" +
			"Requires a running observer proxy. Start one with `observer\n" +
			"start` or `observer proxy start` first.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			// Attach-by-default (attach-all-launchers): when attach resolves,
			// hand the PTY to the daemon so the dashboard can view/drive this
			// SAME live opencode session. opencode self-routes via
			// OPENAI_BASE_URL in the daemon-spawned inner launcher, so we forward
			// NO proxy env (attachEnv nil) and there is no --no-proxy-route flag
			// to forward (noProxyRoute nil). A leading `run` subcommand (headless
			// one-shot) or the continue-from family forces the bare path. toolArgs
			// is the RAW operator remainder — the inner launcher re-applies its
			// own OPENAI_BASE_URL injection and arg-build.
			outcome, err := launcherAttach(cmd.Context(), launcherAttachSpec{
				tool:          "opencode",
				configPath:    configPath,
				proxyOverride: proxyURL,
				proxyFlag:     "--proxy",
				flagAttach:    *attach,
				flagNoAttach:  *noAttach,
				incompatible: continueFamilyEngaged(continueFrom, carry, fromMessage, fromTime) ||
					argsLeadWithSubcommand(args, opencodeHeadlessSubcommands),
				passthrough: append(opencodeAttachPassthrough(opencodePath), resumeAttachPassthrough(*resume)...),
				toolArgs:    args,
				stderr:      cmd.ErrOrStderr(),
			})
			if outcome.handled {
				return err
			}
			// Native resume (native-resume wave): translate `--resume <id>` to
			// `opencode --session <id>` on the bare path. Mutually exclusive with
			// the handoff-fork family (rejected loud); the attach branch above
			// already forwarded --resume to the daemon-spawned inner launcher.
			resumedArgs, releaseResume, okResume, resumeErr := applyLauncherResume(launcherResumeSpec{
				verb: "opencode", label: "opencode", configPath: configPath, id: *resume,
				continueFrom: continueFrom, carry: carry, fromMessage: fromMessage, fromTime: fromTime,
				args: args, stderr: cmd.ErrOrStderr(),
			})
			if !okResume {
				return resumeErr
			}
			defer releaseResume()
			args = resumedArgs
			// --continue-from: distill a handover from the source session and
			// seed it via opencode's --prompt flag before the launcher builds
			// the child argv. The proxy env (OPENAI_BASE_URL) is injected
			// inside runOpencodeLauncher AFTER arg-build, so only `args`
			// changes here.
			var continueDir string
			if continueFrom != "" {
				seeded, cwd, cerr := continueFromArgs(cmd.Context(), continueFromParams{
					tool:        "opencode",
					label:       "opencode",
					configPath:  configPath,
					sessionID:   continueFrom,
					carry:       carry,
					fromMessage: fromMessage,
					fromTime:    fromTime,
					args:        args,
					// opencode --prompt seeds the interactive TUI's first
					// prompt (the headless one-shot form is the `run`
					// subcommand). opencode's bare positional is a PROJECT
					// PATH, not a prompt, so BarePositionalIsPrompt stays at
					// its zero value — only --prompt collides.
					inject: promptInjection{
						Kind:          injectFlagValue,
						Flag:          "--prompt",
						ConflictFlags: []string{"--prompt"},
					},
					stderr: cmd.ErrOrStderr(),
				})
				if cerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "observer opencode: continue-from failed: %v\n", cerr)
					return cerr
				}
				args = seeded
				continueDir = cwd
			}
			return runOpencodeLauncher(opencodeLauncherOptions{
				configPath:   configPath,
				proxyURL:     proxyURL,
				opencodePath: opencodePath,
				opencodeArgs: args,
				dir:          continueDir,
				stderr:       cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "Override the observer proxy URL (default: http://127.0.0.1:<cfg.proxy.port>)")
	cmd.Flags().StringVar(&opencodePath, "opencode-path", "", "Path to the opencode binary (default: resolve `opencode` on PATH)")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via opencode's --prompt flag (delivery=inject_prompt). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	attach, noAttach = registerAttachFlags(cmd, "opencode")
	resume = registerResumeFlag(cmd, "opencode")
	return cmd
}

// opencodeHeadlessSubcommands are the opencode leading verbs whose mode is a
// non-interactive one-shot (no interactive PTY to attach) — currently just
// `run`. A leading `run` classifies the launch incompatible with attach, so it
// takes the bare path (attach-all-launchers §4).
var opencodeHeadlessSubcommands = map[string]bool{"run": true}

// opencodeAttachPassthrough forwards --opencode-path to the daemon-spawned
// inner `observer opencode` launcher when the operator overrode the binary
// path; nil otherwise.
func opencodeAttachPassthrough(opencodePath string) []string {
	if opencodePath != "" {
		return []string{"--opencode-path", opencodePath}
	}
	return nil
}

type opencodeLauncherOptions struct {
	configPath   string
	proxyURL     string
	opencodePath string
	opencodeArgs []string
	dir          string // child cwd; "" inherits. Set by --continue-from to the source project root.
	stderr       interface{ Write([]byte) (int, error) }
}

// runOpencodeLauncher resolves the proxy URL, injects OPENAI_BASE_URL,
// and execs opencode with the original argv. Exit code is forwarded via
// exitErr (same shape as the claude/codex launchers).
func runOpencodeLauncher(opts opencodeLauncherOptions) error {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: opts.configPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	proxyURL := resolveProxyURL(cfg.Proxy.Port, opts.proxyURL)

	bin, err := resolveToolBin("opencode", opts.opencodePath, "--opencode-path", opts.configPath, opts.stderr)
	if err != nil {
		return err
	}

	// Layer the rename-safe agent runtime-dir env under OPENAI_BASE_URL, so an
	// SMB/NFS HOME (e.g. a containerized node on Azure Files) can't break
	// OpenCode's openrouter-provider npm/bun install (adapter-agnostic; no-op
	// unless [launch].agent_runtime_dir is set).
	env, baseURL, preset := prepareOpencodeEnv(applyChildPATH(applyAgentRuntimeEnv(os.Environ(), agentRuntimeDir()), daemonLoginPathDirs(), bin), proxyURL)
	if preset {
		fmt.Fprintf(opts.stderr,
			"observer opencode: OPENAI_BASE_URL already set in env (%s); using yours.\n", baseURL)
	}

	if !proxyReachable(proxyURL, 250*time.Millisecond) {
		fmt.Fprintf(opts.stderr,
			"observer opencode: warning — proxy not reachable at %s (start it with `observer start`)\n", proxyURL)
	} else {
		fmt.Fprintf(opts.stderr, "observer opencode: routing via %s\n", baseURL)
	}
	evidence := envBudgetLaunchEvidence("opencode", proxyURL,
		map[string]string{"OPENAI_BASE_URL": strings.TrimRight(proxyURL, "/") + "/v1"},
		env, opts.opencodeArgs)
	evidence.Executable = bin
	evidence.Arguments = opts.opencodeArgs
	if err := enforceBudgetControlledLaunch(context.Background(), opts.configPath, "opencode", evidence); err != nil {
		return err
	}

	child := exec.Command(bin, opts.opencodeArgs...) //nolint:gosec // user-launched tool, args are theirs
	child.Env = scrubOOBEnv(env)                     // strip the trusted OOB channel env
	child.Dir = opts.dir                             // "" inherits the caller's cwd; set by --continue-from to the source project root
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	discovery := prepareGenericDiscovery(context.Background(), "opencode", opts.dir)
	if rErr := child.Start(); rErr != nil {
		return fmt.Errorf("exec opencode: %w", rErr)
	}
	// Direct process attribution (migration 086): record the child pid now
	// that Start has made it knowable; retract the seed when the child is
	// reaped. Best-effort both ways — a seeding failure never affects the
	// launch (see cmd/observer/launchseed.go).
	recordLaunchSeed(cfg.Observer.DBPath, "opencode", opts.dir, child.Process.Pid, opts.stderr)
	// Best-effort generic post-launch session discovery (WS-DISCOVERY): a
	// no-op unless the trusted OOB channel is active AND "opencode" resolves
	// to an adapter that declares session-file watch roots. Cancel the
	// instant the child exits so a window cut short by exit never announces a
	// candidate that only looked unique because the scan stopped early.
	discoverCancel := discovery.start()
	if discoverCancel != nil {
		defer discoverCancel()
	}
	if rErr := child.Wait(); rErr != nil {
		var ee *exec.ExitError
		if errors.As(rErr, &ee) {
			return exitErr(ee.ExitCode())
		}
		return fmt.Errorf("exec opencode: %w", rErr)
	}
	return nil
}

// prepareOpencodeEnv sets OPENAI_BASE_URL=<proxyURL>/v1 in the child env
// unless the user already exported one (theirs wins — the launcher never
// clobbers explicit env state). Returns the final env, the effective
// base URL, and whether a pre-existing value was kept.
func prepareOpencodeEnv(parent []string, proxyURL string) (env []string, baseURL string, preset bool) {
	target := strings.TrimRight(proxyURL, "/") + "/v1"
	out, _, presets := applyBaseURLEnv(parent, map[string]string{"OPENAI_BASE_URL": target})
	if len(presets) > 0 {
		return out, envValue(out, "OPENAI_BASE_URL"), true
	}
	return out, target, false
}
