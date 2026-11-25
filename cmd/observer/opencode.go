// opencode.go — `observer opencode` launcher subcommand.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

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
			"(delivery=inject_prompt). See `observer handoff --help`.\n\n" +
			"Caveat: an Azure-direct provider configured in OpenCode may\n" +
			"bypass OPENAI_BASE_URL (observer then sees local activity but no\n" +
			"proxy-level api_turns). Run `observer doctor opencode` to check.\n\n" +
			"Routes through the observer proxy. When the daemon is not running\n" +
			"the launcher starts it first and waits for its proxy (--no-start or\n" +
			"[launch].start_daemon = false skip that). When it still does not\n" +
			"answer, opencode launches WITHOUT proxy routing and the launcher\n" +
			"says so; it refuses\n" +
			"instead when your own OPENAI_BASE_URL or OPENCODE_CONFIG_CONTENT\n" +
			"still points at the proxy, or when your organization owns this\n" +
			"managed machine's routes.",
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
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it via opencode's --prompt flag (delivery=inject_prompt). See observer handoff --help.")
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
	// P6 item 5 + G8: the process that starts the tool refuses an
	// org-disallowed tool and counts a tool grant's use, once (review M3-10).
	if err := refuseIfToolDisallowedCfg(cfg, "opencode", opts.stderr); err != nil {
		return err
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
	childBase := applyChildPATH(applyAgentRuntimeEnv(os.Environ(), agentRuntimeDir()), daemonLoginPathDirs(), bin)
	var (
		env     []string
		baseURL string
		preset  bool
	)
	// Proxy-down fallback (lane launcher-proxy-down; D-514 for a build
	// without capture.proxy): never point OpenCode at a dead port. The gate
	// neutralizes (one notice, no OPENAI_BASE_URL / OPENCODE_CONFIG_CONTENT
	// from the launcher, no proxied marker) or fails closed when a value the
	// caller set still points at the proxy, or the organization owns this
	// managed machine's routes. preset keeps the run's telemetry unmarked.
	outcome, gateErr := envLauncherProxyGate(context.Background(), envProxyGateRequest{
		label:      "opencode",
		configPath: opts.configPath,
		proxyURL:   proxyURL,
		inject:     map[string]string{"OPENAI_BASE_URL": strings.TrimRight(proxyURL, "/") + "/v1"},
		parentEnv:  childBase,
		callerPins: func() []string { return opencodeContentPins(childBase, proxyURL) },
		stderr:     opts.stderr,
	})
	if gateErr != nil {
		return gateErr
	}
	if outcome == envProxyGateNeutralize {
		env, preset = childBase, true
	} else {
		env, baseURL, preset = prepareOpencodeEnv(childBase, proxyURL)
		if preset {
			fmt.Fprintf(opts.stderr,
				"observer opencode: OPENAI_BASE_URL already set in env (%s); using yours.\n", baseURL)
		}
		// OpenCode's built-in Zen provider ignores OPENAI_BASE_URL; route it
		// through the proxy's opencode-zen lane too, or a Zen session (the
		// free default models) bypasses the proxy: no prompt-lane warning, no
		// accurate tokens.
		var zenRouted bool
		openaiBase := ""
		if !preset {
			openaiBase = baseURL
		}
		env, zenRouted = prepareOpencodeZenRoute(env, proxyURL, openaiBase)
		if !zenRouted {
			fmt.Fprintln(opts.stderr,
				"observer opencode: OPENCODE_CONFIG_CONTENT already set in env; OpenCode Zen models are not routed through the proxy.")
		}

		if opencodeContentShadowsRoute(env, proxyURL) {
			// CLI-2: the caller's config content decides the openai
			// provider's host; this launch proves no route and its
			// telemetry is not marked proxied.
			fmt.Fprintln(opts.stderr,
				"observer opencode: not routed through the proxy: OPENCODE_CONFIG_CONTENT sets provider.openai.options.baseURL, which OpenCode reads over OPENAI_BASE_URL; point it at the proxy or remove it to route this launch")
			preset = true
		} else {
			fmt.Fprintf(opts.stderr, "observer opencode: routing via %s\n", redactRouteURL(baseURL))
		}
	}
	evidence := envBudgetLaunchEvidence("opencode", proxyURL,
		map[string]string{"OPENAI_BASE_URL": strings.TrimRight(proxyURL, "/") + "/v1"},
		env, opts.opencodeArgs)
	if outcome == envProxyGateNeutralize || opencodeContentShadowsRoute(env, proxyURL) {
		// A neutralized launch carries no route of ours, whatever the caller's
		// environment holds; the managed budget gate judges it as unrouted.
		evidence = budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	}
	evidence.Executable = bin
	evidence.Arguments = opts.opencodeArgs
	if err := enforceBudgetControlledLaunch(context.Background(), opts.configPath, "opencode", evidence); err != nil {
		return err
	}

	child := exec.Command(bin, opts.opencodeArgs...) //nolint:gosec // user-launched tool, args are theirs
	if !preset {
		env = withOTelRouteMarker(env, "opencode") // T-536: this run's export is proxied
	}
	child.Env = scrubOOBEnv(env) // strip the trusted OOB channel env
	child.Dir = opts.dir         // "" inherits the caller's cwd; set by --continue-from to the source project root
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	discovery := prepareGenericDiscovery(context.Background(), "opencode", opts.dir)
	if rErr := child.Start(); rErr != nil {
		noteBoxToolLaunch(opts.stderr, "opencode", bin, opts.opencodeArgs, rErr)
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
		noteBoxToolLaunch(opts.stderr, "opencode", bin, opts.opencodeArgs, rErr)
		var ee *exec.ExitError
		if errors.As(rErr, &ee) {
			return exitErr(ee.ExitCode())
		}
		return fmt.Errorf("exec opencode: %w", rErr)
	}
	return nil
}

// opencodeContentPins returns ["OPENCODE_CONFIG_CONTENT"] when the caller
// set it with any provider's options.baseURL reaching the proxy's listener
// (OpenCode reads it over OPENAI_BASE_URL and over its config files, and the
// launcher never replaces a caller's value), else nil. Only the provider
// baseURL members are decoded.
func opencodeContentPins(env []string, proxyURL string) []string {
	raw, ok := lookupEnvValue(env, "OPENCODE_CONFIG_CONTENT")
	if !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	var doc struct {
		Provider map[string]struct {
			Options struct {
				BaseURL string `json:"baseURL"`
			} `json:"options"`
		} `json:"provider"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return nil
	}
	for _, p := range doc.Provider {
		if proxyListenerURL(p.Options.BaseURL, proxyURL) {
			return []string{"OPENCODE_CONFIG_CONTENT"}
		}
	}
	return nil
}

// prepareOpencodeZenRoute points OpenCode's built-in Zen provider
// ("opencode", e.g. the free big-pickle model, served from
// opencode.ai/zen) at the proxy's config.OpenCodeZenLane lane through
// OPENCODE_CONFIG_CONTENT, which OpenCode merges over its config files.
// OPENAI_BASE_URL only reroutes the openai provider, so without this a
// Zen session never touched the proxy (demo node 1, 2026-10-02: no
// prompt-lane warning on a pasted token). A caller-set
// OPENCODE_CONFIG_CONTENT is left alone (routed=false).
//
// openaiBase, when set (the launcher's own OPENAI_BASE_URL, not a preset
// one), is carried as provider.openai.options.baseURL too (surface-gap
// CLI-2): a project or user opencode.json that sets that key outranks the
// environment variable, and the config content outranks every file.
func prepareOpencodeZenRoute(parent []string, proxyURL, openaiBase string) (env []string, routed bool) {
	providers := map[string]any{
		"opencode": map[string]any{"options": map[string]any{"baseURL": strings.TrimRight(proxyURL, "/") + "/up/" + config.OpenCodeZenLane + "/v1"}},
	}
	if openaiBase != "" {
		providers["openai"] = map[string]any{"options": map[string]any{"baseURL": openaiBase}}
	}
	b, err := json.Marshal(map[string]any{"provider": providers})
	if err != nil {
		return parent, false
	}
	out, _, presets := applyBaseURLEnv(parent, map[string]string{"OPENCODE_CONFIG_CONTENT": string(b)})
	return out, len(presets) == 0
}

// opencodeContentShadowsRoute reports whether a caller-set
// OPENCODE_CONFIG_CONTENT takes the openai provider away from the proxy
// (CLI-2): it sets provider.openai.options.baseURL to something else, which
// OpenCode reads over OPENAI_BASE_URL, or it does not parse, so the route
// cannot be shown to hold. Read from the child environment only.
func opencodeContentShadowsRoute(env []string, proxyURL string) bool {
	raw, ok := lookupEnvValue(env, "OPENCODE_CONFIG_CONTENT")
	if !ok || strings.TrimSpace(raw) == "" {
		return false
	}
	var doc struct {
		Provider map[string]struct {
			Options map[string]any `json:"options"`
		} `json:"provider"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return true
	}
	v, ok := doc.Provider["openai"].Options["baseURL"]
	if !ok {
		return false
	}
	s, _ := v.(string)
	return !urlRoutesToProxy(s, proxyURL)
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
