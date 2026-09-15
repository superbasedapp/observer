// codex.go — `observer codex` launcher subcommand.
//
// Codex CLI 0.129.0 supports two auth paths (API key sk-... and
// ChatGPT-Plus subscription JWT) and routes both through `/v1/responses`
// — the API-key form against api.openai.com directly, the JWT form
// against chatgpt.com/backend-api/codex/responses. Both forms can be
// redirected at observer's proxy by overriding the built-in `openai`
// provider's base URL via the `openai_base_url` top-level config field.
//
// The launcher injects `-c openai_base_url='"<proxy>/v1"'` into codex's
// argv so observer's proxy intercepts the request body. The proxy
// detects the auth shape (sk- vs eyJ JWT) and path-translates to
// chatgpt.com when needed (see internal/proxy/provider.go::isChatGPTAuthRequest
// + translateChatGPTPath). Same upstream billing — observer just gets
// to see (and compress) the body.
//
// Distinct from `observer claude`: codex doesn't have an OAuth token
// re-export problem because both auth shapes already ride the standard
// Authorization Bearer header that the proxy intercepts unmodified.
// All we need is to point the base URL at the proxy.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/codexipc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/jobobject"
)

// newCodexCmd implements `observer codex` — runs the user's `codex`
// binary with `-c openai_base_url='"<proxy>/v1"'` injected so the
// Responses API call lands at the observer proxy.
func newCodexCmd() *cobra.Command {
	var (
		configPath       string
		proxyURL         string
		codexPath        string
		exclusive        bool
		noAppServerCheck bool
		detectOnly       bool
		writeConfig      bool
		verify           bool
		continueFrom     string
		carry            string
		fromMessage      int
		fromTime         string
		attach           bool
		noAttach         bool
		noProxy          bool
		noProxyRoute     bool
		resume           string
	)
	cmd := &cobra.Command{
		Use:   "codex [-- codex-args...]",
		Short: "Launch Codex CLI with traffic routed through the observer proxy",
		Long: "Wraps `codex` with `-c openai_base_url='\"<proxy>/v1\"'` injected\n" +
			"into argv so the Responses API request lands at the observer proxy.\n" +
			"Both auth paths (API-key sk-... and ChatGPT-Plus JWT) flow through\n" +
			"the same override — the proxy detects the bearer shape and routes\n" +
			"to api.openai.com vs chatgpt.com/backend-api/codex/responses\n" +
			"automatically.\n\n" +
			"All arguments after the subcommand are forwarded to codex. Use\n" +
			"`--` to separate observer flags from codex flags:\n" +
			"    observer codex -- exec \"hello world\"\n\n" +
			"Requires a running observer proxy. Start one with `observer start`\n" +
			"or `observer proxy start` first.\n\n" +
			"Shared codex `app-server` processes (e.g., the VS Code Codex\n" +
			"extension or Codex Desktop) can silently intercept `codex exec`\n" +
			"calls via codex's global IPC pipe and bypass the proxy override\n" +
			"(V5-1). Pre- and post-flight checks warn when this happens; pass\n" +
			"`--exclusive` to terminate the shared app-server(s) before exec,\n" +
			"`--detect-only` to inspect without running codex, or\n" +
			"`--no-app-server-check` to silence. See\n" +
			"docs/codex-shared-app-server-gotcha.md.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			return runCodexLauncher(cmd.Context(), codexLauncherOptions{
				configPath:       configPath,
				proxyURL:         proxyURL,
				codexPath:        codexPath,
				codexArgs:        args,
				exclusive:        exclusive,
				noAppServerCheck: noAppServerCheck,
				detectOnly:       detectOnly,
				writeConfig:      writeConfig,
				verify:           verify,
				continueFrom:     continueFrom,
				carry:            carry,
				fromMessage:      fromMessage,
				fromTime:         fromTime,
				attach:           attach,
				noAttach:         noAttach,
				noProxy:          noProxy,
				noProxyRoute:     noProxyRoute,
				resume:           resume,
				stderr:           cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "Override the observer proxy URL (default: http://127.0.0.1:<cfg.proxy.port>)")
	cmd.Flags().StringVar(&codexPath, "codex-path", "", "Path to the codex binary (default: resolve `codex` on PATH)")
	cmd.Flags().BoolVar(&exclusive, "exclusive", false,
		"Terminate detected shared codex app-servers (e.g., VS Code Codex extension) before exec. Operator-hostile but bounded — see docs/codex-shared-app-server-gotcha.md.")
	cmd.Flags().BoolVar(&noAppServerCheck, "no-app-server-check", false,
		"Skip pre- and post-flight detection of shared codex app-servers. For scripts that have verified the host is clean.")
	cmd.Flags().BoolVar(&detectOnly, "detect-only", false,
		"Run pre-flight detection only and exit. Exit code 1 if any shared app-server is detected, 0 otherwise. Does not run codex.")
	cmd.Flags().BoolVar(&writeConfig, "write-config", false,
		"Auto-fix V6-2: when $CODEX_HOME/config.toml is missing openai_base_url (or points elsewhere), write it pointing at the observer proxy. A .bak file is created next to the original before any mutation. Codex 0.130+ silently drops the wrapper's -c override; until upstream fixes that, the file value is the only thing that works. See docs/proxy-wrappers.md.")
	cmd.Flags().BoolVar(&verify, "verify", false,
		"Run every pre-flight check (proxy reachability + V5-1 shared app-server detection + V6-2 config.toml correctness) and exit. Does NOT launch codex. Exit 0 if every check passes, 1 if any fail. Composes with --write-config to auto-fix V6-2 issues during verify. See docs/proxy-wrappers.md.")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as codex's first prompt (delivery=inject_prompt). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	// --no-proxy-route is a REAL routing skip available in bare mode too: it
	// makes this launcher NOT inject `-c openai_base_url`, so codex talks to
	// its provider directly and its turns are not captured through the proxy.
	// The attach client forwards it to the inner launcher as the escape hatch.
	cmd.Flags().BoolVar(&noProxyRoute, "no-proxy-route", false,
		"Do NOT route codex through the observer proxy: skip the `-c openai_base_url` override and launch codex with your normal config. Turns are NOT captured. Also the argv escape hatch the attach client forwards for [terminal.attach].route_proxy=false / --no-proxy.")
	// --attach / --no-proxy are registered ONLY when codex declares an Attach
	// capability (session-attach design §2.3; capability dispatch, not a
	// tool-name branch — CLAUDE.md #3). runCodexLauncher hard-errors at runtime
	// if --attach is set without the capability.
	if capCodex, _ := integration.For("codex"); capCodex.Attach != nil {
		cmd.Flags().BoolVar(&attach, "attach", false,
			"Attach mode: have the running observer daemon own this session's PTY so the dashboard can view and drive the SAME live session (session-attach). Your terminal stays interactive; detaching leaves the codex child running under the daemon, and Ctrl-C still reaches codex. Requires `observer start`. Attach is the DEFAULT for an interactive `observer codex` when the daemon is reachable ([terminal.attach].default_on); this flag FORCES it. See docs/plans/session-attach-design-2026-07-19.md.")
		cmd.Flags().BoolVar(&noAttach, "no-attach", false,
			"Opt out of attach for this launch: exec codex as a normal child of your shell (the bare launcher) even when attach would otherwise be the default. Use it to bypass the daemon-owned PTY for one run without changing [terminal.attach].default_on. Composes with --resume and --continue-from.")
		cmd.Flags().BoolVar(&noProxy, "no-proxy", false,
			"With --attach: escape hatch for [terminal.attach].route_proxy. Forwards --no-proxy-route to the daemon-spawned inner launcher so it skips the `-c openai_base_url` override and the attached codex session is NOT routed through the observer proxy (turns are not captured).")
	}
	// --resume is registered ONLY when codex declares a grounded native
	// ResumeNative contract (session-attach design Phase 3; capability dispatch,
	// never a tool-name branch — CLAUDE.md #3). It prepends codex's `resume
	// <id>` subcommand so the tool reattaches its REAL prior session (not a
	// distilled fork). Mutually exclusive with the handoff-fork family;
	// combinable with --attach (the daemon owns the resumed PTY).
	if capCodex, _ := integration.For("codex"); capCodex.Resume.Kind == integration.ResumeNative {
		cmd.Flags().StringVar(&resume, "resume", "",
			"Resume a CLOSED codex session by its id: launches `codex resume <id>`, reattaching the tool's REAL prior session — NOT a distilled fork. Composes with proxy routing (`codex -c openai_base_url=… resume <id>`). Mutually exclusive with --continue-from/--carry/--from-message/--from-time. Combine with --attach to resume into a daemon-owned session the dashboard can join. See docs/plans/session-attach-design-2026-07-19.md.")
	}
	return cmd
}

type codexLauncherOptions struct {
	configPath       string
	proxyURL         string
	codexPath        string
	codexArgs        []string
	exclusive        bool
	noAppServerCheck bool
	detectOnly       bool
	writeConfig      bool
	verify           bool
	continueFrom     string
	carry            string
	fromMessage      int
	fromTime         string
	attach           bool
	noAttach         bool
	noProxy          bool
	noProxyRoute     bool
	// routeSkipReason records WHY this launch skips codex's `-c openai_base_url`
	// override, so the ONE notice printed for it says the true thing.
	// noProxyRoute alone cannot answer that: the launcher SETS it on the
	// proxy-down neutralize path, which used to make codexLaunchArgs claim
	// "--no-proxy-route set" for a launch that passed no such flag — two
	// contradictory notices for one outcome (Q1 probe, P2). Meaningful only when
	// noProxyRoute is true; see codexRouteSkipNotice.
	routeSkipReason proxyFallbackReason
	resume          string
	stderr          interface{ Write([]byte) (int, error) }
}

// runCodexLauncher resolves the proxy URL, prepares the child argv with
// the openai_base_url override, and execs codex. Exit code is forwarded
// via exitErr (same shape as `observer run`).
//
// Before exec, runs codex `app-server` pre-flight detection (V5-1) and
// either warns (default), terminates (--exclusive), or short-circuits
// to inspection-only (--detect-only). The --no-app-server-check flag
// disables the check entirely. See docs/codex-shared-app-server-gotcha.md.
func runCodexLauncher(ctx context.Context, opts codexLauncherOptions) error {
	if opts.detectOnly && opts.exclusive {
		// SilenceErrors: true on the parent cmd hides returned errors.
		// Print explicitly so the operator sees why the wrapper bailed.
		msg := "observer codex: --detect-only and --exclusive are mutually exclusive (pick inspection OR termination)"
		fmt.Fprintln(opts.stderr, msg)
		return errors.New(msg)
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: opts.configPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// P6 item 5: refuse a bare launch of an org-disallowed tool (node.features
	// tools.disallow). "codex" is codex's integration-registry key.
	if err := refuseIfToolDisallowedCfg(cfg, "codex", opts.stderr); err != nil {
		return err
	}

	// Attach mode (session-attach design Phase 1 + resilient-attach WP-C): hand
	// the PTY to the daemon instead of exec'ing codex as a child of this shell.
	// The daemon spawns the inner `observer codex` launcher, which runs the
	// app-server preflight AND injects `-c openai_base_url` itself — so codex
	// routing is config/argv based, NOT env-based: we honestly forward NO proxy
	// env (design §6, and the task's codex carve-out). Attach is now the DEFAULT
	// for an interactive launch when the daemon is reachable; decideAttach
	// resolves the verdict from injected facts, printing ONE notice + falling
	// back to the bare launch when default-on attach is wanted but the daemon
	// socket is unreachable. We branch here, before the client-side app-server
	// detection, so an attach runs that preflight once (in the daemon child), not
	// twice; a bare verdict flows on to the detection + launch below.
	// The attach gate is now the shared launcherAttach (attach-all-launchers):
	// it walks the SAME decideAttach table, prints the SAME notice, and on an
	// attach verdict runs the SAME runAttachSession — the codex-specific pieces
	// (the reject-flags list + the B3-1 fail-closed conflict check, the CODEX_HOME
	// profile env, the --codex-path/--no-app-server-check/--resume passthrough,
	// the --no-proxy/--no-proxy-route escape-hatch resolution) are expressed as
	// spec closures so shared code never branches on tool identity (CLAUDE.md #3).
	// Byte-equal to the prior inline block + runCodexAttach. attachProxyURL is
	// the resolved base URL the B3-1 closure and the attach spawn both use — the
	// SAME value launcherAttach resolves internally.
	attachProxyURL := resolveProxyURL(cfg.Proxy.Port, opts.proxyURL)
	outcome, attachErr := launcherAttach(ctx, launcherAttachSpec{
		tool:          "codex",
		configPath:    opts.configPath,
		proxyOverride: opts.proxyURL,
		proxyFlag:     "--proxy",
		flagAttach:    opts.attach,
		flagNoAttach:  opts.noAttach,
		incompatible:  codexAttachIncompatible(opts),
		rejectFlags: func() error {
			// B2-6: reject wrapper flags the daemon-spawned inner launcher cannot
			// honor (naming each).
			if aerr := rejectIncompatibleCodexAttachFlags(opts); aerr != nil {
				return aerr
			}
			// B3-1: FAIL CLOSED client-side when the escape hatch is engaged but a
			// persistent $CODEX_HOME/config.toml still routes to the proxy — the
			// inner launcher would refuse anyway, but that failure would surface as
			// PTY output/exit inside the attach session, so fail fast here (same
			// machine in v1; effective home + active profile resolve identically).
			if opts.noProxyRoute || opts.noProxy || !cfg.Terminal.Attach.RouteProxy {
				return codexNoProxyRouteConflict(effectiveCodexHomeRoots(), attachProxyURL, codexActiveProfile(opts.codexArgs))
			}
			return nil
		},
		noProxyRoute: func(rp bool) bool { return opts.noProxyRoute || opts.noProxy || !rp },
		// Codex routes via argv (`-c openai_base_url`), so there is NO proxy env
		// to forward — but the caller's per-invocation CODEX_HOME IS forwarded
		// (R2-5) so the inner launcher discovers/routes the right profile.
		attachEnv:   func(_ string, _ bool) []string { return codexAttachEnv(os.Environ()) },
		passthrough: codexAttachPassthrough(opts),
		toolArgs:    opts.codexArgs,
		stderr:      opts.stderr,
	})
	if outcome.handled {
		return attachErr
	}

	// Native resume (session-attach design Phase 3): `observer codex --resume
	// <id>` prepends the `resume <id>` subcommand to codex's argv. The final
	// launch is `codex -c openai_base_url=<proxy>/v1 resume <id>` because
	// codexLaunchArgs/prepareCodexArgs later prepends the global `-c` override,
	// which codex honors BEFORE the resume subcommand (verified live), so proxy
	// routing composes with native resume. Mutually exclusive with the
	// handoff-fork family, rejected loud. The attach branch above already
	// returned for `--attach --resume` (forwarded via passthrough), so this
	// injection is bare-launch only; the no-launch modes (--detect-only /
	// --verify) still short-circuit later and ignore the injected args.
	if opts.resume != "" {
		if rerr := rejectIncompatibleCodexResumeFlags(opts); rerr != nil {
			fmt.Fprintln(opts.stderr, rerr)
			return rerr
		}
		// Durable cross-process resume claim (H3): held for the child's lifetime
		// so a concurrent daemon attach-resume (or another bare resume) of the
		// same session is refused rather than duplicating the transcript. No-op
		// for a daemon-spawned inner launcher (the daemon already holds it).
		release, ok := acquireBareResumeClaim(opts.stderr, cfg.Observer.DBPath, "codex", opts.resume)
		if !ok {
			return exitErr(1)
		}
		defer release()
		opts.codexArgs = injectCodexResume(opts.codexArgs, opts.resume)
		fmt.Fprintf(opts.stderr,
			"observer codex: native resume — reattaching session %s via `codex resume` (real session, not a fork)\n",
			opts.resume)
		// Session-attach Phase 2 (P2-1): when this is a daemon-spawned launcher
		// (a live OOB channel), announce the RESUMED session id on the trusted
		// out-of-band channel immediately — deterministic, mirrors the claude
		// resume announce (claude.go::forceClaudeSessionID). `codex resume <id>`
		// reattaches the REAL session (same id), so the announced id is the id
		// the daemon will see captured. This short-circuits the filesystem
		// discovery below (the id is already known). No-op for a bare `observer
		// codex --resume` (no OOB channel).
		announceOOBSession(opts.resume)
	}

	// Pre-flight app-server detection. Three modes:
	//   --detect-only           : print summary, exit (0 if empty, 1 if found).
	//   --exclusive             : print intent + terminate + recovery hint.
	//   default (no new flag)   : one-line stderr warning if any detected.
	// --no-app-server-check skips the entire branch.
	var preflight []codexipc.Process
	if !opts.noAppServerCheck {
		procs, derr := codexipc.Detect(ctx)
		if derr != nil {
			// Detection failure is non-fatal — surface so the operator
			// can investigate, then continue with the normal exec path.
			fmt.Fprintf(opts.stderr,
				"observer codex: warning — could not enumerate shared codex app-servers: %v (continuing without pre-flight check)\n",
				derr)
		}
		preflight = procs

		switch {
		case opts.detectOnly:
			return runDetectOnly(opts.stderr, procs)
		case opts.exclusive && len(procs) > 0:
			runExclusiveTermination(ctx, opts.stderr, procs)
		case len(procs) > 0:
			emitPreflightWarning(opts.stderr, procs)
		}
	} else if opts.detectOnly {
		// --detect-only + --no-app-server-check is contradictory. Be
		// kind: print a note and exit 0 instead of erroring out.
		fmt.Fprintln(opts.stderr,
			"observer codex: --detect-only requested but --no-app-server-check also set; detection skipped, exiting clean.")
		return nil
	}

	proxyURL := opts.proxyURL
	if proxyURL == "" {
		port := cfg.Proxy.Port
		if port <= 0 {
			port = 8820
		}
		proxyURL = "http://127.0.0.1:" + strconv.Itoa(port)
	}

	// V6-2 pre-flight: warn/auto-fix $CODEX_HOME/config.toml base-URL
	// (see runCodexConfigPreflight). Skipped under --no-proxy-route — the
	// config.toml base-URL is irrelevant when we are deliberately not routing.
	if !opts.noProxyRoute {
		runCodexConfigPreflight(opts, proxyURL)
	}

	proxyUp := proxyReachable(proxyURL, 250*time.Millisecond)
	// Proxy-unreachable handling moved to the decideProxyFallback switch below,
	// which fails closed or neutralizes honestly instead of the old warn-and-
	// launch-anyway into a dead proxy. proxyUp is still consumed by --verify and
	// by that decision.

	// --verify short-circuits after every pre-flight check has run.
	// Composes naturally with --write-config (which already ran above)
	// so an operator can do `observer codex --verify --write-config`
	// in one shot to (a) auto-fix V6-2 and (b) confirm everything's
	// healthy without spending a single token.
	if opts.verify {
		return runCodexVerify(opts.stderr, codexVerifyResult{
			ProxyURL:       proxyURL,
			ProxyReachable: proxyUp,
			PreflightProcs: preflight,
			Misconfigs:     findCodexConfigMisconfigs(codexHomeRoots(), proxyURL),
		})
	}

	// Launch-time proxy-routing fallback decision (resilient-attach scenario 4/5
	// + the existing B3-1 --no-proxy-route guard, now unified through the shared
	// decideProxyFallback table). Codex 0.130+ reads $CODEX_HOME/config.toml and
	// silently drops the wrapper's argv `-c openai_base_url` override, so a
	// persistent config route there CANNOT be neutralized by the launcher — the
	// same capability shape as claude's settings.json (which WINS over the env).
	// Fail closed when such a route would defeat --no-proxy-route (B3-1) OR would
	// send codex into an UNREACHABLE proxy (the daemon-down hole the operator hit
	// on the attach fallback); neutralize to codex's own default provider when no
	// config route exists (a working bypass). Evaluated after the no-launch modes
	// (--detect-only/--verify) so those still short-circuit.
	//
	// Finding 3: the verdict is scoped to the EFFECTIVE CODEX_HOME (env CODEX_HOME
	// or ~/.codex) — a stale foreign-OS cross-mount config (e.g. a Windows .codex
	// when the daemon runs in WSL) will NOT be loaded by this launch, so it must
	// never refuse it (it is surfaced as a non-blocking WARN instead) — and it
	// resolves the ACTIVE `-p/--profile` overlay so a profile-layered route is
	// seen (or a profile that overrides a routed base back to a non-proxy provider
	// is honored).
	activeProfile := codexActiveProfile(opts.codexArgs)
	configOffenders := codexConfigsRoutingToProxy(effectiveCodexHomeRoots(), proxyURL, activeProfile)
	if foreign := codexConfigsRoutingToProxy(codexForeignHomeRoots(), proxyURL, activeProfile); len(foreign) > 0 {
		fmt.Fprintf(opts.stderr,
			"observer codex: note — a cross-mount codex config still routes to the observer proxy (%s) but will NOT be loaded by this launch (effective CODEX_HOME is %s); ignoring it for the routing decision. Remove it if it's stale.\n",
			strings.Join(foreign, ", "), effectiveCodexHome())
	}
	switch fb := decideProxyFallback(proxyFallbackInputs{
		noProxyRoute:    opts.noProxyRoute,
		proxyReachable:  proxyUp,
		persistentRoute: len(configOffenders) > 0,
		// codex has NO CLI-scope override lever: config.toml wins and codex 0.130+
		// silently DROPS the wrapper's argv `-c openai_base_url` override (V6-2), so
		// a persistent config route cannot be neutralized — it stays fail-closed.
		// (Asymmetric with claude, which has `--settings`; stated explicitly.)
		canNeutralizePersistent: false,
	}); fb.action {
	case proxyFailClosed:
		fmt.Fprintln(opts.stderr, codexProxyFailClosedMsg(fb.reason, proxyURL, configOffenders))
		return exitErr(1)
	case proxyNeutralize:
		// Bypass the proxy: make codexLaunchArgs skip the `-c openai_base_url`
		// override so codex reaches its own default provider (which works even
		// with our proxy down). opts is a by-value copy, so flipping noProxyRoute
		// here is launch-local. The REASON travels with it so exactly ONE notice
		// is printed for this outcome, by codexLaunchArgs, naming the true cause
		// (P2: this branch used to print its own "proxy unreachable" line and
		// then codexLaunchArgs printed a second, contradictory "--no-proxy-route
		// set" line for the same skipped route).
		opts.noProxyRoute = true
		opts.routeSkipReason = fb.reason
	}
	// proxyRouteProceed → the routed launch below injects `-c openai_base_url`.

	return runCodexChild(ctx, opts, proxyURL, preflight, cfg.Observer.DBPath)
}

// runCodexChild resolves the codex binary, applies any --continue-from handover,
// assembles the child process with the resolved proxy routing (via
// codexLaunchArgs), wires OOB rollout-discovery for a daemon-spawned launch, and
// execs codex — forwarding the exit code. preflight carries the app-server
// processes detected upstream so the post-flight capture-rate check can reuse
// them; dbPath is the observer DB (cfg.Observer.DBPath) for the best-effort
// launch-seed attribution row. Extracted from runCodexLauncher to keep its
// cyclomatic complexity in bounds; the caller reaches it only on a
// proxyRouteProceed / neutralized verdict.
func runCodexChild(ctx context.Context, opts codexLauncherOptions, proxyURL string, preflight []codexipc.Process, dbPath string) error {
	bin, binErr := resolveToolBin("codex", opts.codexPath, "--codex-path", opts.configPath, opts.stderr)
	if binErr != nil {
		return binErr
	}

	codexArgs := opts.codexArgs
	var continueDir string
	if opts.continueFrom != "" {
		seeded, cwd, cerr := codexContinueArgs(ctx, opts)
		if cerr != nil {
			// SilenceErrors: true hides the returned error, so surface it
			// explicitly — the operator needs to know why we didn't launch.
			fmt.Fprintf(opts.stderr, "observer codex: continue-from failed: %v\n", cerr)
			return cerr
		}
		codexArgs = seeded
		continueDir = cwd
	}

	args := codexLaunchArgs(opts, codexArgs, proxyURL)
	evidence := budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	switch {
	case opts.noProxyRoute:
		evidence.Route = budgetLaunchRouteDirect
	case !hasUserCodexConfigOverride(codexArgs):
		evidence = budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: proxyURL}
	}
	evidence.Executable = bin
	evidence.Arguments = args
	if err := enforceBudgetControlledLaunch(ctx, opts.configPath, "codex", evidence); err != nil {
		return err
	}

	child := exec.Command(bin, args...)
	// Never leak the trusted OOB channel's env into the untrusted tool child.
	//
	// DI-04b: a node-shim codex (npm channel, #!/usr/bin/env node) needs node
	// on the CHILD's PATH; widen it with the shim's own dir + the login-only
	// dirs the resolver saw (additive; the daemon PATH survives in order).
	child.Env = applyChildPATH(scrubOOBEnv(os.Environ()), daemonLoginPathDirs(), bin)
	child.Dir = continueDir // "" inherits the caller's cwd; set by --continue-from to the source project root
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	// Session-attach Phase 2 (P2-1): codex has no `--session-id`, so a
	// daemon-spawned attach/fresh launch cannot FORCE a known id the way claude
	// does. Instead, DISCOVER the new rollout codex writes for this run and
	// announce its session id on the trusted OOB channel so the run correlates
	// to its dashboard session (see codex_discover.go). Eligible ONLY for a
	// daemon-spawned launcher (OOB channel live) that is neither a native resume
	// (id already announced above) nor a handoff-continue. The pre-existing
	// rollouts are snapshotted BEFORE the child starts so the child's own new
	// file is detectable; the watch itself runs on a goroutine after Start so it
	// never delays the child's startup or I/O.
	discoverSession := oobChannelActive() && opts.resume == "" && opts.continueFrom == "" && !terminalNativeDiscoveryAvailable(genericAdapterRegistry().Get("codex"))
	var (
		discoverRoots       []string
		discoverPreexisting map[string]struct{}
		discoverCwd         string
	)
	if discoverSession {
		discoverRoots = codexSessionsRoots()
		discoverPreexisting = snapshotCodexRollouts(discoverRoots)
		discoverCwd = continueDir
		if discoverCwd == "" {
			discoverCwd, _ = os.Getwd()
		}
	}

	// cmdStart anchors the post-flight rollout-file scan: any
	// rollout-*.jsonl modified at-or-after this stamp is in this run's
	// scope. Recorded BEFORE child.Start() so the file ModTime
	// comparison is monotonic.
	cmdStart := time.Now()
	if err := child.Start(); err != nil {
		return fmt.Errorf("exec codex: start: %w", err)
	}
	// Direct process attribution (migration 086): record the child pid now
	// that Start has made it knowable; retract the seed when the child is
	// reaped. Best-effort both ways — a seeding failure never affects the
	// launch (see cmd/observer/launchseed.go).
	recordLaunchSeed(dbPath, "codex", continueDir, child.Process.Pid, opts.stderr)
	// discCancel is hoisted out of the discoverSession block so it can be
	// fired the INSTANT child.Wait returns (F1), before the post-flight scan.
	var discCancel context.CancelFunc
	if discoverSession {
		var discCtx context.Context
		discCtx, discCancel = context.WithCancel(ctx)
		defer discCancel()
		// DISCOVERY announce: the id is inferred from the run's new rollout file
		// (codex has no `--session-id`), so it rides the trusted channel with the
		// discovered-source hint → recorded at SourceDiscovered confidence, below
		// the resume short-circuit's known-id OOB echo above.
		go runCodexDiscovery(discCtx, discoverRoots, discoverPreexisting, cmdStart, discoverCwd, defaultCodexDiscoverConfig(), announceDiscoveredOOBSession)
	}
	// V7-1: on Windows, attach codex.exe to a Job Object with
	// KILL_ON_JOB_CLOSE. If this observer wrapper dies (clean exit,
	// watchdog hammer, SIGKILL), Windows closes our handle and
	// codex.exe terminates automatically — no zombie left writing
	// to rollout-*.jsonl. Non-Windows: no-op stub. Attach failure
	// is non-fatal: log to stderr, continue without protection.
	jobCloser, jobErr := jobobject.AttachProcess(child)
	if jobErr != nil {
		fmt.Fprintf(opts.stderr, "observer codex: jobobject attach failed; V7-1 protection unavailable for this run: %v\n", jobErr)
	} else if jobCloser != nil {
		defer jobCloser.Close()
	}
	runErr := child.Wait()
	// F1: cancel discovery the INSTANT the child exits — BEFORE the post-flight
	// capture-rate scan below, which can itself run long enough to cross the
	// discovery deadline. Deferring discCancel to function return (the pre-fix
	// behaviour) let discovery observe its whole window and announce a cut-short
	// guess while this post-flight scan was still running. The `defer discCancel`
	// above remains as an idempotent backstop for the early-return paths.
	if discCancel != nil {
		discCancel()
	}

	// Post-flight V5-1 capture-rate check (silent on success). Skipped
	// when --no-app-server-check is set. Errors are swallowed because
	// the check is diagnostic-only — a stale DB or transient FS hiccup
	// must never fail the wrapper.
	if !opts.noAppServerCheck {
		if warn, _ := validateCaptureRate(ctx, opts.configPath, cmdStart, preflight); warn != "" {
			fmt.Fprintln(opts.stderr, warn)
		}
	}

	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return exitErr(ee.ExitCode())
		}
		return fmt.Errorf("exec codex: %w", runErr)
	}
	return nil
}

// codexLaunchArgs builds codex's argv and prints the matching routing status
// line. Under --no-proxy-route it launches codex untouched (no `-c
// openai_base_url` injected). A persistent $CODEX_HOME/config.toml that still
// routes to the proxy is NOT neutralized here — because that flag only skips the
// ARGV override, codex 0.130+ would keep routing through the proxy from the file
// value. That conflict is caught EARLIER and FAILS CLOSED
// (codexNoProxyRouteConflict, B3-1): we refuse to launch rather than silently
// capture. We do NOT inject a stock-default override to neutralize it because
// codex's effective default base URL depends on the auth shape (API-key vs
// ChatGPT-Plus JWT). Extracted from runCodexLauncher for cyclomatic complexity.
func codexLaunchArgs(opts codexLauncherOptions, codexArgs []string, proxyURL string) []string {
	if opts.noProxyRoute {
		// A persistent config.toml that still routes to the proxy is caught
		// earlier and FAILS CLOSED (codexNoProxyRouteConflict, B3-1), so by the
		// time we get here no config re-routes us: launch codex untouched.
		args := append([]string{}, codexArgs...)
		fmt.Fprintln(opts.stderr,
			codexRouteSkipNotice(opts.routeSkipReason, proxyURL, runningAsDaemonChild()))
		return args
	}
	args, info := prepareCodexArgs(codexArgs, proxyURL)
	if info.OverrideAlreadyPresent {
		fmt.Fprintf(opts.stderr,
			"observer codex: routing via existing -c openai_base_url override (no inject; user-provided)\n")
	} else {
		fmt.Fprintf(opts.stderr,
			"observer codex: routing via %s (-c openai_base_url injected; auth shape detected by proxy)\n",
			proxyURL)
	}
	return args
}

// codexRouteSkipNotices maps the decideProxyFallback REASON that made a launch
// skip codex's `-c openai_base_url` override onto the ONE notice printed for it.
// A data table, not an if-ladder (CLAUDE.md #5), with exactly one row per
// outcome — which is the whole point: before it, a proxy-down neutralize printed
// its own "proxy unreachable … WITHOUT proxy routing" line at the decision site
// AND, because it expressed itself by flipping opts.noProxyRoute, a second
// "--no-proxy-route set" line at the argv site, claiming a flag the caller (a
// dashboard launch) never passed. Two stated reasons, one skipped route.
//
// Only the two NEUTRALIZE reasons have rows; the fail-closed and routed reasons
// never reach the skip branch. Each row takes the same injected facts so the
// table stays uniform: the resolved proxy URL and whether this process is a
// daemon-spawned child (which decides the honest advice clause — see
// proxyDownAdvice).
var codexRouteSkipNotices = map[proxyFallbackReason]func(proxyURL string, daemonChild bool) string{
	reasonNoProxyRouteClean: func(string, bool) string {
		return "observer codex: --no-proxy-route set — launching codex WITHOUT the -c openai_base_url proxy override (turns are NOT captured)."
	},
	reasonProxyDownClean: func(proxyURL string, daemonChild bool) string {
		return fmt.Sprintf(
			"observer codex: proxy not reachable at %s — launching codex WITHOUT the -c openai_base_url proxy override (turns are NOT captured for this run; %s).",
			proxyURL, proxyDownAdvice(daemonChild))
	},
}

// codexRouteSkipNotice resolves the single notice for a skipped proxy route.
// An unlisted reason falls back to the operator-flag row: opts.noProxyRoute is
// literally "the operator asked for no routing", so that is the honest reading
// of a skip whose reason never travelled (a caller that sets the flag without
// walking decideProxyFallback). Pure — the daemon-child fact is injected.
func codexRouteSkipNotice(reason proxyFallbackReason, proxyURL string, daemonChild bool) string {
	row, ok := codexRouteSkipNotices[reason]
	if !ok {
		row = codexRouteSkipNotices[reasonNoProxyRouteClean]
	}
	return row(proxyURL, daemonChild)
}

// runCodexConfigPreflight runs the V6-2 $CODEX_HOME/config.toml base-URL
// check: warn if config.toml is missing `openai_base_url` matching the
// proxy. Codex 0.130+ silently drops the wrapper's argv-injected -c
// override (see docs/observer-platform-issues-v6.md §V6-2); without the
// config.toml value, every turn bypasses the proxy. Honors
// --no-app-server-check (the universal silence escape hatch).
//
// When --write-config is set AND any config is misconfigured, fix it in
// place (with a .bak backup) before running codex. The warning still
// prints if a write fails for any root; otherwise the run proceeds with
// the file value reaching the inner app-server.
func runCodexConfigPreflight(opts codexLauncherOptions, proxyURL string) {
	if opts.noAppServerCheck {
		return
	}
	misconfigs := findCodexConfigMisconfigs(codexHomeRoots(), proxyURL)
	switch {
	case len(misconfigs) == 0:
		// silent happy path
	case opts.writeConfig:
		runWriteCodexConfig(opts.stderr, misconfigs)
		// Re-check so a partial failure still warns the operator.
		if warn := checkCodexConfigTOMLBaseURL(codexHomeRoots(), proxyURL); warn != "" {
			fmt.Fprintln(opts.stderr, warn)
		}
	default:
		if warn := checkCodexConfigTOMLBaseURL(codexHomeRoots(), proxyURL); warn != "" {
			fmt.Fprintln(opts.stderr, warn)
			fmt.Fprintln(opts.stderr,
				"observer codex: re-run with --write-config to auto-fix (creates a .bak before mutating).")
		}
	}
}

// codexAttachEnv builds the profile env forwarded across the attach socket to
// the daemon-spawned inner `observer codex` launcher: the caller's own
// CODEX_HOME when PRESENT (R2-5). It reads from the passed environment
// (os.Environ() in production; injectable for tests). Codex routes via argv, so
// this carries NO proxy var — only the profile selector both the inner
// launcher's discovery and codex itself honor. It forwards on PRESENCE, not
// non-emptiness (F3): an explicit `CODEX_HOME=` (empty) is forwarded verbatim so
// the child resets to codex's default profile — otherwise it would be
// indistinguishable from unset and the daemon's inherited CODEX_HOME would
// wrongly stand. Nil only when CODEX_HOME is absent (the daemon's own profile is
// then correct). launchChildEnv layers ExtraEnv AFTER the inherited env, so a
// forwarded `CODEX_HOME=` wins over the daemon's value at the child (last-wins).
func codexAttachEnv(environ []string) []string {
	if home, ok := lookupEnvValue(environ, "CODEX_HOME"); ok {
		return []string{"CODEX_HOME=" + home}
	}
	return nil
}

// codexAttachPassthrough builds the launcher-specific wrapper flags forwarded
// to the daemon-spawned inner `observer codex` (B2-6): --codex-path,
// --no-app-server-check, and --resume. --resume is FORWARDED (not rejected) so
// `observer codex --attach --resume <id>` resumes the REAL session into a
// daemon-owned PTY the dashboard can join (design §2.4 mortality backstop).
func codexAttachPassthrough(opts codexLauncherOptions) []string {
	var p []string
	if opts.codexPath != "" {
		p = append(p, "--codex-path", opts.codexPath)
	}
	if opts.noAppServerCheck {
		p = append(p, "--no-app-server-check")
	}
	if opts.resume != "" {
		p = append(p, "--resume", opts.resume)
	}
	return p
}

// injectCodexResume prepends codex's `resume <id>` subcommand to its argv.
// prepareCodexArgs later prepends the global `-c openai_base_url` override, so
// the final child argv is `codex -c openai_base_url=… resume <id> [user args]`
// — codex honors the global `-c` before the subcommand (verified live), so
// native resume composes with proxy routing.
func injectCodexResume(codexArgs []string, id string) []string {
	return append([]string{"resume", id}, codexArgs...)
}

// codexAttachIncompatible reports whether this launch is in a mode that cannot
// compose with attach, so default-on attach must NOT engage (it falls through to
// the bare launch SILENTLY — these are scripted/one-shot/inspection paths where
// an attach notice would be spam). It mirrors the flags
// rejectIncompatibleCodexAttachFlags refuses under an explicit `--attach`
// (verify + detect-only + write-config + exclusive + the handoff-fork family)
// and additionally treats codex's non-interactive `exec` subcommand (claude's
// `--print` analogue) as incompatible so `observer codex -- exec "…"` always
// takes the bare path. --resume is NOT incompatible (attach forwards it via
// passthrough), and neither is --no-proxy-route (an attach escape hatch).
func codexAttachIncompatible(opts codexLauncherOptions) bool {
	return opts.verify ||
		opts.detectOnly ||
		opts.writeConfig ||
		opts.exclusive ||
		opts.continueFrom != "" ||
		opts.carry != "" ||
		opts.fromMessage != 0 ||
		opts.fromTime != "" ||
		argsAreCodexHeadless(opts.codexArgs)
}

// rejectIncompatibleCodexAttachFlags fails `observer codex --attach` fast for
// wrapper flags the daemon-spawned inner launcher cannot honor, naming the
// offending flag rather than silently dropping it (B2-6). --config / --proxy /
// --codex-path / --no-app-server-check / --no-proxy / --no-proxy-route ARE
// forwarded (handled by the caller), as is the trailing `--` tool remainder;
// everything else that changes launch behavior is rejected here.
func rejectIncompatibleCodexAttachFlags(opts codexLauncherOptions) error {
	switch {
	case opts.verify:
		return errors.New("observer codex: --verify is not supported with --attach in v1 (run `observer codex --verify` without --attach)")
	case opts.detectOnly:
		return errors.New("observer codex: --detect-only is not supported with --attach in v1 (run `observer codex --detect-only` without --attach)")
	case opts.writeConfig:
		return errors.New("observer codex: --write-config is not supported with --attach in v1 (run `observer codex --write-config` without --attach to fix $CODEX_HOME/config.toml first)")
	case opts.exclusive:
		return errors.New("observer codex: --exclusive is not supported with --attach in v1 (terminate shared app-servers with `observer codex --exclusive` without --attach first)")
	case opts.continueFrom != "":
		return errors.New("observer codex: --continue-from is not supported with --attach in v1 (attach launches a fresh session; use the dashboard handoff to continue a session)")
	case opts.carry != "":
		return errors.New("observer codex: --carry is not supported with --attach in v1 (it only applies to --continue-from)")
	case opts.fromMessage != 0:
		return errors.New("observer codex: --from-message is not supported with --attach in v1 (it only applies to --continue-from)")
	case opts.fromTime != "":
		return errors.New("observer codex: --from-time is not supported with --attach in v1 (it only applies to --continue-from)")
	}
	return nil
}

// rejectIncompatibleCodexResumeFlags fails `observer codex --resume` fast for
// the handoff-fork family (--continue-from and its modifiers), which composes a
// NEW session from a distilled handover — the opposite of native resume's
// real-session reattach. Naming each conflict keeps it loud rather than
// silently dropping one.
func rejectIncompatibleCodexResumeFlags(opts codexLauncherOptions) error {
	switch {
	case opts.continueFrom != "":
		return errors.New("observer codex: --resume (native, reattaches the REAL session) is mutually exclusive with --continue-from (distilled fork into a NEW session) — pick one")
	case opts.carry != "":
		return errors.New("observer codex: --carry only applies to --continue-from and cannot be combined with --resume")
	case opts.fromMessage != 0:
		return errors.New("observer codex: --from-message only applies to --continue-from and cannot be combined with --resume")
	case opts.fromTime != "":
		return errors.New("observer codex: --from-time only applies to --continue-from and cannot be combined with --resume")
	}
	return nil
}

// codexContinueArgs runs the --continue-from handoff for codex and returns
// the codex argv with the handover appended as the trailing positional
// prompt (injectTrailingPositional — codex reads a positional prompt in
// both the TUI and `exec` forms; prepareCodexArgs later prepends the -c
// openai_base_url override). It errors when the forwarded codex args
// already carry a positional prompt so a two-prompt collision is loud, not
// silent.
func codexContinueArgs(ctx context.Context, opts codexLauncherOptions) ([]string, string, error) {
	return continueFromArgs(ctx, continueFromParams{
		tool:        "codex",
		label:       "codex",
		configPath:  opts.configPath,
		sessionID:   opts.continueFrom,
		carry:       opts.carry,
		fromMessage: opts.fromMessage,
		fromTime:    opts.fromTime,
		args:        opts.codexArgs,
		inject:      promptInjection{Kind: injectTrailingPositional, Subcommands: codexSubcommands},
		stderr:      opts.stderr,
	})
}

// runDetectOnly emits a human-readable summary of the pre-flight scan
// and exits without launching codex. Returns exitErr(1) when any
// shared app-server was detected (CI-gate friendly), nil otherwise.
func runDetectOnly(stderr interface{ Write([]byte) (int, error) }, procs []codexipc.Process) error {
	if len(procs) == 0 {
		fmt.Fprintln(stderr, "observer codex: no shared codex app-servers detected; proxy capture should be reliable.")
		return nil
	}
	fmt.Fprintf(stderr, "observer codex: detected %d shared codex app-server(s) — V5-1 bypass risk:\n", len(procs))
	for _, p := range procs {
		fmt.Fprintf(stderr, "  PID %-6d  %-16s  %s\n", p.PID, p.Source, displayPath(p))
	}
	fmt.Fprintln(stderr, "observer codex: re-run with --exclusive to terminate them before exec, or terminate manually. See docs/codex-shared-app-server-gotcha.md.")
	return exitErr(1)
}

// runExclusiveTermination prints what it's about to kill, calls
// codexipc.Terminate for each, and prints the per-PID outcome and a
// recovery hint. Never returns an error — terminations are
// best-effort, surfaced verbatim, and the wrapper continues into the
// normal exec path regardless.
func runExclusiveTermination(ctx context.Context, stderr interface{ Write([]byte) (int, error) }, procs []codexipc.Process) {
	fmt.Fprintf(stderr, "observer codex: terminating %d shared codex app-server(s) per --exclusive:\n", len(procs))
	for _, p := range procs {
		if err := codexipc.Terminate(ctx, p.PID); err != nil {
			fmt.Fprintf(stderr, "  PID %-6d  %-16s  — failed: %v\n", p.PID, p.Source, err)
			continue
		}
		fmt.Fprintf(stderr, "  PID %-6d  %-16s  — terminated\n", p.PID, p.Source)
	}
	fmt.Fprintln(stderr, "observer codex: re-launch your VS Code Codex extension / Codex Desktop manually after this run.")
}

// emitPreflightWarning prints the single concise one-liner when shared
// app-servers are detected and the operator passed neither --exclusive
// nor --detect-only. Self-contained: names PIDs + sources, suggests
// --exclusive, names --no-app-server-check, links the docs.
func emitPreflightWarning(stderr interface{ Write([]byte) (int, error) }, procs []codexipc.Process) {
	var pidParts []string
	for _, p := range procs {
		pidParts = append(pidParts, fmt.Sprintf("PID %d (%s)", p.PID, p.Source))
	}
	fmt.Fprintf(stderr,
		"observer codex: detected %d shared codex app-server(s) — %s; capture may be incomplete. "+
			"Pass --exclusive to terminate them before this run, --no-app-server-check to silence, "+
			"or see docs/codex-shared-app-server-gotcha.md.\n",
		len(procs), strings.Join(pidParts, ", "))
}

// displayPath returns the most informative path-like string for a
// detected process. Prefers Path; falls back to the first whitespace-
// delimited token of CommandLine when Path is empty (POSIX ps output
// doesn't expose the absolute path separately).
func displayPath(p codexipc.Process) string {
	if p.Path != "" {
		return p.Path
	}
	if p.CommandLine == "" {
		return ""
	}
	if i := strings.IndexAny(p.CommandLine, " \t"); i > 0 {
		return p.CommandLine[:i]
	}
	return p.CommandLine
}

// codexArgsInfo records what the launcher injected into codex's argv.
type codexArgsInfo struct {
	OverrideInjected       bool
	OverrideAlreadyPresent bool // user passed their own -c openai_base_url
}

// prepareCodexArgs prepends `-c openai_base_url='"<proxy>/v1"'` to
// codex's argv, unless the user already supplied an `openai_base_url`
// override (via -c openai_base_url=... OR -c model_provider=... — both
// imply intentional routing). Anything the user explicitly set wins;
// the launcher never overrides explicit state.
//
// The override value is TOML-encoded (a string literal must be wrapped
// in quotes inside the TOML value).
func prepareCodexArgs(parent []string, proxyURL string) ([]string, codexArgsInfo) {
	info := codexArgsInfo{}
	if hasUserCodexConfigOverride(parent) {
		info.OverrideAlreadyPresent = true
		// Pass parent through unchanged. User's intent wins.
		return append([]string{}, parent...), info
	}
	// Strip a trailing slash from proxyURL before appending /v1 so we
	// don't end up with `//v1`.
	base := strings.TrimRight(proxyURL, "/")
	override := "openai_base_url=\"" + base + "/v1\""
	out := make([]string, 0, len(parent)+2)
	out = append(out, "-c", override)
	out = append(out, parent...)
	info.OverrideInjected = true
	return out, info
}

// hasUserCodexConfigOverride detects whether the user passed their own
// `openai_base_url` or `model_provider` override in argv. We respect
// either as "user has set up routing" — don't inject.
//
// Matches both `-c key=value` and `--config key=value` shapes, plus the
// space-separated form `-c key=value` where the override comes as the
// next argv slot (`-c`, `key=value`).
func hasUserCodexConfigOverride(args []string) bool {
	for i, a := range args {
		// Combined forms: -c=key=value / --config=key=value
		// (Cobra-style; codex accepts both per its --help.)
		switch {
		case strings.HasPrefix(a, "-c="):
			if isCodexRoutingOverride(a[len("-c="):]) {
				return true
			}
		case strings.HasPrefix(a, "--config="):
			if isCodexRoutingOverride(a[len("--config="):]) {
				return true
			}
		case a == "-c" || a == "--config":
			if i+1 < len(args) && isCodexRoutingOverride(args[i+1]) {
				return true
			}
		}
	}
	return false
}

// isCodexRoutingOverride returns true when `kv` (a `key=value` blob
// codex parses as TOML) sets a routing-relevant field.
func isCodexRoutingOverride(kv string) bool {
	eq := strings.IndexByte(kv, '=')
	if eq <= 0 {
		return false
	}
	key := strings.TrimSpace(kv[:eq])
	switch key {
	case "openai_base_url", "model_provider":
		return true
	}
	return false
}

// codexVerifyResult captures the pre-flight findings runCodexVerify
// reports. Mirrors claudeVerifyResult — both end with a single
// PASS/FAIL summary line and an exit code reflecting health.
type codexVerifyResult struct {
	ProxyURL       string
	ProxyReachable bool
	PreflightProcs []codexipc.Process
	Misconfigs     []codexConfigMisconfig
}

// runCodexVerify prints PASS/FAIL per pre-flight check and returns
// exitErr(1) when any FAIL'd. PASS-only runs exit 0.
func runCodexVerify(stderr interface{ Write([]byte) (int, error) }, r codexVerifyResult) error {
	failed := 0
	fmt.Fprintln(stderr, "observer codex --verify:")

	if r.ProxyReachable {
		fmt.Fprintf(stderr, "  PASS  proxy reachable at %s\n", r.ProxyURL)
	} else {
		fmt.Fprintf(stderr, "  FAIL  proxy NOT reachable at %s — start `observer start` or `observer proxy start`\n", r.ProxyURL)
		failed++
	}

	if len(r.PreflightProcs) == 0 {
		fmt.Fprintln(stderr, "  PASS  no shared codex app-servers detected (V5-1 bypass risk: clean)")
	} else {
		var labels []string
		for _, p := range r.PreflightProcs {
			labels = append(labels, fmt.Sprintf("PID %d (%s)", p.PID, p.Source))
		}
		fmt.Fprintf(stderr, "  FAIL  V5-1: %d shared codex app-server(s) running — %s. Pass --exclusive to terminate them, or close the VS Code Codex extension / Codex Desktop.\n",
			len(r.PreflightProcs), strings.Join(labels, ", "))
		failed++
	}

	if len(r.Misconfigs) == 0 {
		fmt.Fprintln(stderr, "  PASS  every $CODEX_HOME/config.toml correctly sets openai_base_url (V6-2: clean)")
	} else {
		for _, m := range r.Misconfigs {
			var detail string
			switch m.Status {
			case configTOMLOK:
				detail = fmt.Sprintf("openai_base_url=%q (want %s)", m.CurrentValue, m.WantURL)
			case configTOMLMissingKey:
				detail = "key missing"
			case configTOMLMissingFile:
				detail = "file missing"
			}
			fmt.Fprintf(stderr, "  FAIL  V6-2: %s — %s. Pass --write-config to auto-fix (creates a .bak before mutating).\n", m.ConfigPath, detail)
		}
		failed++
	}

	if failed == 0 {
		fmt.Fprintln(stderr, "observer codex --verify: all checks passed; `observer codex` should capture every turn.")
		return nil
	}
	fmt.Fprintf(stderr, "observer codex --verify: %d check(s) failed — fix above and re-verify.\n", failed)
	return exitErr(1)
}

// proxyReachable + splitHostPortFromURL are reused from claude.go in
// the same package — codex routes through the same proxy as claude.
