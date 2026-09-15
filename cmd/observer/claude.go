// claude.go — `observer claude` launcher subcommand.
//
// Pro/Max OAuth-authenticated Claude Code (2.1+) reads
// `~/.claude/.credentials.json` and bypasses ANTHROPIC_BASE_URL for the
// `/v1/messages` chat call — sending Bearer tokens straight to
// api.anthropic.com. That ducks the observer proxy, so compression
// never runs and api_turns rows never land for the OAuth majority.
//
// The launcher works around it by re-exporting the OAuth access token
// as ANTHROPIC_AUTH_TOKEN before exec'ing claude. When the SDK sees an
// auth token in the env, it falls back to the regular API-key code
// path, which DOES respect ANTHROPIC_BASE_URL. Same Bearer header on
// the wire, same Pro/Max billing — observer just gets to see (and
// compress) the body.
//
// API-key users (no `~/.claude/.credentials.json`) get the same
// treatment minus the token export: just ANTHROPIC_BASE_URL set, claude
// uses ANTHROPIC_API_KEY as today.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// newClaudeCmd implements `observer claude` — sets ANTHROPIC_BASE_URL
// and (when a Pro/Max OAuth token is present) ANTHROPIC_AUTH_TOKEN, then
// execs the user's `claude` binary so its chat traffic flows through
// the observer proxy.
func newClaudeCmd() *cobra.Command {
	var (
		configPath   string
		proxyURL     string
		claudePath   string
		verify       bool
		continueFrom string
		carry        string
		fromMessage  int
		fromTime     string
		attach       bool
		noAttach     bool
		noProxy      bool
		noProxyRoute bool
		resume       string
	)
	cmd := &cobra.Command{
		Use:   "claude [-- claude-args...]",
		Short: "Launch Claude Code with traffic routed through the observer proxy",
		Long: "Wraps `claude` with ANTHROPIC_BASE_URL pointed at the observer\n" +
			"proxy. For Pro/Max OAuth users, also re-exports the OAuth access\n" +
			"token as ANTHROPIC_AUTH_TOKEN so Claude Code's normal `/v1/messages`\n" +
			"path lands at the proxy instead of bypassing it. Same Pro/Max\n" +
			"billing — observer just gets to see (and compress) the body.\n\n" +
			"All arguments after the subcommand are forwarded to claude. Use\n" +
			"`--` to separate observer flags from claude flags:\n" +
			"    observer claude -- --print \"hi\"\n\n" +
			"Pass --verify to run every pre-flight check (proxy reachable,\n" +
			"credentials.json present + parseable, OAuth token discoverable)\n" +
			"and print a one-line PASS/FAIL summary without launching claude.\n\n" +
			"Requires a running observer proxy. Start one with `observer start`\n" +
			"or `observer proxy start` first.",
		SilenceErrors:      true,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, done, err := launcherArgsOrDone(cmd, args)
			if done {
				return err
			}
			return runClaudeLauncher(cmd.Context(), claudeLauncherOptions{
				configPath:   configPath,
				proxyURL:     proxyURL,
				claudePath:   claudePath,
				claudeArgs:   args,
				verify:       verify,
				continueFrom: continueFrom,
				carry:        carry,
				fromMessage:  fromMessage,
				fromTime:     fromTime,
				attach:       attach,
				noAttach:     noAttach,
				noProxy:      noProxy,
				noProxyRoute: noProxyRoute,
				resume:       resume,
				stderr:       cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&proxyURL, "proxy", "", "Override the observer proxy URL (default: http://127.0.0.1:<cfg.proxy.port>)")
	cmd.Flags().StringVar(&claudePath, "claude-path", "", "Path to the claude binary (default: resolve `claude` on PATH)")
	cmd.Flags().BoolVar(&verify, "verify", false, "Run pre-flight checks (proxy reachability + credentials.json + OAuth token) and exit. Does NOT launch claude. Exit 0 if every check passes, 1 if any fail. See docs/proxy-wrappers.md.")
	cmd.Flags().StringVar(&continueFrom, "continue-from", "", "Session id to continue from: distill a handover from that session and seed it as claude's first prompt (delivery=inject_prompt). See docs/session-handoff.md.")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode for --continue-from: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "With --continue-from: fork after this 1-based transcript message (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "With --continue-from: fork after the last message at or before this RFC3339 time")
	// --no-proxy-route is a REAL routing skip available in bare mode too: it
	// makes this launcher NOT inject ANTHROPIC_BASE_URL, so claude talks to
	// Anthropic directly and its turns are not captured through the proxy. The
	// attach client forwards it to the inner launcher as the escape hatch
	// (session-attach §6 decision #7) — expressed in ARGV because the inner
	// launcher self-routes regardless of env.
	cmd.Flags().BoolVar(&noProxyRoute, "no-proxy-route", false,
		"Do NOT route claude through the observer proxy: skip ANTHROPIC_BASE_URL injection and launch claude with your normal environment. Turns are NOT captured. Also the argv escape hatch the attach client forwards for [terminal.attach].route_proxy=false / --no-proxy.")
	// --attach / --no-proxy are registered ONLY when claude-code declares an
	// Attach capability (session-attach design §2.3; capability dispatch, never
	// a tool-name branch — CLAUDE.md #3). runClaudeLauncher hard-errors at
	// runtime if --attach is set without the capability, so this stays honest
	// even if the capability is later ungrounded.
	if capClaude, _ := integration.For("claude-code"); capClaude.Attach != nil {
		cmd.Flags().BoolVar(&attach, "attach", false,
			"Attach mode: have the running observer daemon own this session's PTY so the dashboard can view and drive the SAME live session (session-attach). Your terminal stays interactive; detaching (SIGTERM/close) leaves the claude child running under the daemon, and Ctrl-C still reaches claude. Requires `observer start`. Attach is the DEFAULT for an interactive `observer claude` when the daemon is reachable ([terminal.attach].default_on); this flag FORCES it. See docs/plans/session-attach-design-2026-07-19.md.")
		cmd.Flags().BoolVar(&noAttach, "no-attach", false,
			"Opt out of attach for this launch: exec claude as a normal child of your shell (the bare launcher) even when attach would otherwise be the default. Use it to bypass the daemon-owned PTY for one run without changing [terminal.attach].default_on. Composes with --resume and --continue-from.")
		cmd.Flags().BoolVar(&noProxy, "no-proxy", false,
			"With --attach: escape hatch for [terminal.attach].route_proxy. Forwards --no-proxy-route to the daemon-spawned inner launcher (and omits the proxy env) so the attached claude session is NOT routed through the observer proxy (turns are not captured). By default an attached session IS proxy-routed so its turns are captured through :8820.")
	}
	// --resume is registered ONLY when claude-code declares a grounded native
	// ResumeNative contract (session-attach design Phase 3; capability dispatch,
	// never a tool-name branch — CLAUDE.md #3). It injects `--resume <id>` into
	// the claude child so the tool reattaches its REAL prior conversation (not a
	// distilled fork). Mutually exclusive with the handoff-fork family;
	// combinable with --attach (the daemon owns the resumed PTY).
	if capClaude, _ := integration.For("claude-code"); capClaude.Resume.Kind == integration.ResumeNative {
		cmd.Flags().StringVar(&resume, "resume", "",
			"Resume a CLOSED claude-code session by its id: launches `claude --resume <id>`, reattaching the tool's REAL prior conversation (signed thinking blocks and all) — NOT a distilled fork. Mutually exclusive with --continue-from/--carry/--from-message/--from-time. Combine with --attach to resume into a daemon-owned session the dashboard can join. See docs/plans/session-attach-design-2026-07-19.md.")
	}
	return cmd
}

type claudeLauncherOptions struct {
	configPath   string
	proxyURL     string
	claudePath   string
	claudeArgs   []string
	verify       bool
	continueFrom string
	carry        string
	fromMessage  int
	fromTime     string
	attach       bool
	noAttach     bool
	noProxy      bool
	noProxyRoute bool
	resume       string
	stderr       interface{ Write([]byte) (int, error) }
}

// runClaudeLauncher resolves the proxy URL, prepares the child env, and
// execs claude with the original argv. Exit code is forwarded via
// exitErr (same shape as `observer run`). When --continue-from is set it
// first distills a handover (delivery=inject_prompt) and prepends it as
// claude's leading positional prompt.
func runClaudeLauncher(ctx context.Context, opts claudeLauncherOptions) error {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: opts.configPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// P6 item 5: refuse a bare launch of an org-disallowed tool (node.features
	// tools.disallow). "claude-code" is claude's integration-registry key.
	if err := refuseIfToolDisallowedCfg(cfg, "claude-code", opts.stderr); err != nil {
		return err
	}

	proxyURL := opts.proxyURL
	if proxyURL == "" {
		port := cfg.Proxy.Port
		if port <= 0 {
			port = 8820
		}
		proxyURL = "http://127.0.0.1:" + strconv.Itoa(port)
	}

	// Attach mode (session-attach design Phase 1 + resilient-attach WP-C): hand
	// the PTY to the daemon instead of exec'ing claude as a child of this shell.
	// The daemon spawns the inner `observer claude` launcher (which does its own
	// OAuth wiring), so we forward only the proxy-routing var ANTHROPIC_BASE_URL
	// — and omit it under the escape hatch. Attach is now the DEFAULT for an
	// interactive launch when the daemon is reachable; decideAttach resolves the
	// verdict from injected facts (config, capability grounding, TTY-ness,
	// incompatible-mode, and a lazily-dialed reachability probe). On the
	// daemon-unreachable fallback it prints ONE notice and continues to the bare
	// launch below (exit codes preserved). This runs before any bare-launch prep.
	// The attach gate is now the shared launcherAttach (attach-all-launchers):
	// it walks the SAME decideAttach table, prints the SAME notice, and on an
	// attach verdict runs the SAME runAttachSession — the claude-specific pieces
	// (the reject-flags list, the base-URL-unless-escape-hatch + profile env, the
	// --claude-path/--resume passthrough, the --no-proxy/--no-proxy-route
	// escape-hatch resolution) are expressed as spec closures so shared code
	// never branches on tool identity (CLAUDE.md #3). Byte-equal to the prior
	// inline block + runClaudeAttach.
	outcome, attachErr := launcherAttach(ctx, launcherAttachSpec{
		tool:          "claude-code",
		configPath:    opts.configPath,
		proxyOverride: opts.proxyURL,
		proxyFlag:     "--proxy",
		flagAttach:    opts.attach,
		flagNoAttach:  opts.noAttach,
		incompatible:  claudeAttachIncompatible(opts),
		rejectFlags:   func() error { return rejectIncompatibleClaudeAttachFlags(opts) },
		// Escape hatch: skip proxy routing when the operator asked (--no-proxy OR
		// the outer --no-proxy-route, B2-4) or config opted out.
		noProxyRoute: func(rp bool) bool { return opts.noProxyRoute || opts.noProxy || !rp },
		// R2-5: forward ANTHROPIC_BASE_URL (unless the escape hatch is engaged)
		// AND the caller's own claude PROFILE env (CLAUDE_CONFIG_DIR /
		// ANTHROPIC_CONFIG_DIR) regardless of routing, so the daemon-spawned inner
		// launcher resolves the caller's profile, not the daemon's.
		attachEnv: func(u string, npr bool) []string {
			var e []string
			if !npr {
				e = append(e, "ANTHROPIC_BASE_URL="+u)
			}
			return append(e, claudeAttachEnv(os.Environ())...)
		},
		passthrough: claudeAttachPassthrough(opts),
		toolArgs:    opts.claudeArgs,
		stderr:      opts.stderr,
	})
	if outcome.handled {
		return attachErr
	}
	// F3(a): remember when the attach layer already emitted its daemon-unreachable
	// notice, so a downstream empty-unset proxy-down notice (same root cause — the
	// daemon IS the proxy) doesn't print a redundant SECOND line, and the
	// bare-direct neutralize notice condenses to its no-"unreachable"-prefix form
	// (capture-loss info survives; the redundant half doesn't).
	attachDownNoticed := outcome.daemonUnreachableNoticed

	// Native resume (session-attach design Phase 3): `observer claude --resume
	// <id>` injects `--resume <id>` at the front of the claude child argv so
	// claude reattaches its REAL prior conversation. Mutually exclusive with
	// the handoff-fork family (--continue-from et al.), rejected loud. The
	// attach branch above already returned for `--attach --resume` (forwarded
	// to the daemon-spawned inner launcher via passthrough), so this bare-launch
	// injection is reached only WITHOUT --attach. It runs before the --verify /
	// --no-proxy-route branches, which read opts.claudeArgs — verify is a
	// no-launch mode and ignores the injected args (ordering respected).
	if opts.resume != "" {
		if rerr := rejectIncompatibleClaudeResumeFlags(opts); rerr != nil {
			fmt.Fprintln(opts.stderr, rerr)
			return rerr
		}
		// Durable cross-process resume claim (H3): held for the child's lifetime
		// so a concurrent daemon attach-resume (or another bare resume) of the
		// same session is refused rather than duplicating the transcript. No-op
		// for a daemon-spawned inner launcher (the daemon already holds it).
		release, ok := acquireBareResumeClaim(opts.stderr, cfg.Observer.DBPath, "claude", opts.resume)
		if !ok {
			return exitErr(1)
		}
		defer release()
		opts.claudeArgs = injectClaudeResume(opts.claudeArgs, opts.resume)
		fmt.Fprintf(opts.stderr,
			"observer claude: native resume — reattaching session %s via `claude --resume` (real transcript, not a fork)\n",
			opts.resume)
	}

	bin, binErr := resolveToolBin("claude-code", opts.claudePath, "--claude-path", opts.configPath, opts.stderr)
	if binErr != nil {
		return binErr
	}

	// --verify is a NO-LAUNCH mode: evaluate it BEFORE any launch branch so it
	// is never bypassed by --no-proxy-route's early direct-launch below (B3-2).
	// It runs the same pre-flight checks (proxy reachability + credentials.json
	// + OAuth token) regardless of the routing escape hatch, then exits.
	if opts.verify {
		credPath := claudeCredentialsPath()
		_, info, perr := prepareClaudeEnv(os.Environ(), proxyURL, credPath)
		if perr != nil {
			return perr
		}
		proxyUp := proxyReachable(proxyURL, 250*time.Millisecond)
		return runClaudeVerify(opts.stderr, claudeVerifyResult{
			ProxyURL:        proxyURL,
			ProxyReachable:  proxyUp,
			CredentialsPath: credPath,
			Info:            info,
		})
	}

	// Launch-time proxy-routing fallback decision (resilient-attach scenario 4/5
	// + codex-parity --no-proxy-route). Claude Code's settings.json env block WINS
	// over the process environment (docs "How scopes interact" + the empty-string-
	// overrides-shell-export note; empirically confirmed 2026-07-20), so a
	// persistent observer route `observer init` bakes into ~/.claude/settings.json
	// can't be neutralized by touching the process env. It CAN, though, be
	// overridden by a one-shot CLI-scope `--settings` file, which outranks user
	// settings.json (same probe) — so decideProxyFallback NEUTRALIZES a baked-in
	// route to a working direct-to-Anthropic launch (operator decision #2: notice
	// + bare launch, never a silent break), whether it is a --no-proxy-route
	// bypass or the daemon-down attach fallback that broke the operator's session.
	// It FAILS CLOSED only on the residual it genuinely can't neutralize: a
	// baked-in route AND the operator passed their own --settings (unsafe to
	// stack). Runs AFTER --verify (a no-launch diagnostic that must never block).
	// Resolve the EFFECTIVE settings-scope route across every scope claude honors
	// (finding 1): Managed > CLI --settings > Local > Project > User, per-key
	// merge, highest precedence wins. cwd is the launcher's working directory —
	// the dir claude inherits (child.Dir defaults to it; --continue-from later
	// overrides Dir to the source project root, a niche path handled by
	// os.Getwd() here since the decision runs before that resolution).
	// Resolve --continue-from to the FINAL child argv + working directory BEFORE
	// the routing decision (finding N2). --continue-from overrides child.Dir to the
	// SOURCE project root, whose .claude/settings*.json can carry an observer route
	// the launch-cwd resolution would miss — defeating an explicit --no-proxy-route
	// or sending the launch into a dead proxy. Resolving it once here gives ONE
	// route-resolution point against the dir the child truly runs in; the launch
	// helpers below reuse launchArgs/continueDir and never re-resolve the handoff.
	launchCwd, _ := os.Getwd()
	launchArgs := opts.claudeArgs
	var continueDir string
	if opts.continueFrom != "" {
		injected, cwd, cerr := claudeContinueArgs(ctx, opts)
		if cerr != nil {
			// SilenceErrors: true hides the returned error, so surface it
			// explicitly — the operator needs to know why we didn't launch.
			fmt.Fprintf(opts.stderr, "observer claude: continue-from failed: %v\n", cerr)
			return cerr
		}
		launchArgs = injected
		continueDir = cwd
	}
	// The dir the child will ACTUALLY run in: the continue-from source root when
	// set (continueDir), else the launcher's own cwd (child.Dir="" inherits it).
	route := resolveClaudeEffectiveRoute(proxyURL, claudeRouteCwd(launchCwd, continueDir), opts.claudeArgs)

	// Finding N1: the operator passed a --settings observer cannot read/parse (a
	// missing/unreadable file, or unparseable inline JSON). We can't tell whether
	// it routes to the proxy, so we conservatively refuse rather than risk silently
	// capturing (or dead-proxying) turns — the CLI-scope "unknown" that the
	// fail-closed disposition covers. Honest message (never asserts a route we
	// didn't prove); fix or drop --settings and re-run.
	if route.cliUnreadable {
		fmt.Fprintf(opts.stderr,
			"observer claude: refusing to launch — your --settings value (%s) could not be read or parsed as a settings object, so observer cannot tell whether it routes claude to the observer proxy. Fix or drop --settings (pass a readable file path or valid inline JSON) and re-run.\n",
			route.file)
		return exitErr(1)
	}

	// A third-party (non-observer) effective route at ANY scope is the operator's
	// deliberate choice: honor it, don't neutralize or fail closed — proceed to a
	// direct launch that leaves their environment/settings untouched.
	if route.class == claudeRouteThirdParty {
		return runClaudeThirdPartyDirect(opts, bin, route, launchArgs, continueDir)
	}

	// Finding N3: a settings scope explicitly UNSETS ANTHROPIC_BASE_URL (="") — it
	// acts as unset AND defeats the process env, so the routed path's env injection
	// is silently nullified. Handle it distinctly: restore capture via a CLI
	// --settings pin (routed, proxy up, outrankable scope), or honestly warn +
	// launch direct (managed/own-settings, or a bypass/daemon-down intent).
	if route.class == claudeRouteEmptyUnset {
		return runClaudeEmptyUnset(opts, bin, proxyURL, route, launchArgs, continueDir, attachDownNoticed)
	}

	observerRoute := route.class == claudeRouteObserver
	proxyUp := false
	if !opts.noProxyRoute {
		// The dial is irrelevant to a --no-proxy-route verdict (it turns solely on
		// the persistent route), so only pay for it on a routed launch.
		proxyUp = proxyReachable(proxyURL, 250*time.Millisecond)
	}
	// An observer route in user/project/local scope is neutralizable with our
	// one-shot CLI-scope `--settings` bypass (CLI beats those — probe 2026-07-20)
	// UNLESS the operator passed their own --settings (we must not stack). A route
	// in MANAGED scope (managed beats CLI) or in the operator's own --settings file
	// (CLI scope) is genuinely BLOCKING → fail closed. That is the sole residual
	// claude fail-closed, honoring operator decision #2 everywhere it can.
	scopeNeutralizable := route.scope == claudeScopeUser ||
		route.scope == claudeScopeProject ||
		route.scope == claudeScopeLocal
	canNeutralize := observerRoute && scopeNeutralizable && !claudeArgsHaveSettings(opts.claudeArgs)
	switch fb := decideProxyFallback(proxyFallbackInputs{
		noProxyRoute:            opts.noProxyRoute,
		proxyReachable:          proxyUp,
		persistentRoute:         observerRoute,
		canNeutralizePersistent: canNeutralize,
	}); fb.action {
	case proxyFailClosed:
		// Distinguish the two residual causes for the copy: an un-overridable
		// managed-scope route vs the operator's own --settings.
		cause := blockOwnSettings
		if route.scope == claudeScopeManaged {
			cause = blockManaged
		}
		fmt.Fprintln(opts.stderr, claudeProxyFailClosedMsg(fb.reason, proxyURL, route.file, cause, attachDownNoticed))
		return exitErr(1)
	case proxyNeutralize:
		return runClaudeBareDirect(opts, bin, fb.reason, proxyURL, observerRoute, route.file, launchArgs, continueDir, attachDownNoticed)
	}
	// proxyRouteProceed → the routed launch below (proxy reachable, and no
	// baked-in route pointing at a dead proxy).

	return runClaudeRoutedLaunch(opts, bin, proxyURL, route, launchArgs, continueDir)
}

// runClaudeRoutedLaunch prepares the claude child environment (OAuth token
// re-export via prepareClaudeEnv), emits the per-credentials-edge-case stderr
// notices, forces a known session id for a daemon-spawned launch, and execs
// claude on the proxy-routed path. Extracted from runClaudeLauncher to keep its
// cyclomatic complexity in bounds; reached only on a proxyRouteProceed verdict
// (proxy reachable, no baked-in route into a dead proxy).
func runClaudeRoutedLaunch(opts claudeLauncherOptions, bin, proxyURL string, route claudeRouteResolution, launchArgs []string, continueDir string) error {
	credPath := claudeCredentialsPath()
	env, info, err := prepareClaudeEnv(os.Environ(), proxyURL, credPath)
	if err != nil {
		return err
	}

	// Surface a clear stderr line for each credentials-file edge case so
	// the OAuth-fallback path is observable. The wrapper already does
	// the right thing on each branch (file-missing → API-key mode;
	// malformed → API-key mode + surface the parse error); the operator
	// needs to know which path was taken so a silent "API-key mode" line
	// doesn't hide a Pro/Max user who thought OAuth was wiring up.
	switch {
	case info.OAuthStale:
		fmt.Fprintf(opts.stderr,
			"observer claude: stored OAuth token in %s is expired — NOT re-exporting it (a stale env token blocks Claude Code's own refresh and the session 401s). Launching with ANTHROPIC_BASE_URL only; claude refreshes its token itself.\n",
			credPath)
	case info.CredentialsErr != nil:
		fmt.Fprintf(opts.stderr,
			"observer claude: warning — credentials file %s exists but is unparseable (%v); falling back to API-key mode. Fix the file or set ANTHROPIC_AUTH_TOKEN manually if you're a Pro/Max user.\n",
			credPath, info.CredentialsErr)
	case info.OAuthPreset:
		fmt.Fprintf(opts.stderr,
			"observer claude: ANTHROPIC_AUTH_TOKEN already in env; using yours (credentials.json untouched).\n")
	case !info.OAuthInjected:
		// Distinguish "no credentials file at all" (API-key user) from
		// "credentials file present but no token field" (a stale or
		// hand-edited file the user probably wants to know about).
		if credentialsFileExists(credPath) {
			fmt.Fprintf(opts.stderr,
				"observer claude: warning — credentials file %s has no claudeAiOauth.accessToken; falling back to API-key mode. Re-run `claude` to refresh your OAuth credentials if you're a Pro/Max user.\n",
				credPath)
		}
	}

	// (--verify is handled earlier, before the launch branches — B3-2. Proxy
	// reachability is handled earlier too: this routed path is reached only on a
	// proxyRouteProceed verdict, which already requires the proxy to be up, so the
	// old "proxy not reachable" warn-and-launch-anyway is gone — an unreachable
	// proxy now fails closed or neutralizes above instead of silently breaking.)

	if info.OAuthInjected {
		fmt.Fprintf(opts.stderr,
			"observer claude: routing via %s (Pro/Max OAuth token re-exported as ANTHROPIC_AUTH_TOKEN)\n",
			proxyURL)
	} else {
		fmt.Fprintf(opts.stderr,
			"observer claude: routing via %s (ANTHROPIC_BASE_URL only — using existing API-key auth)\n",
			proxyURL)
	}

	// --continue-from was resolved upfront (finding N2); launchArgs already carries
	// the injected handover. When NOT continuing, force a known session id and echo
	// it to the daemon on the trusted OOB channel so a daemon-spawned proxy-routed
	// launch (session-attach Phase 2 / P2-1) correlates to its observer session at
	// oob confidence — the signal "Jump in" matches on. No-op for a bare `observer
	// claude` (no OOB channel).
	if opts.continueFrom == "" {
		launchArgs = forceClaudeSessionID(launchArgs)
	}

	evidence := budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	if route.class == claudeRouteObserver ||
		(route.class == claudeRouteNone && urlRoutesToProxy(envValue(env, "ANTHROPIC_BASE_URL"), proxyURL)) {
		evidence = budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: proxyURL}
	}
	return execClaudeChild(bin, launchArgs, env, continueDir, opts.configPath, evidence)
}

// claudeAttachEnv builds the profile env forwarded across the attach socket to
// the daemon-spawned inner `observer claude` launcher: the caller's own
// CLAUDE_CONFIG_DIR / ANTHROPIC_CONFIG_DIR when PRESENT (R2-5). Both are honored
// by the bare launcher's credentials lookup (claudeCredentialsPath) AND by the
// claude binary, so forwarding them makes a daemon-spawned attach resolve the
// same profile a bare launch would. Reads from the passed environment
// (os.Environ() in production; injectable for tests). It forwards on PRESENCE,
// not non-emptiness (F3): an explicit `CLAUDE_CONFIG_DIR=` (empty) is forwarded
// verbatim so the child resets to claude's default profile rather than silently
// retaining the daemon's inherited value — launchChildEnv layers ExtraEnv AFTER
// the inherited env, so the empty override wins at the child (last-wins). Nil
// when neither key is present.
func claudeAttachEnv(environ []string) []string {
	var out []string
	for _, key := range []string{"CLAUDE_CONFIG_DIR", "ANTHROPIC_CONFIG_DIR"} {
		if v, ok := lookupEnvValue(environ, key); ok {
			out = append(out, key+"="+v)
		}
	}
	return out
}

// claudeAttachPassthrough builds the launcher-specific wrapper flags forwarded
// to the daemon-spawned inner `observer claude` (B2-6): --claude-path and
// --resume. --resume is FORWARDED (not rejected) so `observer claude --attach
// --resume <id>` resumes the REAL transcript into a daemon-owned session the
// dashboard can join (design §2.4 mortality backstop).
func claudeAttachPassthrough(opts claudeLauncherOptions) []string {
	var p []string
	if opts.claudePath != "" {
		p = append(p, "--claude-path", opts.claudePath)
	}
	if opts.resume != "" {
		p = append(p, "--resume", opts.resume)
	}
	return p
}

// injectClaudeResume prepends `--resume <id>` to claude's argv so the child is
// `claude --resume <id> [user args]`. The resume flag LEADS (before the user's
// `--` remainder) so it is unambiguously claude's own, never captured as the
// value of a trailing user flag.
func injectClaudeResume(claudeArgs []string, id string) []string {
	return append([]string{"--resume", id}, claudeArgs...)
}

// claudeAttachIncompatible reports whether this launch is in a mode that cannot
// compose with attach, so default-on attach must NOT engage (it falls through to
// the bare launch SILENTLY — these are scripted/one-shot paths where an attach
// notice would be spam). It mirrors the flags rejectIncompatibleClaudeAttachFlags
// refuses under an explicit `--attach` (verify + the handoff-fork family) and
// additionally treats claude's headless print mode (`-p`/`--print` in the tool
// args) as incompatible — the `observer claude -- --print "hi"` wrapper contract
// must always take the bare path. --resume is NOT incompatible (attach forwards
// it via passthrough), and neither is --no-proxy-route (an attach escape hatch).
func claudeAttachIncompatible(opts claudeLauncherOptions) bool {
	return opts.verify ||
		opts.continueFrom != "" ||
		opts.carry != "" ||
		opts.fromMessage != 0 ||
		opts.fromTime != "" ||
		argsContainClaudePrint(opts.claudeArgs)
}

// rejectIncompatibleClaudeAttachFlags fails `observer claude --attach` fast for
// wrapper flags the daemon-spawned inner launcher cannot honor, naming the
// offending flag rather than silently dropping it (B2-6). --config / --proxy /
// --claude-path / --no-proxy / --no-proxy-route ARE forwarded (handled by the
// caller), as is the trailing `--` tool remainder; everything else that changes
// launch behavior is rejected here.
func rejectIncompatibleClaudeAttachFlags(opts claudeLauncherOptions) error {
	switch {
	case opts.verify:
		return errors.New("observer claude: --verify is not supported with --attach in v1 (run `observer claude --verify` without --attach)")
	case opts.continueFrom != "":
		return errors.New("observer claude: --continue-from is not supported with --attach in v1 (attach launches a fresh session; use the dashboard handoff to continue a session)")
	case opts.carry != "":
		return errors.New("observer claude: --carry is not supported with --attach in v1 (it only applies to --continue-from)")
	case opts.fromMessage != 0:
		return errors.New("observer claude: --from-message is not supported with --attach in v1 (it only applies to --continue-from)")
	case opts.fromTime != "":
		return errors.New("observer claude: --from-time is not supported with --attach in v1 (it only applies to --continue-from)")
	}
	return nil
}

// rejectIncompatibleClaudeResumeFlags fails `observer claude --resume` fast for
// the handoff-fork family (--continue-from and its modifiers), which composes a
// NEW session from a distilled handover — the opposite of native resume's
// real-transcript reattach. Naming each conflict keeps it loud rather than
// silently dropping one.
func rejectIncompatibleClaudeResumeFlags(opts claudeLauncherOptions) error {
	switch {
	case opts.continueFrom != "":
		return errors.New("observer claude: --resume (native, reattaches the REAL transcript) is mutually exclusive with --continue-from (distilled fork into a NEW session) — pick one")
	case opts.carry != "":
		return errors.New("observer claude: --carry only applies to --continue-from and cannot be combined with --resume")
	case opts.fromMessage != 0:
		return errors.New("observer claude: --from-message only applies to --continue-from and cannot be combined with --resume")
	case opts.fromTime != "":
		return errors.New("observer claude: --from-time only applies to --continue-from and cannot be combined with --resume")
	}
	return nil
}

// stripEnvKeys returns env with every KEY=VALUE entry whose key is in drop
// removed. Used by --no-proxy-route to actively neutralize a proxy-routing
// variable the launcher manages (B2-3) rather than passing a stale route
// through to the child.
func stripEnvKeys(env []string, drop ...string) []string {
	if len(drop) == 0 {
		return env
	}
	dropped := make(map[string]struct{}, len(drop))
	for _, k := range drop {
		dropped[k] = struct{}{}
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			if _, ok := dropped[kv[:i]]; ok {
				continue
			}
		}
		out = append(out, kv)
	}
	return out
}

// claudeContinueArgs runs the --continue-from handoff for claude-code and
// returns the launch argv with the handover prepended as claude's leading
// positional prompt (injectLeadingPositional). It errors when the forwarded
// claude args already carry a positional prompt (two prompts) so the
// collision is loud, not silent.
func claudeContinueArgs(ctx context.Context, opts claudeLauncherOptions) ([]string, string, error) {
	return continueFromArgs(ctx, continueFromParams{
		tool:        "claude-code",
		label:       "claude",
		configPath:  opts.configPath,
		sessionID:   opts.continueFrom,
		carry:       opts.carry,
		fromMessage: opts.fromMessage,
		fromTime:    opts.fromTime,
		args:        opts.claudeArgs,
		inject:      promptInjection{Kind: injectLeadingPositional},
		stderr:      opts.stderr,
	})
}

// forceClaudeSessionID, when this process is a daemon-spawned launcher with a
// live trusted OOB channel, ensures claude runs under a KNOWN session id and
// announces that id to the daemon (session-attach Phase 2 / P2-1) so the run
// correlates to its observer session at oob confidence. It returns the launch
// argv (unchanged for a bare, non-daemon-spawned `observer claude`).
//
// claude-code accepts `--session-id <uuid>`. If the operator already supplied
// one it is reused (and announced); otherwise a fresh v4 UUID is minted and
// prepended. Announcement is the load-bearing half — the daemon's OOB drain
// records the run->session link from the frame.
//
// Grounding note (why this is honest for the attach path): attach children are
// PROXY-ROUTED by default (design §6 #7), and the proxy resolves a Claude Code
// session from the request's `metadata.user_id.session_id` (the API/telemetry
// id) — which `--session-id` sets — so the correlated id matches the session
// the proxy records for the captured turns. A non-proxied attach isn't captured
// at all, so a missing correlation there is correct, not a defect. (Claude
// Code's separate LOCAL-persistence UUID in interactive mode is a documented
// upstream inconsistency; the proxy-side telemetry id is the one that matters
// here.) The map mirrors the integration registry's Attach rows — keep them in
// step when a second `--session-id`-settable tool is grounded (codex first).
func forceClaudeSessionID(args []string) []string {
	if !oobChannelActive() {
		return args
	}
	// F3: claude-code REJECTS `--session-id` alongside `--continue`/`--resume`
	// unless `--fork-session` is also present ("--session-id can only be used
	// with --continue or --resume if --fork-session is also specified"). When the
	// argv already reattaches an existing session (a native `observer claude
	// --resume <id>`, or a user `--continue`/`--resume` in the `--` remainder),
	// prepending a forced id would abort the launch — breaking the attach
	// mortality backstop. So DON'T force one; instead announce the RESUMED
	// session id over the trusted OOB channel (when the argv carries `--resume
	// <id>`) so the run still correlates to the reopened session. A bare
	// `--continue` (reattach-most-recent, no id in argv) is left uncorrelated but
	// unbroken. The `--fork-session` variant is handled separately below (R2-4):
	// a fork creates a NEW session, so the resume id is NOT its correlation
	// target — announce the explicit `--session-id NEW` if present, else abstain.
	if id, resuming := claudeResumeContinueID(args); resuming {
		// R2-4: a FORKED resume (`--fork-session`) does NOT reattach the resume
		// target — claude creates a NEW session forked off it, so the resume id
		// (OLD) is the WRONG correlation target. Announce the explicit
		// `--session-id NEW` when the operator pinned one (claude allows a forced
		// id alongside --resume ONLY with --fork-session); otherwise claude mints
		// an id we can't know, so announce NOTHING (abstain — never announce OLD).
		if hasClaudeForkSession(args) {
			if sid, ok := existingSessionIDArg(args); ok {
				announceOOBSession(sid)
			}
			return args
		}
		// Plain --resume/--continue (no fork): claude reattaches the resume
		// target, so announcing that id is correct.
		if id != "" {
			announceOOBSession(id)
		}
		return args
	}
	if sid, ok := existingSessionIDArg(args); ok {
		announceOOBSession(sid)
		return args
	}
	sid, err := newSessionUUID()
	if err != nil {
		return args // fail-open: no forced id, no announce — launch proceeds
	}
	announceOOBSession(sid)
	return append([]string{"--session-id", sid}, args...)
}

// claudeResumeContinueID reports whether a claude argv already reattaches an
// existing session — via `--resume <id>` / `--resume=<id>` (and their short
// alias `-r <id>` / `-r=<id>`), or a bare `--continue` / `-c` (reattach the most
// recent). It returns (id, true) carrying the resume target id when one is
// present in the argv (so the caller can announce it over OOB), or ("", true)
// for the valueless `--continue`/`-c` / a value-less `--resume`/`-r` (no id in
// argv). claude documents `-r` as `--resume` and `-c` as `--continue`, so the
// short forms must gate resume detection identically to the long forms;
// omitting them (the pre-fix bug) let `observer claude --attach -- -r OLD` be
// treated as fresh, so a forced `--session-id NEW` was prepended and claude
// rejected the `--session-id` + `-r` combination without `--fork-session`.
// claude forbids a forced `--session-id` alongside any of these unless
// `--fork-session` is also given, so the caller must NOT inject one. Returns
// ("", false) when none is present. The scan only inspects claude's own reattach
// flags; it never matches a value token.
func claudeResumeContinueID(args []string) (string, bool) {
	for i, a := range args {
		switch {
		case a == "--resume" || a == "-r":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				return args[i+1], true
			}
			return "", true
		case strings.HasPrefix(a, "--resume="):
			return strings.TrimPrefix(a, "--resume="), true
		case strings.HasPrefix(a, "-r="):
			return strings.TrimPrefix(a, "-r="), true
		case a == "--continue" || a == "-c":
			return "", true
		}
	}
	return "", false
}

// hasClaudeForkSession reports whether claude's boolean `--fork-session` flag is
// present in the argv. When set alongside `--resume`/`--continue`, claude does
// NOT reattach the resume target — it forks a NEW session off it — so the resume
// id is the wrong correlation target (R2-4). It is a valueless boolean flag, so
// an exact-token scan suffices.
func hasClaudeForkSession(args []string) bool {
	for _, a := range args {
		if a == "--fork-session" {
			return true
		}
	}
	return false
}

// existingSessionIDArg returns a `--session-id` value already present in args
// (both `--session-id X` and `--session-id=X` forms), so an operator-supplied
// id is reused rather than a second one forced in.
func existingSessionIDArg(args []string) (string, bool) {
	for i, a := range args {
		if a == "--session-id" {
			if i+1 < len(args) && args[i+1] != "" {
				return args[i+1], true
			}
			return "", false
		}
		if v, ok := strings.CutPrefix(a, "--session-id="); ok && v != "" {
			return v, true
		}
	}
	return "", false
}

// newSessionUUID mints a canonical lowercase RFC-4122 v4 UUID from crypto/rand
// for use as a forced claude session id.
func newSessionUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint session uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// claudeEnvInfo records what the launcher actually changed, so callers
// (and tests) can verify intent without diff'ing two []string slices.
type claudeEnvInfo struct {
	BaseURLSet     bool
	BaseURLPreset  bool // user already had ANTHROPIC_BASE_URL set; we kept theirs
	OAuthInjected  bool
	OAuthPreset    bool  // user already had ANTHROPIC_AUTH_TOKEN; we kept theirs
	OAuthStale     bool  // stored token expired — deliberately NOT re-exported (D13)
	CredentialsErr error // non-fatal — file missing / unreadable / wrong shape
}

// prepareClaudeEnv merges the OAuth-routing env vars into the parent
// environment without clobbering anything the user explicitly set.
//
// Rules:
//   - If ANTHROPIC_BASE_URL is unset, set it to proxyURL.
//   - If ANTHROPIC_AUTH_TOKEN is unset and credentialsPath has a usable
//     `claudeAiOauth.accessToken`, set it from there.
//   - Anything the user already exported wins. The launcher never
//     overrides explicit env state.
func prepareClaudeEnv(parent []string, proxyURL, credentialsPath string) ([]string, claudeEnvInfo, error) {
	// The env this builds is handed to the untrusted claude child, so drop the
	// trusted-OOB-channel vars up front — they must never reach the child (the
	// per-session auth secret would let it forge frames on the trusted channel).
	parent = scrubOOBEnv(parent)
	env := make(map[string]string, len(parent))
	keys := make([]string, 0, len(parent)) // preserve order for determinism
	for _, kv := range parent {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		k, v := kv[:idx], kv[idx+1:]
		if _, seen := env[k]; !seen {
			keys = append(keys, k)
		}
		env[k] = v
	}

	info := claudeEnvInfo{}

	if existing, ok := env["ANTHROPIC_BASE_URL"]; ok && existing != "" {
		info.BaseURLPreset = true
	} else {
		env["ANTHROPIC_BASE_URL"] = proxyURL
		keys = appendIfMissing(keys, "ANTHROPIC_BASE_URL")
		info.BaseURLSet = true
	}

	if existing, ok := env["ANTHROPIC_AUTH_TOKEN"]; ok && existing != "" {
		info.OAuthPreset = true
	} else if token, stale, err := readOAuthAccessToken(credentialsPath); err != nil {
		// Non-fatal: API-key users won't have this file. Surface only if
		// the file existed but was malformed (the err signals that).
		info.CredentialsErr = err
	} else if stale {
		info.OAuthStale = true
	} else if token != "" {
		env["ANTHROPIC_AUTH_TOKEN"] = token
		keys = appendIfMissing(keys, "ANTHROPIC_AUTH_TOKEN")
		info.OAuthInjected = true
	}

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out, info, nil
}

func appendIfMissing(keys []string, k string) []string {
	for _, existing := range keys {
		if existing == k {
			return keys
		}
	}
	return append(keys, k)
}

// claudeCredentialsPath resolves where Claude Code's `.credentials.json`
// lives, honoring CLAUDE_CONFIG_DIR / ANTHROPIC_CONFIG_DIR overrides
// before falling back to ~/.claude/. Matches the binary's own lookup
// order (both env-var names appear in the 2.1.x strings table).
func claudeCredentialsPath() string {
	for _, env := range []string{"CLAUDE_CONFIG_DIR", "ANTHROPIC_CONFIG_DIR"} {
		if dir := os.Getenv(env); dir != "" {
			return filepath.Join(dir, ".credentials.json")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", ".credentials.json")
}

// readOAuthAccessToken returns claudeAiOauth.accessToken from path, or
// "" if the file is missing. Returns a non-nil error only when the file
// exists but can't be parsed as the expected JSON shape — those are
// worth surfacing to the user.
func readOAuthAccessToken(path string) (token string, stale bool, err error) {
	if path == "" {
		return "", false, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		ClaudeAiOauth struct {
			AccessToken string `json:"accessToken"`
			// ExpiresAt is Claude Code's token expiry, ms since epoch.
			// Zero/absent = unknown — treated as fresh (legacy shape).
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", false, fmt.Errorf("parse %s: %w", path, err)
	}
	tok := doc.ClaudeAiOauth.AccessToken
	// D13 (2026-06-10): re-exporting an EXPIRED stored token as
	// ANTHROPIC_AUTH_TOKEN suppresses Claude Code's own refresh and the
	// session 401s. Report it stale instead of usable — the launcher
	// then routes via ANTHROPIC_BASE_URL only and claude refreshes
	// itself (capture verified on that path).
	if tok != "" && doc.ClaudeAiOauth.ExpiresAt > 0 &&
		time.Now().UnixMilli() >= doc.ClaudeAiOauth.ExpiresAt {
		return "", true, nil
	}
	return tok, false, nil
}

// credentialsFileExists is a thin wrapper around os.Stat so the wrapper
// can distinguish "no file at all" from "file present but empty or
// missing the token field." Used by stderr-shaping in the OAuth-
// fallback branch.
func credentialsFileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// claudeVerifyResult captures the pre-flight findings runClaudeVerify
// reports. Kept as a struct so future fields (proxy turn capture,
// model availability) plug in without rewriting the call site.
type claudeVerifyResult struct {
	ProxyURL        string
	ProxyReachable  bool
	CredentialsPath string
	Info            claudeEnvInfo
}

// runClaudeVerify prints a PASS/FAIL line per pre-flight check and
// returns exitErr(1) when any FAIL'd. PASS-only runs exit 0. The
// summary mirrors what `observer doctor` would show but scoped to
// just the claude wrapper's contract.
func runClaudeVerify(stderr interface{ Write([]byte) (int, error) }, r claudeVerifyResult) error {
	failed := 0
	fmt.Fprintln(stderr, "observer claude --verify:")

	if r.ProxyReachable {
		fmt.Fprintf(stderr, "  PASS  proxy reachable at %s\n", r.ProxyURL)
	} else {
		fmt.Fprintf(stderr, "  FAIL  proxy NOT reachable at %s — start `observer start` or `observer proxy start`\n", r.ProxyURL)
		failed++
	}

	switch {
	case r.Info.CredentialsErr != nil:
		fmt.Fprintf(stderr, "  FAIL  credentials file %s unparseable: %v\n", r.CredentialsPath, r.Info.CredentialsErr)
		failed++
	case r.Info.OAuthPreset:
		fmt.Fprintln(stderr, "  PASS  ANTHROPIC_AUTH_TOKEN already in env; OAuth credentials file not consulted")
	case r.Info.OAuthInjected:
		fmt.Fprintf(stderr, "  PASS  Pro/Max OAuth token found in %s; would re-export as ANTHROPIC_AUTH_TOKEN\n", r.CredentialsPath)
	case credentialsFileExists(r.CredentialsPath):
		fmt.Fprintf(stderr, "  WARN  %s present but has no accessToken — API-key mode will be used. If you're a Pro/Max user, re-run `claude` interactively to refresh credentials.\n", r.CredentialsPath)
	default:
		fmt.Fprintf(stderr, "  PASS  no Pro/Max credentials file at %s (assuming API-key mode; ensure ANTHROPIC_API_KEY is set)\n", r.CredentialsPath)
	}

	if r.Info.BaseURLPreset {
		fmt.Fprintln(stderr, "  WARN  ANTHROPIC_BASE_URL already set in env; the wrapper would NOT override it. Unset it to route through the observer proxy.")
	} else {
		fmt.Fprintf(stderr, "  PASS  would set ANTHROPIC_BASE_URL=%s\n", r.ProxyURL)
	}

	if failed == 0 {
		fmt.Fprintln(stderr, "observer claude --verify: all checks passed; `observer claude` should capture every turn.")
		return nil
	}
	fmt.Fprintf(stderr, "observer claude --verify: %d check(s) failed — fix above and re-verify.\n", failed)
	return exitErr(1)
}

// proxyReachable returns true when a TCP dial against the proxy URL's
// host:port succeeds within timeout. Used as a soft pre-flight before
// exec — failure is a stderr warning, not a fatal error.
func proxyReachable(proxyURL string, timeout time.Duration) bool {
	host, port, ok := splitHostPortFromURL(proxyURL)
	if !ok {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func splitHostPortFromURL(raw string) (host, port string, ok bool) {
	s := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(s, "http://"):
		s = s[len("http://"):]
	case strings.HasPrefix(s, "https://"):
		s = s[len("https://"):]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", false
	}
	return host, port, true
}
