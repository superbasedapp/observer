// launch.go — shared plumbing for the `observer <tool>` launcher family.
//
// The launchers wrap an AI coding tool so its model traffic flows through
// the observer proxy (accurate tokens + compression + cache tracking). The
// SIMPLE shape — inject one or more base-URL env vars, exec the tool,
// forward its exit code — is factored here and reused by opencode, cline-cli
// and copilot-cli. The two COMPLEX launchers keep their own logic because
// their routing is genuinely different: `observer claude` re-exports a
// Pro/Max OAuth token; `observer codex` injects a `-c openai_base_url`
// override into argv and runs codex app-server pre-flight. Both still reuse
// the lower-level primitives here (resolveProxyURL, proxyReachable).
//
// Implementation rule (CLAUDE.md / docs/audits/notes-on-proxy.md): a
// launcher writes ONLY base-URL fields. It NEVER sets, reads, or moves an
// API key — secret auth must already be in the user's environment.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	"github.com/marmutapp/superbased-observer/internal/toolresolve/host"
)

// resolveProxyURL returns the proxy base URL a launcher should route to: the
// explicit --proxy override when set, otherwise http://127.0.0.1:<port>
// (cfgPort, or 8820 when unset/invalid). Shared by every launcher so the
// default-port logic lives in exactly one place.
func resolveProxyURL(cfgPort int, override string) string {
	if override != "" {
		return override
	}
	if cfgPort <= 0 {
		cfgPort = 8820
	}
	return "http://127.0.0.1:" + strconv.Itoa(cfgPort)
}

// proxyDownAdvice returns the honest "what to do about it" clause a launcher
// appends when the observer proxy did not answer at the URL it resolved.
//
// It branches on a CAPABILITY the daemon itself stamps on every child it spawns
// (OBSERVER_DAEMON_CHILD — see runningAsDaemonChild), never on a tool name
// (CLAUDE.md #3). That marker settles the one thing the old copy got wrong: a
// dashboard-launched terminal was told to "start it with `observer start`" even
// though the daemon that spawned that very terminal was running. For such a
// child the only remaining explanations are the daemon's own `[proxy]` block —
// disabled, or listening on a different port than this launcher resolved — so
// that is what the notice names.
func proxyDownAdvice(daemonChild bool) string {
	// A build without capture.proxy never serves the port, so neither
	// `observer start` nor the daemon's [proxy] block would help: name the
	// build instead (lane MP-L1L, T-715, D-514).
	if reason := proxyNotInBuildReason(); reason != "" {
		return reason
	}
	if daemonChild {
		return "this terminal was launched BY the daemon, so the daemon IS running - check `[proxy] enabled` and `[proxy] port` in the config it was started with"
	}
	return "start it with `observer start`"
}

// proxyUnreachableNotice composes the single stderr line a simple base-URL
// launcher prints when the proxy is unreachable: what failed, the consequence,
// and the honest next step. Pure (no I/O, no env reads) so the daemon-child fact
// is injected and the whole message is table-testable.
func proxyUnreachableNotice(tool, proxyURL string, daemonChild bool) string {
	return fmt.Sprintf(
		"observer %s: warning - proxy not reachable at %s - turns are NOT captured for this run (%s)",
		tool, proxyURL, proxyDownAdvice(daemonChild))
}

// agentRuntimeDir resolves the optional rename-safe runtime dir for launched
// agents ([launch].agent_runtime_dir). The OBSERVER_AGENT_RUNTIME_DIR env var
// wins over the config key so a container can set it without editing config;
// the config fallback reads the DEFAULT config path only (a launcher run with
// a custom --config should use the env var). Memoized: at most one config load
// per process regardless of how many launchers fire. Empty = feature OFF.
var agentRuntimeDir = sync.OnceValue(func() string {
	if e := strings.TrimSpace(os.Getenv("OBSERVER_AGENT_RUNTIME_DIR")); e != "" {
		return e
	}
	if cfg, err := config.Load(config.LoadOptions{}); err == nil {
		return strings.TrimSpace(cfg.Launch.AgentRuntimeDir)
	}
	return ""
})

// agentRuntimeEnv returns the rename-safe runtime-dir env for coding agents
// whose runtimes perform atomic-rename dependency installs (npm/bun). It
// points the agent's XDG config/cache/state and the npm/bun package caches
// under dir — a local, rename-capable filesystem — so a provider-dependency
// install (e.g. OpenCode's openrouter provider module) doesn't fail on an
// SMB/NFS HOME (the EACCES-on-rename footgun). It deliberately does NOT set
// XDG_DATA_HOME: agents write their session storage there and the watcher
// reads it under $HOME/.local/share, so relocating it would blind the
// capture path. Adapter-agnostic — keyed on the runtime-dir capability, never
// on a tool name. Empty dir → nil (feature off). Pure: no I/O.
func agentRuntimeEnv(dir string) map[string]string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	return map[string]string{
		"XDG_CONFIG_HOME":       filepath.Join(dir, "config"),
		"XDG_CACHE_HOME":        filepath.Join(dir, "cache"),
		"XDG_STATE_HOME":        filepath.Join(dir, "state"),
		"npm_config_cache":      filepath.Join(dir, "npm"),
		"BUN_INSTALL_CACHE_DIR": filepath.Join(dir, "bun"),
	}
}

// applyAgentRuntimeEnv layers the rename-safe runtime-dir env into base (a
// launcher's starting env) when the feature is on, creating the target dirs.
// A user's own XDG_* value still wins (applyBaseURLEnv semantics), and the
// runtime keys are layered QUIETLY — they are not reported in the launcher's
// "routing via …" line, which stays focused on the base-URL keys. No-op
// (returns base unchanged) when dir is empty. Shared by runEnvLauncher and
// runOpencodeLauncher so every launcher gets it from one seam — a new
// launcher inherits it for free.
func applyAgentRuntimeEnv(base []string, dir string) []string {
	rt := agentRuntimeEnv(dir)
	if rt == nil {
		return base
	}
	for _, v := range rt {
		_ = os.MkdirAll(v, 0o755) //nolint:errcheck,gosec // best-effort; the child surfaces a real dir failure
	}
	out, _, _ := applyBaseURLEnv(base, rt)
	return out
}

// resolveEnv returns the toolresolve.Env driving the registry resolution
// ladder. It is memoized per process via sync.OnceValue so the login-shell
// PATH capture and the crossmount home walk happen exactly once no matter how
// many launchers resolve. It is a package var so a test can substitute a
// map-backed fake env (restore it in a defer).
var resolveEnv = sync.OnceValue(func() toolresolve.Env {
	return host.NewEnv(host.Options{})
})

// resolveToolBin resolves a launchable tool's binary through the registry-
// driven ladder, returning the launchable path or an honest, actionable error.
// tool is the integration-registry KEY (e.g. "claude-code", "gemini-cli",
// "kimi-code") — the binary spellings, probe dirs, and grounded install hints
// all come from that row, so callers never name the binary themselves. The
// ladder:
//
//  1. override (the --<tool>-path flag) — trusted verbatim, no checks
//     (unchanged trust semantics).
//  2. [launch.tools.<tool>].path from the operator's config — stat-checked; a
//     set-but-missing path is an error NAMING the config key so the operator
//     can fix it. A config that fails to load falls open to the ladder.
//  3. the toolresolve ladder over the registry Binary row: `ok` launches
//     silently; `ok_off_path` / `shadowed` launch with a one-time honest note
//     on stderr; `foreign_only` / `not_found` return an error whose message IS
//     the FormatVerdict text (the grounded install command, or "installed on
//     Windows, not in WSL").
//  4. no Binary row (defensive — the registry coverage test pins one for every
//     launchable tool) → a bare PATH lookup of the tool name.
//
// pathFlag names the override flag surfaced in the step-4 fallback error.
// stderr receives the launchable-but-imperfect notes; pass io.Discard to stay
// quiet.
func resolveToolBin(tool, override, pathFlag, configPath string, stderr io.Writer) (string, error) {
	if override != "" {
		return override, nil
	}

	// Step 2: operator config override. Fail open on a config load error so a
	// broken config never blocks the ladder.
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
		if tc, ok := cfg.Launch.Tools[tool]; ok && tc.Path != "" {
			if fi, statErr := os.Stat(tc.Path); statErr != nil || fi.IsDir() {
				return "", fmt.Errorf(
					"%s binary not found at [launch.tools.%s].path = %q - fix the path or remove the entry",
					tool, tool, tc.Path,
				)
			}
			return tc.Path, nil
		}
	}

	// Step 3: registry-driven resolution ladder over the Binary row.
	if row, ok := integration.For(tool); ok && row.Binary != nil {
		env := resolveEnv()
		r := toolresolve.Resolve(*row.Binary, env)
		switch r.Verdict {
		case toolresolve.VerdictOK, toolresolve.VerdictOKOffPath, toolresolve.VerdictShadowed:
			if r.Verdict != toolresolve.VerdictOK {
				fmt.Fprint(stderr, toolresolve.FormatVerdict(tool, pathFlag, r))
			}
			// Minimum host runtime (runtime_preflight.go): a node shim whose
			// node is older than the vendor's engines.node floor would crash
			// at startup, so refuse up front with the plain fix. Visible, so a
			// dashboard terminal shows it too.
			if c, ok := launchRuntimeCheck(row.Binary, r, env, runtime.GOOS, launchDirHere()); ok && c.Blocking() {
				return "", newVisibleLauncherError(errors.New(c.Remedy), c.Remedy)
			}
			return r.Bin, nil
		default: // foreign_only / not_found
			// Visible: most launchers silence Cobra, so a plain error here
			// exited 1 with no output in a dashboard terminal. The message is
			// our own FormatVerdict text (the same text the off-path case
			// already prints), not an arbitrary internal error.
			msg := strings.TrimRight(toolresolve.FormatVerdict(tool, pathFlag, r), "\n")
			return "", newVisibleLauncherError(errors.New(msg), msg)
		}
	}

	// Step 4: defensive fallback — no grounded Binary row (should not happen).
	resolved, err := exec.LookPath(tool)
	if err != nil {
		return "", fmt.Errorf("locate %s binary: %w (set %s)", tool, err, pathFlag)
	}
	return resolved, nil
}

// applyBaseURLEnv injects each key=value in inject into a copy of parent,
// UNLESS the user already exported a non-empty value for that key — theirs
// always wins (a launcher never clobbers explicit env state). Existing
// entries keep their order and value; newly-injected keys are appended in
// sorted order for determinism. Returns the merged env, the keys actually
// injected (applied), and the keys kept from the user (presets).
//
// It is the single env seam for every base-URL launcher: pure, no I/O, fully
// table-testable. Callers must only ever pass base-URL (and non-secret)
// fields here — never an API key.
func applyBaseURLEnv(parent []string, inject map[string]string) (env, applied, presets []string) {
	existing := make(map[string]string, len(parent))
	for _, kv := range parent {
		if i := strings.IndexByte(kv, '='); i > 0 {
			existing[kv[:i]] = kv[i+1:]
		}
	}

	out := make([]string, len(parent))
	copy(out, parent)

	toAppend := make([]string, 0, len(inject))
	for k, v := range inject {
		if cur, ok := existing[k]; ok && cur != "" {
			presets = append(presets, k)
			continue
		}
		toAppend = append(toAppend, k)
		_ = v
	}
	sort.Strings(toAppend)
	for _, k := range toAppend {
		out = append(out, k+"="+inject[k])
		applied = append(applied, k)
	}
	sort.Strings(presets)
	return out, applied, presets
}

// envValue returns the value of key in an env slice ("KEY=value" entries),
// or "" if absent. When a key appears more than once the last wins (exec
// semantics).
func envValue(env []string, key string) string {
	val := ""
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 && kv[:i] == key {
			val = kv[i+1:]
		}
	}
	return val
}

// lookupEnvValue returns the value of key in an env slice ("KEY=value" entries)
// AND whether the key is PRESENT at all — the os.LookupEnv distinction envValue
// cannot make. It lets a profile-forwarding helper distinguish an absent key
// (forward nothing, the daemon's inherited value stands) from one explicitly set
// to empty (`KEY=`, forward `KEY=` so the child resets to the tool's DEFAULT
// profile) — F3. When a key appears more than once the last wins (exec
// semantics), matching how the child resolves duplicate env entries.
func lookupEnvValue(env []string, key string) (string, bool) {
	val := ""
	found := false
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 && kv[:i] == key {
			val = kv[i+1:]
			found = true
		}
	}
	return val, found
}

// envLauncherSpec configures a simple base-URL-env launcher (the opencode
// shape). Every field in env is a base-URL or non-secret routing hint —
// NEVER an API key.
type envLauncherSpec struct {
	tool       string            // stderr label, e.g. "cline-cli"
	bin        string            // resolved binary path
	args       []string          // forwarded argv
	configPath string            // launcher's --config override; used by cold budget admission
	proxyURL   string            // resolved proxy base URL (for the reachability note)
	env        map[string]string // base-URL (+ non-secret) vars to inject when unset
	// dir is the child's working directory. Empty inherits the caller's
	// cwd (the default). A `--continue-from` launch sets it to the source
	// session's translated project root (via launchDir) so a cross-OS
	// continuation lands in the real project folder, not the daemon's cwd.
	dir string
	// dbPath is the observer DB path (cfg.Observer.DBPath). When set, the
	// launcher records a launch_seeds row for the spawned child so the
	// daemon's correlation sweep can bind it to the ingested session
	// directly (migration 086) instead of falling through to lazy cwd
	// correlation. Best-effort; empty disables seeding.
	dbPath string
	// seedTool overrides the tool name recorded in the launch seed. Empty
	// records spec.tool. Set it when the stderr label differs from the
	// canonical adapter name the watcher stores in sessions.tool (e.g. the
	// gemini launcher labels "gemini" but stores "gemini-cli") — the sweep's
	// matcher requires exact equality with sessions.tool.
	seedTool string
	// routeFile, when set, re-reads the base URL of the provider entry the
	// launcher selected in the tool's own config file (a config-file route,
	// whose capability has no base-URL env var). It is the launch evidence
	// the managed budget check uses for such a route (T-208). ok=false: the
	// file or entry could not be read.
	routeFile func() (baseURL string, ok bool)
	// routeArgs are the operator's own forwarded arguments, without the
	// provider selection the launcher prepended (which would otherwise read
	// as an operator-supplied selector). Nil means args.
	routeArgs []string
	// unrouted marks a launch the caller has already told the operator is NOT
	// going through the proxy (cline-cli keeping the operator's own
	// non-proxied provider). It suppresses the routing/unreachable note,
	// which would otherwise claim a route that does not exist. Zero value =
	// unchanged behaviour.
	unrouted bool
	// routeCaveat, when set, is printed right after the routing line of a
	// routed launch (gatedRoute.caveat): a lane the route gate cannot see that
	// still bypasses the proxy, so "routing via" never over-claims.
	routeCaveat string
	stderr      io.Writer
}

// printRouteCaveat prints spec.routeCaveat (one line) when set.
func printRouteCaveat(spec envLauncherSpec) {
	if c := strings.TrimSpace(spec.routeCaveat); c != "" {
		fmt.Fprintln(spec.stderr, c)
	}
}

// runEnvLauncher injects the spec's base-URL env vars (user values win),
// prints a one-line routing/preset/unreachable note, then execs the tool and
// forwards its exit code (same shape as `observer run`). Pure exec — it does
// not consult or set any secret.
func runEnvLauncher(spec envLauncherSpec) error {
	// P6 item 5: refuse a bare launch of an org-disallowed tool (node.features
	// tools.disallow), read from the node-local LKG sidecar. seedTool is the
	// exact integration-registry key the disallow list uses; fall back to the
	// stderr label. Fail-open on any sidecar-read issue.
	gateTool := spec.seedTool
	if gateTool == "" {
		gateTool = spec.tool
	}
	if err := refuseIfToolDisallowedDB(spec.dbPath, gateTool, spec.stderr); err != nil {
		return err
	}
	// A build without capture.proxy (lane MP-L1L, T-715, D-514): with nothing
	// serving the proxy port, launch unrouted with the one reason rather than
	// inject a base URL that points the tool at a dead port. A config-file
	// route drops the provider selection the launcher prepended, so the tool
	// runs on the operator's own default provider.
	if !spec.unrouted && proxyNotInBuild() && !proxyReachable(spec.proxyURL, 250*time.Millisecond) {
		if notice, ok := proxyNotInBuildNotice(spec.tool); ok {
			fmt.Fprintln(spec.stderr, notice)
		}
		spec.env, spec.unrouted, spec.routeFile = nil, true, nil
		if spec.routeArgs != nil {
			spec.args = spec.routeArgs
		}
	}
	// Layer the rename-safe agent runtime-dir env under the base-URL env, so
	// an SMB/NFS HOME can't break the agent's provider-dependency install
	// (adapter-agnostic; no-op unless [launch].agent_runtime_dir is set).
	childEnv, applied, presets := applyBaseURLEnv(applyAgentRuntimeEnv(os.Environ(), agentRuntimeDir()), spec.env)
	// CLI-8 (D13): on a managed node whose organization owns the routes, a
	// preset that points elsewhere is rewritten to the proxy for this run.
	var orgRewrote []string
	childEnv, presets, orgRewrote = applyManagedPresetRewrite(context.Background(), spec.stderr, spec.tool, spec.configPath, spec.proxyURL, childEnv, spec.env, presets, spec.unrouted)
	applied = append(applied, orgRewrote...)
	// PATH parity (audit DI-04b): the tool was RESOLVED over the merged PATH
	// (process + login shell), so it must EXECUTE with that PATH too — an
	// `#!/usr/bin/env node` shim found under a login-only npm prefix otherwise
	// starts and dies at exit 127. Additive and last in the chain so it sees the
	// final block; a no-op when there are no login-only dirs (the usual case for
	// a launcher run from the operator's own shell).
	childEnv = applyChildPATH(childEnv, daemonLoginPathDirs(), spec.bin)
	evidence := envBudgetLaunchEvidence(gateTool, spec.proxyURL, spec.env, childEnv, spec.args)
	if evidence.Route == budgetLaunchRouteUnknown && spec.routeFile != nil && !spec.unrouted {
		routeArgs := spec.routeArgs
		if routeArgs == nil {
			routeArgs = spec.args
		}
		evidence = fileRouteBudgetLaunchEvidence(gateTool, spec.proxyURL, spec.routeFile, routeArgs)
	}
	// CLI-7: the tool's own .env or config file can outrank the base URL set
	// here; then the route proves nothing and "routing via" would over-claim.
	var shadows []string
	if !spec.unrouted {
		shadows = launchRouteShadows(gateTool, spec.args, spec.dir, childEnv)
	}
	if len(shadows) > 0 {
		evidence = budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	}
	evidence.Executable = spec.bin
	evidence.Arguments = spec.args
	evidence.OrgRewrote = orgRewrote
	if err := enforceBudgetControlledLaunch(context.Background(), spec.configPath, gateTool, evidence); err != nil {
		return err
	}

	for _, k := range presets {
		fmt.Fprintf(spec.stderr,
			"observer %s: %s already set in env; using yours.\n", spec.tool, k)
	}

	switch {
	case spec.unrouted:
		// The caller already printed its own "not routed" note.
	case len(shadows) > 0:
		fmt.Fprintln(spec.stderr, routeShadowNotice(spec.tool, shadows))
	case !proxyReachable(spec.proxyURL, 250*time.Millisecond):
		fmt.Fprintln(spec.stderr, proxyUnreachableNotice(spec.tool, spec.proxyURL, runningAsDaemonChild()))
	case len(applied) > 0:
		fmt.Fprintf(spec.stderr,
			"observer %s: routing via %s (set %s)\n",
			spec.tool, redactRouteURL(spec.proxyURL), strings.Join(applied, ", "))
		printRouteCaveat(spec)
	default:
		fmt.Fprintf(spec.stderr, "observer %s: routing via %s\n", spec.tool, redactRouteURL(spec.proxyURL))
		printRouteCaveat(spec)
	}

	// T-536: mark the run's own telemetry as proxied only when every
	// base-URL variable is ours (a preset user value may point elsewhere).
	if !spec.unrouted && len(presets) == 0 && len(shadows) == 0 {
		childEnv = withOTelRouteMarker(childEnv, gateTool)
	}
	child := exec.Command(spec.bin, spec.args...) //nolint:gosec // user-launched tool, args are theirs
	child.Env = scrubOOBEnv(childEnv)             // strip the trusted OOB channel env
	child.Dir = spec.dir                          // "" inherits the caller's cwd (default)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	seedTool := spec.tool
	if spec.seedTool != "" {
		seedTool = spec.seedTool
	}
	discovery := prepareGenericDiscovery(context.Background(), seedTool, spec.dir)
	if err := child.Start(); err != nil {
		noteBoxToolLaunch(spec.stderr, spec.tool, spec.bin, spec.args, err)
		return fmt.Errorf("exec %s: %w", spec.tool, err)
	}
	// Direct process attribution (migration 086): record the child pid now
	// that Start has made it knowable; retract the seed when the child is
	// reaped. Best-effort both ways — a seeding failure never affects the
	// launch (see cmd/observer/launchseed.go).
	recordLaunchSeed(spec.dbPath, seedTool, spec.dir, child.Process.Pid, spec.stderr)
	// Best-effort generic post-launch session discovery (WS-DISCOVERY): a
	// no-op unless the trusted OOB channel is active AND seedTool resolves to
	// an adapter that declares session-file watch roots. seedTool (not
	// spec.tool) is used deliberately — it is the exact adapter-registry key
	// the launch seed itself already resolved to (e.g. gemini's launcher
	// label "gemini" vs its registered/stored tool name "gemini-cli").
	// Cancel the instant the child exits so a window cut short by exit never
	// announces a candidate that only looked unique because the scan stopped
	// early.
	discoverCancel := discovery.start()
	if discoverCancel != nil {
		defer discoverCancel()
	}
	if err := child.Wait(); err != nil {
		noteBoxToolLaunch(spec.stderr, spec.tool, spec.bin, spec.args, err)
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitErr(ee.ExitCode())
		}
		return fmt.Errorf("exec %s: %w", spec.tool, err)
	}
	return nil
}

// routeTokenPrefix is the path prefix a sandbox's token-scoped model proxy
// base URL carries its run token under (sandboxmxc.BaseURL:
// http://127.0.0.1:<port>/t/<token>).
const routeTokenPrefix = "/t/"

// redactRouteURL masks the run token of a token-scoped base URL before a
// "routing via" line prints it (Windows 11 Pro run 3, 2026-10-22: the token
// reached terminal scrollback and pasted reports). The first path segment
// after /t/ becomes <redacted>; any other URL, or one that does not parse,
// prints as it is. It runs on every OS: the line is the same everywhere.
func redactRouteURL(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" || !strings.HasPrefix(p.EscapedPath(), routeTokenPrefix) {
		return u
	}
	at := strings.Index(u, p.Host)
	if at < 0 {
		return u
	}
	head := u[:at+len(p.Host)]
	rest := u[len(head):]
	if !strings.HasPrefix(rest, routeTokenPrefix) {
		return u
	}
	rest = rest[len(routeTokenPrefix):]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	if end == 0 {
		return u
	}
	return head + routeTokenPrefix + "<redacted>" + rest[end:]
}
