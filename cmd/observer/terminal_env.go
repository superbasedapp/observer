package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// terminal_env.go holds the launcher environment contract every build
// shares (lane MP-L1K, T-715, moved out of terminal_launch.go): the trusted
// out-of-band channel's env names and the scrub that keeps them from a tool
// child, the daemon-child marker, the daemon config path the launchers
// forward, and the internal-env filter. A build without the terminals
// component still scrubs a spoofed or inherited channel variable from every
// child it starts.

// Environment variables the daemon injects so the launcher wrapper (F3) can
// find and authenticate the OOB channel. The tool child never inherits the FD
// once F3 sets close-on-exec; F1 only allocates + drains it.
const (
	envOOBFD   = "OBSERVER_OOB_FD"   // inherited FD number (3+)
	envOOBAuth = "OBSERVER_OOB_AUTH" // per-session Hello auth secret
	envOOBCorr = "OBSERVER_OOB_CORR" // run correlation nonce to echo
	envOOBTool = "OBSERVER_OOB_TOOL" // target tool name
	// envOOBRun carries the terminal run id the daemon minted BEFORE spawning
	// this launcher. It was informational until task 9f; it is now also the
	// deterministic key the launcher records on its launch_seeds row
	// (migration 091), so the daemon sweep can bind the child to its session
	// by JOIN instead of by the cwd/tool/time heuristic. The launcher reads it
	// only while the trusted OOB channel is authenticated - see
	// launchSeedRunID for why that guard is what makes an INHERITED variable
	// safe to treat as identity.
	envOOBRun = "OBSERVER_OOB_RUN"
)

// oobChildEnvKeys are the internal trusted-OOB-channel env vars the daemon
// injects into a launcher's OWN process so it can find and authenticate the F3
// channel. They must NEVER reach the untrusted tool child (nor the hooks and
// subprocesses it spawns): OBSERVER_OOB_AUTH is the per-session secret that
// authenticates writes to the trusted channel, and the fd/corr/run values are
// the daemon's private correlation state. The fd itself is already close-on-exec
// (oob_emit_unix.go); scrubOOBEnv closes the matching ENV leak. The launcher
// reads every one of these from its OWN process env (os.Getenv, before it builds
// the child env - emitOOBLaunchHello in main.go, launchSeedRunID), so removing
// them from the child env costs the launcher nothing. OBSERVER_DAEMON_CHILD is
// deliberately absent: the child legitimately reads it (runningAsDaemonChild /
// decideAttach anti-recursion), so it survives the scrub.
var oobChildEnvKeys = []string{envOOBFD, envOOBAuth, envOOBCorr, envOOBTool, envOOBRun}

// scrubOOBEnv returns a copy of env with every trusted-OOB-channel variable
// (oobChildEnvKeys) removed, so a launcher can hand the result to the untrusted
// tool child without leaking the channel's auth secret or correlation state
// (session-attach design §2.1b). Entries match on the KEY (text before the first
// '='), so both `OBSERVER_OOB_AUTH=x` and a bare `OBSERVER_OOB_AUTH` are dropped.
// Every other entry - including OBSERVER_DAEMON_CHILD, which the child uses - is
// preserved in original order. env is never mutated; a nil/empty env round-trips.
func scrubOOBEnv(env []string) []string {
	if len(env) == 0 {
		return env
	}
	drop := make(map[string]struct{}, len(oobChildEnvKeys))
	for _, k := range oobChildEnvKeys {
		drop[k] = struct{}{}
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if _, bad := drop[key]; bad {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// envDaemonChild is the INFALLIBLE marker the daemon sets in EVERY child env it
// spawns. The two agent-launch paths (attach-spawn + dashboard terminal) funnel
// through launchChildEnv, and the ONE non-termsvc path - a SpecSetup session
// (CreateSetup), which bypasses this launcher - carries it via setupChildEnv, so
// the "every daemon child carries the marker" invariant holds tree-wide (finding:
// marker completeness). Unlike the OOB channel (which is best-effort - a missing
// FD or a failed Hello leaves oobChannelActive() false), this env var is set
// unconditionally, so a daemon-owned inner launcher whose OOB channel died still
// recognizes itself as a daemon child and refuses to re-attach. decideAttach
// checks it FIRST as the primary anti-recursion gate (review finding H1);
// oobChannelActive() stays a belt-and-suspenders secondary row.
const envDaemonChild = "OBSERVER_DAEMON_CHILD"

// runningAsDaemonChild reports whether THIS process was spawned by the daemon's
// terminal launcher (the env marker is present). It is the infallible input
// decideAttach consults before the best-effort OOB probe. Reading the env keeps
// decideAttach pure - the launcher passes this bool in like the reachability
// probe.
func runningAsDaemonChild() bool {
	return os.Getenv(envDaemonChild) == "1"
}

// daemonConfigPathSetting holds the EXPLICIT `--config <path>` the daemon was
// started with, so every `observer <verb>` child the terminal launcher spawns
// resolves the SAME config file the daemon did. Empty - the default, and the
// value on every install that never passes the flag - means the daemon resolved
// the built-in default path, which a child resolves identically; nothing is then
// appended and a launch's argv stays byte-identical to today (CLAUDE.md #6).
//
// Why it exists (Q1 first-launch probe, 2026-09-02): a dashboard-launched child
// re-derived its config from the DEFAULT path. On a daemon started with
// `--config <custom>` that meant the child routed at the built-in :8820 instead
// of the config's `[proxy] port`, and opened `~/.observer/observer.db` instead of
// the config's `db_path` - silently, while advising the operator to "start it
// with `observer start`" although the daemon that spawned the terminal was
// running the whole time.
//
// An atomic pointer, not a plain string: it is written once during daemon
// startup (setDaemonConfigPath) and read afterwards from every launch goroutine.
var daemonConfigPathSetting atomic.Pointer[string]

// setDaemonConfigPath records the daemon's explicit `--config` path so
// daemon-spawned launcher children inherit it. Called ONCE from the daemon's
// start path with the raw flag value; an empty path clears the setting (the
// daemon uses the default config location and a child resolves the same one).
// Safe to call before any terminal stack exists - the launcher reads it per
// spawn, not at construction.
//
// The path is ABSOLUTIZED against the daemon's own working directory, because
// the child's is a different one: a fresh launch into a project root spawns with
// cmd.Dir set there, so a relative `--config observer.toml` handed on verbatim
// would be resolved against the PROJECT, not against the daemon's cwd where the
// operator typed it. Fail-open - an unresolvable path is propagated as given
// rather than dropped, so the child reports the same honest error the operator
// would see running the flag by hand.
func setDaemonConfigPath(path string) {
	p := strings.TrimSpace(path)
	if p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	daemonConfigPathSetting.Store(&p)
}

// daemonConfigPath returns the daemon's explicit `--config` path, or "" when the
// daemon was started without the flag (or before setDaemonConfigPath ran, which
// is the honest zero: propagate nothing rather than guess a path).
func daemonConfigPath() string {
	if p := daemonConfigPathSetting.Load(); p != nil {
		return *p
	}
	return ""
}

// isInternalChildEnv reports whether an env entry is one the daemon manages for
// its children (the OOB channel vars or the daemon-child marker) and must strip
// from any inherited/caller-supplied env before re-adding its own fresh copy -
// so a nested launch can never inherit a stale channel or spoof the marker.
func isInternalChildEnv(kv string) bool {
	return strings.HasPrefix(kv, "OBSERVER_OOB_") ||
		strings.HasPrefix(kv, envDaemonChild+"=") ||
		// B9 (U9 finding): the sandbox marker is daemon-set on the child inside
		// the boundary and must never be spoofable in via inherited/caller env.
		strings.HasPrefix(kv, sandboxEnvMarker+"=") ||
		// The source repository a sandboxed clone's trust check honours
		// accepts for (launch_trust.go) is daemon-set the same way.
		strings.HasPrefix(kv, repoTrustSourceEnv+"=") ||
		strings.HasPrefix(kv, repoTrustBenchmarkSourceEnv+"=") ||
		strings.HasPrefix(kv, repoTrustBenchmarkMarkerEnv+"=") ||
		// The checked-launch marker names one launch's repository; a child
		// gets it only from the launch that checked it (launch_trust.go).
		strings.HasPrefix(kv, repoTrustCheckedEnv+"=")
}
