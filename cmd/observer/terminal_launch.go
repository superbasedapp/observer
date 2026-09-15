package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termoob"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_launch.go holds the cmd-side adapters the terminal application
// service (internal/termsvc) depends on: the persistence recorder over
// internal/store, and the PTY launcher over internal/termsession that also
// allocates + drains the trusted out-of-band control channel (internal/termoob,
// plan §2.1b / F1). termsvc speaks internal/termrun's pure types; these
// adapters translate to the store's row types and to the termsession spec.

// termRunRecorder persists run identity + correlations for termsvc.
type termRunRecorder struct{ st *store.Store }

func (r termRunRecorder) RecordRun(ctx context.Context, run termrun.Run) error {
	return r.st.InsertTerminalRun(ctx, store.TerminalRun{
		RunID:                run.RunID,
		Tool:                 run.Tool,
		Kind:                 string(run.Kind),
		SourceSessionID:      run.SourceSessionID,
		ProjectRootHash:      run.ProjectRootHash,
		CorrelationTokenHash: run.CorrelationTokenHash,
		LaunchedAt:           run.LaunchedAt,
	})
}

func (r termRunRecorder) EndRun(ctx context.Context, runID string, endedAt time.Time, exitCode int, reason string) error {
	return r.st.EndTerminalRun(ctx, runID, endedAt, exitCode, reason)
}

func (r termRunRecorder) RecordCorrelation(ctx context.Context, c termrun.Correlation) error {
	return r.st.UpsertCorrelation(ctx, store.TerminalCorrelation{
		RunID:      c.RunID,
		SessionID:  c.SessionID,
		Confidence: c.Confidence,
		Source:     string(c.Source),
		ObservedAt: c.ObservedAt,
	})
}

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
	// only while the trusted OOB channel is authenticated — see
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
// the child env — emitOOBLaunchHello in main.go, launchSeedRunID), so removing
// them from the child env costs the launcher nothing. OBSERVER_DAEMON_CHILD is
// deliberately absent: the child legitimately reads it (runningAsDaemonChild /
// decideAttach anti-recursion), so it survives the scrub.
var oobChildEnvKeys = []string{envOOBFD, envOOBAuth, envOOBCorr, envOOBTool, envOOBRun}

// scrubOOBEnv returns a copy of env with every trusted-OOB-channel variable
// (oobChildEnvKeys) removed, so a launcher can hand the result to the untrusted
// tool child without leaking the channel's auth secret or correlation state
// (session-attach design §2.1b). Entries match on the KEY (text before the first
// '='), so both `OBSERVER_OOB_AUTH=x` and a bare `OBSERVER_OOB_AUTH` are dropped.
// Every other entry — including OBSERVER_DAEMON_CHILD, which the child uses — is
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
// through launchChildEnv, and the ONE non-termsvc path — a SpecSetup session
// (CreateSetup), which bypasses this launcher — carries it via setupChildEnv, so
// the "every daemon child carries the marker" invariant holds tree-wide (finding:
// marker completeness). Unlike the OOB channel (which is best-effort — a missing
// FD or a failed Hello leaves oobChannelActive() false), this env var is set
// unconditionally, so a daemon-owned inner launcher whose OOB channel died still
// recognizes itself as a daemon child and refuses to re-attach. decideAttach
// checks it FIRST as the primary anti-recursion gate (review finding H1);
// oobChannelActive() stays a belt-and-suspenders secondary row.
const envDaemonChild = "OBSERVER_DAEMON_CHILD"

// runningAsDaemonChild reports whether THIS process was spawned by the daemon's
// terminal launcher (the env marker is present). It is the infallible input
// decideAttach consults before the best-effort OOB probe. Reading the env keeps
// decideAttach pure — the launcher passes this bool in like the reachability
// probe.
func runningAsDaemonChild() bool {
	return os.Getenv(envDaemonChild) == "1"
}

// daemonConfigPathSetting holds the EXPLICIT `--config <path>` the daemon was
// started with, so every `observer <verb>` child the terminal launcher spawns
// resolves the SAME config file the daemon did. Empty — the default, and the
// value on every install that never passes the flag — means the daemon resolved
// the built-in default path, which a child resolves identically; nothing is then
// appended and a launch's argv stays byte-identical to today (CLAUDE.md #6).
//
// Why it exists (Q1 first-launch probe, 2026-09-02): a dashboard-launched child
// re-derived its config from the DEFAULT path. On a daemon started with
// `--config <custom>` that meant the child routed at the built-in :8820 instead
// of the config's `[proxy] port`, and opened `~/.observer/observer.db` instead of
// the config's `db_path` — silently, while advising the operator to "start it
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
// Safe to call before any terminal stack exists — the launcher reads it per
// spawn, not at construction.
//
// The path is ABSOLUTIZED against the daemon's own working directory, because
// the child's is a different one: a fresh launch into a project root spawns with
// cmd.Dir set there, so a relative `--config observer.toml` handed on verbatim
// would be resolved against the PROJECT, not against the daemon's cwd where the
// operator typed it. Fail-open — an unresolvable path is propagated as given
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

// configArgAlreadyPresent reports whether an argv slice already expresses its own
// `--config`. It stops at the first bare `--`: everything after that separator
// belongs to the launched TOOL, so a tool's own `--config` must not suppress the
// daemon's (the two flags address different programs).
func configArgAlreadyPresent(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--config" || strings.HasPrefix(a, "--config=") {
			return true
		}
	}
	return false
}

// launchConfigArgs returns the `--config <path>` tokens a daemon-spawned
// `observer <verb>` launch should carry, or nil when it should carry none.
//
// The decision is capability-shaped, never tool-shaped (CLAUDE.md #3): EVERY
// launcher verb in the capability registry accepts `--config` (verified against
// the built binary's own flag sets, 2026-09-03), so the only two questions are
// whether the daemon HAS an explicit path to propagate and whether the caller
// already expressed one. The attach path composes its own `--proxy`/`--config`
// overrides into ExtraArgs; those win, because they are the CLI client's
// deliberate per-launch intent rather than the daemon-wide default.
func launchConfigArgs(cfgPath string, extraArgs []string) []string {
	if cfgPath == "" || configArgAlreadyPresent(extraArgs) {
		return nil
	}
	return []string{"--config", cfgPath}
}

// launchExtraArgs composes the ExtraArgs a spawn hands termsession: the daemon's
// `--config` propagation PREFIXED to the caller's own tokens.
//
// Prefixed, never appended: ExtraArgs can end in a bare `--` remainder destined
// for the tool (`-- --model X`) or a native resume tail, and a flag appended past
// that separator would be handed to the TOOL instead of to `observer <verb>`.
// The prefix lands immediately after the subcommand (and after a handoff's
// `--continue-from <id>`), which every launcher's flag parser accepts.
//
// Shell and SSH launches are unaffected by construction, not by a branch here:
// termsession.Spec.argv() ignores ExtraArgs entirely for SpecShell/SpecSSH, so
// the `shell` pseudo-tool can never receive an `observer` flag.
func launchExtraArgs(extraArgs []string) []string {
	add := launchConfigArgs(daemonConfigPath(), extraArgs)
	if len(add) == 0 {
		return extraArgs
	}
	return append(add, extraArgs...)
}

// ptyLauncher implements termsvc.Launcher over *termsession.Manager. It
// allocates the trusted OOB control-channel pipe, hands the child the write end
// at fd 3 (via ExtraFiles), keeps + drains the read end on a goroutine, and
// builds the server-derived termsession spec.
type ptyLauncher struct {
	mgr     *termsession.Manager
	binPath string
	feed    *termfeed.Feed
	logger  *slog.Logger
	// correlate is the production run->session correlation seam (P2-1). When the
	// launcher wrapper announces the child's agent session id on the TRUSTED OOB
	// channel (termoob.TypeSession), drainOOB records it here at oob confidence.
	// Wired to termsvc.Service.Correlate in buildTerminalStack; nil disables
	// correlation (the drain still runs — it just doesn't establish links).
	correlate func(ctx context.Context, runID, sessionID string, source termrun.Source, at time.Time) error
}

// argvModeTable maps a run KIND onto the termsession argv SHAPE (CLAUDE.md #5 —
// a data table, not an if-ladder). Fresh, attach, AND resume all launch a BARE
// `observer <sub>` base: a fresh launch has no continuation, an attach launch
// carries only routing escape-hatch ExtraArgs, and a resume's native `--resume
// <id>` tail rides in ExtraArgs (so it must NOT get the handoff --continue-from
// prefix — claude/codex reject `--continue-from … --resume …` together, F2).
// Only a handoff launch takes --continue-from.
var argvModeTable = map[termrun.Kind]termsession.ArgvMode{
	termrun.KindFresh:   termsession.ArgvModeFresh,
	termrun.KindAttach:  termsession.ArgvModeFresh,
	termrun.KindResume:  termsession.ArgvModeFresh,
	termrun.KindHandoff: termsession.ArgvModeHandoff,
}

// argvModeForKind resolves a run kind to its argv shape. An unlisted kind falls
// back to ArgvModeHandoff (the zero value), the more restrictive default — it
// requires a SessionID, so a mis-mapped kind fails closed at Create rather than
// silently launching a bare agent.
func argvModeForKind(kind termrun.Kind) termsession.ArgvMode {
	return argvModeTable[kind]
}

// resolveShellArgv (the server-derived SpecShell argv: the daemon's own $SHELL
// with a per-OS fallback ladder) lives in terminal_launch_shell.go, where the
// OS and its I/O are injected so both ladders are table-tested.

// Spawn starts a PTY-backed launcher for a validated request and returns its
// opaque handle. It is the single place the OOB FD is allocated: after the
// child is spawned the daemon closes its own copy of the write end so the read
// end reports EOF when the child exits, and a goroutine drains framed OOB
// signals (which the launcher wrapper begins emitting in F3).
func (l *ptyLauncher) Spawn(req termsvc.LaunchRequest) (string, error) {
	authToken, err := termoob.NewSessionToken()
	if err != nil {
		return "", err
	}
	oobRead, oobWrite, err := os.Pipe()
	if err != nil {
		return "", err
	}

	spec := termsession.Spec{
		BinPath:    l.binPath,
		Subcommand: req.Subcommand,
		// The run KIND selects the argv SHAPE through argvModeForKind (below): a
		// fresh, attach, OR native-resume launch is a bare `observer <sub>` base
		// (a resume's `--resume <id>` tail rides in ExtraArgs), and only a
		// handoff launch takes the --continue-from argv. Table, not a boolean —
		// a resume is NOT "fresh", it just shares the fresh base argv (F2).
		ArgvMode:    argvModeForKind(req.Kind),
		SessionID:   req.SessionID,
		Carry:       req.Carry,
		FromMessage: req.FromMessage,
		Rows:        req.Rows,
		Cols:        req.Cols,
		Dir:         req.Dir,
		Env:         launchChildEnv(req, authToken),
		ExtraFiles:  []*os.File{oobWrite},
		// Attach launches carry the CLI client's allow-listed argv (routing
		// escape hatch + `--` tool remainder) so the inner `observer <sub>`
		// self-configures exactly like a bare launch (B2/B3). Dashboard
		// fresh/handoff launches carry none of their own — but EVERY launch
		// gets the daemon's `--config` propagation prefixed here
		// (launchExtraArgs), so a child resolves the same proxy port and DB
		// the daemon did instead of re-deriving them from the default path.
		ExtraArgs: launchExtraArgs(req.ExtraArgs),
		// B9 Seam-B application (plan §1/§3/D2): the bwrap wrapper prefix the
		// Sandboxer resolved. termsession.Spec.argv() prepends it before
		// [BinPath, Subcommand, ...ExtraArgs], so the whole inner `observer
		// <verb>` launch runs inside the isolation boundary. Empty for every
		// non-sandboxed launch → argv byte-identical to today.
		WrapArgv: req.WrapArgv,
	}
	if len(req.SSHArgv) > 0 {
		// An outbound SSH remote-system session (plan §2). Like SpecShell it
		// runs no `observer <sub>` at all — SpecSSH carries its own
		// server-derived argv, composed by internal/sshprofile from an
		// operator-authored config profile. It deliberately does NOT take
		// WrapArgv: bwrap would blind the known_hosts / key file / agent
		// socket ssh needs (see termsession.SpecSSH).
		spec.Kind = termsession.SpecSSH
		spec.SSHArgv = req.SSHArgv
	} else if req.IsShell {
		// A plain-shell fresh launch runs no `observer <sub>` at all — SpecShell
		// carries its own server-derived argv (resolveShellArgv), ignoring
		// BinPath/Subcommand/ArgvMode/SessionID entirely (see Spec.argv()).
		spec.Kind = termsession.SpecShell
		spec.ShellArgv = resolveShellArgv()
	}
	handle, cerr := l.mgr.Create(spec)
	// Close the daemon's copy of the write end unconditionally: the child has
	// its own dup (on success), and on failure it frees the pipe.
	_ = oobWrite.Close()
	if cerr != nil {
		_ = oobRead.Close()
		return "", cerr
	}
	go l.drainOOB(req.RunID, req.Tool, oobRead, authToken)
	l.auditEnv(req, spec.Env)
	return handle, nil
}

// launchChildEnv builds the child environment: the daemon env with any stale
// OOB variables stripped (defence — a nested launch must never inherit a
// parent's channel), plus the request's ExtraEnv, plus this launch's fresh OOB
// variables.
//
// The ExtraEnv append is load-bearing for the attach path: LaunchRequest.
// ExtraEnv carries the attach launcher's proxy-routing variables, and dropping
// it here (the pre-2026-07-19 bug) silently voided them. ExtraEnv is layered
// AFTER the inherited env (so an explicit routing var the launcher chose wins
// over a stale inherited one) and BEFORE the OOB vars (which are internal and
// must never be overridden by a caller-supplied entry).
//
// NOTE (deviation from a strict allow-list, plan §F1): a coding agent
// legitimately needs the operator's provider env (API keys it uses to talk to
// its model), so a hard allow-list would break every launched tool. The
// daemon, when started via `observer start`, runs with the user's own shell
// env (observer keeps its own secrets in config files, not env), so the
// residual exposure is the user's own env — which the agent needs anyway. We
// therefore strip only the internal OOB channel variables and emit a per-launch
// env audit line. A tighter policy is a documented follow-up.
//
// CREDENTIAL-BEARING: req.ExtraEnv may include the caller's forwarded provider-
// credential values (forwardAuthEnv, gated by [terminal.attach].forward_auth_env)
// layered last-wins over the inherited env. Never log or persist these values —
// the env audit line (l.auditEnv) records key NAMES + counts only, never values.
func launchChildEnv(req termsvc.LaunchRequest, authToken string) []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+len(req.ExtraEnv)+6)
	for _, kv := range parent {
		if isInternalChildEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	// Caller-supplied extra env (attach proxy-routing vars). Defensively drop
	// any OBSERVER_OOB_ / OBSERVER_DAEMON_CHILD entry so the internal channel and
	// the daemon-child marker can't be spoofed in by a caller.
	for _, kv := range req.ExtraEnv {
		if isInternalChildEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	// PATH parity (audit DI-04b): the child EXECUTES with the merged PATH the
	// daemon RESOLVED the tool on, so a binary that was only reachable through
	// the operator's login shell can actually run — an `#!/usr/bin/env node`
	// shim otherwise starts fine and dies at exit 127. Layered AFTER ExtraEnv
	// (a caller that set PATH explicitly still gets its dirs kept, widened) and
	// BEFORE the internal OOB vars. Strictly additive: every daemon PATH entry
	// survives in order, and a launch with nothing grounded to add is a no-op.
	out = applyChildPATH(out, launchLoginPathDirs(req.LoginPathDirs), req.BinPath)
	out = append(
		out,
		// Infallible daemon-child marker (H1): set on EVERY spawned child so an
		// inner launcher never re-attaches even when its OOB channel is dead.
		envDaemonChild+"=1",
		envOOBFD+"=3", // ExtraFiles[0] → fd 3 in the child
		envOOBAuth+"="+authToken,
		envOOBCorr+"="+req.CorrelationToken,
		envOOBTool+"="+req.Tool,
		envOOBRun+"="+req.RunID,
	)
	// B9 (plan §6): when this launch runs inside the bwrap boundary, stamp the
	// sandbox marker so the hook lane can honestly set Event.Caps.Sandboxed. It
	// is set here AND stripped from inherited/caller env by isInternalChildEnv,
	// so a user env can never spoof OBSERVER_SANDBOX=1 into a non-sandboxed
	// child (U9 finding). Never set on an unsandboxed launch → honest zero.
	if req.Sandboxed {
		out = append(out, sandbox.EnvMarker+"=1")
	}
	// Windows env keys are case-insensitive, so the layering above can leave
	// both `Path=` (inherited) and `PATH=` (ExtraEnv) in one block and "last
	// wins" stops being true. Branching on runtime.GOOS here is a PLATFORM
	// CAPABILITY test (how the OS keys an environment block), not a tool or
	// caller identity — see dedupEnvWindows.
	if runtime.GOOS == "windows" {
		return dedupEnvWindows(out)
	}
	return out
}

// isInternalChildEnv reports whether an env entry is one the daemon manages for
// its children (the OOB channel vars or the daemon-child marker) and must strip
// from any inherited/caller-supplied env before re-adding its own fresh copy —
// so a nested launch can never inherit a stale channel or spoof the marker.
func isInternalChildEnv(kv string) bool {
	return strings.HasPrefix(kv, "OBSERVER_OOB_") ||
		strings.HasPrefix(kv, envDaemonChild+"=") ||
		// B9 (U9 finding): the sandbox marker is daemon-set on the child inside
		// the boundary and must never be spoofable in via inherited/caller env.
		strings.HasPrefix(kv, sandbox.EnvMarker+"=")
}

// setupChildEnv builds the environment for a SETUP session (CreateSetup) — the
// one daemon-child path that does NOT go through termsvc/ptyLauncher, so it
// bypasses launchChildEnv. It is the daemon's own env (a setup command like the
// Tailscale operator grant needs a sane PATH/TERM), with any internal child vars
// stripped (defence against spoofing), PLUS the infallible OBSERVER_DAEMON_CHILD
// marker. A setup session has no OOB channel (no LaunchRequest), so it carries
// ONLY the marker — not the OOB fd/auth vars — which keeps the invariant "every
// daemon child carries the marker" true for the setup path too (finding: marker
// completeness). Recursion via a setup command is currently unreachable (the
// argv is a fixed, server-derived command), so the marker here is belt-and-
// suspenders that makes the invariant claim honest rather than aspirational.
func setupChildEnv() []string { return setupChildEnvFor("") }

// setupChildEnvFor is setupChildEnv for a setup command whose PROGRAM the
// daemon has already resolved to an absolute path (the guided tool install:
// dashboardInstallPlanFor resolves `npm` / `bash` / `uv` over the merged PATH).
// It widens the setup PTY's PATH the same way a tool launch is widened (audit
// DI-04a/b) so the installer itself — an npm shim needing node, a vendor script
// needing curl from a login-only dir — can run on a daemon whose own PATH is
// narrower than the operator's shell. binPath "" adds only the login-only dirs;
// a daemon with none of those is unchanged.
func setupChildEnvFor(binPath string) []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+1)
	for _, kv := range parent {
		if isInternalChildEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	out = applyChildPATH(out, daemonLoginPathDirs(), binPath)
	out = append(out, envDaemonChild+"=1")
	// Same Windows case-insensitive-key hardening as launchChildEnv.
	if runtime.GOOS == "windows" {
		return dedupEnvWindows(out)
	}
	return out
}

// auditEnv logs one metadata-only line per launch: the var count and the
// launch's identity (no values). This is the plan §F1 per-launch env audit.
func (l *ptyLauncher) auditEnv(req termsvc.LaunchRequest, env []string) {
	if l.logger == nil {
		return
	}
	l.logger.Info("terminal launch: spawned",
		"run", req.RunID, "tool", req.Tool, "kind", string(req.Kind),
		"env_vars", strconv.Itoa(len(env)), "dir_set", req.Dir != "")
}

// drainOOB reads framed OOB signals from the child on a daemon goroutine. In
// F1 the launcher wrapper does not yet emit (that is F3), so this typically
// just blocks until the child exits (EOF). When frames do arrive it publishes
// them to the status feed as TRUSTED events (the channel is authenticated and
// unforgeable — §2.1b). Any framing violation poisons the decoder (fail-closed)
// and ends the drain; it never affects the PTY session.
func (l *ptyLauncher) drainOOB(runID, tool string, r *os.File, authToken string) {
	defer func() { _ = r.Close() }()
	dec := termoob.NewDecoder(r, authToken)
	for {
		frame, err := dec.Read()
		if err != nil {
			if !errors.Is(err, io.EOF) && l.logger != nil {
				l.logger.Debug("terminal oob: drain ended", "run", runID, "err", err)
			}
			return
		}
		l.publishOOB(runID, tool, frame)
	}
}

// oobSessionSourceToTermrun maps a Session frame's optional Source hint onto the
// correlation Source the daemon records (CLAUDE.md #5 — a data table, not an
// if-ladder; #3 — dispatch on the frame's declared capability, never on which
// tool sent it). Only KNOWN mappings live here. An EMPTY hint is the back-compat
// known-id case (the launcher KNEW the id: claude's forced `--session-id`, a
// codex `--resume` short-circuit) → SourceOOB; a value IN this table maps to its
// class; a non-empty value NOT in this table is an evidence class this daemon
// does not know and is REFUSED (never guessed) — see termrunSourceForFrame.
var oobSessionSourceToTermrun = map[string]termrun.Source{
	termoob.SessionSourceDiscovered: termrun.SourceDiscovered,
}

// termrunSourceForFrame resolves a Session frame's Source hint to the
// correlation Source the daemon records, returning ok=false when the hint is an
// UNKNOWN non-empty value. An empty hint is the back-compat known-id echo →
// (SourceOOB, true); a hint in oobSessionSourceToTermrun maps to its class (e.g.
// "discovered" → SourceDiscovered, true); anything else — a weaker evidence
// class a NEWER launcher might emit against an OLDER daemon (in-place upgrade) —
// returns ("", false) so the caller SKIPS the correlation rather than promoting
// unknown evidence to full OOB confidence (R2-6).
func termrunSourceForFrame(frameSource string) (termrun.Source, bool) {
	if frameSource == "" {
		return termrun.SourceOOB, true
	}
	if s, ok := oobSessionSourceToTermrun[frameSource]; ok {
		return s, true
	}
	return "", false
}

// publishOOB turns a trusted OOB frame into a status-feed event (F4 consumes
// it) and, for a session-announce frame, records the run->session correlation
// at the confidence its Source hint implies (P2-1 — the ONE production caller of
// the correlation seam). A KNOWN-id echo (empty hint) records at oob confidence;
// a heuristically-DISCOVERED id (Source="discovered") records at the lower
// SourceDiscovered confidence, so a later known-id OOB echo strictly upgrades
// it. Unknown frame types are ignored (forward-compat).
func (l *ptyLauncher) publishOOB(runID, tool string, frame termoob.Frame) {
	if frame.Type == termoob.TypeSession {
		// The launcher learned the child's agent session id (by forcing it, or
		// by heuristic discovery) and echoed it on the authenticated channel.
		// Establish the run->session link at the confidence the frame's Source
		// hint implies so Snapshot's SessionForRun can surface it for "Jump in"
		// — the production path that populates termsvc's bySession map.
		if frame.Session == nil || frame.Session.SessionID == "" {
			return
		}
		source, known := termrunSourceForFrame(frame.Session.Source)
		if !known {
			// An unknown, non-empty evidence class (e.g. a newer launcher emitting
			// a weaker source string to an older daemon after an in-place upgrade).
			// SKIP the correlation entirely rather than guess a confidence for a
			// class this daemon doesn't understand — and skip the feed event too,
			// since we can't trust the id's provenance (R2-6).
			if l.logger != nil {
				l.logger.Warn("terminal oob: skipping session correlation for unknown source class",
					"run", runID, "tool", tool, "source", frame.Session.Source)
			}
			return
		}
		if l.correlate != nil {
			if err := l.correlate(context.Background(), runID, frame.Session.SessionID, source, time.Now().UTC()); err != nil && l.logger != nil {
				l.logger.Debug("terminal oob: correlate failed", "run", runID, "err", err)
			}
		}
		if l.feed != nil {
			l.feed.Publish(termfeed.Event{
				Kind: "oob:session", RunID: runID, Tool: tool, SessionID: frame.Session.SessionID,
				Trust: termfeed.TrustTrusted, At: time.Now().UTC(),
			})
		}
		return
	}
	if l.feed == nil {
		return
	}
	switch frame.Type {
	case termoob.TypeHello:
		l.feed.Publish(termfeed.Event{
			Kind: "oob:hello", RunID: runID, Tool: tool,
			Trust: termfeed.TrustTrusted, At: time.Now().UTC(),
		})
	case termoob.TypeLifecycle:
		if frame.Lifecycle != nil {
			l.feed.Publish(termfeed.Event{
				Kind: "oob:" + string(frame.Lifecycle.Phase), RunID: runID, Tool: tool,
				Trust: termfeed.TrustTrusted, At: time.Now().UTC(),
			})
		}
	}
}
