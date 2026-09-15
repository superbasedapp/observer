package termsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sshprofile"
	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// Errors surfaced by the fresh-launch authorization gate. Handoff launches do
// not consult these — they are gated by [handoff].allow_dashboard_launch at the
// cmd layer (the existing narrow consent, deliberately untouched).
var (
	// ErrFreshLaunchDisabled — [terminal.launch].allow_fresh_agent is false.
	ErrFreshLaunchDisabled = errors.New("termsvc: fresh-agent launch is disabled (set [terminal.launch].allow_fresh_agent)")
	// ErrToolNotAllowed — the tool is not in [terminal.launch].allowed_tools.
	ErrToolNotAllowed = errors.New("termsvc: tool is not in the fresh-launch allow-list")
	// ErrShellLaunchDisabled — [terminal.launch].allow_shell is false.
	ErrShellLaunchDisabled = errors.New("termsvc: plain-shell launch is disabled (set [terminal.launch].allow_shell)")
	// ErrNoLauncher — the service was constructed without a Launcher.
	ErrNoLauncher = errors.New("termsvc: no launcher configured")
	// ErrAttachToolRequired — LaunchAttachable was given an empty Tool.
	ErrAttachToolRequired = errors.New("termsvc: attach launch requires a tool")
	// ErrAttachSubcommandRequired — LaunchAttachable was given an empty Subcommand.
	ErrAttachSubcommandRequired = errors.New("termsvc: attach launch requires a subcommand")
	// ErrAttachDirNotAbsolute — LaunchAttachable was given a non-absolute Dir.
	ErrAttachDirNotAbsolute = errors.New("termsvc: attach launch dir must be absolute")
	// ErrResumeSessionRequired — LaunchResume was given no native session id.
	ErrResumeSessionRequired = errors.New("termsvc: native resume requires a source session id")
	// ErrResumeArgsMismatch — LaunchResume's argv does not resume its declared session.
	ErrResumeArgsMismatch = errors.New("termsvc: native resume args must exactly match --resume <source session id>")
	// ErrSandboxUnavailable is returned when a caller requests a sandboxed
	// fresh launch (FreshRequest.Sandbox) but the Service was constructed
	// without a Sandboxer (B9 plan §7/§12 amendment A5). A nil Sandboxer means
	// the feature is absent; a sandboxed request FAILS CLOSED rather than
	// silently degrading to an unsandboxed launch. Returned BEFORE a run is
	// minted, so no orphan terminal_runs row is created.
	ErrSandboxUnavailable = errors.New("termsvc: sandboxed launch requested but no sandbox seam is configured")
	// ErrSSHLaunchDisabled — [terminal.ssh].enabled is false. An SSH shell runs
	// arbitrary commands on ANOTHER machine, so it has its own master opt-in
	// rather than riding on AllowShell (which grants only a LOCAL shell).
	ErrSSHLaunchDisabled = errors.New("termsvc: SSH remote-system launch is disabled (set [terminal.ssh].enabled)")
	// ErrSSHProfileUnknown — the requested profile name is not in the
	// operator-authored [[terminal.ssh.profiles]] list. This is THE gate that
	// makes the client's only input (a name) safe: a name the operator never
	// wrote can never become a connection.
	ErrSSHProfileUnknown = errors.New("termsvc: no such SSH profile")
	// ErrSSHProfileInvalid — the named profile failed re-validation at launch
	// (bad field, or a key_path that no longer resolves to a regular file).
	// Re-validating here rather than trusting the load-time check mirrors the
	// ValidateProjectRoot-immediately-before-spawn discipline.
	ErrSSHProfileInvalid = errors.New("termsvc: SSH profile is not valid")
	// ErrWorkspacePrepFailed wraps a Sandboxer.Prepare error (workspace
	// creation / git clone / bwrap-plan failure). Returned before a run is
	// minted, same fail-closed posture as ErrSandboxUnavailable. The dashboard
	// maps this to a 500.
	ErrWorkspacePrepFailed = errors.New("termsvc: sandbox workspace preparation failed")
)

// Policy is the resolved fresh-launch authorization, built from the operator's
// [terminal.launch] block. The zero value denies every fresh launch.
type Policy struct {
	// AllowFresh is the master opt-in for non-handoff launches.
	AllowFresh bool
	// AllowedTools is the allow-list of launchable tool NAMES a fresh launch
	// may start. Empty = deny-all.
	AllowedTools []string
	// AllowedProjectRoots is the operator-configured directory allow-list a
	// fresh launch's project_root is validated against (canonicalized).
	AllowedProjectRoots []string
	// AllowShell is the separate opt-in for a fresh PLAIN SHELL launch
	// (never an AI tool). Independent of AllowFresh/AllowedTools — a bare
	// shell is not a member of the tool allow-list and is authorized by this
	// flag alone.
	AllowShell bool
	// AllowSSH is the master opt-in for an OUTBOUND SSH remote-system shell
	// ([terminal.ssh].enabled). Deliberately independent of AllowShell: a local
	// shell and a shell on someone else's production box are different grants.
	AllowSSH bool
	// SSHProfiles is the OPERATOR-AUTHORED allow-list of remote systems, read
	// from [[terminal.ssh.profiles]]. It is the whole authorization model for
	// this feature: the client sends a profile NAME, LaunchSSH resolves it
	// HERE, and a name that is not in this slice is refused. Empty = deny-all,
	// even when AllowSSH is true.
	SSHProfiles []sshprofile.Profile
	// SSHOptions carries the connection-tuning knobs ([terminal.ssh]
	// connect_timeout_seconds / keepalive_seconds). Its zero value resolves to
	// the sshprofile defaults.
	SSHOptions sshprofile.Options
}

// toolAllowed reports whether tool is in the fresh-launch allow-list.
func (p Policy) toolAllowed(tool string) bool {
	for _, t := range p.AllowedTools {
		if t == tool {
			return true
		}
	}
	return false
}

// reasonChildExit is the durable end-reason termsvc stamps for a natural
// process exit (or a never-spawned run). It mirrors store.EndReasonChildExit —
// the store is the canonical owner of the value; termsvc keeps a local copy
// rather than importing the store (it deliberately speaks only termrun's pure
// types). The guarded recorder write means this never downgrades a
// graceful-shutdown/resumed stamp (review finding H2).
const reasonChildExit = "child_exit"

// RunRecorder persists run identity + scored correlations. It is satisfied by
// a cmd adapter over *store.Store; termsvc speaks internal/termrun's pure
// types so it never imports the store.
type RunRecorder interface {
	// RecordRun persists a newly minted run identity.
	RecordRun(ctx context.Context, run termrun.Run) error
	// EndRun records a run's exit (ended_at + exit code) and, when the run has
	// no durable end-reason stamped yet, the given reason (e.g. "child_exit" for
	// a natural exit). The reason write is GUARDED by the recorder so a natural
	// exit never downgrades a graceful-shutdown/resumed stamp (review finding
	// H2).
	EndRun(ctx context.Context, runID string, endedAt time.Time, exitCode int, reason string) error
	// RecordCorrelation upserts a scored run→session correlation (MAX-upgrade).
	RecordCorrelation(ctx context.Context, c termrun.Correlation) error
	// RecordGUISpawn stamps a GUI run's POST-SPAWN facts — the detached child's
	// pid and the honest wrap verdict (termrun.Run PID / WrapApplied /
	// WrapNote, migration 108). It is a SECOND write on the same row rather
	// than part of RecordRun because none of the three exists until the child
	// does, while the row itself must be written BEFORE the spawn (a recorder
	// failure must never leave a process nothing knows about). It is called
	// only for termrun.KindGUI; every other kind carries the honest zeroes.
	RecordGUISpawn(ctx context.Context, run termrun.Run) error
}

// LaunchRequest is the fully server-derived spawn request the Service hands the
// Launcher. Every field is derived from validated inputs; the client never
// supplies argv, paths, or the correlation nonce.
type LaunchRequest struct {
	// RunID is the durable run identity minted for this launch.
	RunID string
	// Tool is the target tool name (for the OOB channel + status feed).
	Tool string
	// Subcommand is the observer launcher verb (from the capability registry).
	Subcommand string
	// Kind is handoff or fresh.
	Kind termrun.Kind
	// Dir is the canonical project root for a fresh launch ("" = default cwd).
	Dir string
	// SessionID identifies the handoff source or native-resume target. Carry /
	// FromMessage are handoff-only continuation params (all unset for fresh).
	SessionID   string
	Carry       string
	FromMessage int
	// Rows / Cols are the initial PTY size (0 = OS default).
	Rows uint16
	Cols uint16
	// CorrelationToken is the raw OOB nonce handed to the child out of band so
	// it can be echoed back on the trusted channel; never persisted in clear.
	CorrelationToken string
	// ExtraEnv is additional environment entries ("KEY=VALUE") the Launcher
	// appends to the child's environment at spawn. It carries the attach
	// launcher's proxy-routing variables (session-attach design §6 decision #7:
	// attach children are proxy-routed by default) so a daemon-spawned attach
	// session captures tokens through :8820 exactly like a bare launch. Empty
	// for dashboard fresh/handoff launches.
	ExtraEnv []string
	// ExtraArgs are additional, server-derived argv tokens the Launcher appends
	// to the inner `observer <Subcommand>` launch AFTER the subcommand. The
	// attach path uses them to express the routing escape hatch
	// (`--no-proxy-route`), `--proxy`/`--config` overrides, and the operator's
	// trailing tool args (`-- --model X`) in ARGV — the env-only approach is a
	// no-op because the inner launcher self-routes regardless of env (B2/B3).
	// Empty for dashboard fresh/handoff launches.
	ExtraArgs []string
	// IsShell marks a fresh plain-shell launch (no AI tool, no Subcommand
	// resolution against the capability registry). The Launcher spawns the
	// child's $SHELL (falling back to /bin/bash / /bin/sh) instead of the
	// usual `observer <Subcommand>` argv.
	IsShell bool
	// SSHArgv is the fully composed, server-derived OpenSSH client argv for a
	// KindSSH launch (internal/sshprofile.Argv over an operator-authored
	// profile). Non-empty ONLY for an SSH launch; the Launcher spawns it
	// verbatim instead of the usual `observer <Subcommand>` argv, and never
	// wraps it in an isolation prefix.
	SSHArgv []string
	// WrapArgv is an optional isolation-wrapper argv prefix (B9) resolved by
	// the Sandboxer seam and threaded through to termsession.Spec.WrapArgv —
	// the bwrap invocation wraps the WHOLE inner `observer <verb>` argv
	// (including any ExtraArgs a model selection composed). Empty for every
	// non-sandboxed launch.
	WrapArgv []string
	// Sandboxed records whether this launch went through the Sandboxer seam
	// (B9). Carried alongside WrapArgv so the Launcher/recorder can label the
	// run without re-deriving it from WrapArgv's mere presence.
	Sandboxed bool
	// LoginPathDirs are the login-shell-only PATH dirs the Launcher prepends to
	// the child's PATH (audit DI-04b). They are populated from the tool
	// resolution taken at the launch decision point (toolresolve.Resolution.
	// LoginOnlyDirs), so the PATH the child EXECUTES with is the same merged
	// PATH the daemon RESOLVED the binary on. termsvc neither computes nor
	// interprets them — they are opaque strings it carries to the Launcher
	// (CLAUDE.md #2). Empty means "the Launcher falls back to the daemon-wide
	// set"; it is never an instruction to narrow a child's PATH.
	LoginPathDirs []string
	// BinPath is the resolved binary this launch runs, when the caller knows it.
	// The Launcher prepends its DIRECTORY to the child's PATH so an interpreted
	// shim finds the interpreter that sits next to it (`<npm prefix>/bin/node`
	// beside the shim) — the DI-04b failure mode is an `#!/usr/bin/env node`
	// shim exiting 127 at runtime, which the daemon cannot see at spawn. Empty
	// contributes nothing; it never selects or overrides the argv, which stays
	// server-derived.
	BinPath string
}

// Sandboxer prepares an isolation-wrapped launch: it prepares the workspace
// (host-side git) and returns the resolved working Dir plus the bwrap wrapper
// argv prefix. A nil Sandboxer means the feature is absent — a sandboxed
// request then fails closed (never degrades to unsandboxed; B9 plan §12
// amendment A5).
//
// termsvc declares this interface itself and imports neither
// internal/sandbox nor internal/workspace (CLAUDE.md module-boundary rule
// #2): only plain string/[]string cross the seam via PrepareRequest /
// PrepareResult. It is satisfied by a cmd adapter over the two pure B9
// packages (cmd/observer/terminal_sandbox.go).
type Sandboxer interface {
	// Prepare resolves the workspace this run will operate in and the argv
	// prefix that wraps the inner launch inside the isolation boundary. On
	// success PrepareResult.Dir is the workspace's absolute path (either the
	// original validated project root for a "live" source, or a freshly
	// prepared managed-workspace directory) and PrepareResult.WrapArgv is the
	// bwrap invocation prefix (or empty, for a backend that needs none).
	Prepare(ctx context.Context, req PrepareRequest) (PrepareResult, error)
}

// PrepareRequest is what LaunchFresh hands the Sandboxer: the already-
// authorized/validated project root plus the client's workspace-source
// choice. Tool selects the SandboxSpec row (state binds); ProjectRoot is the
// canonical path ValidateProjectRoot already accepted.
type PrepareRequest struct {
	// Tool is the target tool name, used to resolve its capability-registry
	// SandboxSpec (StateRW/StateRO binds).
	Tool string
	// ProjectRoot is the canonical, already-validated project root
	// (ValidateProjectRoot's return value).
	ProjectRoot string
	// WorkspaceSource selects the workspace-preparation mechanism: "live"
	// (default; the workspace IS ProjectRoot, no copy), "clone-local",
	// "clone-remote", or "worktree" (off by default; B9 plan §4).
	WorkspaceSource string
	// WorkspaceRemote is the remote URL for a "clone-remote" source. Ignored
	// otherwise.
	WorkspaceRemote string
	// WorkspaceBranch is an optional branch to check out after clone/worktree.
	// Ignored for "live".
	WorkspaceBranch string
}

// PrepareResult is what a successful Sandboxer.Prepare returns.
type PrepareResult struct {
	// Dir is the resolved working directory the launch spawns into: the
	// original ProjectRoot for a "live" source, or a freshly prepared
	// managed-workspace directory otherwise.
	Dir string
	// WrapArgv is the isolation-wrapper argv prefix (e.g. a bwrap invocation)
	// to thread into LaunchRequest.WrapArgv. May be empty.
	WrapArgv []string
	// Note is an optional human-readable detail (e.g. which SandboxSpec row
	// was used, or a workspace-prep caveat) for logging; never surfaced to the
	// authorization decision.
	Note string
}

// Launcher spawns a PTY-backed launcher and returns its opaque handle. It is
// satisfied by a cmd adapter over *termsession.Manager (plus the OOB FD
// plumbing). termsvc owns identity/authorization; the Launcher owns the PTY.
type Launcher interface {
	Spawn(req LaunchRequest) (handle string, err error)
}

// runMeta captures the per-handle run facts the Service already knows at spawn
// time — the run Kind and target Tool — so a Snapshot consumer can label a live
// PTY handle without a store read. Populated beside byHandle on spawn success;
// RETAINED (not dropped) when the run ends so the remote-sensitivity gates keep
// classifying an exited-but-lingering handle (F1). endedAt is the exit stamp:
// zero while the run is live, set by EndRunByHandle at exit. A zero endedAt is
// what makes PruneEndedHandles race-proof — a still-live entry is never pruned
// even against a STALE live-handle set (R2-2) — and it gates the grace-based
// aging that eventually GCs a long-dead entry.
type runMeta struct {
	Kind termrun.Kind
	Tool string
	// dir is the canonical, already-validated project root this run was launched
	// with ("" when launched with the default cwd). It is the SAME value the run
	// hashed into ProjectRootHash at spawn — retained in memory (never persisted;
	// terminal_runs stores only the hash) so the dashboard's project panel can
	// resolve a token to its root without a store read. Retained past exit like
	// the rest of runMeta and read through Service.ProjectRoot.
	dir string
	// spawnDir is the directory the child process ACTUALLY runs in — a
	// different question from dir, and deliberately so:
	//
	//   • dir is AUTHORIZATION-bearing. It is the client-influenced project root
	//     ValidateProjectRoot accepted, and it gates what the dashboard's
	//     Files/Git panel may browse. A launch with no requested root ("default
	//     cwd") legitimately has NO authorized root, so dir stays empty.
	//   • spawnDir is FACT-bearing. Every child has a working directory: the
	//     validated root when one was given, otherwise the daemon's own cwd,
	//     which the child inherits (termsession spawn sets cmd.Dir = spec.Dir,
	//     and an empty Dir inherits). It authorizes nothing and is never
	//     browsed; it exists so correlation can ask "where does this run live?"
	//     without borrowing an authorization answer.
	//
	// Conflating the two is what broke run→session correlation for every
	// default-cwd launch: the discovery sweep asked ProjectRoot for the run's
	// directory, got the honest "no authorized root", and skipped the run
	// forever — so a dashboard "New Terminal" on a node with no
	// [terminal.launch].allowed_project_roots could never link, even though the
	// child's cwd (and the session's project root) were both perfectly known.
	// Read through Service.SpawnDir; retained past exit like the rest of
	// runMeta.
	spawnDir string
	endedAt  time.Time
	// sandboxed records whether this run was launched through the B9
	// Sandboxer seam (in-memory only; no DB column — see B9 plan §10 ledger
	// G19, "was this historical run sandboxed?" is deliberately deferred).
	sandboxed bool
}

// endedHandleGrace is how long a run's retained classification metadata (byMeta)
// outlives the run's exit before it may be garbage-collected. It MUST exceed
// BOTH (a) the termsession Manager's ExitLinger default (30s — the window during
// which an exited PTY is still subscribable, so its classification must survive)
// AND (b) any plausible staleness of the live-handle set a PruneEndedHandles
// caller passes. The inequality is grace(90s) > ExitLinger(30s) + snapshot
// staleness: even if a snapshot captured BEFORE a handle registered is used to
// prune AFTER that handle registered-and-exited, the just-set endedAt is far
// younger than the grace, so the entry is retained and stays classified through
// its whole linger (R2-2). Over-classification (retaining a bit past linger) is
// safe — nothing can subscribe to a reaped handle; under-classification was the
// confidentiality hole this closes.
const endedHandleGrace = 90 * time.Second

// endedHandleGCBound bounds how many ended (retained) byMeta entries accumulate
// before EndRunByHandle opportunistically sheds the ones older than
// endedHandleGrace. It keeps byMeta bounded on a daemon driven ONLY through
// repeated attach sessions with no dashboard Snapshot polling (the usual
// PruneEndedHandles caller) — R2-7. It is a soft high-water mark, not a hard cap:
// entries younger than the grace are always kept (their linger classification is
// still load-bearing), so the live size settles near the number of runs that
// ended within the last grace window.
const endedHandleGCBound = 256

// Service is the terminal application service. One instance per daemon.
type Service struct {
	policy   Policy
	rec      RunRecorder
	launcher Launcher
	// guiLauncher spawns a DETACHED IDE / desktop app (see gui.go). Optional;
	// nil means the feature is absent on this daemon and LaunchGUI fails closed
	// with ErrGUIUnsupported — the same nil-seam posture as sandboxer.
	guiLauncher GUILauncher
	// gui owns the in-memory GUI run list. It carries its OWN mutex because it
	// shares no invariant with the PTY handle maps below (CLAUDE.md #4: one
	// owner per piece of state) — a GUI run has no handle and no PTY reader
	// ever consults it.
	gui guiState
	// sandboxer prepares a B9 sandboxed fresh launch (workspace + wrap argv).
	// Optional; nil means the feature is absent — a Sandbox:true FreshRequest
	// then fails closed with ErrSandboxUnavailable rather than silently
	// degrading to an unsandboxed launch (§12 amendment A5).
	sandboxer Sandboxer
	// sandboxWorkspacesDir is the daemon's managed-workspace root (config
	// `[terminal.sandbox].workspaces_dir`, resolved to an absolute default by
	// the cmd wiring). It gates ValidateManagedWorkspace for a prepared
	// non-"live" workspace; termsvc holds it directly rather than reading
	// config itself (module-boundary rule #1 — config parsing stays outside
	// this package).
	sandboxWorkspacesDir string
	feed                 *termfeed.Feed // optional; nil disables the status event feed
	logger               *slog.Logger   // optional; nil disables the no-mapping debug log
	now                  func() time.Time
	// getwd resolves the daemon's own working directory (prod: os.Getwd). It is
	// the cwd a child spawned with an empty Dir inherits, so it is the factual
	// spawn directory of every default-cwd launch (see runMeta.spawnDir).
	getwd func() (string, error)
	// exitStatus, when set, is the authoritative "has this handle already
	// exited?" query (termsession.Manager.ExitStatus). launch() consults it the
	// instant it installs the handle→run mapping, to close the PRE-REGISTRATION
	// exit gap: a child that exits between Spawn returning and the mapping being
	// installed fires the Manager's OnExit → EndRunByHandle with NO mapping yet
	// (a silent no-op), so the exit would otherwise never be recorded. Nil
	// disables the reconcile (tests / no Manager).
	exitStatus func(handle string) (exited bool, code int, ok bool)
	// onRunExit, when set, is the DIRECT, reliable per-run exit seam fired
	// synchronously from EndRunByHandle the moment a run's exit is recorded —
	// exactly once per run (EndRunByHandle dedupes by handle). It is what the
	// attach hub keys its liveness / flock-release / tombstone CORRECTNESS off,
	// independent of the lossy status feed (resilient-attach round-4). Because
	// EVERY end path funnels through EndRunByHandle — the Manager's OnExit
	// closure, launch()'s pre-registration reconcile, and the attach host's
	// honest-close/teardown — the hub gets one direct notification per run from
	// whichever path wins, with no dependence on term:exit surviving the feed.
	onRunExit func(runID string)

	mu       sync.Mutex
	byHandle map[string]string  // PTY handle -> run id
	byRun    map[string]string  // run id -> PTY handle
	byMeta   map[string]runMeta // PTY handle -> run kind + tool (Snapshot labeling)
	// bySession maps a LIVE run id -> its established observer-session link
	// (session id + the confidence it was established at). Populated by
	// Correlate ONLY for a run byRun still tracks (no resurrection of an ended
	// run) and ONLY when the new observation is at least as strong as the one
	// already stored (MAX-upgrade — a weaker later marker never clobbers a
	// stronger OOB link). Read by SessionForRun so a Snapshot can carry a
	// session id for an attach run (which has no source session at spawn)
	// without a store query. A run with no established link has no entry — an
	// honest "not correlated yet" (correlation is scored + asynchronous).
	bySession map[string]sessionLink
	// launching is the set of run ids that have been minted and handed to the
	// Launcher but whose PTY handle is not installed in byHandle/byRun yet — the
	// LAUNCH RESERVATION. It exists because the Launcher starts the OOB drain
	// goroutine INSIDE Spawn (cmd/observer/terminal_launch.go), so a trusted OOB
	// session frame can reach Correlate BEFORE Spawn has even returned a handle.
	// Correlate's liveness guard (rejecting a run byRun does not track) was
	// written to stop an ENDED run being resurrected, but byRun is equally empty
	// for a NOT-YET-REGISTERED one, so a legitimate early correlation was
	// silently discarded — and because the OOB session frame is one-shot, the
	// in-memory link was lost for the whole life of the run ("Jump in" stays
	// blank). Correlate therefore accepts a run that is live in byRun OR still
	// reserved here. A reservation is released by whichever path leaves launch():
	// the registration critical section on success, releaseLaunching on the
	// Spawn-error path, and a deferred releaseLaunching as the catch-all (panic /
	// any future early return). Every release also drops any bySession entry an
	// early Correlate wrote, so a failed Spawn can never strand a session link
	// that nothing could delete (no handle was produced, so EndRunByHandle — the
	// only deleter, keyed by handle — can never fire for it).
	launching map[string]struct{}
}

// sessionLink is a run's established in-memory correlation: the observer
// session id and the confidence the link was established at. The confidence is
// retained so Correlate can honor the MAX-upgrade contract in memory (only
// strictly stronger evidence replaces an existing link).
type sessionLink struct {
	sessionID  string
	confidence float64
}

// Options configures a Service. Recorder and Launcher are required; the rest
// are optional.
type Options struct {
	Policy   Policy
	Recorder RunRecorder
	Launcher Launcher
	Feed     *termfeed.Feed
	Logger   *slog.Logger
	Now      func() time.Time
	// ExitStatus is the authoritative Manager exit query used by launch() to
	// close the pre-registration exit gap (see Service.exitStatus). Satisfied by
	// termsession.Manager.ExitStatus. Nil disables the reconcile.
	ExitStatus func(handle string) (exited bool, code int, ok bool)
	// OnRunExit is the direct per-run exit callback fired from EndRunByHandle
	// (see Service.onRunExit). Nil disables the direct seam (the status feed's
	// term:exit is then the only exit signal — advisory only).
	OnRunExit func(runID string)
	// Sandboxer prepares a B9 sandboxed fresh launch (see Service.sandboxer).
	// Nil disables the feature: a Sandbox:true FreshRequest then fails closed.
	Sandboxer Sandboxer
	// GUILauncher spawns a DETACHED IDE / desktop app (see gui.go). Nil
	// disables the feature: LaunchGUI then fails closed with
	// ErrGUIUnsupported, never degrading into a PTY launch.
	GUILauncher GUILauncher
	// SandboxWorkspacesDir is the daemon's managed-workspace root (see
	// Service.sandboxWorkspacesDir).
	SandboxWorkspacesDir string
	// Getwd resolves the daemon's own working directory — the cwd a child
	// spawned with no explicit Dir inherits, and therefore the run's factual
	// spawn directory (see runMeta.spawnDir). Injected so the whole decision is
	// table-testable; nil uses os.Getwd.
	Getwd func() (string, error)
}

// New builds a Service.
func New(opts Options) *Service {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	getwd := opts.Getwd
	if getwd == nil {
		getwd = os.Getwd
	}
	return &Service{
		getwd:                getwd,
		policy:               opts.Policy,
		rec:                  opts.Recorder,
		launcher:             opts.Launcher,
		sandboxer:            opts.Sandboxer,
		guiLauncher:          opts.GUILauncher,
		gui:                  guiState{runs: make(map[string]guiRunMeta)},
		sandboxWorkspacesDir: opts.SandboxWorkspacesDir,
		feed:                 opts.Feed,
		logger:               opts.Logger,
		now:                  now,
		exitStatus:           opts.ExitStatus,
		onRunExit:            opts.OnRunExit,
		byHandle:             make(map[string]string),
		byRun:                make(map[string]string),
		byMeta:               make(map[string]runMeta),
		bySession:            make(map[string]sessionLink),
		launching:            make(map[string]struct{}),
	}
}

// FreshRequest is the dashboard-derived fresh-launch request. Tool is validated
// against the allow-list; Subcommand is resolved by the dashboard from the
// capability registry; ProjectRoot is the client-influenced input the service
// canonicalizes + allow-list-checks.
type FreshRequest struct {
	Tool        string
	Subcommand  string
	ProjectRoot string
	Rows        uint16
	Cols        uint16
	// Shell requests a fresh PLAIN SHELL instead of an AI tool. When true,
	// Tool/Subcommand are ignored for authorization purposes (gated by
	// Policy.AllowShell instead of AllowedTools) — see LaunchFresh.
	Shell bool
	// Model is an optional model identifier for the New Terminal model
	// picker (B5). The dashboard has already validated it by MEMBERSHIP
	// against the tool's own suggestion list before it reaches here, but
	// LaunchFresh still resolves the tool's ModelSpec itself and composes
	// it via integration.ModelLaunch — fail-open on any error (unknown
	// tool, ModelNone, a spec-level validation failure): the launch
	// proceeds WITHOUT a model rather than aborting. Ignored when Shell.
	Model string
	// Sandbox requests a B9 filesystem-isolated launch (bwrap). When true and
	// no Sandboxer is configured, LaunchFresh fails closed with
	// ErrSandboxUnavailable — there is no silent unsandboxed fallback.
	// Ignored when Shell (sandboxing a bare shell is not v1 scope).
	Sandbox bool
	// WorkspaceSource selects how the sandboxed workspace is prepared: "live"
	// (default; no copy — the workspace IS ProjectRoot), "clone-local",
	// "clone-remote", or "worktree" (off by default). Ignored when Sandbox is
	// false.
	WorkspaceSource string
	// WorkspaceRemote is the remote URL for a "clone-remote" WorkspaceSource.
	// Ignored otherwise.
	WorkspaceRemote string
	// WorkspaceBranch is an optional branch to check out after clone/worktree.
	// Ignored for "live".
	WorkspaceBranch string
}

// LaunchResult is what a launch returns to the dashboard.
type LaunchResult struct {
	Handle string
	RunID  string
}

// ShellTool is the reserved pseudo-tool name a plain-shell fresh launch is
// recorded and reported under (status feed, run history, remote-sensitivity
// classification) — it is never a member of the capability registry's
// launchable-tool set, so it can never collide with a real AI-tool name.
const ShellTool = "shell"

// SSHTool is the reserved pseudo-tool name an outbound SSH remote-system
// session is recorded and reported under, mirroring ShellTool. Like ShellTool
// it is never a member of the capability registry's launchable-tool set, so it
// can never collide with a real adapter name.
const SSHTool = "ssh"

// LaunchFresh authorizes and starts a fresh agent (no --continue-from), or —
// when req.Shell is set — a fresh plain shell. It fails closed on every
// authorization miss BEFORE minting a run or spawning a process.
func (s *Service) LaunchFresh(ctx context.Context, req FreshRequest) (LaunchResult, error) {
	if s.launcher == nil {
		return LaunchResult{}, ErrNoLauncher
	}
	if req.Shell {
		if !s.policy.AllowShell {
			return LaunchResult{}, ErrShellLaunchDisabled
		}
	} else {
		if !s.policy.AllowFresh {
			return LaunchResult{}, ErrFreshLaunchDisabled
		}
		if !s.policy.toolAllowed(req.Tool) {
			return LaunchResult{}, fmt.Errorf("%w: %q", ErrToolNotAllowed, req.Tool)
		}
	}
	dir, err := ValidateProjectRoot(req.ProjectRoot, s.policy.AllowedProjectRoots)
	if err != nil {
		return LaunchResult{}, err
	}
	tool := req.Tool
	if req.Shell {
		tool = ShellTool
	}

	// B9 sandbox seam — AFTER ValidateProjectRoot, BEFORE the run is minted
	// (plan §1/§5): a failed or unavailable sandbox request never orphans a
	// terminal_runs row. sandboxed/wrapArgv stay their zero values (false/nil)
	// on the unchanged, non-sandboxed path — byte-identical to today.
	var wrapArgv []string
	sandboxed := req.Sandbox
	if sandboxed {
		prepared, perr := s.prepareSandbox(ctx, req, tool, dir)
		if perr != nil {
			return LaunchResult{}, perr
		}
		// The resolved dir becomes the workspace the run is spawned into and
		// attributed to — ProjectRootHash below hashes THIS value, so
		// attribution follows the prepared workspace, not the original
		// project root (plan §5).
		dir = prepared.Dir
		wrapArgv = prepared.WrapArgv
	}

	run := termrun.Run{
		Tool:            tool,
		Kind:            termrun.KindFresh,
		ProjectRootHash: termrun.HashProjectRoot(dir),
		LaunchedAt:      s.now(),
	}
	var extraArgs, extraEnv []string
	if req.Model != "" && !req.Shell {
		extraArgs, extraEnv = s.resolveModelLaunch(req.Tool, req.Model)
	}
	return s.launch(ctx, run, LaunchRequest{
		Subcommand: req.Subcommand,
		Kind:       termrun.KindFresh,
		Dir:        dir,
		Rows:       req.Rows,
		Cols:       req.Cols,
		IsShell:    req.Shell,
		ExtraArgs:  extraArgs,
		ExtraEnv:   extraEnv,
		WrapArgv:   wrapArgv,
		Sandboxed:  sandboxed,
	})
}

// prepareSandbox resolves a sandboxed fresh launch's workspace + wrap argv
// through the Sandboxer seam (B9 plan §1/§7). It fails closed: a nil
// Sandboxer returns ErrSandboxUnavailable, and any Sandboxer.Prepare error is
// wrapped in ErrWorkspacePrepFailed — both returned BEFORE LaunchFresh mints
// a run, so a failed sandbox request never orphans a terminal_runs row.
//
// When the prepared Dir differs from the caller's already-validated project
// root (a managed, non-"live" workspace was created), it must additionally
// canonicalize strictly under the daemon's configured managed-workspace root
// via ValidateManagedWorkspace. A "live" source — where Prepare legitimately
// returns Dir == validatedRoot, the workspace IS the project root, no copy —
// skips that check: the root was already authorized by ValidateProjectRoot,
// and ValidateManagedWorkspace's managedRoot gate would otherwise wrongly
// reject every ordinary project directory.
func (s *Service) prepareSandbox(ctx context.Context, req FreshRequest, tool, validatedRoot string) (PrepareResult, error) {
	if s.sandboxer == nil {
		return PrepareResult{}, ErrSandboxUnavailable
	}
	result, err := s.sandboxer.Prepare(ctx, PrepareRequest{
		Tool:            tool,
		ProjectRoot:     validatedRoot,
		WorkspaceSource: req.WorkspaceSource,
		WorkspaceRemote: req.WorkspaceRemote,
		WorkspaceBranch: req.WorkspaceBranch,
	})
	if err != nil {
		return PrepareResult{}, fmt.Errorf("%w: %w", ErrWorkspacePrepFailed, err)
	}
	if result.Dir != validatedRoot {
		canon, verr := ValidateManagedWorkspace(result.Dir, s.sandboxWorkspacesDir)
		if verr != nil {
			return PrepareResult{}, fmt.Errorf("%w: %w", ErrWorkspacePrepFailed, verr)
		}
		result.Dir = canon
	}
	return result, nil
}

// resolveModelLaunch composes the argv/env for a client-requested model
// (B5, New Terminal model picker) from the tool's capability-registry
// ModelSpec, dispatching on capability SHAPE (ModelSpec.Kind) rather than
// tool name (CLAUDE.md #3). It is fail-open by design: an unknown tool, a
// tool with no model capability (ModelNone), or any integration.ModelLaunch
// validation error all just return nil, nil — LaunchFresh proceeds with the
// tool's own default rather than aborting a launch over a model that turns
// out to be unusable.
func (s *Service) resolveModelLaunch(tool, model string) (extraArgs, extraEnv []string) {
	cap, ok := integration.For(tool)
	if !ok {
		return nil, nil
	}
	args, env, err := integration.ModelLaunch(cap.Model, model)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("termsvc: dropping requested model, launching with tool default",
				"tool", tool, "model", model, "error", err)
		}
		return nil, nil
	}
	return args, env
}

// SSHRequest is the dashboard-derived remote-system shell request
// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md §6.1).
//
// THE CLIENT SUPPLIES A PROFILE NAME AND NOTHING ELSE. Host, user, port, key
// path and jump host are all resolved from the daemon's own operator-authored
// config, so a request can only ever select among destinations the operator
// already wrote down — it can never nominate one. That property is the whole
// security model of this feature; do not add host/user fields here.
type SSHRequest struct {
	// Profile is the [[terminal.ssh.profiles]] name to connect to.
	Profile string
	// Rows / Cols are the initial PTY size (0 = OS default).
	Rows uint16
	Cols uint16
}

// LaunchSSH authorizes and starts an outbound SSH shell to an operator-
// configured remote system. It fails closed on every authorization miss BEFORE
// minting a run or spawning a process, exactly like LaunchFresh.
//
// Policy CONTRAST with LaunchAttachable (which is exempt from the allow-lists
// because its caller is authorized by the attach socket's 0600 filesystem
// permissions): an SSH launch is DASHBOARD-initiated, so it is gated — by
// AllowSSH plus membership in the operator's profile list. There is no
// equivalent of ValidateProjectRoot here because an SSH run has no LOCAL
// project root at all (the shell's cwd is on another machine); Dir is
// deliberately left empty and ProjectRootHash records as the honest zero.
func (s *Service) LaunchSSH(ctx context.Context, req SSHRequest) (LaunchResult, error) {
	if s.launcher == nil {
		return LaunchResult{}, ErrNoLauncher
	}
	if !s.policy.AllowSSH {
		return LaunchResult{}, ErrSSHLaunchDisabled
	}
	profile, ok := sshprofile.Find(s.policy.SSHProfiles, req.Profile)
	if !ok {
		return LaunchResult{}, fmt.Errorf("%w: %q", ErrSSHProfileUnknown, req.Profile)
	}
	// Re-validate at launch, including the key-path filesystem check: a key
	// file deleted after the daemon started must fail the launch loudly rather
	// than produce an opaque ssh error inside the PTY.
	if err := profile.ValidateWithFS(); err != nil {
		return LaunchResult{}, fmt.Errorf("%w: %w", ErrSSHProfileInvalid, err)
	}
	argv, err := sshprofile.Argv(profile, s.policy.SSHOptions)
	if err != nil {
		return LaunchResult{}, fmt.Errorf("%w: %w", ErrSSHProfileInvalid, err)
	}
	run := termrun.Run{
		Tool:       SSHTool,
		Kind:       termrun.KindSSH,
		LaunchedAt: s.now(),
	}
	return s.launch(ctx, run, LaunchRequest{
		Kind:    termrun.KindSSH,
		Rows:    req.Rows,
		Cols:    req.Cols,
		SSHArgv: argv,
	})
}

// SSHProfileList is the READ seam behind the dashboard's system picker: the
// operator-configured remote systems, plus whether the feature is enabled at
// all. It is served from the same Policy the launch gate consults, so the
// picker can never offer a profile LaunchSSH would refuse (one owner, one
// list). The returned slice is a copy — a caller cannot mutate the policy.
//
// There is deliberately no writer counterpart. Profiles are authored in
// config.toml; adding a create/update path here would turn "which machines may
// this daemon shell into" into something the dashboard can change.
func (s *Service) SSHProfileList() (enabled bool, profiles []sshprofile.Profile) {
	if len(s.policy.SSHProfiles) == 0 {
		return s.policy.AllowSSH, nil
	}
	out := make([]sshprofile.Profile, len(s.policy.SSHProfiles))
	copy(out, s.policy.SSHProfiles)
	return s.policy.AllowSSH, out
}

// HandoffRequest is the dashboard-derived continue-a-session request. It does
// not consult the fresh-launch allow-list — handoff-continue is the existing
// narrow consent, gated by [handoff].allow_dashboard_launch at the cmd layer.
type HandoffRequest struct {
	Tool        string
	Subcommand  string
	SessionID   string
	Carry       string
	FromMessage int
	Rows        uint16
	Cols        uint16
}

// LaunchHandoff mints a run + starts a --continue-from launch. The source
// session id is recorded on the run as SourceSessionID (NEVER a correlation
// target — the two are deliberately distinct, plan §2.1a).
func (s *Service) LaunchHandoff(ctx context.Context, req HandoffRequest) (LaunchResult, error) {
	if s.launcher == nil {
		return LaunchResult{}, ErrNoLauncher
	}
	run := termrun.Run{
		Tool:            req.Tool,
		Kind:            termrun.KindHandoff,
		SourceSessionID: req.SessionID,
		LaunchedAt:      s.now(),
	}
	return s.launch(ctx, run, LaunchRequest{
		Subcommand:  req.Subcommand,
		Kind:        termrun.KindHandoff,
		SessionID:   req.SessionID,
		Carry:       req.Carry,
		FromMessage: req.FromMessage,
		Rows:        req.Rows,
		Cols:        req.Cols,
	})
}

// AttachRequest is the CLI-derived request behind `observer <tool> --attach`
// (session-attach design §2.2/Phase 1). Tool + Subcommand come from the wired
// launcher the operator invoked; Dir is the child cwd; Rows/Cols seed the PTY;
// ExtraEnv carries the launcher's proxy-routing env for the child.
type AttachRequest struct {
	// Tool is the target tool name (e.g. "claude-code").
	Tool string
	// Subcommand is the observer launcher verb (e.g. "claude").
	Subcommand string
	// Dir is the child cwd. Empty uses the launcher's default cwd; when set it
	// must be absolute.
	Dir string
	// Rows / Cols are the initial PTY size (0 = OS default).
	Rows uint16
	Cols uint16
	// ExtraEnv is additional child environment ("KEY=VALUE"), carrying the
	// attach launcher's proxy-routing variables.
	ExtraEnv []string
	// ExtraArgs are additional, allow-listed argv tokens the CLI attach client
	// forwards to the inner `observer <Subcommand>` launcher (routing escape
	// hatch + `--` tool remainder). Explicit + allow-listed, never a blind argv
	// copy (B2/B3).
	ExtraArgs []string
}

// LaunchAttachable mints a KindAttach run and spawns a daemon-owned PTY on
// behalf of the operator's own terminal, reached over the attach socket.
//
// Deliberate policy difference from LaunchFresh (session-attach design §3.3):
// the attach socket is AF_UNIX mode 0600, owner-only, so the caller is the node
// operator at their own shell — OS filesystem permissions ARE the authorization.
// The dashboard-launch Policy allow-lists (AllowFresh / AllowedTools /
// AllowedProjectRoots) therefore do NOT gate an attach launch: the operator can
// attach-launch exactly what they could already exec bare. A Policy that would
// deny LaunchFresh still permits LaunchAttachable. It nonetheless mints a run
// identity with Kind=KindAttach through the shared launch() path, so every
// attach session is recorded (before spawn) and feed-published like any other
// run. Validation is intentionally minimal: a non-empty Tool + Subcommand, and
// an absolute Dir when one is supplied.
func (s *Service) LaunchAttachable(ctx context.Context, req AttachRequest) (LaunchResult, error) {
	if s.launcher == nil {
		return LaunchResult{}, ErrNoLauncher
	}
	if req.Tool == "" {
		return LaunchResult{}, ErrAttachToolRequired
	}
	if req.Subcommand == "" {
		return LaunchResult{}, ErrAttachSubcommandRequired
	}
	if req.Dir != "" && !filepath.IsAbs(req.Dir) {
		return LaunchResult{}, fmt.Errorf("%w: %q", ErrAttachDirNotAbsolute, req.Dir)
	}
	run := termrun.Run{
		Tool:            req.Tool,
		Kind:            termrun.KindAttach,
		ProjectRootHash: termrun.HashProjectRoot(req.Dir),
		LaunchedAt:      s.now(),
	}
	return s.launch(ctx, run, LaunchRequest{
		Subcommand: req.Subcommand,
		Kind:       termrun.KindAttach,
		Dir:        req.Dir,
		Rows:       req.Rows,
		Cols:       req.Cols,
		ExtraEnv:   req.ExtraEnv,
		ExtraArgs:  req.ExtraArgs,
	})
}

// ResumeRequest is the dashboard-derived NATIVE-resume request (session-attach
// design Phase 3): reopen a CLOSED session's real transcript by spawning the
// tool's own resume mechanism in a fresh dashboard terminal. Tool is validated
// against the fresh-launch allow-list; Subcommand is the launcher verb resolved
// from the capability registry; ExtraArgs is the resume tail composed at the
// boundary via integration.ResumeArgs (uniformly `["--resume", <id>]`);
// SourceSessionID is the session being resumed; it is both historical source
// and correlation target because native resume reopens that exact transcript.
// ProjectRoot is the client-influenced input canonicalized + allow-list-checked
// here.
type ResumeRequest struct {
	Tool            string
	Subcommand      string
	ProjectRoot     string
	SourceSessionID string
	ExtraArgs       []string
	Rows            uint16
	Cols            uint16
}

// LaunchResume authorizes and starts a NATIVE resume of a closed session. It
// mints a KindResume run and spawns through the shared launch() path.
//
// Deliberate policy CONTRAST with LaunchAttachable (session-attach design §3.3):
// a resume is a DASHBOARD-initiated Execute, not the owner's own shell over the
// AF_UNIX attach socket, so it is NOT exempt from the launch policy. It enforces
// the IDENTICAL fresh-launch gate as LaunchFresh — AllowFresh + toolAllowed +
// ValidateProjectRoot — failing closed on every authorization miss BEFORE
// minting a run or spawning a process. A Policy that denies LaunchFresh
// therefore also denies LaunchResume (whereas LaunchAttachable, whose caller is
// authorized by the socket's 0600 filesystem permissions, would still permit
// it). The resumed session id is recorded on the run as SourceSessionID and,
// after a successful still-live spawn, correlated as that run's target. This is
// intentionally different from LaunchHandoff: a handoff creates a new session,
// while native resume reopens the source session's real transcript.
func (s *Service) LaunchResume(ctx context.Context, req ResumeRequest) (LaunchResult, error) {
	if s.launcher == nil {
		return LaunchResult{}, ErrNoLauncher
	}
	if !s.policy.AllowFresh {
		return LaunchResult{}, ErrFreshLaunchDisabled
	}
	if !s.policy.toolAllowed(req.Tool) {
		return LaunchResult{}, fmt.Errorf("%w: %q", ErrToolNotAllowed, req.Tool)
	}
	dir, err := ValidateProjectRoot(req.ProjectRoot, s.policy.AllowedProjectRoots)
	if err != nil {
		return LaunchResult{}, err
	}
	if strings.TrimSpace(req.SourceSessionID) == "" {
		return LaunchResult{}, ErrResumeSessionRequired
	}
	if len(req.ExtraArgs) != 2 || req.ExtraArgs[0] != "--resume" || req.ExtraArgs[1] != req.SourceSessionID {
		return LaunchResult{}, ErrResumeArgsMismatch
	}
	run := termrun.Run{
		Tool:            req.Tool,
		Kind:            termrun.KindResume,
		SourceSessionID: req.SourceSessionID,
		ProjectRootHash: termrun.HashProjectRoot(dir),
		LaunchedAt:      s.now(),
	}
	res, err := s.launch(ctx, run, LaunchRequest{
		Subcommand: req.Subcommand,
		Kind:       termrun.KindResume,
		Dir:        dir,
		SessionID:  req.SourceSessionID,
		ExtraArgs:  req.ExtraArgs,
		Rows:       req.Rows,
		Cols:       req.Cols,
	})
	if err != nil {
		return LaunchResult{}, err
	}
	// The daemon already verified that this exact argv resumes the exact
	// captured session named by SourceSessionID. Link it directly on every OS;
	// non-Unix launchers have no OOB emitter. SourceDiscovered records daemon-
	// verified identity without fabricating the stronger OOB provenance.
	//
	// launch() reconciles an exit that raced registration before returning. Do
	// not persist a known-session observation when that reconciliation already
	// found the child dead. A later exit racing Correlate is still prevented
	// from resurrecting the in-memory link by Correlate's own liveness check.
	if _, live := s.HandleForRun(res.RunID); !live {
		return res, nil
	}
	if corrErr := s.Correlate(ctx, res.RunID, req.SourceSessionID, termrun.SourceDiscovered, s.now()); corrErr != nil {
		// The PTY has already spawned successfully. Returning corrErr would make
		// the caller believe no child exists and orphan the live terminal. Keep
		// the launch result and report the missing link through the existing
		// uncorrelated-run state; a later trusted producer may still retry it.
		if s.logger != nil {
			s.logger.Warn("termsvc: native resume correlation failed", "run", res.RunID, "err", corrErr)
		}
	}
	return res, nil
}

// launch is the shared mint→record→spawn→map path for both kinds. It records
// the run BEFORE spawning so a record failure never leaves an orphan process,
// and marks the run ended if the spawn itself fails.
func (s *Service) launch(ctx context.Context, run termrun.Run, lr LaunchRequest) (LaunchResult, error) {
	runID, err := termrun.NewRunID()
	if err != nil {
		return LaunchResult{}, fmt.Errorf("termsvc: mint run id: %w", err)
	}
	corr, err := termrun.NewCorrelationToken()
	if err != nil {
		return LaunchResult{}, fmt.Errorf("termsvc: mint correlation token: %w", err)
	}
	run.RunID = runID
	run.CorrelationTokenHash = termrun.HashCorrelationToken(corr)
	lr.RunID = runID
	lr.CorrelationToken = corr

	lr.Tool = run.Tool
	if err := s.rec.RecordRun(ctx, run); err != nil {
		return LaunchResult{}, fmt.Errorf("termsvc: record run: %w", err)
	}

	// Reserve the run BEFORE handing it to the Launcher. The Launcher starts the
	// OOB drain goroutine inside Spawn, so a trusted session frame can reach
	// Correlate before Spawn returns; without the reservation that correlation
	// hits an empty byRun and is dropped forever (the frame is one-shot).
	s.mu.Lock()
	s.launching[runID] = struct{}{}
	s.mu.Unlock()
	// Catch-all release: a no-op on every path that already released (success
	// releases inside the registration critical section, the Spawn-error path
	// releases explicitly), and the ONLY release on a panicking Spawn or any
	// future early return added between here and registration.
	defer s.releaseLaunching(runID)

	handle, err := s.launcher.Spawn(lr)
	if err != nil {
		// The run exists but never produced a process — close it out so it is
		// not left dangling as "running". Release the reservation FIRST: it also
		// drops any bySession entry a Correlate wrote while the run was merely
		// launching, which would otherwise be unreachable garbage (bySession is
		// only ever deleted by EndRunByHandle, keyed by a handle that was never
		// produced) — exactly the resurrection leak Correlate's guard exists to
		// prevent.
		s.releaseLaunching(runID)
		_ = s.rec.EndRun(ctx, runID, s.now(), -1, reasonChildExit)
		return LaunchResult{}, err
	}

	// Resolve BOTH directory answers before taking the lock (each may hit the
	// filesystem): the authorized project root and the factual spawn cwd. See
	// runMeta.dir / runMeta.spawnDir for why they are separate.
	dir := canonicalizeLaunchDir(lr.Dir)
	spawnDir := s.spawnDirFor(lr.Dir)

	s.mu.Lock()
	// Release the launch reservation in the SAME critical section that installs
	// the live mappings. Doing it as a separate lock acquisition (before or
	// after this one) would reopen a smaller version of the very window this
	// reservation closes — a Correlate landing between the two acquisitions
	// would see neither launching nor byRun and drop the link.
	delete(s.launching, runID)
	s.byHandle[handle] = runID
	s.byRun[runID] = handle
	s.byMeta[handle] = runMeta{
		Kind:      run.Kind,
		Tool:      run.Tool,
		dir:       dir,
		spawnDir:  spawnDir,
		sandboxed: lr.Sandboxed,
	}
	s.mu.Unlock()

	s.publish(termfeed.Event{
		Kind:  "term:launch:" + string(run.Kind),
		RunID: runID,
		Tool:  run.Tool,
		Trust: termfeed.TrustTrusted,
		At:    s.now(),
	})

	// Reconcile the PRE-REGISTRATION exit gap (resilient-attach round-4). The
	// child can exit in the window between s.launcher.Spawn returning above and
	// the byHandle mapping being installed just now. In that window the Manager's
	// OnExit → EndRunByHandle found NO mapping and returned silently, so no exit
	// was ever recorded and neither term:exit nor onRunExit ever fired — the hub
	// would then reserve liveness + park the flock-release callback forever. Now
	// that the mapping exists, ask the authoritative Manager whether the handle
	// already exited; if so, run the SAME EndRunByHandle end path exactly once.
	// It is idempotent with a later OnExit (EndRunByHandle dedupes by handle: the
	// second caller finds no mapping and no-ops), and it fires onRunExit → the
	// hub's direct exit seam so the fast-exit tombstone is recorded reliably
	// rather than depending on a term:exit that never came. Manager stays the one
	// owner of exit truth; termsvc only asks.
	if s.exitStatus != nil {
		if exited, code, ok := s.exitStatus(handle); ok && exited {
			s.EndRunByHandle(ctx, handle, code)
		}
	}
	return LaunchResult{Handle: handle, RunID: runID}, nil
}

// releaseLaunching drops a run's launch reservation and, with it, any session
// link an early Correlate established while the run was only reserved. It is
// idempotent: a run whose reservation was already released (the success path
// consumes it inside the registration critical section) is left completely
// untouched — in particular a REGISTERED run's bySession entry is never
// disturbed, which is what makes the deferred catch-all in launch() safe.
func (s *Service) releaseLaunching(runID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, reserved := s.launching[runID]; !reserved {
		return
	}
	delete(s.launching, runID)
	// The run never reached byHandle/byRun, so no handle exists and
	// EndRunByHandle can never clean this up — drop it here or it leaks.
	delete(s.bySession, runID)
}

// RunIDForHandle returns the run id a PTY handle belongs to, if known.
func (s *Service) RunIDForHandle(handle string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	runID, ok := s.byHandle[handle]
	return runID, ok
}

// KindForHandle returns the run Kind and target Tool a live PTY handle belongs
// to, resolved from the run identity the Service minted at spawn — no store
// read. ok=false for an unknown/ended handle. Additive read seam for Snapshot
// labeling (session-attach design Phase 2): the daemon already knows a run's
// Kind + Tool at launch, so a live handle can be labeled without a query, and a
// consumer can dispatch on run SHAPE (e.g. "is this an attach session?") rather
// than a tool name.
func (s *Service) KindForHandle(handle string) (termrun.Kind, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// F4: opportunistically shed a stale ended-entry burst here too. A burst of
	// short runs that all END within one grace window leaves every entry too
	// young for the EndRunByHandle-time GC; if activity then stops and no
	// dashboard Snapshot ever calls PruneEndedHandles, nothing re-triggers the
	// GC once the grace lapses. This read path is exercised by any live daemon
	// (Snapshot labeling + the remote-sensitivity gates), so folding a bounded
	// GC in here reclaims the burst on the next real activity. (A fully-idle
	// daemon retaining a burst until its next activity is accepted — the
	// entries are past-linger dead metadata, harmless until reclaimed.)
	s.gcEndedMetaLocked()
	m, ok := s.byMeta[handle]
	return m.Kind, m.Tool, ok
}

// ProjectRoot returns the canonical project root a live PTY handle was launched
// with, resolved from the run identity the Service minted at spawn — no store
// read. ok=false when the handle is unknown OR the run was launched with the
// default cwd (empty dir): both are honest "no browsable project root" answers.
// Served from byMeta (retained past exit-linger), so it stays answerable for a
// lingering handle exactly like KindForHandle. Additive read seam for the
// dashboard project panel (Arc A): the daemon already knows a run's validated
// root at launch, so a token can be resolved to its root without a query, and
// the browser never supplies a filesystem path.
func (s *Service) ProjectRoot(handle string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.byMeta[handle]
	if !ok || m.dir == "" {
		return "", false
	}
	return m.dir, true
}

// SpawnDir returns the directory the run's child process actually runs in: the
// validated project root when the launch carried one, otherwise the daemon's
// own cwd, which a child spawned with an empty Dir inherits. ok=false only for
// an unknown handle or when the daemon's cwd itself was unreadable — the honest
// "this run's working directory is unknown".
//
// It is NOT an authorization answer and must never gate browsing: use
// ProjectRoot for that. SpawnDir exists for CORRELATION — the discovery sweep
// matches a run to the observer session started in the same directory, and a
// default-cwd launch has a perfectly well-known directory even though it has no
// authorized project root. Served from byMeta (retained past exit-linger), the
// same no-store-read contract as ProjectRoot/KindForHandle.
func (s *Service) SpawnDir(handle string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.byMeta[handle]
	if !ok || m.spawnDir == "" {
		return "", false
	}
	return m.spawnDir, true
}

// canonicalizeLaunchDir pins the AUTHORIZED project root a run was launched
// with — lr.Dir, the canonical value each caller (LaunchFresh/LaunchResume via
// ValidateProjectRoot, LaunchAttachable via AttachRequest.Dir) already hashed
// into run.ProjectRootHash. One place, same value.
//
// It fully resolves symlinks HERE, the single storage point (finding 2a): the
// project panel resolves this token back to its root and browses under it, so
// canonicalizing at launch means a symlink component retargeted after launch
// cannot silently move the panel's root to a new target. On any resolution
// error (path missing/unreadable) it returns "" → treated as "no browsable
// project root" (ProjectRoot returns ok=false). An empty input is a default-cwd
// launch, which has no authorized root at all.
func canonicalizeLaunchDir(dir string) string {
	if dir == "" {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return ""
	}
	return resolved
}

// spawnDirFor resolves the FACTUAL working directory of a launch (see
// runMeta.spawnDir): the launch dir when one was given, otherwise the daemon's
// own cwd, which the child inherits.
//
// It differs from canonicalizeLaunchDir in its failure posture, and on purpose.
// A root that fails to canonicalize is not browsable, so canonicalizeLaunchDir
// must fail closed to ""; correlation authorizes nothing, so an unresolvable
// path degrades to the raw spelling instead — which is frequently the exact
// spelling the adapter stored for the session anyway, and matching on it can
// only ever produce a link that is separately gated by tool + time + a
// unique-or-abstain rule. Only an unreadable daemon cwd yields "", the honest
// "unknown".
func (s *Service) spawnDirFor(dir string) string {
	if dir == "" {
		if s.getwd == nil {
			return ""
		}
		wd, err := s.getwd()
		if err != nil {
			return ""
		}
		dir = wd
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved
	}
	return dir
}

// Sandboxed reports whether a live-or-lingering PTY handle was launched
// through the B9 Sandboxer seam (in-memory only — see runMeta.sandboxed).
// ok=false for an unknown handle, matching ProjectRoot/KindForHandle's
// no-store-read, byMeta-served contract.
func (s *Service) Sandboxed(handle string) (sandboxed bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.byMeta[handle]
	return m.sandboxed, ok
}

// SessionForRun returns the observer session id a run has been correlated to,
// once the correlation is established (>= termrun.MinLinkConfidence). ok=false
// when the run has no established link yet — correlation is scored and
// asynchronous, so a freshly-spawned attach session legitimately has none. The
// value is served from the in-memory map Correlate maintains (no store read on
// the Snapshot hot path).
func (s *Service) SessionForRun(runID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// F4: same opportunistic burst-shed as KindForHandle — this is the other
	// per-run read the Snapshot hot path drives, so a live daemon reclaims a
	// past-grace ended-entry burst here even when no PruneEndedHandles ever runs.
	s.gcEndedMetaLocked()
	link, ok := s.bySession[runID]
	return link.sessionID, ok
}

// SessionLinkForRun returns the observer session id a run has been correlated
// to AND the confidence that link was established at, once the correlation is
// established (>= termrun.MinLinkConfidence). ok=false when the run has no
// established link yet — correlation is scored and asynchronous, so a
// freshly-spawned attach session legitimately has none. It is the
// confidence-carrying companion of SessionForRun (which drops the field):
// same in-memory map, same opportunistic burst-shed, same no-store-read
// contract on the Snapshot hot path. The confidence honors the MAX-upgrade
// semantics Correlate maintains, so a caller sees the strongest evidence
// scored so far.
func (s *Service) SessionLinkForRun(runID string) (sessionID string, confidence float64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Same opportunistic burst-shed as SessionForRun — this is another per-run
	// read the Snapshot hot path can drive, so a live daemon reclaims a
	// past-grace ended-entry burst here even when no PruneEndedHandles ever runs.
	s.gcEndedMetaLocked()
	link, ok := s.bySession[runID]
	return link.sessionID, link.confidence, ok
}

// ResolveHandleLink resolves a PTY handle to its full Session-Cockpit link in
// ONE lock acquisition: liveness (byHandle), run identity (byMeta Kind+Tool),
// and the correlated observer session id + confidence (bySession) are read
// ATOMICALLY. The three-call chain it replaces (RunIDForHandle → KindForHandle
// → SessionLinkForRun) took s.mu three separate times, so a run ending between
// the first and third call could return known=true carrying a correlation that
// EndRunByHandle had already deleted (a live=true answer with a stale/deleted
// session link). Reading all three maps under the single lock closes that race.
// ok=false for an unknown/exited handle (byHandle tracks LIVE runs only — same
// liveness posture as RunIDForHandle). The composed methods are left untouched
// for their existing callers.
func (s *Service) ResolveHandleLink(handle string) (runID string, kind termrun.Kind, tool, sessionID string, confidence float64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	runID, live := s.byHandle[handle]
	if !live {
		return "", "", "", "", 0, false
	}
	// Opportunistic burst-shed, matching KindForHandle/SessionLinkForRun — this
	// read is on the same Snapshot/gate hot path. It never sheds the live handle
	// resolved here (GC only reaps ended entries past grace).
	s.gcEndedMetaLocked()
	if m, mok := s.byMeta[handle]; mok {
		kind, tool = m.Kind, m.Tool
	}
	if link, lok := s.bySession[runID]; lok {
		sessionID, confidence = link.sessionID, link.confidence
	}
	return runID, kind, tool, sessionID, confidence, true
}

// HandleForRun returns the PTY handle a run currently maps to, if live.
func (s *Service) HandleForRun(runID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	handle, ok := s.byRun[runID]
	return handle, ok
}

// EndRunByHandle records a run's exit, keyed by the PTY handle termsession
// reports on process exit (the daemon-observed, trusted lifecycle signal). It
// is idempotent and best-effort; an unknown handle is ignored. It also publishes
// an exit event to the status feed.
//
// It forgets the LIVE-run mappings (byHandle/byRun/bySession) so no later
// correlation can resurrect an ended run and the live-run gates immediately see
// the run as gone. It DELIBERATELY retains byMeta (the run Kind + Tool), because
// the daemon-observed exit only starts termsession's ExitLinger — the PTY stays
// subscribable in the Manager for up to that window, and the remote sensitivity
// gates (visibleSnapshot / handleLaunchWS / IsRemoteSensitiveSession →
// KindForHandle) MUST keep classifying an exited-but-lingering attach/resume
// handle as sensitive for as long as the Manager can still hand out its bytes.
// byMeta is instead RETAINED here (with its endedAt stamped) and garbage-
// collected later — by PruneEndedHandles (Snapshot-driven) and the opportunistic
// gcEndedMetaLocked below — only once the entry has been ended for longer than
// endedHandleGrace (which exceeds ExitLinger + snapshot staleness). So a byMeta
// entry outlives the handle in the Manager by a bounded grace (safe over-
// classification), and never UNDER-lives it (the confidentiality hole this
// closes: the pre-fix delete here made KindForHandle false mid-linger, and the
// pre-R2-2 set-only prune reopened it against a stale snapshot).
func (s *Service) EndRunByHandle(ctx context.Context, handle string, exitCode int) {
	s.mu.Lock()
	runID, ok := s.byHandle[handle]
	if ok {
		delete(s.byHandle, handle)
		delete(s.byRun, runID)
		delete(s.bySession, runID)
		// byMeta is intentionally NOT deleted here — see the doc comment. Instead
		// stamp its exit time so PruneEndedHandles (and the opportunistic GC just
		// below) can age it out past endedHandleGrace, while a zero endedAt keeps
		// a still-live entry classified even against a stale live-handle set (R2-2).
		if m, mok := s.byMeta[handle]; mok {
			m.endedAt = s.now()
			s.byMeta[handle] = m
		}
		// Opportunistic bound (R2-7): on a daemon driven only through attach
		// sessions, no dashboard Snapshot ever calls PruneEndedHandles, so ended
		// entries would accumulate one-per-run until restart. Shed the long-dead
		// ones here when the retained-ended count crosses the soft bound.
		s.gcEndedMetaLocked()
	}
	s.mu.Unlock()
	if !ok {
		// No live mapping for this handle. Post the round-4 reconcile this is the
		// IDEMPOTENT case (the run already ended — reconcile beat OnExit, or vice
		// versa) OR a genuinely unknown handle; either way it is deliberately a
		// no-op, but it is logged (was silently swallowed before) so the
		// missing-producer path that motivated the reconcile is observable rather
		// than invisible.
		if s.logger != nil {
			s.logger.Debug("termsvc: EndRunByHandle found no live mapping (idempotent no-op or unknown handle)", "handle", handle)
		}
		return
	}
	// Natural, daemon-observed exit. The recorder GUARDS end_reason so if a
	// graceful-shutdown sweep already stamped this run 'daemon_shutdown' (the PTY
	// kill that triggered THIS exit), the reason is preserved and only ended_at
	// is updated — the run stays resumable-by-restart (review finding H2). The
	// DB error stays swallowed (best-effort at exit): a fully-failed write leaves
	// the run looking like a crash orphan (reason '', ended_at NULL), which the
	// rediscovery gate WOULD offer — but native-resuming an already-finished
	// session is safe (the tool just reopens its own transcript), so the failure
	// direction is benign.
	_ = s.rec.EndRun(ctx, runID, s.now(), exitCode, reasonChildExit)
	s.publish(termfeed.Event{
		Kind:  "term:exit",
		RunID: runID,
		Trust: termfeed.TrustTrusted,
		At:    s.now(),
	})
	// Fire the DIRECT, reliable per-run exit seam (resilient-attach round-4). It
	// runs exactly once per run — only the EndRunByHandle call that found the live
	// mapping reaches here — and post runID resolution, so the hub can key its
	// liveness / flock-release / tombstone correctness off it without depending on
	// the term:exit above surviving the lossy feed. Fired OUTSIDE s.mu (the hub
	// takes its own lock) to keep the two lock orders independent.
	if s.onRunExit != nil {
		s.onRunExit(runID)
	}
}

// PruneEndedHandles garbage-collects retained per-handle classification metadata
// (byMeta) for handles the Manager no longer tracks. The caller — the Snapshot
// enrichment adapter, the ONE owner of the Manager's live view — passes the set
// of handles currently present in the Manager (live OR exited-but-lingering).
//
// It is race-proof against a STALE live-handle set (R2-2). A byMeta entry is
// dropped ONLY when ALL of:
//
//	(a) it is absent from the passed live set, AND
//	(b) it is not still live-tracked in byHandle, AND
//	(c) it has actually ENDED (non-zero endedAt), AND
//	(d) that end is older than endedHandleGrace.
//
// The pre-fix version dropped an entry the instant it was merely absent from the
// live set + byHandle. That reopened the exit-linger hole under this interleave:
// a Snapshot captured a live set BEFORE handle H registered; H then registered,
// classified sensitive, and exited (EndRunByHandle removed byHandle while the
// Manager kept H for linger); the OLD, STALE set — which never saw H — then
// pruned H, making KindForHandle(H) false mid-linger. With the endedAt stamp,
// H's just-set endedAt is far younger than endedHandleGrace (which exceeds
// ExitLinger + staleness), so (d) fails and H is retained — classification
// survives its whole linger. A still-LIVE entry (zero endedAt) fails (c) and is
// never pruned even against a stale set.
//
// It only shrinks byMeta, so it is safe to call on every Snapshot. A nil/empty
// set no longer prunes everything: an ended-but-within-grace entry is still
// kept (grace, not set-membership, is the aging clock now).
func (s *Service) PruneEndedHandles(liveHandles map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for handle, meta := range s.byMeta {
		if _, live := liveHandles[handle]; live {
			continue
		}
		// Retain while still live-tracked (byHandle) — a belt-and-braces guard so
		// a Snapshot that races a just-completed launch (handle mapped but not yet
		// in the passed set) never drops a live run's classification.
		if _, tracked := s.byHandle[handle]; tracked {
			continue
		}
		// A zero endedAt means the run has not been recorded as ended — retain it
		// even if a STALE live set omits it (R2-2 core).
		if meta.endedAt.IsZero() {
			continue
		}
		// An ended entry ages out only past the grace, which exceeds ExitLinger +
		// any plausible snapshot staleness, so it never drops mid-linger.
		if now.Sub(meta.endedAt) < endedHandleGrace {
			continue
		}
		delete(s.byMeta, handle)
	}
}

// gcEndedMetaLocked opportunistically sheds ENDED byMeta entries older than
// endedHandleGrace when the retained-ended count crosses endedHandleGCBound.
// It bounds byMeta growth on a daemon driven ONLY through repeated attach
// sessions with no dashboard Snapshot polling (which is the usual
// PruneEndedHandles caller) — R2-7. It is called from EndRunByHandle (on each
// exit) AND from the KindForHandle / SessionForRun read paths (F4), so a burst
// of runs that all end WITHIN one grace window — leaving every entry too young
// for the exit-time GC — is still reclaimed on the next real activity once the
// grace lapses, rather than lingering until the next Snapshot or daemon restart.
// A fully-idle daemon (no exits AND no reads after the burst) retains the burst
// until its next activity; that is accepted — the entries are past-linger dead
// metadata, harmless until reclaimed. Self-contained in termsvc: it needs no
// Manager live set, because a run older than the grace is necessarily reaped
// past ExitLinger (grace > ExitLinger). It NEVER drops a still-live entry (zero
// endedAt) or a within-grace ended entry, so it preserves the exit-linger
// classification guarantee identically to PruneEndedHandles; it only sheds
// long-dead metadata. Must be called under s.mu.
func (s *Service) gcEndedMetaLocked() {
	ended := 0
	for _, m := range s.byMeta {
		if !m.endedAt.IsZero() {
			ended++
		}
	}
	if ended <= endedHandleGCBound {
		return
	}
	now := s.now()
	for handle, m := range s.byMeta {
		if m.endedAt.IsZero() {
			continue
		}
		if now.Sub(m.endedAt) < endedHandleGrace {
			continue
		}
		delete(s.byMeta, handle)
	}
}

// Correlate records a scored run→session correlation observation. It scores the
// single observation through internal/termrun (the one owner of the source→
// confidence policy) and upserts it (MAX-upgrade). Source ordering is
// oob > marker > heuristic; a weaker later observation never downgrades a
// stronger established link.
func (s *Service) Correlate(ctx context.Context, runID, sessionID string, source termrun.Source, at time.Time) error {
	if runID == "" || sessionID == "" {
		return nil
	}
	corr, ok := termrun.Score(runID, sessionID, []termrun.Observation{{Source: source, At: at}})
	if !ok {
		return nil
	}
	if err := s.rec.RecordCorrelation(ctx, corr); err != nil {
		return fmt.Errorf("termsvc: record correlation: %w", err)
	}
	// Remember an ESTABLISHED link in memory so Snapshot can label a run (an
	// attach session carries no source session at spawn) with its correlated
	// observer session id without a store read. Only a link at or above
	// MinLinkConfidence is surfaced — a weak heuristic never fills a session id,
	// matching the "links attach only once established" rule (design §2.1a).
	//
	// Two invariants enforced under mu (P2-3):
	//   (a) LIFECYCLE — update only when the run is still LIVE: tracked in byRun,
	//       OR still reserved in launching (minted + handed to the Launcher but
	//       not yet registered). RecordCorrelation above ran WITHOUT the lock (a
	//       store write), so an EndRunByHandle could have deleted this run's maps
	//       in the meantime. Writing bySession here without the guard would
	//       resurrect an ended run's entry that nothing can ever delete
	//       (EndRunByHandle already fired). The launching arm is NOT a hole in
	//       that invariant: every path out of launch() releases the reservation
	//       and drops the bySession entry with it, so a Spawn that fails (no
	//       handle → EndRunByHandle can never fire) leaves nothing behind. It IS
	//       load-bearing: the Launcher starts the OOB drain goroutine inside
	//       Spawn, so the one-shot trusted session frame routinely arrives before
	//       registration, and gating on byRun alone silently discarded it for the
	//       whole life of the run. Together the two arms keep bySession a strict
	//       subset of live-or-launching runs, and still reject an observation for
	//       an unknown/never-launched run.
	//   (b) MAX-UPGRADE — replace an existing link only with strictly stronger
	//       evidence, so a later marker/heuristic observation can never clobber
	//       a stronger OOB link in memory (the store keeps its own MAX-upgrade;
	//       this mirrors it for the in-memory hot-path copy).
	if corr.Linkable() {
		s.mu.Lock()
		_, live := s.byRun[runID]
		if !live {
			_, live = s.launching[runID]
		}
		if live {
			if cur, exists := s.bySession[runID]; !exists || corr.Confidence > cur.confidence {
				s.bySession[runID] = sessionLink{sessionID: sessionID, confidence: corr.Confidence}
			}
		}
		s.mu.Unlock()
	}
	// A correlation event enters the feed so F4 can attach a session id to a
	// run's status once the link is established.
	trust := termfeed.TrustHint
	if source == termrun.SourceOOB {
		trust = termfeed.TrustTrusted
	}
	s.publish(termfeed.Event{
		Kind:      "term:correlate:" + string(source),
		RunID:     runID,
		SessionID: sessionID,
		Trust:     trust,
		At:        at,
	})
	return nil
}

// publish emits an event to the status feed when one is configured.
func (s *Service) publish(ev termfeed.Event) {
	if s.feed != nil {
		s.feed.Publish(ev)
	}
}
