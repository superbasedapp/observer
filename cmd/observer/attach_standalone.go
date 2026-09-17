package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/remotenotify"
	"github.com/marmutapp/superbased-observer/internal/sshforward"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termstatus"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// attach_standalone.go owns the daemon's ONE terminal application service +
// PTY manager stack (terminalStack) and the two surfaces that consume it — the
// dashboard embedded-launch manager AND the owner-only session-attach socket —
// as INDEPENDENT capabilities off a single shared stack.
//
// This is the one-owner seam (CLAUDE.md #4): the Manager/Service is constructed
// exactly once per daemon, in buildTerminalStack above the per-surface
// constructors, so an
// attach-launched session and a dashboard-launched one share the manager's
// OnExit run-recording, the spawn audit sink, the lease model, and the status
// feed. Neither surface ever stands up a second Manager.
//
// Enablement is per-surface, not coupled: the attach socket serves whenever
// [terminal.attach].enabled is true, and the dashboard launch manager is wired
// whenever [handoff].allow_dashboard_launch is true — each independent of the
// other. Both still require an in-process PTY backend (termsession.PTYSupported).

// terminalStack is the single termsession.Manager + termsvc.Service the daemon
// builds, plus the shared status provider, spawn-audit sink, and teardown func.
// Its launchManager() and attachHost() methods derive the two surfaces over the
// SAME svc + mgr, so both funnel exits through one OnExit closure and arbitrate
// writer leases through one lease model.
type terminalStack struct {
	svc    *termsvc.Service
	mgr    *termsession.Manager
	status dashboard.TerminalStatusProvider
	// sandboxProber is the B9 dashboard.SandboxProber (the SAME *sandboxHolder
	// wired as termsvc.Options.Sandboxer — one hot-swappable seam, two
	// surfaces). It is non-nil whenever a stack was built, even with
	// [terminal.sandbox].enabled = false: the holder then reports
	// disabled_by_config and fails Prepare closed, and it picks the feature
	// up WITHOUT a restart once the operator saves the enable switch. Held
	// as the interface so the surfaces hand the dashboard a value, never a
	// non-nil interface over a nil pointer.
	sandboxProber dashboard.SandboxProber
	// attachAudit records the metadata-only terminal_attach spawn-audit row (F4,
	// session-attach design §3.5). Nil when no DB is wired (auditing disabled).
	// Built over the SAME SpawnAuditKind vocabulary the dashboard resume handler
	// uses so the two paths write identically shaped rows.
	attachAudit func(runID, tool, handle string)
	// hub bridges the correlation feed to the attach socket (resilient-attach
	// Layer 1): per-run correlated-session delivery + the daemon-wide live view
	// the double-spawn guard reads. Built over the SAME feed the Service
	// publishes correlation/exit events on.
	hub *attachHub
	// resumableRuns maps each rediscovered orphan session id → ALL of its
	// startup-eligible PREDECESSOR run ids, newest first (the attach runs this
	// daemon rediscovered as orphans at startup: no recorded end + a correlated
	// session id). Membership validates a daemon-death AUTO-resume target (a run
	// that recorded its end is NOT resumable-by-restart); the run-id LIST lets the
	// supersede stamp EVERY eligible predecessor by id — not just the newest — so
	// older same-session orphans can't be re-offered on a later restart (round-4
	// multi-orphan finding), while never touching the fresh replacement (finding:
	// wrong-run supersede). Empty/nil when no DB is wired.
	resumableRuns map[string][]string
	// instances owns the instance switcher's SSH local port forwards
	// (docs/ssh-terminals.md "Instance switcher"). It is built from the SAME
	// [terminal.ssh] profile list the SSH terminal picker uses — one
	// operator-authored allow-list, two surfaces over it — and is torn down by
	// close so an `ssh -N` child can never outlive this daemon.
	instances *sshforward.Manager
	// attachDir is the attach socket's owner-only directory. The attach host
	// takes a durable cross-process resume flock here (H3). Empty disables the
	// flock layer (no DB).
	attachDir string
	// supersedeResumed stamps rediscovered orphan rows end_reason='resumed' after
	// a successful auto-resume spawn, keyed by the PREDECESSOR run ids (H2 +
	// finding: wrong-run supersede + round-4 multi-orphan). Nil when no DB is wired.
	supersedeResumed func(runIDs []string)
	// resumeAuthority is the DURABLE store-backed double-spawn authority (round-5
	// finding 1): it reports whether the store already holds a LIVE run correlated
	// to a resume target session — the authority the attach host's resume conflict
	// check consults alongside the in-memory hub guard, so a dashboard resume (or
	// any dashboard-spawned run that correlates to an AI session), which never
	// rides the attach hub's feed and never takes the resume flock, still blocks a
	// duplicate attach resume. Nil when no DB is wired (the in-memory guard stands
	// alone). The attach host passes the target session's rediscovered predecessor
	// run ids to exclude, so the authority never self-blocks a crash-orphan
	// auto-resume by matching its own predecessor (review finding 1).
	resumeAuthority func(sessionID string, excludeRunIDs []string) bool
	// reclaimOnInput is [terminal.attach].reclaim_on_input (Feature 1): the
	// native-terminal writer-reclaim capability, resolved once at build time and
	// handed to the attach host. Default TRUE.
	reclaimOnInput bool
	// guard is the process-wide egress-policy Guard (internal/guard), acquired
	// nil-safely via acquireProcessGuard when a DB is wired and [guard] is
	// enabled. Consulted by the launch surface (P7 gateway-arc item 3) to
	// decide whether a fresh launch of a sandbox_enforce-classified tool must
	// be auto-upgraded to a sandboxed launch. Nil when guarding is disabled or
	// no DB is wired — every consumer must nil-check.
	guard *guard.Guard
	// nf is the node.features policy handle (P7 gateway-arc item 4's
	// org_disallow honor path) shared with the rest of the process. Nil-safe
	// on every method; a nil nf answers "allowed" for every tool.
	nf *nodeFeaturesHandle
	// close stops the status-hub reaper and kills every live session; wire it
	// into the command's teardown BEFORE the DB is closed (start.go relies on
	// defer-LIFO ordering to run it first).
	close func()
}

// buildTerminalStack constructs the shared terminal stack exactly once (see
// terminalStack). It returns (nil, nil) — not an error — when the OS has no
// in-process PTY backend (a native-Windows daemon): a nil stack is the honest
// "disabled" state both surfaces treat as unavailable, and the message is logged
// here so callers don't each duplicate it. A future ConPTY backend flips
// termsession.PTYSupported() to true and re-enables the stack with no caller
// change.
//
// Fresh-agent launch (F1) is a SEPARATE, default-off opt-in resolved into the
// termsvc.Policy from [terminal] + [terminal.launch]; building the stack never
// widens it (that stays gated on [terminal.launch].allow_fresh_agent).
// resolveTerminalSandbox builds the B9 sandbox seam: ONE long-lived
// sandboxHolder implementing both termsvc.Sandboxer and
// dashboard.SandboxProber over a hot-swappable *sandboxRuntime
// (cmd/observer/terminal_sandbox.go), plus the managed-workspaces root
// termsvc validates prepared workspaces against. Extracted from
// buildTerminalStack to keep that function under the gocyclo bound.
//
// The holder is returned UNCONDITIONALLY — including when
// [terminal.sandbox].enabled is false. That is the change that makes the
// feature hot-reloadable: the old code resolved enabled-ness once and
// returned nil seams when it was off, which pinned the dashboard to
// "disabled_by_config" until the daemon restarted even after the operator
// enabled the sandbox from Terminals → Settings. Fail-closed behaviour is
// unchanged — a holder with no live runtime returns
// termsvc.ErrSandboxUnavailable from Prepare (exactly what a nil Sandboxer
// produces) and reports disabled_by_config from the probe (exactly what a
// nil prober produces), so nothing a sandboxed launch may do has widened.
func resolveTerminalSandbox(cfg config.Config, binPath string, logger *slog.Logger) (termsvc.Sandboxer, string, dashboard.SandboxProber) {
	// The path the holder stats to notice a [terminal.sandbox] save. Empty
	// (unresolvable) simply pins the holder to its boot-time resolve.
	cfgPath, _ := config.ResolveGlobalPath(daemonConfigPath())
	h := newSandboxHolder(cfg, cfgPath, filepath.Dir(cfg.Observer.DBPath), binPath, logger)
	return h, h.workspacesDir(), h
}

func buildTerminalStack(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger, nf *nodeFeaturesHandle) (*terminalStack, error) {
	// Leave the stack unbuilt on an OS with no in-process PTY backend (a
	// native-Windows daemon). A nil stack is the honest "disabled" state: the
	// dashboard "Launch here" button is hidden and the attach socket is not
	// served, rather than either failing on use.
	if !termsession.PTYSupported() {
		// This branch is gated on PTYSupported() alone, so name that cause
		// (audit DI-16). The other way a nil stack arises — [handoff].
		// allow_dashboard_launch = false — is reported where that gate lives
		// (the dashboard's 503, errTerminalUnavailable). The stale "run the
		// daemon under WSL/Linux" has been wrong since ConPTY landed
		// (a6cc151c3, 2026-07-04) — a native Windows daemon runs these
		// terminals fine when it's new enough.
		logger.Info("embedded terminal disabled — unsupported on this OS " +
			"(Windows before 10 version 1809 has no ConPTY; other platforms need a PTY backend); " +
			"dashboard launch + session-attach are unavailable, handoff-doc migration is unaffected")
		return nil, nil
	}
	binPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("buildTerminalStack: resolve observer binary: %w", err)
	}

	// The status event feed (F4 prereq): a bounded in-process fan-out the
	// terminal service publishes launch/exit/correlation events to. Consumers
	// (F4 status) subscribe; it never back-pressures the producer.
	feed := termfeed.New(termfeed.Options{})

	// Resilient-attach Layer 1: the correlation hub is built EARLY (before svc)
	// because svc now wires the hub's DIRECT exit seam (hub.NotifyExit) into
	// termsvc.Options.OnRunExit — the reliable, feed-independent signal the hub
	// keys liveness / flock release / tombstones off (round-4). It subscribes to
	// the feed for advisory correlation only; the exit-driven correctness reaches
	// it through EndRunByHandle, not this subscription.
	hub := newAttachHub(feed, logger)

	// svc is assigned after the manager is built, but the manager's OnExit
	// closure references it by variable so the daemon-observed exit signal can
	// mark the run ended (and publish an exit event). The pre-registration
	// fast-exit gap — a child that exits before termsvc.launch installs the
	// handle→run mapping, so OnExit finds nothing — is closed inside termsvc.launch
	// by an ExitStatus reconcile (wired below), so the exit is recorded (and
	// NotifyExit fired) exactly once regardless of ordering.
	var svc *termsvc.Service

	// The untrusted OSC hint tap (F3): one bounded scanner per PTY handle,
	// turning OSC 133/633/title/BEL hints into TrustHint status events + durable
	// command boundaries. runID is resolved through svc by variable.
	scanHub := newTerminalScanHub(feed, store.New(database), func(handle string) (string, bool) {
		if svc == nil {
			return "", false
		}
		return svc.RunIDForHandle(handle)
	}, logger)

	opts := termsession.Options{
		Logger: logger,
		// Startup seed closes the construction-before-controller-wiring window.
		// wireRemoteExecuteTier replaces this with the live controller reader
		// before either dashboard listener starts serving.
		AllowRemoteTakeover: func() bool { return cfg.Remote.AllowRemoteTerminalTakeover },
	}
	applyTerminalBounds(&opts, cfg.Terminal, logger)
	// Remote writer-lease lifetimes (§4.α.2c) come from [remote]; 0 falls back
	// to the termsession defaults (5m idle / 30m hard cap).
	if cfg.Remote.WriterLeaseIdleMinutes > 0 {
		opts.WriterLeaseIdle = time.Duration(cfg.Remote.WriterLeaseIdleMinutes) * time.Minute
	}
	if cfg.Remote.WriterLeaseMaxMinutes > 0 {
		opts.WriterLeaseMax = time.Duration(cfg.Remote.WriterLeaseMaxMinutes) * time.Minute
	}
	opts.OnOutput = scanHub.Observe
	// Direct process attribution for daemon-launched terminals
	// (terminal_pidseed.go). termsession publishes the PTY child's pid through
	// this content-free callback; the seeder holds it until correlation names
	// the run's agent session, then writes the §9.2.1 pidbridge seed — and
	// retracts it the moment the child is reaped. Nil (no DB) is a clean no-op.
	pidSeeder := newTerminalPidSeeder(database, logger)
	opts.OnProcess = pidSeeder.Observe
	// Metadata-only writer-lease audit tap (Phase-4 execute-tier audit
	// lifecycle, plan §8.1). termsession stays store-free — this cmd-side FUNC
	// SEAM maps each content-free LeaseEvent to a typed remote_audit row.
	opts.OnLeaseEvent = newLeaseAuditSink(database)
	notifier := newRemoteNotifier(cfg, logger)
	// DEFERRED (review B6): this OnExit closure runs on the manager's own exit
	// goroutine and calls svc.EndRunByHandle (a DB write) with a background
	// context. At daemon shutdown that write can, in principle, race the DB
	// close. This is PRE-EXISTING behaviour shared with every terminal launch
	// (handoff/fresh/attach all funnel exits through here) — decoupling attach
	// from the dashboard gate did NOT introduce it; an attach session is just
	// another run recorded through the same seam. A proper fix (track these
	// writes in a WaitGroup the shutdown path joins, or gate them on a shutdown
	// flag) is a broader launch-manager change out of scope here; noted so the
	// race has a documented home.
	opts.OnExit = func(se termsession.SessionExit) {
		if svc != nil {
			svc.EndRunByHandle(context.Background(), se.Handle, se.ExitCode)
		}
		scanHub.Drop(se.Handle)
		if notifier != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if nerr := notifier.Notify(ctx, remotenotify.Event{
				Type:       remotenotify.EventSessionFinished,
				SessionID:  se.SessionID,
				Tool:       se.Subcommand,
				Subcommand: se.Subcommand,
				ExitCode:   se.ExitCode,
				Time:       se.At,
			}); nerr != nil {
				logger.Warn("remote notify: session-finished delivery failed", "err", nerr, "session", se.SessionID)
			}
		}
	}

	mgr := termsession.NewManager(opts)
	launcher := &ptyLauncher{mgr: mgr, binPath: binPath, feed: feed, logger: logger}

	// B9 sandbox seam (plan §1/§9 U5): ONE cmd-side sandboxHolder implementing
	// BOTH termsvc.Sandboxer (Prepare) and dashboard.SandboxProber
	// (ProbeSandbox) over internal/sandbox + internal/workspace, holding the
	// live runtime behind an atomic pointer so a [terminal.sandbox] save takes
	// effect on the next launch instead of the next restart. Resolved
	// out-of-line to keep buildTerminalStack under the gocyclo bound.
	//
	// Fail-closed is unchanged: with the feature off (or a runtime that will
	// not initialize) Prepare returns termsvc.ErrSandboxUnavailable and the
	// probe reports disabled_by_config / runtime_init_failed — the U4/U6
	// states, now told apart instead of flattened into one string.
	//
	// sandboxWorkspacesDir is the ONE managed-workspace root termsvc holds for
	// the daemon's life; moving workspaces_dir at runtime is the one knob that
	// still needs a restart (the holder logs a warning when it sees that).
	sandboxSeam, sandboxWorkspacesDir, sandboxProber := resolveTerminalSandbox(cfg, binPath, logger)

	svc = termsvc.New(termsvc.Options{
		Policy:   terminalLaunchPolicy(cfg.Terminal),
		Recorder: termRunRecorder{st: store.New(database)},
		Launcher: launcher,
		Feed:     feed,
		Logger:   logger,
		// Close the pre-registration exit gap: launch() reconciles a just-spawned
		// handle against the authoritative Manager exit status the instant it
		// installs the mapping (Manager stays the one owner of exit truth).
		ExitStatus: mgr.ExitStatus,
		// The DIRECT per-run exit seam: EndRunByHandle fires this once per run so
		// the attach hub's correctness never rides the lossy status feed.
		OnRunExit: hub.NotifyExit,
		// B9: the sandbox workspace+wrap-argv seam (nil when disabled → a
		// Sandbox:true FreshRequest fails closed with ErrSandboxUnavailable).
		Sandboxer:            sandboxSeam,
		SandboxWorkspacesDir: sandboxWorkspacesDir,
		// T2: the DETACHED IDE / desktop-app spawn seam. It shares this stack's
		// service (one run-identity model, one policy, one recorder, one status
		// feed) but NONE of its PTY machinery — a GUI child has no pseudo-
		// terminal, no OOB channel and no job object (it must outlive the
		// daemon, the exact opposite of a PTY child's contract).
		//
		// FOLLOW-UP (documented, not solved here): the terminal stack is only
		// built when termsession.PTYSupported(), so a host with no PTY backend
		// also gets no GUI launch — even though a detached spawn needs no PTY
		// at all. On Windows 10 1809+ PTYSupported() is true, so this is not a
		// live gap today; decoupling the GUI seam from the PTY stack is a
		// separate change.
		GUILauncher: &guiLauncher{
			proxyPort:  cfg.Proxy.Port,
			configPath: daemonConfigPath,
			resolveEnv: dashResolveEnv,
			logger:     logger,
		},
	})
	// Wire the OOB run->session correlation seam (P2-1): when the launcher
	// wrapper announces the child's agent session id on the trusted OOB channel,
	// drainOOB establishes the link through the service (bySession) so a live
	// attach run's Snapshot carries a session id and "Jump in" can match it.
	// Assigned after svc exists (launcher is svc's Launcher, so the two are
	// mutually referential — the same shape as the OnExit/scanHub closures).
	// correlate is svc.Correlate plus the direct-pid-seed after-effect: whenever
	// a run acquires an ESTABLISHED session link, the terminal's PTY child pid
	// is written into session_pid_bridge so its whole process subtree is
	// attributed directly instead of riding the confidence-scored lazy cwd
	// correlation. Wrapping HERE — at the single point both correlation
	// producers (the OOB drain below and the discovery sweep) are wired from —
	// keeps termsvc the one owner of the link itself.
	correlate := seedingCorrelator(svc.Correlate, pidSeeder, svc)
	launcher.correlate = correlate

	// Generic terminal-run discovery sweep (Session Cockpit part C). A
	// daemon-resident, tool-AGNOSTIC pass that periodically links a LIVE
	// uncorrelated run to a UNIQUE candidate observer session — agreeing on tool +
	// git root + launch time, unique-or-abstain, held across a dwell — at
	// termrun.SourceDiscovered (0.75). It closes the correlation gap for every
	// launcher that has no OOB id echo (only claude-code and codex correlate
	// today; every other launcher's Session Cockpit otherwise waits forever). It
	// reads the SAME svc seams the OOB path uses (HandleForRun = liveness truth;
	// SpawnDir = the directory the run's child actually runs in — NOT
	// ProjectRoot, whose emptiness for a launch with no requested project root
	// used to make this sweep skip the run forever; Correlate = the one
	// scored-link seam) so a stale crash-orphan run from a previous boot simply
	// misses the live-handle lookup and is skipped. Gated on a wired DB, and run on its OWN
	// context so the stack's close func can stop it FIRST — before the H2 shutdown
	// stamps and mgr.Shutdown() — so no in-flight tick write can race the
	// defer-LIFO DB close (the same ordering discipline the H2 stamps rely on).
	stopDiscover := func() {}
	if database != nil {
		disc := newTerminalDiscoverer(
			store.New(database),
			svc.HandleForRun,
			newTerminalNativeResolver(svc.HandleForRun, mgr.ProcessIdentityForHandle, svc.KindForHandle, &cfg),
			svc.SessionLinkForRun,
			svc.SpawnDir,
			correlate,
			func(dir string) string {
				info, gerr := git.Resolve(dir)
				if gerr != nil {
					return dir // unreadable dir: fall back to the raw path (store filter still applies)
				}
				return info.Root
			},
			nil, // now → time.Now (the link timestamp is now().UTC())
			logger,
			defaultTerminalDiscoverConfig(),
		)
		dctx, dcancel := context.WithCancel(context.Background())
		var dwg sync.WaitGroup
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			disc.run(dctx)
		}()
		stopDiscover = func() {
			dcancel()
			dwg.Wait()
		}
	}

	// F4 agent-status hub: fuses the feed (OSC hints + OOB/lifecycle) with
	// termsession output-recency/exit into a per-run status. Gated by
	// [terminal.status].enabled; when off, no provider is wired (endpoints 503).
	var statusProvider dashboard.TerminalStatusProvider
	stopStatus := func() {}
	if cfg.Terminal.Status.Enabled {
		hub := newTerminalStatusHub(
			feed,
			mgr.LastActivity,
			mgr.ExitStatus,
			svc.RunIDForHandle,
			svc.HandleForRun,
			func() []string {
				live := mgr.Snapshot()
				ids := make([]string, 0, len(live))
				for _, s := range live {
					ids = append(ids, s.ID)
				}
				return ids
			},
			termstatus.Thresholds{},
		)
		statusProvider = hub
		stopStatus = hub.Stop
	}

	// Resilient-attach Layer 1: rediscover this daemon's orphaned attach runs so
	// an auto-resume target can be validated (the hub itself was built early,
	// above, so svc could wire its direct exit seam). Additive over the SAME
	// store the rest of the stack already uses.
	resumable := rediscoverResumableSessions(database, logger)

	// H3/H2 durable-resume wiring. attachDir is the attach socket's owner-only
	// directory (the flock lives beside the socket); supersedeResumed stamps the
	// old orphan row after a successful auto-resume, keyed by the PREDECESSOR run
	// id so the fresh replacement (which can correlate to the same session via OOB
	// first) is never touched. Both are gated on a wired DB.
	var attachDir string
	var supersedeResumed func(runIDs []string)
	var resumeAuthority func(sessionID string, excludeRunIDs []string) bool
	if database != nil {
		attachDir = filepath.Dir(attachSocketPath(cfg.Observer.DBPath))
		st := store.New(database)
		supersedeResumed = func(runIDs []string) {
			if len(runIDs) == 0 {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := st.StampResumedByRunIDs(ctx, runIDs); err != nil && logger != nil {
				logger.Warn("attach: stamp resumed orphans failed", "err", err, "runs", runIDs)
			}
		}
		// The DURABLE double-spawn authority (round-5 finding 1): refuse a resume
		// whenever the store already holds a LIVE run correlated to the target
		// session — including a dashboard resume that never rides the attach hub's
		// feed and never takes the resume flock. The in-memory hub guard remains
		// the fast path; this catches everything persisted. The confidence gate is
		// termrun.MinLinkConfidence so a weak heuristic guess never fabricates a
		// conflict (the same ABSTAIN rule the hub applies). Fail OPEN on a query
		// error (return false = no conflict): the hub guard + the H3 flock still
		// apply, and blocking every resume on a transient DB error is the worse
		// failure — matching the best-effort, benign-direction posture of the rest
		// of the resilient-attach path.
		resumeAuthority = func(sessionID string, excludeRunIDs []string) bool {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			live, err := st.LiveRunForSessionExcluding(ctx, sessionID, termrun.MinLinkConfidence, excludeRunIDs)
			if err != nil {
				if logger != nil {
					logger.Warn("attach: live-run authority query failed — falling back to the in-memory guard + flock", "err", err, "session", sessionID)
				}
				return false
			}
			return live
		}
	}

	// Instance switcher forwards. Built over the SAME converted profile list
	// and connection knobs terminalLaunchPolicy hands the terminal service, so
	// the two surfaces can never disagree about which machines exist or how
	// long a connect may take.
	instances := sshforward.New(sshforward.Options{
		Enabled:    cfg.Terminal.Enabled && cfg.Terminal.SSH.Enabled,
		Profiles:   config.SSHProfiles(cfg.Terminal.SSH),
		SSHOptions: config.SSHOptions(cfg.Terminal.SSH),
		Logger:     logger,
	})

	// P7 gateway-arc item 3: acquire the SAME process-wide guard the proxy
	// already primed (acquireProcessGuard is keyed + cached by DB path, so
	// this is a cache hit in the common `observer start` path, not a second
	// build). Nil-safe when no DB is wired or guarding is disabled.
	var procGuard *guard.Guard
	if database != nil {
		procGuard = acquireProcessGuard(ctx, cfg, store.New(database), logger)
	}

	return &terminalStack{
		svc:              svc,
		instances:        instances,
		mgr:              mgr,
		status:           statusProvider,
		sandboxProber:    sandboxProber,
		attachAudit:      newSpawnAuditSink(database, dashboard.SpawnAuditKind(termrun.KindAttach)),
		hub:              hub,
		resumableRuns:    resumable,
		attachDir:        attachDir,
		supersedeResumed: supersedeResumed,
		resumeAuthority:  resumeAuthority,
		reclaimOnInput:   cfg.Terminal.Attach.ReclaimOnInput,
		guard:            procGuard,
		nf:               nf,
		close: func() {
			// Stop the discovery sweep FIRST — before ANY DB write below and before
			// mgr.Shutdown() — and WAIT for its goroutine to drain, so no in-flight
			// tick's Correlate write can race the defer-LIFO DB close that start.go
			// runs after this. No-op when no DB was wired.
			stopDiscover()
			// H2: stamp every LIVE attach run 'daemon_shutdown' SYNCHRONOUSLY,
			// BEFORE mgr.Shutdown() kills the PTYs (whose async OnExit would
			// otherwise race the DB close) and before start.go's defer-LIFO closes
			// the DB. The durable stamp — NOT the racy ended_at — is what makes
			// those runs deterministically resumable-by-restart on the next
			// daemon. Best-effort: a failure only risks a shutdown orphan not
			// being offered (the honest resume hint still fires).
			if database != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				st := store.New(database)
				if n, err := st.StampLiveAttachRunsShutdown(ctx); err != nil {
					if logger != nil {
						logger.Warn("attach: stamp live attach runs at shutdown failed", "err", err)
					}
				} else if n > 0 && logger != nil {
					logger.Info("attach: stamped live attach runs for resumable-on-restart", "count", n)
				}
				// Sibling hygiene sweep: stamp the LIVE non-attach kinds
				// (resume/fresh/handoff) too, so a graceful shutdown never strands
				// them as ended_at-NULL "live" rows in the runs-history view. This is
				// disjoint from the attach sweep above (kind != 'attach') and does not
				// touch the attach resume-offer path.
				if n, err := st.StampLiveNonAttachRunsShutdown(ctx); err != nil {
					if logger != nil {
						logger.Warn("attach: stamp live non-attach runs at shutdown failed", "err", err)
					}
				} else if n > 0 && logger != nil {
					logger.Info("attach: stamped live non-attach runs at shutdown", "count", n)
				}
				cancel()
			}
			stopStatus()
			hub.stop()
			// Retract every direct pid seed while the DB is still open and
			// BEFORE mgr.Shutdown() kills the PTYs — a row left behind would
			// attribute whatever process the OS next hands that pid to a
			// terminal that no longer exists. mgr.Shutdown's own exit edges are
			// then a no-op (the seeder has already dropped the handles).
			pidSeeder.releaseAll()
			// Close every instance-switcher forward BEFORE the PTY shutdown, so
			// no `ssh -N` child outlives the daemon that opened it (there is no
			// reaper that would ever clean one up otherwise).
			instances.Close()
			mgr.Shutdown()
		},
	}, nil
}

// rediscoverResumableSessions builds the AUTO-resume rediscovery map on daemon
// startup (resilient-attach Layer 1, part 2). It queries terminal_run for
// KindAttach runs that have NO recorded end AND a correlated agent session id,
// and returns a map from each such session id to its PREDECESSOR run id. The
// gate — no recorded end — is exactly the "ended by DAEMON DEATH, not child-exit"
// distinction: a child that exits on its own is recorded via termsvc's OnExit →
// EndRunByHandle (ended_at set), so it is NOT resumable-by-restart; a run whose
// daemon was killed before it could record the exit keeps ended_at NULL, so it
// IS an orphan a returning client may auto-resume. The membership half drives the
// validation predicate; the run-id value lets the auto-resume supersede stamp the
// exact predecessor (never the fresh replacement — finding: wrong-run supersede).
// A nil DB (or a query error) yields an empty map, so validation fails closed and
// nothing is superseded. Read-only; the map is a snapshot at startup (in-memory
// on the stack).
func rediscoverResumableSessions(database *sql.DB, logger *slog.Logger) map[string][]string {
	if database == nil {
		return map[string][]string{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runs, err := store.New(database).ListTerminalRuns(ctx, 500)
	if err != nil {
		if logger != nil {
			logger.Warn("attach: rediscover resumable sessions failed — auto-resume validation will reject all targets", "err", err)
		}
		return map[string][]string{}
	}
	set := resumableSessionSet(runs)
	if logger != nil && len(set) > 0 {
		logger.Info("attach: rediscovered orphaned attach sessions eligible for auto-resume", "count", len(set))
	}
	return set
}

// resumableSessionSet is the pure rediscovery gate over a terminal-run history:
// it maps the agent session id of each resumable-by-restart session to the LIST
// of that session's eligible KindAttach PREDECESSOR run ids (newest first), for
// the KindAttach runs that carry a correlated session id. Split out (no DB) so
// the resumability distinction is unit-tested directly.
//
// The value is the FULL list of run ids (not just the newest, and not a bare
// bool) so the auto-resume supersede stamps EVERY eligible predecessor by id
// (StampResumedByRunIDs) rather than by session — a by-session stamp would also
// hit the FRESH replacement run once it correlates to the same session via OOB
// (finding: wrong-run supersede), while stamping only the newest would leave
// OLDER same-session orphans (historical duplicates / prior stamp failures)
// offerable on every future restart (round-4 multi-orphan finding). Newest-first
// input order (ListTerminalRuns) is preserved in each list, so element 0 remains
// the offered predecessor.
//
// Resumability (review finding H2) uses the DURABLE end_reason, not the racy
// ended_at:
//   - end_reason 'resumed'    → already superseded by a prior auto-resume; NEVER
//     re-offer (excluded even though ended_at may be NULL).
//   - end_reason 'child_exit' → a natural exit; NOT resumable.
//   - end_reason 'daemon_shutdown' → stamped synchronously at graceful shutdown;
//     ALWAYS resumable, even if a racing OnExit later set ended_at.
//   - end_reason ” (running or crash orphan) → resumable only while ended_at is
//     NULL (a crash left no record; a live run is legitimately mid-flight and a
//     resume of it is caught downstream by the live-session guard + flock).
func resumableSessionSet(runs []store.TerminalRunSummary) map[string][]string {
	set := make(map[string][]string)
	for _, r := range runs {
		if r.Kind != string(termrun.KindAttach) {
			continue // only owner-terminal attach runs are auto-resumable
		}
		if r.BestSessionID == "" {
			continue // no correlated session ⇒ nothing to resume
		}
		// Defense in depth (attach-all-launchers §3): only a tool with grounded
		// native resume can be auto-resumed — its inner launcher registers
		// `--resume` and reattaches the REAL transcript. The 17 ResumeNone
		// launchers now grounded as attachable have no native resume argv, so an
		// orphaned attach run for one must NEVER enter the offer set (the daemon
		// would compose a `--resume` the inner launcher can't parse). The client
		// gate already refuses, but the registry is static data so this pure
		// gate stays cheap; dispatch on the capability SHAPE, not the tool name
		// (CLAUDE.md #3). Such orphans simply age out via the shutdown stamps.
		if c, ok := integration.For(r.Tool); !ok || c.Resume.Kind != integration.ResumeNative {
			continue
		}
		switch r.EndReason {
		case store.EndReasonResumed, store.EndReasonChildExit:
			continue // superseded, or a clean child exit — not resumable-by-restart
		}
		// Accumulate EVERY eligible orphan for the session (newest first, since
		// the input is newest-first), so a successful resume can supersede all of
		// them, not merely the newest (round-4 multi-orphan finding).
		if r.EndedAt == nil || r.EndReason == store.EndReasonDaemonShutdown {
			set[r.BestSessionID] = append(set[r.BestSessionID], r.RunID)
		}
	}
	return set
}

// launchManager wraps the shared stack in the dashboard.LaunchManager adapter.
// The adapter's remote-execute authorizer stays nil until wireRemoteExecuteTier
// installs it (fail-closed until then). The returned adapter drives the SAME
// svc + mgr the attach host does.
func (s *terminalStack) launchManager() *launchManagerAdapter {
	return &launchManagerAdapter{
		svc:           s.svc,
		mgr:           s.mgr,
		attachAudit:   s.attachAudit,
		instances:     s.instances,
		guard:         s.guard,
		sandboxProber: s.sandboxProber,
		nf:            s.nf,
	}
}

// attachHost builds the session-attach socket Host over the shared stack's
// terminal service + PTY manager — the SAME *termsvc.Service and
// *termsession.Manager the dashboard launch manager drives (session-attach
// design Phase 1). Reusing them (rather than a parallel PTY stack) means an
// attach-launched session's exit is recorded by the shared OnExit closure, its
// writer lease arbitrates against dashboard writers through the one lease model,
// its spawn writes the same metadata-only audit row, and it appears in the same
// Snapshot / status feed as a dashboard launch. Crucially this reaches the
// attach host DIRECTLY off the stack, so it serves even when the dashboard
// launch manager is disabled ([handoff].allow_dashboard_launch = false).
func (s *terminalStack) attachHost() attachsock.Host {
	// Derive the two resume seams from the ONE rediscovery map: a non-empty list
	// is the auto-resume validation predicate; the run-id LIST resolves EVERY
	// predecessor the supersede stamps by exact id — all eligible same-session
	// orphans, never the fresh replacement (finding: wrong-run supersede +
	// round-4 multi-orphan). Reading a nil map is safe (zero value, empty slice).
	resumable := func(sessionID string) bool { return len(s.resumableRuns[sessionID]) > 0 }
	predecessors := func(sessionID string) ([]string, bool) {
		ids := s.resumableRuns[sessionID]
		return ids, len(ids) > 0
	}
	return newAttachHost(s.svc, s.mgr, s.attachAudit).
		withResume(s.hub, resumable).
		withDurableResume(s.attachDir, s.supersedeResumed, predecessors).
		withResumeAuthority(s.resumeAuthority).
		withReclaim(s.reclaimOnInput)
}

// terminalSurfaces is the decoupled per-surface result start.go consumes: the
// dashboard launch manager (nil unless [handoff].allow_dashboard_launch), its
// status provider, and the attach-socket host (nil unless
// [terminal.attach].enabled) — all derived from ONE shared terminalStack, plus
// its single teardown func. A nil field is the honest "surface disabled" state
// for that capability alone; the OTHER surface is unaffected.
type terminalSurfaces struct {
	launchMgr    dashboard.LaunchManager
	launchStatus dashboard.TerminalStatusProvider
	// policyStop resolves a dashboard terminal run's node-intervention
	// policy-stop explanation (policystop.go). Populated whenever launchMgr
	// is (the launch manager's gate is the natural gate for this too — a
	// policy stop only ever concerns a dashboard-launched PTY run); nil
	// otherwise, which is the honest "nothing to show" seam state.
	policyStop dashboard.PolicyStopProvider
	attachHost attachsock.Host
	// sandboxProber is the B9 dashboard.SandboxProber (nil only when NO
	// terminal stack was built at all — no PTY backend, or neither surface
	// requested). start.go / dashboard.go wire it into
	// dashboard.Options.SandboxProber; a nil value is the honest "sandbox
	// feature absent" state (endpoint reports disabled, launch validation
	// 501s), and a non-nil holder with the feature switched off reports the
	// same disabled_by_config verdict while staying able to pick a later
	// save up without a restart.
	sandboxProber dashboard.SandboxProber
	// mgr is the concrete one-owner session manager (nil when no stack was
	// built). Exposed so start.go can register post-construction hooks that
	// need the concrete type (SetOnStandingLocalTakeover) — the dashboard
	// itself keeps talking through the LaunchManager interface.
	mgr   *termsession.Manager
	close func()
}

// buildTerminalSurfaces constructs the shared terminal stack ONCE and derives
// the requested surfaces from it, decoupled: the attach host is wired whenever
// [terminal.attach].enabled is true and the launch manager whenever
// [handoff].allow_dashboard_launch is true, independently. When neither surface
// is requested (or there is no PTY backend) it returns a zero-value result with
// a no-op close and NO stack is built. The single source of the per-surface
// gating truth — shared by `observer start` and its tests.
func buildTerminalSurfaces(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger, nf *nodeFeaturesHandle) (terminalSurfaces, error) {
	surf := terminalSurfaces{close: func() {}}
	// Terminal websocket liveness bounds ([terminal].ws_ping_*). Applied before
	// any bridge can start; non-positive values leave the built-in defaults, and
	// the failure budget is what lets a FROZEN backgrounded mobile tab survive a
	// trip to another app instead of having its bridge reaped inside ~40s.
	dashboard.SetTerminalPingPolicy(
		time.Duration(cfg.Terminal.WSPingIntervalSeconds)*time.Second,
		time.Duration(cfg.Terminal.WSPingTimeoutSeconds)*time.Second,
		cfg.Terminal.WSPingFailuresAllowed,
	)
	// Nothing requested → build no stack (and no PTY reaper goroutine).
	if !cfg.Handoff.AllowDashboardLaunch && !cfg.Terminal.Attach.Enabled {
		return surf, nil
	}
	stack, err := buildTerminalStack(ctx, cfg, database, logger, nf)
	if err != nil {
		return surf, err
	}
	if stack == nil {
		// No PTY backend (logged inside buildTerminalStack) — both surfaces stay
		// honestly disabled.
		return surf, nil
	}
	surf.close = stack.close
	surf.mgr = stack.mgr
	// B9: expose the sandbox prober (nil when the feature is off) so the
	// dashboard's /api/terminal/sandbox + fail-closed launch validation see it.
	// Independent of the launch-manager gate below: the endpoint is always
	// registered and reports honestly whether sandbox support exists.
	surf.sandboxProber = stack.sandboxProber
	// Assign the launch manager only when the gate is on so the field stays a
	// nil interface (not a non-nil interface over a nil pointer) when disabled —
	// the dashboard keys off that nil to hide the button, and
	// wireRemoteExecuteTier's type assertion no-ops on it.
	if cfg.Handoff.AllowDashboardLaunch {
		surf.launchMgr = stack.launchManager()
		surf.launchStatus = stack.status
		surf.policyStop = &policyStopProvider{mgr: stack.mgr, st: store.New(database)}
	}
	if cfg.Terminal.Attach.Enabled {
		surf.attachHost = stack.attachHost()
	}
	return surf, nil
}
