package main

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
)

// terminal_pidseed.go closes the process-attribution gap for terminals the
// daemon itself launches (the dashboard "⊙ Session" button and the owner-only
// session-attach socket).
//
// THE GAP. Direct process attribution — the §9.2.1 pid seed in
// session_pid_bridge — has historically been written by exactly one producer:
// the Claude Code SessionStart hook's ancestor walk. Every other AI tool falls
// through to the confidence-scored lazy cwd correlation
// (store.CorrelateCrossOS), which is why the process panels are blank for most
// tools (docs/audits/process-attribution-coverage-audit-2026-07-15.md).
// Meanwhile internal/termsession already KNOWS the pid of the `observer <tool>`
// child it spawned — it uses it for the process-group reap and then discards
// it. This file is the seam that stops discarding it.
//
// SEEDING STRATEGY: ON CORRELATION, NOT AT SPAWN.
// A pidbridge row is (pid → session_id); Store.Write REJECTS an empty session
// id by construction, and every reader (the proxy's ProcResolver ancestor
// walk, the process observer's SeedLookup) treats the row as authoritative
// HIGH-confidence identity. So the row can only be written once a REAL agent
// session id exists:
//
//   - The terminal RUN id is not a session id. Writing it into the session_id
//     column would fabricate identity: the proxy would resolve a session that
//     does not exist and stamp it onto api_turns, corrupting cost attribution.
//     That is fighting the contract, not composing with it.
//   - Spec.SessionID is NOT usable either. For the dominant handoff launch it
//     is the SOURCE session the run continues FROM, and migration
//     064_terminal_run.sql's identity invariant is explicit that the source and
//     any correlated target session are DISTINCT and must never be conflated.
//   - The run→session link already exists as a first-class, scored concept
//     (terminal_run_session) with exactly one owner: termsvc.Service.Correlate.
//     Hooking the seed to it means one owner and one moment, with no parallel
//     mechanism — and it inherits the link's own MAX-upgrade + min-confidence
//     policy for free.
//
// So: the pid is RECORDED at spawn (that is the only moment it is knowable) and
// the bridge row is WRITTEN the instant correlation establishes which session
// the run belongs to.
//
// PID REUSE. The pid is retracted on the ProcessExited edge, which termsession
// fires INLINE from the waiting goroutine the moment the child is reaped, and
// the delete is SCOPED to the session id this seeder wrote — so it can neither
// leave a stale row (a recycled pid silently inheriting a dead terminal's
// session) nor delete a row a later writer has already claimed for the same
// pid. The daemon's own shutdown path calls releaseAll for the same reason.

// terminalRunResolver is the read-only slice of *termsvc.Service the seeder
// needs to turn a correlated run id into (live handle, session id, canonical
// tool, project root). Declared as an interface here — not taken as a concrete
// service — so the seeder is unit-testable without standing up a Service, and
// so it can never reach for anything beyond these four reads.
type terminalRunResolver interface {
	// HandleForRun maps a run id to its LIVE PTY handle; ok=false once the run
	// has ended, which is also the seeder's liveness gate.
	HandleForRun(runID string) (string, bool)
	// SessionLinkForRun returns the ESTABLISHED (>= termrun.MinLinkConfidence)
	// correlated session for a run, after the service's MAX-upgrade.
	SessionLinkForRun(runID string) (sessionID string, confidence float64, ok bool)
	// KindForHandle returns the run kind + CANONICAL tool name for a handle
	// (the launcher verb alone is not the tool the pidbridge keys on).
	KindForHandle(handle string) (termrun.Kind, string, bool)
	// SpawnDir returns the directory the run's child process actually runs in:
	// the validated launch root when the launch carried one, otherwise the
	// daemon's cwd the child inherits. It is deliberately NOT ProjectRoot, whose
	// empty answer for a launch with no authorized project root would record a
	// pid-bridge row with no working directory at all.
	SpawnDir(handle string) (string, bool)
}

// pidSeedWriteTimeout bounds every DB call the seeder makes. The retract path
// runs on termsession's waitExit goroutine, so an unbounded write there could
// stall session teardown (and therefore Manager.Shutdown).
const pidSeedWriteTimeout = 3 * time.Second

// seededTerminal is the seeder's per-handle state: the pid recorded at spawn
// plus whatever identity has been written for it so far.
type seededTerminal struct {
	pid        int
	subcommand string
	dir        string
	// sessionID is the session currently WRITTEN into the bridge for pid, or ""
	// when nothing has been written yet. It is what the retract is scoped to.
	sessionID string
}

// terminalPidSeeder writes (and retracts) direct process-attribution seeds for
// daemon-launched terminals. Safe for concurrent use. A nil *terminalPidSeeder
// is a valid no-op receiver, so the caller can wire it unconditionally.
type terminalPidSeeder struct {
	write  func(ctx context.Context, e pidbridge.Entry) error
	delete func(ctx context.Context, pid int, sessionID string) (bool, error)
	logger *slog.Logger

	mu   sync.Mutex
	live map[string]*seededTerminal
}

// newTerminalPidSeeder builds a seeder over the daemon's DB. It returns nil
// when no DB is wired — the seam then stays a clean no-op rather than the
// caller having to branch.
func newTerminalPidSeeder(database *sql.DB, logger *slog.Logger) *terminalPidSeeder {
	if database == nil {
		return nil
	}
	bridge := pidbridge.New(database)
	return newTerminalPidSeederWith(bridge.Write, bridge.Delete, logger)
}

// newTerminalPidSeederWith builds a seeder over injected store functions. This
// is the constructor tests use; production goes through newTerminalPidSeeder.
func newTerminalPidSeederWith(
	write func(ctx context.Context, e pidbridge.Entry) error,
	del func(ctx context.Context, pid int, sessionID string) (bool, error),
	logger *slog.Logger,
) *terminalPidSeeder {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(nopWriter{}, nil))
	}
	return &terminalPidSeeder{
		write:  write,
		delete: del,
		logger: logger,
		live:   make(map[string]*seededTerminal),
	}
}

// nopWriter discards logger output for a seeder built without one.
type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// Observe is the termsession.Options.OnProcess sink. It records the PTY child
// pid at spawn and retracts any seed written for it at exit. Never blocks on
// anything unbounded (see pidSeedWriteTimeout).
func (s *terminalPidSeeder) Observe(ev termsession.ProcessEvent) {
	if s == nil || ev.Handle == "" || ev.PID <= 0 {
		return
	}
	switch ev.Kind {
	case termsession.ProcessSpawned:
		s.mu.Lock()
		s.live[ev.Handle] = &seededTerminal{
			pid:        ev.PID,
			subcommand: ev.Subcommand,
			dir:        ev.Dir,
		}
		s.mu.Unlock()
	case termsession.ProcessExited:
		s.mu.Lock()
		t := s.live[ev.Handle]
		delete(s.live, ev.Handle)
		s.mu.Unlock()
		if t == nil || t.sessionID == "" {
			return // nothing was ever written for this pid
		}
		s.retract(t.pid, t.sessionID)
	}
}

// OnRunCorrelated writes the direct pid seed for a run that has just acquired
// an established session link. It is called AFTER the one owner of run→session
// correlation (termsvc.Service.Correlate) has persisted the link, so it only
// ever mirrors an identity the store already agreed on. Best-effort and
// fail-open: a resolver miss, a dead run, or a write error degrades to a
// DEBUG/WARN and never affects the correlation itself.
func (s *terminalPidSeeder) OnRunCorrelated(ctx context.Context, runID string, res terminalRunResolver) {
	if s == nil || runID == "" || res == nil || s.write == nil {
		return
	}
	handle, ok := res.HandleForRun(runID)
	if !ok || handle == "" {
		return // the run already ended; its pid is not an attribution target
	}
	sessionID, _, ok := res.SessionLinkForRun(runID)
	if !ok || sessionID == "" {
		return // only an ESTABLISHED link (>= termrun.MinLinkConfidence) seeds
	}

	s.mu.Lock()
	t := s.live[handle]
	var pid int
	var subcommand, dir string
	if t != nil {
		pid, subcommand, dir = t.pid, t.subcommand, t.dir
		if t.sessionID == sessionID {
			s.mu.Unlock()
			return // already seeded with this identity — idempotent
		}
	}
	s.mu.Unlock()
	if pid <= 0 {
		return // not a daemon-launched terminal we recorded (or already exited)
	}

	tool := subcommand
	if _, canonical, kok := res.KindForHandle(handle); kok && canonical != "" {
		tool = canonical
	}
	cwd := dir
	if spawnDir, sok := res.SpawnDir(handle); sok && spawnDir != "" {
		cwd = spawnDir
	}
	if tool == "" {
		return // pidbridge.Write requires a tool; never write a half-identity
	}

	wctx, cancel := context.WithTimeout(ctx, pidSeedWriteTimeout)
	defer cancel()
	if err := s.write(wctx, pidbridge.Entry{PID: pid, SessionID: sessionID, Tool: tool, CWD: cwd}); err != nil {
		s.logger.Warn("terminal pid seed: write failed (attribution falls back to lazy correlation)",
			"run", runID, "pid", pid, "err", err)
		return
	}

	// Re-check liveness under the lock before recording ownership. The write
	// above ran unlocked, so the child may have exited (and its retract already
	// run, finding sessionID=="") in the meantime — recording ownership now
	// would leave a row nothing will ever delete. Retract it immediately
	// instead: a stale row is a WRONG attribution once the pid is recycled.
	s.mu.Lock()
	cur, stillLive := s.live[handle]
	if stillLive && cur.pid == pid {
		cur.sessionID = sessionID
		s.mu.Unlock()
		s.logger.Debug("terminal pid seed: direct attribution seeded",
			"run", runID, "handle_len", len(handle), "pid", pid, "tool", tool, "session", sessionID)
		return
	}
	s.mu.Unlock()
	s.retract(pid, sessionID)
}

// releaseAll retracts every seed this seeder still owns. The daemon calls it
// during terminal-stack teardown, BEFORE the PTY manager is shut down and the
// DB is closed, so a daemon restart can never leave rows whose pids the OS is
// free to recycle.
func (s *terminalPidSeeder) releaseAll() {
	if s == nil {
		return
	}
	s.mu.Lock()
	owned := make([]seededTerminal, 0, len(s.live))
	for handle, t := range s.live {
		if t.sessionID != "" {
			owned = append(owned, *t)
		}
		delete(s.live, handle)
	}
	s.mu.Unlock()
	for _, t := range owned {
		s.retract(t.pid, t.sessionID)
	}
}

// retract deletes the bridge row this seeder wrote, scoped to the session id it
// wrote — so a row another writer has since claimed for a recycled pid is left
// alone. Fail-open: a delete error is a WARN, never fatal.
func (s *terminalPidSeeder) retract(pid int, sessionID string) {
	if s.delete == nil || pid <= 0 || sessionID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), pidSeedWriteTimeout)
	defer cancel()
	if _, err := s.delete(ctx, pid, sessionID); err != nil {
		s.logger.Warn("terminal pid seed: retract failed (stale pid row may mis-attribute a recycled pid)",
			"pid", pid, "session", sessionID, "err", err)
	}
}

// seedingCorrelator wraps a run→session correlation function so that a
// successful correlation ALSO writes the direct pid seed. The wrapper shape
// keeps the seeder off termsvc's own API surface: correlation stays the one
// owner of the link, and this is a pure after-effect at the single cmd-side
// wiring point both correlation producers (the OOB drain and the discovery
// sweep) already share. A nil seeder returns correlate unchanged.
func seedingCorrelator(
	correlate func(ctx context.Context, runID, sessionID string, source termrun.Source, at time.Time) error,
	seeder *terminalPidSeeder,
	res terminalRunResolver,
) func(ctx context.Context, runID, sessionID string, source termrun.Source, at time.Time) error {
	if seeder == nil || correlate == nil || res == nil {
		return correlate
	}
	return func(ctx context.Context, runID, sessionID string, source termrun.Source, at time.Time) error {
		if err := correlate(ctx, runID, sessionID, source, at); err != nil {
			return err
		}
		seeder.OnRunCorrelated(ctx, runID, res)
		return nil
	}
}
