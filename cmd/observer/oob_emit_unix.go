//go:build unix

package main

import (
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termoob"
)

// oobChannel holds the process-wide trusted OOB emitter once a daemon-spawned
// launcher has authenticated the channel. It is set by emitOOBLaunchHello and
// read by announceOOBSession so a launcher command (e.g. `observer claude`,
// running under cobra AFTER main.go opened the channel) can echo the child's
// agent session id back to the daemon on the SAME authenticated channel — no
// second transport (session-attach design Phase 2 / P2-1). The mutex serializes
// the (otherwise sequential) Hello / session-announce / exit writes; encoding
// is single-writer by construction, the lock is cheap insurance.
var (
	oobChanMu  sync.Mutex
	oobEncoder *termoob.Encoder
)

// oob_emit_unix.go is the TRUSTED out-of-band launcher-emission half of F3
// (plan §2.1b / F3 channel (a)). When the observer daemon spawns an
// `observer <tool>` launcher it hands it an inherited pipe write end (fd 3) and
// the OBSERVER_OOB_* env. This process — running as that launcher — authenticates
// the channel with a framed Hello (carrying the run's correlation nonce so the
// daemon can correlate the run to the session it produces at oob confidence) and
// emits lifecycle transitions the daemon cannot forge from the untrusted PTY
// stream. The FD is set close-on-exec so the untrusted tool child never inherits
// it (§2.1b — the child must not be able to write to the trusted channel).
//
// It is best-effort and fail-open: any error leaves the launcher running
// normally (the daemon still observes exit via termsession.Wait).

// emitOOBLaunchHello opens the inherited OOB FD (when present), authenticates
// the channel, emits Hello + launcher_started, and returns a finalizer that
// emits tool_exec_end with the process exit code and closes the FD. When no OOB
// env is present (a normal, non-daemon-spawned invocation) it returns a no-op.
func emitOOBLaunchHello() func(exitCode int) {
	noop := func(int) {}
	fdStr := os.Getenv(envOOBFD)
	auth := os.Getenv(envOOBAuth)
	if fdStr == "" || auth == "" {
		return noop
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil || fd < 3 {
		return noop
	}
	// The OBSERVER_OOB_* env is inherited by EVERY descendant of the launcher
	// (the tool itself, and every hook/subprocess the tool spawns — e.g. the
	// `observer hook claude-code …` processes Claude Code runs), but the pipe
	// itself is close-on-exec and reaches only the launcher. In a descendant,
	// fd 3 is whatever that process happened to open first — for a Go binary
	// that is usually the runtime's own epoll descriptor — so wrapping and
	// closing it blindly crashed hooks with "epollwait on fd 3 failed with 9
	// (EBADF)" and, because a PreToolUse hook exiting non-zero BLOCKS the tool
	// call, randomly blocked ~1 in 4 shell commands (2026-09-02). Only treat the
	// fd as the trusted channel when it really is a pipe or socket.
	if !isPipeOrSocket(fd) {
		return noop
	}
	// Prevent the untrusted tool child from inheriting the trusted channel.
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "observer-oob")
	if f == nil {
		return noop
	}
	enc := termoob.NewEncoder(f)
	if err := enc.WriteHello(termoob.Hello{
		AuthToken:        auth,
		CorrelationToken: os.Getenv(envOOBCorr),
		Tool:             os.Getenv(envOOBTool),
		PID:              os.Getpid(),
	}); err != nil {
		_ = f.Close()
		return noop
	}
	oobChanMu.Lock()
	oobEncoder = enc
	oobChanMu.Unlock()
	_ = enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseLauncherStarted, At: time.Now().UnixNano()})
	return func(exitCode int) {
		oobChanMu.Lock()
		_ = enc.WriteLifecycle(termoob.Lifecycle{
			Phase:    termoob.PhaseToolExecEnd,
			ExitCode: &exitCode,
			At:       time.Now().UnixNano(),
		})
		oobEncoder = nil
		oobChanMu.Unlock()
		_ = f.Close()
	}
}

// isPipeOrSocket reports whether fd is currently open and is a FIFO/pipe or a
// socket — the only shapes the daemon ever hands a launcher as its OOB channel.
// An unopened fd, a regular file, a tty, or an anonymous inode (epoll, eventfd)
// is never the channel.
func isPipeOrSocket(fd int) bool {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return false
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFIFO, syscall.S_IFSOCK:
		return true
	}
	return false
}

// announceOOBSession echoes a KNOWN child agent session id to the daemon on the
// trusted OOB channel (session-attach Phase 2 / P2-1). A launcher command calls
// it once it knows the id the tool will use because it FORCED it (claude's
// `--session-id`) or deterministically reattached it (`--resume <id>`), so the
// daemon can correlate the run at OOB (full) confidence. It is best-effort +
// fail-open: no channel (a normal, non-daemon-spawned invocation) or an empty id
// is a silent no-op, and a write error never affects the launch.
func announceOOBSession(sessionID string) {
	announceOOBSessionSource(sessionID, "")
}

// announceDiscoveredOOBSession echoes a HEURISTICALLY-DISCOVERED child session
// id to the daemon on the trusted OOB channel (session-attach Phase 2 / P2-1).
// Used by the codex discovery path, which cannot force an id (`codex` has no
// `--session-id`) and instead infers this run's rollout file. The channel is
// still unforgeable, but the id rests on a filesystem/timing inference, so the
// frame carries termoob.SessionSourceDiscovered and the daemon records the
// correlation at the lower SourceDiscovered confidence (a later known-id OOB
// echo strictly upgrades it). Same best-effort + fail-open contract.
func announceDiscoveredOOBSession(sessionID string) {
	announceOOBSessionSource(sessionID, termoob.SessionSourceDiscovered)
}

// announceOOBSessionSource is the shared writer for the two announce helpers: it
// emits a single TypeSession frame carrying the id and its Source hint on the
// authenticated channel. The empty source is the KNOWN-id default (claude +
// codex-resume); termoob.SessionSourceDiscovered marks a discovered id.
func announceOOBSessionSource(sessionID, source string) {
	if sessionID == "" {
		return
	}
	oobChanMu.Lock()
	enc := oobEncoder
	if enc != nil {
		_ = enc.WriteSession(termoob.Session{SessionID: sessionID, Source: source})
	}
	oobChanMu.Unlock()
}

// oobChannelActive reports whether this process is a daemon-spawned launcher
// with a live trusted OOB channel — i.e. an announceOOBSession would reach the
// daemon. A launcher command uses it to decide whether to force a session id.
func oobChannelActive() bool {
	oobChanMu.Lock()
	defer oobChanMu.Unlock()
	return oobEncoder != nil
}
