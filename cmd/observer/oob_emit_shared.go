//go:build (unix || windows) && !sbo_omit_terminals

package main

import (
	"sync"

	"github.com/marmutapp/superbased-observer/internal/termoob"
)

// oob_emit_shared.go holds the launcher's OOB emitter state and the
// session announce shared by the unix emitter (the inherited fd 3,
// oob_emit_unix.go) and the Windows one (a sandbox driver's own stream,
// oob_emit_windows.go).

// oobChannel holds the process-wide trusted OOB emitter once a daemon-spawned
// launcher has authenticated the channel. It is set by emitOOBLaunchHello and
// read by announceOOBSession so a launcher command (e.g. `observer claude`,
// running under cobra AFTER main.go opened the channel) can echo the child's
// agent session id back to the daemon on the SAME authenticated channel, no
// second transport (session-attach design Phase 2 / P2-1). The mutex serializes
// the (otherwise sequential) Hello / session-announce / exit writes; encoding
// is single-writer by construction, the lock is cheap insurance.
var (
	oobChanMu  sync.Mutex
	oobEncoder *termoob.Encoder
	// oobBoxClaims: oobEncoder is a sandbox box's own stream to its run's
	// host helper (oob_emit_windows.go), whose frames are untrusted box
	// claims, not the daemon's spawn channel.
	oobBoxClaims bool
)

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
// with a live trusted OOB channel, that is, an announceOOBSession would reach the
// daemon. A launcher command uses it to decide whether to force a session id.
func oobChannelActive() bool {
	oobChanMu.Lock()
	defer oobChanMu.Unlock()
	return oobEncoder != nil
}

// oobChannelSpawnedByDaemon reports whether the live OOB channel is the
// daemon's own: this process is the inner launcher the daemon spawned for an
// attach or dashboard PTY. A sandbox box's stream to its host helper is not
// (Windows 11 Pro run 4: the in-box launcher took the attach decision's
// daemon-spawned row and stayed silent although its stdin and stdout were
// terminals and attach was not available there).
func oobChannelSpawnedByDaemon() bool {
	oobChanMu.Lock()
	defer oobChanMu.Unlock()
	return oobEncoder != nil && !oobBoxClaims
}
