package attachsock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// handshakeTimeout bounds how long the server waits for a client's spawn frame
// before giving up on the connection, so a dead client cannot hold a connection
// open pre-spawn. Long-lived idle connections AFTER spawn are normal (an
// attached agent may sit at a prompt), so no per-frame read deadline applies
// once the session is live.
const handshakeTimeout = 5 * time.Second

// exitPollTimeout bounds how long the output pump waits, after the PTY output
// stream hits EOF, for the child's exit code to become observable via
// Session.ExitCode. The manager records the exit slightly after the pty master
// closes, so a short poll avoids racing a known code into an "unknown" report
// (A4). If it stays unknown past the budget we send exit{known:false} and the
// client reports an honest failure instead of a fabricated 0.
const (
	exitPollTimeout  = 2 * time.Second
	exitPollInterval = 20 * time.Millisecond
)

// shutdownGrace bounds how long Serve waits for in-flight connection handlers to
// drain after ctx cancel before returning, so a wedged handler cannot pin
// shutdown forever (A6).
const shutdownGrace = 3 * time.Second

// SpawnRequest is the server-side view of a client's spawn control frame.
type SpawnRequest struct {
	// Tool is the target tool name (e.g. "claude-code").
	Tool string
	// Subcommand is the observer launcher verb (e.g. "claude").
	Subcommand string
	// Dir is the requested child cwd ("" = launcher default).
	Dir string
	// Rows / Cols are the initial PTY size.
	Rows uint16
	Cols uint16
	// Env is the extra child environment ("KEY=VALUE") the launcher forwards:
	// the tool's proxy-routing / profile vars AND — when
	// [terminal.attach].forward_auth_env is on — the caller's provider-
	// credential values (forwardAuthEnv). CREDENTIAL-BEARING: entries may carry
	// secret values; they transit the owner-only attach endpoint (a 0600 AF_UNIX
	// socket in a 0700 dir, or a named pipe with an owner-only protected DACL —
	// see the Transport seam) once per launch and must NEVER be logged or
	// persisted.
	Env []string
	// ExtraArgs are the allow-listed argv tokens appended to the inner
	// `observer <Subcommand>` launcher (routing escape hatch + `--` tool
	// remainder). Explicit + allow-listed by the client (B2/B3).
	ExtraArgs []string
	// AutoResumeCapable is true when the client understands the frameCorrelated
	// announce (resilient-attach Layer 1); the server pushes that frame only
	// then. Absent for a pre-Layer-1 client (decoded false).
	AutoResumeCapable bool
	// ResumeSession is the agent session id this attach resumes (any resume-
	// attach), used by the Host's double-spawn guard. Empty for a non-resume
	// attach.
	ResumeSession string
	// AutoResume marks a daemon-death auto-resume (vs a user-initiated resume),
	// so the Host applies the rediscovered-orphan validation gate only then.
	AutoResume bool
}

// CorrelatedSession is one correlated-session announcement the server relays to
// an AutoResumeCapable client as a frameCorrelated frame. SessionID is always a
// REAL id (the producer abstains on an unresolved correlation — it never emits a
// fabricated one). Source/Confidence carry the provenance the client surfaces.
type CorrelatedSession struct {
	SessionID  string
	Source     string
	Confidence float64
}

// CorrelationSource is an OPTIONAL capability a Session may implement to feed
// the server correlated-session announcements (resilient-attach Layer 1). When a
// Session implements it AND the client advertised AutoResumeCapable, the server
// relays each announcement as a frameCorrelated frame. A Session that does not
// implement it (or whose run never correlates) simply never sends the frame —
// the client then has no auto-resume target and degrades to the resume hint.
type CorrelationSource interface {
	// CorrelatedSessions returns a channel delivering correlation announcements
	// for this session's run. The implementation MUST close the channel when the
	// session ends (Detach), so the server's relay goroutine exits.
	CorrelatedSessions() <-chan CorrelatedSession
}

// Session is a daemon-owned PTY the server bridges to one attach client. It is
// satisfied by a cmd adapter over the termsession Manager (Subscribe +
// AcquireWriterLocal).
type Session interface {
	// Handle is the opaque PTY handle (also the dashboard join key).
	Handle() string
	// RunID is the run identity minted for this attach launch.
	RunID() string
	// Output returns a replay-then-tail reader over the PTY ring. Its Read
	// returns io.EOF once the child has exited and the ring is drained; any
	// other error (e.g. the viewer was unsubscribed on Detach) means "stop
	// streaming" without implying the child died.
	Output() io.Reader
	// Write forwards raw bytes to the PTY (the client's keystrokes). A write
	// that returns ErrWriterRevoked means the writer lease was fenced out (a
	// dashboard/other seat took over) while the PTY session lives on — the
	// server relays a non-fatal CodeWriterRevoked notice and keeps streaming.
	Write([]byte) (int, error)
	// Resize resizes the PTY.
	Resize(rows, cols uint16) error
	// ExitCode returns the child's exit code once known.
	ExitCode() (int, bool)
	// Detach releases the writer lease and unsubscribes the viewer WITHOUT
	// killing the child — the PTY lives on for the dashboard and other viewers.
	// It must be safe to call more than once.
	Detach()
}

// Reclaimer is an OPTIONAL capability a Session may implement so the server can
// RE-ACQUIRE the writer for a native-terminal attach client whose writer lease
// was revoked (Feature 1: native-terminal reclaim). When a stdin chunk is fenced
// out (ErrWriterRevoked) and its first byte is a real typed key — NOT ESC —
// the server calls ReclaimWriter and, on success, RE-DELIVERS the chunk and
// notifies the client with CodeWriterReclaimed. A Session that does not implement
// it, or whose ReclaimWriter returns an error (e.g. reclaim-on-input disabled by
// config, or the re-acquire failed), keeps today's fence-and-notify behavior
// (CodeWriterRevoked). The reclaim MUST route through the same local-acquire
// funnel the dashboard uses so the standing-remote-takeover hook keeps firing —
// attachsock never sees that; it only asks the Session to reclaim.
type Reclaimer interface {
	// ReclaimWriter re-takes the local writer lease for this attach session.
	// nil means the session's write path now reaches the PTY again.
	ReclaimWriter() error
}

// ReclaimAvailabler is an OPTIONAL companion to Reclaimer: a Session that can
// report whether reclaim-on-input is currently enabled. The server uses it only
// to WORD the takeover notice — so it tells the operator to press a key to take
// control back ONLY when that gesture will actually reclaim (reclaim-on-input
// on). A Session that does not implement it is treated as "unknown ⇒ don't
// promise reclaim", preserving the neutral wording.
type ReclaimAvailabler interface {
	// ReclaimAvailable reports whether a real keystroke will reclaim the writer.
	ReclaimAvailable() bool
}

// Host launches daemon-owned PTYs on behalf of attach clients.
type Host interface {
	// LaunchAttachable spawns a PTY for req and returns the live Session, or an
	// error the server relays as a spawn_failed control frame.
	LaunchAttachable(ctx context.Context, req SpawnRequest) (Session, error)
}

// server holds shared state for one Serve loop.
type server struct {
	host   Host
	logger *slog.Logger

	wg    sync.WaitGroup // tracks in-flight connection handlers (A6)
	mu    sync.Mutex
	conns map[*frameConn]net.Conn
}

// Serve accepts attach connections on ln until ctx is canceled or ln fails.
// Each connection is handled in its own goroutine: read the spawn frame, launch
// via host, reply spawned, then bridge PTY output ↔ client stdin/resize until
// the child exits (exit frame) or the client detaches/drops (Session.Detach,
// child lives on). On ctx cancel every live connection gets a best-effort
// daemon_shutdown error frame and is closed. A clean shutdown returns nil.
func Serve(ctx context.Context, ln net.Listener, host Host, logger *slog.Logger) error {
	if host == nil {
		return errors.New("attachsock.Serve: nil host")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &server{host: host, logger: logger, conns: make(map[*frameConn]net.Conn)}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		s.broadcastShutdown()
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// Graceful shutdown: the ctx-cancel goroutine has closed the
				// listener and broadcast a shutdown frame + closed every live
				// conn. Wait (bounded) for the handlers to drain so we don't
				// return while goroutines still touch the host/PTY (A6).
				s.waitHandlers(shutdownGrace)
				return nil
			}
			return fmt.Errorf("attachsock.Serve: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(ctx, nc)
		}()
	}
}

// waitHandlers blocks until every in-flight connection handler returns, or
// grace elapses — whichever comes first. Bounded so a single wedged handler
// cannot pin daemon shutdown (A6).
func (s *server) waitHandlers(grace time.Duration) {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(grace):
		if s.logger != nil {
			s.logger.Warn("attachsock: shutdown grace elapsed with connection handlers still in flight")
		}
	}
}

// track/untrack maintain the live-connection set for shutdown broadcast.
func (s *server) track(fc *frameConn, nc net.Conn) {
	s.mu.Lock()
	s.conns[fc] = nc
	s.mu.Unlock()
}

func (s *server) untrack(fc *frameConn) {
	s.mu.Lock()
	delete(s.conns, fc)
	s.mu.Unlock()
}

// broadcastShutdown sends a daemon_shutdown error to every live connection and
// closes it. Best-effort: send/close errors are ignored.
func (s *server) broadcastShutdown() {
	s.mu.Lock()
	live := make([]struct {
		fc *frameConn
		nc net.Conn
	}, 0, len(s.conns))
	for fc, nc := range s.conns {
		live = append(live, struct {
			fc *frameConn
			nc net.Conn
		}{fc, nc})
	}
	s.mu.Unlock()
	for _, c := range live {
		_ = c.fc.sendError(CodeDaemonShutdown, "observer daemon is shutting down")
		_ = c.nc.Close()
	}
}

// serveConn handles a single attach connection end to end.
func (s *server) serveConn(ctx context.Context, nc net.Conn) {
	fc := newFrameConn(nc)
	s.track(fc, nc)
	defer s.untrack(fc)
	defer func() { _ = nc.Close() }()

	// Handshake: bounded wait for the spawn frame so a dead pre-spawn client
	// cannot pin the connection.
	_ = nc.SetReadDeadline(time.Now().Add(handshakeTimeout))
	sm, err := s.readSpawn(fc)
	if err != nil {
		if errors.Is(err, ErrProtocol) {
			_ = fc.sendError(CodeProtocol, err.Error())
		}
		return
	}
	_ = nc.SetReadDeadline(time.Time{}) // clear; idle live connections are fine

	sess, err := s.host.LaunchAttachable(ctx, SpawnRequest{
		Tool:              sm.Tool,
		Subcommand:        sm.Subcommand,
		Dir:               sm.Dir,
		Rows:              sm.Rows,
		Cols:              sm.Cols,
		Env:               sm.Env,
		ExtraArgs:         sm.ExtraArgs,
		AutoResumeCapable: sm.AutoResumeCapable,
		ResumeSession:     sm.ResumeSession,
		AutoResume:        sm.AutoResume,
	})
	if err != nil {
		// A resume-guard refusal maps to its own code so the client prints why
		// and does NOT spawn a duplicate / loop; every other launch failure is a
		// generic spawn_failed (Layer-1 double-spawn guard + orphan validation).
		_ = fc.sendError(spawnErrorCode(err), err.Error())
		return
	}

	// Detach exactly once, whether the child exits or the client drops. Detach
	// never kills the child — it lives on for the dashboard/other viewers.
	var detachOnce sync.Once
	detach := func() { detachOnce.Do(sess.Detach) }
	defer detach()

	if err := fc.sendControl(spawnedMsg{Op: opSpawned, Handle: sess.Handle(), RunID: sess.RunID()}); err != nil {
		return
	}

	// Correlation relay (resilient-attach Layer 1): when the client advertised
	// AutoResumeCapable AND the Session can source correlation announcements,
	// push each REAL correlated-session id as a frameCorrelated frame so the
	// client retains an auto-resume target. Gated on the capability so a pre-
	// Layer-1 client never receives an unknown frame. Tracked in the shutdown
	// WaitGroup like the output pump. The relay ends when the Session's channel
	// closes (Detach) or a frame write fails.
	if sm.AutoResumeCapable {
		if cs, ok := sess.(CorrelationSource); ok {
			if ch := cs.CorrelatedSessions(); ch != nil {
				s.wg.Add(1)
				go func() {
					defer s.wg.Done()
					s.relayCorrelations(fc, ch)
				}()
			}
		}
	}

	// Output pump: PTY ring → frameOutput frames. io.EOF ⇒ child exit ⇒ send
	// exit frame then close the connection to unblock the read loop. Tracked in
	// the shutdown WaitGroup so a graceful shutdown waits for it too, not just
	// the read-loop handler (A2-5).
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.pumpOutput(fc, nc, sess)
	}()

	// Read loop: client stdin/resize/detach → PTY. Ends on client drop, detach,
	// child exit (conn closed by the pump), or a protocol violation.
	s.readLoop(fc, sess)
}

// readSpawn reads and validates the initial spawn control frame.
func (s *server) readSpawn(fc *frameConn) (spawnMsg, error) {
	t, payload, err := fc.readFrame()
	if err != nil {
		return spawnMsg{}, err
	}
	if t != frameControl {
		return spawnMsg{}, fmt.Errorf("%w: expected a control spawn frame, got type %d", ErrProtocol, t)
	}
	op, err := peekOp(payload)
	if err != nil {
		return spawnMsg{}, err
	}
	if op != opSpawn {
		return spawnMsg{}, fmt.Errorf("%w: expected op %q, got %q", ErrProtocol, opSpawn, op)
	}
	var sm spawnMsg
	if err := unmarshalControl(payload, &sm); err != nil {
		return spawnMsg{}, err
	}
	if sm.V != ProtocolVersion {
		return spawnMsg{}, fmt.Errorf("%w: unsupported protocol version %d (want %d)", ErrProtocol, sm.V, ProtocolVersion)
	}
	if sm.Tool == "" || sm.Subcommand == "" {
		return spawnMsg{}, fmt.Errorf("%w: spawn requires tool and subcommand", ErrProtocol)
	}
	return sm, nil
}

// pumpOutput copies the PTY ring to the client, terminating the session on
// child exit.
func (s *server) pumpOutput(fc *frameConn, nc net.Conn, sess Session) {
	buf := make([]byte, dataFrameMax)
	out := sess.Output()
	for {
		n, err := out.Read(buf)
		if n > 0 {
			if werr := fc.writeData(frameOutput, buf[:n]); werr != nil {
				_ = nc.Close()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// EOF on the output ring means the child's PTY closed. The
				// manager records the exit code slightly after the master
				// closes, so poll briefly (A4) rather than reporting whatever
				// ExitCode returns this instant — a not-yet-known code must be
				// reported as unknown, never fabricated as 0.
				code, known := s.awaitExitCode(sess)
				_ = fc.sendControl(exitMsg{Op: opExit, Code: code, Known: known})
			}
			// Either the child exited (exit frame sent above) or the viewer was
			// unsubscribed on Detach / the conn broke — in every case stop and
			// unblock the read loop.
			_ = nc.Close()
			return
		}
	}
}

// relayCorrelations forwards correlated-session announcements to the client as
// frameCorrelated frames until the channel closes (session ended) or a write
// fails (the conn is gone — the read/output loops handle the teardown). It
// forwards only announcements carrying a REAL session id; an empty id is dropped
// (defensive — the producer already abstains). A write error simply ends the
// relay; it never tears the session down (the output pump owns exit).
func (s *server) relayCorrelations(fc *frameConn, ch <-chan CorrelatedSession) {
	for c := range ch {
		if c.SessionID == "" {
			continue
		}
		if err := fc.sendCorrelated(correlatedMsg{
			SessionID:  c.SessionID,
			Source:     c.Source,
			Confidence: c.Confidence,
		}); err != nil {
			return
		}
	}
}

// spawnErrorCode maps a Host launch error to the wire error code the client
// keys off. A resume-guard refusal (double-spawn / not-a-daemon-death-orphan)
// gets its own code so the client prints why and neither loops nor spawns a
// duplicate; anything else is a generic spawn_failed.
func spawnErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrResumeConflict):
		return CodeResumeConflict
	case errors.Is(err, ErrResumeNotResumable):
		return CodeResumeNotResumable
	default:
		return CodeSpawnFailed
	}
}

// awaitExitCode polls Session.ExitCode until it becomes known or exitPollTimeout
// elapses. Returns (code, known); known=false means the daemon could not
// determine the exit within the budget (A4).
func (s *server) awaitExitCode(sess Session) (int, bool) {
	deadline := time.Now().Add(exitPollTimeout)
	for {
		if code, ok := sess.ExitCode(); ok {
			return code, true
		}
		if time.Now().After(deadline) {
			return 0, false
		}
		time.Sleep(exitPollInterval)
	}
}

// escByte is the leading byte a fenced stdin chunk must NOT carry to trigger a
// native-terminal reclaim: ESC (0x1b).
const escByte = 0x1b

// machineReplySuppressWindow is how long after a machine-led fenced drop a
// non-machine-led chunk is still refused reclaim: a terminal reply split across
// two stdin reads delivers an ESC-led head and a bare `[6;1R`-style tail — the
// tail must not reclaim just because its first byte is printable. Machine reply
// fragments arrive within milliseconds; human follow-up typing lands well past
// this window (and a keystroke swallowed inside it merely stays fenced — the
// next one reclaims). A var (not const) solely so tests can tighten or disable
// the window race-free before starting a server.
var machineReplySuppressWindow = 300 * time.Millisecond

// machineLedByte reports whether a fenced chunk's first byte marks it as a
// terminal-emulator machine reply rather than a human keystroke: ESC (7-bit
// sequence introducer) or an 8-bit C1 control (0x80–0x9F — CSI 0x9b, DCS 0x90,
// OSC 0x9d as emitted by S8C1T-mode emulators). A split multi-byte UTF-8 rune
// can also land in 0x80–0xBF; refusing reclaim for it is the safe failure
// (stays fenced, next keystroke reclaims).
func machineLedByte(b byte) bool { return b == escByte || (b >= 0x80 && b <= 0x9f) }

// fencedState is readLoop-local (single-goroutine) classification state carried
// across fenced stdin chunks on one attach connection.
type fencedState struct {
	// lastMachineDrop is when a machine-led fenced chunk was last dropped;
	// non-machine-led chunks inside machineReplySuppressWindow of it are treated
	// as split-reply tails and refused reclaim. Only machine-led chunks refresh
	// it — a long paste body can therefore still reclaim past the window, which
	// is the documented residual (docs/session-handoff.md).
	lastMachineDrop time.Time
}

// handleFencedWrite decides what to do with a stdin chunk the session fenced out
// because the attach client's writer lease was revoked (a dashboard Jump-in took
// control). It either RECLAIMS the writer for this native terminal and
// re-delivers the chunk (Feature 1), or surfaces the non-fatal revoked notice.
func (s *server) handleFencedWrite(fc *frameConn, sess Session, payload []byte, st *fencedState) {
	// NATIVE-TERMINAL RECLAIM CLASSIFICATION (Feature 1). A fenced chunk reclaims
	// the writer ONLY when reclaim is available (the Session implements Reclaimer
	// and its ReclaimWriter succeeds) AND the chunk begins with a real typed key —
	// not a machine-led byte, and not inside the split-reply suppress window.
	//
	// The machine-led exclusion is load-bearing and is the whole reason this is
	// byte-classified: a TUI app emits terminal QUERIES on its output — a
	// cursor-position report request (ESC[6n), a Device-Attributes request
	// (ESC[c) — which the native terminal EMULATOR auto-answers by writing
	// ESC-prefixed (or 8-bit C1-prefixed) replies back on stdin, with NO human at
	// the keyboard. If those machine bytes reclaimed control, the dashboard's
	// writer would be stolen the instant a TUI redrew itself, with nobody typing.
	// So only a chunk that leads with a real key (a printable byte or Enter),
	// clear of a just-dropped machine reply, reclaims; everything else stays
	// fenced and dropped exactly as before.
	machineLed := len(payload) > 0 && machineLedByte(payload[0])
	if machineLed {
		st.lastMachineDrop = time.Now()
	}
	suppressed := time.Since(st.lastMachineDrop) < machineReplySuppressWindow
	if r, ok := sess.(Reclaimer); ok && len(payload) > 0 && !machineLed && !suppressed {
		if rerr := r.ReclaimWriter(); rerr == nil {
			if _, werr := sess.Write(payload); werr == nil {
				// The reclaimed lease delivered this very chunk; tell the client
				// its keystrokes are landing again (re-notifiable per transition).
				_ = fc.sendError(CodeWriterReclaimed, "You're back in control of this terminal — keep typing.")
				return
			}
		}
	}
	// Not reclaimed (machine-led, split-reply-suppressed, reclaim disabled /
	// unavailable, or the re-acquire / re-delivery failed): the lease stays
	// fenced. Surface the revoked notice once (the client dedupes) and keep
	// streaming output (A5).
	_ = fc.sendError(CodeWriterRevoked, revokedNotice(sess))
}

// revokedNotice returns the operator-facing takeover message. When reclaim-on-
// input is live it guides the operator to the reclaim gesture (press a key);
// otherwise it states plainly that input won't land from here — never promising
// a key press that would do nothing.
func revokedNotice(sess Session) string {
	if ra, ok := sess.(ReclaimAvailabler); ok && ra.ReclaimAvailable() {
		return "The dashboard is controlling this terminal. Press any key here to take control back."
	}
	return "The dashboard is controlling this terminal. Take control back from the dashboard to type here again."
}

// readLoop consumes client frames until the connection ends or a protocol
// violation occurs. It never kills the child; the deferred detach in serveConn
// releases the writer + viewer.
func (s *server) readLoop(fc *frameConn, sess Session) {
	var fenced fencedState
	for {
		t, payload, err := fc.readFrame()
		if err != nil {
			if errors.Is(err, ErrProtocol) {
				_ = fc.sendError(CodeProtocol, err.Error())
			}
			return
		}
		switch t {
		case frameStdin:
			if _, werr := sess.Write(payload); werr != nil {
				if errors.Is(werr, ErrWriterRevoked) {
					// The lease was fenced out (a dashboard/other seat took over)
					// but the session lives on. Either RECLAIM the writer for this
					// native terminal (Feature 1) or surface the non-fatal revoked
					// notice, keeping the loop running so output still streams (A5).
					s.handleFencedWrite(fc, sess, payload, &fenced)
				} else if s.logger != nil {
					// Any other write error is worth a server-side line rather
					// than a silent swallow (A5).
					s.logger.Warn("attachsock: session write failed", "err", werr)
				}
			}
		case frameControl:
			op, perr := peekOp(payload)
			if perr != nil {
				_ = fc.sendError(CodeProtocol, perr.Error())
				return
			}
			switch op {
			case opResize:
				var rm resizeMsg
				if err := unmarshalControl(payload, &rm); err != nil {
					_ = fc.sendError(CodeProtocol, err.Error())
					return
				}
				if rerr := sess.Resize(rm.Rows, rm.Cols); rerr != nil && s.logger != nil {
					s.logger.Warn("attachsock: session resize failed", "err", rerr)
				}
			case opDetach:
				return
			default:
				// Forward-compat (review finding M7): an UNKNOWN control op from a
				// newer client is fully consumed (peekOp already parsed the whole
				// payload) and SKIPPED, not fatal — mirroring the unknown-FRAME-type
				// tolerance below and the client's own tolerant read loop, so the
				// control channel is bidirectionally forward-compatible. Only
				// MALFORMED frames (peekOp/unmarshal errors, length/junk) stay fatal
				// protocol errors; op-code unknownness alone is tolerated.
				if s.logger != nil {
					s.logger.Debug("attachsock: ignoring unknown control op", "op", op)
				}
				continue
			}
		default:
			// Forward-compat: a size-bounded unknown frame type from a newer
			// client is SKIPPED, not fatal (the stream stays synced via the
			// length prefix). frameStdin/frameControl are the only types a client
			// legitimately sends today; a future one is ignored here rather than
			// poisoning the session.
			continue
		}
	}
}

// The attach endpoint's creation, naming and dial live behind the Transport
// seam (transport.go + transport_{unix,windows,other}.go): ListenSocket, Dial,
// Endpoint and ErrSocketLiveDaemon are defined there, so everything in this
// file stays transport-agnostic (net.Listener / net.Conn only).
