package attachsock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// dialTimeout bounds a client's connect to the attach socket.
const dialTimeout = 2 * time.Second

// stdinJoinTimeout bounds how long Attach waits for the stdin pump goroutine to
// stop once the session has ended, before returning. Combined with the pump's
// pre-forward ctx check and the deterministic reader unblock, this GUARANTEES
// no stdin read is forwarded after Attach returns — the operator's shell
// reclaims its terminal without the attach client stealing a keystroke (A3).
const stdinJoinTimeout = 2 * time.Second

// ErrDaemonUnreachable is wrapped by Dial when the attach socket cannot be
// reached — typically because `observer start` is not running. Callers can
// errors.Is against it to print a "daemon not running" hint.
var ErrDaemonUnreachable = errors.New("attachsock: daemon not reachable")

// ErrDaemonExited is returned by Attach ONLY when the server sent an explicit
// daemon_shutdown control frame — a definitive daemon exit with the session
// still live (design §2.4). The cmd layer prints the "observer daemon exited —
// this session ended with it" message on this error.
var ErrDaemonExited = errors.New("attachsock: daemon exited before the session ended")

// ErrConnLost is returned by Attach when the connection closed WITHOUT an exit
// frame and WITHOUT an explicit daemon_shutdown — an ambiguous EOF that could be
// a daemon exit OR a plain connection failure. The cmd layer must NOT
// definitively claim the daemon exited on this error (A2-2); it prints the
// honest "connection to the observer daemon lost" copy instead.
var ErrConnLost = errors.New("attachsock: connection to the daemon was lost before the session ended")

// ErrInputStalled is returned by Attach when forwarding the operator's
// keystrokes to the PTY failed (a stdin data-frame write errored/timed out) so
// the session was detached. Surfaced explicitly rather than swallowed (A2-2) so
// the operator learns their input stopped reaching the session.
var ErrInputStalled = errors.New("attachsock: stdin forwarding stalled — detached")

// Dial connects to the attach endpoint (an AF_UNIX socket path on unix, a
// named-pipe name on Windows — whatever Endpoint returned for the daemon's DB
// path) through this platform's transport. Every failure is wrapped with
// ErrDaemonUnreachable so callers keep their single "daemon not running" hint,
// whichever transport is compiled in.
func Dial(endpoint string) (net.Conn, error) {
	c, err := defaultTransport.Dial(context.Background(), endpoint, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("attachsock.Dial: %w: %w", ErrDaemonUnreachable, err)
	}
	return c, nil
}

// Winsize is a terminal window size the client forwards as a resize control
// frame.
type Winsize struct {
	Rows uint16
	Cols uint16
}

// ClientReader is the interruptible input contract ClientIO.Stdin must satisfy
// (A3-1). It is io.Reader + io.Closer + SetReadDeadline so Attach can
// GUARANTEE it unblocks a parked Read when the session ends: SetReadDeadline in
// the past pops the read; Close is the fallback. A *os.File over a non-blocking
// TTY fd satisfies it — that is what the cmd client passes.
type ClientReader interface {
	io.Reader
	io.Closer
	SetReadDeadline(t time.Time) error
}

// writeDeadlinePopper is the OPTIONAL contract a Stdout may satisfy so Attach
// can pop a blocked Write on teardown (A3-3, e.g. a Ctrl-S flow-controlled
// terminal). A *os.File over a non-blocking TTY fd satisfies it; a plain buffer
// does not, and popWriter is then a no-op.
type writeDeadlinePopper interface {
	SetWriteDeadline(t time.Time) error
}

// ClientIO wires the operator's terminal to an attach session. TTY raw-mode and
// SIGWINCH translation are the cmd layer's job; it feeds Resize.
type ClientIO struct {
	// Stdin is the operator's terminal input, forwarded as PTY keystrokes. It
	// is an interruptible ClientReader so Attach can GUARANTEE no read is
	// forwarded after the session ends: Attach pops any parked Read via
	// SetReadDeadline (falling back to Close) when the session ends and joins
	// the pump before returning (A3). nil disables stdin forwarding.
	Stdin ClientReader
	// Stdout receives the PTY's output. When it also implements SetWriteDeadline
	// (a non-blocking *os.File), Attach pops a Write blocked by terminal flow
	// control (Ctrl-S) on teardown so it always returns (A3-3); a plain
	// io.Writer works too, just without that guarantee.
	Stdout io.Writer
	// Resize delivers window-size changes (nil disables resize forwarding).
	Resize <-chan Winsize
	// Notice, when non-nil, receives NON-FATAL server notices (e.g. a
	// writer-lease takeover, code CodeWriterRevoked). Attach dedupes by code so
	// each distinct notice fires at most once; the session keeps running (A5).
	Notice func(code, message string)
	// Correlated, when non-nil, receives the run's correlated agent session id
	// as the daemon resolves it (resilient-attach Layer 1). Setting it ALSO
	// advertises AutoResumeCapable in the spawn frame, so the daemon knows to
	// push frameCorrelated announcements. SessionID is always a REAL id (the
	// daemon abstains on an unresolved correlation). It may fire more than once
	// as the correlation upgrades (e.g. discovered → oob); the caller keeps the
	// latest. nil disables the capability (the daemon then never sends the
	// frame — the old behavior).
	Correlated func(sessionID, source string, confidence float64)
	// InitialRows / InitialCols seed the spawn frame's PTY size; 0 falls back to
	// the SpawnRequest's Rows/Cols.
	InitialRows uint16
	InitialCols uint16
}

// ExitStatus reports how an attach session ended. Exited is true only when the
// child process itself exited (an exit control frame); a clean detach returns
// Exited=false with a nil error. Known is false when the child exited but the
// daemon could not determine its exit code within the poll budget — the cmd
// layer then reports an honest failure instead of a fabricated success (A4).
type ExitStatus struct {
	Code   int
	Exited bool
	Known  bool
}

// ServerError is returned by Attach when the server ended the session with an
// error control frame (other than a daemon shutdown, which maps to
// ErrDaemonExited).
type ServerError struct {
	Code    string
	Message string
}

// Error implements error.
func (e *ServerError) Error() string {
	return fmt.Sprintf("attachsock: server error [%s]: %s", e.Code, e.Message)
}

// Attach runs the client side of an attach session over conn: it sends the
// spawn request, waits for the server's spawned reply, then bridges stdin →
// PTY, PTY output → stdout, and window resizes, until:
//
//   - the child exits (exit frame) → ExitStatus{Exited:true}, nil;
//   - the server ends with an error frame → ExitStatus{}, *ServerError (or
//     ErrDaemonExited for a daemon shutdown);
//   - the connection closes without an exit → ExitStatus{}, ErrDaemonExited;
//   - ctx is canceled or Stdin hits EOF → a detach frame is sent and the call
//     returns ExitStatus{} with a nil error (detached, child lives on).
//
// On every return path Attach stops the stdin pump (cancel + unblock + bounded
// join) so no keystroke is forwarded after it returns.
func Attach(ctx context.Context, conn net.Conn, spawn SpawnRequest, cio ClientIO) (ExitStatus, error) {
	fc := newFrameConn(conn)

	// detached records that WE ended the session (ctx cancel / stdin EOF / an
	// explicit detach), so a subsequent connection close reads as a clean
	// detach rather than an unexpected daemon exit. markDetached only sets the
	// flag; sending the detach frame is decoupled so the cancellation path can
	// close the conn WITHOUT first blocking on the frame mutex (A2-4).
	var detached atomic.Bool
	var detachFrameOnce sync.Once
	markDetached := func() { detached.Store(true) }
	sendDetachFrame := func() {
		detachFrameOnce.Do(func() { _ = fc.sendControl(detachMsg{Op: opDetach}) })
	}

	// Cancellation watchdog, armed BEFORE the spawn is sent (A3): the instant
	// ctx is canceled we mark detached and UNCONDITIONALLY close the conn —
	// which unblocks any framed read/write (the handshake, the read loop, or a
	// wedged writer) PROMPTLY. We deliberately do NOT send a detach frame on
	// this path: the server already treats a conn EOF as a detach (child lives
	// on), so a frame is redundant, and sending it here would risk blocking
	// behind the frame mutex / a data write deadline and delaying the close
	// (A2-4). conn.Close() never waits on the mutex.
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			markDetached()
			// Pop a Stdout Write blocked by terminal flow control (Ctrl-S)
			// BEFORE closing the conn: readServerLoop runs synchronously in
			// Attach, so a wedged Write would otherwise keep Attach from ever
			// returning and the terminal from being restored (A3-3). conn.Close
			// then unblocks any framed read/write PROMPTLY.
			popWriter(cio.Stdout)
			_ = conn.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)

	rows, cols := spawn.Rows, spawn.Cols
	if cio.InitialRows != 0 {
		rows = cio.InitialRows
	}
	if cio.InitialCols != 0 {
		cols = cio.InitialCols
	}
	if err := fc.sendControl(spawnMsg{
		Op:         opSpawn,
		V:          ProtocolVersion,
		Tool:       spawn.Tool,
		Subcommand: spawn.Subcommand,
		Dir:        spawn.Dir,
		Rows:       rows,
		Cols:       cols,
		Env:        spawn.Env,
		ExtraArgs:  spawn.ExtraArgs,
		// Advertise Layer-1 capability only when the caller wants the frame, so
		// the daemon pushes frameCorrelated announcements just to a consumer.
		AutoResumeCapable: cio.Correlated != nil,
		ResumeSession:     spawn.ResumeSession,
		AutoResume:        spawn.AutoResume,
	}); err != nil {
		// A watchdog conn-close during the initial spawn write (ctx canceled
		// mid-handshake) fails this send. That is a clean ctx-cancel detach —
		// the daemon may already have spawned the child (it lives on) and reads
		// our close as a detach — not a launch error (A3-4).
		if ctx.Err() != nil {
			return ExitStatus{}, nil
		}
		return ExitStatus{}, fmt.Errorf("attachsock.Attach: send spawn: %w", err)
	}

	if err := awaitSpawned(fc); err != nil {
		// A cancel during the handshake window closes the conn under us, so the
		// spawned-reply read fails. If ctx was canceled (guaranteed visible via
		// the context package), that is a clean detach — the daemon may already
		// have spawned the child (it lives on), and the server reads our conn
		// close as a detach — not a connection-lost error (A2-4).
		if ctx.Err() != nil && (errors.Is(err, ErrConnLost) || errors.Is(err, ErrDaemonExited)) {
			return ExitStatus{}, nil
		}
		return ExitStatus{}, err
	}

	// pumpCtx bounds the stdin/resize pumps independently of ctx: it is canceled
	// on EVERY Attach return so the pumps stop even on a child-exit path (where
	// ctx is not canceled).
	pumpCtx, cancelPumps := context.WithCancel(context.Background())
	defer cancelPumps()

	// stdin → frameStdin. The ctx check right before forwarding guarantees a
	// read that completes after the session ends is dropped, not forwarded.
	// inputStalled latches when a stdin data-frame write fails/times out so
	// Attach can surface ErrInputStalled instead of returning silently (A2-2).
	// connLostOnWrite latches the SUBSET of those failures that mean the
	// connection itself is gone (EPIPE/ECONNRESET — a daemon crash mid-write)
	// as opposed to a mere write-deadline stall; it takes precedence so a
	// daemon death is not misreported as a plain stall (A2-2 interleaving).
	var inputStalled atomic.Bool
	var connLostOnWrite atomic.Bool
	var stdinDone chan struct{}
	if cio.Stdin != nil {
		stdinDone = make(chan struct{})
		go func() {
			defer close(stdinDone)
			buf := make([]byte, dataFrameMax)
			for {
				n, rerr := cio.Stdin.Read(buf)
				if pumpCtx.Err() != nil {
					return // session ended — never forward a post-exit read
				}
				if n > 0 {
					if werr := fc.writeData(frameStdin, buf[:n]); werr != nil {
						// A stdin write failure means keystrokes are no longer
						// reaching the PTY. Distinguish the two causes: a blown
						// write DEADLINE (the daemon's socket buffer wedged but
						// the conn is still nominally open) is a mere stall,
						// whereas a broken pipe / reset means the daemon went
						// away mid-write and the connection is LOST — the latter
						// must not be masked as a stall. Latch the right cause,
						// mark detached so the read loop reads the ensuing close
						// as a clean detach, and close the conn (A2-2).
						if writeIndicatesConnLost(werr) {
							connLostOnWrite.Store(true)
						} else {
							inputStalled.Store(true)
						}
						markDetached()
						_ = conn.Close()
						return
					}
				}
				if rerr != nil {
					// Stdin EOF (Ctrl-D at a raw TTY is a byte, not EOF; this is
					// a genuine close): detach cleanly, child lives on. This is
					// not a cancellation path, so a best-effort detach frame is
					// fine before the close.
					markDetached()
					sendDetachFrame()
					_ = conn.Close()
					return
				}
			}
		}()
	}

	// resize → resize control frames.
	if cio.Resize != nil {
		go func() {
			for {
				select {
				case <-pumpCtx.Done():
					return
				case ws, ok := <-cio.Resize:
					if !ok {
						return
					}
					_ = fc.sendControl(resizeMsg{Op: opResize, Rows: ws.Rows, Cols: ws.Cols})
				}
			}
		}()
	}

	status, aerr := readServerLoop(ctx, fc, &detached, cio)

	// Stop the stdin pump deterministically before returning so the shell
	// reclaims its terminal with zero risk of a stolen keystroke (A3): cancel
	// the pump ctx, pop any parked Read, then bounded-join the goroutine. If the
	// join times out (a Read that ignored the deadline), force a Close on the
	// reader and re-join briefly so we never return with the pump still live
	// (A2-3).
	cancelPumps()
	unblockReader(cio.Stdin)
	if stdinDone != nil {
		select {
		case <-stdinDone:
		case <-time.After(stdinJoinTimeout):
			if cio.Stdin != nil {
				_ = cio.Stdin.Close()
			}
			select {
			case <-stdinDone:
			case <-time.After(stdinJoinTimeout):
			}
		}
	}

	return resolveAttachResult(ctx, status, aerr, inputStalled.Load(), connLostOnWrite.Load())
}

// resolveAttachResult applies the attach result precedence (A3-2 / B3-4). An
// input-forwarding stall is the WEAKEST outcome and must never override a more
// authoritative one. In order:
//
//  1. an OBSERVED child exit (exit frame) — the definitive result;
//  2. a clean ctx-cancel detach — the operator asked to leave;
//  3. a lost connection / server error observed by the read loop — honest;
//  4. a connection LOST during a stdin write (daemon crash mid-write) — the
//     stdin pump marks detached so the read loop reports a clean detach, so
//     this flag carries the loss forward as ErrConnLost rather than letting it
//     be masked as a mere stall;
//  5. only if none of the above, an input stall (ErrInputStalled).
func resolveAttachResult(ctx context.Context, status ExitStatus, aerr error, inputStalled, connLostOnWrite bool) (ExitStatus, error) {
	switch {
	case aerr == nil && status.Exited:
		return status, nil
	case ctx.Err() != nil:
		return ExitStatus{}, nil
	case aerr != nil:
		return status, aerr
	case connLostOnWrite:
		return ExitStatus{}, ErrConnLost
	case inputStalled:
		return ExitStatus{}, ErrInputStalled
	default:
		return status, aerr
	}
}

// writeIndicatesConnLost reports whether a stdin data-frame write error means
// the connection to the daemon is GONE (broken pipe / connection reset / closed
// conn — a daemon crash mid-write) rather than a mere write-deadline stall (the
// daemon's socket buffer wedged but the connection is still nominally open). A
// blown write deadline surfaces as a net.Error with Timeout()==true; anything
// else on a socket write means the peer/connection is gone.
func writeIndicatesConnLost(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false // deadline blown — a stall, conn still nominally open
	}
	return true
}

// unblockReader pops a parked Read on r so the stdin pump can observe the
// canceled pump ctx and exit. SetReadDeadline in the past is preferred (it
// leaves the fd open for the caller to Close/restore); if it ERRORS (an fd that
// does not support deadlines), fall through to Close so the parked Read is still
// broken (A2-3).
func unblockReader(r ClientReader) {
	if r == nil {
		return
	}
	if err := r.SetReadDeadline(time.Now()); err == nil {
		return
	}
	// deadline unsupported/failed — fall through to Close.
	_ = r.Close()
}

// popWriter sets a past write deadline on w so a Write blocked by terminal flow
// control (Ctrl-S) returns promptly on teardown (A3-3). It is a no-op for a
// writer that does not support deadlines (a plain buffer) — such a writer
// cannot wedge Attach anyway. It is only ever called on a terminal teardown
// path (ctx cancel), after which Attach unwinds and no further normal output is
// written, so no stale deadline can bite a subsequent legitimate write.
func popWriter(w io.Writer) {
	if w == nil {
		return
	}
	if d, ok := w.(writeDeadlinePopper); ok {
		_ = d.SetWriteDeadline(time.Now())
	}
}

// readServerLoop consumes server frames: PTY output → stdout, non-fatal notices
// surfaced once, and exit/error control frames end the session. It never reads
// stdin — that is the caller's pump.
func readServerLoop(ctx context.Context, fc *frameConn, detached *atomic.Bool, cio ClientIO) (ExitStatus, error) {
	// lastWriterNotice dedupes CONSECUTIVE writer_revoked notices only: repeated
	// fenced drops (a held key, machine-reply chunks) must not spam the terminal.
	// writer_reclaimed is NEVER deduped — each successful reclaim is a distinct
	// takeover cycle (after a reclaim the writes stop being fenced, so a repeat
	// reclaimed can only mean the dashboard took over again in between, with no
	// intervening revoked notice on the wire), and the Notice side-effect
	// re-pushes the native terminal size, which every cycle needs (Feature 1).
	var lastWriterNotice string
	for {
		t, payload, err := fc.readFrame()
		if err != nil {
			// A read error after WE ended the session is a clean detach. We
			// check ctx.Err() as well as the detached flag: on the ctx-cancel
			// path the watchdog closes the conn, and the context package
			// guarantees ctx.Err() is visible here (its Done-channel close
			// synchronizes-with this read) even if the plain atomic Store has
			// not yet propagated — so the cancel is never misread as a lost
			// connection.
			if detached.Load() || ctx.Err() != nil {
				return ExitStatus{}, nil
			}
			// A bare read error (EOF/reset) without an exit or explicit
			// daemon_shutdown frame is AMBIGUOUS — daemon exit or connection
			// failure. Report ErrConnLost so the cmd layer does not falsely
			// assert the daemon exited (A2-2).
			return ExitStatus{}, ErrConnLost
		}
		switch t {
		case frameCorrelated:
			// Resilient-attach Layer 1: the daemon resolved (or upgraded) the
			// run's correlated agent session id. Surface the REAL id to the
			// caller, which retains it as the auto-resume target. A malformed
			// payload or an empty id is dropped (defensive; the producer already
			// abstains on an unresolved correlation).
			if cio.Correlated != nil {
				var cm correlatedMsg
				if uerr := unmarshalControl(payload, &cm); uerr == nil && cm.SessionID != "" {
					cio.Correlated(cm.SessionID, cm.Source, cm.Confidence)
				}
			}
		case frameOutput:
			if cio.Stdout != nil {
				if _, werr := cio.Stdout.Write(payload); werr != nil {
					// A write that fails AFTER we began tearing down (ctx cancel
					// popped a flow-control-blocked writer via a past deadline)
					// is a clean detach, not a stdout failure (A3-3). Check
					// ctx.Err()/detached the same way the read-error path does.
					if detached.Load() || ctx.Err() != nil {
						return ExitStatus{}, nil
					}
					return ExitStatus{}, fmt.Errorf("attachsock.Attach: write stdout: %w", werr)
				}
			}
		case frameControl:
			op, perr := peekOp(payload)
			if perr != nil {
				return ExitStatus{}, perr
			}
			if op == opError {
				var em errorMsg
				if uerr := unmarshalControl(payload, &em); uerr != nil {
					return ExitStatus{}, uerr
				}
				// The writer revoked/reclaimed pair are NON-FATAL transition
				// notices: surface them and keep streaming output (A5). Only a
				// CONSECUTIVE repeat of revoked is deduped (see lastWriterNotice);
				// reclaimed always fires — a reclaimed→reclaimed sequence is two
				// real takeover cycles and each must re-push the native size.
				if em.Code == CodeWriterRevoked || em.Code == CodeWriterReclaimed {
					dup := em.Code == CodeWriterRevoked && lastWriterNotice == CodeWriterRevoked
					lastWriterNotice = em.Code
					if cio.Notice != nil && !dup {
						cio.Notice(em.Code, em.Message)
					}
					continue
				}
				if em.Code == CodeDaemonShutdown {
					return ExitStatus{}, ErrDaemonExited
				}
				return ExitStatus{}, &ServerError{Code: em.Code, Message: em.Message}
			}
			if op == opExit {
				status, done, cerr := handleServerControl(payload)
				if done {
					return status, cerr
				}
				continue
			}
			// Forward-compat: an unknown control op from a newer daemon is
			// skipped, not fatal (termoob's TypeUnknown discipline).
			continue
		default:
			// Forward-compat: a size-bounded unknown frame type is skipped (the
			// length prefix keeps the stream synced), so a newer daemon's future
			// frame type never poisons this reader (resilient-attach Layer 1).
			continue
		}
	}
}

// awaitSpawned reads the server's reply to a spawn, accepting a spawned frame
// and mapping an error frame to a returned error.
func awaitSpawned(fc *frameConn) error {
	t, payload, err := fc.readFrame()
	if err != nil {
		if errors.Is(err, ErrProtocol) {
			return err
		}
		// Pre-spawn EOF/reset is ambiguous (daemon exit vs conn failure);
		// report ErrConnLost, not a definitive daemon-exit claim (A2-2).
		return ErrConnLost
	}
	if t != frameControl {
		return fmt.Errorf("%w: expected a control reply, got type %d", ErrProtocol, t)
	}
	op, err := peekOp(payload)
	if err != nil {
		return err
	}
	switch op {
	case opSpawned:
		return nil
	case opError:
		var em errorMsg
		if err := unmarshalControl(payload, &em); err != nil {
			return err
		}
		if em.Code == CodeDaemonShutdown {
			return ErrDaemonExited
		}
		return &ServerError{Code: em.Code, Message: em.Message}
	default:
		return fmt.Errorf("%w: expected spawned/error, got op %q", ErrProtocol, op)
	}
}

// handleServerControl processes a server → client exit frame during the pump.
// It returns done=true (with the terminal status) when the session ends. An
// exit whose code the daemon could not determine (Known=false) is surfaced as
// Code=-1 so the cmd layer reports an honest failure rather than a fabricated 0
// (A4). Non-fatal notices and terminal error frames are handled by the caller
// (readServerLoop) before this is reached.
func handleServerControl(payload []byte) (ExitStatus, bool, error) {
	op, err := peekOp(payload)
	if err != nil {
		return ExitStatus{}, true, err
	}
	switch op {
	case opExit:
		var em exitMsg
		if err := unmarshalControl(payload, &em); err != nil {
			return ExitStatus{}, true, err
		}
		if !em.Known {
			return ExitStatus{Code: -1, Exited: true, Known: false}, true, nil
		}
		return ExitStatus{Code: em.Code, Exited: true, Known: true}, true, nil
	default:
		return ExitStatus{}, true, fmt.Errorf("%w: unexpected server op %q", ErrProtocol, op)
	}
}
