package attachsock

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ProtocolVersion is the attach wire protocol version carried in a spawn frame.
// The server rejects any other value with an error frame.
const ProtocolVersion = 1

// Frame types. A frame is [len:4 big-endian][type:1][payload:len].
const (
	frameControl    byte = 1 // JSON control message
	frameStdin      byte = 2 // client → server raw PTY input
	frameOutput     byte = 3 // server → client raw PTY output
	frameCorrelated byte = 4 // server → client: correlated-session announce (JSON)
)

// frameCorrelated (type 4, resilient-attach Layer 1) is an ADDITIVE server→
// client frame carrying the run's correlated agent session id + provenance,
// emitted whenever correlation lands (claude: at spawn; codex: when discovery
// resolves). It is sent ONLY to a client that advertised AutoResumeCapable in
// its spawn frame, so a pre-Layer-1 client — which has no case for it — never
// receives it (backward compat). Forward compat runs the other way: an unknown
// frame type is size-bounded and SKIPPED by both read loops (capForType's
// tolerant default + the read-loop default cases), so a NEWER daemon's future
// frame type never poisons THIS client. The two together keep old-client/new-
// daemon AND new-client/old-daemon working without a version bump (the spawn
// frame's V stays ProtocolVersion, so an old daemon still accepts a new client
// and simply ignores the unknown spawn fields + never emits the frame).

// Frame payload caps. Control frames are JSON and small; data frames carry raw
// bytes and are chunked to dataFrameMax by the writers.
const (
	controlFrameMax = 64 * 1024
	dataFrameMax    = 32 * 1024
	lenHeaderSize   = 4
	typeHeaderSize  = 1
)

// Bounded write deadlines (A3/A4): every framed write is time-boxed so a stuck
// peer (a wedged TTY, a half-open socket) can never hold the frame mutex — and
// thus the whole session — open forever. Data frames get a longer budget than
// control frames because a large PTY burst legitimately takes longer to drain.
const (
	writeDeadlineData    = 30 * time.Second
	writeDeadlineControl = 5 * time.Second
)

// Control op names.
const (
	opSpawn   = "spawn"   // client → server
	opResize  = "resize"  // client → server
	opDetach  = "detach"  // client → server
	opSpawned = "spawned" // server → client
	opExit    = "exit"    // server → client
	opError   = "error"   // server → client
)

// Error codes carried on an error control frame.
const (
	// CodeSpawnFailed — the Host could not launch the requested PTY.
	CodeSpawnFailed = "spawn_failed"
	// CodeProtocol — a malformed/oversized frame or an invalid handshake.
	CodeProtocol = "protocol"
	// CodeDaemonShutdown — the daemon is shutting down and closed the session.
	CodeDaemonShutdown = "daemon_shutdown"
	// CodeWriterRevoked — a NON-FATAL notice: the client's writer lease was
	// revoked (a dashboard/other seat took over), so a keystroke did not reach
	// the PTY, but the session lives on and output keeps streaming. The client
	// surfaces this once and does NOT terminate (A5).
	CodeWriterRevoked = "writer_revoked"
	// CodeWriterReclaimed — a NON-FATAL notice paired with CodeWriterRevoked as a
	// transition toggle (Feature 1: native-terminal reclaim): the native
	// terminal's REVOKED writer lease was re-acquired because the operator typed
	// a real key (not ESC) into the attach client, so keystrokes reach the
	// session again. The client surfaces it — re-notifiable across
	// revoke→reclaim→revoke cycles (each transition prints) — and re-pushes its
	// terminal size so any foreign geometry a dashboard left behind heals in the
	// same gesture.
	CodeWriterReclaimed = "writer_reclaimed"
	// CodeResumeConflict — a FATAL spawn refusal: the auto-resume target already
	// has a live run under the daemon (the operator separately relaunched it, or
	// a concurrent resume won the single-flight). The client prints why and does
	// NOT spawn a duplicate (Layer-1 double-spawn guard).
	CodeResumeConflict = "resume_conflict"
	// CodeResumeNotResumable — a FATAL spawn refusal: the auto-resume target is
	// not a daemon-death orphan the resumed daemon rediscovered (its run recorded
	// its end, so it is not resumable-by-restart). The client prints why and
	// falls back to the native-resume hint rather than looping.
	CodeResumeNotResumable = "resume_not_resumable"
)

// ErrResumeConflict is the sentinel a Host's LaunchAttachable returns when an
// auto-resume request collides with an already-live run for the same session id
// (the double-spawn guard). The server maps it to a CodeResumeConflict error
// frame. Kept as an attachsock sentinel so the cmd Host can signal the refusal
// without importing the server's wire codes.
var ErrResumeConflict = errors.New("attachsock: session already has a live run (resume refused)")

// ErrResumeNotResumable is the sentinel a Host's LaunchAttachable returns when
// an auto-resume request names a session the resumed daemon did NOT rediscover
// as a daemon-death orphan (its run recorded its end). The server maps it to a
// CodeResumeNotResumable error frame.
var ErrResumeNotResumable = errors.New("attachsock: session is not resumable-by-restart (resume refused)")

// ErrWriterRevoked is the sentinel a Host's Session.Write returns when the
// write was fenced out because the writer lease is no longer live (revoked,
// taken over, or expired) while the underlying PTY session keeps running. The
// server maps it to a non-fatal CodeWriterRevoked control frame rather than
// tearing the connection down. The cmd adapter translates its termsession
// equivalent (ErrNotWriter) into this so attachsock never imports termsession.
var ErrWriterRevoked = errors.New("attachsock: writer lease revoked (write dropped, session alive)")

// ErrProtocol is the sentinel wrapped by every framing/handshake violation, so
// callers (and tests) can errors.Is against it.
var ErrProtocol = errors.New("attachsock: protocol error")

// Control message shapes. Each is a distinct struct because the "code" field
// means different things (int exit code vs string error code) across ops.

// spawnMsg — client → server: launch a PTY for tool/subcommand.
type spawnMsg struct {
	Op         string   `json:"op"`
	V          int      `json:"v"`
	Tool       string   `json:"tool"`
	Subcommand string   `json:"subcommand"`
	Dir        string   `json:"dir,omitempty"`
	Rows       uint16   `json:"rows"`
	Cols       uint16   `json:"cols"`
	Env        []string `json:"env,omitempty"`
	// ExtraArgs are the allow-listed argv tokens the daemon appends to the
	// inner `observer <subcommand>` launcher (routing escape hatch, --proxy/
	// --config overrides, and the `--` tool remainder). Explicit + allow-listed
	// on the client, never a blind argv copy (B2/B3).
	ExtraArgs []string `json:"extra_args,omitempty"`
	// AutoResumeCapable advertises that the client understands the
	// frameCorrelated announce (resilient-attach Layer 1). The server emits that
	// frame ONLY when this is true, so a pre-Layer-1 daemon (which never reads
	// the field) and a pre-Layer-1 client (which never sets it) both stay on the
	// old behavior. Additive + omitempty so an old daemon's decode is byte-
	// unchanged.
	AutoResumeCapable bool `json:"auto_resume_capable,omitempty"`
	// ResumeSession is the agent session id THIS attach is resuming, set for any
	// resume-attach (a manual `--attach --resume <id>` OR the daemon-death auto-
	// resume). It lets the daemon track a live run per resume target so a second
	// resume of the same session id is refused cleanly (double-spawn guard). It
	// is metadata for the guard only — the actual resume mechanism rides
	// ExtraArgs (`--resume <id>`). Empty for a non-resume attach.
	ResumeSession string `json:"resume_session,omitempty"`
	// AutoResume marks this spawn as a daemon-death AUTO-resume (not a user-
	// initiated `--attach --resume`). Only an auto-resume is validated against
	// the resumed daemon's rediscovered orphan set; a manual resume of a cleanly
	// closed session must NOT be gated on that set. Meaningful only when
	// ResumeSession is set.
	AutoResume bool `json:"auto_resume,omitempty"`
	// AgentEnv and AgentEnvSession are the client's agent-session hint
	// (lane cli-2): the client found an agent session's environment marker
	// (procmodel.SessionTokenEnvKeys) in its own environment, and the
	// session id it named. A hint can only make the launch an agent's, never
	// a human's; the daemon judges the caller's ancestry itself. Additive.
	AgentEnv        bool   `json:"agent_env,omitempty"`
	AgentEnvSession string `json:"agent_env_session,omitempty"`
}

// correlatedMsg is the frameCorrelated payload: the run's correlated agent
// session id plus provenance (source + confidence). The ABSTAIN rule is at the
// producer — this frame is emitted only for a REAL id (never a fabricated one),
// so a client that receives it can trust SessionID is a genuine resume target.
type correlatedMsg struct {
	SessionID  string  `json:"session_id"`
	Source     string  `json:"source,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// resizeMsg — client → server: the operator's terminal changed size.
type resizeMsg struct {
	Op   string `json:"op"`
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// detachMsg — client → server: leave without killing the child.
type detachMsg struct {
	Op string `json:"op"`
}

// spawnedMsg — server → client: the PTY is live.
type spawnedMsg struct {
	Op     string `json:"op"`
	Handle string `json:"handle"`
	RunID  string `json:"run_id"`
}

// exitMsg — server → client: the child process exited. Known distinguishes a
// real, observed exit code (Known=true) from an exit the daemon could not
// determine within its poll budget (Known=false → the client reports an honest
// failure rather than a fabricated 0). Older peers that omit the field decode
// Known=false; the server always sets it explicitly (A4).
type exitMsg struct {
	Op    string `json:"op"`
	Code  int    `json:"code"`
	Known bool   `json:"known"`
}

// errorMsg — server → client: a terminal error ended the session.
type errorMsg struct {
	Op      string `json:"op"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// opEnvelope peeks a control payload's op discriminator.
type opEnvelope struct {
	Op string `json:"op"`
}

// peekOp returns the op field of a JSON control payload.
func peekOp(payload []byte) (string, error) {
	var e opEnvelope
	if err := json.Unmarshal(payload, &e); err != nil {
		return "", fmt.Errorf("%w: malformed control frame: %w", ErrProtocol, err)
	}
	return e.Op, nil
}

// unmarshalControl decodes a control payload into v, wrapping any decode error
// as an ErrProtocol so a malformed control frame fails the connection.
func unmarshalControl(payload []byte, v any) error {
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("%w: malformed control frame: %w", ErrProtocol, err)
	}
	return nil
}

// capForType returns the payload cap for a frame type. Known data frames get
// the data cap; every other type (frameControl, frameCorrelated, AND any type
// this build does not recognize) gets the control cap. The tolerant default is
// deliberate forward-compat (resilient-attach Layer 1): the stream is length-
// prefixed, so an unknown but size-bounded frame can be read and SKIPPED by the
// read loops without losing sync — a NEWER daemon's future frame type never
// poisons this reader. The overall length is still capped at controlFrameMax in
// readFrame before this is consulted, so an oversized frame of ANY type is
// rejected first. The second result is retained (always true now) so callers
// need no signature change.
func capForType(t byte) (int, bool) {
	switch t {
	case frameStdin, frameOutput:
		return dataFrameMax, true
	default:
		// frameControl, frameCorrelated, and unrecognized (future) types.
		return controlFrameMax, true
	}
}

// writeDeadliner is the subset of net.Conn a frameConn uses to bound its
// writes. A stream that cannot set a deadline (a raw io.Pipe) simply skips the
// deadline — the mutex is still released when Write returns.
type writeDeadliner interface {
	SetWriteDeadline(t time.Time) error
}

// frameConn wraps a duplex byte stream with framed read/write. Writes are
// serialized by a mutex so an output-pump goroutine and a control-sending
// goroutine can share one connection safely. Reads happen from a single
// goroutine per side.
type frameConn struct {
	mu sync.Mutex
	w  io.Writer
	r  *bufio.Reader
	dl writeDeadliner // nil when the stream cannot set write deadlines
}

// newFrameConn wraps a duplex stream. When the stream is a net.Conn (the real
// AF_UNIX socket and net.Pipe in tests) its SetWriteDeadline is used to bound
// every framed write (A3/A4).
func newFrameConn(c io.ReadWriter) *frameConn {
	fc := &frameConn{w: c, r: bufio.NewReader(c)}
	if d, ok := c.(writeDeadliner); ok {
		fc.dl = d
	}
	return fc
}

// readFrame reads one frame, enforcing the per-type payload cap. A clean stream
// close before any byte returns io.EOF; a mid-frame close returns
// io.ErrUnexpectedEOF; an oversized/unknown-type frame returns ErrProtocol.
func (fc *frameConn) readFrame() (byte, []byte, error) {
	var hdr [lenHeaderSize]byte
	if _, err := io.ReadFull(fc.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int(n) > controlFrameMax {
		return 0, nil, fmt.Errorf("%w: frame length %d exceeds max %d", ErrProtocol, n, controlFrameMax)
	}
	var tb [typeHeaderSize]byte
	if _, err := io.ReadFull(fc.r, tb[:]); err != nil {
		return 0, nil, err
	}
	t := tb[0]
	limit, _ := capForType(t) // always ok: unknown types get the control cap (forward-compat)
	if int(n) > limit {
		return t, nil, fmt.Errorf("%w: frame type %d length %d exceeds cap %d", ErrProtocol, t, n, limit)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(fc.r, payload); err != nil {
		return t, nil, err
	}
	return t, payload, nil
}

// writeFrame writes one framed payload atomically. It rejects an oversized or
// unknown-type payload with ErrProtocol before touching the wire.
func (fc *frameConn) writeFrame(t byte, payload []byte) error {
	limit, _ := capForType(t) // always ok: unknown types get the control cap (forward-compat)
	if len(payload) > limit {
		return fmt.Errorf("%w: payload %d exceeds cap %d for type %d", ErrProtocol, len(payload), limit, t)
	}
	frame := make([]byte, lenHeaderSize+typeHeaderSize+len(payload))
	binary.BigEndian.PutUint32(frame[:lenHeaderSize], uint32(len(payload)))
	frame[lenHeaderSize] = t
	copy(frame[lenHeaderSize+typeHeaderSize:], payload)
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.dl != nil {
		budget := writeDeadlineData
		if t == frameControl {
			budget = writeDeadlineControl
		}
		_ = fc.dl.SetWriteDeadline(time.Now().Add(budget))
		// Clear the deadline after the write so a subsequent write under a
		// fresh mutex acquisition starts with a clean budget.
		defer func() { _ = fc.dl.SetWriteDeadline(time.Time{}) }()
	}
	if _, err := fc.w.Write(frame); err != nil {
		return err
	}
	return nil
}

// writeData writes raw bytes as one or more data frames, chunking to
// dataFrameMax. An empty payload writes nothing.
func (fc *frameConn) writeData(t byte, p []byte) error {
	for len(p) > 0 {
		n := len(p)
		if n > dataFrameMax {
			n = dataFrameMax
		}
		if err := fc.writeFrame(t, p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// sendControl marshals and writes a control frame.
func (fc *frameConn) sendControl(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("attachsock: marshal control: %w", err)
	}
	return fc.writeFrame(frameControl, b)
}

// sendError writes an error control frame.
func (fc *frameConn) sendError(code, msg string) error {
	return fc.sendControl(errorMsg{Op: opError, Code: code, Message: msg})
}

// sendCorrelated marshals and writes a frameCorrelated announce (Layer 1). The
// caller emits it only for a REAL correlated id (the abstain rule) and only to a
// client that advertised AutoResumeCapable.
func (fc *frameConn) sendCorrelated(c correlatedMsg) error {
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("attachsock: marshal correlated: %w", err)
	}
	return fc.writeFrame(frameCorrelated, b)
}
