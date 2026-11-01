package termoob

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// wireVersion is the framing version. A frame carries it in byte 0 so a future
// revision can be negotiated (the subprotocol-version-token groundwork the plan
// wants versioned from day one). Only v1 exists today.
const wireVersion uint8 = 1

// MaxFrameBytes bounds a single frame's JSON payload. It is deliberately small
// (§2.1b — NOT xterm's 10 MB OSC default): lifecycle/turn frames are tiny, so a
// larger frame signals corruption or abuse and poisons the channel.
const MaxFrameBytes = 4096

// headerBytes is the fixed frame header: [version:1][type:1][length:4-BE].
const headerBytes = 6

// Type is the frame type discriminator.
type Type uint8

const (
	// TypeUnknown is the zero value and the surface for any frame type this
	// version does not recognize (forward compatibility). It NEVER authorizes.
	TypeUnknown Type = 0
	// TypeHello authenticates the channel and declares the correlation nonce.
	// It MUST be the first frame; a second Hello is a protocol error.
	TypeHello Type = 1
	// TypeLifecycle carries a trusted launcher lifecycle transition.
	TypeLifecycle Type = 2
	// TypeSession announces the agent session id the launcher learned for THIS
	// run (session-attach design Phase 2 / §4). It is the trusted signal that
	// lets the daemon correlate a run to its observer session id at oob
	// confidence — the launcher knows the id (it minted/forced it via the
	// tool's `--session-id`), so echoing it on the authenticated channel is
	// unforgeable. A pre-Phase-2 decoder surfaces it as TypeUnknown (harmless).
	TypeSession Type = 3
	// Types >= 4 are reserved; a decoder that does not recognize a type
	// surfaces it as TypeUnknown.
)

// Phase enumerates the trusted launcher lifecycle transitions carried by a
// Lifecycle frame.
type Phase string

const (
	// PhaseLauncherStarted — the observer launcher process is up (pre-exec).
	PhaseLauncherStarted Phase = "launcher_started"
	// PhaseToolExecBegin — the launcher is about to exec the real AI tool.
	PhaseToolExecBegin Phase = "tool_exec_begin"
	// PhaseToolExecEnd — the tool exited; ExitCode is set.
	PhaseToolExecEnd Phase = "tool_exec_end"
	// PhaseSandboxEgressRefused - the run's sandbox gateway refused
	// connections while the tool owned the terminal, so the notices were
	// kept off the tool's screen (Windows 11 Pro run 4, N2); Count is the
	// number refused so far. Sent by a sandbox host helper; an older daemon
	// publishes it as an unknown lifecycle phase and nothing else.
	PhaseSandboxEgressRefused Phase = "sandbox_egress_refused"
)

// Hello is the first frame: it authenticates the channel and declares the
// run's correlation nonce so the daemon can correlate this run to the agent
// session it produces at oob (highest) confidence.
type Hello struct {
	// AuthToken is the per-session secret the daemon minted (NewSessionToken)
	// and handed to the child out of band. Matched constant-time by the decoder.
	AuthToken string `json:"auth"`
	// CorrelationToken is the run's opaque correlation nonce
	// (termrun.NewCorrelationToken), echoed so the daemon can hash-match it.
	CorrelationToken string `json:"corr"`
	// Tool is the target tool the launcher is starting.
	Tool string `json:"tool"`
	// PID is the launcher's process id (informational).
	PID int `json:"pid"`
}

// Lifecycle is a trusted lifecycle transition.
type Lifecycle struct {
	Phase Phase `json:"phase"`
	// ExitCode is set only for PhaseToolExecEnd.
	ExitCode *int `json:"exit_code,omitempty"`
	// Count is set only for PhaseSandboxEgressRefused.
	Count *int `json:"count,omitempty"`
	// At is an informational unix-nano timestamp (0 = unset).
	At int64 `json:"at,omitempty"`
}

// Session announces the agent session id the launcher learned for this run.
// It rides the authenticated channel AFTER the Hello, so the daemon can trust
// the mapping (run -> session id) at oob confidence without re-deriving it from
// untrusted PTY bytes or a heuristic store scan.
type Session struct {
	// SessionID is the tool's own session identifier for this run (e.g. the
	// claude-code session UUID the launcher forced via `--session-id`).
	SessionID string `json:"session_id"`
	// Source is an OPTIONAL hint about HOW the launcher learned SessionID, so
	// the daemon can record the resulting run->session correlation at a
	// confidence that matches the evidence. Absent/empty means the launcher
	// KNEW the id (it forced it via the tool's `--session-id`, or reattached a
	// deterministic `--resume <id>`) — the strongest, unforgeable signal, which
	// the daemon records at oob confidence. SessionSourceDiscovered means the id
	// was inferred by a heuristic scan (e.g. codex's post-launch rollout
	// discovery) — still a trusted-channel echo, but grounded in a guess, so the
	// daemon records it at a lower confidence. An unrecognized value is treated
	// as the default (absent), never elevated. Additive + omitempty so a
	// pre-existing producer (claude.go) that never sets it is byte-unchanged.
	Source string `json:"source,omitempty"`
}

// SessionSourceDiscovered is the Session.Source hint value for an id the
// launcher learned by a heuristic post-launch scan rather than by forcing or
// deterministically resuming it. The daemon maps it to a lower correlation
// confidence than an absent/empty Source (which means the id was known). Kept
// as a wire-level string constant here (the one place the Session frame is
// defined) so the producer and the daemon-side consumer agree on the token
// without termoob importing any domain package.
const SessionSourceDiscovered = "discovered"

// Frame is a decoded frame. Exactly one payload pointer is non-nil for a known
// type; all are nil for TypeUnknown (the raw payload is discarded after the
// size check — an unknown frame never carries actionable trusted data).
type Frame struct {
	Type      Type
	Hello     *Hello
	Lifecycle *Lifecycle
	Session   *Session
}

// Errors surfaced by the decoder. Every one poisons the channel (fail-closed):
// a length-prefixed binary stream cannot resync mid-frame.
var (
	// ErrUnauthenticated — the first frame was not a Hello, or its AuthToken did
	// not match the expected per-session secret.
	ErrUnauthenticated = errors.New("termoob: channel not authenticated")
	// ErrFrameTooLarge — a frame's declared length exceeds MaxFrameBytes.
	ErrFrameTooLarge = errors.New("termoob: frame exceeds size limit")
	// ErrProtocol — a structural violation (bad version, duplicate Hello,
	// malformed payload).
	ErrProtocol = errors.New("termoob: protocol violation")
)

// sessionTokenBytes is the entropy of a per-session auth secret (32 bytes).
const sessionTokenBytes = 32

// NewSessionToken mints a per-session auth secret from crypto/rand. The daemon
// mints one per launch, hands it to the child out of band, and constructs the
// Decoder with it.
func NewSessionToken() (string, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("termoob: read session secret bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Encoder writes frames to the child's end of the OOB channel. It is used by
// the launcher wrapper (cmd) over the inherited FD. Safe for use by a single
// writer.
type Encoder struct {
	w io.Writer
}

// NewEncoder wraps an io.Writer (the child's end of the inherited pipe).
func NewEncoder(w io.Writer) *Encoder { return &Encoder{w: w} }

// WriteHello sends the authenticating first frame.
func (e *Encoder) WriteHello(h Hello) error { return e.write(TypeHello, h) }

// WriteLifecycle sends a lifecycle transition frame.
func (e *Encoder) WriteLifecycle(l Lifecycle) error { return e.write(TypeLifecycle, l) }

// WriteSession announces the run's agent session id (session-attach Phase 2).
// Sent by the launcher after Hello once it knows the session id the tool will
// use; the daemon consumes it to correlate the run at oob confidence.
func (e *Encoder) WriteSession(s Session) error { return e.write(TypeSession, s) }

func (e *Encoder) write(t Type, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("termoob: marshal frame: %w", err)
	}
	if len(body) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	var hdr [headerBytes]byte
	hdr[0] = wireVersion
	hdr[1] = byte(t)
	binary.BigEndian.PutUint32(hdr[2:], uint32(len(body)))
	if _, err := e.w.Write(hdr[:]); err != nil {
		return fmt.Errorf("termoob: write header: %w", err)
	}
	if _, err := e.w.Write(body); err != nil {
		return fmt.Errorf("termoob: write body: %w", err)
	}
	return nil
}

// Decoder reads frames on the daemon's end of the OOB channel. It enforces the
// per-session auth handshake (the first frame MUST be a matching Hello) and the
// per-frame size limit. It is the trusted seam: a frame it returns is
// authenticated; anything it rejects poisons the channel.
type Decoder struct {
	r         io.Reader
	expected  string // the per-session auth secret
	authed    bool
	poisoned  error
	headerBuf [headerBytes]byte
}

// NewDecoder wraps the daemon's end of the inherited pipe with the per-session
// auth secret the daemon minted (NewSessionToken) and handed to the child.
func NewDecoder(r io.Reader, expectedAuthToken string) *Decoder {
	return &Decoder{r: r, expected: expectedAuthToken}
}

// Read returns the next frame, or an error. On the first call it requires a
// Hello whose AuthToken matches; a mismatch (or any framing violation) poisons
// the decoder so every subsequent Read returns the same error. io.EOF is
// returned unchanged when the child closes the channel cleanly.
func (d *Decoder) Read() (Frame, error) {
	if d.poisoned != nil {
		return Frame{}, d.poisoned
	}
	frame, err := d.readOne()
	if err != nil {
		if errors.Is(err, io.EOF) {
			// A clean EOF is not a poison — the caller stops reading.
			return Frame{}, io.EOF
		}
		d.poisoned = err
		return Frame{}, err
	}
	return frame, nil
}

func (d *Decoder) readOne() (Frame, error) {
	if _, err := io.ReadFull(d.r, d.headerBuf[:]); err != nil {
		// io.ReadFull returns EOF only if zero bytes were read (clean close);
		// a partial header is ErrUnexpectedEOF → a framing violation.
		if errors.Is(err, io.EOF) {
			return Frame{}, io.EOF
		}
		return Frame{}, fmt.Errorf("%w: short header: %w", ErrProtocol, err)
	}
	if d.headerBuf[0] != wireVersion {
		return Frame{}, fmt.Errorf("%w: unsupported wire version %d", ErrProtocol, d.headerBuf[0])
	}
	typ := Type(d.headerBuf[1])
	length := binary.BigEndian.Uint32(d.headerBuf[2:])
	if length > MaxFrameBytes {
		return Frame{}, ErrFrameTooLarge
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(d.r, body); err != nil {
		return Frame{}, fmt.Errorf("%w: short body: %w", ErrProtocol, err)
	}

	// Auth gate: the first frame MUST be a Hello with a matching secret.
	if !d.authed {
		if typ != TypeHello {
			return Frame{}, ErrUnauthenticated
		}
		var h Hello
		if err := json.Unmarshal(body, &h); err != nil {
			return Frame{}, fmt.Errorf("%w: bad hello payload: %w", ErrProtocol, err)
		}
		if !tokenMatch(h.AuthToken, d.expected) {
			return Frame{}, ErrUnauthenticated
		}
		d.authed = true
		return Frame{Type: TypeHello, Hello: &h}, nil
	}

	switch typ {
	case TypeHello:
		// A second Hello is a protocol error (re-auth is not a thing).
		return Frame{}, fmt.Errorf("%w: duplicate hello", ErrProtocol)
	case TypeLifecycle:
		var l Lifecycle
		if err := json.Unmarshal(body, &l); err != nil {
			return Frame{}, fmt.Errorf("%w: bad lifecycle payload: %w", ErrProtocol, err)
		}
		return Frame{Type: TypeLifecycle, Lifecycle: &l}, nil
	case TypeSession:
		var sess Session
		if err := json.Unmarshal(body, &sess); err != nil {
			return Frame{}, fmt.Errorf("%w: bad session payload: %w", ErrProtocol, err)
		}
		return Frame{Type: TypeSession, Session: &sess}, nil
	default:
		// Forward-compat: an unknown (but size-bounded) frame is surfaced as
		// TypeUnknown and its body discarded — it never authorizes anything.
		return Frame{Type: TypeUnknown}, nil
	}
}

// tokenMatch is a constant-time equality check on the auth secret. Unequal
// lengths short-circuit to false without leaking timing on the compare.
func tokenMatch(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
