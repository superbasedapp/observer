package relaymux

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// mux.go is the relay over a remote box's exec stream (sandbox plan v2
// section 5.7, "box-to-home is initiated from home and rides a separate
// stream"; lane SBX-P7). The home side starts `observer sandbox-guest
// --relay-stdio` in the box as a non-PTY exec with a streaming stdin, and
// this protocol runs over that process's stdin and stdout:
//
//   - the frames are the capture relay's own authenticated frames
//     (internal/sandboxrelay: header, per-direction sequence, HMAC-SHA256
//     keyed from a per-run secret, fixed check order), no new crypto; a
//     wrongly keyed, replayed, oversized or out-of-state frame ends the
//     channel;
//   - the home side speaks first (a nonce), so the keys differ per
//     connection and a reconnect after a drop is re-keyed (the
//     separate_stream relay reattach);
//   - only the home side opens streams: the guest asks on the control
//     stream (stream 1) for a connection of a kind (the relay socket, the
//     model proxy) and the home side, if the run's tier allows that kind,
//     dials its own socket and opens a stream for it;
//   - stream 2 carries the box PTY where the guest helper owns it (a vendor
//     with no documented resize): the home side sends its terminal's bytes
//     and sizes, the guest sends the PTY's output;
//   - flow control is the mux's own byte window per stream (the receiver
//     grants credit after its local side drained the bytes), so one slow
//     socket never stalls the others and memory is bounded per stream.
//
// The package is pure: no socket, file or process; the cmd layer injects
// the connection, the dialler and the box-side listeners.

// The fixed stream ids.
const (
	StreamControl uint32 = 1
	StreamPTY     uint32 = 2
	firstDynamic  uint32 = 16
)

// The connection kinds a guest may ask for.
const (
	KindRelay = "relay"
	KindProxy = "proxy"
	// KindGateway is the egress gateway (the Apple container row's tunnel
	// carries it; the hosted rows never offer it).
	KindGateway = "gateway"
)

// Bounds.
const (
	// Window is the per-stream receive credit, in bytes.
	Window = 256 << 10
	// MaxActiveStreams caps the concurrently open data streams.
	MaxActiveStreams = 64
	// maxStreamsPerSession caps the streams one session ever opens (the
	// frame layer keeps closed stream ids); past it the home side ends the
	// session and opens a new, re-keyed one.
	maxStreamsPerSession = 4000
	// maxControl caps one control message.
	maxControl = 64 << 10
	// HeartbeatEvery is how often each side pings (it also keeps a vendor
	// that ends an idle stdin, such as Modal's interactive exec, alive).
	HeartbeatEvery = 15 * time.Second
)

// limits are the frame-layer bounds: the frame layer's own credit is set
// out of reach (the mux enforces its own window), streams are counted per
// session.
var limits = sandboxrelay.Limits{MaxPayload: 32 << 10, MaxStreams: maxStreamsPerSession + 8, InitialWindow: 1<<32 - 1, MaxWindow: 1<<32 - 1}

// DefaultConnLimits suit a remote link: a frame may take seconds to cross.
var DefaultConnLimits = sandboxrelay.ConnLimits{
	IdleTimeout:     4 * HeartbeatEvery,
	FrameDeadline:   20 * time.Second,
	WriteDeadline:   30 * time.Second,
	MessageDeadline: 30 * time.Second,
	FramesPerSec:    20000,
	BytesPerSec:     256 << 20,
	Burst:           1,
}

// Errors.
var (
	ErrHandshake = errors.New("relaymux: handshake refused")
	ErrProtocol  = errors.New("relaymux: protocol violation")
	ErrRefused   = errors.New("relaymux: connection refused by the home side")
	ErrClosed    = errors.New("relaymux: session closed")
)

var muxMagic = []byte("SBM1")

// Options are what both ends share.
type Options struct {
	RunID  string
	Secret []byte
	Conn   sandboxrelay.ConnLimits
	Now    func() time.Time
}

func (o *Options) fill() {
	if o.Conn == (sandboxrelay.ConnLimits{}) {
		o.Conn = DefaultConnLimits
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// control is one control message.
type control struct {
	Op     string   `json:"op"`
	ID     uint32   `json:"id,omitempty"`
	Kind   string   `json:"kind,omitempty"`
	Stream uint32   `json:"stream,omitempty"`
	Reason string   `json:"reason,omitempty"`
	Rows   uint16   `json:"rows,omitempty"`
	Cols   uint16   `json:"cols,omitempty"`
	PTY    bool     `json:"pty,omitempty"`
	Kinds  []string `json:"kinds,omitempty"`
	Record []byte   `json:"record,omitempty"`
	Env    []string `json:"env,omitempty"`
	// Log, in a hello, says the home side keeps the run's relay log and
	// accepts opLog (an older guest ignores it; an older home side never
	// sets it, so a newer guest never sends opLog to it).
	Log bool `json:"log,omitempty"`
	// Keep, in a hello, says the home side accepts opKeeperKey: the guest's
	// PTY keeper may send its keeper-only attach key home (SBX-UPD audit
	// finding 2). Key, in a hello, is the keeper key the home side hands a
	// guest attach verb; in an opKeeperKey, the key the keeper minted. An
	// older peer ignores both.
	Keep bool   `json:"keep,omitempty"`
	Key  []byte `json:"key,omitempty"`
}

// The control ops.
const (
	opHello   = "hello"
	opConnect = "connect"
	opOpen    = "open"
	opRefuse  = "refuse"
	opResize  = "resize"
	// opEOF says one side's local end will send nothing more on Stream (a
	// half close); the stream's frame-layer Close comes only once both
	// directions are done, so neither side ever sends after its Close.
	opEOF = "eof"
	// opReady is the guest's acknowledgement that it acted on the hello:
	// the box record is written and its sockets listen (live run
	// 2026-10-23, finding F2: the home side started the agent before the
	// record existed, so the in-box launch gate refused). The home side
	// starts the agent only after it.
	opReady = "ready"
	// opLog is one line from the guest for the run's kept relay log (lane
	// SBX-UPD, finding H1): why the guest closed a box connection, carried
	// in Reason. Sent only when the hello set Log.
	opLog = "log"
	// opKeeperKey carries, in Key, the keeper-only attach key the guest's
	// PTY keeper minted at --keep start (SBX-UPD audit finding 2). Sent only
	// when the hello set Keep.
	opKeeperKey = "keeper_key"
)

// MaxLogLine bounds one opLog line.
const MaxLogLine = 512

// stream is one open data stream.
type stream struct {
	id    uint32
	local io.ReadWriteCloser

	mu   sync.Mutex
	cond *sync.Cond
	// sendCredit is what this side may still send.
	sendCredit int64
	// recvLeft is what the peer may still send (this side's grant).
	recvLeft int64
	queue    []byte
	peerDone bool
	dead     bool
}

func newStream(id uint32) *stream {
	st := &stream{id: id, sendCredit: Window, recvLeft: Window}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// session is the shared engine of both ends.
type session struct {
	opts   Options
	host   bool
	r      *sandboxrelay.Reader
	w      *sandboxrelay.Writer
	c      sandboxrelay.Conn
	asm    *sandboxrelay.Assembler
	onCtl  func(control)
	mu     sync.Mutex
	strs   map[uint32]*stream
	done   chan struct{}
	err    error
	once   sync.Once
	closer io.Closer
}

func (s *session) fail(err error) {
	s.once.Do(func() {
		if err == nil {
			err = ErrClosed
		}
		s.err = err
		close(s.done)
		s.mu.Lock()
		for _, st := range s.strs {
			st.mu.Lock()
			st.dead = true
			st.cond.Broadcast()
			st.mu.Unlock()
			if st.local != nil {
				_ = st.local.Close()
			}
		}
		s.mu.Unlock()
		// Closing the stream ends the read loop's Next; the loop releases
		// the reader's buffer itself (it is in use until then).
		if s.closer != nil {
			_ = s.closer.Close()
		}
		s.w.Release()
	})
}

// sendControl writes one control message.
func (s *session) sendControl(m control) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return sandboxrelay.AppendMessageFrames(b, limits.MaxPayload, func(chunk []byte) error {
		return s.w.Write(sandboxrelay.TypeData, StreamControl, chunk)
	})
}

// readLoop routes every frame until the channel fails.
func (s *session) readLoop() {
	defer s.r.Release()
	for {
		h, p, err := s.r.Next()
		if err != nil {
			s.fail(err)
			return
		}
		if err := s.route(h, p); err != nil {
			s.fail(err)
			return
		}
	}
}

func (s *session) route(h sandboxrelay.Header, p []byte) error {
	switch h.Type {
	case sandboxrelay.TypePing, sandboxrelay.TypeOpen:
		return nil
	case sandboxrelay.TypeData:
		if h.Stream == StreamControl {
			msg, err := s.asm.Add(p)
			if err != nil {
				return fmt.Errorf("%w: control: %w", ErrProtocol, err)
			}
			if msg == nil {
				return nil
			}
			var m control
			dec := json.NewDecoder(bytes.NewReader(msg))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&m); err != nil {
				return fmt.Errorf("%w: control message: %w", ErrProtocol, err)
			}
			s.onCtl(m)
			return nil
		}
		st := s.stream(h.Stream)
		if st == nil {
			// A stream this side already let go of (its local side closed):
			// the bytes have nowhere to go.
			return nil
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		if int64(len(p)) > st.recvLeft {
			return fmt.Errorf("%w: stream %d sent past its window", ErrProtocol, h.Stream)
		}
		st.recvLeft -= int64(len(p))
		st.queue = append(st.queue, p...)
		st.cond.Broadcast()
		return nil
	case sandboxrelay.TypeWindow:
		st := s.stream(h.Stream)
		if st == nil {
			return nil
		}
		n := int64(binary.BigEndian.Uint32(p))
		st.mu.Lock()
		st.sendCredit += n
		if st.sendCredit > 2*Window {
			st.mu.Unlock()
			return fmt.Errorf("%w: stream %d granted past the window", ErrProtocol, h.Stream)
		}
		st.cond.Broadcast()
		st.mu.Unlock()
		return nil
	case sandboxrelay.TypeClose:
		// The peer is done with the stream in both directions.
		if st := s.stream(h.Stream); st != nil {
			st.mu.Lock()
			st.dead = true
			st.cond.Broadcast()
			st.mu.Unlock()
			_ = st.local.Close()
		}
		return nil
	}
	return fmt.Errorf("%w: frame type %d", ErrProtocol, h.Type)
}

func (s *session) stream(id uint32) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.strs[id]
}

func (s *session) addStream(st *stream) {
	s.mu.Lock()
	s.strs[st.id] = st
	s.mu.Unlock()
}

// peerEOF marks a stream's incoming direction finished (the peer's eof).
func (s *session) peerEOF(id uint32) {
	if st := s.stream(id); st != nil {
		st.mu.Lock()
		st.peerDone = true
		st.cond.Broadcast()
		st.mu.Unlock()
	}
}

func (s *session) dropStream(id uint32) {
	s.mu.Lock()
	delete(s.strs, id)
	s.mu.Unlock()
}

func (s *session) active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id := range s.strs {
		if id >= firstDynamic {
			n++
		}
	}
	return n
}

// pump moves bytes both ways between a stream and its local side until
// both directions end.
func (s *session) pump(st *stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.pumpOut(st) }()
	go func() { defer wg.Done(); s.pumpIn(st) }()
	wg.Wait()
	_ = st.local.Close()
	s.dropStream(st.id)
	select {
	case <-s.done:
	default:
		_ = s.w.Write(sandboxrelay.TypeClose, st.id, nil)
	}
}

// pumpOut sends what the local side writes, within the peer's credit.
func (s *session) pumpOut(st *stream) {
	buf := make([]byte, limits.MaxPayload)
	for {
		st.mu.Lock()
		for st.sendCredit <= 0 && !st.dead {
			st.cond.Wait()
		}
		credit, dead := st.sendCredit, st.dead
		st.mu.Unlock()
		if dead {
			return
		}
		want := int64(len(buf))
		if credit < want {
			want = credit
		}
		n, err := st.local.Read(buf[:want])
		if n > 0 {
			st.mu.Lock()
			st.sendCredit -= int64(n)
			st.mu.Unlock()
			if werr := s.w.Write(sandboxrelay.TypeData, st.id, buf[:n]); werr != nil {
				s.fail(werr)
				return
			}
		}
		if err != nil {
			_ = s.sendControl(control{Op: opEOF, Stream: st.id})
			return
		}
	}
}

// pumpIn writes what the peer sent to the local side, then grants the
// credit back.
func (s *session) pumpIn(st *stream) {
	for {
		st.mu.Lock()
		for len(st.queue) == 0 && !st.peerDone && !st.dead {
			st.cond.Wait()
		}
		q, done, dead := st.queue, st.peerDone, st.dead
		st.queue = nil
		st.mu.Unlock()
		if dead {
			return
		}
		if len(q) > 0 {
			if _, err := st.local.Write(q); err != nil {
				st.mu.Lock()
				st.dead = true
				st.cond.Broadcast()
				st.mu.Unlock()
				return
			}
			st.mu.Lock()
			st.recvLeft += int64(len(q))
			st.mu.Unlock()
			var grant [4]byte
			binary.BigEndian.PutUint32(grant[:], uint32(len(q))) //nolint:gosec // G115: bounded by Window
			if err := s.w.Write(sandboxrelay.TypeWindow, st.id, grant[:]); err != nil {
				s.fail(err)
				return
			}
			continue
		}
		if done {
			if cw, ok := st.local.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			} else {
				_ = st.local.Close()
			}
			return
		}
	}
}

func (s *session) heartbeat() {
	t := time.NewTicker(HeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if err := s.w.Write(sandboxrelay.TypePing, 0, nil); err != nil {
				s.fail(err)
				return
			}
		}
	}
}

// ---- the home side -----------------------------------------------------------

// HostOptions configure the home side.
type HostOptions struct {
	Options
	// Rand supplies the nonce.
	Rand io.Reader
	// Kinds are the connection kinds the run's tier allows (the relay
	// always; the model proxy unless the tier is none).
	Kinds map[string]bool
	// Dial connects one guest request to the home side's own socket.
	Dial func(ctx context.Context, kind string) (io.ReadWriteCloser, error)
	// PTY, when set, is the terminal the box PTY is bridged to (the guest
	// helper owns the box PTY): Read is the user's input, Write the box's
	// output.
	PTY io.ReadWriteCloser
	// Record is the box launch record the guest writes into its socket
	// dir (the relay's box secret travels inside the authenticated
	// channel).
	Record []byte
	// Env is the launch environment the guest starts the agent with
	// (NAME=value; the Apple container row, whose container config would
	// otherwise keep it on disk): it travels inside the authenticated
	// channel. The hosted rows send none.
	Env []string
	// Log, when set, receives one line per stream the home side refused or
	// could not dial (with why) and each line the guest sends for the run's
	// kept relay log (lane SBX-UPD, finding H1). Nil: nothing is logged and
	// the hello does not offer the guest a log.
	Log func(line string)
	// KeeperKey, when set, receives the keeper-only attach key the guest's
	// PTY keeper mints at --keep start (SBX-UPD audit finding 2): the home
	// side keeps it in the run's own record, never in the box record the
	// in-box hooks read. Nil: the hello offers the keeper no channel, so a
	// keeper started under it serves no attach socket.
	KeeperKey func(key []byte)
	// AttachKey is the keeper key a re-adoption's home side hands the guest
	// attach verb inside the authenticated channel; the verb proves itself
	// to the keeper with it, so nothing a box process can read from disk
	// authenticates an attach.
	AttachKey []byte
}

// Host is the home side of one mux session.
type Host struct {
	s      *session
	opts   HostOptions
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	next   uint32
	// ready is closed by the guest's opReady (once).
	ready     chan struct{}
	readyOnce sync.Once
}

// ServeHost runs the handshake on c and starts the home side.
func ServeHost(ctx context.Context, c sandboxrelay.Conn, o HostOptions) (*Host, error) {
	o.fill()
	if o.Rand == nil || o.Dial == nil || !sandboxrelay.ValidRunID(o.RunID) || len(o.Secret) < 16 {
		return nil, fmt.Errorf("%w: host options", ErrHandshake)
	}
	nonce := make([]byte, sandboxrelay.NonceSize)
	if _, err := io.ReadFull(o.Rand, nonce); err != nil {
		return nil, err
	}
	pre := append(append(append([]byte(nil), muxMagic...), 1, 0, 0, 0), nonce...)
	if err := c.SetWriteDeadline(o.Now().Add(o.Conn.WriteDeadline)); err != nil {
		return nil, err
	}
	if _, err := c.Write(pre); err != nil {
		return nil, fmt.Errorf("%w: preamble: %w", ErrHandshake, err)
	}
	if err := c.SetReadDeadline(o.Now().Add(o.Conn.FrameDeadline)); err != nil {
		return nil, err
	}
	var fixed [6]byte
	if _, err := io.ReadFull(c, fixed[:]); err != nil {
		return nil, fmt.Errorf("%w: hello: %w", ErrHandshake, err)
	}
	if !bytes.Equal(fixed[:4], muxMagic) || fixed[4] != 1 || int(fixed[5]) != len(o.RunID) {
		return nil, fmt.Errorf("%w: hello", ErrHandshake)
	}
	id := make([]byte, fixed[5])
	if _, err := io.ReadFull(c, id); err != nil || string(id) != o.RunID {
		return nil, fmt.Errorf("%w: run id", ErrHandshake)
	}
	k, err := sandboxrelay.DeriveKeys(o.Secret, sandboxrelay.PurposeBox, o.RunID, nonce, 0)
	if err != nil {
		return nil, err
	}
	s := &session{
		opts: o.Options, host: true, c: c, strs: map[uint32]*stream{}, done: make(chan struct{}),
		r:   sandboxrelay.NewReader(c, sandboxrelay.NewOpener(sandboxrelay.HostSide, k.GuestToHost, 0, limits), o.Conn, o.Now),
		w:   sandboxrelay.NewWriter(c, sandboxrelay.NewSealer(k.HostToGuest, 0), o.Conn.WriteDeadline, o.Now),
		asm: sandboxrelay.NewAssembler(maxControl),
	}
	if cl, ok := c.(io.Closer); ok {
		s.closer = cl
	}
	hctx, cancel := context.WithCancel(ctx)
	h := &Host{s: s, opts: o, ctx: hctx, cancel: cancel, next: firstDynamic, ready: make(chan struct{})}
	s.onCtl = h.onControl
	if err := s.r.Opener().Grant(StreamControl); err != nil {
		cancel()
		return nil, err
	}
	if err := s.w.Write(sandboxrelay.TypeOpen, StreamControl, nil); err != nil {
		cancel()
		return nil, err
	}
	var kinds []string
	for _, kd := range []string{KindRelay, KindProxy, KindGateway} {
		if o.Kinds[kd] {
			kinds = append(kinds, kd)
		}
	}
	if o.PTY != nil {
		if err := s.r.Opener().Grant(StreamPTY); err != nil {
			cancel()
			return nil, err
		}
		if err := s.w.Write(sandboxrelay.TypeOpen, StreamPTY, nil); err != nil {
			cancel()
			return nil, err
		}
	}
	if err := s.sendControl(control{Op: opHello, PTY: o.PTY != nil, Kinds: kinds, Record: o.Record, Env: o.Env, Log: o.Log != nil, Keep: o.KeeperKey != nil, Key: o.AttachKey}); err != nil {
		cancel()
		return nil, err
	}
	if o.PTY != nil {
		st := newStream(StreamPTY)
		st.local = o.PTY
		s.addStream(st)
		go s.pump(st)
	}
	go s.readLoop()
	go s.heartbeat()
	go func() {
		<-s.done
		cancel()
	}()
	return h, nil
}

// onControl handles a guest request.
func (h *Host) onControl(m control) {
	if m.Op == opEOF {
		h.s.peerEOF(m.Stream)
		return
	}
	if m.Op == opReady {
		h.readyOnce.Do(func() { close(h.ready) })
		return
	}
	if m.Op == opLog {
		h.log("guest: " + clipLogLine(m.Reason))
		return
	}
	if m.Op == opKeeperKey {
		if h.opts.KeeperKey == nil || len(m.Key) < minKeeperKey {
			h.s.fail(fmt.Errorf("%w: an unrequested or short keeper key", ErrProtocol))
			return
		}
		h.opts.KeeperKey(bytes.Clone(m.Key))
		return
	}
	if m.Op != opConnect {
		h.s.fail(fmt.Errorf("%w: the guest sent control op %q", ErrProtocol, m.Op))
		return
	}
	refuse := func(why string) {
		h.log("refused a " + clipLogLine(m.Kind) + " connection from the box: " + why)
		_ = h.s.sendControl(control{Op: opRefuse, ID: m.ID, Reason: why})
	}
	if !h.opts.Kinds[m.Kind] {
		refuse("kind not allowed on this run's tier")
		return
	}
	if h.s.active() >= MaxActiveStreams {
		refuse("too many open connections")
		return
	}
	h.mu.Lock()
	if h.next >= firstDynamic+maxStreamsPerSession {
		h.mu.Unlock()
		// The frame layer keeps every stream id; a fresh session re-keys.
		h.s.fail(fmt.Errorf("%w: stream ids exhausted; the session is re-opened", ErrClosed))
		return
	}
	id := h.next
	h.next++
	h.mu.Unlock()
	// The frame layer's stream state belongs to the read loop, which runs
	// this handler: the grant happens here, before the dial.
	if err := h.s.r.Opener().Grant(id); err != nil {
		h.s.fail(err)
		return
	}
	go func() {
		local, err := h.opts.Dial(h.ctx, m.Kind)
		if err != nil {
			h.log("could not connect a " + clipLogLine(m.Kind) + " connection to the home side: " + clipLogLine(err.Error()))
			refuse("the home side could not connect")
			return
		}
		st := newStream(id)
		st.local = local
		h.s.addStream(st)
		if err := h.s.w.Write(sandboxrelay.TypeOpen, id, nil); err != nil {
			_ = local.Close()
			h.s.fail(err)
			return
		}
		if err := h.s.sendControl(control{Op: opOpen, ID: m.ID, Stream: id}); err != nil {
			_ = local.Close()
			h.s.fail(err)
			return
		}
		h.s.pump(st)
	}()
}

// log passes one line to HostOptions.Log (nothing without one).
func (h *Host) log(line string) {
	if h.opts.Log != nil {
		h.opts.Log(line)
	}
}

// clipLogLine keeps a log line to MaxLogLine bytes of printable text.
func clipLogLine(s string) string {
	out := make([]rune, 0, len(s))
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		n += len(string(r))
		if n > MaxLogLine {
			break
		}
		out = append(out, r)
	}
	return string(out)
}

// Resize sends the terminal's size to the guest helper's PTY.
func (h *Host) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}
	return h.s.sendControl(control{Op: opResize, Rows: rows, Cols: cols})
}

// Ready is closed once the guest acknowledged the hello (Guest.Ready): the
// box record it carried is written and the guest's sockets listen.
func (h *Host) Ready() <-chan struct{} { return h.ready }

// Done is closed when the session ends; Err says why.
func (h *Host) Done() <-chan struct{} { return h.s.done }

// Err is the reason the session ended (nil while it runs).
func (h *Host) Err() error {
	select {
	case <-h.s.done:
		return h.s.err
	default:
		return nil
	}
}

// Close ends the session.
func (h *Host) Close() { h.s.fail(ErrClosed) }

// ---- the box side ------------------------------------------------------------

// Hello is what the home side told the guest at the start.
type Hello struct {
	PTY    bool
	Kinds  []string
	Record []byte
	// Env is the launch environment the home side sent (HostOptions.Env).
	Env []string
	// Log: the home side keeps a relay log and accepts Guest.Log.
	Log bool
	// Keep: the home side keeps a PTY keeper's key (Guest.SendKeeperKey).
	Keep bool
	// AttachKey is the keeper key the home side handed an attach verb
	// (HostOptions.AttachKey); empty otherwise.
	AttachKey []byte
}

// Size is one terminal size.
type Size struct{ Rows, Cols uint16 }

// Guest is the box side of one mux session.
type Guest struct {
	s       *session
	hello   Hello
	helloCh chan struct{}
	resizes chan Size
	mu      sync.Mutex
	nextID  uint32
	waits   map[uint32]chan answer
	pty     *pipeEnd
}

// answer is the home side's reply to one Connect.
type answer struct {
	m    control
	conn io.ReadWriteCloser
}

// DialGuest runs the box side of the handshake on c and waits for the
// home side's hello.
func DialGuest(ctx context.Context, c sandboxrelay.Conn, o Options) (*Guest, error) {
	o.fill()
	if !sandboxrelay.ValidRunID(o.RunID) || len(o.Secret) < 16 {
		return nil, fmt.Errorf("%w: guest options", ErrHandshake)
	}
	if err := c.SetReadDeadline(o.Now().Add(o.Conn.FrameDeadline)); err != nil {
		return nil, err
	}
	pre := make([]byte, 8+sandboxrelay.NonceSize)
	if _, err := io.ReadFull(c, pre); err != nil {
		return nil, fmt.Errorf("%w: preamble: %w", ErrHandshake, err)
	}
	if !bytes.Equal(pre[:4], muxMagic) || pre[4] != 1 {
		return nil, fmt.Errorf("%w: preamble", ErrHandshake)
	}
	nonce := pre[8:]
	hello := append(append(append([]byte(nil), muxMagic...), 1, byte(len(o.RunID))), o.RunID...)
	if err := c.SetWriteDeadline(o.Now().Add(o.Conn.WriteDeadline)); err != nil {
		return nil, err
	}
	if _, err := c.Write(hello); err != nil {
		return nil, fmt.Errorf("%w: hello: %w", ErrHandshake, err)
	}
	k, err := sandboxrelay.DeriveKeys(o.Secret, sandboxrelay.PurposeBox, o.RunID, nonce, 0)
	if err != nil {
		return nil, err
	}
	s := &session{
		opts: o, c: c, strs: map[uint32]*stream{}, done: make(chan struct{}),
		r:   sandboxrelay.NewReader(c, sandboxrelay.NewOpener(sandboxrelay.GuestSide, k.HostToGuest, 0, limits), o.Conn, o.Now),
		w:   sandboxrelay.NewWriter(c, sandboxrelay.NewSealer(k.GuestToHost, 0), o.Conn.WriteDeadline, o.Now),
		asm: sandboxrelay.NewAssembler(maxControl),
	}
	if cl, ok := c.(io.Closer); ok {
		s.closer = cl
	}
	g := &Guest{s: s, helloCh: make(chan struct{}), resizes: make(chan Size, 8), nextID: 1, waits: map[uint32]chan answer{}}
	s.onCtl = g.onControl
	go s.readLoop()
	go s.heartbeat()
	select {
	case <-g.helloCh:
	case <-s.done:
		return nil, s.err
	case <-ctx.Done():
		s.fail(ctx.Err())
		return nil, ctx.Err()
	}
	return g, nil
}

func (g *Guest) onControl(m control) {
	switch m.Op {
	case opHello:
		select {
		case <-g.helloCh:
			g.s.fail(fmt.Errorf("%w: a second hello", ErrProtocol))
			return
		default:
		}
		g.hello = Hello{PTY: m.PTY, Kinds: m.Kinds, Record: m.Record, Env: m.Env, Log: m.Log, Keep: m.Keep, AttachKey: m.Key}
		if m.PTY {
			a, b := newPipePair()
			g.pty = a
			st := newStream(StreamPTY)
			st.local = b
			g.s.addStream(st)
			go g.s.pump(st)
		}
		close(g.helloCh)
	case opEOF:
		g.s.peerEOF(m.Stream)
	case opResize:
		select {
		case g.resizes <- Size{Rows: m.Rows, Cols: m.Cols}:
		default:
		}
	case opOpen, opRefuse:
		g.mu.Lock()
		ch := g.waits[m.ID]
		delete(g.waits, m.ID)
		g.mu.Unlock()
		if ch == nil {
			g.s.fail(fmt.Errorf("%w: an answer to no request", ErrProtocol))
			return
		}
		ans := answer{m: m}
		if m.Op == opOpen {
			if m.Stream < firstDynamic {
				g.s.fail(fmt.Errorf("%w: open of a fixed stream", ErrProtocol))
				return
			}
			// The stream is added here, in the read loop, before any of its
			// data can be routed.
			a, b := newPipePair()
			st := newStream(m.Stream)
			st.local = b
			g.s.addStream(st)
			go g.s.pump(st)
			ans.conn = a
		}
		ch <- ans
	default:
		g.s.fail(fmt.Errorf("%w: the home side sent control op %q", ErrProtocol, m.Op))
	}
}

// Hello returns what the home side said at the start.
func (g *Guest) Hello() Hello { return g.hello }

// PTY is the box PTY's stream (nil when the home side owns no PTY here):
// Read is the user's input, Write the PTY's output.
func (g *Guest) PTY() io.ReadWriteCloser {
	if g.pty == nil {
		return nil
	}
	return g.pty
}

// Log sends one line for the run's kept relay log when the home side keeps
// one (lane SBX-UPD, finding H1); otherwise it does nothing.
func (g *Guest) Log(line string) {
	if !g.hello.Log {
		return
	}
	_ = g.s.sendControl(control{Op: opLog, Reason: clipLogLine(line)})
}

// minKeeperKey is the shortest keeper key either side accepts.
const minKeeperKey = 16

// errNoKeeperChannel refuses SendKeeperKey when the hello did not offer one.
var errNoKeeperChannel = errors.New("relaymux: the home side keeps no keeper key")

// SendKeeperKey sends the PTY keeper's keeper-only attach key home, inside
// the authenticated channel, where the home side keeps it in the run's own
// record (SBX-UPD audit finding 2). It refuses when the hello did not offer
// the channel (HostOptions.KeeperKey) or the key is short.
func (g *Guest) SendKeeperKey(key []byte) error {
	if !g.hello.Keep {
		return errNoKeeperChannel
	}
	if len(key) < minKeeperKey {
		return fmt.Errorf("%w: a short keeper key", ErrProtocol)
	}
	return g.s.sendControl(control{Op: opKeeperKey, Key: key})
}

// Ready tells the home side the guest acted on the hello (its box record
// is written and its sockets listen), so the home side may start the agent.
func (g *Guest) Ready() error { return g.s.sendControl(control{Op: opReady}) }

// Resizes delivers the terminal sizes the home side sends.
func (g *Guest) Resizes() <-chan Size { return g.resizes }

// Connect asks the home side for a connection of kind and returns its
// stream once opened.
func (g *Guest) Connect(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	g.mu.Lock()
	id := g.nextID
	g.nextID++
	ch := make(chan answer, 1)
	g.waits[id] = ch
	g.mu.Unlock()
	if err := g.s.sendControl(control{Op: opConnect, ID: id, Kind: kind}); err != nil {
		return nil, err
	}
	select {
	case a := <-ch:
		if a.m.Op == opRefuse {
			return nil, fmt.Errorf("%w: %s", ErrRefused, a.m.Reason)
		}
		return a.conn, nil
	case <-g.s.done:
		return nil, g.s.err
	case <-ctx.Done():
		// An open that arrives later finds no waiter's channel drained; its
		// stream closes when the session does.
		return nil, ctx.Err()
	}
}

// Done is closed when the session ends.
func (g *Guest) Done() <-chan struct{} { return g.s.done }

// Err is why the session ended.
func (g *Guest) Err() error {
	select {
	case <-g.s.done:
		return g.s.err
	default:
		return nil
	}
}

// Close ends the session.
func (g *Guest) Close() { g.s.fail(ErrClosed) }
