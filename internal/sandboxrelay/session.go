package sandboxrelay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// The handshake. The server (the side that verifies the hostile peer: the
// host helper on the box channel, the daemon on the link) speaks first:
//
//	preamble  "SBR1" | version 1 | purpose | 0 | 0 | nonce[32]      40 bytes
//	hello     "SBR1" | version 1 | purpose | len | run id[len]       7+len bytes
//
// Neither is MAC'd: both feed the key derivation, so a changed nonce,
// purpose or run id only produces keys that disagree and the first frame
// fails its MAC. The server then opens the hook stream with an Open frame.

// StreamHook is the hook stream id.
const StreamHook uint32 = 1

const (
	preambleSize = 40
	helloFixed   = 7
	// MaxRunID bounds the run id in the hello.
	MaxRunID = 64
)

var handshakeMagic = []byte("SBR1")

// ErrHandshake reports a malformed or refused handshake.
var ErrHandshake = errors.New("sandboxrelay: handshake refused")

// ErrNoHello reports a peer that closed its connection before it sent a
// hello: a readiness check that dials and hangs up (the CLI's relay gate,
// Windows 11 Pro run 4, where the daemon warned once per launch that "the
// pipe is being closed"), or a peer that gave up before its handshake. It is
// not a refused handshake, and no secret was ever exchanged on it.
var ErrNoHello = errors.New("sandboxrelay: the peer closed before its hello")

// noHello reports whether err, from writing the preamble or reading the
// first hello byte, means the peer was already gone (not a deadline).
func noHello(err error) bool {
	var t interface{ Timeout() bool }
	return !(errors.As(err, &t) && t.Timeout())
}

// Params are the bounds and injected sources of a session.
type Params struct {
	Purpose Purpose
	Limits  Limits
	Conn    ConnLimits
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// Rand supplies the server's nonce (required on the server).
	Rand io.Reader
	// RekeyAfter is how many guest-to-host payload bytes one key epoch may
	// carry before the host re-keys the connection (zero: DefaultRekeyAfter;
	// negative: never). Only the host re-keys (sandbox plan section 5.2).
	RekeyAfter int64
	// ExpectBeat is the heartbeat interval of the peer this side waits on
	// (zero: none expected). Recv counts the heartbeats that did not come
	// (MissedBeats).
	ExpectBeat time.Duration
}

// DefaultRekeyAfter is the bytes one epoch carries before the host re-keys:
// a large hook payload (an 8 MiB prompt) crosses a few epochs, a typical
// one none (lane sbx-p2b: re-keying in use, not only in the codec).
const DefaultRekeyAfter = 4 << 20

// HeartbeatInterval is how often a server that is still working on a
// request pings the waiting peer (lane sbx-p2b: heartbeats in use). A
// waiting client can then use ClientConnLimits, whose idle bound is a few
// missed heartbeats instead of a whole guard decision.
const HeartbeatInterval = 5 * time.Second

// ClientConnLimits are DefaultConnLimits for a side that waits on a server
// which heartbeats: silence for three intervals means the server is gone.
var ClientConnLimits = func() ConnLimits {
	l := DefaultConnLimits
	l.IdleTimeout = 3 * HeartbeatInterval
	return l
}()

func (p Params) now() func() time.Time {
	if p.Now == nil {
		return time.Now
	}
	return p.Now
}

// Session is one authenticated connection, from either end.
type Session struct {
	// RunID is the run the channel speaks for: the server's lookup key, or
	// the id the client dialled with.
	RunID string
	r     *Reader
	w     *Writer
	p     Params
	// The key derivation inputs, kept for re-keying.
	secret, nonce []byte
	// host reports the server (re-keying) side; epoch is the current key
	// epoch; epochBytes the guest-to-host payload bytes seen under it.
	host       bool
	epoch      uint32
	epochBytes int64
	// missed counts heartbeats this side missed: pings it could not send
	// or sent late, and pings it waited for that did not come.
	missed atomic.Int64
}

// MissedBeats returns the heartbeats this side missed (plans decision log
// P-032: missed heartbeats are counted and reach the run's evidence).
func (s *Session) MissedBeats() int { return int(s.missed.Load()) }

// noteGap counts the heartbeats a waiting side missed over a gap between
// frames: every interval past the first with no frame is one. failed says
// the wait ended without a frame (every interval of it was missed).
func (s *Session) noteGap(gap time.Duration, failed bool) {
	every := s.p.ExpectBeat
	if every <= 0 {
		return
	}
	n := int64(gap / every)
	if !failed {
		if gap <= every*3/2 {
			return
		}
		n--
	}
	if n > 0 {
		s.missed.Add(n)
	}
}

// ErrRekey reports a re-key announcement that is out of order.
var ErrRekey = errors.New("sandboxrelay: bad re-key announcement")

// Epoch returns the connection's current key epoch.
func (s *Session) Epoch() uint32 { return s.epoch }

// Rekey moves the connection to the next key epoch (host side only): it
// arms the guest's next keys at once, and the announcement of the epoch
// goes out under the current key in front of the next frame the host
// sends, after which the host seals under the next one. The guest follows
// on the announcement (onRekey); its frames already in flight under the old
// epoch still verify until its first frame of the new one.
func (s *Session) Rekey() error {
	if !s.host {
		return fmt.Errorf("%w: only the host re-keys", ErrRekey)
	}
	next := s.epoch + 1
	k, err := DeriveKeys(s.secret, s.p.Purpose, s.RunID, s.nonce, next)
	if err != nil {
		return err
	}
	s.r.Opener().Rekey(k.GuestToHost, next)
	var ann [4]byte
	binary.BigEndian.PutUint32(ann[:], next)
	s.w.scheduleRekey(ann[:], k.HostToGuest, next)
	s.epoch, s.epochBytes = next, 0
	return nil
}

// onRekey follows a host's announcement (guest side): the announced epoch
// must be the next one; the host's next frames verify under it, and this
// side's frames are sealed under it from now on.
func (s *Session) onRekey(payload []byte) error {
	if s.host || len(payload) != 4 || binary.BigEndian.Uint32(payload) != s.epoch+1 {
		return ErrRekey
	}
	next := s.epoch + 1
	k, err := DeriveKeys(s.secret, s.p.Purpose, s.RunID, s.nonce, next)
	if err != nil {
		return err
	}
	s.r.Opener().Rekey(k.HostToGuest, next)
	s.w.switchKey(k.GuestToHost, next)
	s.epoch = next
	return nil
}

// countForRekey adds n guest-to-host payload bytes to the epoch and
// re-keys the connection once the epoch has carried RekeyAfter (host side).
func (s *Session) countForRekey(n int) error {
	if !s.host {
		return nil
	}
	limit := s.p.RekeyAfter
	if limit == 0 {
		limit = DefaultRekeyAfter
	}
	if limit < 0 {
		return nil
	}
	s.epochBytes += int64(n)
	// Never announce another epoch before the guest's first frame under
	// the last one (its keys would no longer be armed).
	if s.epochBytes < limit || s.r.Opener().pending != nil {
		return nil
	}
	return s.Rekey()
}

// Heartbeat pings the peer every interval until the returned stop is
// called (a server working on a request, so the waiting peer can tell
// "still working" from "gone"). It costs one timer and no goroutine until
// the first interval passes, so a request answered at once pays nothing.
// stop waits for a ping in progress, so no ping follows the answer; a
// failed ping ends the heartbeat.
func (s *Session) Heartbeat(interval time.Duration) (stop func()) {
	if interval <= 0 {
		interval = HeartbeatInterval
	}
	var (
		mu      sync.Mutex
		stopped bool
		t       *time.Timer
		last    = time.Now()
	)
	beat := func() {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		// A beat that fires two intervals or more after the last one was
		// late (this side stalled): the beats between were missed.
		now := time.Now()
		if late := int64(now.Sub(last)/interval) - 1; late > 0 {
			s.missed.Add(late)
		}
		last = now
		if s.Ping() != nil {
			s.missed.Add(1)
			stopped = true
			return
		}
		t.Reset(interval)
	}
	mu.Lock()
	t = time.AfterFunc(interval, beat)
	mu.Unlock()
	return func() {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		t.Stop()
	}
}

// ValidRunID reports whether id is a run id the handshake carries:
// 1..MaxRunID bytes of [A-Za-z0-9_-].
func ValidRunID(id string) bool {
	if id == "" || len(id) > MaxRunID {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Accept runs the server side of the handshake on c. lookup returns the
// secret of the run the client names; an error refuses the connection
// before any frame is read.
func Accept(c Conn, p Params, lookup func(runID string) ([]byte, error)) (*Session, error) {
	if !p.Purpose.valid() || p.Rand == nil {
		return nil, fmt.Errorf("%w: server params", ErrHandshake)
	}
	now := p.now()
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(p.Rand, nonce); err != nil {
		return nil, fmt.Errorf("sandboxrelay.Accept: nonce: %w", err)
	}
	pre := make([]byte, 0, preambleSize)
	pre = append(pre, handshakeMagic...)
	pre = append(pre, frameVersion, byte(p.Purpose), 0, 0)
	pre = append(pre, nonce...)
	if err := c.SetWriteDeadline(now().Add(p.Conn.WriteDeadline)); err != nil {
		// A connection whose peer already hung up refuses even the deadline.
		return nil, fmt.Errorf("sandboxrelay.Accept: preamble: %w: %w", ErrNoHello, err)
	}
	if _, err := c.Write(pre); err != nil {
		if noHello(err) {
			return nil, fmt.Errorf("sandboxrelay.Accept: preamble: %w: %w", ErrNoHello, err)
		}
		return nil, fmt.Errorf("sandboxrelay.Accept: preamble: %w", err)
	}
	if err := c.SetReadDeadline(now().Add(p.Conn.FrameDeadline)); err != nil {
		return nil, err
	}
	var fixed [helloFixed]byte
	if _, err := io.ReadFull(c, fixed[:]); err != nil {
		if errors.Is(err, io.EOF) {
			// io.ReadFull returns io.EOF only when not one byte arrived.
			return nil, fmt.Errorf("sandboxrelay.Accept: hello: %w: %w", ErrNoHello, err)
		}
		return nil, fmt.Errorf("sandboxrelay.Accept: hello: %w", err)
	}
	if !bytes.Equal(fixed[:4], handshakeMagic) || fixed[4] != frameVersion || Purpose(fixed[5]) != p.Purpose {
		return nil, fmt.Errorf("%w: hello", ErrHandshake)
	}
	n := int(fixed[6])
	if n == 0 || n > MaxRunID {
		return nil, fmt.Errorf("%w: run id length", ErrHandshake)
	}
	id := make([]byte, n)
	if _, err := io.ReadFull(c, id); err != nil {
		return nil, fmt.Errorf("sandboxrelay.Accept: hello: %w", err)
	}
	runID := string(id)
	if !ValidRunID(runID) {
		return nil, fmt.Errorf("%w: run id", ErrHandshake)
	}
	secret, err := lookup(runID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	k, err := DeriveKeys(secret, p.Purpose, runID, nonce, 0)
	if err != nil {
		return nil, err
	}
	s := &Session{
		RunID:  runID,
		r:      NewReader(c, NewOpener(HostSide, k.GuestToHost, 0, p.Limits), p.Conn, now),
		w:      NewWriter(c, NewSealer(k.HostToGuest, 0), p.Conn.WriteDeadline, now),
		p:      p,
		secret: append([]byte(nil), secret...), nonce: nonce, host: true,
	}
	if err := s.r.Opener().Grant(StreamHook); err != nil {
		return nil, err
	}
	if err := s.w.Write(TypeOpen, StreamHook, nil); err != nil {
		return nil, fmt.Errorf("sandboxrelay.Accept: open: %w", err)
	}
	return s, nil
}

// Dial runs the client side of the handshake on c for runID with the
// run's secret, and waits for the server to open the hook stream.
func Dial(c Conn, p Params, runID string, secret []byte) (*Session, error) {
	if !p.Purpose.valid() || !ValidRunID(runID) {
		return nil, fmt.Errorf("%w: client params", ErrHandshake)
	}
	now := p.now()
	if err := c.SetReadDeadline(now().Add(p.Conn.FrameDeadline)); err != nil {
		return nil, err
	}
	pre := make([]byte, preambleSize)
	if _, err := io.ReadFull(c, pre); err != nil {
		return nil, fmt.Errorf("sandboxrelay.Dial: preamble: %w", err)
	}
	if !bytes.Equal(pre[:4], handshakeMagic) || pre[4] != frameVersion || Purpose(pre[5]) != p.Purpose || pre[6] != 0 || pre[7] != 0 {
		return nil, fmt.Errorf("%w: preamble", ErrHandshake)
	}
	nonce := pre[8:]
	hello := make([]byte, 0, helloFixed+len(runID))
	hello = append(hello, handshakeMagic...)
	hello = append(hello, frameVersion, byte(p.Purpose), byte(len(runID)))
	hello = append(hello, runID...)
	if err := c.SetWriteDeadline(now().Add(p.Conn.WriteDeadline)); err != nil {
		return nil, err
	}
	if _, err := c.Write(hello); err != nil {
		return nil, fmt.Errorf("sandboxrelay.Dial: hello: %w", err)
	}
	k, err := DeriveKeys(secret, p.Purpose, runID, nonce, 0)
	if err != nil {
		return nil, err
	}
	s := &Session{
		RunID:  runID,
		r:      NewReader(c, NewOpener(GuestSide, k.HostToGuest, 0, p.Limits), p.Conn, now),
		w:      NewWriter(c, NewSealer(k.GuestToHost, 0), p.Conn.WriteDeadline, now),
		p:      p,
		secret: append([]byte(nil), secret...), nonce: append([]byte(nil), nonce...),
	}
	h, _, err := s.r.Next()
	if err != nil {
		return nil, fmt.Errorf("sandboxrelay.Dial: %w", err)
	}
	if h.Type != TypeOpen || h.Stream != StreamHook {
		return nil, fmt.Errorf("%w: expected the hook stream to open", ErrState)
	}
	return s, nil
}

// Send writes msg on stream as one message.
func (s *Session) Send(stream uint32, msg []byte) error {
	return messageParts(msg, s.p.Limits.MaxPayload, func(prefix, chunk []byte) error {
		return s.w.write2(TypeData, stream, prefix, chunk)
	})
}

// Release returns the session's frame buffers to the pool once its
// connection is done; the session cannot be used afterwards. A message an
// earlier Recv returned stays valid (it is never the read buffer).
func (s *Session) Release() {
	s.r.Release()
	s.w.Release()
}

// Recv reads frames until one whole message has arrived on stream, under
// the message deadline from its first frame. Heartbeats are skipped; data
// on another stream, or the stream closing mid-message, is fatal.
func (s *Session) Recv(stream uint32, max int) ([]byte, error) {
	a := NewAssembler(max)
	defer s.r.CapDeadline(time.Time{})
	last := s.p.now()()
	for {
		h, payload, err := s.r.Next()
		now := s.p.now()()
		s.noteGap(now.Sub(last), err != nil)
		last = now
		if err != nil {
			return nil, err
		}
		switch h.Type {
		case TypePing:
			continue
		case TypeRekey:
			if err := s.onRekey(payload); err != nil {
				return nil, err
			}
			continue
		case TypeData:
			if h.Stream != stream {
				return nil, fmt.Errorf("%w: data on stream %d", ErrState, h.Stream)
			}
			if !a.Pending() && s.p.Conn.MessageDeadline > 0 {
				s.r.CapDeadline(s.p.now()().Add(s.p.Conn.MessageDeadline))
			}
			n := len(payload)
			msg, err := a.Add(payload)
			if err != nil {
				return nil, err
			}
			if err := s.countForRekey(n); err != nil {
				return nil, err
			}
			if msg != nil {
				return msg, nil
			}
		case TypeClose:
			return nil, fmt.Errorf("%w: stream %d closed before a whole message", ErrState, h.Stream)
		default:
			return nil, fmt.Errorf("%w: frame type %d", ErrState, h.Type)
		}
	}
}

// ForwardChecks are what a cut-through Forward checks before it passes a
// message on.
type ForwardChecks struct {
	// Head judges the message's leading bytes: done=false asks for more,
	// an error refuses. Nothing is forwarded (and the next hop is not even
	// opened) until it is done.
	Head func(sofar []byte) (done bool, err error)
	// Whole judges the complete message before its last frame is
	// forwarded, so the next hop never receives a whole message that
	// fails it.
	Whole func(msg []byte) error
}

// Forward reads one message on stream from s and writes it to the session
// open returns, on the same stream, frame by frame as each frame verifies
// (lane sbx-p2b: a store-and-forward helper put four MAC passes over a
// large payload one after another; cut-through lets the hops overlap). It
// opens the next hop only after checks.Head is done and forwards the final
// bytes only after checks.Whole passed. It returns the next hop's session
// (nil when it was never opened; the caller releases it) and the whole
// message.
func (s *Session) Forward(stream uint32, max int, checks ForwardChecks, open func() (*Session, error)) (*Session, []byte, error) {
	a := NewAssembler(max)
	defer s.r.CapDeadline(time.Time{})
	var dst *Session
	// The next hop is written on its own goroutine, so verifying a frame
	// under this hop's key and sealing the previous one under the next
	// hop's key run side by side. It is handed snapshots of the assembled
	// body: the bytes of a snapshot are never written again (the
	// assembler only appends past them), so the two never touch the same
	// memory.
	var (
		out     chan []byte
		werr    error
		wdone   chan struct{}
		failed  = make(chan struct{})
		stopped bool
	)
	stop := func() error {
		if out == nil || stopped {
			return werr
		}
		stopped = true
		close(out)
		<-wdone
		return werr
	}
	defer func() { _ = stop() }()
	var prefix [messagePrefix]byte
	headDone := false
	for {
		payload, err := s.nextData(stream)
		if err != nil {
			return dst, nil, err
		}
		if !a.Pending() && s.p.Conn.MessageDeadline > 0 {
			s.r.CapDeadline(s.p.now()().Add(s.p.Conn.MessageDeadline))
		}
		n := len(payload)
		msg, err := a.Add(payload)
		if err != nil {
			return dst, nil, err
		}
		if err := s.countForRekey(n); err != nil {
			return dst, nil, err
		}
		sofar, want := a.have, a.want
		if msg != nil {
			sofar, want = msg, len(msg)
		}
		if !headDone {
			done, err := checks.Head(sofar)
			if err != nil {
				return dst, nil, err
			}
			if !done && msg == nil {
				continue
			}
			headDone = true
			if dst, err = open(); err != nil {
				return nil, nil, err
			}
			binary.BigEndian.PutUint32(prefix[:], uint32(want)) //nolint:gosec // G115: bounded by the assembler's cap
			if msg != nil {
				// A message whole in its first frame has nothing to
				// overlap: forward it inline.
				if err := checks.Whole(msg); err != nil {
					return dst, nil, err
				}
				sent := 0
				if err := dst.forwardBytes(stream, &prefix, msg, &sent); err != nil {
					return dst, nil, err
				}
				return dst, msg, nil
			}
			out, wdone = make(chan []byte, 8), make(chan struct{})
			go func(dst *Session) {
				defer close(wdone)
				sent := 0
				for body := range out {
					if werr != nil {
						continue
					}
					if werr = dst.forwardBytes(stream, &prefix, body, &sent); werr != nil {
						// The next hop is gone (it closed a body that
						// dripped past its deadline, say): stop reading
						// this hop too, rather than hold it to the end.
						close(failed)
					}
				}
			}(dst)
		}
		if msg != nil {
			if err := checks.Whole(msg); err != nil {
				return dst, nil, err
			}
		}
		select {
		case <-failed:
			return dst, nil, stop()
		case out <- sofar:
		}
		if msg != nil {
			if err := stop(); err != nil {
				return dst, nil, err
			}
			return dst, msg, nil
		}
	}
}

// nextData returns the next Data payload on stream, following heartbeats
// and the host's re-key announcements on the way; a close or a frame of
// any other kind or stream is fatal.
func (s *Session) nextData(stream uint32) ([]byte, error) {
	for {
		h, payload, err := s.r.Next()
		if err != nil {
			return nil, err
		}
		switch h.Type {
		case TypePing:
			continue
		case TypeRekey:
			if err := s.onRekey(payload); err != nil {
				return nil, err
			}
			continue
		case TypeData:
			if h.Stream != stream {
				return nil, fmt.Errorf("%w: data on stream %d", ErrState, h.Stream)
			}
			return payload, nil
		case TypeClose:
			return nil, fmt.Errorf("%w: stream %d closed before a whole message", ErrState, h.Stream)
		default:
			return nil, fmt.Errorf("%w: frame type %d", ErrState, h.Type)
		}
	}
}

// forwardBytes sends body[*sent:] as Data frames (the first frame of the
// message carries prefix) and advances *sent.
func (s *Session) forwardBytes(stream uint32, prefix *[messagePrefix]byte, body []byte, sent *int) error {
	max := int(s.p.Limits.MaxPayload)
	for *sent < len(body) || (*sent == 0 && len(body) == 0) {
		var pre []byte
		room := max
		if *sent == 0 {
			pre, room = prefix[:], max-messagePrefix
		}
		k := min(room, len(body)-*sent)
		if err := s.w.write2(TypeData, stream, pre, body[*sent:*sent+k]); err != nil {
			return err
		}
		*sent += k
		if k == 0 {
			return nil
		}
	}
	return nil
}

// Ping sends a heartbeat.
func (s *Session) Ping() error { return s.w.Write(TypePing, 0, nil) }

// CloseStream ends stream from this side.
func (s *Session) CloseStream(stream uint32) error { return s.w.Write(TypeClose, stream, nil) }
