package sandboxrelay

import (
	"errors"
	"io"
	"sync"
	"time"
)

// ErrRate is returned when the peer exceeds the frame or byte rate.
var ErrRate = errors.New("sandboxrelay: rate limit exceeded")

// ReadConn is what a Reader needs of a connection.
type ReadConn interface {
	io.Reader
	SetReadDeadline(t time.Time) error
}

// WriteConn is what a Writer needs of a connection.
type WriteConn interface {
	io.Writer
	SetWriteDeadline(t time.Time) error
}

// Conn is a full duplex connection (a net.Conn satisfies it).
type Conn interface {
	ReadConn
	WriteConn
}

// ConnLimits bound one connection in time and rate.
type ConnLimits struct {
	// IdleTimeout is the most a peer may stay silent before a frame's
	// first byte.
	IdleTimeout time.Duration
	// FrameDeadline is ONE absolute deadline for the rest of a frame after
	// its first byte (never reset per read: a slow drip loses to it).
	FrameDeadline time.Duration
	// WriteDeadline bounds one frame write.
	WriteDeadline time.Duration
	// MessageDeadline is ONE absolute deadline for a whole message from
	// its first frame (the per-message deadline): a peer that sends a
	// message as a slow trickle of valid frames is closed at it.
	MessageDeadline time.Duration
	// FramesPerSec and BytesPerSec are token-bucket rates; Burst is the
	// bucket depth in seconds of rate.
	FramesPerSec float64
	BytesPerSec  float64
	Burst        float64
}

// DefaultConnLimits are the shipped bounds. The idle timeout covers a
// guard decision the daemon may take its time over (an ask); the frame
// deadline is generous for 64 KiB on a local socket and still closes a
// drip long before it could hold the run.
var DefaultConnLimits = ConnLimits{
	IdleTimeout:     60 * time.Second,
	FrameDeadline:   2 * time.Second,
	WriteDeadline:   5 * time.Second,
	MessageDeadline: 10 * time.Second,
	FramesPerSec:    4000,
	BytesPerSec:     64 << 20,
	Burst:           0.5,
}

// Reader reads and verifies frames from a connection. One goroutine.
type Reader struct {
	c   ReadConn
	o   *Opener
	lim ConnLimits
	buf []byte
	// have bytes of buf are read; the frame Next returned last is
	// buf[:used] and the bytes after it already belong to the next frame.
	have, used int
	err        error
	ftok       float64
	btok       float64
	last       time.Time
	now        func() time.Time
	// cap, when set, bounds every read deadline (the message deadline).
	cap time.Time
}

// ErrDeadline is returned when a frame or message misses its deadline on a
// clock the caller injected (a real connection reports its own timeout).
var ErrDeadline = errors.New("sandboxrelay: deadline exceeded")

// CapDeadline bounds every later read by t (the zero time removes the
// bound). A message's absolute deadline is set through it.
func (r *Reader) CapDeadline(t time.Time) { r.cap = t }

// deadline is now+d, capped by the message deadline.
func (r *Reader) deadline(d time.Duration) time.Time {
	t := r.now().Add(d)
	if !r.cap.IsZero() && r.cap.Before(t) {
		return r.cap
	}
	return t
}

// NewReader wraps c. The read buffer is one buffer of the maximum frame
// size for the reader's life, so a hostile peer cannot grow memory; it
// comes from a pool shared by every connection (lane sbx-p2b: four readers
// per relayed round trip each allocated and zeroed 64 KiB, the largest
// share of the relay's garbage), and Release returns it. now nil is
// time.Now.
func NewReader(c ReadConn, o *Opener, lim ConnLimits, now func() time.Time) *Reader {
	if now == nil {
		now = time.Now
	}
	return &Reader{
		c: c, o: o, lim: lim, buf: getFrameBuf(HeaderSize + int(o.lim.MaxPayload) + MACSize),
		ftok: lim.FramesPerSec * lim.Burst, btok: lim.BytesPerSec * lim.Burst, last: now(), now: now,
	}
}

// ErrReleased is returned by a Reader used after Release.
var ErrReleased = errors.New("sandboxrelay: reader released")

// Release returns the read buffer to the pool. Every later Next fails, and
// a payload an earlier Next returned is no longer valid. Idempotent.
func (r *Reader) Release() {
	if r.buf == nil {
		return
	}
	putFrameBuf(r.buf)
	r.buf, r.err = nil, ErrReleased
}

// frameBufs pools read and write buffers of the default maximum frame size
// (the size every relay connection uses); any other size is allocated.
var frameBufs = sync.Pool{New: func() any {
	b := make([]byte, defaultFrameBuf)
	return &b
}}

// defaultFrameBuf is the frame buffer size of DefaultLimits.
const defaultFrameBuf = HeaderSize + 64<<10 + MACSize

func getFrameBuf(n int) []byte {
	if n != defaultFrameBuf {
		return make([]byte, n)
	}
	return *frameBufs.Get().(*[]byte)
}

func putFrameBuf(b []byte) {
	if cap(b) != defaultFrameBuf {
		return
	}
	b = b[:defaultFrameBuf]
	frameBufs.Put(&b)
}

// Opener returns the reader's opener (to grant streams and add credit).
func (r *Reader) Opener() *Opener { return r.o }

// Next returns the next verified frame. The payload aliases the reader's
// buffer and is valid until the next call. Any error is sticky.
func (r *Reader) Next() (Header, []byte, error) {
	if r.err != nil {
		return Header{}, nil, r.err
	}
	h, p, err := r.next()
	if err != nil {
		r.err = err
	}
	return h, p, err
}

func (r *Reader) next() (Header, []byte, error) {
	// Bytes after the previous frame already belong to this one.
	if r.used > 0 {
		r.have = copy(r.buf, r.buf[r.used:r.have])
		r.used = 0
	}
	// The first byte under the idle timeout, then the whole rest of the
	// frame under one absolute deadline. Each read takes whatever has
	// arrived (up to the one buffer), so a frame usually costs one read
	// call instead of three; bytes past it are kept for the next frame.
	if !r.cap.IsZero() && !r.now().Before(r.cap) {
		return Header{}, nil, ErrDeadline
	}
	if r.have == 0 {
		if err := r.c.SetReadDeadline(r.deadline(r.lim.IdleTimeout)); err != nil {
			return Header{}, nil, err
		}
		n, err := io.ReadAtLeast(r.c, r.buf, 1)
		r.have = n
		if err != nil {
			return Header{}, nil, err
		}
	}
	if err := r.c.SetReadDeadline(r.deadline(r.lim.FrameDeadline)); err != nil {
		return Header{}, nil, err
	}
	if err := r.fill(HeaderSize); err != nil {
		return Header{}, nil, err
	}
	h, err := DecodeHeader(r.buf[:HeaderSize], r.o.lim)
	if err != nil {
		return Header{}, nil, err
	}
	total := HeaderSize + int(h.Len) + MACSize
	if !r.take(float64(total)) {
		return Header{}, nil, ErrRate
	}
	if err := r.fill(total); err != nil {
		return Header{}, nil, err
	}
	r.used = total
	return r.o.Open(r.buf[:total])
}

// fill reads until at least n bytes of the buffer are read (n is never
// more than the buffer: DecodeHeader has checked the length cap).
func (r *Reader) fill(n int) error {
	if r.have >= n {
		return nil
	}
	m, err := io.ReadAtLeast(r.c, r.buf[r.have:], n-r.have)
	r.have += m
	if err == io.EOF {
		// A frame cut short is an unexpected end, as io.ReadFull reports.
		err = io.ErrUnexpectedEOF
	}
	return err
}

// take charges one frame of n bytes against both buckets.
func (r *Reader) take(n float64) bool {
	now := r.now()
	dt := now.Sub(r.last).Seconds()
	if dt < 0 {
		dt = 0
	}
	r.last = now
	r.ftok = min(r.ftok+dt*r.lim.FramesPerSec, r.lim.FramesPerSec*r.lim.Burst)
	r.btok = min(r.btok+dt*r.lim.BytesPerSec, r.lim.BytesPerSec*r.lim.Burst)
	if r.ftok < 1 || r.btok < n {
		return false
	}
	r.ftok--
	r.btok -= n
	return true
}

// Writer seals and writes frames. Safe for concurrent use.
type Writer struct {
	mu       sync.Mutex
	c        WriteConn
	s        *Sealer
	buf      []byte
	rekey    *scheduledRekey
	released bool
	wd       time.Duration
	now      func() time.Time
}

// scheduleRekey makes the next frame this writer sends be preceded by a
// Rekey frame carrying announce under the current key, after which frames
// are sealed under key at epoch. It never writes itself: the reader side
// arms re-keying while the peer may still be writing, and a write from
// there could wait on a peer that is not reading.
func (w *Writer) scheduleRekey(announce, key []byte, epoch uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rekey = &scheduledRekey{announce: append([]byte(nil), announce...), key: key, epoch: epoch}
}

// scheduledRekey is a Rekey frame waiting for the writer's next frame.
type scheduledRekey struct {
	announce, key []byte
	epoch         uint32
}

// switchKey seals everything after it under key at epoch.
func (w *Writer) switchKey(key []byte, epoch uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.s.Rekey(key, epoch)
}

// Release returns the write buffer to the pool; every later Write fails.
// Idempotent.
func (w *Writer) Release() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf != nil {
		putFrameBuf(w.buf)
	}
	w.buf, w.released = nil, true
}

// NewWriter wraps c with a per-frame write deadline (0 = none). now nil is
// time.Now.
func NewWriter(c WriteConn, s *Sealer, writeDeadline time.Duration, now func() time.Time) *Writer {
	if now == nil {
		now = time.Now
	}
	return &Writer{c: c, s: s, wd: writeDeadline, now: now}
}

// Write sends one frame.
func (w *Writer) Write(t byte, stream uint32, payload []byte) error {
	return w.write2(t, stream, nil, payload)
}

// write2 sends one frame whose payload is prefix then payload, sealed
// without first joining them (the first chunk of a message carries its
// length prefix).
func (w *Writer) write2(t byte, stream uint32, prefix, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf == nil && !w.released {
		w.buf = getFrameBuf(defaultFrameBuf)[:0]
	}
	if w.released {
		return ErrReleased
	}
	w.buf = w.buf[:0]
	if r := w.rekey; r != nil {
		// The announcement and the frame go out in one write.
		w.buf = w.s.seal2(w.buf, TypeRekey, 0, nil, r.announce)
		w.s.Rekey(r.key, r.epoch)
		w.rekey = nil
	}
	w.buf = w.s.seal2(w.buf, t, stream, prefix, payload)
	if w.wd > 0 {
		if err := w.c.SetWriteDeadline(w.now().Add(w.wd)); err != nil {
			return err
		}
	}
	_, err := w.c.Write(w.buf)
	return err
}
