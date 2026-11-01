package relaymux

import (
	"errors"
	"io"
	"sync"
	"time"
)

// deadline.go is the host-side deadline adapter (lane SBX-P7, milestone 2):
// the relay's reader needs read and write deadlines (internal/sandboxrelay
// conn.go: one absolute deadline per frame after an idle timeout for its
// first byte), and a vendor's exec stream (an HTTP response body, a gRPC
// stream, a stdin POST) has none. The adapter reads the stream on one pump
// goroutine and hands the bytes to Read under the deadline; a write runs on
// its own goroutine and the caller stops waiting at the deadline, after
// which the adapter is broken (a half-written frame cannot be resumed) and
// every later call fails.

// ErrTimeout is returned when a deadline passes. It satisfies the
// net.Error Timeout convention.
var ErrTimeout error = timeoutError{}

type timeoutError struct{}

func (timeoutError) Error() string   { return "relaymux: deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// ErrBroken is returned after a write timed out: the stream may hold half
// a frame, so the adapter refuses everything after it.
var ErrBroken = errors.New("relaymux: stream broken by a write timeout")

// DeadlineConn adapts a deadline-less stream to sandboxrelay.Conn.
type DeadlineConn struct {
	w     io.Writer
	close func() error

	reads chan readResult
	// readMu serialises Read (one reader at a time, as the relay's Reader
	// is).
	readMu  sync.Mutex
	pending []byte
	rerr    error

	mu     sync.Mutex
	rdl    time.Time
	wdl    time.Time
	broken bool
	closed chan struct{}
	once   sync.Once
	now    func() time.Time
}

type readResult struct {
	b   []byte
	err error
}

// NewDeadlineConn wraps a reader and a writer; closeFn (may be nil) is
// called once by Close.
func NewDeadlineConn(r io.Reader, w io.Writer, closeFn func() error) *DeadlineConn {
	c := &DeadlineConn{w: w, close: closeFn, reads: make(chan readResult, 1), closed: make(chan struct{}), now: time.Now}
	go c.pump(r)
	return c
}

// pump reads the stream; one result is outstanding at a time (the channel
// holds one), so memory is bounded by one 32 KiB chunk.
func (c *DeadlineConn) pump(r io.Reader) {
	for {
		buf := make([]byte, 32<<10)
		n, err := r.Read(buf)
		select {
		case c.reads <- readResult{b: buf[:n], err: err}:
		case <-c.closed:
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *DeadlineConn) timer(dl time.Time) (<-chan time.Time, func()) {
	if dl.IsZero() {
		return nil, func() {}
	}
	d := dl.Sub(c.now())
	if d < 0 {
		d = 0
	}
	t := time.NewTimer(d)
	return t.C, func() { t.Stop() }
}

// Read returns stream bytes, or ErrTimeout at the read deadline.
func (c *DeadlineConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.rerr != nil {
		return 0, c.rerr
	}
	c.mu.Lock()
	dl, broken := c.rdl, c.broken
	c.mu.Unlock()
	if broken {
		return 0, ErrBroken
	}
	tc, stop := c.timer(dl)
	defer stop()
	select {
	case res := <-c.reads:
		n := copy(p, res.b)
		c.pending = res.b[n:]
		if res.err != nil {
			c.rerr = res.err
			if n > 0 {
				return n, nil
			}
			return 0, res.err
		}
		return n, nil
	case <-tc:
		return 0, ErrTimeout
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

// Write writes p, or returns ErrTimeout at the write deadline (and the
// adapter is broken from then on).
func (c *DeadlineConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	dl, broken := c.wdl, c.broken
	c.mu.Unlock()
	if broken {
		return 0, ErrBroken
	}
	done := make(chan readResult, 1)
	buf := append([]byte(nil), p...)
	go func() {
		n, err := c.w.Write(buf)
		done <- readResult{b: buf[:n], err: err}
	}()
	tc, stop := c.timer(dl)
	defer stop()
	select {
	case res := <-done:
		return len(res.b), res.err
	case <-tc:
		c.mu.Lock()
		c.broken = true
		c.mu.Unlock()
		return 0, ErrTimeout
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

// SetReadDeadline sets the read deadline (zero: none).
func (c *DeadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the write deadline (zero: none).
func (c *DeadlineConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	c.mu.Unlock()
	return nil
}

// Close stops the adapter and closes the stream.
func (c *DeadlineConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		if c.close != nil {
			err = c.close()
		}
	})
	return err
}
