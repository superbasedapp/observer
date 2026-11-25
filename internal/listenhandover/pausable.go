package listenhandover

import (
	"net"
	"sync"
)

// Pausable is a listener whose Accept can be paused. While it is paused,
// new connections wait in the socket's backlog (the kernel completes them)
// and nothing accepts them here; the image the socket is handed to accepts
// them. An Accept already waiting in the socket when Pause is called may
// still return one connection, which is served as usual.
type Pausable struct {
	net.Listener

	mu        sync.Mutex
	paused    bool
	closed    chan struct{}
	closeOnce sync.Once
}

// NewPausable wraps ln.
func NewPausable(ln net.Listener) *Pausable {
	return &Pausable{Listener: ln, closed: make(chan struct{})}
}

// Pause stops accepting. It cannot be undone: a paused listener is handed
// over or closed.
func (p *Pausable) Pause() {
	p.mu.Lock()
	p.paused = true
	p.mu.Unlock()
}

// Paused reports whether Pause was called.
func (p *Pausable) Paused() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.paused
}

// Accept accepts the next connection, or, while paused, waits for Close.
func (p *Pausable) Accept() (net.Conn, error) {
	if p.Paused() {
		<-p.closed
		return nil, net.ErrClosed
	}
	return p.Listener.Accept()
}

// Close closes the listener and ends a paused Accept.
func (p *Pausable) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return p.Listener.Close()
}
