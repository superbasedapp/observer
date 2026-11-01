//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"net"
	"sync"
)

// pipeProcess is a process backed by a duplex pipe (the box end is handed
// to a goroutine playing the box). It is used only by the Linux hosted
// host and adopt tests, so it lives in a Linux test file (WINFIX4 lint:
// unused on Windows).
type pipeProcess struct {
	c    net.Conn
	done chan int
	pid  string
	mu   sync.Mutex
	size [2]uint16
	// failWait makes Wait report a cut stream.
	failWait error
}

func (p *pipeProcess) Read(b []byte) (int, error)  { return p.c.Read(b) }
func (p *pipeProcess) Write(b []byte) (int, error) { return p.c.Write(b) }
func (p *pipeProcess) PID() string                 { return p.pid }
func (p *pipeProcess) Resize(_ context.Context, r, c uint16) error {
	p.mu.Lock()
	p.size = [2]uint16{r, c}
	p.mu.Unlock()
	return nil
}

func (p *pipeProcess) Wait(ctx context.Context) (int, error) {
	select {
	case c := <-p.done:
		p.mu.Lock()
		err := p.failWait
		p.mu.Unlock()
		return c, err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (p *pipeProcess) Kill(context.Context) error { _ = p.c.Close(); return nil }
func (p *pipeProcess) Close() error               { return p.c.Close() }
