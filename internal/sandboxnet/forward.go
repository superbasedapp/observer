package sandboxnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// closeWriter is implemented by *net.TCPConn, *net.UnixConn and bufferedConn.
type closeWriter interface {
	CloseWrite() error
}

// ServeForward accepts connections on ln until ctx is done or ln is closed,
// and for each one dials a peer with dial and copies bytes both ways
// (half-close aware: when one direction hits EOF, CloseWrite the other side
// if it supports it; close both when both directions finish). A failed dial
// closes the accepted conn and keeps serving. Returns nil when ctx is
// cancelled or ln is closed, otherwise the accept error wrapped.
//
// Cancelling ctx closes ln. When ServeForward returns, every connection it
// was serving has been closed and its goroutines have exited. A peer that
// cannot half-close (no CloseWrite, or CloseWrite fails) is fully closed
// instead, since a full close is then the only way to deliver the EOF.
func ServeForward(ctx context.Context, ln net.Listener, dial func(ctx context.Context) (net.Conn, error)) error {
	if ln == nil || dial == nil {
		return errors.New("sandboxnet.ServeForward: nil listener or dial func")
	}
	inner, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("sandboxnet.ServeForward: accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer, err := dial(inner)
			if err != nil {
				_ = c.Close()
				return
			}
			pipe(inner, c, peer)
		}()
	}
}

// pipe copies a->b and b->a until both directions finish, then closes both.
// Cancelling ctx closes both immediately. A copy error in either direction
// aborts the whole pair so the other direction cannot hang.
func pipe(ctx context.Context, a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyHalf(b, a, closeBoth)
	}()
	go func() {
		defer wg.Done()
		copyHalf(a, b, closeBoth)
	}()
	wg.Wait()
	closeBoth()
}

// copyHalf copies src into dst; on a clean EOF it half-closes dst, and on an
// error (or when dst cannot half-close) it aborts the pair.
func copyHalf(dst, src net.Conn, abort func()) {
	if _, err := io.Copy(dst, src); err != nil {
		abort()
		return
	}
	cw, ok := dst.(closeWriter)
	if !ok || cw.CloseWrite() != nil {
		abort()
	}
}

// bufferedConn is a hijacked client connection whose bufio.Reader still holds
// bytes the client sent after the request head (for example a TLS
// ClientHello pipelined right behind CONNECT). Reads drain the buffer first.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

// Read reads from the buffered reader, which falls through to the conn.
func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite half-closes the underlying conn when it supports it.
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("sandboxnet: connection does not support CloseWrite")
}
