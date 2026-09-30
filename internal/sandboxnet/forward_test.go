package sandboxnet

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// startForward runs ServeForward from a unix listener to a TCP address and
// returns the socket path plus a func that cancels and waits for the result.
func startForward(t *testing.T, dial func(ctx context.Context) (net.Conn, error)) (string, func() error) {
	t.Helper()
	ln, path := listenUnix(t, "fwd.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeForward(ctx, ln, dial) }()
	var stopped bool
	var result error
	stop := func() error {
		if stopped {
			return result
		}
		stopped = true
		cancel()
		select {
		case result = <-done:
		case <-time.After(testTimeout):
			t.Fatal("ServeForward did not return after cancel")
		}
		return result
	}
	t.Cleanup(func() { _ = stop() })
	return path, stop
}

func tcpDialer(addr string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func dialUnix(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	c, err := net.DialTimeout("unix", path, testTimeout)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(testTimeout))
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.UnixConn)
}

func TestServeForward_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		messages []string
	}{
		{"single message", []string{"ping"}},
		{"several messages", []string{"a", "bb", "ccc", "hello over the forwarder"}},
		{"large payload", []string{string(make([]byte, 256<<10))}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := startTCPServer(t, echoHandler)
			path, _ := startForward(t, tcpDialer(addr))
			c := dialUnix(t, path)
			for _, m := range tc.messages {
				go func() { _, _ = c.Write([]byte(m)) }()
				got := make([]byte, len(m))
				if _, err := io.ReadFull(c, got); err != nil {
					t.Fatalf("read echo: %v", err)
				}
				if string(got) != m {
					t.Fatalf("echo mismatch (len %d vs %d)", len(got), len(m))
				}
			}
			if err := c.CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			rest, err := io.ReadAll(c)
			if err != nil || len(rest) != 0 {
				t.Fatalf("after CloseWrite: rest=%q err=%v, want clean EOF", rest, err)
			}
		})
	}
}

func TestServeForward_HalfClose(t *testing.T) {
	t.Parallel()
	// The server reads until EOF, then still writes its reply: the reply
	// only arrives if the forwarder half-closed instead of fully closing.
	addr := startTCPServer(t, func(c *net.TCPConn) {
		in, err := io.ReadAll(c)
		if err != nil {
			return
		}
		_, _ = c.Write(append([]byte("got:"), in...))
	})
	path, _ := startForward(t, tcpDialer(addr))
	c := dialUnix(t, path)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(got) != "got:hello" {
		t.Fatalf("reply = %q, want %q", got, "got:hello")
	}
}

func TestServeForward_CancelStops(t *testing.T) {
	t.Parallel()
	addr := startTCPServer(t, echoHandler)
	path, stop := startForward(t, tcpDialer(addr))

	// An in-flight connection is torn down by the cancel.
	c := dialUnix(t, path)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	if err := stop(); err != nil {
		t.Fatalf("ServeForward after cancel = %v, want nil", err)
	}
	if _, err := io.ReadAll(c); err != nil && !errors.Is(err, net.ErrClosed) {
		// Either a clean EOF or a reset is fine; a timeout is not.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("in-flight conn not closed by cancel: %v", err)
		}
	}
	if c2, err := net.DialTimeout("unix", path, time.Second); err == nil {
		_ = c2.Close()
		t.Fatal("listener still accepting after cancel")
	}
}

func TestServeForward_ListenerClosedReturnsNil(t *testing.T) {
	t.Parallel()
	ln, _ := listenUnix(t, "closed.sock")
	done := make(chan error, 1)
	go func() {
		done <- ServeForward(context.Background(), ln, func(context.Context) (net.Conn, error) {
			return nil, errors.New("unused")
		})
	}()
	_ = ln.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeForward after ln.Close = %v, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("ServeForward did not return after ln.Close")
	}
}

func TestServeForward_FailedDialKeepsServing(t *testing.T) {
	t.Parallel()
	addr := startTCPServer(t, echoHandler)
	var calls atomic.Int32
	realDial := tcpDialer(addr)
	path, _ := startForward(t, func(ctx context.Context) (net.Conn, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("upstream down")
		}
		return realDial(ctx)
	})

	first := dialUnix(t, path)
	got, err := io.ReadAll(first)
	if err != nil || len(got) != 0 {
		t.Fatalf("failed-dial conn: got=%q err=%v, want closed with no data", got, err)
	}

	second := dialUnix(t, path)
	if _, err := second.Write([]byte("ok")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(second, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("second conn echo = %q, %v", buf, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("dial calls = %d, want 2", calls.Load())
	}
}

func TestServeForward_NilArgs(t *testing.T) {
	t.Parallel()
	if err := ServeForward(context.Background(), nil, nil); err == nil {
		t.Fatal("ServeForward(nil, nil) = nil, want error")
	}
}
