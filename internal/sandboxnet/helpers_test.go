package sandboxnet

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testTimeout bounds every blocking step in the tests.
const testTimeout = 10 * time.Second

// socketDir returns a directory short enough for a unix socket path (the
// sun_path limit is 108 bytes). t.TempDir() is used when it fits.
func socketDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if len(filepath.Join(dir, "gateway.sock")) < 100 {
		return dir
	}
	dir, err := os.MkdirTemp("", "sn")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// listenUnix opens a unix listener in a short temp dir.
func listenUnix(t *testing.T, name string) (net.Listener, string) {
	t.Helper()
	path := filepath.Join(socketDir(t), name)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, path
}

// startTCPServer runs handle for every connection on 127.0.0.1:0 and returns
// the address. Connections are closed after handle returns.
func startTCPServer(t *testing.T, handle func(c *net.TCPConn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(testTimeout))
				handle(c.(*net.TCPConn))
			}()
		}
	}()
	return ln.Addr().String()
}

// echoHandler copies everything back and closes after the client's EOF.
func echoHandler(c *net.TCPConn) {
	_, _ = io.Copy(c, c)
	_ = c.CloseWrite()
}

// discardLogger keeps gateway refusals out of test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
