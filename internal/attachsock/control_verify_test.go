//go:build unix

package attachsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
)

// TestControlCallRefusesAnUnverifiedServer: when the endpoint's server is
// not this user's, the client sends nothing and reports
// ErrServerUnverified (ATT-1 client precondition; the Windows check is the
// real verifier, swapped here for one that refuses).
func TestControlCallRefusesAnUnverifiedServer(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := localipc.Endpoint(filepath.Join(dir, "observer.db"))
	if err != nil {
		t.Skipf("no endpoint: %v", err)
	}
	ln, err := localipc.ListenSocket(endpoint)
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	var got atomic.Int64
	// handled fires once the server side has finished reading a connection
	// (the client closed it, or the one-second read deadline passed), so the
	// byte count below is final, not a sample taken too early.
	handled := make(chan struct{}, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 64)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				n, _ := c.Read(buf)
				got.Add(int64(n))
				select {
				case handled <- struct{}{}:
				default:
				}
			}(c)
		}
	}()
	old := verifyControlServer
	verifyControlServer = func(net.Conn) error { return fmt.Errorf("%w: it runs as S-1-5-21-other", ErrServerUnverified) }
	defer func() { verifyControlServer = old }()

	_, err = ControlCall(context.Background(), endpoint, ControlRequest{Op: opLaunch, Launch: &LaunchSpec{Tool: "claude", Remote: "https://token@example.com/r.git"}})
	if !errors.Is(err, ErrServerUnverified) {
		t.Fatalf("err = %v, want ErrServerUnverified", err)
	}
	select {
	case <-handled:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never finished reading the client's connection")
	}
	if n := got.Load(); n != 0 {
		t.Fatalf("the unverified server received %d bytes", n)
	}
}
