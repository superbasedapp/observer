//go:build windows

package attachsock

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
)

// transport_windows_test.go keeps the protocol round trip over a real named
// pipe in this package (the transport itself moved to internal/localipc,
// which pins the pipe's DACL and live-daemon guard).

// testPipeEndpoint returns a unique pipe endpoint for one test, derived the
// same way production is (hash of a DB path) so the naming under test is the
// shipped naming.
func testPipeEndpoint(t *testing.T) string {
	t.Helper()
	ep, err := localipc.Endpoint(filepath.Join(t.TempDir(), "observer.db"))
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	return ep
}

// TestPipeDialRoundTrip runs the REAL protocol over a real pipe: Serve on one
// side, Dial + Attach on the other, one output frame across and an exit frame
// back. This is the end-to-end proof that the framing above the transport is
// transport-agnostic — the same harness the AF_UNIX test uses, over a pipe.
func TestPipeDialRoundTrip(t *testing.T) {
	endpoint := testPipeEndpoint(t)
	ln, err := localipc.ListenSocket(endpoint)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- Serve(ctx, ln, host, nil) }()

	conn, err := Dial(endpoint)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	out := &syncBuffer{}
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), conn, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{Stdout: out})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not complete over the named pipe")
	}
	sess.feed([]byte("ok"))
	waitFor(t, "stdout ok", func() bool { return out.String() == "ok" })
	sess.endOutput(0)
	select {
	case st := <-resultCh:
		if !st.Exited || st.Code != 0 {
			t.Fatalf("status = %+v, want a clean child exit", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Attach did not return")
	}

	cancel()
	select {
	case serr := <-serveDone:
		if serr != nil {
			t.Fatalf("Serve returned %v, want nil on ctx cancel", serr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}
