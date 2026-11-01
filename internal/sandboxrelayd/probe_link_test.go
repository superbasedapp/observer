package sandboxrelayd

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
)

// TestServeConnReadinessCheckIsNotAWarning: a link that closes before its
// hello (the CLI's relay readiness check, which dials and hangs up) logs
// nothing; a link with a bad hello still logs its handshake failure
// (Windows 11 Pro run 4: one "pipe is being closed" warning per launch with
// run="").
func TestServeConnReadinessCheckIsNotAWarning(t *testing.T) {
	var logged []string
	d := &Daemon{ObserverDir: t.TempDir(), Log: func(_, reason string) { logged = append(logged, reason) }}

	a, b := net.Pipe()
	_ = b.Close()
	if err := d.ServeConn(context.Background(), a); err == nil {
		t.Fatal("a link closed before its hello was served")
	}
	if len(logged) != 0 {
		t.Fatalf("a readiness check was logged: %q", logged)
	}

	a, b = net.Pipe()
	go func() {
		buf := make([]byte, 40)
		_, _ = io.ReadFull(b, buf)
		_, _ = b.Write([]byte("XXXX\x01\x01\x02"))
	}()
	_ = d.ServeConn(context.Background(), a)
	_ = b.Close()
	if len(logged) != 1 || !strings.Contains(logged[0], "handshake failed") {
		t.Fatalf("a bad hello: %q", logged)
	}
}
