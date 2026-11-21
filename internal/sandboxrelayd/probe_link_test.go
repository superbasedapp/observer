package sandboxrelayd

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
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

// TestServeConnFailedHandshakeNamesNoRun (fold audit N4): a link whose
// handshake claims a real run but fails the secret check is logged with no
// run id, so its line never reaches the claimed run's kept relay log.
func TestServeConnFailedHandshakeNamesNoRun(t *testing.T) {
	obs := t.TempDir()
	rec, err := NewRunRecord(RunRecord{RunID: "run-n4", Tool: "claude-code", WorkspaceDir: "/w", Roots: []string{"/w"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var runs []string
	d := &Daemon{ObserverDir: obs, Log: func(runID, _ string) {
		mu.Lock()
		defer mu.Unlock()
		runs = append(runs, runID)
	}}
	done := make(chan struct{})
	dial := func(context.Context) (net.Conn, error) {
		cli, srv := net.Pipe()
		go func() {
			defer close(done)
			_ = d.ServeConn(context.Background(), srv)
		}()
		return cli, nil
	}
	forged := rec
	forged.LinkSecret = bytes.Repeat([]byte{7}, len(rec.LinkSecret))
	msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := LinkRoundTrip(ctx, dial, forged, msg, sandboxrelay.DefaultConnLimits); err == nil {
		t.Fatal("a link with the wrong secret was answered")
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(runs) != 1 || runs[0] != "" {
		t.Fatalf("a failed handshake was logged under runs %q, want one line with no run", runs)
	}
}
