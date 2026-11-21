//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestRelayFailedHandshakeLeavesTheClaimedRunsLogAlone (fold audit N4): a
// link whose handshake names another run but fails the secret check is
// logged in the daemon's own log with no run, and the kept relay log of the
// run it claimed is left byte for byte as it was (syncBuffer is the
// package's test helper). The control: a link the handshake proved still
// feeds that run's kept log.
func TestRelayFailedHandshakeLeavesTheClaimedRunsLogAlone(t *testing.T) {
	obs := t.TempDir()
	const run = "runN4victim"
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: run, Tool: "claude-code", WorkspaceDir: "/w", Roots: []string{"/w"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	p := hostedRelayLogPath(obs, run)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	const kept = "2026-11-06T09:00:00Z the relay process started\n"
	if err := os.WriteFile(p, []byte(kept), 0o600); err != nil {
		t.Fatal(err)
	}
	var daemonLog syncBuffer
	d := &sandboxrelayd.Daemon{ObserverDir: obs, Log: relayDaemonLog(slog.New(slog.NewTextHandler(&daemonLog, nil)), obs)}

	// roundTrip dials the daemon over a pipe and waits for ServeConn to
	// return, so every line it logs is written before the log is read.
	roundTrip := func(r sandboxrelayd.RunRecord, msg []byte) error {
		done := make(chan struct{})
		dial := func(context.Context) (net.Conn, error) {
			cli, srv := net.Pipe()
			go func() {
				defer close(done)
				_ = d.ServeConn(context.Background(), srv)
			}()
			return cli, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := sandboxrelayd.LinkRoundTrip(ctx, dial, r, msg, sandboxrelay.DefaultConnLimits)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("ServeConn did not return")
		}
		return err
	}

	msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Args: []string{"claude-code", "PreToolUse"}})
	if err != nil {
		t.Fatal(err)
	}
	forged := rec
	forged.LinkSecret = bytes.Repeat([]byte{7}, len(rec.LinkSecret))
	if err := roundTrip(forged, msg); err == nil {
		t.Fatal("a link with the wrong secret was answered")
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != kept {
		t.Fatalf("a failed handshake naming %s changed its kept relay log (%v):\n%s", run, err, b)
	}
	if got := daemonLog.String(); !strings.Contains(got, "handshake failed") || strings.Contains(got, "run="+run) {
		t.Fatalf("the daemon's own log: want the handshake failure with no run, got:\n%s", got)
	}

	// The control: a proven link whose request does not decode is the run's
	// event, so its line reaches the run's kept log.
	if err := roundTrip(rec, []byte("not a hook request")); err == nil {
		t.Fatal("an undecodable request was answered")
	}
	if b, _ := os.ReadFile(p); !strings.HasPrefix(string(b), kept) || len(b) == len(kept) {
		t.Fatalf("a proven link's line did not reach the run's kept relay log:\n%s", b)
	}
}
