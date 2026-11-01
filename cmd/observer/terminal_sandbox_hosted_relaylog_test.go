//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestHostedRelayLogWrittenCappedRedacted (lane SBX-UPD, finding H1): the
// run's relay log is owner-only, every line is redacted and cleaned, the
// relay process's stderr is kept line by line, the cap stops it with a
// final line, it survives the teardown record's removal, and status lists
// it.
func TestHostedRelayLogWrittenCappedRedacted(t *testing.T) {
	obs := t.TempDir()
	clock := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	l := openHostedRelayLog(obs, "run-h1", []string{"sk-SECRET-1234"}, func() time.Time { return clock })
	if l == nil {
		t.Fatal("the log did not open")
	}
	l.line("refused a relay connection: token sk-SECRET-1234\x1b[31m")
	_, _ = l.Write([]byte("panic: the secret file is missing\npartial"))
	l.flush()
	raw, err := os.ReadFile(hostedRelayLogPath(obs, "run-h1"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, "sk-SECRET-1234") || strings.ContainsRune(s, 0x1b) {
		t.Fatalf("the log kept a secret or a control character:\n%s", s)
	}
	for _, want := range []string{"refused a relay connection", "relay process stderr: panic: the secret file is missing", "relay process stderr: partial", "2026-10-23T12:00:00Z"} {
		if !strings.Contains(s, want) {
			t.Fatalf("log lacks %q:\n%s", want, s)
		}
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(hostedRelayLogPath(obs, "run-h1"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("log mode %v, want 0600", fi.Mode().Perm())
		}
	}
	// The cap.
	big := strings.Repeat("y", hostedRelayLineMax)
	for i := 0; i < hostedRelayLogMax/hostedRelayLineMax+10; i++ {
		l.line("%s", big)
	}
	fi, _ := os.Stat(hostedRelayLogPath(obs, "run-h1"))
	if fi.Size() > hostedRelayLogMax+200 {
		t.Fatalf("log size %d over the cap", fi.Size())
	}
	raw, _ = os.ReadFile(hostedRelayLogPath(obs, "run-h1"))
	if !strings.Contains(string(raw), "reached its cap") {
		t.Fatal("the cap line is missing")
	}
	// Kept after the teardown record goes (the record is a separate file).
	_ = os.RemoveAll(hostedRunsDir(obs))
	logs := hostedKeptRelayLogs(obs)
	if len(logs) != 1 || logs[0].RunID != "run-h1" {
		t.Fatalf("kept logs = %+v", logs)
	}
	var out bytes.Buffer
	renderHostedRelayLogs(&out, logs)
	if !strings.Contains(out.String(), hostedRelayLogPath(obs, "run-h1")) {
		t.Fatalf("status = %q", out.String())
	}
	// A nil log is inert; a bad run id opens nothing.
	var none *hostedRelayLog
	none.line("x")
	if n, _ := none.Write([]byte("y")); n != 1 {
		t.Fatal("a nil log refused a write")
	}
	if openHostedRelayLog(obs, "../x", nil, nil) != nil {
		t.Fatal("a log opened for a bad run id")
	}
}

// TestHostedRelayLogsPruned: only the newest logs are kept, and pruning
// removes nothing but relay.log files and emptied run directories.
func TestHostedRelayLogsPruned(t *testing.T) {
	obs := t.TempDir()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < hostedRelayLogsKept+3; i++ {
		id := fmt.Sprintf("run-%02d", i)
		l := openHostedRelayLog(obs, id, nil, nil)
		l.line("x")
		_ = os.Chtimes(hostedRelayLogPath(obs, id), base.Add(time.Duration(i)*time.Minute), base.Add(time.Duration(i)*time.Minute))
		if i == 0 {
			if err := os.WriteFile(filepath.Join(hostedStateDir(obs), "run-00", "keep.me"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	other := filepath.Join(hostedStateDir(obs), "run-00", "keep.me")
	openHostedRelayLog(obs, "run-new", nil, nil).line("x")
	logs := hostedKeptRelayLogs(obs)
	if len(logs) != hostedRelayLogsKept {
		t.Fatalf("%d logs kept, want %d", len(logs), hostedRelayLogsKept)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("pruning removed a file that is not a relay log")
	}
}

// TestBoxClosedNotePerRow: the closed-stream refusal names the log the
// box's row keeps: the inner log on the MXC row, the home relay log on a
// hosted row, and never an inner log on a hosted row.
func TestBoxClosedNotePerRow(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if n := boxClosedLogNote(env(map[string]string{sandboxInnerLogEnv: `C:\t\inner.log`})); !strings.Contains(n, "inner log") {
		t.Fatalf("mxc row: %q", n)
	}
	hosted := boxClosedLogNote(env(map[string]string{hostedRelayRedialEnv: "1"}))
	if strings.Contains(hosted, "inner log") || !strings.Contains(hosted, "relay.log") {
		t.Fatalf("hosted row: %q", hosted)
	}
	if n := boxClosedLogNote(env(nil)); strings.Contains(n, "inner log") || n == "" {
		t.Fatalf("other rows: %q", n)
	}
}

// TestBoxRedialRetriesAClosedHandshake is the H1 fix's test: on a hosted
// box (redial on) a relay stream closed during its handshake (nothing
// sent) is tried again until the relay answers, like a failed connect; a
// stream closed after the request was sent is not (it could repeat the
// request); with redial off nothing is retried. Before the fix the first
// case failed the launch at once.
func TestBoxRedialRetriesAClosedHandshake(t *testing.T) {
	saved := boxRedialEvery
	boxRedialEvery = time.Millisecond
	t.Cleanup(func() { boxRedialEvery = saved })
	// A handshake closed by the helper, from the real round trip.
	handshakeClosed := realHandshakeClosedErr(t)
	if !errors.Is(handshakeClosed, sandboxrelayd.ErrNothingSent) {
		t.Fatalf("the closed handshake is not marked nothing-sent: %v", handshakeClosed)
	}
	var hop *sandboxrelay.HopError
	if !errors.As(handshakeClosed, &hop) || hop.Hop != sandboxrelay.HopBoxClosed {
		t.Fatalf("the hop is lost: %v", handshakeClosed)
	}
	calls := 0
	resp, err := boxRedial(context.Background(), true, func(context.Context) (sandboxrelay.HookResponse, error) {
		calls++
		if calls < 3 {
			return sandboxrelay.HookResponse{}, handshakeClosed
		}
		return sandboxrelay.HookResponse{Exit: 7}, nil
	})
	if err != nil || resp.Exit != 7 || calls != 3 {
		t.Fatalf("redial = %+v %v after %d calls", resp, err, calls)
	}
	sent := &sandboxrelay.HopError{Hop: sandboxrelay.HopBoxClosed, Detail: "read: EOF"}
	calls = 0
	if _, err := boxRedial(context.Background(), true, func(context.Context) (sandboxrelay.HookResponse, error) {
		calls++
		return sandboxrelay.HookResponse{}, sent
	}); err == nil || calls != 1 {
		t.Fatalf("a close after sending was retried: %d calls, %v", calls, err)
	}
	calls = 0
	if _, err := boxRedial(context.Background(), false, func(context.Context) (sandboxrelay.HookResponse, error) {
		calls++
		return sandboxrelay.HookResponse{}, handshakeClosed
	}); err == nil || calls != 1 {
		t.Fatalf("redial off retried: %d calls", calls)
	}
}

// realHandshakeClosedErr runs the box round trip against a helper that
// accepts the connection and closes it at once (what a relay process that
// is ending, or whose session cannot open a stream home, does).
func realHandshakeClosedErr(t *testing.T) error {
	t.Helper()
	box, helper := net.Pipe()
	go func() { _ = helper.Close() }()
	rec := sandboxrelayd.BoxRecord{RunID: "run-h1", BoxSecret: bytes.Repeat([]byte{1}, sandboxrelay.SecretSize)}
	_, err := sandboxrelayd.BoxRoundTripConn(context.Background(), box, rec, []byte("{}"), sandboxrelay.ClientConnLimits)
	if err == nil {
		t.Fatal("the round trip against a closed helper succeeded")
	}
	return err
}
