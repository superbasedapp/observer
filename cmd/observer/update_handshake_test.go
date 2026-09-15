//go:build !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// update_handshake_test.go proves §3.7 step 7 with a REAL child process.
//
// The "new binary" is a shell script, which is the point: the parent must
// survive and act correctly no matter what the successor does, including
// dying before any Observer code runs. A mock of the child would test the
// mock's manners, not the handshake's.
//
// No supervisor exists in this test environment, which is exactly the
// condition acceptance 7 names — the still-live PARENT is the actor in all
// three failure shapes.

// writeFakeBinary drops an executable script into dir.
func writeFakeBinary(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil { //nolint:gosec // a fake binary in a temp dir
		t.Fatal(err)
	}
	return path
}

// TestHandshakeSuccessLetsTheParentExit: the child reports ready with the
// right nonce, and superviseNewBinary returns without killing it.
func TestHandshakeSuccessLetsTheParentExit(t *testing.T) {
	dir := t.TempDir()
	// The script echoes the nonce it was handed, which is what proves the
	// nonce actually reaches the child rather than being decorative.
	bin := writeFakeBinary(t, dir, "child-ready", `echo "ready $OBSERVER_UPDATE_HANDSHAKE" >&3
exec sleep 2`)

	res, err := superviseNewBinary(context.Background(), bin, nil, dir, 5*time.Second, nil)
	if err != nil {
		t.Fatalf("superviseNewBinary: %v (%s)", err, res.Detail)
	}
	if !res.Ready {
		t.Fatalf("result = %+v, want Ready", res)
	}
	if res.ChildPID <= 0 {
		t.Errorf("ChildPID = %d, want a real pid", res.ChildPID)
	}
}

// TestHandshakeRejectsTheWrongNonce: a stale child, or an unrelated process,
// must not be able to satisfy this handshake.
func TestHandshakeRejectsTheWrongNonce(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "child-wrong-nonce", `echo "ready deadbeef" >&3
exec sleep 5`)

	res, err := superviseNewBinary(context.Background(), bin, nil, dir, 5*time.Second, nil)
	if err == nil {
		t.Fatal("a child reporting the wrong nonce was accepted")
	}
	if res.Ready {
		t.Fatal("result claims Ready with the wrong nonce")
	}
	if !strings.Contains(res.Detail, "nonce") {
		t.Errorf("detail = %q, want it to name the nonce", res.Detail)
	}
}

// TestHandshakeFailureShapes is acceptance 7's three shapes at the transport
// level. Each must produce an error and a NON-ready result, so the caller
// takes the rollback branch.
func TestHandshakeFailureShapes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		script      string
		timeout     time.Duration
		mustContain string
	}{
		{
			name:        "(a) the child reports a failed self-check",
			script:      `echo "fail listener bind refused" >&3` + "\n" + `exit 1`,
			timeout:     5 * time.Second,
			mustContain: "failed self-check",
		},
		{
			name:        "(b) the child exits non-zero before reporting anything",
			script:      `exit 3`,
			timeout:     5 * time.Second,
			mustContain: "exited before completing its self-check",
		},
		{
			name:        "(c) the child hangs and never reports",
			script:      `exec sleep 30`,
			timeout:     300 * time.Millisecond,
			mustContain: "did not report within",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := writeFakeBinary(t, dir, "child", tc.script)
			started := time.Now()
			res, err := superviseNewBinary(context.Background(), bin, nil, dir, tc.timeout, nil)
			if err == nil {
				t.Fatalf("superviseNewBinary succeeded on %s", tc.name)
			}
			if res.Ready {
				t.Fatal("result claims Ready on a failure shape")
			}
			if !strings.Contains(res.Detail, tc.mustContain) {
				t.Errorf("detail = %q, want it to contain %q", res.Detail, tc.mustContain)
			}
			// The parent must not wait past its own budget. A generous
			// ceiling: what is being asserted is "bounded", not "fast".
			if elapsed := time.Since(started); elapsed > tc.timeout+4*time.Second {
				t.Errorf("the handshake took %s with a %s timeout", elapsed, tc.timeout)
			}
		})
	}
}

// TestHandshakeChildNonceIsAbsentByDefault: a normal `observer start` must
// not think it owes a self-check report.
func TestHandshakeChildNonceIsAbsentByDefault(t *testing.T) {
	t.Setenv(handshakeNonceEnv, "")
	if got := handshakeChildNonce(); got != "" {
		t.Fatalf("handshakeChildNonce = %q with no env set, want empty", got)
	}
	t.Setenv(handshakeNonceEnv, "  abc123  ")
	if got := handshakeChildNonce(); got != "abc123" {
		t.Fatalf("handshakeChildNonce = %q, want the trimmed nonce", got)
	}
}

// TestInterpretHandshakeMessage is the message vocabulary as a table.
// SILENCE IS NOT CONSENT: an empty message is what a closed channel produces,
// and treating it as success is how a boot crash would be mistaken for a
// healthy daemon.
func TestInterpretHandshakeMessage(t *testing.T) {
	const nonce = "n0nce"
	for _, tc := range []struct {
		name    string
		msg     string
		wantOK  bool
		wantHas string
	}{
		{"ready with the right nonce", "ready " + nonce + "\n", true, "passed its self-check"},
		{"ready with no nonce", "ready\n", false, "wrong handshake nonce"},
		{"ready with the wrong nonce", "ready other\n", false, "wrong handshake nonce"},
		{"an explicit failure", "fail could not bind :8820\n", false, "could not bind"},
		{"a failure with no reason", "fail\n", false, "no reason given"},
		{"silence", "", false, "without reporting"},
		{"whitespace only", "   \n", false, "without reporting"},
		{"an unrecognised word", "hello there\n", false, "unrecognised"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, detail := interpretHandshakeMessage(tc.msg, nonce)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (detail %q)", ok, tc.wantOK, detail)
			}
			if !strings.Contains(detail, tc.wantHas) {
				t.Errorf("detail = %q, want it to contain %q", detail, tc.wantHas)
			}
		})
	}
}
