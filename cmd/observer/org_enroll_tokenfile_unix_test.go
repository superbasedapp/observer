//go:build unix

package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestEnrolTokenFileRefusesFIFO pins F-029 V1 and O5 audit finding O5-A7
// on unix: a named pipe with no writer is opened without blocking and
// refused by the type of the opened file, so enrolment never hangs in
// open(2), even when the path became a FIFO after any earlier check; the
// refusal names `--token-file -` for reading a pipe. The call runs under a
// deadline so a regression to a blocking open fails instead of hanging the
// suite.
func TestEnrolTokenFileRefusesFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := enrolArgsWithTokenFile(p, "", "", []string{"https://org"}, strings.NewReader(""))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") || !strings.Contains(err.Error(), "--token-file -") {
			t.Fatalf("err = %v, want a not-a-regular-file refusal naming --token-file -", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reading a FIFO with no writer blocked")
	}
}
