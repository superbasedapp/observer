//go:build unix

package main

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestClaudeSettingsReadersRefuseAFIFO: a FIFO at a settings path is refused
// at once (regularfile.Read), never blocking the launcher on an open.
func TestClaudeSettingsReadersRefuseAFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("no mkfifo")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, present := readClaudeSettingsBaseURLPresent(p); present {
			t.Error("a FIFO read as a present key")
		}
		if _, _, readable := readClaudeSettingsEnv(p); readable {
			t.Error("a FIFO read as a readable settings file")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a settings reader blocked on a FIFO")
	}
}

// TestReadOAuthAccessTokenRefusesAFIFO (FU-172): a FIFO at the credentials
// path is refused at once, never blocking the launcher on an open.
func TestReadOAuthAccessTokenRefusesAFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".credentials.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("no mkfifo")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if tok, _, err := readOAuthAccessToken(p); tok != "" || err == nil {
			t.Errorf("a FIFO read as credentials: %q, %v", tok, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the credentials reader blocked on a FIFO")
	}
}
