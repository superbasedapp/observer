//go:build !windows

package hook

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestReadSettingsFileRefusesNonRegular pins the bounded read: a FIFO or a
// directory at a settings path is refused promptly (a FIFO used to hang the
// read with no writer), a regular file reads, and a missing one keeps
// os.ErrNotExist.
func TestReadSettingsFileRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "settings.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readSettingsFile(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("FIFO read error = %v", err)
		}
		var safe *safeMsgError
		if !errors.As(err, &safe) {
			t.Errorf("the refusal must be a composed (safe) message: %T", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readSettingsFile hung on a FIFO")
	}

	if _, err := readSettingsFile(dir); err == nil {
		t.Error("a directory must be refused")
	}
	reg := filepath.Join(dir, "ok.json")
	if err := os.WriteFile(reg, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readSettingsFile(reg); err != nil || string(b) != `{"a":1}` {
		t.Errorf("regular read = %q, %v", b, err)
	}
	if _, err := readSettingsFile(filepath.Join(dir, "missing.json")); !os.IsNotExist(err) {
		t.Errorf("missing file error = %v, want not-exist", err)
	}
}
