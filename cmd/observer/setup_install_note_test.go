package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSetupInstallPathOnMacOSIsANote pins D-MU8: on macOS and Linux (no
// per-user Path or sign-in entry for the setup commands) `observer setup
// install --path --autostart` installs, prints a note naming the
// mechanism that owns each step, and succeeds; before, it exited 1 with no
// message because the command silences cobra's error line.
func TestSetupInstallPathOnMacOSIsANote(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "payload", "observer-new")
	setupWriteFile(t, src, "v2")
	dir := filepath.Join(tmp, "bin")
	var out bytes.Buffer
	err := runSetupInstall(setupInstallOptions{
		dir: dir, source: src, addPath: true, autostart: true,
		out: &out, sys: setupOS{}, preflight: noOthers,
		now: func() time.Time { return time.Unix(0, 0) },
	})
	if err != nil {
		t.Fatalf("install = %v, want success with notes\n%s", err, out.String())
	}
	for _, want := range []string{"Installed", "Note: the per-user Path is edited on Windows only", "Note: start at sign-in is set here on Windows only"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

// TestRenderSetupErrorPrintsOnce pins that a silenced setup verb's real
// error is printed, and an exit-code outcome is left to its own output.
func TestRenderSetupErrorPrintsOnce(t *testing.T) {
	var stderr bytes.Buffer
	err := errors.New("create /x: permission denied")
	if got := renderSetupError(&stderr, "setup install", err); !errors.Is(got, err) {
		t.Fatalf("returned %v", got)
	}
	if !strings.Contains(stderr.String(), "observer setup install: create /x: permission denied") {
		t.Errorf("stderr = %q", stderr.String())
	}
	stderr.Reset()
	_ = renderSetupError(&stderr, "setup install", exitErr(setupExitBlocked))
	_ = renderSetupError(&stderr, "setup install", nil)
	if stderr.Len() != 0 {
		t.Errorf("printed for an exit-code outcome or success: %q", stderr.String())
	}
}
