//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestGUIInstanceRunningSeesAChild runs the real /proc probe: a child the
// test starts is a running instance of its binary; a binary nothing runs is
// not.
func TestGUIInstanceRunningSeesAChild(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	cmd := exec.Command(sleep, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(5 * time.Second)
	for !platformGUIInstanceRunning(sleep) {
		if time.Now().After(deadline) {
			t.Fatalf("the probe did not see the running %s", sleep)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if platformGUIInstanceRunning(filepath.Join(t.TempDir(), "observer-ide2-never-running")) {
		t.Fatal("a binary nothing runs must not read as running")
	}
	// Audit item 10: a different file with the running program's base name
	// is not the running program.
	sameName := filepath.Join(t.TempDir(), filepath.Base(sleep))
	if err := os.WriteFile(sameName, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if platformGUIInstanceRunning(sameName) {
		t.Fatalf("%s only shares the running program's base name", sameName)
	}
}
