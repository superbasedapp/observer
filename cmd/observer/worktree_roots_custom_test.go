//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCustomScanRootLinkedWorktree: a custom scanner run in a linked
// worktree scans the worktree's files (F0-14).
func TestCustomScanRootLinkedWorktree(t *testing.T) {
	_, wtRoot := linkedWorktreeFixture(t)
	sub := filepath.Join(wtRoot, "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := customScanProjectRoot(sub)
	if err != nil || got != wtRoot {
		t.Fatalf("customScanProjectRoot = %q %v, want %q", got, err, wtRoot)
	}
}
