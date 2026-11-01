//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRepoTrustTargetLinkedWorktree: the launch trust check reads a linked
// worktree's own files (F0-14).
func TestRepoTrustTargetLinkedWorktree(t *testing.T) {
	_, wtRoot := linkedWorktreeFixture(t)
	sub := filepath.Join(wtRoot, "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	tgt, err := resolveRepoTrustTarget(sub)
	if err != nil || tgt.root != wtRoot || tgt.launchRel != "pkg" {
		t.Fatalf("resolveRepoTrustTarget = %+v %v, want root %q launchRel pkg", tgt, err, wtRoot)
	}
}
