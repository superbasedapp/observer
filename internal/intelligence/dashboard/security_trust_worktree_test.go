//go:build !sbo_omit_security && !sbo_omit_security_trust

package dashboard

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveSecurityTrustDir_LinkedWorktree: the dashboard's trust check
// reads a linked worktree's own files, not its main checkout's (F0-14).
func TestResolveSecurityTrustDir_LinkedWorktree(t *testing.T) {
	_, wtRoot := dashWorktree(t)
	sub := filepath.Join(wtRoot, "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	tgt, ok := resolveSecurityTrustDir(sub)
	if !ok || tgt.root != wtRoot || tgt.launch != "pkg" {
		t.Fatalf("resolveSecurityTrustDir = %+v %v, want root %q launch pkg", tgt, ok, wtRoot)
	}
}
