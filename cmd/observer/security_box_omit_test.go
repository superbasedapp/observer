//go:build sbo_omit_security && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestSandboxReturnWithoutSecurity: a build without the security module
// leaves the return step's scan nil, so a return is today's return.
func TestSandboxReturnWithoutSecurity(t *testing.T) {
	if sandboxReturnScan != nil {
		t.Fatal("sandboxReturnScan is bound in a build without the security module")
	}
	req, inCopy := returnFixture(t)
	_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
	inCopy("add", "b.txt")
	inCopy("commit", "-qm", "two")
	if _, err := sandboxReturn(context.Background(), req, runReturnGit, sandboxReturnScan); err != nil {
		t.Fatal(err)
	}
}
