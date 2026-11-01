//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// TestSandboxReturnRefusesAnEscapingSymlinkChain is RB1 sweep finding
// SBX-RET-1 through the return step itself: two returned links that each
// stay inside the tree on their own (a/b/d -> .. and a/b/esc -> d/../../x)
// resolve together to a path outside it, so the return is refused before
// any ref is written.
func TestSandboxReturnRefusesAnEscapingSymlinkChain(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "workspaces")
	copyDir := filepath.Join(managed, "RUN000000000003", "src")
	if err := os.MkdirAll(filepath.Join(copyDir, ".git", "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	req := workspace.ReturnRequest{SourceRepo: src, CopyDir: copyDir, ManagedRoot: managed, RunID: "RUN000000000003"}
	sha := strings.Repeat("c", 40)
	up, esc := strings.Repeat("4", 40), strings.Repeat("5", 40)
	line := func(obj, p string) string { return "120000 blob " + obj + "\t" + p + "\x00" }
	run := cannedReturnRunner(sha, line(up, "a/b/d")+line(esc, "a/b/esc"), map[string]string{up: "..", esc: "d/../../x"})
	wrote := false
	spy := func(ctx context.Context, st workspace.Step) ([]byte, error) {
		if strings.Contains(strings.Join(st.Argv, " "), " update-ref ") {
			wrote = true
		}
		return run(ctx, st)
	}
	_, err := sandboxReturn(context.Background(), req, spy, nil)
	if err == nil || !strings.Contains(err.Error(), "resolves outside the returned tree") {
		t.Fatalf("err %v, want the chain refused as resolving outside the returned tree", err)
	}
	if wrote {
		t.Fatal("a refused return wrote the ref")
	}
}
