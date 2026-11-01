//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// TestSandboxReturnRefusesBoxPlantedCommondir proves the return step blocks
// the host-side effect of the live Mac D1 escape with real git: a box that
// planted .git/commondir in its copy is refused before any host git touches
// the copy (the first step reads FROM it and would run git-upload-pack in
// it), the refusal names the file, and no ref is written. Ledger SBX-BE-21.
func TestSandboxReturnRefusesBoxPlantedCommondir(t *testing.T) {
	req, inCopy := returnFixture(t)
	_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
	inCopy("add", "b.txt")
	inCopy("commit", "-qm", "two")

	// The box plants a commondir in the copy's git dir (a clone's .git is a
	// directory) pointing at a directory it controls.
	if err := os.WriteFile(filepath.Join(req.CopyDir, ".git", "commondir"), []byte("../evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := sandboxReturn(context.Background(), req, runReturnGit, nil)
	if err == nil {
		t.Fatalf("the return did not refuse a box-planted commondir (res %+v)", res)
	}
	if !strings.Contains(err.Error(), "commondir") {
		t.Fatalf("the refusal does not name commondir: %v", err)
	}
	// No ref was written.
	out, _ := exec.Command("git", "-C", req.SourceRepo, "rev-parse", "--verify", "--quiet", workspace.ReturnRefPrefix+req.RunID).Output()
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("a ref was written despite the refusal: %q", out)
	}
	// The copy is kept, not deleted.
	if _, err := os.Stat(req.CopyDir); err != nil {
		t.Fatalf("the copy was deleted: %v", err)
	}
}

// TestSandboxReturnRefusesUploadPackHookInCopyConfig proves the config-key
// arm of the refusal: a clone's config legitimately exists, so only a
// dangerous key (here uploadpack.packObjectsHook, which git-upload-pack would
// run while serving the host's fetch from the copy) refuses the return.
func TestSandboxReturnRefusesUploadPackHookInCopyConfig(t *testing.T) {
	req, inCopy := returnFixture(t)
	_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
	inCopy("add", "b.txt")
	inCopy("commit", "-qm", "two")
	inCopy("config", "uploadpack.packObjectsHook", "touch /tmp/pwned")

	_, err := sandboxReturn(context.Background(), req, runReturnGit, nil)
	if err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatalf("the return did not refuse a copy config that sets packObjectsHook: %v", err)
	}
}
