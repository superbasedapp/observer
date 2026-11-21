//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// TestDefaultWorkspaceConsentManifest proves the consent path end to end on
// a set-up default workspace: the listing and the upload plan the hosted
// consent screen uses (hostedDriver.manifest: `git rev-parse` + `git
// ls-files` through the read-only envelope, then PlanManifest) accept it.
// It is NOT refused as upload_scope_not_repository, needs no commit, and
// plans exactly the marker file, so the box receives nothing of a project.
func TestDefaultWorkspaceConsentManifest(t *testing.T) {
	needGit(t)
	dir := filepath.Join(t.TempDir(), "observer-workspace")
	cfg := config.Default()
	cfg.Workspace.DefaultDir = dir
	var out bytes.Buffer
	ensureDefaultWorkspace(context.Background(), &out, cfg)
	if out.Len() == 0 || bytes.HasPrefix(out.Bytes(), []byte("WARN")) {
		t.Fatalf("set-up failed: %q", out.String())
	}
	// The listing step (any OS): git sees a repository rooted exactly at the
	// workspace and lists the marker.
	cands, repo, err := hostedListWorkspace(context.Background(), dir)
	if err != nil || !repo {
		t.Fatalf("listing: repo=%v err=%v", repo, err)
	}
	if len(cands) != 1 || cands[0].Path != ".observer-workspace" || cands[0].Kind != sandboxremote.KindRegular {
		t.Fatalf("want exactly the marker listed, got %+v", cands)
	}
	if runtime.GOOS == "windows" {
		// The hosted host side runs on Linux and WSL2 only: PlanManifest
		// takes POSIX roots. The plan step runs on those hosts.
		t.Log("upload plan step skipped on Windows (hosted host side is Linux/WSL2 only)")
		return
	}
	m, err := (&hostedDriver{}).manifest(context.Background(), dir)
	if errors.Is(err, sandboxremote.ErrScopeNotRepository) {
		t.Fatalf("the consent screen would refuse the workspace: %v", err)
	}
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if m.Count != 1 || len(m.Files) != 1 || m.Files[0].Path != ".observer-workspace" {
		t.Fatalf("want exactly the marker planned, got %+v", m)
	}
	if m.ScopeKey == "" {
		t.Fatal("no scope key for the consent facts")
	}
}

// TestEmptyRepositoryManifestIsNotRefused pins that an empty file set is a
// valid upload plan (a repository with nothing to send), so a workspace
// whose marker were ever excluded would still get a consent screen.
func TestEmptyRepositoryManifestIsNotRefused(t *testing.T) {
	m, err := sandboxremote.PlanManifest(sandboxremote.ManifestInput{Root: "/work/ws", Home: "/home/dev", Repository: true})
	if err != nil || m.Count != 0 {
		t.Fatalf("empty repository: %+v, %v", m, err)
	}
}
