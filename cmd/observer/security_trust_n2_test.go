//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
)

// TestTrustCheckCmdListsAndAcceptsTheN2Row (SBX-P3D audit finding 1):
// `observer security trust check` reads the same conditional rows as the
// launch gate, so a repository's initializeCommand is listed, and
// `accept` accepts it; the next check reports it accepted.
func TestTrustCheckCmdListsAndAcceptsTheN2Row(t *testing.T) {
	ctx := context.Background()
	st := baselineTestStore(t)
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".devcontainer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".devcontainer", "devcontainer.json"), []byte(n2Devcontainer), 0o644); err != nil {
		t.Fatal(err)
	}
	target, err := resolveRepoTrustTarget(root)
	if err != nil {
		t.Fatal(err)
	}
	paths, parse := repoTrustConditional(config.Default(), componentstate.Snapshot{})
	s := trustCmdState{st: st, target: target, rootHash: guard.HashProjectRoot(target.root), close: func() {}, paths: paths, devcontainer: parse}
	res, err := s.runTrustCheck(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range res.Reasons {
		if r.Code == "devcontainer_ignored_field" && r.Key == "initializeCommand" {
			found = r.Digest != "" && !r.Accepted
		}
	}
	if !found {
		t.Fatalf("check does not list the N2 row as pending: %+v", res.Reasons)
	}
	items, err := trustAcceptSelection(res, nil, true)
	if err != nil || len(items) != 1 {
		t.Fatalf("accept selection %v %v", items, err)
	}
	if n, err := st.AcceptSecTrustItems(ctx, s.rootHash, items, "cli:test", time.Now()); err != nil || n != 1 {
		t.Fatalf("accept %d %v", n, err)
	}
	after, err := s.runTrustCheck(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range after.Reasons {
		if r.Code == "devcontainer_ignored_field" && r.Key == "initializeCommand" && !r.Accepted {
			t.Fatalf("still pending after accept: %+v", r)
		}
	}
	if len(after.Digests()) != 0 {
		t.Fatalf("pending after accept: %v", after.Digests())
	}
}
