//go:build !sbo_omit_security && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
)

// security_box_audit_wire_test.go pins the SEC-BOX merge-audit fixes on
// the sandbox binding's side (findings 4, 5 and 6).

// TestSecurityReturnStepNeverDefaultConfig (audit finding 4): outside the
// daemon the return-step scan builds its step only from the absolute
// config path the helper was handed; with none (or a relative one) it
// records nothing and never opens or creates a database under the default
// config.
func TestSecurityReturnStepNeverDefaultConfig(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	securityRT.commitScan.Store(nil)
	prev := securityReturnStepFromConfig
	t.Cleanup(func() { securityReturnStepFromConfig = prev })
	var asked []string
	securityReturnStepFromConfig = func(_ context.Context, p string) (*securityCommitStep, func()) {
		asked = append(asked, p)
		return nil, nil
	}
	ctx := context.Background()
	for _, p := range []string{"", filepath.Join("relative", "config.toml")} {
		if err := securitySandboxReturnScan(ctx, sandboxReturnScanInput{Repo: t.TempDir(), ConfigPath: p}); err != nil {
			t.Fatal(err)
		}
	}
	if len(asked) != 0 {
		t.Fatalf("a step was built from %v", asked)
	}
	abs := filepath.Join(t.TempDir(), "config.toml")
	if err := securitySandboxReturnScan(ctx, sandboxReturnScanInput{Repo: t.TempDir(), ConfigPath: abs}); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != abs {
		t.Fatalf("asked %v, want [%s]", asked, abs)
	}
	// The real builder, no path: nothing appears under the default config.
	securityReturnStepFromConfig = prev
	if err := securitySandboxReturnScan(ctx, sandboxReturnScanInput{Repo: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".observer")); !os.IsNotExist(err) {
		t.Fatalf("the default observer directory was touched: %v", err)
	}

	// The OCI helper's half lives in security_box_audit_wire_linux_test.go
	// (the helper is Linux-only) and security_box_audit_wire_oci_test.go.
}

// TestCopyRunIndexOwns (audit finding 5): a run id is confirmed only by a
// host-written record of that run whose project is the repository.
func TestCopyRunIndexOwns(t *testing.T) {
	st, _ := openTestStore(t)
	obs := boxRunsFixture(t)
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	writeBoxRun(t, st, obs, "RUNOWN000001", root, "", false, nil)
	ctx := context.Background()
	for _, tc := range []struct {
		root, run string
		want      bool
	}{
		{root, "RUNOWN000001", true},
		{t.TempDir(), "RUNOWN000001", false},
		{root, "RUNOTHER0001", false},
		{root, "", false},
	} {
		if got := securityCopyRuns.owns(ctx, tc.root, tc.run); got != tc.want {
			t.Errorf("owns(%s, %q) = %v, want %v", tc.root, tc.run, got, tc.want)
		}
	}
}

// TestCopyRunIndexOverflow (audit finding 6): past copyRunMax records the
// index says so once, and a tree no indexed run holds reads as inside a
// box (unknown), never live; under the cap again it reads live.
func TestCopyRunIndexOverflow(t *testing.T) {
	obs := t.TempDir()
	clock := time.Now()
	var warned int
	x := &copyRunIndex{
		observerDir: func() string { return obs },
		now:         func() time.Time { return clock },
		warn:        func(string, ...any) { warned++ },
	}
	for i := 0; i <= copyRunMax; i++ {
		ws := filepath.Join(obs, "ws", fmt.Sprintf("%d", i))
		rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: fmt.Sprintf("RUNOVER%05d", i), Tool: "codex", ProjectRoot: ws, WorkspaceDir: ws, Roots: []string{ws}})
		if err != nil {
			t.Fatal(err)
		}
		if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	tree := t.TempDir()
	if r := x.resolve(ctx, nil, tree); r.Kind != secsvc.CopyInBox {
		t.Fatalf("an unindexed tree past the cap: %+v, want copy_in_box", r)
	}
	clock = clock.Add(copyRunRefresh)
	if r := x.resolve(ctx, nil, tree); r.Kind != secsvc.CopyInBox || warned != 1 {
		t.Fatalf("second read: %+v, %d warnings (want one line)", r, warned)
	}
	if err := sandboxrelayd.RemoveRun(obs, fmt.Sprintf("RUNOVER%05d", copyRunMax)); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(copyRunRefresh)
	if r := x.resolve(ctx, nil, tree); r.Kind != secsvc.CopyLive {
		t.Fatalf("under the cap again: %+v, want live", r)
	}
}
