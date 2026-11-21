package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestLivePinReaderFollowsTheFile pins G3 (managed policy visibility,
// 2026-11-12): the reported pins follow a local edit without a restart, and a
// config that stops loading keeps the last value that loaded.
func TestLivePinReaderFollowsTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[guard]\nmode = \"enforce\"\n")
	read := livePinReader(func() string { return path }, config.Default(), nil)
	if got := read()["guard.mode"]; got != "enforce" {
		t.Fatalf("guard.mode = %q, want enforce", got)
	}
	write("[guard]\nmode = \"observe\"\n")
	if got := read()["guard.mode"]; got != "observe" {
		t.Fatalf("after a local edit guard.mode = %q, want observe", got)
	}
	write("[guard\nbroken")
	if got := read()["guard.mode"]; got != "observe" {
		t.Fatalf("a broken file must keep the last value, got %q", got)
	}
}

// TestPolicyInputsStampWatchesProjectFiles (review finding 10, 2026-11-12):
// an edit to a recently active project's in-repo policy file changes the
// stamp at once, within the policyInputsStampProjectLimit most recent roots;
// a root past the bound waits for the heartbeat.
func TestPolicyInputsStampWatchesProjectFiles(t *testing.T) {
	home := t.TempDir()
	cfgPath := filepath.Join(home, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[guard]\nmode = \"enforce\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Guard.Rules.ProjectPolicy == "" {
		t.Skip("no in-repo project policy file configured by default")
	}
	var roots []string
	for i := 0; i <= policyInputsStampProjectLimit; i++ {
		roots = append(roots, filepath.Join(home, "proj", fmt.Sprintf("p%03d", i)))
	}
	writePolicy := func(root, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(cfg.Guard.Rules.ProjectPolicy))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stamp := policyInputsStamp(func() string { return cfgPath }, home, func() []string { return roots })
	for _, tc := range []struct {
		name        string
		root        string
		wantChanged bool
	}{
		{"most recent project", roots[0], true},
		{"last project inside the bound", roots[policyInputsStampProjectLimit-1], true},
		{"project past the bound", roots[policyInputsStampProjectLimit], false},
	} {
		before := stamp()
		writePolicy(tc.root, "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\n")
		if changed := stamp() != before; changed != tc.wantChanged {
			t.Errorf("%s: stamp changed = %v, want %v", tc.name, changed, tc.wantChanged)
		}
	}
}

// TestWatchPolicyInputsPokesOnChange: a change to a watched file pokes the
// reporter; an unchanged one does not.
func TestWatchPolicyInputsPokesOnChange(t *testing.T) {
	var stamp atomic.Value
	stamp.Store("a")
	var pokes atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchPolicyInputs(ctx, func() string { return stamp.Load().(string) }, func() { pokes.Add(1) }, 5*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if pokes.Load() != 0 {
		t.Fatalf("poked %d times with no change", pokes.Load())
	}
	stamp.Store("b")
	deadline := time.Now().Add(2 * time.Second)
	for pokes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if pokes.Load() != 1 {
		t.Fatalf("poked %d times after one change, want 1", pokes.Load())
	}
}
