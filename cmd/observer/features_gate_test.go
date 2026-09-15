package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures/lkgsidecar"
)

func TestDisallowKeys(t *testing.T) {
	got := disallowKeys(map[string]bool{"codex": true, "aider": true, "crush": false})
	if len(got) != 2 || got[0] != "aider" || got[1] != "codex" {
		t.Fatalf("disallowKeys = %v, want [aider codex] (true keys, sorted)", got)
	}
	if disallowKeys(nil) != nil {
		t.Error("nil map should yield nil")
	}
}

// TestWriterThenGate is the end-to-end slice: the daemon-side writer
// materializes the sidecar, and the launcher-side gate reads it back and
// refuses the disallowed tool while allowing others.
func TestWriterThenGate(t *testing.T) {
	dir := t.TempDir()
	var cfg config.Config
	cfg.Observer.DBPath = filepath.Join(dir, "observer.db")
	path := config.ResolveFeaturesSidecarPath(cfg, "")
	if path == "" {
		t.Fatal("resolved sidecar path is empty")
	}

	write := makeFeaturesSidecarWriter(cfg, "v-test", nil)
	if write == nil {
		t.Fatal("writer is nil for a configured DB path")
	}
	write([]string{"codex", "crush"})

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}

	// Disallowed tool → error + honest copy on stderr.
	var errBuf bytes.Buffer
	if err := refuseIfToolDisallowedCfg(cfg, "codex", &errBuf); err == nil {
		t.Error("expected refusal for a disallowed tool")
	}
	if !strings.Contains(errBuf.String(), "disallowed this tool") {
		t.Errorf("stderr copy missing; got %q", errBuf.String())
	}

	// Allowed tool → nil, no copy.
	errBuf.Reset()
	if err := refuseIfToolDisallowedCfg(cfg, "claude-code", &errBuf); err != nil {
		t.Errorf("allowed tool refused: %v", err)
	}
	if errBuf.Len() != 0 {
		t.Errorf("unexpected stderr for an allowed tool: %q", errBuf.String())
	}

	// DB-path form resolves the same file.
	if err := refuseIfToolDisallowedDB(cfg.Observer.DBPath, "crush", &bytes.Buffer{}); err == nil {
		t.Error("DB-path gate should also refuse a disallowed tool")
	}
}

// TestGateFailsOpenWithoutSidecar: no sidecar file ⇒ every tool launches.
func TestGateFailsOpenWithoutSidecar(t *testing.T) {
	dir := t.TempDir()
	var cfg config.Config
	cfg.Observer.DBPath = filepath.Join(dir, "observer.db") // never written
	if err := refuseIfToolDisallowedCfg(cfg, "codex", &bytes.Buffer{}); err != nil {
		t.Errorf("absent sidecar must fail open, got %v", err)
	}
	if err := refuseIfToolDisallowed("", "codex", &bytes.Buffer{}); err != nil {
		t.Errorf("empty path must fail open, got %v", err)
	}
}

// TestWriterClearsDisallow: writing an empty list (clear/inert) removes the
// gate on the previously-disallowed tool.
func TestWriterClearsDisallow(t *testing.T) {
	dir := t.TempDir()
	var cfg config.Config
	cfg.Observer.DBPath = filepath.Join(dir, "observer.db")
	write := makeFeaturesSidecarWriter(cfg, "v-test", nil)
	write([]string{"codex"})
	if err := refuseIfToolDisallowedCfg(cfg, "codex", &bytes.Buffer{}); err == nil {
		t.Fatal("codex should be disallowed after write")
	}
	write(nil) // clear
	if err := refuseIfToolDisallowedCfg(cfg, "codex", &bytes.Buffer{}); err != nil {
		t.Errorf("codex should be allowed after clear, got %v", err)
	}
	// The file still exists but with an empty list.
	f, reason := lkgsidecar.Read(config.ResolveFeaturesSidecarPath(cfg, ""), time.Now())
	if reason != lkgsidecar.ReasonNone || f == nil || len(f.Disallow) != 0 {
		t.Errorf("after clear: reason=%q file=%+v", reason, f)
	}
}
