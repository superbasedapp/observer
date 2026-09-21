package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestCollectIntegritySignals asserts the boundary seam assembles coarse labels
// from the diag + proxyroute detectors: a cross-OS sibling observer.db becomes
// an "origin/os" label, and a claude route repointed off observer becomes the
// "claude-code" drifted-tool label. Only labels are produced (no paths).
func TestCollectIntegritySignals(t *testing.T) {
	nativeHome := t.TempDir()
	foreignHome := t.TempDir()

	// Daemon's own DB in the native home.
	daemonDir := filepath.Join(nativeHome, ".observer")
	if err := os.MkdirAll(daemonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	daemonDB := filepath.Join(daemonDir, "observer.db")
	if err := os.WriteFile(daemonDB, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A cross-OS sibling observer.db in a foreign home.
	fdir := filepath.Join(foreignHome, ".observer")
	if err := os.MkdirAll(fdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fdir, "observer.db"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A drifted claude route in the native home.
	cdir := filepath.Join(nativeHome, ".claude")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "settings.json"),
		[]byte(`{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	homes := []crossmount.HomeRoot{
		{Path: nativeHome, OS: "linux", Origin: "native"},
		{Path: foreignHome, OS: "windows", Origin: "wsl-mnt:marmu"},
	}
	report := collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, false)

	if len(report.SiblingDetail) != 1 || report.SiblingDetail[0] != "wsl-mnt/windows" {
		t.Errorf("siblings = %v, want [wsl-mnt/windows]", report.SiblingDetail)
	}
	if len(report.DriftedTools) != 1 || report.DriftedTools[0] != "claude-code" {
		t.Errorf("drifted = %v, want [claude-code]", report.DriftedTools)
	}
	if report.CaptureCheckVersion != 1 {
		t.Errorf("capture check version = %d, want 1", report.CaptureCheckVersion)
	}
	wire, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{nativeHome, foreignHome, "marmu", "/home/", "Users"} {
		if strings.Contains(string(wire), forbidden) {
			t.Errorf("managed-integrity wire leaked host identity/path %q: %s", forbidden, wire)
		}
	}
}

// TestCollectIntegritySignals_Clean: default-path daemon + observer-pointing
// route yields no evidence.
func TestCollectIntegritySignals_Clean(t *testing.T) {
	nativeHome := t.TempDir()
	// The kimi-code / qwen-code / crush readers resolve their config path
	// through env vars; pin them at this fixture host so the RUNNING
	// developer's own configs can never be inspected by this test.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(nativeHome, ".config"))
	t.Setenv("CRUSH_CONFIG", "")
	t.Setenv("KIMI_CODE_HOME", "")
	t.Setenv("QWEN_HOME", "")
	daemonDir := filepath.Join(nativeHome, ".observer")
	if err := os.MkdirAll(daemonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	daemonDB := filepath.Join(daemonDir, "observer.db")
	if err := os.WriteFile(daemonDB, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cdir := filepath.Join(nativeHome, ".claude")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "settings.json"),
		[]byte(`{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	homes := []crossmount.HomeRoot{{Path: nativeHome, OS: "linux", Origin: "native"}}
	report := collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, false)
	if len(report.SiblingDetail) != 0 || len(report.DriftedTools) != 0 {
		t.Errorf("clean host produced evidence: siblings=%v drifted=%v", report.SiblingDetail, report.DriftedTools)
	}

	// Track C item 2, corrected by adversarial finding P1-2: the SAME clean
	// host, read under an org that is authoritative over an enforcement point
	// here. claude-code is routed, and NO OTHER inspected tool is installed on
	// this fixture host — so there is still nothing to report. A single-tool
	// developer must not light up as a four-tool bypass the moment the
	// stricter reading ships.
	managed := collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, true)
	if len(managed.DriftedTools) != 0 {
		t.Errorf("managed+enforce host reported drift for tools that are not installed: %v", managed.DriftedTools)
	}

	// Install codex — its config is now ON the host and names no route. THAT
	// is the shape an enforcing managed node reads as drift.
	codexDir := filepath.Join(nativeHome, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"),
		[]byte("model = \"gpt-5\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	managed = collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, true)
	if len(managed.DriftedTools) != 1 || managed.DriftedTools[0] != "codex" {
		t.Errorf("drifted = %v, want [codex] (config present, route key gone)", managed.DriftedTools)
	}
	if managed.RouteDrift != len(managed.DriftedTools) {
		t.Errorf("RouteDrift = %d, want %d", managed.RouteDrift, len(managed.DriftedTools))
	}
	// The individual-node reading of the identical host is unchanged: an
	// absent route key is not drift there.
	if indiv := collectIntegritySignalsFrom(daemonDB, nativeHome, "/current/observer", homes, false); len(indiv.DriftedTools) != 0 {
		t.Errorf("individual node reported drift for an absent route key: %v", indiv.DriftedTools)
	}
}
