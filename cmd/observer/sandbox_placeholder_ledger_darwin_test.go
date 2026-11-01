//go:build darwin && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// sandbox_placeholder_ledger_darwin_test.go: the macOS host helper keeps the
// Linux helper's placeholder ledger (ledger SBX-MAC-4, lane LEFT-SBX), so a
// SIGKILLed Seatbelt or Apple container helper's placeholders are cleared by
// the daemon's next start sweep under the same provably-own rule.

// macPhLayout is a non-git workspace's .git placeholders as the plan names
// them: the .git and .git/hooks directories and the .git/config file.
func macPhLayout(t *testing.T) (obs, ws string, files, dirs []string) {
	t.Helper()
	obs = t.TempDir()
	ws = t.TempDir()
	git := filepath.Join(ws, ".git")
	return obs, ws, []string{filepath.Join(git, "config")}, []string{git, filepath.Join(git, "hooks")}
}

// TestMacSweepRemovesAKilledHelpersPlaceholders: the ledger names what the
// helper made; once its lock is gone the sweep removes exactly those
// placeholders and the ledger, and never a placeholder-shaped .git nobody
// recorded.
func TestMacSweepRemovesAKilledHelpersPlaceholders(t *testing.T) {
	obs, ws, files, dirs := macPhLayout(t)
	l, err := openPlaceholderLedger(obs, "run-mac1")
	if err != nil || l == nil {
		t.Fatalf("open ledger: %v", err)
	}
	made, err := createMacPlaceholders(files, dirs)
	if err != nil || len(made) != 3 {
		t.Fatalf("made %d: %v", len(made), err)
	}
	if err := l.recordMac(made); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(placeholderLedgerPath(obs, "run-mac1"))
	var led placeholderLedgerFile
	if err := json.Unmarshal(b, &led); err != nil || len(led.Entries) != 3 || led.Entries[0].Ino == 0 {
		t.Fatalf("ledger %s: %v", b, err)
	}
	if n, _ := sweepStalePlaceholders(obs, time.Now()); n != 0 {
		t.Fatal("the sweep cleared a live helper's ledger")
	}
	_ = l.f.Close() // SIGKILL
	if n, err := sweepStalePlaceholders(obs, time.Now()); err != nil || n != 1 {
		t.Fatalf("sweep %d %v", n, err)
	}
	if _, err := os.Lstat(filepath.Join(ws, ".git")); err == nil {
		t.Fatal("the killed helper's placeholders survived the sweep")
	}
	if _, err := createMacPlaceholders(files, dirs); err != nil {
		t.Fatal(err)
	}
	if n, _ := sweepStalePlaceholders(obs, time.Now()); n != 0 {
		t.Fatal("the sweep cleared a ledger nobody wrote")
	}
	if _, err := os.Lstat(filepath.Join(ws, ".git", "config")); err != nil {
		t.Fatal("the sweep removed a .git no ledger named")
	}
}

// TestMacSweepNeverRemovesARealGit: a .git git wrote into after the helper
// died keeps every path.
func TestMacSweepNeverRemovesARealGit(t *testing.T) {
	obs, ws, files, dirs := macPhLayout(t)
	l, err := openPlaceholderLedger(obs, "run-mac2")
	if err != nil {
		t.Fatal(err)
	}
	made, err := createMacPlaceholders(files, dirs)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.recordMac(made); err != nil {
		t.Fatal(err)
	}
	_ = l.f.Close()
	git := filepath.Join(ws, ".git")
	if err := os.WriteFile(filepath.Join(git, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(git, "config.lock")
	if err := os.WriteFile(tmp, []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(git, "config")); err != nil {
		t.Fatal(err)
	}
	if n, err := sweepStalePlaceholders(obs, time.Now()); err != nil || n != 1 {
		t.Fatalf("sweep %d %v", n, err)
	}
	for _, p := range []string{git, filepath.Join(git, "HEAD"), filepath.Join(git, "config")} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed", p)
		}
	}
}
