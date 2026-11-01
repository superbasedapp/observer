//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// sandbox_placeholder_ledger_linux_test.go: a SIGKILLed host helper's .git
// placeholder (Linux live re-check on the Docker sandbox 2026-10-23, N3).

// phLayout is a non-git live workspace's protected .git placeholders, as
// the plan names them (sandbox.WorkspaceExecState): the .git and .git/hooks
// directories and the .git/config file.
func phLayout(t *testing.T) (obs, ws string, files, dirs []string) {
	t.Helper()
	obs = relayShortDir(t)
	ws = t.TempDir()
	git := filepath.Join(ws, ".git")
	return obs, ws, []string{filepath.Join(git, "config")}, []string{git, filepath.Join(git, "hooks")}
}

func phExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// TestHostServicesKeepAPlaceholderLedger: the host helper records the
// placeholders it creates in a locked ledger under the observer directory
// before anything else can fail, and its own exit removes both. (Here the
// relay start fails for want of a run record, after the placeholders and
// the ledger exist, which is exactly the state a SIGKILL would leave.)
func TestHostServicesKeepAPlaceholderLedger(t *testing.T) {
	obs, ws, files, dirs := phLayout(t)
	run := "run-ph0"
	h := sandbox.HostArgs{SockDir: filepath.Join(relayShortDir(t), "s"), PlaceholderFiles: files, PlaceholderDirs: dirs, RelayRun: run, ObserverDir: obs}
	stop, err := startHostServices(h)
	if err == nil {
		stop()
		t.Fatal("the relay started with no run record")
	}
	ledger := placeholderLedgerPath(obs, run)
	b, rerr := os.ReadFile(ledger)
	if rerr != nil || !phExists(filepath.Join(ws, ".git", "config")) {
		stop()
		t.Fatalf("no ledger beside the placeholders: %v", rerr)
	}
	var led placeholderLedgerFile
	if err := json.Unmarshal(b, &led); err != nil || led.V != placeholderLedgerVersion || len(led.Entries) != 3 {
		stop()
		t.Fatalf("ledger %s: %v", b, err)
	}
	if n, err := sweepStalePlaceholders(obs, time.Now()); err != nil || n != 0 || !phExists(filepath.Join(ws, ".git")) {
		stop()
		t.Fatalf("the sweep cleared a live helper's ledger: %d %v", n, err)
	}
	stop()
	if phExists(ledger) || phExists(filepath.Join(ws, ".git")) {
		t.Fatal("the helper's own exit left its ledger or its placeholders")
	}
}

// TestSweepRemovesAKilledHelpersPlaceholders: once the helper is gone (the
// kernel dropped its lock), the daemon's start sweep removes exactly the
// placeholders the ledger proves and the ledger itself. Without a ledger
// (a helper from before it, or a .git nobody recorded) nothing is removed.
func TestSweepRemovesAKilledHelpersPlaceholders(t *testing.T) {
	obs, ws, files, dirs := phLayout(t)
	if n, err := sweepStalePlaceholders(obs, time.Now()); err != nil || n != 0 {
		t.Fatalf("empty runs dir: %d %v", n, err)
	}
	l, err := openPlaceholderLedger(obs, "run-ph1")
	if err != nil || l == nil {
		t.Fatalf("open ledger: %v", err)
	}
	created, err := createPlaceholders(files, dirs)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.record(created); err != nil {
		t.Fatal(err)
	}
	// SIGKILL: the descriptor goes, the ledger file stays.
	_ = l.f.Close()
	n, err := sweepStalePlaceholders(obs, time.Now())
	if err != nil || n != 1 {
		t.Fatalf("sweep %d %v", n, err)
	}
	if phExists(filepath.Join(ws, ".git")) || phExists(placeholderLedgerPath(obs, "run-ph1")) {
		t.Fatal("the killed helper's placeholder or ledger survived the sweep")
	}

	// An unrecorded placeholder-shaped .git is never touched.
	if _, err := createPlaceholders(files, dirs); err != nil {
		t.Fatal(err)
	}
	if n, _ := sweepStalePlaceholders(obs, time.Now()); n != 0 || !phExists(filepath.Join(ws, ".git", "config")) {
		t.Fatal("the sweep removed a .git no ledger named")
	}
}

// TestSweepNeverRemovesARealGit: a .git that became real after the helper
// died (git wrote HEAD and a sample hook, and replaced config) keeps every
// path, and a ledger naming a file of the user's with its own body (not a
// placeholder body) removes nothing either; each ledger is still cleared.
func TestSweepNeverRemovesARealGit(t *testing.T) {
	obs, ws, files, dirs := phLayout(t)
	git := filepath.Join(ws, ".git")
	l, err := openPlaceholderLedger(obs, "run-ph2")
	if err != nil {
		t.Fatal(err)
	}
	created, err := createPlaceholders(files, dirs)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.record(created); err != nil {
		t.Fatal(err)
	}
	_ = l.f.Close()
	if err := os.WriteFile(filepath.Join(git, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(git, "hooks", "pre-commit.sample"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(git, "config.lock")
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(git, "config")); err != nil {
		t.Fatal(err)
	}
	// A forged entry: the user's notes.txt with its true inode and body.
	notes := filepath.Join(ws, "notes.txt")
	if err := os.WriteFile(notes, []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(notes, &st); err != nil {
		t.Fatal(err)
	}
	forged, _ := json.Marshal(placeholderLedgerFile{V: placeholderLedgerVersion, Entries: []placeholderLedgerEntry{{Path: notes, Dev: uint64(st.Dev), Ino: st.Ino, Content: []byte("mine\n")}}}) //nolint:unconvert // Dev is uint64 on amd64
	if err := os.WriteFile(placeholderLedgerPath(obs, "run-forged"), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := sweepStalePlaceholders(obs, time.Now())
	if err != nil || n != 2 {
		t.Fatalf("sweep %d %v", n, err)
	}
	for _, p := range []string{git, filepath.Join(git, "HEAD"), filepath.Join(git, "config"), filepath.Join(git, "hooks"), notes} {
		if !phExists(p) {
			t.Errorf("%s was removed", p)
		}
	}
}
