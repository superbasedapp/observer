package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// locTokenTestLogger discards output: these tests exercise the warning
// paths, and a real handler would spray them across the test log.
func locTokenTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestResolveLocEditorTokenGeneratesOnce pins the first-start behaviour:
// the file is created 0600 inside a 0700 directory, and a SECOND call
// returns the SAME token rather than rotating it (a rotation on every
// daemon start would invalidate every extension that had already read it).
func TestResolveLocEditorTokenGeneratesOnce(t *testing.T) {
	t.Setenv(locEditorTokenEnv, "")
	dir := filepath.Join(t.TempDir(), "home", ".observer")
	path := filepath.Join(dir, "loc-editor-token")

	first := resolveLocEditorToken(path, locTokenTestLogger())
	if len(first) != locEditorTokenBytes*2 {
		t.Fatalf("token = %q (len %d), want %d hex chars", first, len(first), locEditorTokenBytes*2)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("token file mode = %o, want 600", perm)
		}
		dinfo, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat dir: %v", err)
		}
		if perm := dinfo.Mode().Perm(); perm != 0o700 {
			t.Errorf("token dir mode = %o, want 700", perm)
		}
	}

	if second := resolveLocEditorToken(path, locTokenTestLogger()); second != first {
		t.Errorf("second start rotated the token: %q → %q", first, second)
	}

	// The file's own bytes must match what the daemon handed the handler,
	// modulo the trailing newline the extension trims.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(raw); got != first+"\n" {
		t.Errorf("file holds %q, daemon uses %q", got, first)
	}
}

// TestResolveLocEditorTokenRewritesEmptyFile covers the half-finished
// write: an empty file is a truncated write, not a decision to run without
// a credential, so it is replaced rather than accepted as "no token".
func TestResolveLocEditorTokenRewritesEmptyFile(t *testing.T) {
	t.Setenv(locEditorTokenEnv, "")
	path := filepath.Join(t.TempDir(), "loc-editor-token")
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok := resolveLocEditorToken(path, locTokenTestLogger()); len(tok) != locEditorTokenBytes*2 {
		t.Errorf("empty token file was not replaced: %q", tok)
	}
}

// TestResolveLocEditorTokenEnvOverride keeps the deprecated environment
// variable working for one release, and keeps it AUTHORITATIVE: an
// operator who scripted it has a running setup, so a token file must not
// silently win over it.
func TestResolveLocEditorTokenEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "loc-editor-token")
	if err := os.WriteFile(path, []byte("from-the-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(locEditorTokenEnv, "  from-the-env  ")
	if got := resolveLocEditorToken(path, locTokenTestLogger()); got != "from-the-env" {
		t.Errorf("env override = %q, want the trimmed env value", got)
	}
}

// TestResolveLocEditorTokenFailsOpen pins the fail-OPEN rule: a path the
// daemon cannot write yields an empty token and no error, because the
// endpoint's loopback + Origin posture is still intact and refusing to
// start the daemon over it would be the wrong trade.
func TestResolveLocEditorTokenFailsOpen(t *testing.T) {
	t.Setenv(locEditorTokenEnv, "")
	// A path whose PARENT is a regular file: MkdirAll cannot create the
	// directory, on every platform.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveLocEditorToken(filepath.Join(blocker, "loc-editor-token"), locTokenTestLogger()); got != "" {
		t.Errorf("unwritable path returned %q, want an empty token (fail open)", got)
	}
	if got := resolveLocEditorToken("", locTokenTestLogger()); got != "" {
		t.Errorf("empty path returned %q, want an empty token", got)
	}
}

// TestLocEditorTokenPathFallsBackToObserverHome covers the degraded-config
// start: `observer start` builds the dashboard even when the config load
// failed, so an empty configured path must still resolve somewhere sane
// rather than disabling the credential.
func TestLocEditorTokenPathFallsBackToObserverHome(t *testing.T) {
	var cfg config.Config
	got := locEditorTokenPath(cfg)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory on this host")
	}
	if want := filepath.Join(home, ".observer", "loc-editor-token"); got != want {
		t.Errorf("locEditorTokenPath(zero cfg) = %q, want %q", got, want)
	}

	cfg.Loc.EditorTokenFile = "/custom/tok"
	if got := locEditorTokenPath(cfg); got != "/custom/tok" {
		t.Errorf("configured path lost: %q", got)
	}
}
