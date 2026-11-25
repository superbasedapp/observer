package localipc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// listensocket_test.go pins the AF_UNIX listener's own rules: the 0700
// parent directory and 0600 socket, tightening a looser directory, and the
// live-daemon guard. These tests moved here from internal/attachsock, which
// used to reach ListenSocket through its re-export.

// ListenSocket refuses to unlink a regular file; on a clean path it creates
// a 0600 socket.
func TestListenSocketPerms(t *testing.T) {
	t.Parallel()
	skipUnlessUnixSocketTransport(t)
	dir := t.TempDir()

	// Refuse a non-socket file.
	regular := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("write regular: %v", err)
	}
	if _, err := ListenSocket(regular); err == nil {
		t.Fatal("expected ListenSocket to refuse a regular file")
	}
	if _, err := os.Stat(regular); err != nil {
		t.Fatalf("regular file should be untouched: %v", err)
	}

	// Clean path → a 0700 parent dir + a 0600 socket (A1). The socket lives in
	// its own dedicated directory so the parent-dir permission enforces
	// owner-only connect().
	sockPath := filepath.Join(dir, "attach", "attach.sock")
	ln, err := ListenSocket(sockPath)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	defer ln.Close()
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected a socket, got mode %v", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket perm = %o, want 600", perm)
	}
	// A1: the parent dir must be 0700 (owner rwx only).
	dfi, err := os.Stat(filepath.Dir(sockPath))
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if perm := dfi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("attach dir perm = %o, want 700", perm)
	}
}

// A1: a pre-existing looser parent dir is tightened to 0700.
func TestListenSocketTightensLooseDir(t *testing.T) {
	t.Parallel()
	skipUnlessUnixSocketTransport(t)
	dir := t.TempDir()
	attachDir := filepath.Join(dir, "attach")
	if err := os.MkdirAll(attachDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ln, err := ListenSocket(filepath.Join(attachDir, "attach.sock"))
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	defer ln.Close()
	dfi, _ := os.Stat(attachDir)
	if perm := dfi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("attach dir perm = %o, want 700 (should have been tightened)", perm)
	}
}

// A9: ListenSocket refuses to steal a path a LIVE daemon is already serving,
// and DOES rebind a stale socket left by a crashed daemon.
func TestListenSocketRefusesLiveDaemon(t *testing.T) {
	t.Parallel()
	skipUnlessUnixSocketTransport(t)
	sockPath := filepath.Join(t.TempDir(), "attach", "attach.sock")
	ln1, err := ListenSocket(sockPath)
	if err != nil {
		t.Fatalf("first ListenSocket: %v", err)
	}
	// Accept in the background so the probe-dial succeeds (a live server).
	go func() {
		for {
			c, aerr := ln1.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// A second bind must refuse — the path is served by a live daemon.
	if _, err := ListenSocket(sockPath); !errors.Is(err, ErrSocketLiveDaemon) {
		t.Fatalf("second ListenSocket err = %v, want ErrSocketLiveDaemon", err)
	}

	// Close the live listener → the socket file is now stale → a rebind
	// succeeds (the probe-dial fails).
	_ = ln1.Close()
	ln2, err := ListenSocket(sockPath)
	if err != nil {
		t.Fatalf("rebind over stale socket: %v", err)
	}
	_ = ln2.Close()
}
