//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// update_handshake_windows.go is the Windows transport for §3.7 step 7.
//
// DEVIATION FROM THE PLAN, STATED PLAINLY. The plan says "an inherited fd on
// Unix; a NAMED PIPE on Windows". This ships a WATCHED FILE instead, for two
// reasons that both point the same way:
//
//   - exec.Cmd.ExtraFiles is not supported on Windows at all, so the Unix
//     mechanism cannot simply be reused; a named pipe would mean a second,
//     platform-only IPC implementation (server creation, connect, overlapped
//     I/O) whose failure modes could not be exercised on the Linux machine
//     this is developed and CI'd on.
//   - the pipe's real advantage — EOF tells the parent the child died — is
//     already covered here by cmd.Wait: superviseNewBinary watches the child
//     process AND the channel, and failure shape (b) is decided by the Wait
//     branch on every platform, not by the transport.
//
// So the file carries only the POSITIVE signal (ready / fail), the process
// wait carries death, and the timer carries silence. The child writes to a
// temp name and renames, so the parent can never read a half-written line.

// handshakeFileEnv names the file the child reports through.
const handshakeFileEnv = "OBSERVER_UPDATE_HANDSHAKE_FILE"

// handshakePollInterval is how often the parent re-reads the file. It bounds
// only the latency of a SUCCESSFUL handshake; a failure is detected by the
// process wait, which is immediate.
const handshakePollInterval = 100 * time.Millisecond

// handshakeChannel is the parent-side half of the transport.
type handshakeChannel struct {
	// Env is appended to the child's environment.
	Env []string
	// ExtraFiles is always nil on Windows; the field exists so
	// superviseNewBinary needs no platform branch.
	ExtraFiles []*os.File

	path string
	done chan struct{}
}

// newHandshakeChannel picks the report path under the update state dir.
func newHandshakeChannel(nonce, stateDir string) (*handshakeChannel, error) {
	dir := strings.TrimSpace(stateDir)
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("observer update: handshake dir: %w", err)
	}
	path := filepath.Join(dir, "handshake-"+nonce)
	// A leftover report from an abandoned apply must never satisfy this one.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("observer update: clearing %s: %w", path, err)
	}
	return &handshakeChannel{
		Env:  []string{handshakeNonceEnv + "=" + nonce, handshakeFileEnv + "=" + path},
		path: path,
		done: make(chan struct{}),
	}, nil
}

// CloseChildSide is a no-op: there is no descriptor the parent holds.
func (c *handshakeChannel) CloseChildSide() {}

// Wait polls for the child's report.
func (c *handshakeChannel) Wait() (string, error) {
	for {
		select {
		case <-c.done:
			return "", nil
		case <-time.After(handshakePollInterval):
		}
		b, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		if line := strings.TrimSpace(string(b)); line != "" {
			return line, nil
		}
	}
}

// Close stops the poller and removes the report file.
func (c *handshakeChannel) Close() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	if c.path != "" {
		_ = os.Remove(c.path)
	}
}

// sendHandshakeMessage is the CHILD side: write the report atomically.
func sendHandshakeMessage(msg string) error {
	path := strings.TrimSpace(os.Getenv(handshakeFileEnv))
	if path == "" {
		return fmt.Errorf("observer update: no handshake report path in %s", handshakeFileEnv)
	}
	tmp := path + ".part"
	if err := os.WriteFile(tmp, []byte(msg+"\n"), 0o600); err != nil {
		return fmt.Errorf("observer update: reporting the handshake: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("observer update: publishing the handshake report: %w", err)
	}
	return nil
}
