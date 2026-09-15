//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"os"
)

// update_handshake_unix.go is the Unix transport for §3.7 step 7: an
// INHERITED FILE DESCRIPTOR.
//
// A pipe is the right primitive here and not merely a convenient one. It
// gives the parent two signals for the price of one: the message the child
// writes, and — when the child dies without writing — an EOF. A file, a
// socket or a status column would all require the parent to distinguish
// "silent because still starting" from "silent because dead", which is
// exactly the ambiguity failure shape (b) exists to remove.
//
// The child receives it as fd 3: exec.Cmd.ExtraFiles[0] is always fd 3,
// because 0/1/2 are stdin/stdout/stderr.

// handshakeChildFD is the descriptor ExtraFiles[0] lands on in the child.
const handshakeChildFD = 3

// handshakeChannel is the parent-side half of the transport.
type handshakeChannel struct {
	// Env is appended to the child's environment.
	Env []string
	// ExtraFiles is passed to exec.Cmd; index 0 becomes fd 3.
	ExtraFiles []*os.File

	r *os.File
	w *os.File
}

// newHandshakeChannel creates the pipe. stateDir is unused on Unix and is
// taken anyway so the two transports share one signature — the platform
// difference stays inside this file rather than leaking into the caller.
func newHandshakeChannel(nonce, _ /*stateDir*/ string) (*handshakeChannel, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("observer update: handshake pipe: %w", err)
	}
	return &handshakeChannel{
		Env:        []string{handshakeNonceEnv + "=" + nonce},
		ExtraFiles: []*os.File{w},
		r:          r,
		w:          w,
	}, nil
}

// CloseChildSide releases the parent's copy of the write end after the child
// has been started. Without it the parent holds the pipe open and a dead
// child never produces the EOF that makes failure shape (b) detectable.
func (c *handshakeChannel) CloseChildSide() {
	if c.w != nil {
		_ = c.w.Close()
		c.w = nil
	}
}

// Wait blocks until the child writes a line or closes the pipe.
func (c *handshakeChannel) Wait() (string, error) {
	line, err := bufio.NewReader(c.r).ReadString('\n')
	if err != nil && line == "" {
		// EOF with nothing written is the child dying silently; report it
		// as an empty message, which interpretHandshakeMessage refuses.
		return "", nil
	}
	return line, nil
}

// Close releases both ends.
func (c *handshakeChannel) Close() {
	c.CloseChildSide()
	if c.r != nil {
		_ = c.r.Close()
		c.r = nil
	}
}

// sendHandshakeMessage is the CHILD side: write one line to fd 3.
//
// The descriptor is not closed on the success path. The parent reads a whole
// line and stops; leaving fd 3 open costs one descriptor for the daemon's
// lifetime and avoids a class of bug where a second report (or a logging
// wrapper) writes to a closed file.
func sendHandshakeMessage(msg string) error {
	f := os.NewFile(handshakeChildFD, "observer-update-handshake")
	if f == nil {
		return fmt.Errorf("observer update: no handshake descriptor on fd %d", handshakeChildFD)
	}
	if _, err := f.WriteString(msg + "\n"); err != nil {
		return fmt.Errorf("observer update: reporting the handshake: %w", err)
	}
	return nil
}
