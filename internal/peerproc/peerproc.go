package peerproc

import (
	"context"
	"errors"
	"net/netip"
)

// Peer is the process at the client end of a local connection.
type Peer struct {
	// PID is the holder (0 when Outside).
	PID int
	// Ancestors are its strict ancestors, nearest first.
	Ancestors []int
	// Outside: the holder could not be read, but every strict descendant
	// of every root passed to Find was read and none holds the connection
	// (Linux only). Not a proof on its own: a box can leave its socket
	// held by no process for a moment; see SocketUID.
	Outside bool
	// SocketUID is the uid that owns the client socket in the kernel's TCP
	// table (Linux; -1 when not known). The caller check lets an Outside
	// answer through only for a socket another uid owns, which no box can
	// open (callerid.Facts.SocketOtherUID).
	SocketUID int
}

// ErrUnsupported is Find's answer on a platform without a lookup.
var ErrUnsupported = errors.New("peerproc: caller identification is not offered on this platform")

// ErrNotFound is Find's answer when no readable process holds the
// connection's client socket.
var ErrNotFound = errors.New("peerproc: no process found for the connection")

// ErrBoxUnreadable is Find's answer when no readable process holds the
// connection and a descendant of a box root could not be read (a box
// process that made itself non-dumpable, say), so it could be the holder.
var ErrBoxUnreadable = errors.New("peerproc: no readable process holds the connection and a process inside a live box could not be read")

// Find returns the process holding the client end of the connection from
// client to server (both as the daemon saw them). roots are the live box
// roots: when the holder cannot be read, Find reads their descendants to
// prove it is outside every box (Peer.Outside) or answers
// ErrBoxUnreadable; with no roots it answers ErrNotFound.
func Find(ctx context.Context, client, server netip.AddrPort, roots map[int]string) (Peer, error) {
	return find(ctx, client, server, roots)
}

// StartToken returns a token naming this start of process pid, or false
// when it cannot be read (the process is gone, or the platform has none).
// A process that exited but is not reaped yet (a zombie, or on Windows a
// process object an open handle keeps) is gone: it has no token.
func StartToken(pid int) (string, bool) { return startToken(pid) }

// Ancestors returns pid's strict ancestors, nearest first, through the
// platform's parent lookup (Linux /proc/<pid>/stat; Windows a process
// snapshot whose parents started no later than their children; macOS
// sysctl kern.proc.pid with the same start-time check), walked by
// callerid.Ancestors. Empty when pid is unknown or the platform has no
// lookup. It is the one ancestry walk the caller checks share: the
// dashboard's caller check reads it through Find, and the launch
// initiator (lane cli-2) for a caller identified another way (the attach
// endpoint's peer credentials).
func Ancestors(pid int) []int {
	if pid <= 0 {
		return nil
	}
	return ancestors(pid)
}

// EnvMarker returns the value of the first of keys set in the environment
// of the first process in pids that has one (pids nearest first: the caller,
// then its ancestors), and false when none does or the platform cannot read
// another process's environment (Linux reads /proc/<pid>/environ, which a
// process of the same user can; elsewhere nothing is read). Only the named
// keys are looked at (callerid.EnvValue). A process's environment there is
// the one it was started with, so a child that drops the marker before it
// runs (env -i) still has an ancestor that carries it (lane cli-2 fixes-2).
func EnvMarker(pids []int, keys []string) (string, bool) {
	if len(keys) == 0 {
		return "", false
	}
	return envMarker(pids, keys)
}

// Supported reports whether Find works on this platform.
func Supported() bool { return supported }
