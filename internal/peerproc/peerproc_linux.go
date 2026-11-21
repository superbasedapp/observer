//go:build linux

package peerproc

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/callerid"
)

const supported = true

// procRoot is /proc (a var so tests can point it at a fixture tree).
var procRoot = "/proc"

func find(ctx context.Context, client, server netip.AddrPort, roots map[int]string) (Peer, error) {
	var socks []callerid.Socket
	for _, name := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(filepath.Join(procRoot, "self", "net", name))
		if err == nil {
			socks = append(socks, callerid.ParseProcNetTCP(b)...)
		}
	}
	sock, ok := callerid.FindClientSocket(socks, client, server)
	if !ok {
		return Peer{SocketUID: -1}, ErrNotFound
	}
	want := "socket:[" + strconv.FormatUint(sock.Inode, 10) + "]"
	pids, err := listPIDs()
	if err != nil {
		return Peer{SocketUID: sock.UID}, ErrNotFound
	}
	// read[pid] is true for a process whose fds were read, false for one
	// whose fds could not be (another user's: skipped, not the holder).
	read := make(map[int]bool, len(pids))
	for _, pid := range pids {
		if ctx.Err() != nil {
			return Peer{}, ctx.Err()
		}
		holds, readable := holdsSocket(pid, want)
		if holds {
			return Peer{PID: pid, Ancestors: callerid.Ancestors(pid, parentOf), SocketUID: sock.UID}, nil
		}
		read[pid] = readable
	}
	if len(roots) == 0 {
		return Peer{SocketUID: sock.UID}, ErrNotFound
	}
	p, err := outsideBoxes(ctx, want, roots, read)
	p.SocketUID = sock.UID
	return p, err
}

// outsideBoxes is the fallback when no readable process holds the socket:
// every process's parent is world-readable in /proc/<pid>/stat, so the
// strict descendants of the box roots are known; if each of them can be
// read (a process that started after the first scan is read now) and none
// holds the socket, it answers Outside, which the caller check accepts
// only for a socket another uid owns (Peer.SocketUID). One that cannot be
// read could be the holder: fail closed.
func outsideBoxes(ctx context.Context, want string, roots map[int]string, read map[int]bool) (Peer, error) {
	pids, err := listPIDs()
	if err != nil {
		return Peer{}, ErrBoxUnreadable
	}
	parents := make(map[int]int, len(pids))
	for _, pid := range pids {
		if pp, ok := parentOf(pid); ok {
			parents[pid] = pp
		}
	}
	for _, pid := range callerid.Descendants(parents, roots) {
		if ctx.Err() != nil {
			return Peer{}, ctx.Err()
		}
		readable, seen := read[pid]
		if seen && !readable {
			return Peer{}, ErrBoxUnreadable
		}
		if seen {
			continue
		}
		holds, readable := holdsSocket(pid, want)
		if holds {
			return Peer{PID: pid, Ancestors: callerid.Ancestors(pid, parentOf)}, nil
		}
		if !readable {
			if _, alive := statOf(pid); !alive {
				continue // it exited between the scans
			}
			return Peer{}, ErrBoxUnreadable
		}
	}
	return Peer{Outside: true}, nil
}

// listPIDs lists the numeric entries of /proc.
func listPIDs() ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// holdsSocket reports whether pid holds the socket link want, and whether
// its fd directory could be read at all. It reads /proc/<pid>/fd only, not
// /proc/<pid>/task/*/fd: a thread group whose leader exited shows an empty
// fd directory, so its socket is missed here, and the holder then reads
// as "not found". The caller check makes that moot: a socket of the
// daemon's own uid with no holder found is refused (rule C8), and only a
// socket another uid owns, which no box process can open, may pass
// (callerid fixes-2, N1).
func holdsSocket(pid int, want string) (holds, readable bool) {
	fdDir := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return false, false
	}
	for _, fd := range fds {
		if link, err := os.Readlink(filepath.Join(fdDir, fd.Name())); err == nil && link == want {
			return true, true
		}
	}
	return false, true
}

func ancestors(pid int) []int { return callerid.Ancestors(pid, parentOf) }

// maxEnviron bounds the environment block read per process.
const maxEnviron = 1 << 20

func envMarker(pids []int, keys []string) (string, bool) {
	for _, pid := range pids {
		if pid <= 1 {
			continue
		}
		f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "environ"))
		if err != nil {
			continue // gone, or another user's: no marker read
		}
		b, err := io.ReadAll(io.LimitReader(f, maxEnviron))
		_ = f.Close()
		if err != nil {
			continue
		}
		if v, ok := callerid.EnvValue(b, keys); ok {
			return v, true
		}
	}
	return "", false
}

func parentOf(pid int) (int, bool) {
	st, ok := statOf(pid)
	return st.PPID, ok
}

func statOf(pid int) (callerid.Stat, bool) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return callerid.Stat{}, false
	}
	st, err := callerid.ParseStat(string(b))
	return st, err == nil
}

// startToken names pid's current start, false when it cannot be read or the
// process has exited: a zombie keeps its stat and start time until its
// parent reaps it, which a parent that never waits can put off for as long
// as it runs, so a readable stat alone does not say the process still runs.
func startToken(pid int) (string, bool) {
	st, ok := statOf(pid)
	if !ok || st.Exited() {
		return "", false
	}
	boot, err := os.ReadFile(filepath.Join(procRoot, "sys", "kernel", "random", "boot_id"))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(boot)) + ":" + strconv.FormatUint(st.StartTicks, 10), true
}
