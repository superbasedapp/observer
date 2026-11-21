package callerid

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Verdict is the decision for one request.
type Verdict int

// The closed Verdict vocabulary.
const (
	// Allow lets the request through.
	Allow Verdict = iota
	// RefuseBox refuses a caller identified inside a live box.
	RefuseBox
	// RefuseUnidentified refuses a caller that could not be identified
	// while a box that can reach this listener is live (fail closed).
	RefuseUnidentified
	// RefuseUnrooted refuses a caller while a box that can reach this
	// listener is live whose root process is not known (so no caller can
	// be shown to be outside it): the coarse rule, kept for that case only.
	RefuseUnrooted
)

// Facts are what the request path knows about one request.
type Facts struct {
	// Mutating: an unsafe method (POST, PUT, PATCH, DELETE) or a WebSocket
	// upgrade (the terminal bridge, whose writer lease types into a PTY).
	Mutating bool
	// LocalPeer: the TCP peer is on this machine (a loopback address, or
	// the listener's own address). A remote peer is never a local box.
	LocalPeer bool
	// ExposedBoxLive: a live box can reach this listener (the exposure
	// rule of agentlaunch.LoopbackExposure).
	ExposedBoxLive bool
	// Identified: the peer process was found.
	Identified bool
	// ProvenOutside: the peer process was not found, but every strict
	// descendant of every live box root was read and none holds the
	// connection. On its own it proves nothing (see SocketOtherUID).
	ProvenOutside bool
	// SocketOtherUID: the client socket is owned (in the kernel's TCP
	// table) by a uid other than this daemon's. A box's processes run as
	// the daemon's user (bwrap maps the same uid, and its no_new_privs
	// rules out a setuid helper), so a socket another uid owns was not
	// opened BY a box process: the WSL2 /init relay that carries a Windows
	// browser's connection is root's. It does not prove the request did
	// not come from a box: a box can still cause another uid's process to
	// open the connection for it, through a forwarder it can reach (a host
	// HTTP proxy run as root or a service user, or under WSL2 NAT a
	// Windows-side proxy whose connection returns through the same /init
	// relay); that is a named residual (security ledger LAUNCH-1, (5)).
	// A socket of the daemon's own uid
	// with no readable holder proves nothing, since a box can make its
	// socket held by no process for a moment (an fd in flight over
	// SCM_RIGHTS, an io_uring fixed file, a thread group whose leader
	// exited, a fork race).
	SocketOtherUID bool
	// InBox: a strict ancestor of the peer is a live box root.
	InBox bool
	// UnrootedExposedBox: a box that can reach this listener is live but
	// its processes cannot all be traced to a known root: its root pid is
	// not known (a terminal whose child pid could not be read, an older
	// build's marker with no pid), or its backend does not keep its
	// processes in its root's tree (no PID namespace of its own, so an
	// orphan leaves the tree: the MXC rows).
	UnrootedExposedBox bool
}

// rule is one ordered row of the decision table: it decides (verdict,
// true) or passes (_, false).
type rule struct {
	id     string
	decide func(f Facts) (Verdict, bool)
}

// rules are walked top-down; the first deciding row wins (TestDecideRows,
// one case per row).
var rules = []rule{
	{"C1-read-only", func(f Facts) (Verdict, bool) { return Allow, !f.Mutating }},
	{"C2-remote-peer", func(f Facts) (Verdict, bool) { return Allow, !f.LocalPeer }},
	// No box that can reach this listener is live: no box caller is
	// possible, and no lookup is made.
	{"C3-no-exposed-box", func(f Facts) (Verdict, bool) { return Allow, !f.ExposedBoxLive }},
	{"C4-in-box", func(f Facts) (Verdict, bool) { return RefuseBox, f.Identified && f.InBox }},
	// A reachable box whose processes cannot all be traced to a known
	// root: no caller can be shown to be outside it, so the coarse rule
	// holds while it lives.
	{"C5-unrooted-exposed-box", func(f Facts) (Verdict, bool) { return RefuseUnrooted, f.UnrootedExposedBox }},
	{"C6-identified-outside", func(f Facts) (Verdict, bool) { return Allow, f.Identified }},
	// The holder could not be read, but every box process could, none
	// holds the connection, and the socket belongs to another uid, which
	// no box process can open: the holder is outside every box. A socket
	// of the daemon's own uid falls through to C8 (callerid fixes-2, N1).
	{"C7-other-uid-outside-boxes", func(f Facts) (Verdict, bool) { return Allow, f.ProvenOutside && f.SocketOtherUID }},
	{"C8-unidentified-fail-closed", func(Facts) (Verdict, bool) { return RefuseUnidentified, true }},
}

// Decide walks the table and returns the verdict and the deciding row.
func Decide(f Facts) (Verdict, string) {
	for _, r := range rules {
		if v, ok := r.decide(f); ok {
			return v, r.id
		}
	}
	return RefuseUnidentified, ""
}

// maxAncestry bounds the parent walk (a process tree is never this deep;
// the bound also ends a cycle a reused pid could form).
const maxAncestry = 128

// Ancestors returns pid's strict ancestors, nearest first, through parent
// (which reports a process's parent and false when it is gone or
// unreadable). The walk stops at pid 0 or 1, at a repeated pid, or at
// maxAncestry steps.
func Ancestors(pid int, parent func(pid int) (int, bool)) []int {
	var out []int
	seen := map[int]bool{pid: true}
	cur := pid
	for range maxAncestry {
		p, ok := parent(cur)
		if !ok || p <= 0 || seen[p] {
			break
		}
		out = append(out, p)
		if p == 1 {
			break
		}
		seen[p] = true
		cur = p
	}
	return out
}

// Descendants returns every strict descendant of a root in roots, given
// each process's parent (parents maps pid to ppid), sorted ascending. A
// chain longer than maxAncestry or one that repeats a pid is not followed.
func Descendants(parents map[int]int, roots map[int]string) []int {
	var out []int
	for pid := range parents {
		if _, isRoot := roots[pid]; isRoot {
			continue
		}
		parent := func(p int) (int, bool) {
			pp, ok := parents[p]
			return pp, ok
		}
		if _, in := InBox(Ancestors(pid, parent), roots); in {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out
}

// InBox reports whether one of ancestors is a live box root, and which.
func InBox(ancestors []int, roots map[int]string) (string, bool) {
	for _, a := range ancestors {
		if run, ok := roots[a]; ok {
			return run, true
		}
	}
	return "", false
}

// Socket is one row of /proc/net/tcp or tcp6.
type Socket struct {
	Local, Remote netip.AddrPort
	UID           int
	Inode         uint64
}

// ParseProcNetTCP parses the content of /proc/net/tcp or /proc/net/tcp6.
// Malformed rows are skipped.
func ParseProcNetTCP(data []byte) []Socket {
	var out []Socket
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	first := true
	for sc.Scan() {
		if first { // the header row
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, err1 := parseHexAddr(f[1])
		remote, err2 := parseHexAddr(f[2])
		uid, err3 := strconv.Atoi(f[7])
		inode, err4 := strconv.ParseUint(f[9], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			continue
		}
		out = append(out, Socket{Local: local, Remote: remote, UID: uid, Inode: inode})
	}
	return out
}

// parseHexAddr parses procfs's "ADDR:PORT" in hex, the address in the
// kernel's byte order (32-bit words in host little-endian order).
func parseHexAddr(s string) (netip.AddrPort, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("callerid: no port in %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("callerid: bad address %q", a)
	}
	// Each 32-bit word is stored little-endian.
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

// FindClientSocket returns the socket whose local end is client and whose
// remote end is server: the client side of the connection, as the kernel
// lists it (its inode, and the uid that owns it).
func FindClientSocket(socks []Socket, client, server netip.AddrPort) (Socket, bool) {
	c, s := unmap(client), unmap(server)
	for _, sk := range socks {
		if sk.Local == c && sk.Remote == s && sk.Inode != 0 {
			return sk, true
		}
	}
	return Socket{}, false
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Stat is what the request path reads from /proc/<pid>/stat.
type Stat struct {
	PPID int
	// StartTicks is the process start time in clock ticks since boot.
	StartTicks uint64
	// State is the one-letter process state (field 3: R, S, D, Z, X, ...).
	State byte
}

// Exited reports whether the process has exited and only its entry is
// left: a zombie (Z) its parent has not reaped yet, or one being reaped
// (X). Its stat still reads, with the same start time, so a check that a
// recorded process is still running must not take a readable stat alone
// as the answer.
func (s Stat) Exited() bool { return s.State == 'Z' || s.State == 'X' }

// ParseStat parses /proc/<pid>/stat. The command name (field 2) is in
// parentheses and may hold spaces or parentheses itself, so the fields are
// read after its LAST closing parenthesis.
func ParseStat(data string) (Stat, error) {
	i := strings.LastIndexByte(data, ')')
	if i < 0 {
		return Stat{}, fmt.Errorf("callerid: no command in stat")
	}
	f := strings.Fields(data[i+1:])
	// After the command: state(3) ppid(4) ... starttime(22).
	if len(f) < 20 {
		return Stat{}, fmt.Errorf("callerid: short stat")
	}
	ppid, err := strconv.Atoi(f[1])
	if err != nil {
		return Stat{}, err
	}
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return Stat{}, err
	}
	return Stat{PPID: ppid, StartTicks: start, State: f[0][0]}, nil
}

// IsLocalPeer reports whether client is on this machine for a connection
// accepted on server: a loopback address, or the listener's own address
// (a connection to a non-loopback bind from the same host).
func IsLocalPeer(client, server netip.AddrPort) bool {
	c := client.Addr().Unmap()
	return c.IsLoopback() || (server.IsValid() && c == server.Addr().Unmap())
}

// EnvValue returns the value of the first of keys set (non-empty) in a
// process environment block as /proc/<pid>/environ holds it (NUL-separated
// KEY=value entries). Only the named keys are looked at; the rest of the
// block, which holds secrets, is never returned (lane cli-2 fixes-2: the
// agent session marker of a launching or confirming process).
func EnvValue(environ []byte, keys []string) (string, bool) {
	for _, k := range keys {
		prefix := []byte(k + "=")
		for _, entry := range bytes.Split(environ, []byte{0}) {
			if bytes.HasPrefix(entry, prefix) && len(entry) > len(prefix) {
				return string(entry[len(prefix):]), true
			}
		}
	}
	return "", false
}
