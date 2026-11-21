//go:build linux

package pidbridge

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcResolver is the Linux implementation of [Resolver]. It scans
// /proc/net/tcp and /proc/net/tcp6 to map a client TCP remote addr to a
// socket inode, then scans /proc/<pid>/fd to find the owning pid, then
// walks up the PPid chain looking for a bridge entry. Results are
// cached for CacheTTL per remote addr.
//
// The ancestor walk matters because Claude Code's own process is the
// pid captured by the hook, but in principle a child process could be
// the one that opened the socket. In practice Claude Code opens the
// HTTP connection itself, so the first lookup hits.
//
// A zero-value ProcResolver is unusable — use [NewProcResolver].
type ProcResolver struct {
	store    *Store
	procDir  string
	cacheTTL time.Duration
	now      func() time.Time

	// toolBinaries names a tool's executables (the registry Binary rows),
	// for the own-process check; nil answers the tool id alone.
	toolBinaries func(tool string) []string

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// SetToolBinaries installs the tool -> executable names lookup the
// own-process check matches against (the daemon passes the integration
// registry's Binary names). Call once at construction, before Resolve.
func (r *ProcResolver) SetToolBinaries(names func(tool string) []string) {
	r.toolBinaries = names
}

// ownProcess reports whether pid is itself one of tool's executables, by
// exact executable identity (comm, exe basename, argv[0] basename, or the
// script under an interpreter), never a substring of its arguments.
func (r *ProcResolver) ownProcess(pid int, tool string) bool {
	names := []string{tool}
	if r.toolBinaries != nil {
		names = append(names, r.toolBinaries(tool)...)
	}
	dir := filepath.Join(r.procDir, strconv.Itoa(pid))
	comm, err := os.ReadFile(filepath.Join(dir, "comm"))
	if err != nil {
		return false
	}
	id := processIdentity{comm: string(comm)}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		id.exe = exe
	}
	if cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		id.argv = strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	}
	return id.isOwnProcess(names)
}

type cacheEntry struct {
	sessionID string
	tool      string
	cwd       string
	ok        bool
	// own reports that the process holding the socket is itself the
	// bridge hit's tool (ownProcess: its executable identity), not just
	// a descendant of it: a script the developer started from the tool's
	// shell resolves the tool's session through the ancestor walk but is
	// not the tool (ResolveOwnTool).
	own     bool
	expires time.Time
}

// NewProcResolver constructs a ProcResolver. procDir defaults to "/proc"
// when empty; tests pass a temp directory. cacheTTL defaults to 30s when
// zero.
func NewProcResolver(store *Store, procDir string, cacheTTL time.Duration) *ProcResolver {
	if procDir == "" {
		procDir = "/proc"
	}
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}
	return &ProcResolver{
		store:    store,
		procDir:  procDir,
		cacheTTL: cacheTTL,
		now:      time.Now,
		cache:    map[string]cacheEntry{},
	}
}

// SetClock overrides the resolver's clock. Not safe for concurrent use
// with Resolve; call once at construction.
func (r *ProcResolver) SetClock(now func() time.Time) {
	if now != nil {
		r.now = now
	}
}

// Resolve implements [Resolver]. remoteAddr is the "IP:port" the server
// sees for the incoming connection (from http.Request.RemoteAddr).
func (r *ProcResolver) Resolve(ctx context.Context, remoteAddr string) (string, bool, error) {
	e, err := r.resolveCached(ctx, remoteAddr)
	if err != nil {
		return "", false, err
	}
	return e.sessionID, e.ok, nil
}

// ResolveTool reports the AI tool that owns the connection (the
// bridge Entry's Tool field, written by the SessionStart hook). Same
// /proc walk and per-addr cache as Resolve — calling both for one
// request costs one walk. Consumed by the compression profile
// router's per-tool assignments (R2); "" with ok=false on any miss.
func (r *ProcResolver) ResolveTool(ctx context.Context, remoteAddr string) (string, bool, error) {
	e, err := r.resolveCached(ctx, remoteAddr)
	if err != nil {
		return "", false, err
	}
	return e.tool, e.ok && e.tool != "", nil
}

// ResolveCWD reports the working directory of the connection's owning
// session — the R3 input for per-project compression overrides. The
// bridge entry's CWD (hook-fed) wins when the ancestor walk hits; for
// hookless tools (codex and any client with no SessionStart hook
// feeding the bridge) it falls back to the socket-owning process's own
// /proc/<pid>/cwd, captured during the same walk. Shares the walk and
// per-addr cache with Resolve and ResolveTool; "" with ok=false when
// neither source produced a directory.
func (r *ProcResolver) ResolveCWD(ctx context.Context, remoteAddr string) (string, bool, error) {
	e, err := r.resolveCached(ctx, remoteAddr)
	if err != nil {
		return "", false, err
	}
	return e.cwd, e.cwd != "", nil
}

// ResolveOwnTool reports the bridge hit's tool only when the process that
// opened the connection is itself that tool's binary (ownProcess: an exact
// executable identity of the socket-owning pid against the tool's
// executables, see SetToolBinaries), never when the tool is merely an
// ancestor. The
// proxy uses it to decide whether a request's own-agent header may claim
// the turn: the tool's own process may not, a child it spawned may (P-228
// fix round 2, N2). Same walk and per-addr cache as Resolve; "" with
// ok=false on any miss.
func (r *ProcResolver) ResolveOwnTool(ctx context.Context, remoteAddr string) (string, bool, error) {
	e, err := r.resolveCached(ctx, remoteAddr)
	if err != nil {
		return "", false, err
	}
	return e.tool, e.ok && e.own && e.tool != "", nil
}

// resolveCached returns the cache entry for remoteAddr, filling it
// with one uncached /proc walk on miss/expiry.
func (r *ProcResolver) resolveCached(ctx context.Context, remoteAddr string) (cacheEntry, error) {
	if remoteAddr == "" {
		return cacheEntry{}, nil
	}
	now := r.now()
	r.mu.Lock()
	if e, ok := r.cache[remoteAddr]; ok && now.Before(e.expires) {
		r.mu.Unlock()
		return e, nil
	}
	r.mu.Unlock()

	sessionID, tool, cwd, ok, own, err := r.resolveUncached(ctx, remoteAddr)
	if err != nil {
		return cacheEntry{}, err
	}
	e := cacheEntry{
		sessionID: sessionID,
		tool:      tool,
		cwd:       cwd,
		ok:        ok,
		own:       own,
		expires:   now.Add(r.cacheTTL),
	}
	r.mu.Lock()
	r.cache[remoteAddr] = e
	r.mu.Unlock()
	return e, nil
}

func (r *ProcResolver) resolveUncached(ctx context.Context, remoteAddr string) (sessionID, tool, cwd string, ok, own bool, err error) {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return "", "", "", false, false, fmt.Errorf("pidbridge.Resolve: parse %q: %w", remoteAddr, err)
	}
	inode, err := r.findSocketInode(ap)
	if err != nil {
		return "", "", "", false, false, err
	}
	if inode == 0 {
		return "", "", "", false, false, nil
	}
	pid, err := r.findPIDForInode(inode)
	if err != nil {
		return "", "", "", false, false, err
	}
	if pid == 0 {
		return "", "", "", false, false, nil
	}
	sessionID, tool, cwd, hitPID, ok, err := r.walkAncestors(ctx, pid)
	if err != nil {
		return "", "", "", false, false, err
	}
	if ok {
		// The socket owner is the tool's own process when the bridge row
		// was registered for that exact pid (a hook, adapter or terminal
		// seed named it, and the walk validated it), or, for a hit on an
		// ancestor, when its executable identity is one of the tool's
		// executables (sdk-1f L4: an exact name, never a substring of a
		// child script's path or arguments).
		own = hitPID == pid || r.ownProcess(pid, tool)
		return sessionID, tool, cwd, true, own, nil
	}
	// Clean bridge miss: the connection's owner has no hook-fed entry
	// (hookless tools — codex exec, third-party clients). Best-effort
	// fall back to the owning process's own working directory so R3
	// project-overlay resolution still works; tool and session stay
	// unresolved (ok=false) — only the cwd field is populated.
	if link, lerr := os.Readlink(filepath.Join(r.procDir, strconv.Itoa(pid), "cwd")); lerr == nil && link != "" {
		return "", "", link, false, false, nil
	}
	return "", "", "", false, false, nil
}

// findSocketInode reads /proc/net/tcp and /proc/net/tcp6 looking for an
// entry whose local_address matches target. The proxy's server sees the
// client-side tuple as the request's RemoteAddr, which in /proc/net/tcp
// appears as local_address of the client socket.
func (r *ProcResolver) findSocketInode(target netip.AddrPort) (uint64, error) {
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		inode, err := scanNetTCP(filepath.Join(r.procDir, name), target)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		if inode != 0 {
			return inode, nil
		}
	}
	return 0, nil
}

func scanNetTCP(path string, target netip.AddrPort) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		local, err := parseHexAddrPort(fields[1])
		if err != nil {
			continue
		}
		if !addrsMatch(local, target) {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		return inode, nil
	}
	return 0, scanner.Err()
}

// addrsMatch compares two AddrPort values tolerant of IPv4-mapped-IPv6
// (::ffff:127.0.0.1 vs 127.0.0.1).
func addrsMatch(a, b netip.AddrPort) bool {
	if a.Port() != b.Port() {
		return false
	}
	return a.Addr().Unmap() == b.Addr().Unmap()
}

// parseHexAddrPort parses the "HEXIP:HEXPORT" format used by /proc/net/tcp.
// The IP portion is laid out in host byte order per 4-byte group; on
// little-endian platforms that means each word needs byte-swapping.
func parseHexAddrPort(s string) (netip.AddrPort, error) {
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return netip.AddrPort{}, fmt.Errorf("pidbridge: bad addr %q", s)
	}
	ipHex := s[:colon]
	portHex := s[colon+1:]
	raw, err := hex.DecodeString(ipHex)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("pidbridge: hex decode ip %q: %w", ipHex, err)
	}
	if len(raw) != 4 && len(raw) != 16 {
		return netip.AddrPort{}, fmt.Errorf("pidbridge: unexpected ip length %d", len(raw))
	}
	// Kernel writes each 32-bit group in host byte order. Reverse each
	// 4-byte chunk to get network byte order.
	for i := 0; i+3 < len(raw); i += 4 {
		raw[i], raw[i+3] = raw[i+3], raw[i]
		raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("pidbridge: AddrFromSlice failed on %x", raw)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("pidbridge: parse port %q: %w", portHex, err)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// findPIDForInode scans /proc/<pid>/fd for a symlink pointing at
// "socket:[<inode>]". Returns 0 on clean miss.
func (r *ProcResolver) findPIDForInode(inode uint64) (int, error) {
	socketLink := fmt.Sprintf("socket:[%d]", inode)
	entries, err := os.ReadDir(r.procDir)
	if err != nil {
		return 0, fmt.Errorf("pidbridge: read %s: %w", r.procDir, err)
	}
	for _, de := range entries {
		pid, err := strconv.Atoi(de.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(r.procDir, de.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// EACCES (different uid) or ESRCH (pid died) — skip.
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if target == socketLink {
				return pid, nil
			}
		}
	}
	return 0, nil
}

// walkAncestors walks pid's PPid chain, looking up each pid in the bridge
// table. The first hit wins; hitPID is the pid whose row hit (pid itself
// when the socket owner was registered directly). The walk stops at pid 2 (init-class: pid 1
// and WSL's distro init at pid 2 are system space — a bridge entry there
// is registration poison, never a real AI tool; see the D17 record) or
// on the first /proc read failure.
//
// A Lookup hit is trusted only after validateProcess confirms the pid is
// still alive and still matches the row's Tool: bridge rows survive
// until the 6h prune after their process exits, and the OS is free to
// recycle the pid onto an unrelated binary — trusting such a row stamped
// a fresh shell's bash/tail processes with a dead session's id (observed
// live 2026-08-21). A failed validation skips the row and continues the
// climb, so a stale hit cannot mask a legitimate ancestor row. Every
// false answer counts as invalid, including /proc read errors:
// validateProcess cannot distinguish a dead pid from an unreadable one,
// and a wrong attribution is worse than none (a miss beats a wrong
// link). Where the platform cannot answer at all (non-Linux,
// platformCanValidate=false) hits are trusted unchanged — otherwise
// resolution there would degrade to a permanent miss. Validation runs
// only during this uncached walk — at most two small /proc reads per
// bridge hit, zero on the common miss path — and its verdict becomes
// part of the per-remote-addr cacheEntry like the rest of the walk's
// decision.
func (r *ProcResolver) walkAncestors(ctx context.Context, pid int) (sessionID, tool, cwd string, hitPID int, ok bool, err error) {
	seen := map[int]struct{}{}
	cur := pid
	for cur > 2 {
		if _, ok := seen[cur]; ok {
			break
		}
		seen[cur] = struct{}{}
		e, hit, lerr := r.store.Lookup(ctx, cur)
		if lerr != nil {
			return "", "", "", 0, false, lerr
		}
		if hit && (!platformCanValidate || validateProcess(r.procDir, cur, e.Tool)) {
			return e.SessionID, e.Tool, e.CWD, cur, true, nil
		}
		// No row here — or a stale one whose pid is gone or was
		// recycled onto a different binary. Either way climb past.
		ppid, perr := readPPid(filepath.Join(r.procDir, strconv.Itoa(cur), "status"))
		if perr != nil {
			return "", "", "", 0, false, nil
		}
		cur = ppid
	}
	return "", "", "", 0, false, nil
}

// readPPid extracts the PPid field from /proc/<pid>/status.
func readPPid(statusPath string) (int, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		return strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("pidbridge: no PPid line")
}
