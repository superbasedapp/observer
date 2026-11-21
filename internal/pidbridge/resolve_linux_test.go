//go:build linux

package pidbridge

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestParseHexAddrPort(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want netip.AddrPort
	}{
		// 127.0.0.1 = 0x7F000001 → host-order 0100007F, port 8820 = 0x2274
		{"ipv4 loopback", "0100007F:2274", netip.MustParseAddrPort("127.0.0.1:8820")},
		{"ipv4 another port", "0100007F:D431", netip.MustParseAddrPort("127.0.0.1:54321")},
		// ::1 = 16 zero bytes then 1. Per-word-swap: the last 4 bytes become
		// 01000000 after swap, so that group encodes as "01000000". The
		// preceding 12 bytes are all-zero.
		{"ipv6 loopback", "00000000000000000000000001000000:2274", netip.MustParseAddrPort("[::1]:8820")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseHexAddrPort(tc.in)
			if err != nil {
				t.Fatalf("parseHexAddrPort(%q): %v", tc.in, err)
			}
			if got.Port() != tc.want.Port() {
				t.Errorf("port: got %d want %d", got.Port(), tc.want.Port())
			}
			if got.Addr().Unmap() != tc.want.Addr().Unmap() {
				t.Errorf("addr: got %s want %s", got.Addr(), tc.want.Addr())
			}
		})
	}
}

// writeProcSocket constructs a fake /proc layout where a socket with
// inode `inode` is owned by pid `pid`. Returns the faked procDir.
func writeProcSocket(t *testing.T, pid int, inode uint64, localHexAddr, remoteHexAddr string, ppid int) string {
	t.Helper()
	procDir := t.TempDir()

	// /proc/net/tcp with our entry.
	netDir := filepath.Join(procDir, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatalf("mkdir net: %v", err)
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	entry := fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 100 0 0 10 0\n",
		localHexAddr, remoteHexAddr, inode)
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(header+entry), 0o644); err != nil {
		t.Fatalf("write net/tcp: %v", err)
	}
	// Empty tcp6 so findSocketInode sees it exists but has no match.
	if err := os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(header), 0o644); err != nil {
		t.Fatalf("write net/tcp6: %v", err)
	}

	// /proc/<pid>/fd/3 → socket:[<inode>]
	pidDir := filepath.Join(procDir, strconv.Itoa(pid))
	fdDir := filepath.Join(pidDir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatalf("mkdir fd: %v", err)
	}
	if err := os.Symlink(fmt.Sprintf("socket:[%d]", inode), filepath.Join(fdDir, "3")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// /proc/<pid>/status with PPid
	status := fmt.Sprintf("Name:\ttest\nPPid:\t%d\n", ppid)
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}

	// Ancestor pid with its own status pointing at init (1).
	if ppid > 1 {
		ppidDir := filepath.Join(procDir, strconv.Itoa(ppid))
		if err := os.MkdirAll(ppidDir, 0o755); err != nil {
			t.Fatalf("mkdir ppid: %v", err)
		}
		pstatus := "Name:\tancestor\nPPid:\t1\n"
		if err := os.WriteFile(filepath.Join(ppidDir, "status"), []byte(pstatus), 0o644); err != nil {
			t.Fatalf("write ppid status: %v", err)
		}
	}
	return procDir
}

func TestProcResolver_Resolve_DirectPIDHit(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)

	// Pid 4242 registered as owner of session "sess-x".
	if err := st.Write(ctx, Entry{PID: 4242, SessionID: "sess-x", Tool: "claude-code"}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Fake /proc: pid 4242 owns inode 12345, whose local_address is
	// 127.0.0.1:54321 (hex "0100007F:D431"), rem_address is
	// 127.0.0.1:8820 (hex "0100007F:2274").
	procDir := writeProcSocket(t, 4242, 12345, "0100007F:D431", "0100007F:2274", 1)
	// Live process matching the row's Tool — required now that hits
	// are validated before being trusted.
	writeProc(t, procDir, 4242, "node", "node\x00/usr/local/bin/claude-code\x00")

	r := NewProcResolver(st, procDir, time.Minute)
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:54321")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ok {
		t.Fatal("Resolve: miss, want hit")
	}
	if sid != "sess-x" {
		t.Fatalf("session: got %q want %q", sid, "sess-x")
	}
}

func TestProcResolver_Resolve_AncestorWalk(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)

	// Ancestor pid 100 registered; descendant pid 200 owns the socket.
	if err := st.Write(ctx, Entry{PID: 100, SessionID: "ancestor-sess", Tool: "claude-code"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	procDir := writeProcSocket(t, 200, 55555, "0100007F:1F40", "0100007F:2274", 100)
	writeProc(t, procDir, 100, "node", "node\x00/opt/claude-code/cli.js\x00")

	r := NewProcResolver(st, procDir, time.Minute)
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:8000")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ok || sid != "ancestor-sess" {
		t.Fatalf("Resolve: sid=%q ok=%v", sid, ok)
	}
}

func TestProcResolver_Resolve_Miss(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	procDir := writeProcSocket(t, 777, 98765, "0100007F:D431", "0100007F:2274", 1)

	r := NewProcResolver(st, procDir, time.Minute)
	// No bridge entry for pid 777 → clean miss.
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:54321")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ok {
		t.Fatalf("Resolve: unexpected hit sid=%q", sid)
	}
}

func TestProcResolver_Resolve_NoMatchingSocket(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	// /proc layout with a different port than the one we query.
	procDir := writeProcSocket(t, 777, 98765, "0100007F:1F40", "0100007F:2274", 1)

	r := NewProcResolver(st, procDir, time.Minute)
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:54321")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ok || sid != "" {
		t.Fatalf("Resolve: want miss, got %q ok=%v", sid, ok)
	}
}

func TestProcResolver_CacheHit(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if err := st.Write(ctx, Entry{PID: 500, SessionID: "cached", Tool: "claude-code"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	procDir := writeProcSocket(t, 500, 7777, "0100007F:1F40", "0100007F:2274", 1)
	writeProc(t, procDir, 500, "node", "node\x00/usr/local/bin/claude-code\x00")

	r := NewProcResolver(st, procDir, time.Minute)
	if _, _, err := r.Resolve(ctx, "127.0.0.1:8000"); err != nil {
		t.Fatalf("Resolve 1: %v", err)
	}
	// Break the /proc layout; a cached resolve should still succeed.
	if err := os.WriteFile(filepath.Join(procDir, "net", "tcp"), []byte(""), 0o644); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:8000")
	if err != nil {
		t.Fatalf("Resolve 2: %v", err)
	}
	if !ok || sid != "cached" {
		t.Fatalf("cache miss: sid=%q ok=%v", sid, ok)
	}
}

func TestProcResolver_EmptyAddr(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	r := NewProcResolver(st, t.TempDir(), time.Minute)
	sid, ok, err := r.Resolve(ctx, "")
	if sid != "" || ok || err != nil {
		t.Fatalf("empty addr: sid=%q ok=%v err=%v", sid, ok, err)
	}
}

// TestProcResolver_PoisonedInitEntryIgnored pins the D17 guard: a
// bridge entry registered at pid 2 (WSL distro init — wsl.exe-bridged
// hooks used to write these) must never resolve. The ancestor walk
// stops before system pids even when the poisoned row exists.
func TestProcResolver_PoisonedInitEntryIgnored(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if err := st.Write(ctx, Entry{PID: 2, SessionID: "poison", Tool: "claude-code", CWD: `D:\somewhere`}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Socket owner 600 chains to init: 600 -> 2 (-> 1).
	procDir := writeProcSocket(t, 600, 31337, "0100007F:1F40", "0100007F:2274", 2)

	r := NewProcResolver(st, procDir, time.Minute)
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:8000")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ok || sid != "" {
		t.Fatalf("poisoned init entry resolved: sid=%q ok=%v", sid, ok)
	}
	tool, ok, err := r.ResolveTool(ctx, "127.0.0.1:8000")
	if err != nil || ok || tool != "" {
		t.Fatalf("poisoned tool resolved: tool=%q ok=%v err=%v", tool, ok, err)
	}
}

// TestProcResolver_ResolveCWD_ProcFallback pins the hookless-tool R3
// path: on a clean bridge miss the resolver reports the socket-owning
// process's own /proc/<pid>/cwd so per-project overrides work for
// clients with no SessionStart hook (codex exec). Session and tool
// stay unresolved.
func TestProcResolver_ResolveCWD_ProcFallback(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	procDir := writeProcSocket(t, 700, 42424, "0100007F:1F40", "0100007F:2274", 1)
	wsDir := t.TempDir()
	if err := os.Symlink(wsDir, filepath.Join(procDir, "700", "cwd")); err != nil {
		t.Fatalf("symlink cwd: %v", err)
	}

	r := NewProcResolver(st, procDir, time.Minute)
	cwd, ok, err := r.ResolveCWD(ctx, "127.0.0.1:8000")
	if err != nil {
		t.Fatalf("ResolveCWD: %v", err)
	}
	if !ok || cwd != wsDir {
		t.Fatalf("cwd fallback: got %q ok=%v want %q true", cwd, ok, wsDir)
	}
	// Session and tool remain clean misses for the same (cached) walk.
	if sid, ok, _ := r.Resolve(ctx, "127.0.0.1:8000"); ok || sid != "" {
		t.Fatalf("session resolved from cwd fallback: %q ok=%v", sid, ok)
	}
	if tool, ok, _ := r.ResolveTool(ctx, "127.0.0.1:8000"); ok || tool != "" {
		t.Fatalf("tool resolved from cwd fallback: %q ok=%v", tool, ok)
	}
}

// TestProcResolver_ResolveCWD_BridgeEntryWins pins precedence: when
// the ancestor walk hits a hook-fed bridge entry, its CWD wins over
// the /proc fallback (the hook payload's cwd is the session's true
// project directory; the socket owner may be a subprocess elsewhere).
func TestProcResolver_ResolveCWD_BridgeEntryWins(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if err := st.Write(ctx, Entry{PID: 800, SessionID: "s", Tool: "claude-code", CWD: "/repo/project"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	procDir := writeProcSocket(t, 800, 53535, "0100007F:1F40", "0100007F:2274", 1)
	writeProc(t, procDir, 800, "node", "node\x00/usr/local/bin/claude-code\x00")
	if err := os.Symlink(t.TempDir(), filepath.Join(procDir, "800", "cwd")); err != nil {
		t.Fatalf("symlink cwd: %v", err)
	}

	r := NewProcResolver(st, procDir, time.Minute)
	cwd, ok, err := r.ResolveCWD(ctx, "127.0.0.1:8000")
	if err != nil || !ok || cwd != "/repo/project" {
		t.Fatalf("bridge cwd should win: got %q ok=%v err=%v", cwd, ok, err)
	}
}

// TestProcResolver_ResolveTool reports the bridge entry's Tool for
// the same connection Resolve maps to a session — the R2 input for
// per-tool compression profile assignment. Shares Resolve's cache:
// the second call must not re-walk /proc (verified by deleting the
// fixture before it).
func TestProcResolver_ResolveTool(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if err := st.Write(ctx, Entry{PID: 4242, SessionID: "sess-x", Tool: "kilo-code-cli"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	procDir := writeProcSocket(t, 4242, 12345, "0100007F:D431", "0100007F:2274", 1)
	writeProc(t, procDir, 4242, "node", "node\x00/usr/local/bin/kilo-code-cli/cli.js\x00")

	r := NewProcResolver(st, procDir, time.Minute)
	tool, ok, err := r.ResolveTool(ctx, "127.0.0.1:54321")
	if err != nil {
		t.Fatalf("ResolveTool: %v", err)
	}
	if !ok || tool != "kilo-code-cli" {
		t.Fatalf("tool: got %q ok=%v, want kilo-code-cli true", tool, ok)
	}

	// Cached: removing the fake /proc must not break the second call
	// (one walk fills both Resolve and ResolveTool).
	if err := os.RemoveAll(procDir); err != nil {
		t.Fatal(err)
	}
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:54321")
	if err != nil || !ok || sid != "sess-x" {
		t.Fatalf("cached Resolve after ResolveTool: sid=%q ok=%v err=%v", sid, ok, err)
	}

	// A miss reports cleanly.
	tool, ok, err = r.ResolveTool(ctx, "127.0.0.1:1")
	if err != nil || ok || tool != "" {
		t.Fatalf("miss: got %q ok=%v err=%v, want clean miss", tool, ok, err)
	}
}

// TestProcResolver_StaleRow_IdentityMismatchRejected reproduces the
// live 2026-08-21 defect: a bridge row survives until the 6h prune
// after its process exits, the OS recycles the pid onto an unrelated
// binary, and the ancestor walk of a fresh shell's connection stamps
// that shell with the dead session's id. The resolver must refuse the
// hit — the pid is alive but its comm/cmdline no longer matches the
// row's Tool — and report a clean miss.
func TestProcResolver_StaleRow_IdentityMismatchRejected(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	// Stale row: pid 200 used to be the claude-code process behind
	// "sess-dead"; that pid now runs tail.
	if err := st.Write(ctx, Entry{PID: 200, SessionID: "sess-dead", Tool: "claude-code"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Socket owner 300 is an unrelated bash whose parent chain reaches
	// the recycled pid.
	procDir := writeProcSocket(t, 300, 60606, "0100007F:1F40", "0100007F:2274", 200)
	writeProc(t, procDir, 300, "bash", "bash\x00")
	writeProc(t, procDir, 200, "tail", "tail\x00-f\x00app.log\x00")

	r := NewProcResolver(st, procDir, time.Minute)
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:8000")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ok || sid != "" {
		t.Fatalf("stale row attributed: sid=%q ok=%v, want clean miss", sid, ok)
	}
}

// TestProcResolver_StaleRow_WalkContinuesToLiveAncestor pins that a
// rejected stale hit does not mask a legitimate row higher in the
// ancestor chain: the walk skips the mismatching pid and resolves via
// the live, identity-matching grandparent instead.
func TestProcResolver_StaleRow_WalkContinuesToLiveAncestor(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if err := st.Write(ctx, Entry{PID: 200, SessionID: "sess-stale", Tool: "claude-code"}); err != nil {
		t.Fatalf("Write stale: %v", err)
	}
	if err := st.Write(ctx, Entry{PID: 100, SessionID: "sess-live", Tool: "claude-code"}); err != nil {
		t.Fatalf("Write live: %v", err)
	}
	procDir := writeProcSocket(t, 300, 70707, "0100007F:1F40", "0100007F:2274", 200)
	writeProc(t, procDir, 300, "bash", "bash\x00")
	writeProc(t, procDir, 200, "tail", "tail\x00-f\x00app.log\x00")
	// Re-chain the middle pid under the valid ancestor (the generic
	// fixture wires every ancestor straight to init).
	if err := os.WriteFile(filepath.Join(procDir, "200", "status"), []byte("Name:\ttail\nPPid:\t100\n"), 0o644); err != nil {
		t.Fatalf("rewrite status: %v", err)
	}
	writeProc(t, procDir, 100, "node", "node\x00/usr/local/bin/claude-code\x00")

	r := NewProcResolver(st, procDir, time.Minute)
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:8000")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ok || sid != "sess-live" {
		t.Fatalf("Resolve: sid=%q ok=%v, want sess-live true", sid, ok)
	}
}

// TestProcResolver_StaleRow_DeadPIDRejected covers the vanished-pid
// half of validation: the bridge row's pid has no /proc entry at all,
// so validateProcess finds no comm, rejects the hit, and the result is
// a clean miss — never attribution to the dead session.
func TestProcResolver_StaleRow_DeadPIDRejected(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	if err := st.Write(ctx, Entry{PID: 250, SessionID: "sess-dead", Tool: "claude-code"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Socket owner 300 chains to the dead pid...
	procDir := writeProcSocket(t, 300, 80808, "0100007F:1F40", "0100007F:2274", 250)
	writeProc(t, procDir, 300, "bash", "bash\x00")
	// ...whose process table entry is gone entirely (fixture wrote a
	// placeholder status for it; delete the whole dir).
	if err := os.RemoveAll(filepath.Join(procDir, "250")); err != nil {
		t.Fatalf("remove dead pid dir: %v", err)
	}

	r := NewProcResolver(st, procDir, time.Minute)
	sid, ok, err := r.Resolve(ctx, "127.0.0.1:8000")
	if err != nil || ok || sid != "" {
		t.Fatalf("dead pid attributed: sid=%q ok=%v err=%v, want clean miss", sid, ok, err)
	}
}

// TestProcResolver_ResolveOwnTool (P-228 fix round 2, N2): the bridge
// reports a tool as the connection's OWN process only when the socket
// owner itself is that tool's binary. A script the developer starts from
// the tool's shell still resolves the tool's session through the ancestor
// walk (Resolve / ResolveTool unchanged), but ResolveOwnTool misses, so the
// proxy lets that child's own-agent header claim its turns.
func TestProcResolver_ResolveOwnTool(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name       string
		ownerComm  string
		ownerArgv  string
		ownerExe   string
		ancestor   bool // the bridge row is on pid 100, the socket owner is pid 200
		wantOwn    bool
		wantShared bool // ResolveTool still names the tool
	}{
		// Claude Code's Node CLI sets process.title, so comm is "claude".
		{"the tool's own process", "claude", "node\x00/opt/claude-code/cli.js\x00", "", false, true, true},
		{"the tool's own worker under its main process", "claude", "node\x00/opt/claude-code/cli.js\x00--worker\x00", "", true, true, true},
		{"a native tool binary by its exe", "claude", "/home/u/.local/bin/claude\x00", "/home/u/.local/share/claude/versions/2.1.0/claude", true, true, true},
		// fixes-1 N1: a row registered for the socket owner's exact pid (a
		// hook, adapter or terminal seed named it) is the tool's own
		// process whatever its argv looks like.
		{"a registered pid with a generic node argv", "node", "node\x00--max-old-space-size=8192\x00/opt/claude-code/cli.js\x00", "/usr/bin/node", false, true, true},
		{"a child script under the tool", "python3", "python3\x00/home/u/agent.py\x00", "/usr/bin/python3.12", true, false, true},
		// sdk-1f L4: a child whose path or arguments merely mention the
		// tool id is not the tool (the old substring check said it was).
		{"a child script whose path names the tool", "python3", "python3\x00/home/u/claude-code/agent.py\x00--as\x00claude-code\x00", "/usr/bin/python3.12", true, false, true},
		{"a node script in a folder named for the tool", "node", "node\x00/home/u/claude-code-tools/run.js\x00", "/usr/bin/node", true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			rowPID, ownerPID, ppid := 200, 200, 1
			if tc.ancestor {
				rowPID, ppid = 100, 100
			}
			if err := st.Write(ctx, Entry{PID: rowPID, SessionID: "cc-sess", Tool: "claude-code"}); err != nil {
				t.Fatalf("Write: %v", err)
			}
			procDir := writeProcSocket(t, ownerPID, 777, "0100007F:1F40", "0100007F:2274", ppid)
			writeProc(t, procDir, ownerPID, tc.ownerComm, tc.ownerArgv)
			if tc.ownerExe != "" {
				if err := os.Symlink(tc.ownerExe, filepath.Join(procDir, strconv.Itoa(ownerPID), "exe")); err != nil {
					t.Fatal(err)
				}
			}
			if tc.ancestor {
				writeProc(t, procDir, 100, "claude", "node\x00/opt/claude-code/cli.js\x00")
			}
			r := NewProcResolver(st, procDir, time.Minute)
			r.SetToolBinaries(func(tool string) []string {
				if tool == "claude-code" {
					return []string{"claude"}
				}
				return nil
			})
			tool, ok, err := r.ResolveTool(ctx, "127.0.0.1:8000")
			if err != nil || ok != tc.wantShared || (ok && tool != "claude-code") {
				t.Fatalf("ResolveTool = %q %v %v, want claude-code %v", tool, ok, err, tc.wantShared)
			}
			own, ok, err := r.ResolveOwnTool(ctx, "127.0.0.1:8000")
			if err != nil || ok != tc.wantOwn {
				t.Fatalf("ResolveOwnTool = %q %v %v, want own=%v", own, ok, err, tc.wantOwn)
			}
		})
	}
}
