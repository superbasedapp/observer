//go:build linux

package peerproc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestFindOnARealLoopbackConnection: the client end of a real loopback
// connection is found in /proc, with its parent as the nearest ancestor.
func TestFindOnARealLoopbackConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	srv := <-accepted
	defer func() { _ = srv.Close() }()
	client := netip.MustParseAddrPort(srv.RemoteAddr().String())
	server := netip.MustParseAddrPort(srv.LocalAddr().String())
	p, err := Find(context.Background(), client, server, nil)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if p.PID != os.Getpid() {
		t.Fatalf("pid %d, want this process %d", p.PID, os.Getpid())
	}
	if len(p.Ancestors) == 0 || p.Ancestors[0] != os.Getppid() {
		t.Fatalf("ancestors %v, want the parent %d first", p.Ancestors, os.Getppid())
	}
	// A connection that does not exist is not found.
	if _, err := Find(context.Background(), netip.MustParseAddrPort("127.0.0.1:1"), server, nil); err == nil {
		t.Fatal("found a connection that does not exist")
	}
}

// TestStartToken: stable for one process, absent for a pid that is gone.
func TestStartToken(t *testing.T) {
	a, ok := StartToken(os.Getpid())
	b, ok2 := StartToken(os.Getpid())
	if !ok || !ok2 || a == "" || a != b {
		t.Fatalf("tokens %q %q (%v %v)", a, b, ok, ok2)
	}
	if _, ok := StartToken(1 << 30); ok {
		t.Fatal("a pid that cannot exist has a token")
	}
}

// TestStartTokenOfAZombie: a process that exited but is not reaped yet
// keeps its /proc stat and start time; it has no token, so a caller that
// exited reads as gone however long its parent puts off reaping it (the
// attach confirm of a child whose opener exited read the unreaped opener
// as present).
func TestStartTokenOfAZombie(t *testing.T) {
	child := exec.Command(os.Args[0], "-test.run=^$")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	// Not waited for until the end: the child stays a zombie.
	defer func() { _ = child.Wait() }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		st, ok := statOf(pid)
		if !ok {
			t.Fatalf("the unreaped child %d has no stat", pid)
		}
		if st.State == 'Z' {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the child %d did not exit (state %c)", pid, st.State)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if tok, ok := StartToken(pid); ok {
		t.Fatalf("an exited, unreaped process has a start token %q", tok)
	}
}

// fakeProc builds a /proc fixture: the daemon's TCP table holds the
// client socket 127.0.0.1:40000 -> 127.0.0.1:8081 with inode 555, and each
// process has a stat with its parent and an fd directory (nil links) or,
// when unreadable, an fd FILE, which os.ReadDir refuses as an unreadable
// fd directory would (the test may run as root, which reads every one).
type fakeProcess struct {
	ppid       int
	links      []string
	unreadable bool
}

func fakeProc(t *testing.T, procs map[int]fakeProcess) {
	t.Helper()
	root := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "self", "net", "tcp"),
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 0100007F:9C40 0100007F:1F91 01 00000000:00000000 00:00000000 00000000  1000        0 555 1 0 20 4 30 10 -1\n")
	for pid, p := range procs {
		dir := filepath.Join(root, strconv.Itoa(pid))
		write(filepath.Join(dir, "stat"), fmt.Sprintf("%d (p) S %d%s 4242", pid, p.ppid, strings.Repeat(" 0", 17)))
		if p.unreadable {
			write(filepath.Join(dir, "fd"), "")
			continue
		}
		if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		for i, l := range p.links {
			if err := os.Symlink(l, filepath.Join(dir, "fd", strconv.Itoa(i))); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

// TestFindFallsBackToTheBoxDescendants (fixes-1, H2): when no readable
// process holds the socket (the WSL2 /init relay of a Windows browser is
// root's), the box roots' descendants decide: all readable and none
// holding it proves the holder outside every box; one unreadable fails
// closed; a descendant holding it is found.
func TestFindFallsBackToTheBoxDescendants(t *testing.T) {
	client := netip.MustParseAddrPort("127.0.0.1:40000")
	server := netip.MustParseAddrPort("127.0.0.1:8081")
	sock := "socket:[555]"
	base := func() map[int]fakeProcess {
		return map[int]fakeProcess{
			1:   {ppid: 0},
			50:  {ppid: 1, unreadable: true}, // the relay, another user's
			100: {ppid: 1},                   // the box root (the host helper)
			101: {ppid: 100, links: []string{"socket:[9]", "/dev/null"}},
			102: {ppid: 101},
		}
	}
	roots := map[int]string{100: "run-box"}
	cases := []struct {
		name    string
		mutate  func(m map[int]fakeProcess)
		roots   map[int]string
		wantErr error
		wantPID int
		outside bool
	}{
		{"holder found outside a box", func(m map[int]fakeProcess) { m[60] = fakeProcess{ppid: 1, links: []string{sock}} }, roots, nil, 60, false},
		{"holder found inside a box", func(m map[int]fakeProcess) { m[102] = fakeProcess{ppid: 101, links: []string{sock}} }, roots, nil, 102, false},
		{"no holder, every box descendant readable", func(map[int]fakeProcess) {}, roots, nil, 0, true},
		{"no holder, one box descendant unreadable", func(m map[int]fakeProcess) { m[102] = fakeProcess{ppid: 101, unreadable: true} }, roots, ErrBoxUnreadable, 0, false},
		{"no holder and no box root", func(map[int]fakeProcess) {}, nil, ErrNotFound, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.mutate(m)
			fakeProc(t, m)
			p, err := Find(context.Background(), client, server, tc.roots)
			if !errors.Is(err, tc.wantErr) || p.PID != tc.wantPID || p.Outside != tc.outside {
				t.Fatalf("Find = %+v, %v; want pid %d outside %v err %v", p, err, tc.wantPID, tc.outside, tc.wantErr)
			}
			// The socket's owner from the TCP table rides along, so the
			// caller check can tell another uid's socket (fixes-2, N1).
			if p.SocketUID != 1000 {
				t.Fatalf("SocketUID %d, want the table's 1000", p.SocketUID)
			}
		})
	}
}

// TestAncestorsOfThisProcess pins the exported walk (lane cli-2): this
// process's parent is its first ancestor, and an unknown pid has none.
func TestAncestorsOfThisProcess(t *testing.T) {
	got := Ancestors(os.Getpid())
	if len(got) == 0 || got[0] != os.Getppid() {
		t.Fatalf("Ancestors(self) = %v, want first %d", got, os.Getppid())
	}
	if a := Ancestors(0); a != nil {
		t.Fatalf("Ancestors(0) = %v", a)
	}
}

// TestEnvMarkerOfThisProcess reads a marker from this process's own
// environment, and finds none for a key it does not carry.
func TestEnvMarkerOfThisProcess(t *testing.T) {
	// /proc/self/environ is the environment at exec, so the key must be
	// one the test binary started with: PATH is always there.
	if v, ok := EnvMarker([]int{os.Getpid()}, []string{"PATH"}); !ok || v == "" {
		t.Fatalf("EnvMarker(self, PATH) = %q %v", v, ok)
	}
	if _, ok := EnvMarker([]int{os.Getpid()}, []string{"OBSERVER_NO_SUCH_MARKER_KEY"}); ok {
		t.Fatal("a key the process does not carry was found")
	}
	if _, ok := EnvMarker([]int{os.Getpid()}, nil); ok {
		t.Fatal("no keys found a value")
	}
}
