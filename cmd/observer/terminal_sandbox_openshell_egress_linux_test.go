//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// egressFakeProc writes a fake /proc: a net/tcp table with the given lines
// and a process pid whose fd dir holds the given socket inodes.
func egressFakeProc(t *testing.T, tcp []string, pid int, inodes ...string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	// An IPv6 local address (32 hex digits) goes to net/tcp6, as the
	// kernel lists it.
	head := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	tables := map[string]string{"tcp": head, "tcp6": head}
	for i, l := range tcp {
		table := "tcp"
		if addr, _, _ := strings.Cut(l, ":"); len(addr) == 32 {
			table = "tcp6"
		}
		tables[table] += "   " + strconv.Itoa(i) + ": " + l + "\n"
	}
	for name, body := range tables {
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fd := filepath.Join(root, strconv.Itoa(pid), "fd")
	if err := os.MkdirAll(fd, 0o700); err != nil {
		t.Fatal(err)
	}
	for i, in := range inodes {
		if err := os.Symlink("socket:["+in+"]", filepath.Join(fd, strconv.Itoa(i+3))); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// egressTCPLine is one /proc/net/tcp line: local address hex, state, uid,
// inode.
func egressTCPLine(local, st string, uid int, inode string) string {
	return local + " 00000000:0000 " + st + " 00000000:00000000 00:00000000 00000000  " + strconv.Itoa(uid) + "        0 " + inode + " 1 0000000000000000 100 0 0 10 0"
}

func egressWriteMarker(t *testing.T, stateDir string, m openShellOCSFMarker) {
	t.Helper()
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(stateDir, openShellOCSFMarkerName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestOpenShellReceiverFactsAt is audit finding O3-A1 and O3-A2 at the
// kernel's socket table: one case per receiver state the table reads.
func TestOpenShellReceiverFactsAt(t *testing.T) {
	const addr = "127.0.0.1:14317"
	const pid, uid = 4242, 1000
	ours := egressTCPLine("0100007F:37ED", "0A", uid, "777")
	const v6Any = "00000000000000000000000000000000"
	cases := []struct {
		name   string
		tcp    []string
		marker *openShellOCSFMarker
		held   []string
		want   sandboxopenshell.OCSFReceiverState
	}{
		{"nothing listens", nil, nil, nil, sandboxopenshell.OCSFReceiverAbsent},
		{"another port only", []string{egressTCPLine("0100007F:1F90", "0A", uid, "1")}, nil, nil, sandboxopenshell.OCSFReceiverAbsent},
		{"an established socket on the port is not a listener", []string{egressTCPLine("0100007F:37ED", "01", uid, "2")}, nil, nil, sandboxopenshell.OCSFReceiverAbsent},
		{"another user's listener", []string{egressTCPLine("0100007F:37ED", "0A", 1001, "777")}, nil, nil, sandboxopenshell.OCSFReceiverTaken},
		{"ours but no daemon marker", []string{ours}, nil, []string{"777"}, sandboxopenshell.OCSFReceiverTaken},
		{"marker's process does not hold it", []string{ours}, &openShellOCSFMarker{V: 1, PID: pid, Addr: addr, SinkReady: true}, []string{"888"}, sandboxopenshell.OCSFReceiverTaken},
		{"a wildcard squatter beside ours", []string{ours, egressTCPLine("00000000:37ED", "0A", uid, "999")}, &openShellOCSFMarker{V: 1, PID: pid, Addr: addr, SinkReady: true}, []string{"777"}, sandboxopenshell.OCSFReceiverTaken},
		{"marker for another address", []string{ours}, &openShellOCSFMarker{V: 1, PID: pid, Addr: "127.0.0.1:1", SinkReady: true}, []string{"777"}, sandboxopenshell.OCSFReceiverTaken},
		{"relay not serving", []string{ours}, &openShellOCSFMarker{V: 1, PID: pid, Addr: addr}, []string{"777"}, sandboxopenshell.OCSFReceiverNotReady},
		{"the daemon's receiver", []string{ours}, &openShellOCSFMarker{V: 1, PID: pid, Addr: addr, SinkReady: true}, []string{"777"}, sandboxopenshell.OCSFReceiverListening},
		// Audit finding O3-V5: an IPv6 wildcard listener beside the
		// daemon's own is IPv6-only (the kernel would have refused one of
		// the two binds otherwise), so it is no squatter.
		{"the daemon's receiver beside another user's [::] listener", []string{ours, egressTCPLine(v6Any+":37ED", "0A", 1001, "555")}, &openShellOCSFMarker{V: 1, PID: pid, Addr: addr, SinkReady: true}, []string{"777"}, sandboxopenshell.OCSFReceiverListening},
		{"only another user's [::] listener", []string{egressTCPLine(v6Any+":37ED", "0A", 1001, "555")}, nil, nil, sandboxopenshell.OCSFReceiverUncertain},
		{"only a ::1 listener", []string{egressTCPLine("00000000000000000000000001000000:37ED", "0A", 1001, "556")}, nil, nil, sandboxopenshell.OCSFReceiverAbsent},
		{"another user's v4-mapped loopback listener", []string{egressTCPLine("0000000000000000FFFF00000100007F:37ED", "0A", 1001, "557")}, nil, nil, sandboxopenshell.OCSFReceiverTaken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proc := egressFakeProc(t, tc.tcp, pid, tc.held...)
			stateDir := t.TempDir()
			if tc.marker != nil {
				egressWriteMarker(t, stateDir, *tc.marker)
			}
			st, why := sandboxopenshell.ClassifyOCSFReceiver(openShellReceiverFactsAt(proc, stateDir, addr, uid))
			if st != tc.want {
				t.Fatalf("%s (%s), want %s", st, why, tc.want)
			}
		})
	}
}

// TestOpenShellReceiverMarkerLifecycle: the daemon's real receiver writes
// its marker only while it listens, says when the refusal audit is wired,
// passes the kernel check on this machine, and removes the marker at stop.
func TestOpenShellReceiverMarkerLifecycle(t *testing.T) {
	stateDir, observerDir := t.TempDir(), t.TempDir()
	t.Cleanup(func() {
		for _, src := range sandboxEgressRefusalSources {
			src(nil)
		}
		openShellStopOCSFReceiver()
	})
	for _, src := range sandboxEgressRefusalSources {
		src(nil)
	}
	if !openShellStartOCSFReceiver(stateDir, observerDir, nil) {
		t.Fatal("the receiver did not start")
	}
	m, ok := openShellReadOCSFMarker(stateDir)
	if !ok || m.PID != os.Getpid() || m.SinkReady {
		t.Fatalf("marker %+v %v, want this pid and sink not ready", m, ok)
	}
	if _, _, err := net.SplitHostPort(m.Addr); err != nil {
		t.Fatalf("marker addr %q", m.Addr)
	}
	f := openShellReceiverFactsAt("/proc", stateDir, m.Addr, os.Getuid())
	if st, why := sandboxopenshell.ClassifyOCSFReceiver(f); st != sandboxopenshell.OCSFReceiverNotReady {
		t.Fatalf("%s (%s) before the relay, want not_ready", st, why)
	}
	for _, src := range sandboxEgressRefusalSources {
		src(func(sandboxrelayd.RunRecord, sandboxrelay.EgressRefusalReport) {})
	}
	f = openShellReceiverFactsAt("/proc", stateDir, m.Addr, os.Getuid())
	if st, why := sandboxopenshell.ClassifyOCSFReceiver(f); st != sandboxopenshell.OCSFReceiverListening {
		t.Fatalf("%s (%s) with the relay wired, want listening", st, why)
	}
	openShellStopOCSFReceiver()
	if _, ok := openShellReadOCSFMarker(stateDir); ok {
		t.Fatal("the marker outlived the receiver")
	}
}
