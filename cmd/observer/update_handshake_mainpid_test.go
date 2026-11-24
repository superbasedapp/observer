//go:build linux && !sbo_omit_org_update

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// update_handshake_mainpid_test.go pins INFRA-01's handover half with a real
// child and a real datagram socket standing in for systemd's notify socket:
// once the child passes its self-check, the old daemon (the unit's main
// process) names the child the unit's new main PID, so systemd does not stop
// the unit when the old daemon exits 0. The drill in the lane report runs the
// same exchange against a real systemd 245, 249 and 255.

// listenFakeNotifySocket binds a unixgram socket like systemd's and points
// NOTIFY_SOCKET at it.
func listenFakeNotifySocket(t *testing.T) *net.UnixConn {
	t.Helper()
	// A short path: sun_path is 108 bytes and t.TempDir can exceed it.
	dir, err := os.MkdirTemp("", "ntfy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	return conn
}

// readNotify returns the next datagram, or "" when none arrives in d.
func readNotify(t *testing.T, conn *net.UnixConn, d time.Duration) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 512)
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

// withUnitCgroup makes /proc/self/cgroup read as cg for the test.
func withUnitCgroup(t *testing.T, cg string) {
	t.Helper()
	saved := handoverCgroup
	handoverCgroup = func() (string, error) { return cg, nil }
	t.Cleanup(func() { handoverCgroup = saved })
}

func TestHandshakeHandsTheMainPIDToTheSupervisor(t *testing.T) {
	conn := listenFakeNotifySocket(t)
	withUnitCgroup(t, "0::/user.slice/user-1000.slice/user@1000.service/app.slice/observer.service\n")
	dir := t.TempDir()
	bin := writeFakeBinary(t, dir, "child-ready", `echo "ready $OBSERVER_UPDATE_HANDSHAKE" >&3
exec sleep 2`)

	res, err := superviseNewBinary(context.Background(), bin, nil, dir, 5*time.Second, nil)
	if err != nil || !res.Ready {
		t.Fatalf("superviseNewBinary: %+v, %v", res, err)
	}
	want := "MAINPID=" + strconv.Itoa(res.ChildPID) + "\n"
	if got := readNotify(t, conn, 2*time.Second); got != want {
		t.Fatalf("supervisor heard %q, want %q", got, want)
	}
}

// TestHandshakeNamesNoMainPIDWithoutAHandover: a failed self-check keeps the
// old daemon the unit's main process (it exits 1 and the unit restarts the
// restored binary), and a daemon outside this product's unit never writes to
// a notify socket it merely inherited.
func TestHandshakeNamesNoMainPIDWithoutAHandover(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cgroup string
		script string
	}{
		{"failed self-check", "0::/system.slice/observer.service\n", `echo "fail listener bind refused" >&3` + "\n" + `exit 1`},
		{"another unit's notify socket", "0::/system.slice/tmux.service\n", `echo "ready $OBSERVER_UPDATE_HANDSHAKE" >&3` + "\n" + `exec sleep 2`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := listenFakeNotifySocket(t)
			withUnitCgroup(t, tc.cgroup)
			dir := t.TempDir()
			bin := writeFakeBinary(t, dir, "child", tc.script)
			_, _ = superviseNewBinary(context.Background(), bin, nil, dir, 5*time.Second, nil)
			if got := readNotify(t, conn, 300*time.Millisecond); got != "" {
				t.Fatalf("supervisor heard %q, want nothing", got)
			}
		})
	}
}
