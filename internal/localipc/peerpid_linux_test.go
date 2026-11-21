//go:build linux

package localipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestPeerPIDUnixSocket pins SO_PEERCRED: a connection this process made
// reports this process's pid on the accepted end.
func TestPeerPIDUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			done <- nil
			return
		}
		done <- c
	}()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	server := <-done
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()
	pid, ok := PeerPID(server)
	if !ok || pid != os.Getpid() {
		t.Fatalf("PeerPID = %d, %v; want %d", pid, ok, os.Getpid())
	}
	if _, ok := PeerPID(nil); ok {
		t.Fatal("PeerPID(nil) reported a pid")
	}
}
