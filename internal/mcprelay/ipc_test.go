package mcprelay_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
)

// ipcConn is a framed client over the IPC endpoint.
type ipcConn struct {
	t  *testing.T
	c  net.Conn
	fr *mcprelay.FrameReader
}

func dialIPC(t *testing.T, ep string) *ipcConn {
	t.Helper()
	c, err := mcprelay.DialIPC(context.Background(), ep, 2*time.Second)
	mustNoErr(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return &ipcConn{t: t, c: c, fr: mcprelay.NewFrameReader(c, 0)}
}

func (c *ipcConn) send(frame []byte) { mustNoErr(c.t, mcprelay.WriteFrame(c.c, frame)) }

func (c *ipcConn) recv() []byte {
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := c.fr.Next()
	mustNoErr(c.t, err)
	return f
}

func hello(secret, vserver string) []byte {
	b, _ := json.Marshal(mcprelay.IPCHello{Hello: 1, Secret: secret, VServer: vserver, CodingSessionID: "sess_ipc"})
	return b
}

func TestIPCOwnerOnlyEndpointAndBootstrap(t *testing.T) {
	if !attachsock.Supported() {
		t.Skip("no owner-only transport on this platform")
	}
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	ln, ep, err := mcprelay.ListenIPC(dbPath)
	mustNoErr(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	if runtime.GOOS != "windows" {
		// The owner-only model: connect(2) needs search permission on the
		// 0700 parent; the socket itself is 0600. Another uid is refused
		// by the kernel - not exercisable without privileges in a unit
		// test, so the enforced modes are asserted instead.
		dfi, err := os.Stat(filepath.Dir(ep))
		mustNoErr(t, err)
		if dfi.Mode().Perm() != 0o700 {
			t.Fatalf("ipc dir perm %o", dfi.Mode().Perm())
		}
		sfi, err := os.Stat(ep)
		mustNoErr(t, err)
		if sfi.Mode()&os.ModeSocket == 0 || sfi.Mode().Perm() != 0o600 {
			t.Fatalf("socket mode %v", sfi.Mode())
		}
		if !strings.Contains(ep, "/mcprelay/") || strings.HasSuffix(filepath.Dir(filepath.Dir(ep)), "attach") {
			t.Fatalf("endpoint %q must not collide with the daemon's attach socket", ep)
		}
	}
	// A second listener on the same DB is refused (live-daemon guard).
	if _, _, err := mcprelay.ListenIPC(dbPath); !errors.Is(err, attachsock.ErrSocketLiveDaemon) {
		t.Fatalf("second listener: %v", err)
	}

	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	front.deny["rm"] = true
	store := newMemStore()
	r, _ := newRelay(t, sts, front, store, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	secrets := mcprelay.StaticSecrets{"boot-claude": {Agent: "agent:claude-code", Product: "claude-code", VServers: []string{"gh"}}}
	done := make(chan error, 1)
	go func() { done <- r.ServeIPC(ctx, ln, secrets) }()

	// Bad secret -> refused, nothing forwarded.
	c := dialIPC(t, ep)
	c.send(hello("wrong", "gh"))
	m, _ := mcprelay.ParseMessage(c.recv())
	if m.Error == nil || m.Error.Code != mcprelay.CodeForbidden {
		t.Fatalf("bad secret answer %+v", m)
	}
	// Wrong vserver for this secret -> refused.
	c = dialIPC(t, ep)
	c.send(hello("boot-claude", "other"))
	m, _ = mcprelay.ParseMessage(c.recv())
	if m.Error == nil || m.Error.Code != mcprelay.CodeForbidden {
		t.Fatalf("vserver restriction %+v", m)
	}
	// No hello at all -> refused.
	c = dialIPC(t, ep)
	c.send(toolCall(1, "x"))
	m, _ = mcprelay.ParseMessage(c.recv())
	if m.Error == nil || m.Error.Code != mcprelay.CodeInvalidRequest {
		t.Fatalf("hello-less stream %+v", m)
	}

	// Good secret: the stream carries JSON-RPC at ipc_bound.
	c = dialIPC(t, ep)
	c.send(hello("boot-claude", "gh"))
	if ok := c.recv(); !strings.Contains(string(ok), "sbo_hello_ok") {
		t.Fatalf("hello ack %s", ok)
	}
	c.send(toolCall(1, "search"))
	reply, err := mcprelay.ParseMessage(c.recv())
	mustNoErr(t, err)
	if reply.Result == nil || string(reply.ID) != "1" {
		t.Fatalf("reply %+v", reply)
	}
	if act := sts.lastActor(); act["sbo_client_attestation"] != "ipc_bound" || act["sbo_agent"] != "agent:claude-code" {
		t.Fatalf("actor %v", act)
	}
	if fr := front.requests()[0]; fr.Corr == nil || fr.Corr.CodingSessionID != "sess_ipc" {
		t.Fatalf("corr %+v", fr.Corr)
	}
	c.send(toolCall(2, "rm"))
	reply, _ = mcprelay.ParseMessage(c.recv())
	if reply.Error == nil || reply.Error.Code != mcprelay.CodeForbidden || string(reply.ID) != "2" {
		t.Fatalf("deny %+v", reply)
	}
	// A notification is forwarded (202) and yields no frame; the next
	// request still answers in order.
	c.send([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	c.send(toolCall(3, "search"))
	reply, _ = mcprelay.ParseMessage(c.recv())
	if string(reply.ID) != "3" {
		t.Fatalf("after notification: %+v", reply)
	}
	if rows := store.snapshot(); rows[0].ClientAttestation != "ipc_bound" {
		t.Fatalf("record attestation %q", rows[0].ClientAttestation)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
