//go:build linux

package inspectionbroker

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intervention"
)

func TestClientServerReturnsStableIdentityAndReauthorizes(t *testing.T) {
	identity := testIdentity(os.Getuid())
	var authorized atomic.Int32
	server := testServer(identity.UID, func(_ context.Context, peer Peer) error {
		if peer.PID != os.Getpid() || peer.UID != os.Getuid() || peer.GID != os.Getgid() {
			return ErrUnauthorized
		}
		authorized.Add(1)
		return nil
	}, func(_ context.Context, pid int) (intervention.Identity, error) {
		if pid != identity.PID {
			t.Fatalf("Inspect pid = %d, want %d", pid, identity.PID)
		}
		return identity, nil
	})
	client, stop := startTestBroker(t, server)
	defer stop()

	got, err := client.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got != identity {
		t.Fatalf("Inspect identity = %+v, want %+v", got, identity)
	}
	if got := authorized.Load(); got != 2 {
		t.Fatalf("AuthorizePeer calls = %d, want 2", got)
	}
}

func TestServerRejectsSpoofedPeerUIDBeforeInspection(t *testing.T) {
	actualUID := os.Getuid()
	identity := testIdentity(actualUID + 1)
	var authorizeCalled atomic.Bool
	var inspectCalled atomic.Bool
	server := testServer(identity.UID, func(context.Context, Peer) error {
		authorizeCalled.Store(true)
		return nil
	}, func(context.Context, int) (intervention.Identity, error) {
		inspectCalled.Store(true)
		return identity, nil
	})
	path, listener := newTestListener(t)
	defer listener.Close()
	done := serveTestServer(t, server, listener)

	response := rawRequest(t, path, validTestRequest(identity))
	if response.Error != codeUnauthorized || response.Identity != nil {
		t.Fatalf("response = %+v, want unauthorized", response)
	}
	if authorizeCalled.Load() || inspectCalled.Load() {
		t.Fatalf("unauthorized UID reached callbacks: authorize=%v inspect=%v", authorizeCalled.Load(), inspectCalled.Load())
	}
	stopTestServer(t, listener, done)
}

func TestServerRejectsSameUIDPeerWithoutControllerAuthorization(t *testing.T) {
	identity := testIdentity(os.Getuid())
	var inspectCalled atomic.Bool
	server := testServer(identity.UID, func(context.Context, Peer) error {
		return errors.New("fixture controller mismatch")
	}, func(context.Context, int) (intervention.Identity, error) {
		inspectCalled.Store(true)
		return identity, nil
	})
	client, stop := startTestBroker(t, server)
	defer stop()

	if _, err := client.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Inspect error = %v, want ErrUnauthorized", err)
	}
	if inspectCalled.Load() {
		t.Fatal("same-UID unauthorized peer reached Inspect")
	}
}

func TestServerRejectsTargetPIDReuseAndUIDMismatch(t *testing.T) {
	tests := []struct {
		name    string
		inspect func(intervention.Identity) func(context.Context, int) (intervention.Identity, error)
	}{
		{
			name: "PID reuse between reads",
			inspect: func(identity intervention.Identity) func(context.Context, int) (intervention.Identity, error) {
				var calls atomic.Int32
				return func(context.Context, int) (intervention.Identity, error) {
					if calls.Add(1) == 2 {
						identity.StartTicks++
					}
					return identity, nil
				}
			},
		},
		{
			name: "UID mismatch",
			inspect: func(identity intervention.Identity) func(context.Context, int) (intervention.Identity, error) {
				identity.UID++
				return func(context.Context, int) (intervention.Identity, error) { return identity, nil }
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := testIdentity(os.Getuid())
			server := testServer(identity.UID, allowPeer, test.inspect(identity))
			client, stop := startTestBroker(t, server)
			defer stop()

			if _, err := client.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID); !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf("Inspect error = %v, want ErrIdentityMismatch", err)
			}
		})
	}
}

func TestServerReauthorizationFencesControllerReplacement(t *testing.T) {
	identity := testIdentity(os.Getuid())
	var calls atomic.Int32
	server := testServer(identity.UID, func(context.Context, Peer) error {
		if calls.Add(1) == 2 {
			return errors.New("fixture controller replaced")
		}
		return nil
	}, func(context.Context, int) (intervention.Identity, error) { return identity, nil })
	client, stop := startTestBroker(t, server)
	defer stop()

	if _, err := client.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Inspect error = %v, want ErrUnauthorized", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("AuthorizePeer calls = %d, want 2", got)
	}
}

func TestClientRejectsStaleNonce(t *testing.T) {
	identity := testIdentity(os.Getuid())
	client, stop := startFakeBroker(t, func(connection *net.UnixConn) {
		var request inspectRequest
		if err := readFrame(connection, &request); err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		staleNonce := "0" + request.Nonce[1:]
		if staleNonce == request.Nonce {
			staleNonce = "1" + request.Nonce[1:]
		}
		_ = writeFrame(connection, inspectResponse{
			Version: wireVersion, Kind: kindResult, Nonce: staleNonce, Identity: &identity,
		})
	})
	defer stop()

	if _, err := client.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Inspect error = %v, want ErrProtocol", err)
	}
}

func TestServerRejectsMalformedAndOversizedRequests(t *testing.T) {
	identity := testIdentity(os.Getuid())
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "malformed", raw: "{malformed}\n"},
		{name: "oversized", raw: strings.Repeat("x", MaxMessageBytes) + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := testServer(identity.UID, allowPeer, func(context.Context, int) (intervention.Identity, error) {
				t.Fatal("invalid request reached Inspect")
				return intervention.Identity{}, nil
			})
			path, listener := newTestListener(t)
			done := serveTestServer(t, server, listener)
			connection := dialTestSocket(t, path)
			if _, err := connection.Write([]byte(test.raw)); err != nil {
				t.Fatalf("write raw request: %v", err)
			}
			var response inspectResponse
			if err := readFrame(connection, &response); err != nil {
				t.Fatalf("read response: %v", err)
			}
			_ = connection.Close()
			if response.Error != codeInvalidRequest || response.Identity != nil {
				t.Fatalf("response = %+v, want invalid request", response)
			}
			stopTestServer(t, listener, done)
		})
	}
}

func TestClientRejectsMalformedAndOversizedResponses(t *testing.T) {
	identity := testIdentity(os.Getuid())
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "malformed", raw: "{malformed}\n"},
		{name: "oversized", raw: strings.Repeat("x", MaxMessageBytes) + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, stop := startFakeBroker(t, func(connection *net.UnixConn) {
				var request inspectRequest
				if err := readFrame(connection, &request); err != nil {
					t.Errorf("read request: %v", err)
					return
				}
				_, _ = connection.Write([]byte(test.raw))
			})
			defer stop()
			if _, err := client.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Inspect error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestClientTimeoutAndUnavailableBroker(t *testing.T) {
	identity := testIdentity(os.Getuid())
	client, stop := startFakeBroker(t, func(connection *net.UnixConn) {
		var request inspectRequest
		if err := readFrame(connection, &request); err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		time.Sleep(150 * time.Millisecond)
	})
	client.Timeout = 30 * time.Millisecond
	if _, err := client.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID); !errors.Is(err, ErrTimeout) {
		t.Fatalf("timed Inspect error = %v, want ErrTimeout", err)
	}
	stop()

	missing := testClient(filepath.Join(localTestDirectory(t), "missing.sock"), identity.UID)
	if _, err := missing.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing Inspect error = %v, want ErrUnavailable", err)
	}
}

func TestClientAllowsGroupWritableSocketAndRejectsWorldWritableSocket(t *testing.T) {
	identity := testIdentity(os.Getuid())
	server := testServer(identity.UID, allowPeer, func(context.Context, int) (intervention.Identity, error) { return identity, nil })
	client, stop := startTestBroker(t, server)
	if mode := socketMode(t, client.SocketPath); mode&0o020 == 0 || mode&0o002 != 0 {
		t.Fatalf("test socket mode = %#o, want group writable and not world writable", mode)
	}
	if _, err := client.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID); err != nil {
		t.Fatalf("group-writable socket Inspect: %v", err)
	}
	stop()

	path, listener := newTestListener(t)
	defer listener.Close()
	if err := os.Chmod(path, 0o662); err != nil {
		t.Fatalf("chmod world-writable socket: %v", err)
	}
	client = testClient(path, identity.UID)
	if _, err := client.Inspect(context.Background(), identity.PID, identity.StartTicks, identity.BootID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("world-writable socket Inspect error = %v, want ErrUnavailable", err)
	}
}

func testIdentity(uid int) intervention.Identity {
	return intervention.Identity{
		BootID: "boot-fixture", PID: 4242, StartTicks: 987654, UID: uid,
		Executable: intervention.ExecutableIdentity{Device: 11, Inode: 22},
	}
}

func validTestRequest(identity intervention.Identity) inspectRequest {
	return inspectRequest{
		Version: wireVersion, Kind: kindInspect, PID: identity.PID,
		StartTicks: identity.StartTicks, BootID: identity.BootID,
		Nonce: strings.Repeat("a", nonceBytes*2),
	}
}

func allowPeer(context.Context, Peer) error { return nil }

func testServer(targetUID int, authorize func(context.Context, Peer) error, inspect func(context.Context, int) (intervention.Identity, error)) Server {
	return Server{
		TargetUID: targetUID, IOTimeout: 500 * time.Millisecond,
		AuthorizePeer: authorize, Inspect: inspect,
		effectiveUID: func() int { return 0 },
	}
}

func startTestBroker(t *testing.T, server Server) (Client, func()) {
	t.Helper()
	path, listener := newTestListener(t)
	done := serveTestServer(t, server, listener)
	return testClient(path, server.TargetUID), func() { stopTestServer(t, listener, done) }
}

func startFakeBroker(t *testing.T, handle func(*net.UnixConn)) (Client, func()) {
	t.Helper()
	path, listener := newTestListener(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer connection.Close()
		handle(connection)
	}()
	return testClient(path, os.Getuid()), func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fake broker did not stop")
		}
	}
}

func serveTestServer(t *testing.T, server Server, listener *net.UnixListener) chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(cancel)
	return done
}

func stopTestServer(t *testing.T, listener *net.UnixListener, done chan error) {
	t.Helper()
	_ = listener.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, ErrUnavailable) {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Error("broker server did not stop")
	}
}

func newTestListener(t *testing.T) (string, *net.UnixListener) {
	t.Helper()
	directory := localTestDirectory(t)
	path := filepath.Join(directory, "broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		listener.Close()
		t.Fatalf("chmod socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return path, listener
}

func localTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatalf("Abs test directory: %v", err)
	}
	return absolute
}

func testClient(path string, targetUID int) Client {
	uid := os.Getuid()
	return Client{
		SocketPath: path, TargetUID: targetUID, Timeout: 500 * time.Millisecond,
		testRootUID: uid, testRootUIDSet: true, testSkipParentTrust: true,
	}
}

func dialTestSocket(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		connection.Close()
		t.Fatalf("SetDeadline: %v", err)
	}
	return connection
}

func rawRequest(t *testing.T, path string, request inspectRequest) inspectResponse {
	t.Helper()
	connection := dialTestSocket(t, path)
	defer connection.Close()
	if err := writeFrame(connection, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var response inspectResponse
	if err := readFrame(connection, &response); err != nil {
		t.Fatalf("read response: %v", err)
	}
	return response
}

func socketMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat socket: %v", err)
	}
	return info.Mode().Perm()
}
