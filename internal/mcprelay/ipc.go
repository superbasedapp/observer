package mcprelay

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
)

// ipc.go is the owner-only IPC mode (§12.2 "ipc"): the endpoint is
// internal/attachsock's Transport seam - an AF_UNIX socket under a 0700
// directory on unix, a named pipe with an owner-only DACL on Windows -
// never a new primitive. A per-client bootstrap secret on the first frame
// binds the stream to a registered product client -> `ipc_bound`.

// ipcKeyName is the synthetic key the attach transport derives the relay's
// endpoint from: <dir(dbPath)>/mcprelay/attach/attach.sock on unix, a
// distinct hashed pipe name on Windows - never the daemon's own attach
// endpoint.
const ipcKeyName = "mcprelay"

// IPCEndpoint returns the relay's IPC endpoint for an observer DB path.
func IPCEndpoint(dbPath string) (string, error) {
	ep, err := attachsock.DefaultTransport().Endpoint(filepath.Join(filepath.Dir(dbPath), ipcKeyName, "ipc"))
	if err != nil {
		return "", fmt.Errorf("mcprelay.IPCEndpoint: %w", err)
	}
	return ep, nil
}

// ListenIPC creates the owner-only IPC endpoint for dbPath through the
// attach transport (which enforces the 0700 parent / owner DACL and refuses
// to steal a live listener).
func ListenIPC(dbPath string) (net.Listener, string, error) {
	if !attachsock.Supported() {
		return nil, "", fmt.Errorf("mcprelay.ListenIPC: %w", attachsock.ErrUnsupported)
	}
	ep, err := IPCEndpoint(dbPath)
	if err != nil {
		return nil, "", err
	}
	ln, err := attachsock.DefaultTransport().Listen(ep)
	if err != nil {
		return nil, "", fmt.Errorf("mcprelay.ListenIPC: %w", err)
	}
	return ln, ep, nil
}

// DialIPC connects to the relay's IPC endpoint.
func DialIPC(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error) {
	return attachsock.DefaultTransport().Dial(ctx, endpoint, timeout)
}

// IPCClient is what a bootstrap secret proves about the connecting client.
type IPCClient struct {
	// Agent / Product identify the registered product client.
	Agent, Product string
	// VServers, when non-empty, restricts which virtual servers this
	// client may address over this secret.
	VServers []string
}

// BootstrapSecrets resolves a per-client bootstrap secret (minted by the
// daemon when it projects a client's config, never reused across clients).
type BootstrapSecrets interface {
	Lookup(secret string) (IPCClient, bool)
}

// StaticSecrets is a BootstrapSecrets over a fixed table (constant-time
// compare).
type StaticSecrets map[string]IPCClient

// Lookup implements BootstrapSecrets.
func (s StaticSecrets) Lookup(secret string) (IPCClient, bool) {
	for k, v := range s {
		if len(k) == len(secret) && subtle.ConstantTimeCompare([]byte(k), []byte(secret)) == 1 {
			return v, true
		}
	}
	return IPCClient{}, false
}

// IPCHello is the first frame on an IPC stream.
type IPCHello struct {
	Hello  int    `json:"sbo_hello"`
	Secret string `json:"secret"`
	// VServer is the virtual server this stream addresses; ServerID an
	// approved local entry (Local=true) instead.
	VServer  string `json:"vserver,omitempty"`
	ServerID string `json:"server_id,omitempty"`
	Local    bool   `json:"local,omitempty"`
	// ProjectDir is the session's working directory (P11(e)): the relay
	// resolves it to the project hash it attests; a hash is never accepted.
	ProjectDir string `json:"project_dir,omitempty"`
	// Corr anchors the stream to a coding session (R11.8).
	CodingSessionID string `json:"coding_session_id,omitempty"`
	TurnRef         string `json:"turn_ref,omitempty"`
	ActionRef       string `json:"action_ref,omitempty"`
}

// ipcHelloTimeout bounds how long a fresh connection may wait before its
// hello frame.
const ipcHelloTimeout = 5 * time.Second

// ErrIPCRefused is returned on the stream when the hello is rejected.
var ErrIPCRefused = errors.New("mcprelay: ipc hello refused")

// ServeIPC accepts connections on ln until ctx ends. Each connection must
// open with an IPCHello whose secret resolves; the stream then carries
// newline-delimited JSON-RPC at attestation ipc_bound.
func (r *Relay) ServeIPC(ctx context.Context, ln net.Listener, secrets BootstrapSecrets) error {
	if secrets == nil {
		return errors.New("mcprelay.ServeIPC: bootstrap secrets are required")
	}
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
	)
	track := func(c net.Conn) {
		mu.Lock()
		conns[c] = struct{}{}
		mu.Unlock()
	}
	untrack := func(c net.Conn) {
		mu.Lock()
		delete(conns, c)
		mu.Unlock()
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		// A stream blocked in a read does not observe ctx: close it.
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("mcprelay.ServeIPC: accept: %w", err)
		}
		track(conn)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer untrack(conn)
			defer func() { _ = conn.Close() }()
			r.serveIPCConn(ctx, conn, secrets)
		}()
	}
}

func (r *Relay) serveIPCConn(ctx context.Context, conn net.Conn, secrets BootstrapSecrets) {
	_ = conn.SetReadDeadline(time.Now().Add(ipcHelloTimeout))
	fr := NewFrameReader(conn, 64<<10)
	raw, err := fr.Next()
	if err != nil {
		return
	}
	var hello IPCHello
	if json.Unmarshal(raw, &hello) != nil || hello.Hello != 1 || hello.Secret == "" {
		_ = WriteFrame(conn, ErrorFrame(nil, CodeInvalidRequest, "ipc: hello frame required"))
		return
	}
	client, ok := secrets.Lookup(hello.Secret)
	if !ok {
		_ = WriteFrame(conn, ErrorFrame(nil, CodeForbidden, "ipc: bootstrap secret not recognised"))
		r.log().Info("mcprelay: ipc hello refused", "remote", conn.RemoteAddr())
		return
	}
	target := Target{VServer: hello.VServer, ServerID: hello.ServerID, Local: hello.Local}
	if target.VServer == "" {
		_ = WriteFrame(conn, ErrorFrame(nil, CodeInvalidRequest, "ipc: hello names no vserver"))
		return
	}
	if len(client.VServers) > 0 && !containsString(client.VServers, target.VServer) {
		_ = WriteFrame(conn, ErrorFrame(nil, CodeForbidden, "ipc: this client may not address that virtual server"))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if err := WriteFrame(conn, []byte(`{"sbo_hello_ok":1}`)); err != nil {
		return
	}
	spec := sessionSpec{
		target: target, transport: localpdp.TransportIPC, agent: client.Agent, product: client.Product,
		corr:        Correlation{CodingSessionID: hello.CodingSessionID, TurnRef: hello.TurnRef, ActionRef: hello.ActionRef},
		projectHash: r.projectHash(hello.ProjectDir),
	}
	// The hello reader may have buffered frames after the hello; continue
	// from the same reader.
	s := newSession(r, spec, readerFrom(fr), conn, nil)
	if target.Local {
		// A local target over IPC needs a spawned child: the wrapper mode
		// owns that. IPC serves remote vservers this wave.
		_ = WriteFrame(conn, ErrorFrame(nil, CodeUnavailable, "ipc: node-local servers are served by the stdio wrapper"))
		return
	}
	s.up, s.upCompletes = httpUpstream{s: s}, true
	if err := s.run(ctx); err != nil && ctx.Err() == nil {
		r.log().Debug("mcprelay: ipc stream ended", "err", err)
	}
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
