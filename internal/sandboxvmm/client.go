package sandboxvmm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// maxBody caps every answer the client reads.
const maxBody = 1 << 20

// requestTimeout bounds one call (vm.create and vm.boot included: they
// return once the VMM acted, not when the guest finished booting).
const requestTimeout = 30 * time.Second

// apiPrefix is the API's version prefix.
const apiPrefix = "/api/v1/"

// Dialer opens one connection to the VMM's API socket.
type Dialer func(ctx context.Context) (net.Conn, error)

// APIError is an answer that is not the call's documented success.
type APIError struct {
	Op      string
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sandboxvmm: %s: the VMM answered %d: %s", e.Op, e.Status, e.Message)
}

// ErrMalformed is an answer whose body does not have the documented shape.
var ErrMalformed = errors.New("sandboxvmm: the VMM's answer is malformed")

// Client speaks the Cloud Hypervisor API through one dialer.
type Client struct {
	hc *http.Client
}

// New returns a client over dial. It does not dial.
func New(dial Dialer) (*Client, error) {
	if dial == nil {
		return nil, errors.New("sandboxvmm: no dialer")
	}
	tr := &http.Transport{
		DialContext:        func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
		DisableCompression: true, DisableKeepAlives: true, Proxy: nil,
	}
	return &Client{hc: &http.Client{Transport: tr, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// call is one row of the call table: its method, endpoint and the status
// that means success (with or without a body).
type call struct {
	method string
	path   string
	ok     int
	body   bool
}

// The call table (Cloud Hypervisor 54 API).
var (
	callPing        = call{http.MethodGet, "vmm.ping", http.StatusOK, true}
	callCreate      = call{http.MethodPut, "vm.create", http.StatusNoContent, false}
	callBoot        = call{http.MethodPut, "vm.boot", http.StatusNoContent, false}
	callInfo        = call{http.MethodGet, "vm.info", http.StatusOK, true}
	callShutdown    = call{http.MethodPut, "vm.shutdown", http.StatusNoContent, false}
	callDelete      = call{http.MethodPut, "vm.delete", http.StatusNoContent, false}
	callVMMShutdown = call{http.MethodPut, "vmm.shutdown", http.StatusNoContent, false}
)

// do runs one call and returns its body (nil for a no-content call).
func (c *Client) do(ctx context.Context, k call, in []byte) ([]byte, error) {
	var rd io.Reader
	if in != nil {
		rd = bytes.NewReader(in)
	}
	req, err := http.NewRequestWithContext(ctx, k.method, "http://localhost"+apiPrefix+k.path, rd)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sandboxvmm: %s: %w", k.path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("sandboxvmm: %s: reading the answer: %w", k.path, err)
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("%w: %s: the answer is over %d bytes", ErrMalformed, k.path, maxBody)
	}
	if resp.StatusCode != k.ok {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 512 {
			msg = msg[:512]
		}
		return nil, &APIError{Op: k.path, Status: resp.StatusCode, Message: msg}
	}
	if !k.body && len(bytes.TrimSpace(b)) != 0 {
		return nil, fmt.Errorf("%w: %s: a body where none is due", ErrMalformed, k.path)
	}
	if k.body && !json.Valid(b) {
		return nil, fmt.Errorf("%w: %s: not JSON", ErrMalformed, k.path)
	}
	return b, nil
}

// Ping is vmm.ping's answer.
type Ping struct {
	BuildVersion string   `json:"build_version"`
	Version      string   `json:"version"`
	PID          int      `json:"pid"`
	Features     []string `json:"features"`
}

// Ping asks the VMM for its version and pid.
func (c *Client) Ping(ctx context.Context) (Ping, error) {
	b, err := c.do(ctx, callPing, nil)
	if err != nil {
		return Ping{}, err
	}
	var p Ping
	if err := json.Unmarshal(b, &p); err != nil || p.Version == "" || p.PID <= 0 {
		return Ping{}, fmt.Errorf("%w: vmm.ping: no version or pid", ErrMalformed)
	}
	return p, nil
}

// Create sends the vm.create body for plan (built by sandboxvm.CreateBody).
func (c *Client) Create(ctx context.Context, plan sandboxvm.Plan) error {
	body, err := sandboxvm.CreateBody(plan)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, callCreate, body)
	return err
}

// Boot boots the created VM.
func (c *Client) Boot(ctx context.Context) error { _, err := c.do(ctx, callBoot, nil); return err }

// Info returns vm.info's raw answer (sandboxvm.ReadBack judges it).
func (c *Client) Info(ctx context.Context) ([]byte, error) { return c.do(ctx, callInfo, nil) }

// Shutdown shuts the VM down.
func (c *Client) Shutdown(ctx context.Context) error {
	_, err := c.do(ctx, callShutdown, nil)
	return err
}

// Delete deletes the VM.
func (c *Client) Delete(ctx context.Context) error { _, err := c.do(ctx, callDelete, nil); return err }

// ShutdownVMM ends the VMM process.
func (c *Client) ShutdownVMM(ctx context.Context) error {
	_, err := c.do(ctx, callVMMShutdown, nil)
	return err
}

// VsockDialer opens one connection to the VMM's vsock unix socket.
type VsockDialer func(ctx context.Context) (net.Conn, error)

// handshakeTimeout bounds the CONNECT exchange (the VMM waits forever for a
// request without a newline; the guest may not listen yet).
const handshakeTimeout = 5 * time.Second

// DialVsock connects to guest port through the VMM's hybrid vsock socket:
// it writes CONNECT <port>\n, reads the OK <hostport>\n answer under a
// deadline and returns the connection positioned at the guest's first byte.
func DialVsock(ctx context.Context, dial VsockDialer, port uint32) (net.Conn, uint32, error) {
	req, err := sandboxvm.ConnectRequest(port)
	if err != nil {
		return nil, 0, err
	}
	c, err := dial(ctx)
	if err != nil {
		return nil, 0, err
	}
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if _, err := c.Write(req); err != nil {
		_ = c.Close()
		return nil, 0, fmt.Errorf("%w: %w", sandboxvm.ErrVsockRefused, err)
	}
	hostPort, err := sandboxvm.ReadConnectAnswer(c)
	if err != nil {
		_ = c.Close()
		return nil, 0, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, hostPort, nil
}
