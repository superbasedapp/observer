package cloudsessionnet

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
)

// Caps and defaults.
const (
	// DefaultTimeout bounds one delivery. A flush runs inside a vendor hook
	// with its own timeout, so this stays well under the hook's 60 seconds.
	DefaultTimeout = 20 * time.Second
	// MaxEnvelopeBytes is the largest envelope accepted (uncompressed), the
	// org push default batch budget's order of magnitude.
	MaxEnvelopeBytes = 8 << 20
	// maxResponseBytes caps the response body read.
	maxResponseBytes = 64 << 10
)

// DeliveryError is a delivery that reached the destination and was refused,
// or did not reach it. It never carries the token or the request body.
type DeliveryError struct {
	// Status is the HTTP status (0 when no response arrived).
	Status int
	// Retryable reports that a later flush may succeed (network failure,
	// 408, 429, 5xx). An auth refusal or a too-large body is not.
	Retryable bool
	// NetworkBlocked reports that the sandbox's egress proxy refused the
	// CONNECT to the destination host: the request never left the VM. A
	// Claude Code cloud environment answers 403 at CONNECT for a host its
	// network level does not list (CA-A2). Not retryable: only the
	// environment owner can change the level.
	NetworkBlocked bool
	// ConnectStatus is the proxy's CONNECT status when NetworkBlocked.
	ConnectStatus int
	// Host is the destination host (never a token or a path).
	Host string
	// Reason is a short description.
	Reason string
}

func (e *DeliveryError) Error() string {
	if e.NetworkBlocked {
		return fmt.Sprintf("cloudsessionnet: the egress proxy refused CONNECT to %s (%d): the environment's network level blocks the host", e.Host, e.ConnectStatus)
	}
	if e.Status != 0 {
		return fmt.Sprintf("cloudsessionnet: destination answered %d: %s", e.Status, e.Reason)
	}
	return "cloudsessionnet: " + e.Reason
}

// HTTPDeliverer POSTs envelopes to a network destination.
type HTTPDeliverer struct {
	endpoint  string
	host      string
	token     string
	userAgent string
	client    *http.Client
}

// HTTPOptions tune NewHTTP. The zero value is the production setting.
type HTTPOptions struct {
	// Timeout overrides DefaultTimeout.
	Timeout time.Duration
	// AgentVersion is sent in the User-Agent.
	AgentVersion string
	// Transport overrides the HTTP transport (tests).
	Transport http.RoundTripper
	// Proxy overrides the proxy selection of the default transport (tests;
	// production reads HTTPS_PROXY / NO_PROXY like every other client).
	Proxy func(*http.Request) (*url.URL, error)
}

// errConnectRefused is what the transport's CONNECT hook returns; Deliver
// maps it to a NetworkBlocked DeliveryError.
type errConnectRefused struct{ status int }

func (e *errConnectRefused) Error() string {
	return fmt.Sprintf("egress proxy refused CONNECT (%d)", e.status)
}

// newTransport is the production transport: the environment's proxy, short
// dial and handshake bounds, and a CONNECT hook that types a proxy refusal
// so it is told apart from the destination's own answer.
func newTransport(timeout time.Duration, proxy func(*http.Request) (*url.URL, error)) *http.Transport {
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	return &http.Transport{
		Proxy:                 proxy,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          1,
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
			if res.StatusCode != http.StatusOK {
				return &errConnectRefused{status: res.StatusCode}
			}
			return nil
		},
	}
}

// NewHTTP returns a deliverer for a resolved network destination. token is
// the ship token (CA-D8); it is required when the destination needs one.
func NewHTTP(d cloudsession.Destination, token string, opts HTTPOptions) (*HTTPDeliverer, error) {
	if !d.Network {
		return nil, errors.New("cloudsessionnet.NewHTTP: not a network destination")
	}
	if err := checkEndpoint(d.Endpoint); err != nil {
		return nil, err
	}
	token = strings.TrimSpace(token)
	if d.NeedsToken && token == "" {
		return nil, errors.New("cloudsessionnet.NewHTTP: the destination needs a ship token (SBO_CLOUD_SESSION_TOKEN or SBO_CLOUD_SESSION_TOKEN_FILE)")
	}
	if strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("cloudsessionnet.NewHTTP: the ship token holds a line break")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	transport := opts.Transport
	if transport == nil {
		transport = newTransport(timeout, opts.Proxy)
	}
	ua := "superbased-observer-cloud-session"
	if opts.AgentVersion != "" {
		ua += "/" + opts.AgentVersion
	}
	u, _ := url.Parse(d.Endpoint) // checkEndpoint parsed it already
	return &HTTPDeliverer{
		endpoint:  d.Endpoint,
		host:      u.Hostname(),
		token:     token,
		userAgent: ua,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// Never follow a redirect: it would carry the token elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// checkEndpoint re-applies the destination URL rules.
func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("cloudsessionnet: endpoint: %w", err)
	}
	if u.User != nil || u.Host == "" {
		return errors.New("cloudsessionnet: endpoint must have a host and no user info")
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	}
	return errors.New("cloudsessionnet: endpoint must be https (plain http only to a loopback host)")
}

func isLoopback(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Deliver gzips envelope and POSTs it with the ship token.
func (h *HTTPDeliverer) Deliver(ctx context.Context, envelope []byte) (cloudsession.Receipt, error) {
	if len(envelope) == 0 {
		return cloudsession.Receipt{}, errors.New("cloudsessionnet: empty envelope")
	}
	if len(envelope) > MaxEnvelopeBytes {
		return cloudsession.Receipt{}, &DeliveryError{Reason: fmt.Sprintf("envelope is %d bytes, over the %d cap", len(envelope), MaxEnvelopeBytes)}
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(envelope); err != nil {
		return cloudsession.Receipt{}, fmt.Errorf("cloudsessionnet: gzip: %w", err)
	}
	if err := zw.Close(); err != nil {
		return cloudsession.Receipt{}, fmt.Errorf("cloudsessionnet: gzip: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(gz.Bytes()))
	if err != nil {
		return cloudsession.Receipt{}, fmt.Errorf("cloudsessionnet: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", h.userAgent)
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		var refused *errConnectRefused
		if errors.As(err, &refused) {
			return cloudsession.Receipt{}, &DeliveryError{NetworkBlocked: true, ConnectStatus: refused.status, Host: h.host, Reason: "network level blocks " + h.host}
		}
		// The error text of a failed Do names the URL, never a header.
		return cloudsession.Receipt{}, &DeliveryError{Retryable: true, Host: h.host, Reason: "no response: " + redactURLError(err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		r := cloudsession.Receipt{Status: resp.StatusCode}
		var ack struct {
			AcceptedRows int `json:"accepted_rows"`
		}
		if json.Unmarshal(body, &ack) == nil {
			r.Accepted = ack.AcceptedRows
		}
		return r, nil
	}
	return cloudsession.Receipt{Status: resp.StatusCode}, &DeliveryError{
		Host:      h.host,
		Status:    resp.StatusCode,
		Retryable: retryable(resp.StatusCode),
		Reason:    http.StatusText(resp.StatusCode),
	}
}

// retryable reports whether a later flush may succeed after this status.
func retryable(status int) bool {
	switch {
	case status == http.StatusRequestTimeout, status == http.StatusTooManyRequests:
		return true
	case status >= 500:
		return true
	}
	return false
}

// redactURLError returns err's text without any query string a URL error
// might print (the endpoint has none by construction; belt and braces).
func redactURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
}

// FileDeliverer writes each envelope as one JSON file in a directory.
type FileDeliverer struct {
	dir string
	now func() time.Time
	seq atomic.Uint64
}

// NewFile returns a deliverer for a resolved file destination.
func NewFile(d cloudsession.Destination) (*FileDeliverer, error) {
	if d.Network || d.Dir == "" {
		return nil, errors.New("cloudsessionnet.NewFile: not a file destination")
	}
	return &FileDeliverer{dir: d.Dir, now: time.Now}, nil
}

// Deliver writes envelope to <dir>/envelope-<utc time>-<seq>.json with mode
// 0600, atomically (a temporary file renamed into place).
func (f *FileDeliverer) Deliver(_ context.Context, envelope []byte) (cloudsession.Receipt, error) {
	if len(envelope) == 0 {
		return cloudsession.Receipt{}, errors.New("cloudsessionnet: empty envelope")
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return cloudsession.Receipt{}, fmt.Errorf("cloudsessionnet: file destination: %w", err)
	}
	name := fmt.Sprintf("envelope-%s-%04d.json", f.now().UTC().Format("20060102T150405.000000000Z"), f.seq.Add(1))
	tmp, err := os.CreateTemp(f.dir, ".envelope-*.tmp")
	if err != nil {
		return cloudsession.Receipt{}, fmt.Errorf("cloudsessionnet: file destination: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return cloudsession.Receipt{}, fmt.Errorf("cloudsessionnet: file destination: %w", err)
	}
	if _, err := tmp.Write(envelope); err != nil {
		tmp.Close()
		return cloudsession.Receipt{}, fmt.Errorf("cloudsessionnet: file destination: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return cloudsession.Receipt{}, fmt.Errorf("cloudsessionnet: file destination: %w", err)
	}
	dst := filepath.Join(f.dir, name)
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return cloudsession.Receipt{}, fmt.Errorf("cloudsessionnet: file destination: %w", err)
	}
	return cloudsession.Receipt{Location: dst}, nil
}

// Host returns the destination host.
func (h *HTTPDeliverer) Host() string { return h.host }

// New returns the deliverer for a resolved destination.
func New(d cloudsession.Destination, token string, opts HTTPOptions) (cloudsession.Deliverer, error) {
	if d.Network {
		return NewHTTP(d, token, opts)
	}
	return NewFile(d)
}
