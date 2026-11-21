package signerd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// ProtocolVersion is the wire version every request and response carries.
const ProtocolVersion = 1

// maxMessage bounds one request or response line.
const maxMessage = 64 << 10

// defaultTimeout bounds one connection, end to end.
const defaultTimeout = 5 * time.Second

// Response error codes.
const (
	ErrClaimsRefusedCode = "claims_refused"
	ErrBadRequestCode    = "bad_request"
	ErrPeerRefusedCode   = "peer_refused"
	ErrInternalCode      = "internal"
)

// ErrPeerCredUnsupported is returned where SO_PEERCRED is not available
// (every OS but Linux): the signer refuses to start there.
var ErrPeerCredUnsupported = errors.New("signerd: peer credentials (SO_PEERCRED) are supported on Linux only")

// ErrPeerRefused is what the client sees when the signer refused its uid.
var ErrPeerRefused = errors.New("signerd: the signer refused this process's uid")

type request struct {
	V      int                `json:"v"`
	Op     string             `json:"op"`
	KID    string             `json:"kid,omitempty"`
	Claims *oidcissuer.Claims `json:"claims,omitempty"`
}

type keyEntry struct {
	KID string         `json:"kid"`
	JWK oidcissuer.JWK `json:"jwk"`
}

type response struct {
	V     int        `json:"v"`
	JWT   string     `json:"jwt,omitempty"`
	Keys  []keyEntry `json:"keys,omitempty"`
	Error string     `json:"error,omitempty"`
}

// Server serves a Signer over a listener. The zero PeerUID uses SO_PEERCRED.
type Server struct {
	// Signer holds the keys and applies the claim rules.
	Signer oidcissuer.Signer
	// AllowUID is the only peer uid served.
	AllowUID int
	// PeerUID returns a connection's peer uid; nil means PeerCredUID
	// (SO_PEERCRED). Tests on systems without it inject one.
	PeerUID func(net.Conn) (int, error)
	// Logger receives one line per request (op, kid, org, jti, outcome);
	// never claims beyond those, never a token. nil means slog.Default().
	Logger *slog.Logger
	// Timeout bounds one connection; zero means five seconds.
	Timeout time.Duration
}

// op is one row of the operation table.
type op struct {
	name string
	run  func(ctx context.Context, s *Server, req request) response
}

var ops = []op{
	{name: "keys", run: func(ctx context.Context, s *Server, _ request) response {
		keys, err := s.Signer.PublicKeys(ctx)
		if err != nil {
			return response{V: ProtocolVersion, Error: ErrInternalCode}
		}
		out := make([]keyEntry, 0, len(keys))
		for _, k := range keys {
			out = append(out, keyEntry{KID: k.KID, JWK: k.JWK})
		}
		return response{V: ProtocolVersion, Keys: out}
	}},
	{name: "sign", run: func(ctx context.Context, s *Server, req request) response {
		if req.Claims == nil || req.KID == "" {
			return response{V: ProtocolVersion, Error: ErrBadRequestCode}
		}
		jwt, err := s.Signer.Sign(ctx, req.KID, *req.Claims)
		switch {
		case errors.Is(err, oidcissuer.ErrClaimsRefused):
			return response{V: ProtocolVersion, Error: ErrClaimsRefusedCode}
		case err != nil:
			return response{V: ProtocolVersion, Error: ErrInternalCode}
		}
		return response{V: ProtocolVersion, JWT: jwt}
	}},
}

// Serve accepts connections on ln until ctx is done or ln fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.Signer == nil {
		return errors.New("signerd.Server.Serve: no signer")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("signerd.Server.Serve: accept: %w", err)
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	peer := s.PeerUID
	if peer == nil {
		peer = PeerCredUID
	}
	uid, err := peer(conn)
	if err != nil || uid != s.AllowUID {
		s.logger().Warn("signerd: refused a peer", "uid", uid, "err", err)
		// The request is drained, unparsed, so closing does not reset the
		// connection before the refusal reaches the peer.
		_, _ = readLine(conn)
		writeResponse(conn, response{V: ProtocolVersion, Error: ErrPeerRefusedCode})
		return
	}
	req, err := readRequest(conn)
	if err != nil || req.V != ProtocolVersion {
		writeResponse(conn, response{V: ProtocolVersion, Error: ErrBadRequestCode})
		return
	}
	resp := response{V: ProtocolVersion, Error: ErrBadRequestCode}
	for _, o := range ops {
		if o.name == req.Op {
			resp = o.run(ctx, s, req)
			break
		}
	}
	attrs := []any{"op", req.Op, "kid", req.KID, "outcome", outcome(resp)}
	if req.Claims != nil {
		attrs = append(attrs, "org", req.Claims.Org, "jti", req.Claims.Jti)
	}
	s.logger().Info("signerd: request", attrs...)
	writeResponse(conn, resp)
}

func outcome(r response) string {
	if r.Error != "" {
		return r.Error
	}
	return "ok"
}

func readRequest(r io.Reader) (request, error) {
	line, err := readLine(r)
	if err != nil {
		return request{}, err
	}
	var req request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return request{}, fmt.Errorf("signerd: decode request: %w", err)
	}
	if dec.More() {
		return request{}, errors.New("signerd: trailing data after the request")
	}
	return req, nil
}

func readLine(r io.Reader) ([]byte, error) { return readLineLimit(r, maxMessage) }

// readLineLimit reads one newline-terminated line of at most limit bytes.
func readLineLimit(r io.Reader, limit int) ([]byte, error) {
	br := bufio.NewReaderSize(io.LimitReader(r, int64(limit)+1), 4096)
	line, err := br.ReadBytes('\n')
	if len(line) > limit {
		return nil, errors.New("signerd: message too large")
	}
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return nil, fmt.Errorf("signerd: read: %w", err)
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

func writeResponse(w io.Writer, r response) {
	b, err := json.Marshal(r) //nolint:gosec // G117: the signed id_token IS the response the peer-checked caller asked for
	if err != nil {
		return
	}
	_, _ = w.Write(append(b, '\n'))
}

// Client is an oidcissuer.Signer that talks to a signer over its socket.
type Client struct {
	// Network is "unix" in production ("tcp" only in tests).
	Network string
	// Address is the socket path (or a test address).
	Address string
	// Timeout bounds one call; zero means five seconds.
	Timeout time.Duration
}

// NewUnixClient returns a client for the socket at path.
func NewUnixClient(path string) *Client { return &Client{Network: "unix", Address: path} }

// Sign implements oidcissuer.Signer.
func (c *Client) Sign(ctx context.Context, kid string, claims oidcissuer.Claims) (string, error) {
	resp, err := c.call(ctx, request{V: ProtocolVersion, Op: "sign", KID: kid, Claims: &claims})
	if err != nil {
		return "", err
	}
	if resp.JWT == "" {
		return "", errors.New("signerd.Client.Sign: empty response")
	}
	return resp.JWT, nil
}

// PublicKeys implements oidcissuer.Signer.
func (c *Client) PublicKeys(ctx context.Context) ([]oidcissuer.PublicKey, error) {
	resp, err := c.call(ctx, request{V: ProtocolVersion, Op: "keys"})
	if err != nil {
		return nil, err
	}
	out := make([]oidcissuer.PublicKey, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		out = append(out, oidcissuer.PublicKey{KID: k.KID, JWK: k.JWK})
	}
	return out, nil
}

func (c *Client) call(ctx context.Context, req request) (response, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	network := c.Network
	if network == "" {
		network = "unix"
	}
	conn, err := d.DialContext(ctx, network, c.Address)
	if err != nil {
		return response{}, fmt.Errorf("signerd.Client: dial: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	b, err := json.Marshal(req)
	if err != nil {
		return response{}, fmt.Errorf("signerd.Client: encode: %w", err)
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return response{}, fmt.Errorf("signerd.Client: write: %w", err)
	}
	line, err := readLine(conn)
	if err != nil {
		return response{}, fmt.Errorf("signerd.Client: %w", err)
	}
	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		return response{}, fmt.Errorf("signerd.Client: decode: %w", err)
	}
	switch resp.Error {
	case "":
		return resp, nil
	case ErrClaimsRefusedCode:
		return response{}, fmt.Errorf("signerd.Client: %w", oidcissuer.ErrClaimsRefused)
	case ErrPeerRefusedCode:
		return response{}, ErrPeerRefused
	default:
		return response{}, fmt.Errorf("signerd.Client: signer answered %s", resp.Error)
	}
}
