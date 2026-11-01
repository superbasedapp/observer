package sandboxengine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Stream is a hijacked attach connection to a container's main process. In
// TTY mode it is a raw byte stream both ways (no multiplexing headers).
type Stream struct {
	conn net.Conn
	br   *bufio.Reader
}

// Read reads the container's terminal output (including any bytes the
// engine sent right after its upgrade answer).
func (s *Stream) Read(p []byte) (int, error) { return s.br.Read(p) }

// Write sends terminal input to the container.
func (s *Stream) Write(p []byte) (int, error) { return s.conn.Write(p) }

// CloseWrite half-closes the input side.
func (s *Stream) CloseWrite() error {
	if u, ok := s.conn.(*net.UnixConn); ok {
		return u.CloseWrite()
	}
	return nil
}

// Close drops the stream. The container keeps running: a later attach
// re-attaches to its main process (section 5.5).
func (s *Stream) Close() error { return s.conn.Close() }

// attachHandshakeTimeout bounds the upgrade exchange, not the stream.
const attachHandshakeTimeout = 15 * time.Second

// ContainerAttach is the hijacked POST /containers/{id}/attach with stdin,
// stdout, stderr and stream set: the host helper's transport to the agent's
// TTY. It must only be called while the container is running (or before
// its first start); sandboxoci.Allowed holds the rule.
func (c *Client) ContainerAttach(ctx context.Context, id string) (*Stream, error) {
	p, err := c.versioned("/containers/" + url.PathEscape(id) + "/attach")
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, fmt.Errorf("sandboxengine: container attach: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(attachHandshakeTimeout))
	q := url.Values{"stream": {"1"}, "stdin": {"1"}, "stdout": {"1"}, "stderr": {"1"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://engine"+p+"?"+q.Encode(), nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sandboxengine: container attach: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sandboxengine: container attach: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		msg := errorMessage(resp.Body)
		_ = conn.Close()
		return nil, &APIError{Op: "container attach", Status: resp.StatusCode, Message: msg}
	}
	_ = conn.SetDeadline(time.Time{})
	return &Stream{conn: conn, br: br}, nil
}
