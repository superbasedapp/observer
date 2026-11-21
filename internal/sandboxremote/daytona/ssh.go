package daytona

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// ssh.go is the box's exec transport: Daytona's SSH access (the main API's
// POST /sandbox/{sandboxIdOrName}/ssh-access, SshAccessDto; the SSH access
// page: "ssh <token>@ssh.app.daytona.io", token-based authentication) over
// golang.org/x/crypto/ssh, the pure-Go SSH transport sandbox plan v2 names
// for this row (REST plus its SSH access tokens, wire_only). One connection
// per box, opened on the first exec and kept with keepalives; each process
// is one exec channel on it.
//
// What the docs do not state, and how the client meets it:
//   - the gateway's host key is not published: the client trusts the first
//     key a gateway host shows for this client's life and refuses a changed
//     one (ledger row SBX-DAY-1; register REM-DAY-1);
//   - whether a password or key is asked besides the token-as-username: the
//     client offers none, then the token as a password and as the answer to
//     a keyboard-interactive prompt (unverified, REM-DAY-1);
//   - whether a connection outlives its token's expiry: a dropped connection
//     is re-opened with a fresh token on the next exec.

// sshKeepalive is the interval of the keepalive requests on an idle
// connection.
const sshKeepalive = 30 * time.Second

// sshDefaultMinutes is the SSH access lifetime for a box whose TTL this
// client did not set (the docs' default).
const sshDefaultMinutes = 60

// sshMaxMinutes is the most the spec allows for expiresInMinutes.
const sshMaxMinutes = 1440

// sshConn is one box's connection.
type sshConn struct {
	client *ssh.Client
	stop   chan struct{}
}

// newTag is a fresh random tag for a command's pid file.
func newTag() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// session opens an exec channel on the box's connection, dialling (or
// re-dialling once) as needed.
func (c *Client) session(ctx context.Context, id string) (*ssh.Session, error) {
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.sshConnFor(ctx, id)
		if err != nil {
			return nil, err
		}
		s, err := conn.client.NewSession()
		if err == nil {
			return s, nil
		}
		c.dropSSH(id, conn)
		if attempt == 1 {
			return nil, fmt.Errorf("daytona: ssh session: %s", c.redact(err.Error()))
		}
	}
	return nil, errors.New("daytona: ssh session: unreachable")
}

// sshConnFor returns the box's connection, opening it when there is none.
func (c *Client) sshConnFor(ctx context.Context, id string) (*sshConn, error) {
	c.mu.Lock()
	conn := c.ssh[id]
	c.mu.Unlock()
	if conn != nil {
		return conn, nil
	}
	conn, err := c.dialSSH(ctx, id)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if old := c.ssh[id]; old != nil {
		c.mu.Unlock()
		conn.close()
		return old, nil
	}
	c.ssh[id] = conn
	c.mu.Unlock()
	return conn, nil
}

// dropSSH forgets and closes a box's connection.
func (c *Client) dropSSH(id string, conn *sshConn) {
	c.mu.Lock()
	if conn == nil {
		conn = c.ssh[id]
	}
	if c.ssh[id] == conn {
		delete(c.ssh, id)
	}
	c.mu.Unlock()
	if conn != nil {
		conn.close()
	}
}

func (s *sshConn) close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	_ = s.client.Close()
}

// sshAccess is the answer of the SSH access call (SshAccessDto, the fields
// the client reads).
type sshAccess struct {
	Token      string `json:"token"`
	SSHCommand string `json:"sshCommand"`
	ExpiresAt  string `json:"expiresAt"`
}

// sshTarget parses the documented connection command ("ssh <token>@host",
// with an optional "-p <port>") into host and port.
func sshTarget(cmd string) (host string, port int, err error) {
	f := strings.Fields(cmd)
	port = 22
	if len(f) < 2 || f[0] != "ssh" {
		return "", 0, errors.New("daytona: the SSH access answer has no ssh command")
	}
	for i := 1; i < len(f); i++ {
		switch {
		case f[i] == "-p" && i+1 < len(f):
			p, perr := strconv.Atoi(f[i+1])
			if perr != nil || p < 1 || p > 65535 {
				return "", 0, errors.New("daytona: the SSH access answer names a bad port")
			}
			port = p
			i++
		case strings.Contains(f[i], "@"):
			host = f[i][strings.LastIndexByte(f[i], '@')+1:]
		case strings.HasPrefix(f[i], "-"):
			return "", 0, errors.New("daytona: the SSH access answer carries an option the client does not take")
		}
	}
	if host == "" {
		return "", 0, errors.New("daytona: the SSH access answer names no host")
	}
	return host, port, nil
}

// sshHostAllowed: the token goes to the gateway, so it must be under
// Daytona's own domain, or the bound endpoint's own host (a loopback test).
func (c *Client) sshHostAllowed(host string) bool {
	if strings.EqualFold(host, c.base.Hostname()) {
		return true
	}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona)
	return v.OwnsHost(c.base.Hostname()) && v.OwnsHost(host)
}

// dialSSH asks for SSH access to the box and opens the connection.
func (c *Client) dialSSH(ctx context.Context, id string) (*sshConn, error) {
	c.mu.Lock()
	minutes := c.ttl[id]
	c.mu.Unlock()
	if minutes <= 0 {
		minutes = sshDefaultMinutes
	}
	minutes = min(minutes, sshMaxMinutes)
	var acc sshAccess
	q := url.Values{"expiresInMinutes": {strconv.Itoa(minutes)}}
	if err := c.doJSON(ctx, request{method: http.MethodPost, url: c.apiURL("/sandbox/"+url.PathEscape(id)+"/ssh-access", q)}, nil, &acc); err != nil {
		return nil, fmt.Errorf("daytona: ssh access: %w", err)
	}
	if acc.Token == "" {
		return nil, errors.New("daytona: the SSH access answer carried no token")
	}
	c.addSecret(acc.Token)
	host, port, err := sshTarget(c.redact(acc.SSHCommand))
	if err != nil {
		return nil, err
	}
	if !c.sshHostAllowed(host) {
		return nil, fmt.Errorf("daytona: %w: the SSH gateway %s is outside Daytona's domain", sandboxremote.ErrCredentialEndpointMismatch, host)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	token := acc.Token
	cfg := &ssh.ClientConfig{
		User: token,
		Auth: []ssh.AuthMethod{
			ssh.Password(token),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				out := make([]string, len(qs))
				for i := range out {
					out[i] = token
				}
				return out, nil
			}),
		},
		HostKeyCallback: c.pinHostKey,
		Timeout:         30 * time.Second,
	}
	raw, err := c.o.DialSSH(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("daytona: ssh dial: %s", c.redact(err.Error()))
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	cc, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("daytona: ssh handshake: %s", c.redact(err.Error()))
	}
	_ = raw.SetDeadline(time.Time{})
	conn := &sshConn{client: ssh.NewClient(cc, chans, reqs), stop: make(chan struct{})}
	go c.keepalive(id, conn)
	return conn, nil
}

// keepalive sends a keepalive request on an idle connection and drops the
// connection when one fails.
func (c *Client) keepalive(id string, conn *sshConn) {
	t := time.NewTicker(sshKeepalive)
	defer t.Stop()
	for {
		select {
		case <-conn.stop:
			return
		case <-t.C:
			if _, _, err := conn.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				c.dropSSH(id, conn)
				return
			}
		}
	}
}

// pinHostKey trusts the first host key a gateway shows for this client's
// life and refuses a different one (Daytona publishes no host key).
func (c *Client) pinHostKey(hostname string, _ net.Addr, key ssh.PublicKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	got := key.Marshal()
	if want, ok := c.hostKeys[hostname]; ok {
		if !bytes.Equal(want, got) {
			return fmt.Errorf("daytona: the SSH gateway %s changed its host key during the run", hostname)
		}
		return nil
	}
	c.hostKeys[hostname] = got
	return nil
}

// dialTCP is the default SSH dial.
func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}
