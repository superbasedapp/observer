package sandboxnet

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// tlsname.go is the host allow-list's second half (lane SBX-P3C audit
// finding 2, ledger SBX-NET-1): a listed name is reached through a shared
// CDN edge, so the CONNECT target alone does not say which site the tunnel
// talks to; the TLS ClientHello's server name does. While a Gateway carries
// a HostRules:
//
//   - a CONNECT may name port 443 only, and an absolute-form plain http
//     request port 80 only (listedPortRules), refused as port-not-allowed;
//   - after the tunnel is up, the gateway reads the client's ClientHello
//     (bounded in time and bytes) BEFORE any byte reaches the destination:
//     no server name, or one that cannot be read, refuses as sni-absent; a
//     server name other than the CONNECT target (compared as the list
//     compares names) refuses as sni-mismatch. Only then are the ClientHello
//     bytes, unchanged, sent on and the tunnel piped.
//
// Each refusal is logged as LogEgressRefused with its rule, which the run's
// RefusalLogger turns into one terminal line and one run-log line. A
// list-less gateway (every agent run) is unchanged: any port, no TLS read.

// The rules this file adds (hyphenated like every gateway rule).
const (
	// RulePortNotAllowed refuses a port other than 443 for a CONNECT, or 80
	// for an absolute-form request, while a host list is set.
	RulePortNotAllowed = "port-not-allowed"
	// RuleSNIAbsent refuses a tunnel whose first bytes are not a TLS
	// ClientHello carrying a server name.
	RuleSNIAbsent = "sni-absent"
	// RuleSNIMismatch refuses a tunnel whose ClientHello names another host
	// than the CONNECT target.
	RuleSNIMismatch = "sni-mismatch"
)

// requestForm is how a request reached the gateway.
type requestForm string

const (
	formConnect  requestForm = "connect"
	formAbsolute requestForm = "absolute"
)

// listedPortRules is the one port a request form may name while a host list
// is set (walked top-down; a form with no row is refused).
var listedPortRules = []struct {
	form requestForm
	port string
}{
	{formConnect, "443"},
	{formAbsolute, "80"},
}

// listedPortAllowed reports whether form may name port under a host list.
func listedPortAllowed(form requestForm, port string) bool {
	for _, r := range listedPortRules {
		if r.form == form {
			return r.port == port
		}
	}
	return false
}

// clientHelloTimeout bounds the wait for the ClientHello, and
// clientHelloMaxBytes the bytes read for it.
const (
	clientHelloTimeout  = 15 * time.Second
	clientHelloMaxBytes = 64 << 10
)

// errClientHelloSeen stops the TLS read once the ClientHello is parsed.
var errClientHelloSeen = errors.New("sandboxnet: client hello read")

// errClientHelloTooLarge refuses a ClientHello over the byte cap.
var errClientHelloTooLarge = errors.New("sandboxnet: client hello over the cap")

// helloConn feeds crypto/tls the client's bytes, keeps a copy of every byte
// read so they can be sent on unchanged, and discards whatever TLS writes
// (an alert never reaches the client).
type helloConn struct {
	r   io.Reader
	buf bytes.Buffer
}

func (h *helloConn) Read(p []byte) (int, error) {
	if h.buf.Len() >= clientHelloMaxBytes {
		return 0, errClientHelloTooLarge
	}
	if room := clientHelloMaxBytes - h.buf.Len(); len(p) > room {
		p = p[:room]
	}
	n, err := h.r.Read(p)
	h.buf.Write(p[:n])
	return n, err
}

func (h *helloConn) Write(p []byte) (int, error) { return len(p), nil }
func (h *helloConn) Close() error                { return nil }
func (h *helloConn) LocalAddr() net.Addr         { return &net.UnixAddr{Name: "gateway", Net: "unix"} }

func (h *helloConn) RemoteAddr() net.Addr             { return &net.UnixAddr{Name: "client", Net: "unix"} }
func (h *helloConn) SetDeadline(time.Time) error      { return nil }
func (h *helloConn) SetReadDeadline(time.Time) error  { return nil }
func (h *helloConn) SetWriteDeadline(time.Time) error { return nil }

// readClientHello reads the client's TLS ClientHello from r through
// crypto/tls's own parser and returns its server name and every byte read.
// seen is false when no ClientHello could be parsed.
func readClientHello(ctx context.Context, r io.Reader) (name string, raw []byte, seen bool) {
	hc := &helloConn{r: r}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			name, seen = info.ServerName, true
			return nil, errClientHelloSeen
		},
	}
	_ = tls.Server(hc, cfg).HandshakeContext(ctx)
	return name, hc.buf.Bytes(), seen
}

// checkTunnelName judges the ClientHello's server name against the CONNECT
// target host (already list-checked): "" passes, else the refusal rule.
func (g *Gateway) checkTunnelName(target, name string, seen bool) string {
	switch {
	case !seen || name == "":
		return RuleSNIAbsent
	case !strings.EqualFold(name, target) || g.Hosts.Check(name) != "":
		return RuleSNIMismatch
	}
	return ""
}

// admitTunnel is the host-list check of an established tunnel: it reads the
// ClientHello from client, refuses (logging the rule) when its server name
// is absent or is not target, and otherwise sends the ClientHello bytes on
// to upstream. ok false means both ends must be closed.
func (g *Gateway) admitTunnel(ctx context.Context, client, upstream net.Conn, target, port string) bool {
	_ = client.SetReadDeadline(time.Now().Add(clientHelloTimeout))
	hctx, cancel := context.WithTimeout(ctx, clientHelloTimeout)
	name, raw, seen := readClientHello(hctx, client)
	cancel()
	_ = client.SetReadDeadline(time.Time{})
	if rule := g.checkTunnelName(target, name, seen); rule != "" {
		logged := target
		if name != "" && rule == RuleSNIMismatch {
			logged = oneLine(name) + " via " + target
		}
		g.logger().Warn(LogEgressRefused, "host", logged, "port", port, "rules", rule)
		return false
	}
	if _, err := upstream.Write(raw); err != nil {
		return false
	}
	return true
}
