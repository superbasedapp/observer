package sandboxnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultDialTimeout bounds the zero-value Dial.
const defaultDialTimeout = 15 * time.Second

// ruleLocalAddrsUnavailable is the reason reported when the host's own
// interface addresses cannot be listed; the gateway then fails closed.
const ruleLocalAddrsUnavailable = "local-addresses-unavailable"

// connectEstablished is the reply sent on the hijacked conn after a
// successful CONNECT dial.
const connectEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"

// Gateway is an HTTP forward proxy for the sandbox egress tier. Zero-value
// fields fall back to real I/O: Resolve -> net.DefaultResolver.LookupIPAddr
// (return the IPs), Dial -> (&net.Dialer{Timeout: 15s}).DialContext,
// LocalAddrs -> the IPs of net.InterfaceAddrs(), Logger -> slog.Default().
//
// The host's interface addresses are listed on every dial (no cache), and a
// failure to list them refuses the request. A Gateway must not be copied
// after first use.
type Gateway struct {
	// Resolve returns the addresses of a host name. Literal IPs never reach it.
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
	// Dial connects to an "ip:port" address that already passed the policy.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// LocalAddrs lists the host's own interface addresses (refused as
	// destinations).
	LocalAddrs func() ([]net.IP, error)
	// Allow is the operator's allow-list of private prefixes
	// (AllowCIDRsConfigKey, built with ParseAllowCIDRs). Empty refuses every
	// private, shared-address and unique-local destination.
	Allow []netip.Prefix
	// Logger receives refusals and upstream failures. Nil means slog.Default().
	Logger *slog.Logger

	once  sync.Once
	proxy *httputil.ReverseProxy
}

// gatewayError carries the HTTP status and the short plain-text reason the
// gateway reports for a failed egress attempt.
type gatewayError struct {
	status int
	reason string
	err    error
}

func (e *gatewayError) Error() string {
	if e.err != nil {
		return e.reason + ": " + e.err.Error()
	}
	return e.reason
}

func (e *gatewayError) Unwrap() error { return e.err }

// ServeHTTP handles:
//   - CONNECT host:port -> resolve host ONCE (a literal IP skips resolution),
//     keep only addresses DestinationAllowed accepts, dial the FIRST allowed
//     address by IP (never re-resolving the name, so there is no DNS-rebinding
//     TOCTOU), hijack, reply "HTTP/1.1 200 Connection Established", then pipe
//     both ways with ServeForward's half-close discipline. Nothing allowed ->
//     403 naming the refused rule; resolution or dial failure -> 502; a
//     missing or invalid port -> 400.
//   - absolute-form http requests -> forwarded through an http.Transport whose
//     DialContext applies the same resolve-once + policy + dial-by-IP logic,
//     with Proxy nil, hop-by-hop headers (incl. Proxy-Authorization and
//     Proxy-Connection) stripped both ways, and the response streamed back.
//     https absolute-form -> 400 (use CONNECT); any other scheme -> 400.
//   - anything else (origin-form, i.e. talking to the gateway as if it were
//     the origin server) -> 400.
//
// It never follows redirects itself; the client does.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		g.serveConnect(w, r)
	case r.URL != nil && r.URL.IsAbs():
		switch strings.ToLower(r.URL.Scheme) {
		case "http":
			g.serveForward(w, r)
		case "https":
			http.Error(w, "sandbox egress gateway: https requests must use CONNECT", http.StatusBadRequest)
		default:
			http.Error(w, "sandbox egress gateway: unsupported scheme", http.StatusBadRequest)
		}
	default:
		http.Error(w, "sandbox egress gateway: this is a forward proxy; send CONNECT or an absolute-form http request", http.StatusBadRequest)
	}
}

// serveConnect tunnels a CONNECT request.
func (g *Gateway) serveConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" && r.URL != nil {
		target = r.URL.Host
	}
	upstream, err := g.dialAllowed(r.Context(), "tcp", target)
	if err != nil {
		g.writeError(w, err)
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		_ = upstream.Close()
		g.logger().Warn("sandboxnet: CONNECT hijack failed", "target", target, "err", err)
		http.Error(w, "sandbox egress gateway: connection cannot be tunnelled", http.StatusInternalServerError)
		return
	}
	// The server may have set deadlines on the conn; a tunnel lives as long
	// as both ends want it to.
	_ = conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, connectEstablished); err != nil {
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	client := conn
	if brw != nil && brw.Reader.Buffered() > 0 {
		client = &bufferedConn{Conn: conn, r: brw.Reader}
	}
	pipe(r.Context(), client, upstream)
}

// serveForward proxies an absolute-form http request.
func (g *Gateway) serveForward(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "sandbox egress gateway: missing host", http.StatusBadRequest)
		return
	}
	g.once.Do(g.initProxy)
	g.proxy.ServeHTTP(w, r)
}

// initProxy builds the ReverseProxy used for absolute-form requests. The
// transport never consults the environment's proxy, never negotiates HTTP/2
// and never decompresses, so the response reaches the client as sent.
func (g *Gateway) initProxy() {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           g.dialAllowed,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	g.proxy = &httputil.ReverseProxy{
		// The inbound URL is already absolute; keep it and the Host.
		// ReverseProxy strips hop-by-hop headers (Connection and the headers
		// it lists, Keep-Alive, Proxy-Authenticate, Proxy-Authorization,
		// Proxy-Connection, TE, Trailer, Transfer-Encoding, Upgrade) in both
		// directions, and the client-supplied Forwarded/X-Forwarded-* headers.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.Host = pr.In.Host
		},
		Transport:     tr,
		FlushInterval: -1,
		ErrorLog:      slog.NewLogLogger(g.logger().Handler(), slog.LevelWarn),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			g.writeError(w, err)
		},
	}
}

// dialAllowed is the ONE resolve-once + policy + dial-by-IP path shared by
// CONNECT and the absolute-form transport. Errors are *gatewayError.
func (g *Gateway) dialAllowed(ctx context.Context, network, hostport string) (net.Conn, error) {
	host, port, err := splitTarget(hostport)
	if err != nil {
		return nil, &gatewayError{status: http.StatusBadRequest, reason: "sandbox egress gateway: " + err.Error()}
	}
	local, err := g.localAddrs()
	if err != nil {
		g.logger().Warn("sandboxnet: egress refused, cannot list local addresses", "host", host, "err", err)
		return nil, &gatewayError{status: http.StatusForbidden, reason: "sandbox egress gateway: destination refused by rule " + ruleLocalAddrsUnavailable}
	}
	var ips []net.IP
	if ip := parseLiteral(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = g.resolve(ctx, host)
		if err != nil {
			g.logger().Warn("sandboxnet: egress resolve failed", "host", host, "err", err)
			return nil, &gatewayError{status: http.StatusBadGateway, reason: "sandbox egress gateway: cannot resolve host", err: err}
		}
		if len(ips) == 0 {
			return nil, &gatewayError{status: http.StatusBadGateway, reason: "sandbox egress gateway: host has no addresses"}
		}
	}

	var chosen net.IP
	var rules []string
	allowListable := false
	policy := Policy{Allow: g.Allow}
	for _, ip := range ips {
		err := policy.Check(ip, local)
		if err == nil {
			chosen = ip
			break
		}
		var re *RefusedError
		if errors.As(err, &re) {
			allowListable = allowListable || re.AllowListable
			if !containsString(rules, re.Rule) {
				rules = append(rules, re.Rule)
			}
		}
	}
	if chosen == nil {
		g.logger().Warn("sandboxnet: egress refused", "host", host, "port", port, "rules", strings.Join(rules, ","))
		reason := "sandbox egress gateway: destination refused by rule " + strings.Join(rules, ", ")
		if allowListable {
			reason += " (to allow a private destination, add its CIDR to " + AllowCIDRsConfigKey + ")"
		}
		return nil, &gatewayError{status: http.StatusForbidden, reason: reason}
	}

	if !strings.HasPrefix(network, "tcp") {
		network = "tcp"
	}
	addr := net.JoinHostPort(chosen.String(), port)
	conn, err := g.dial(ctx, network, addr)
	if err != nil {
		g.logger().Warn("sandboxnet: egress dial failed", "host", host, "addr", addr, "err", err)
		return nil, &gatewayError{status: http.StatusBadGateway, reason: "sandbox egress gateway: cannot reach destination", err: err}
	}
	return conn, nil
}

// writeError renders err as a short plain-text response.
func (g *Gateway) writeError(w http.ResponseWriter, err error) {
	var ge *gatewayError
	if errors.As(err, &ge) {
		http.Error(w, ge.reason, ge.status)
		return
	}
	g.logger().Warn("sandboxnet: upstream request failed", "err", err)
	http.Error(w, "sandbox egress gateway: upstream request failed", http.StatusBadGateway)
}

// splitTarget splits host:port and validates both halves; the port must be a
// decimal number in 1..65535.
func splitTarget(hostport string) (string, string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", "", fmt.Errorf("target %q needs host:port", hostport)
	}
	if host == "" {
		return "", "", fmt.Errorf("target %q has no host", hostport)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", "", fmt.Errorf("target %q has an invalid port", hostport)
	}
	return host, strconv.FormatUint(n, 10), nil
}

// parseLiteral returns host as an IP when it is an IP literal (a zone suffix
// is dropped), or nil when it is a name.
func parseLiteral(host string) net.IP {
	a, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	return net.IP(a.WithZone("").AsSlice())
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (g *Gateway) logger() *slog.Logger {
	if g.Logger != nil {
		return g.Logger
	}
	return slog.Default()
}

func (g *Gateway) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if g.Resolve != nil {
		return g.Resolve(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("sandboxnet.Gateway.resolve: %w", err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

func (g *Gateway) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if g.Dial != nil {
		return g.Dial(ctx, network, addr)
	}
	return (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(ctx, network, addr)
}

func (g *Gateway) localAddrs() ([]net.IP, error) {
	if g.LocalAddrs != nil {
		return g.LocalAddrs()
	}
	return InterfaceIPs()
}

// InterfaceIPs returns the IPs of every address net.InterfaceAddrs reports.
// It is the zero-value Gateway.LocalAddrs.
func InterfaceIPs() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("sandboxnet.InterfaceIPs: %w", err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ips = append(ips, v.IP)
		case *net.IPAddr:
			ips = append(ips, v.IP)
		}
	}
	return ips, nil
}
