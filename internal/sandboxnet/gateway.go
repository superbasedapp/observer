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

// LogEgressRefused is the message of every refusal the gateway logs, with
// the attributes host, port and rules (RefusalLogger keys on it).
const LogEgressRefused = "sandboxnet: egress refused"

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
	// Providers, when set, is the run's model-provider host block (section
	// 7.3, provider.go). Nil means the block is off.
	Providers *ProviderBlock
	// Hosts, when set, is the run's host allow-list (G23, hosts.go): a
	// target host must be listed, checked before any resolution, and a
	// literal-IP target is refused. Nil means no list: every public host
	// passes, as before the list existed (agent runs keep nil; only the
	// first-start install step's gateway sets one).
	Hosts *HostRules
	// Report, when set, receives every refusal (refusal.go): the host
	// helper hands it to the daemon for the refusal audit. It is called on
	// the request's goroutine, so it must not block (queue and return).
	// Nil reports nothing; the 403 body is the same either way.
	Report func(Refusal)
	// Closed, when set, is asked at the start of every CONNECT and
	// absolute-form request (tracker F-012, audit findings N4-A4 and
	// FU5-A5): a non-empty reason refuses the run's new requests, each
	// answered 503 with that reason before any policy check, resolution or
	// dial, and the idle upstream connections are dropped. A tunnel opened
	// before keeps running. It is not a refusal (nothing was
	// judged), so it is never reported; the caller counts what it closed.
	// The host helper sets it when the org requires the refusal audit and
	// its link to the daemon is lost. Nil never closes.
	Closed func() string

	once      sync.Once
	proxy     *httputil.ReverseProxy
	transport *http.Transport
}

// refuseClosed answers a request 503 when Closed names a reason, before
// anything else is done for it (CONNECT and absolute-form alike, so a
// request that would reuse a pooled upstream connection is refused too),
// and drops the absolute-form transport's idle upstream connections. A
// CONNECT tunnel opened before stays open: only new requests are refused
// (audit finding FU5-A5).
func (g *Gateway) refuseClosed(w http.ResponseWriter, target string) bool {
	if g.Closed == nil {
		return false
	}
	reason := g.Closed()
	if reason == "" {
		return false
	}
	g.logger().Warn("sandboxnet: egress closed", "target", target, "reason", reason)
	// The once orders this read after the transport is built.
	g.once.Do(g.initProxy)
	g.transport.CloseIdleConnections()
	http.Error(w, "sandbox egress gateway: "+reason, http.StatusServiceUnavailable)
	return true
}

// gatewayError carries the HTTP status and the short reason the gateway
// reports for a failed egress attempt. A refusal (refusal set) is answered
// with the structured 403 body whose message is reason; anything else with
// reason as plain text.
type gatewayError struct {
	status  int
	reason  string
	err     error
	refusal *Refusal
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
	if g.refuseClosed(w, target) {
		return
	}
	upstream, err := g.dialChecked(r.Context(), "tcp", target, formConnect)
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
	if g.Hosts != nil {
		// A listed name may sit on a shared edge: the tunnel carries only a
		// TLS session whose server name is the CONNECT target (tlsname.go).
		host, port, _ := splitTarget(target)
		if !g.admitTunnel(r.Context(), client, upstream, strings.ToLower(host), port) {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
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
	if g.refuseClosed(w, r.URL.Host) {
		return
	}
	g.proxy.ServeHTTP(w, r)
}

// initProxy builds the ReverseProxy used for absolute-form requests. The
// transport never consults the environment's proxy, never negotiates HTTP/2
// and never decompresses, so the response reaches the client as sent.
func (g *Gateway) initProxy() {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return g.dialChecked(ctx, network, addr, formAbsolute)
		},
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	g.transport = tr
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

// dialChecked is the ONE resolve-once + policy + dial-by-IP path shared by
// CONNECT (form formConnect) and the absolute-form transport (formAbsolute).
// Errors are *gatewayError.
func (g *Gateway) dialChecked(ctx context.Context, network, hostport string, form requestForm) (net.Conn, error) {
	host, port, err := splitTarget(hostport)
	if err != nil {
		return nil, &gatewayError{status: http.StatusBadRequest, reason: "sandbox egress gateway: " + err.Error()}
	}
	if rule := g.Hosts.Check(host); rule != "" {
		g.logger().Warn(LogEgressRefused, "host", host, "port", port, "rules", rule)
		return nil, g.refused(stageHosts, rule, host, port, "sandbox egress gateway: destination refused by rule "+rule+" (this run may reach only "+strings.Join(g.Hosts.Entries(), ", ")+")")
	}
	if g.Hosts != nil && !listedPortAllowed(form, port) {
		g.logger().Warn(LogEgressRefused, "host", host, "port", port, "rules", RulePortNotAllowed)
		return nil, g.refused(stagePort, RulePortNotAllowed, host, port, "sandbox egress gateway: destination refused by rule "+RulePortNotAllowed+" (this run may use only port 443 through CONNECT, or port 80 for a plain http request)")
	}
	if g.Hosts != nil {
		// The name resolved is the name the list checked.
		host = strings.ToLower(host)
	}
	if rule := g.Providers.checkTarget(host); rule != "" {
		g.logger().Warn(LogEgressRefused, "host", host, "port", port, "rules", rule)
		return nil, g.refused(stageProvider, rule, host, port, "sandbox egress gateway: destination refused by rule "+rule+providerHint)
	}
	local, err := g.localAddrs()
	if err != nil {
		g.logger().Warn("sandboxnet: egress refused, cannot list local addresses", "host", host, "err", err)
		return nil, g.refused(stageLocal, ruleLocalAddrsUnavailable, host, port, "sandbox egress gateway: destination refused by rule "+ruleLocalAddrsUnavailable)
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
		if rule := g.Providers.checkResolved(ips, g.resolve); rule != "" {
			g.logger().Warn(LogEgressRefused, "host", host, "port", port, "rules", rule)
			return nil, g.refused(stageProvider, rule, host, port, "sandbox egress gateway: destination refused by rule "+rule+providerHint)
		}
	}

	var chosen net.IP
	var rules []string
	allowListable := false
	// The rule the refusal is recorded under: the first allow-listable one
	// when any is (the one an operator can act on), else the first.
	recorded := ""
	policy := Policy{Allow: g.Allow}
	for _, ip := range ips {
		err := policy.Check(ip, local)
		if err == nil {
			chosen = ip
			break
		}
		var re *RefusedError
		if errors.As(err, &re) {
			if recorded == "" || (re.AllowListable && !allowListable) {
				recorded = re.Rule
			}
			allowListable = allowListable || re.AllowListable
			if !containsString(rules, re.Rule) {
				rules = append(rules, re.Rule)
			}
		}
	}
	if chosen != nil && parseLiteral(host) != nil {
		if rule := g.Providers.checkLiteral(chosen, g.Allow); rule != "" {
			g.logger().Warn(LogEgressRefused, "host", host, "port", port, "rules", rule)
			return nil, g.refused(stageProvider, rule, host, port, "sandbox egress gateway: destination refused by rule "+rule+providerHint)
		}
	}
	if chosen == nil {
		g.logger().Warn(LogEgressRefused, "host", host, "port", port, "rules", strings.Join(rules, ","))
		reason := "sandbox egress gateway: destination refused by rule " + strings.Join(rules, ", ")
		if allowListable {
			reason += " (to allow a private destination, add its CIDR to " + AllowCIDRsConfigKey + ")"
		}
		return nil, g.refused(stagePolicy, recorded, host, port, reason)
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

// refused reports a refusal of host:port by the gateway rule constant rule
// (found at stage) and returns its 403 error, whose message is reason.
func (g *Gateway) refused(stage refusalStage, rule, host, port, reason string) *gatewayError {
	r := g.report(stage, rule, host, port)
	return &gatewayError{status: http.StatusForbidden, reason: reason, refusal: &r}
}

// report builds the Refusal of host:port by rule and hands it to Report.
func (g *Gateway) report(stage refusalStage, rule, host, port string) Refusal {
	closed, key := mapAt(stage, rule)
	if key == KeyEgressAllowHosts && g.Hosts != nil {
		// A host list that is not the owner's names its own key.
		key = g.Hosts.Key()
	}
	n, _ := strconv.Atoi(port)
	r := Refusal{Host: host, Port: n, Rule: closed, Key: key, At: time.Now().UTC()}
	if g.Report != nil {
		g.Report(r)
	}
	return r
}

// writeError renders err: a refusal as the structured 403 body
// (refusal.go), anything else as a short plain-text response.
func (g *Gateway) writeError(w http.ResponseWriter, err error) {
	var ge *gatewayError
	if errors.As(err, &ge) {
		if ge.refusal != nil {
			WriteRefusal(w, *ge.refusal, ge.reason)
			return
		}
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
