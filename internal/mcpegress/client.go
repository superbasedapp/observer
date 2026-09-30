package mcpegress

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/netpolicy"
)

// ClientConfig tunes the guarded client. The zero value takes the defaults,
// and its zero proxy posture is DIRECT: a guarded client never takes a proxy
// from the process environment (HTTPS_PROXY / HTTP_PROXY) or from a Base
// transport, because a proxy moves the destination decision off the dial
// hook (Sol fold 5 finding 1). A proxy is only ever an explicit choice.
type ClientConfig struct {
	// Timeout bounds one whole request (default 30 s).
	Timeout time.Duration
	// DialTimeout bounds one connection attempt (default 10 s).
	DialTimeout time.Duration
	// MaxResponseBytes bounds every response body read by this package's
	// discovery helpers (default 4 MiB).
	MaxResponseBytes int64
	// UserAgent is sent on every request (default "superbased-observer-mcpegress").
	UserAgent string
	// Base is an optional transport template; its TLS config is kept, its
	// dialers AND its proxy are replaced (the proxy comes only from Proxy /
	// WithExplicitProxy). nil = http.DefaultTransport's shape.
	Base *http.Transport
	// Proxy is an explicit per-request proxy selector (for example
	// http.ProxyFromEnvironment on a developer's own machine). nil = direct
	// dial, the guarded default. The dial to whatever proxy it selects is
	// still checked against the client's DialPolicy, exactly like a direct
	// dial; the proxy then decides where the request lands.
	Proxy func(*http.Request) (*url.URL, error)

	// explicitProxy is the operator's trusted egress proxy set through
	// WithExplicitProxy; it wins over Proxy.
	explicitProxy *url.URL
}

const (
	defaultTimeout          = 30 * time.Second
	defaultDialTimeout      = 10 * time.Second
	defaultMaxResponseBytes = 4 << 20
	defaultUserAgent        = "superbased-observer-mcpegress"
)

// trustedProxyPolicy is the dial policy for the connection to an explicit,
// operator-configured egress proxy: it may sit on loopback or a private
// range (the observer-mcpgw egress role binds loopback), but link-local /
// cloud metadata / multicast / unspecified stay refused.
var trustedProxyPolicy = netpolicy.DialPolicy{AllowLoopback: true, AllowPrivate: true}

// WithExplicitProxy returns c routed through u, the operator's trusted
// egress proxy ([agent_access].egress_proxy_url): EVERY request of the
// client goes through u, and the destination decision moves to that proxy
// (the recommended one is observer-mcpgw's own egress CONNECT proxy, which
// applies the same netpolicy per resolved address). The dial to u itself is
// checked against a proxy policy that admits loopback and private ranges and
// still refuses link-local / metadata / multicast. u == nil returns c
// unchanged (direct dial).
func (c ClientConfig) WithExplicitProxy(u *url.URL) ClientConfig {
	if u == nil {
		return c
	}
	cp := *u
	c.explicitProxy = &cp
	return c
}

// ExplicitProxy reports the trusted egress proxy WithExplicitProxy set (nil
// = none).
func (c ClientConfig) ExplicitProxy() *url.URL {
	if c.explicitProxy == nil {
		return nil
	}
	cp := *c.explicitProxy
	return &cp
}

func (c ClientConfig) withDefaults() ClientConfig {
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = defaultDialTimeout
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = defaultMaxResponseBytes
	}
	if c.UserAgent == "" {
		c.UserAgent = defaultUserAgent
	}
	return c
}

// proxyAuthority is the "host:port" the transport dials for proxy u (the
// scheme's default port when u names none) - the same canonical form
// net/http hands DialContext.
func proxyAuthority(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// noRedirect makes the client return a 3xx verbatim instead of following it
// (ENT-2: Go keeps custom credential headers across a cross-host redirect).
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// NewClient builds one guarded *http.Client for policy: the dial-time
// netpolicy hook, no redirects, HTTP/2 kept, and NO ambient proxy (direct
// dial unless cfg names a proxy explicitly). Callers that need several
// policies should use a Pool so each policy keeps its own connection pool.
func NewClient(policy netpolicy.DialPolicy, cfg ClientConfig) *http.Client {
	cfg = cfg.withDefaults()
	var transport *http.Transport
	if cfg.Base != nil {
		transport = cfg.Base.Clone()
	} else if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = dt.Clone()
	} else {
		transport = &http.Transport{}
	}
	// Never inherit a proxy: http.DefaultTransport's clone carries
	// ProxyFromEnvironment, and with a proxy selected the dial hook below
	// sees only the proxy's address (Sol fold 5 finding 1).
	transport.Proxy = nil
	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second,
		Control:   policy.Control(),
	}
	dial := dialer.DialContext
	switch {
	case cfg.explicitProxy != nil:
		transport.Proxy = http.ProxyURL(cfg.explicitProxy)
		trusted := proxyAuthority(cfg.explicitProxy)
		proxyDialer := &net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: 30 * time.Second,
			Control:   trustedProxyPolicy.Control(),
		}
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			if host, port, err := net.SplitHostPort(address); err == nil && net.JoinHostPort(strings.ToLower(host), port) == trusted {
				return proxyDialer.DialContext(ctx, network, address)
			}
			return dialer.DialContext(ctx, network, address)
		}
	case cfg.Proxy != nil:
		transport.Proxy = cfg.Proxy
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dial(ctx, network, address)
	}
	// A DialTLSContext would bypass DialContext (and the Control hook)
	// entirely, so a base transport never keeps one; ForceAttemptHTTP2 is
	// re-asserted because a custom DialContext otherwise disables h2.
	transport.DialTLSContext = nil
	transport.ForceAttemptHTTP2 = true
	return &http.Client{Transport: transport, CheckRedirect: noRedirect, Timeout: cfg.Timeout}
}

// Pool is the per-policy set of guarded clients. Build it once and share it.
type Pool struct {
	cfg     ClientConfig
	mu      sync.Mutex
	clients map[netpolicy.DialPolicy]*http.Client
}

// NewPool returns an empty pool that builds clients with cfg on demand.
func NewPool(cfg ClientConfig) *Pool {
	return &Pool{cfg: cfg.withDefaults(), clients: map[netpolicy.DialPolicy]*http.Client{}}
}

// Client returns the guarded client for policy, building it on first use.
func (p *Pool) Client(policy netpolicy.DialPolicy) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[policy]; ok {
		return c
	}
	c := NewClient(policy, p.cfg)
	p.clients[policy] = c
	return c
}

// Config returns the pool's effective configuration (defaults applied).
func (p *Pool) Config() ClientConfig { return p.cfg }
