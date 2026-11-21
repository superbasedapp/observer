package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/netpolicy"
)

// ErrRefused is the sentinel every guard refusal wraps (it also wraps
// netpolicy.ErrDialRefused for a refused address), so a caller can tell "the
// guard refused this destination" from a network error with errors.Is.
var ErrRefused = errors.New("netguard: destination refused")

// Default bounds of a guarded client.
const (
	DefaultTimeout      = 30 * time.Second
	DefaultDialTimeout  = 10 * time.Second
	DefaultMaxRedirects = 5
)

// Policy is the set of non-public destinations one client may reach. The zero
// value is the strictest policy: public addresses only.
type Policy struct {
	// Classes admits whole classes (loopback, private). The org LLM
	// providers use it for their per-provider unlock; the shared default
	// client never sets it.
	Classes netpolicy.DialPolicy
	// AllowCIDRs admits loopback or private addresses inside these ranges.
	// A range can never admit a forbidden address (metadata, link-local,
	// multicast, unspecified): those are refused first.
	AllowCIDRs []netip.Prefix
}

// CheckIP applies the policy to one resolved address. host is carried only
// for the error text.
func (p Policy) CheckIP(host string, ip net.IP) error {
	class := netpolicy.ClassifyIP(ip)
	if p.Classes.Allows(class) {
		return nil
	}
	if class == netpolicy.ClassLoopback || class == netpolicy.ClassPrivate {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			addr = addr.Unmap()
			for _, c := range p.AllowCIDRs {
				if c.Contains(addr) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%w: %w", ErrRefused, p.Classes.CheckIP(host, ip))
}

// Check is a per-address decision: nil admits the dial.
type Check func(host string, ip net.IP) error

// Control returns a net.Dialer.Control hook that refuses a non-TCP dial and
// applies check to the resolved IP literal it is handed. This is the
// security boundary: it runs after DNS, per connection attempt.
func Control(check Check) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		if err := netpolicy.CheckDialNetwork(network); err != nil {
			return fmt.Errorf("%w: %w", ErrRefused, err)
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w: unparseable dial address %q", ErrRefused, address)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			// Control is called with a resolved literal; anything else means
			// an assumption broke, so fail closed rather than guess.
			return fmt.Errorf("%w: dial address %q is not an IP literal", ErrRefused, host)
		}
		return check(host, ip)
	}
}

// Options configures one guarded client.
type Options struct {
	// Policy decides which addresses may be dialed.
	Policy Policy
	// Check overrides Policy.CheckIP at dial time, for a caller that owns its
	// own refusal text (the LLM providers). nil uses Policy.CheckIP.
	Check Check
	// Timeout bounds one whole request; DefaultTimeout when <= 0.
	Timeout time.Duration
	// DialTimeout bounds one connection attempt; DefaultDialTimeout when <= 0.
	DialTimeout time.Duration
	// MaxRedirects bounds followed redirects: 0 means DefaultMaxRedirects, a
	// negative value refuses every redirect.
	MaxRedirects int
	// EnvProxy honours the server's HTTP(S)_PROXY (see the package doc).
	EnvProxy bool
	// Hint is appended to a refusal, naming how an operator admits a
	// destination they trust (for example the config key).
	Hint string
}

// NewClient builds a guarded client.
func NewClient(o Options) *http.Client {
	check := o.Check
	if check == nil {
		check = o.Policy.CheckIP
	}
	if o.Hint != "" {
		inner := check
		check = func(host string, ip net.IP) error {
			if err := inner(host, ip); err != nil {
				return fmt.Errorf("%w (%s)", err, o.Hint)
			}
			return nil
		}
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	guarded := &net.Dialer{Timeout: o.DialTimeout, KeepAlive: 30 * time.Second, Control: Control(check)}
	tr := &http.Transport{
		DialContext:           guarded.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if o.EnvProxy {
		proxies := envProxyAddrs()
		if len(proxies) > 0 {
			plain := &net.Dialer{Timeout: o.DialTimeout, KeepAlive: 30 * time.Second}
			tr.Proxy = proxyWithPreflight(check)
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if proxies[addr] {
					return plain.DialContext(ctx, network, addr)
				}
				return guarded.DialContext(ctx, network, addr)
			}
		}
	}
	return &http.Client{Transport: tr, Timeout: o.Timeout, CheckRedirect: redirectRule(o.MaxRedirects, check)}
}

// redirectRule re-checks every redirect hop: bounded, http(s) only, no
// https to http downgrade, and an IP-literal target checked before it is
// requested. A hostname target is checked at dial time like any request.
func redirectRule(max int, check Check) func(*http.Request, []*http.Request) error {
	if max == 0 {
		max = DefaultMaxRedirects
	}
	return func(req *http.Request, via []*http.Request) error {
		if max < 0 {
			return fmt.Errorf("%w: refusing redirect to %s", ErrRefused, req.URL.Host)
		}
		if len(via) >= max {
			return fmt.Errorf("%w: stopped after %d redirects", ErrRefused, max)
		}
		switch req.URL.Scheme {
		case "https":
		case "http":
			if len(via) > 0 && via[0].URL.Scheme == "https" {
				return fmt.Errorf("%w: refusing https to http redirect to %s", ErrRefused, req.URL.Host)
			}
		default:
			return fmt.Errorf("%w: refusing redirect to scheme %q", ErrRefused, req.URL.Scheme)
		}
		if ip := net.ParseIP(req.URL.Hostname()); ip != nil {
			return check(req.URL.Hostname(), ip)
		}
		return nil
	}
}

// proxyWithPreflight is http.ProxyFromEnvironment plus a pre-flight check of
// the TARGET: when a proxy will carry the request, the target is resolved
// here and every address it resolves to must pass check, since the dial-time
// hook only ever sees the proxy's address on that path.
func proxyWithPreflight(check Check) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		proxy, err := http.ProxyFromEnvironment(req)
		if err != nil || proxy == nil {
			return proxy, err
		}
		host := req.URL.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			return proxy, check(host, ip)
		}
		addrs, err := net.DefaultResolver.LookupIPAddr(req.Context(), host)
		if err != nil {
			return nil, fmt.Errorf("netguard: resolve %s before proxying: %w", host, err)
		}
		for _, a := range addrs {
			if err := check(host, a.IP); err != nil {
				return nil, err
			}
		}
		return proxy, nil
	}
}

// envProxyAddrs returns the host:port dial addresses of the proxies named in
// the environment, in the form http.Transport dials them.
func envProxyAddrs() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			// http.ProxyFromEnvironment also accepts a bare host:port.
			u, err = url.Parse("http://" + v)
			if err != nil || u.Host == "" {
				continue
			}
		}
		port := u.Port()
		if port == "" {
			switch u.Scheme {
			case "https":
				port = "443"
			case "socks5", "socks5h":
				port = "1080"
			default:
				port = "80"
			}
		}
		out[net.JoinHostPort(u.Hostname(), port)] = true
	}
	return out
}

// ParseCIDRs parses an allow-list of CIDR ranges (a bare address is a /32 or
// /128). A range that covers no loopback or private address admits nothing
// and is refused, so a typo cannot read as an allow.
func ParseCIDRs(raw []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		var p netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			p, err = netip.ParsePrefix(s)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(s)
			if err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			return nil, fmt.Errorf("netguard: %q is not a CIDR range or address", s)
		}
		p = p.Masked()
		c := netpolicy.ClassifyIP(net.IP(p.Addr().AsSlice()))
		if c != netpolicy.ClassLoopback && c != netpolicy.ClassPrivate {
			return nil, fmt.Errorf("netguard: %s is not a loopback or private range (metadata, link-local and public ranges cannot be allow-listed; public needs no entry)", p)
		}
		out = append(out, p)
	}
	return out, nil
}

// The process default: the allow-list the org server configured at boot, read
// by Client. One owner, set once at startup (Configure) and read on every
// client build.
var (
	defaultMu   sync.RWMutex
	defaultCIDR []netip.Prefix
	// defaultClients caches one default client per timeout, so a poller
	// that asks for its client on every request shares one transport (and
	// its idle connections) instead of building a new one each time.
	// Configure clears it.
	defaultClients = map[time.Duration]*http.Client{}
	defaultHint    = "admit a trusted private destination with [outbound] allow_private_cidrs"
)

// Configure sets the process-wide allow-list Client uses, from the org
// server's [outbound].allow_private_cidrs. It returns the parse error and
// leaves the previous list in place when a range is invalid.
func Configure(allowCIDRs []string) error {
	p, err := ParseCIDRs(allowCIDRs)
	if err != nil {
		return err
	}
	defaultMu.Lock()
	defaultCIDR = p
	defaultClients = map[time.Duration]*http.Client{}
	defaultMu.Unlock()
	return nil
}

// DefaultPolicy returns the process default policy: public destinations plus
// the configured allow-list. A caller that builds its own transport (the
// Identity page's connection probe) decides addresses with it, so it agrees
// with the clients Client builds.
func DefaultPolicy() Policy {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return Policy{AllowCIDRs: append([]netip.Prefix(nil), defaultCIDR...)}
}

// Client returns a guarded client under the process default policy (public
// destinations plus the configured allow-list), honouring the environment
// proxy and following at most DefaultMaxRedirects redirects. timeout <= 0
// means DefaultTimeout. It is the replacement for every http.DefaultClient
// fallback on a customer-supplied URL.
//
// Clients are cached per timeout until the next Configure, so repeated calls
// share one transport.
func Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if c, ok := defaultClients[timeout]; ok {
		return c
	}
	c := NewClient(Options{
		Policy:   Policy{AllowCIDRs: append([]netip.Prefix(nil), defaultCIDR...)},
		Timeout:  timeout,
		EnvProxy: true,
		Hint:     defaultHint,
	})
	defaultClients[timeout] = c
	return c
}
