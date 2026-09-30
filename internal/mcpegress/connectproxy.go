package mcpegress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/netpolicy"
)

// ConnectProxyOptions configures a ConnectProxy (the observer-mcpgw `egress`
// role, R8.23.b / R9.11: the agentgateway backendTunnel target).
type ConnectProxyOptions struct {
	// Policy is the address-class policy every CONNECT authority is checked
	// against AFTER resolution, per resolved address. The zero value is the
	// strictest (public only); the org unlocks loopback + private through
	// the same typed netpolicy.DialPolicy the discovery client uses.
	Policy netpolicy.DialPolicy
	// Allow lists CONNECT authorities ("host:port", exactly as requested)
	// admitted regardless of the class their addresses fall in. It is the
	// per-server unlock seam for a self-hosted upstream on the perimeter;
	// ClassForbidden (link-local / metadata / multicast) is still refused.
	Allow []string
	// Resolver overrides DNS (tests). nil = net.DefaultResolver.
	Resolver func(ctx context.Context, host string) ([]netip.Addr, error)
	// DialTimeout bounds the upstream dial (default 5 s); ResolveTimeout
	// bounds the lookup (default 5 s).
	DialTimeout, ResolveTimeout time.Duration
	// Log receives one entry per CONNECT attempt (nil = kept in the ring
	// buffer only).
	Log func(ConnectLog)
	// LogKeep bounds the in-memory ring of recent attempts (default 256).
	LogKeep int
}

// ConnectLog is one CONNECT attempt as the proxy saw it.
type ConnectLog struct {
	At       time.Time
	Target   string   // the CONNECT authority as requested
	Resolved []string // the addresses the proxy resolved it to
	Dialed   string   // the exact address dialed ("" when refused)
	Allowed  bool
	Reason   string
}

// ConnectProxy is the HTTP CONNECT egress proxy: it resolves DNS itself,
// applies the DialPolicy to EVERY resolved address (the only unlock is the
// exact-authority allow-list, and never for ClassForbidden), dials the
// CHECKED literal address (never re-resolving, so a rebinding answer cannot
// slip in between check and dial) and logs every attempt. Non-CONNECT
// requests are refused. The listener bind is the caller's job: loopback-only
// is a network posture (the role binds loopback unless listener mTLS is
// configured), never a property of this type.
type ConnectProxy struct {
	opts  ConnectProxyOptions
	allow map[string]bool

	mu       sync.Mutex
	recent   []ConnectLog
	attempts int64
	refused  int64
}

// NewConnectProxy builds a proxy; it is an http.Handler.
func NewConnectProxy(o ConnectProxyOptions) *ConnectProxy {
	if o.DialTimeout <= 0 {
		o.DialTimeout = 5 * time.Second
	}
	if o.ResolveTimeout <= 0 {
		o.ResolveTimeout = 5 * time.Second
	}
	if o.LogKeep <= 0 {
		o.LogKeep = 256
	}
	p := &ConnectProxy{opts: o, allow: map[string]bool{}}
	for _, a := range o.Allow {
		p.allow[strings.ToLower(strings.TrimSpace(a))] = true
	}
	return p
}

// Recent returns a copy of the most recent CONNECT attempts (newest last).
func (p *ConnectProxy) Recent() []ConnectLog {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ConnectLog(nil), p.recent...)
}

// Stats returns the attempt / refusal counters.
func (p *ConnectProxy) Stats() (attempts, refused int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.attempts, p.refused
}

func (p *ConnectProxy) record(l ConnectLog) {
	p.mu.Lock()
	p.attempts++
	if !l.Allowed {
		p.refused++
	}
	p.recent = append(p.recent, l)
	if len(p.recent) > p.opts.LogKeep {
		p.recent = p.recent[len(p.recent)-p.opts.LogKeep:]
	}
	p.mu.Unlock()
	if p.opts.Log != nil {
		p.opts.Log(l)
	}
}

func (p *ConnectProxy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	if p.opts.Resolver != nil {
		return p.opts.Resolver(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ErrEgressRefused is the sentinel wrapped by every policy refusal so a
// caller can distinguish "refused by policy" from a network error.
var ErrEgressRefused = errors.New("mcpegress: egress refused")

// ErrEgressResolve marks a refusal caused by name resolution (the authority
// could not be resolved at all), distinct from a policy refusal; it wraps
// ErrEgressRefused.
var ErrEgressResolve = errors.New("mcpegress: egress resolve failed")

// Check resolves target ("host:port") and applies the policy to every
// address; it returns the address to dial or the refusal. It is the
// decision the handler makes, exposed for tests and for the doctor probe.
func (p *ConnectProxy) Check(ctx context.Context, target string) (dial string, resolved []string, err error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", nil, fmt.Errorf("%w: bad authority %q", ErrEgressRefused, target)
	}
	rctx, cancel := context.WithTimeout(ctx, p.opts.ResolveTimeout)
	defer cancel()
	addrs, err := p.resolve(rctx, host)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w: %q: %w", ErrEgressRefused, ErrEgressResolve, host, err)
	}
	if len(addrs) == 0 {
		return "", nil, fmt.Errorf("%w: %w: %q: no addresses", ErrEgressRefused, ErrEgressResolve, host)
	}
	for _, a := range addrs {
		resolved = append(resolved, a.String())
	}
	allowListed := p.allow[strings.ToLower(target)]
	for _, a := range addrs {
		ip := net.IP(a.Unmap().AsSlice())
		class := netpolicy.ClassifyIP(ip)
		if class == netpolicy.ClassForbidden {
			return "", resolved, fmt.Errorf("%w: %s resolves to %s, which is never permitted", ErrEgressRefused, host, a)
		}
		if allowListed {
			continue
		}
		if cerr := p.opts.Policy.CheckIP(host, ip); cerr != nil {
			return "", resolved, fmt.Errorf("%w: %w", ErrEgressRefused, cerr)
		}
	}
	return net.JoinHostPort(addrs[0].Unmap().String(), port), resolved, nil
}

// ServeHTTP implements the CONNECT method.
func (p *ConnectProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	target := r.Host
	l := ConnectLog{At: time.Now().UTC(), Target: target}
	dialAddr, resolved, err := p.Check(r.Context(), target)
	l.Resolved = resolved
	if err != nil {
		l.Reason = err.Error()
		p.record(l)
		status := http.StatusForbidden
		if errors.Is(err, ErrEgressResolve) {
			status = http.StatusBadGateway
		}
		http.Error(w, "egress denied", status)
		return
	}
	dctx, cancel := context.WithTimeout(r.Context(), p.opts.DialTimeout)
	defer cancel()
	up, err := (&net.Dialer{Timeout: p.opts.DialTimeout}).DialContext(dctx, "tcp", dialAddr)
	if err != nil {
		l.Reason = fmt.Sprintf("dial %s: %v", dialAddr, err)
		p.record(l)
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	l.Allowed, l.Dialed, l.Reason = true, dialAddr, "allowed"
	p.record(l)
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	cl, buf, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	_, _ = cl.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if n := buf.Reader.Buffered(); n > 0 {
		b, _ := buf.Reader.Peek(n)
		_, _ = up.Write(b)
	}
	go func() { _, _ = io.Copy(up, cl); _ = up.Close() }()
	go func() { _, _ = io.Copy(cl, up); _ = cl.Close() }()
}
