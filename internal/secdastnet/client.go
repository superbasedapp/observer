package secdastnet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/marmutapp/superbased-observer/internal/secdast"
)

// UserAgent is the one User-Agent every request carries.
const UserAgent = "superbased-observer-dast/" + secdast.Version

// MaxRoundTrips is the most HTTP round trips one client makes, redirects
// included (twice secdast.MaxRequests).
const MaxRoundTrips = 2 * secdast.MaxRequests

// ErrRefused wraps every refusal of the loopback rule.
var ErrRefused = errors.New("secdastnet: refused")

// Options are a client's settings.
type Options struct {
	// InsecureTLS accepts an untrusted certificate on an https loopback dev
	// server (a self-signed development certificate). The address is still
	// held to loopback.
	InsecureTLS bool
	// LookupIP resolves the target host once; nil uses the system resolver.
	// A test seam.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
}

// Client makes a run's requests to one loopback target.
type Client struct {
	t      secdast.Target
	ip     net.IP
	client *http.Client

	mu     sync.Mutex
	trips  int
	closed bool
}

// New resolves the target host once and builds the client. It refuses a
// target whose host is not a loopback name or literal, and a host that
// resolves to any address that is not loopback (secdast.IsLoopbackAddr).
func New(ctx context.Context, t secdast.Target, opts Options) (*Client, error) {
	if !secdast.IsLoopbackHost(t.Host) || t.Port == "" || (t.Scheme != "http" && t.Scheme != "https") {
		return nil, fmt.Errorf("%w: %s is not a loopback http(s) target with a port", ErrRefused, t.Origin())
	}
	ip, err := resolveLoopback(ctx, t.Host, opts.LookupIP)
	if err != nil {
		return nil, err
	}
	c := &Client{t: t, ip: ip}
	dialer := &net.Dialer{Timeout: secdast.RequestTimeout, Control: loopbackControl}
	pinned := net.JoinHostPort(ip.String(), t.Port)
	tr := &http.Transport{
		// Never a proxy from the environment: the request would leave the
		// machine through it.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if _, port, err := net.SplitHostPort(addr); err != nil || port != t.Port {
				return nil, fmt.Errorf("%w: dial to %q is not the target's port", ErrRefused, addr)
			}
			return dialer.DialContext(ctx, network, pinned)
		},
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         tlsServerName(t.Host),
			InsecureSkipVerify: opts.InsecureTLS, //nolint:gosec // G402: opt-in, loopback dev server only; the address is pinned to loopback.
		},
		TLSHandshakeTimeout:    secdast.RequestTimeout,
		ResponseHeaderTimeout:  secdast.RequestTimeout,
		MaxResponseHeaderBytes: secdast.MaxHeaderBytes,
		// Bodies are read as sent, so the cap is a cap on the bytes read.
		DisableCompression: true,
		MaxIdleConns:       1,
		MaxConnsPerHost:    2,
		ForceAttemptHTTP2:  false,
	}
	c.client = &http.Client{
		Transport: tr,
		// Redirects are followed by Fetch itself, on the origin only.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       secdast.RequestTimeout,
	}
	return c, nil
}

// Close releases idle connections; the client makes no request after it.
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.client.CloseIdleConnections()
}

// RoundTrips is how many round trips the client made.
func (c *Client) RoundTrips() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.trips
}

// Fetch is a secdast.Fetch: one GET of an origin-relative path, following
// same-origin redirects up to secdast.MaxRedirects.
func (c *Client) Fetch(ctx context.Context, req secdast.Request) secdast.Response {
	resp := secdast.Response{RequestID: req.ID, Path: req.Path}
	if !strings.HasPrefix(req.Path, "/") || strings.HasPrefix(req.Path, "//") || strings.ContainsAny(req.Path, " \r\n\t\\") {
		resp.Err = fmt.Sprintf("%v: %q is not an origin-relative path", ErrRefused, req.Path)
		return resp
	}
	if req.Origin != "" && req.Origin != secdast.CanaryOrigin {
		resp.Err = fmt.Sprintf("%v: only the canary Origin header is sent", ErrRefused)
		return resp
	}
	path := req.Path
	for hop := 0; ; hop++ {
		r, err := c.roundTrip(ctx, path, req.Origin)
		if err != nil {
			resp.Err = err.Error()
			return resp
		}
		resp.Path, resp.Status, resp.Header = path, r.status, r.header
		resp.Body, resp.Truncated = r.body, r.truncated
		if r.status < 300 || r.status > 399 || r.location == "" {
			return resp
		}
		next, ok := c.t.SameOrigin(path, r.location)
		if !ok {
			resp.OffOriginRedirect = true
			return resp
		}
		if hop >= secdast.MaxRedirects {
			return resp
		}
		path = next
	}
}

type answer struct {
	status    int
	header    secdast.Header
	body      []byte
	truncated bool
	location  string
}

func (c *Client) roundTrip(ctx context.Context, path, origin string) (answer, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return answer{}, fmt.Errorf("%w: the client is closed", ErrRefused)
	}
	if c.trips >= MaxRoundTrips {
		c.mu.Unlock()
		return answer{}, fmt.Errorf("%w: the run's %d round trips are used", ErrRefused, MaxRoundTrips)
	}
	c.trips++
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, secdast.RequestTimeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, c.t.URL(path), nil)
	if err != nil {
		return answer{}, err
	}
	if !strings.EqualFold(hr.URL.Hostname(), c.t.Host) || hr.URL.Port() != c.t.Port || hr.URL.User != nil {
		return answer{}, fmt.Errorf("%w: %s is off the target's origin", ErrRefused, hr.URL.Redacted())
	}
	hr.Header.Set("User-Agent", UserAgent)
	hr.Header.Set("Accept", "*/*")
	if origin != "" {
		hr.Header.Set("Origin", origin)
	}
	res, err := c.client.Do(hr)
	if err != nil {
		return answer{}, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, secdast.MaxBodyBytes+1))
	if err != nil {
		return answer{}, err
	}
	a := answer{status: res.StatusCode, header: secdast.Header{}, location: res.Header.Get("Location")}
	if len(body) > secdast.MaxBodyBytes {
		body, a.truncated = body[:secdast.MaxBodyBytes], true
	}
	a.body = body
	for k, v := range res.Header {
		a.header[strings.ToLower(k)] = append([]string(nil), v...)
	}
	return a, nil
}

// resolveLoopback resolves host once and refuses unless every address is
// loopback; it returns the first.
func resolveLoopback(ctx context.Context, host string, lookup func(context.Context, string) ([]net.IP, error)) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !loopbackIP(ip) {
			return nil, fmt.Errorf("%w: %s is not a loopback address", ErrRefused, ip)
		}
		return ip, nil
	}
	if lookup == nil {
		lookup = func(ctx context.Context, h string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, h)
			out := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				out = append(out, a.IP)
			}
			return out, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, secdast.RequestTimeout)
	defer cancel()
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("secdastnet: resolving %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s resolved to no address", ErrRefused, host)
	}
	for _, ip := range ips {
		if !loopbackIP(ip) {
			return nil, fmt.Errorf("%w: %s resolves to %s, which is not a loopback address", ErrRefused, host, ip)
		}
	}
	return ips[0], nil
}

// loopbackControl is the dialer's Control hook: TCP only, and the resolved
// address must be loopback.
func loopbackControl(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("%w: refusing non-TCP network %q", ErrRefused, network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable dial address %q", ErrRefused, address)
	}
	ip := net.ParseIP(host)
	if ip == nil || !loopbackIP(ip) {
		return fmt.Errorf("%w: %s is not a loopback address", ErrRefused, host)
	}
	return nil
}

// loopbackIP is secdast.IsLoopbackAddr for a net.IP (127.0.0.0/8 or ::1;
// stricter than internal/netpolicy, which reads a NAT64 or 6to4 address
// embedding 127/8 as loopback).
func loopbackIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	return ok && secdast.IsLoopbackAddr(a)
}

// tlsServerName is the SNI and verification name: the host itself
// ("localhost"), or "" for an IP literal (Go checks the IP SAN then).
func tlsServerName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}
