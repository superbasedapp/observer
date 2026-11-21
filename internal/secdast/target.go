package secdast

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ComponentID is the catalog id of the checker.
const ComponentID = "security.dast"

// Driver is the engine name a finding carries; Version is the check table's
// version (bumped when a row is added, removed or changes what it reports).
const (
	Driver  = "observer-dast"
	Version = "1"
)

// The caps every run is held to (section 14.9: "bodies capped"; the lane
// enforces each again on its side).
const (
	// MaxRequests is the most requests one run makes (the fixed probes,
	// the scripts and their maps come to at most 4 + 2*MaxScripts).
	MaxRequests = 16
	// MaxScripts is the most same-origin scripts whose source map is looked
	// for.
	MaxScripts = 3
	// MaxBodyBytes is the most bytes of one response body read; the rest is
	// never read and the response is marked truncated.
	MaxBodyBytes = 256 << 10
	// MaxHeaderBytes is the most bytes of one response's headers.
	MaxHeaderBytes = 64 << 10
	// MaxRedirects is the most same-origin redirects followed for one
	// request; a redirect off the origin is never followed.
	MaxRedirects = 3
	// RequestTimeout is one request's limit, RunTimeout the whole run's.
	RequestTimeout = 5 * time.Second
	RunTimeout     = 30 * time.Second
)

// CanaryOrigin is the Origin header the page request carries, to read the
// CORS answer. It is a name under the reserved .invalid top-level domain
// (RFC 2606), so it can never be resolved or contacted: it only names a
// foreign origin for the server to reflect, or not.
const CanaryOrigin = "https://observer-dast-canary.invalid"

// Target is the one dev server a run checks: a loopback origin and the page
// path the developer named.
type Target struct {
	// Scheme is "http" or "https".
	Scheme string
	// Host is "localhost", an IPv4 address in 127.0.0.0/8 or an IPv6
	// loopback address, lower case, without brackets.
	Host string
	// Port is the explicit port, decimal.
	Port string
	// Path is the page path, "/" when none was typed; the query is kept
	// (RawQuery) and the fragment dropped.
	Path     string
	RawQuery string
}

// ErrNotLoopback is the refusal of a target whose host is not a loopback
// literal or "localhost".
var ErrNotLoopback = errors.New("secdast: the target must be localhost, 127.0.0.0/8 or ::1")

// ParseTarget validates a typed URL: http or https, a loopback host
// (IsLoopbackHost: "localhost" or a loopback IP literal, nothing
// that merely resolves to one), an explicit port, no user information. The
// lane checks the resolved address again at dial time.
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, errors.New("secdast: no URL")
	}
	if len(raw) > 2048 {
		return Target{}, errors.New("secdast: the URL is over 2048 bytes")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("secdast: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Target{}, fmt.Errorf("secdast: %q is not an http or https URL (type it as http://localhost:<port>/)", raw)
	}
	if u.Opaque != "" || u.Host == "" {
		return Target{}, fmt.Errorf("secdast: %q has no host", raw)
	}
	if u.User != nil {
		return Target{}, errors.New("secdast: a URL with user information is refused (no credential is ever sent)")
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, "%") || !IsLoopbackHost(host) {
		return Target{}, fmt.Errorf("%w (got %q)", ErrNotLoopback, u.Hostname())
	}
	port := u.Port()
	if port == "" {
		return Target{}, fmt.Errorf("secdast: %q has no port: name the dev server's port (for example http://localhost:3000/)", raw)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return Target{}, fmt.Errorf("secdast: %q is not a port", port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return Target{}, fmt.Errorf("secdast: %q is not an absolute path", path)
	}
	return Target{Scheme: scheme, Host: host, Port: port, Path: path, RawQuery: u.RawQuery}, nil
}

// HTTPS reports whether the target is served over TLS.
func (t Target) HTTPS() bool { return t.Scheme == "https" }

// hostPort is the host and port as they appear in a URL authority.
func (t Target) hostPort() string {
	if strings.Contains(t.Host, ":") {
		return "[" + t.Host + "]:" + t.Port
	}
	return t.Host + ":" + t.Port
}

// Origin is scheme://host:port.
func (t Target) Origin() string { return t.Scheme + "://" + t.hostPort() }

// Page is the origin-relative page path with its query.
func (t Target) Page() string {
	if t.RawQuery != "" {
		return t.Path + "?" + t.RawQuery
	}
	return t.Path
}

// String is the page URL.
func (t Target) String() string { return t.Origin() + t.Page() }

// URL is the absolute URL of an origin-relative path.
func (t Target) URL(path string) string { return t.Origin() + path }

// SameOrigin resolves ref (absolute, scheme-relative, or relative to base,
// an origin-relative path) and returns its origin-relative path with query
// when it is on the target's origin: the same scheme, host and effective
// port. Anything else, a data: URI included, is not on the origin.
func (t Target) SameOrigin(base, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > 2048 {
		return "", false
	}
	b, err := url.Parse(t.URL(base))
	if err != nil {
		return "", false
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	u := b.ResolveReference(r)
	if strings.ToLower(u.Scheme) != t.Scheme || u.User != nil {
		return "", false
	}
	if strings.ToLower(u.Hostname()) != t.Host || effectivePort(u) != t.Port {
		return "", false
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p, true
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}
