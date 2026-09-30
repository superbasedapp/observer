package dpop

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// CanonicalHTU normalises an htu for comparison (RFC 9449 §4.3 with RFC 3986
// §6 syntax normalisation): scheme and host lower-cased, the default port
// (443/https, 80/http) dropped, an empty path rendered "/", and the query and
// fragment REMOVED. Only http(s) absolute URIs without userinfo are valid.
func CanonicalHTU(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 {
		return "", errors.New("dpop: htu empty or too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("dpop: htu: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("dpop: htu scheme %q", u.Scheme)
	}
	if u.User != nil || u.Opaque != "" {
		return "", errors.New("dpop: htu carries userinfo or is opaque")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("dpop: htu has no host")
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// RequestInfo is the transport view of an inbound request the verifier
// reconstructs htu from. It is filled at the HTTP boundary (the caller owns
// net/http; this package does not).
type RequestInfo struct {
	// TLS is true when the connection terminated TLS at OUR listener.
	TLS bool
	// Host is the Host header / :authority as received.
	Host string
	// Path is the escaped request path.
	Path string
	// RemoteAddr is the immediate peer "ip:port".
	RemoteAddr string
	// ForwardedProto / ForwardedHost are the raw X-Forwarded-Proto /
	// X-Forwarded-Host values (possibly comma lists). They are honoured ONLY
	// when RemoteAddr is inside a trusted-proxy CIDR.
	ForwardedProto, ForwardedHost string
}

// CanonicalRequestHTU reconstructs the canonical request URI. X-Forwarded-*
// is honoured only when the immediate peer is a configured trusted proxy
// (the TLS terminator, §14.3), and then only its LAST list element - the
// value the trusted hop appended, never one a client injected upstream of it.
func CanonicalRequestHTU(ri RequestInfo, trustedProxyCIDRs []string) (string, error) {
	scheme, host := "http", ri.Host
	if ri.TLS {
		scheme = "https"
	}
	trusted, err := peerTrusted(ri.RemoteAddr, trustedProxyCIDRs)
	if err != nil {
		return "", err
	}
	if trusted {
		if p := lastListValue(ri.ForwardedProto); p != "" {
			scheme = strings.ToLower(p)
		}
		if h := lastListValue(ri.ForwardedHost); h != "" {
			host = h
		}
	}
	if host == "" {
		return "", errors.New("dpop: request has no host")
	}
	path := ri.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "", errors.New("dpop: request path is not absolute")
	}
	return CanonicalHTU(scheme + "://" + host + path)
}

func lastListValue(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ",")
	return strings.TrimSpace(parts[len(parts)-1])
}

func peerTrusted(remoteAddr string, cidrs []string) (bool, error) {
	if len(cidrs) == 0 || remoteAddr == "" {
		return false, nil
	}
	ap, err := netip.ParseAddrPort(remoteAddr)
	var addr netip.Addr
	if err == nil {
		addr = ap.Addr()
	} else if addr, err = netip.ParseAddr(remoteAddr); err != nil {
		return false, nil // unparseable peer is never trusted
	}
	addr = addr.Unmap()
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return false, fmt.Errorf("dpop: trusted proxy CIDR %q: %w", c, err)
		}
		if p.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}
