package cloudpop

import (
	"fmt"
	"net/url"
	"strings"
)

// CanonicalHTU returns the canonical form of an HTTP target URL for the `htu`
// claim, so both signer and verifier derive the same string from the same
// request regardless of incidental framing.
//
// Canonicalization rules (a subset of RFC 3986 §6):
//
//   - scheme is lowercased; only "http" and "https" are accepted.
//   - host is lowercased; the default port (80 for http, 443 for https) is
//     removed, any other port is kept. IPv6 literals keep their brackets.
//   - query and fragment are dropped entirely.
//   - the path is taken from the raw escaped path (an empty path becomes "/")
//     and its percent-encoding is normalized per RFC 3986 §6.2.2: hex digits
//     are uppercased, and ONLY the unreserved set (ALPHA / DIGIT / "-" / "." /
//     "_" / "~") is percent-decoded. Reserved and other octets stay
//     percent-encoded.
//
// The last rule is load-bearing for security: "/a%2Fb" and "/a/b" MUST NOT
// canonicalize to the same string, because they address different resources.
// Because "%2F" decodes to '/', which is not unreserved, it is left encoded
// (uppercased), so the two forms stay distinct.
func CanonicalHTU(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("cloudpop.CanonicalHTU: parse: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("cloudpop.CanonicalHTU: unsupported scheme %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("cloudpop.CanonicalHTU: missing host in %q", raw)
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && !isDefaultPort(scheme, port) {
		host += ":" + port
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	normPath, err := normalizePercentEncoding(path)
	if err != nil {
		return "", fmt.Errorf("cloudpop.CanonicalHTU: %w", err)
	}
	return scheme + "://" + host + normPath, nil
}

// isDefaultPort reports whether port is the scheme's default and can be
// dropped.
func isDefaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

// normalizePercentEncoding rewrites every %XX sequence in s to canonical form:
// uppercased hex, with unreserved octets decoded to their literal character.
// Everything else is passed through unchanged. It never fully decodes the
// string, so encoded reserved characters (notably "%2F") survive as encoded.
func normalizePercentEncoding(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("truncated percent-encoding at %q", s[i:])
		}
		hi, ok1 := fromHexDigit(s[i+1])
		lo, ok2 := fromHexDigit(s[i+2])
		if !ok1 || !ok2 {
			return "", fmt.Errorf("invalid percent-encoding %q", s[i:i+3])
		}
		decoded := hi<<4 | lo
		if isUnreserved(decoded) {
			b.WriteByte(decoded)
		} else {
			b.WriteByte('%')
			b.WriteByte(toUpperHexDigit(hi))
			b.WriteByte(toUpperHexDigit(lo))
		}
		i += 2
	}
	return b.String(), nil
}

// isUnreserved reports whether c is in RFC 3986's unreserved set.
func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '_' || c == '~':
		return true
	default:
		return false
	}
}

// fromHexDigit decodes a single ASCII hex digit.
func fromHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// toUpperHexDigit encodes a nibble as an uppercase ASCII hex digit.
func toUpperHexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + (n - 10)
}
