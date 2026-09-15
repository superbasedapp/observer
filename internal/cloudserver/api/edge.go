package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// DefaultEdgeAuthHeader is the default private header name used to
	// authenticate the Cloudflare-to-ACA proxy hop.
	DefaultEdgeAuthHeader = "X-SBCI-Edge-Auth"
	// EdgeClientIPHeader is the private client-IP copy the trusted edge sends
	// to the API. The Worker copies the inbound Cloudflare value into this
	// header before the cross-zone ACA fetch. It is accepted only after the
	// edge-authentication proof succeeds; an inbound CF-Connecting-IP header is
	// deliberately never used by the API because Cloudflare may rewrite it on
	// the subrequest.
	EdgeClientIPHeader = "X-SBCI-Client-IP"
	// EdgeHostHeader is the authenticated original Host value supplied by the
	// edge when the edge fetches an ACA origin FQDN. It is accepted only after
	// the private edge proof succeeds and is then used by the canonical-host
	// fence; generic forwarded-host headers are never trusted.
	EdgeHostHeader = "X-SBCI-Edge-Host"

	// defaultEdgeAuthHeader is the private hop-authentication header used when
	// an authenticated Cloudflare-to-ACA proxy hop is configured. It is not a
	// substitute for HTTPS: the origin must still be HTTPS-only.
	defaultEdgeAuthHeader = DefaultEdgeAuthHeader
	// edgeClientIPHeader is the private forwarded identity accepted by this
	// service. X-Forwarded-For, Forwarded, and the reserved CF-Connecting-IP
	// header are intentionally ignored by the API.
	edgeClientIPHeader = EdgeClientIPHeader
	// cloudflareConnectingIPHeader is retained solely as a reserved header name
	// to strip from the request before application middleware sees it. It is
	// never parsed as an API client identity.
	cloudflareConnectingIPHeader = "CF-Connecting-IP"
	// edgeHostHeader is kept private at call sites so the header cannot be
	// confused with an ordinary client-controlled Host value.
	edgeHostHeader = EdgeHostHeader
)

var (
	errEdgeUntrusted = errors.New("cloudserver/api: untrusted edge peer")
	errEdgeIdentity  = errors.New("cloudserver/api: invalid edge client identity")
	errEdgeConfig    = errors.New("cloudserver/api: invalid edge configuration")
)

// EdgeConfig describes the origin/edge trust boundary. When Enabled is true,
// every route except /healthz must arrive from a trusted peer and carry one
// canonical private client-IP value. A peer may be authenticated either by
// TrustedPeerCIDRs (the direct TCP peer is in one of those networks), or by a
// configured AuthSecret on the authenticated proxy hop. When both are set,
// both checks are required. AuthSecret comparisons are constant-time.
//
// With Enabled false, forwarded client-IP headers are ignored and rate limits
// use the canonical direct peer address. Supplying either AuthSecret or
// TrustedPeerCIDRs implicitly enables the edge fence, preventing a partially
// configured production deployment from silently trusting forwarded identity.
type EdgeConfig struct {
	Enabled bool
	// TrustedPeerCIDRs are CIDR networks from which the service accepts direct
	// proxy connections. Values are parsed and masked once at New/Handler time.
	TrustedPeerCIDRs []string
	// AuthHeader is the private proxy-hop header. Empty uses
	// X-SBCI-Edge-Auth.
	AuthHeader string
	// AuthSecret is the expected value of AuthHeader. Empty means CIDR-only
	// trust; it is only valid when TrustedPeerCIDRs is non-empty.
	AuthSecret string
}

// edgeConfig is the parsed, immutable request-time form of EdgeConfig.
type edgeConfig struct {
	enabled      bool
	trustedPeers []netip.Prefix
	authHeader   string
	authSecret   string
	err          error
}

func parseEdgeConfig(cfg EdgeConfig) edgeConfig {
	parsed := edgeConfig{
		enabled:    cfg.Enabled || len(cfg.TrustedPeerCIDRs) > 0 || strings.TrimSpace(cfg.AuthSecret) != "",
		authHeader: strings.TrimSpace(cfg.AuthHeader),
		authSecret: strings.TrimSpace(cfg.AuthSecret),
	}
	if parsed.authHeader == "" {
		parsed.authHeader = defaultEdgeAuthHeader
	}
	for _, raw := range cfg.TrustedPeerCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			parsed.err = errors.Join(parsed.err, errors.Join(errEdgeConfig, err))
			continue
		}
		parsed.trustedPeers = append(parsed.trustedPeers, prefix.Masked())
	}
	if parsed.enabled && len(parsed.trustedPeers) == 0 && parsed.authSecret == "" {
		// Enabled-with-no-proof would be an origin-wide trust bypass. Requiring
		// either a peer network or a secret keeps a mistaken empty list safe.
		parsed.err = errors.Join(parsed.err, errEdgeConfig)
	}
	if !parsed.enabled && (len(parsed.trustedPeers) > 0 || parsed.authSecret != "") {
		// This is unreachable because those fields imply enabled, but keep the
		// invariant explicit if the parser changes later.
		parsed.err = errors.Join(parsed.err, errEdgeConfig)
	}
	// A secret-only authenticated proxy hop (authSecret set, no trustedPeers) is
	// deliberately accepted: it is the ACA shape, where the direct TCP peer is an
	// internal Envoy whose address is not a stable Cloudflare range. The secret
	// is the peer-authentication proof in that deployment; direct origin access
	// without it is refused.
	return parsed
}

// clientIPContextKey carries the one canonical client address selected by the
// outer edge middleware. Keeping it in context ensures every limiter dimension
// uses exactly the same identity decision for one request.
type clientIPContextKey struct{}

// edgeClientIP returns the already-selected request identity, or derives a
// canonical direct peer for tests that call a middleware in isolation.
func edgeClientIP(r *http.Request) (string, error) {
	if r == nil {
		return "", errEdgeIdentity
	}
	if ip, ok := r.Context().Value(clientIPContextKey{}).(string); ok && ip != "" {
		return ip, nil
	}
	return directPeerIP(r.RemoteAddr)
}

// parseSingleIP accepts exactly one textual IPv4 or IPv6 address and returns
// its stable netip spelling. IPv4-mapped IPv6 addresses are un-mapped so one
// endpoint cannot consume two counter keys for the same IPv4 client.
func parseSingleIP(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, ", \t\r\n") {
		return "", errEdgeIdentity
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" {
		return "", errEdgeIdentity
	}
	return addr.Unmap().String(), nil
}

// directPeerIP extracts and canonicalizes the TCP peer from RemoteAddr. The
// standard server supplies host:port; accepting a bare address keeps direct
// unit tests and httptest handlers straightforward without accepting arbitrary
// strings as rate-limit keys.
func directPeerIP(remote string) (string, error) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", errEdgeIdentity
	}
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		return parseSingleIP(host)
	}
	return parseSingleIP(remote)
}

// hasTrustedPeer reports whether the direct TCP peer is covered by one of the
// configured networks. It is deliberately evaluated before reading the
// forwarded client header, so an untrusted caller cannot influence the key or
// learn whether its spoofed value parsed.
func (c edgeConfig) hasTrustedPeer(remote string) bool {
	ipText, err := directPeerIP(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		return false
	}
	for _, prefix := range c.trustedPeers {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// headerValuesFold returns all values for a header name, including entries
// whose map keys were not canonicalized by net/http. Network requests normally
// arrive canonicalized, but accepting a hand-built request with one key while
// silently ignoring a second differently-cased key would undermine the
// duplicate-header refusal invariant at middleware boundaries and in tests.
func headerValuesFold(header http.Header, name string) []string {
	var values []string
	for key, entries := range header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	return values
}

// validAuthHeader verifies one and only one private hop-authentication header.
// Multiple values are rejected even when they are byte-identical; accepting
// duplicates would make intermediaries disagree about which value was signed.
func (c edgeConfig) validAuthHeader(r *http.Request) bool {
	if c.authSecret == "" {
		return true
	}
	values := headerValuesFold(r.Header, c.authHeader)
	if len(values) != 1 {
		return false
	}
	presented := sha256.Sum256([]byte(values[0]))
	expected := sha256.Sum256([]byte(c.authSecret))
	return subtle.ConstantTimeCompare(presented[:], expected[:]) == 1
}

// forwardedClientIP reads exactly one private edge client-IP field.
// Header.Get is intentionally not used because it silently selects the first
// value when a request carries duplicate fields. Comma-lists are likewise
// rejected rather than picking a side of an ambiguous proxy chain. The
// reserved CF-Connecting-IP field is never read here: Cloudflare may rewrite
// that field on a cross-zone Worker subrequest.
func forwardedClientIP(r *http.Request) (string, error) {
	values := headerValuesFold(r.Header, edgeClientIPHeader)
	if len(values) != 1 {
		return "", errEdgeIdentity
	}
	return parseSingleIP(values[0])
}

// parseEdgeHost canonicalizes the authenticated original host. It accepts a
// DNS name (or an IP literal) with an optional valid port, but never a URL,
// path, userinfo, comma-list, or unbracketed IPv6 spelling. The result is the
// same lower-case, port-free form used by the canonical-host middleware.
func parseEdgeHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, ", \t\r\n/?#@") || strings.Contains(raw, "://") {
		return "", errEdgeIdentity
	}
	host := raw
	if strings.Contains(raw, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(raw)
		if err != nil || host == "" || port == "" {
			return "", errEdgeIdentity
		}
		for _, r := range port {
			if r < '0' || r > '9' {
				return "", errEdgeIdentity
			}
		}
		if n := len(port); n > 5 || (n > 1 && port[0] == '0') {
			return "", errEdgeIdentity
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 {
			return "", errEdgeIdentity
		}
	}
	if host == "" || strings.ContainsAny(host, "[]:") {
		return "", errEdgeIdentity
	}
	canonical := normalizeHost(raw)
	if canonical == "" || strings.ContainsAny(canonical, "[]:") {
		return "", errEdgeIdentity
	}
	return canonical, nil
}

// forwardedEdgeHost reads exactly one authenticated original-host field.
// Duplicate values are rejected even when byte-identical, just like the
// client-IP field: no intermediary may make the service choose between two
// interpretations of one request.
func forwardedEdgeHost(r *http.Request) (string, error) {
	values := headerValuesFold(r.Header, edgeHostHeader)
	if len(values) != 1 {
		return "", errEdgeIdentity
	}
	return parseEdgeHost(values[0])
}

type edgeRequestIdentity struct {
	clientIP string
	host     string
}

func (c edgeConfig) requestIdentity(r *http.Request) (edgeRequestIdentity, error) {
	if r == nil {
		return edgeRequestIdentity{}, errEdgeUntrusted
	}
	if !c.enabled {
		ip, err := directPeerIP(r.RemoteAddr)
		return edgeRequestIdentity{clientIP: ip}, err
	}
	if c.err != nil {
		return edgeRequestIdentity{}, c.err
	}
	// Always parse the direct peer, even in secret-only proxy-hop mode. The
	// secret authenticates the hop, while a syntactically valid TCP peer keeps
	// an empty/garbled RemoteAddr from becoming an accepted identity boundary.
	peer, peerErr := directPeerIP(r.RemoteAddr)
	if peerErr != nil {
		return edgeRequestIdentity{}, errEdgeUntrusted
	}
	if len(c.trustedPeers) > 0 && !c.hasTrustedPeer(peer) {
		return edgeRequestIdentity{}, errEdgeUntrusted
	}
	if !c.validAuthHeader(r) {
		return edgeRequestIdentity{}, errEdgeUntrusted
	}
	ip, err := forwardedClientIP(r)
	if err != nil {
		return edgeRequestIdentity{}, err
	}
	host, err := forwardedEdgeHost(r)
	if err != nil {
		return edgeRequestIdentity{}, err
	}
	return edgeRequestIdentity{clientIP: ip, host: host}, nil
}

// edgeRequestIP authenticates the edge and selects one client IP. In the
// unenforced local/development posture it intentionally ignores every
// forwarded header and uses the direct peer. In enforced posture any proof
// failure or malformed forwarded identity is a refusal, never a fallback to a
// potentially attacker-controlled alternate key.
func (c edgeConfig) edgeRequestIP(r *http.Request) (string, error) {
	identity, err := c.requestIdentity(r)
	return identity.clientIP, err
}

// enforceTrustedEdge is the outer edge fence. /healthz stays reachable by
// Container Apps' health probes, which hit the container directly and do not
// carry Cloudflare headers; all other paths receive one canonical client IP in
// context before routing or rate limiting.
func (s *Server) enforceTrustedEdge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			stripEdgeProofHeaders(r, s.edge.authHeader)
			next.ServeHTTP(w, r)
			return
		}
		if !s.edge.enabled {
			// Even in direct/local mode the reserved edge fields are not
			// application data. Remove them before inner middleware/loggers can
			// persist or accidentally start trusting them in a future route.
			stripEdgeProofHeaders(r, s.edge.authHeader)
			next.ServeHTTP(w, r)
			return
		}
		identity, err := s.edge.requestIdentity(r)
		if err != nil {
			switch {
			case errors.Is(err, errEdgeUntrusted):
				writeErr(w, http.StatusForbidden, "edge_untrusted", "request did not arrive through the trusted edge")
			case errors.Is(err, errEdgeConfig):
				if s.log != nil {
					s.log.Error("cloudserver/api: invalid edge configuration", "err", err)
				}
				writeErr(w, http.StatusServiceUnavailable, "edge_not_configured", "edge trust is not configured")
			default:
				writeErr(w, http.StatusBadRequest, "invalid_edge_identity", "the edge did not provide one valid client identity")
			}
			return
		}
		ctx := context.WithValue(r.Context(), clientIPContextKey{}, identity.clientIP)
		// The ACA origin request's Host may be its *.azurecontainerapps.io
		// FQDN. Only the authenticated edge value may replace it; generic
		// X-Forwarded-Host is never consulted. The inner canonical-host fence
		// then checks this value against the configured /v1 or /portal host.
		r = r.WithContext(ctx)
		r.Host = identity.host
		// These fields are proof material, not application data. Remove them
		// before any inner middleware/handler (including request logging) sees
		// the request, so the shared secret and edge-supplied identity cannot be
		// accidentally persisted or reinterpreted downstream. Delete keys using
		// EqualFold as requests assembled by tests or non-net/http callers may
		// not have canonicalized their map keys.
		stripEdgeProofHeaders(r, s.edge.authHeader)
		next.ServeHTTP(w, r)
	})
}

// stripEdgeProofHeaders removes all edge-only headers from a request. The
// operation is deliberately case-insensitive because requests assembled by
// tests and non-net/http callers are not required to use net/http's canonical
// map keys. In particular, the reserved CF-Connecting-IP header is removed
// even though it is never trusted or parsed by the API.
func stripEdgeProofHeaders(r *http.Request, authHeader string) {
	if r == nil {
		return
	}
	for key := range r.Header {
		if strings.EqualFold(key, authHeader) ||
			strings.EqualFold(key, edgeHostHeader) ||
			strings.EqualFold(key, edgeClientIPHeader) ||
			strings.EqualFold(key, cloudflareConnectingIPHeader) {
			delete(r.Header, key)
		}
	}
}
