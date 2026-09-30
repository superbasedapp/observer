package mcpegress

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/netpolicy"
)

// Transport vocabulary (mcp_server.transport, plan section 3.2).
const (
	TransportStreamableHTTP = "streamable_http"
	TransportSSELegacy      = "sse_legacy"
	TransportNodeLocalStdio = "node_local_stdio"
	TransportOpenAPI        = "openapi"
)

// Options is one server's egress posture: the transport (which decides
// whether there is a URL to dial at all) and the org's typed per-server
// unlock of loopback + private ranges.
type Options struct {
	Transport string
	// AllowPrivateNetwork admits loopback, RFC 1918, CGNAT and ULA addresses
	// for THIS server. Link-local / metadata / multicast stay refused.
	AllowPrivateNetwork bool
}

// DialPolicyFor resolves the options to the dial-time policy. The table has
// two rows and no third: the flag unlocks loopback AND private together
// (a self-hosted upstream on the perimeter is the one legitimate case for
// either), and nothing unlocks ClassForbidden.
//
//	allow_private_network   public  loopback  private  forbidden
//	false                   yes     no        no       no
//	true                    yes     yes       yes      no
func DialPolicyFor(o Options) netpolicy.DialPolicy {
	if !o.AllowPrivateNetwork {
		return netpolicy.DialPolicy{}
	}
	return netpolicy.DialPolicy{AllowLoopback: true, AllowPrivate: true}
}

// ErrUpstreamBaseURL is the sentinel every ValidateUpstreamBaseURL refusal
// wraps, so a store can classify a rejected URL as the CALLER's mistake
// (ErrInvalid / 400) with errors.Is, without parsing the message.
var ErrUpstreamBaseURL = errors.New("mcpegress: upstream base URL rejected")

// dialingTransports are the transports that dial a URL; the others carry no
// URL and skip the preflight.
var dialingTransports = map[string]bool{TransportStreamableHTTP: true, TransportSSELegacy: true, TransportOpenAPI: true}

// Dials reports whether transport reaches an upstream over the network.
func Dials(transport string) bool { return dialingTransports[transport] }

// ValidateUpstreamBaseURL is the PRE-FLIGHT check (doc.go). It rejects:
//
//   - an empty / unparseable URL, a URL with no host, or one embedding
//     credentials (user:pass@);
//   - a scheme other than https / http, and plain http to anything that is
//     not a loopback host unless the server's private-network unlock is set
//     (a cleartext upstream credential on the wire);
//   - a host LITERAL in the unconditionally-forbidden class (169.254.0.0/16
//     cloud metadata, fe80::/10, multicast, unspecified, 0.0.0.0/8, the
//     IPv4-compatible ::/96 form, NAT64/6to4-wrapped forms of those) - no
//     option unlocks these;
//   - a loopback or private LITERAL (incl. IPv4-mapped IPv6 and "localhost")
//     unless AllowPrivateNetwork is set.
//
// A hostname passes preflight whatever it resolves to; the dial-time policy
// decides. A non-dialing transport (node_local_stdio) skips the check.
func ValidateUpstreamBaseURL(raw string, o Options) error {
	if !Dials(o.Transport) {
		return nil
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%w: url is required for transport %s", ErrUpstreamBaseURL, o.Transport)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: not a valid URL: %w", ErrUpstreamBaseURL, err)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: url must not embed credentials", ErrUpstreamBaseURL)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("%w: url %q has no host", ErrUpstreamBaseURL, raw)
	}
	policy := DialPolicyFor(o)
	loopbackHost := netpolicy.IsLoopbackHost(host)
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !loopbackHost && !policy.AllowPrivate {
			return fmt.Errorf("%w: url must use https (plain http is accepted only for a loopback host or with allow_private_network)", ErrUpstreamBaseURL)
		}
	default:
		return fmt.Errorf("%w: scheme %q is not supported (use https, or http for a loopback/private upstream)", ErrUpstreamBaseURL, parsed.Scheme)
	}
	if loopbackHost && !policy.AllowLoopback {
		return fmt.Errorf("%w: loopback host %q is refused unless allow_private_network is set for this server", ErrUpstreamBaseURL, host)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if err := policy.CheckIP(host, ip); err != nil {
		return fmt.Errorf("%w: %w", ErrUpstreamBaseURL, err)
	}
	return nil
}
