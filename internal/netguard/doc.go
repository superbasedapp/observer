// Package netguard is the ONE owner of the SSRF-guarded HTTP client the org
// server uses for every outbound call to a URL a customer or admin supplied
// (MS-R-001, managed SaaS plan H3/H8/H9): alert and budget webhooks, IdP
// metadata / discovery / JWKS fetches, the vendor analytics pollers, and the
// org LLM providers (internal/orgserver/llmprovider builds its client here
// with its own unlock table and error text).
//
// It is built on the shared classifier: internal/ipclass via
// internal/netpolicy. The guard has three parts, and the third is the
// boundary:
//
//   - a deny table: link-local and cloud metadata (169.254.0.0/16,
//     fe80::/10), multicast, the unspecified address, 0.0.0.0/8 and the
//     deprecated ::/96 form are never dialed, whatever the policy says;
//     loopback and private space (RFC 1918, CGNAT, ULA) are dialed only when
//     the policy admits the class or an explicit allow-listed CIDR covers the
//     address (Policy.AllowCIDRs, the org server's
//     [outbound].allow_private_cidrs); public space is always reachable;
//   - redirects are re-checked: a bounded number, http(s) only, never an
//     https to http downgrade, and an IP-literal target is refused before
//     the request is sent;
//   - the dial-time check: net.Dialer.Control runs on the address the
//     resolver actually produced, per connection attempt, so a DNS answer
//     that flips between any pre-flight check and the dial (rebinding) is
//     caught, and a name with several A records is checked per address.
//
// Every client has a non-zero whole-request timeout.
//
// Proxy: a client built with EnvProxy honours the server's HTTP(S)_PROXY, as
// http.DefaultClient did, so a deployment that egresses through a corporate
// proxy keeps working. The proxy itself is operator configuration and is
// dialed as configured; the TARGET is then checked before the request is
// handed to the proxy, by resolving it and checking every address. That
// pre-flight cannot see a rebinding answer the proxy resolves later, so the
// dial-time guarantee belongs to the proxy on that path. A client built
// without EnvProxy (the LLM providers) never uses a proxy.
package netguard
