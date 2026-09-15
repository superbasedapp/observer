package proxy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/netip"
	"strings"
)

// promptGuardScopeNamespace separates prompt-guard fallback keys from every
// other identifier the observer may derive. The returned key contains only
// this namespace and a digest; the request's lane, user-agent, and address
// are never stored or sent to an upstream as part of this fallback.
const promptGuardScopeNamespace = "observer/prompt-guard-scope/v1"

// promptGuardUpstreamID gives fixed provider lanes and configured /up lanes
// distinct identities even when an operator happens to name a lane after a
// provider (for example, /up/anthropic). The provider remains a separate
// hashed dimension in resolvePromptGuardScopeID.
func promptGuardUpstreamID(laneID, provider string) string {
	if laneID = strings.TrimSpace(laneID); laneID != "" {
		return "lane:" + laneID
	}
	if provider = strings.TrimSpace(provider); provider != "" {
		return "provider:" + provider
	}
	return ""
}

// resolvePromptGuardScopeID returns the session scope used by the prompt
// guard's ask-once state. An existing session identity always wins and is
// returned byte-for-byte. When no real identity exists, a stable local scope
// is derived from the routed upstream identity, provider, user-agent, and
// canonical remote host. The fallback is deliberately guard-only: callers
// must keep it out of api_turns, observer traces, cost attribution, and
// forwarded request metadata.
//
// A scope cannot be derived safely without all four dimensions. Invalid or
// missing request metadata therefore returns an empty string, preserving the
// prompt guard's existing fail-closed behavior for an empty session scope.
// This is a local correlation key, not authentication: clients sharing the
// same lane, user-agent, and host intentionally share ask-once state.
func resolvePromptGuardScopeID(r *http.Request, explicitSessionID, upstreamID, provider string) string {
	if explicitSessionID != "" {
		return explicitSessionID
	}
	if r == nil {
		return ""
	}
	userAgent := strings.TrimSpace(r.UserAgent())
	if userAgent == "" {
		return ""
	}
	remoteHost, ok := normalizePromptGuardRemoteHost(r.RemoteAddr)
	if !ok {
		return ""
	}
	upstreamID = strings.TrimSpace(upstreamID)
	provider = strings.TrimSpace(provider)
	if upstreamID == "" || provider == "" {
		return ""
	}

	// Length-prefix each component so a delimiter in user-controlled header
	// text cannot create an ambiguous tuple before hashing. The digest keeps
	// raw user-agent/address values out of local guard keys and log surfaces.
	h := sha256.New()
	writePromptGuardScopePart(h, promptGuardScopeNamespace)
	writePromptGuardScopePart(h, upstreamID)
	writePromptGuardScopePart(h, provider)
	writePromptGuardScopePart(h, userAgent)
	writePromptGuardScopePart(h, remoteHost)
	return promptGuardScopeNamespace + ":" + hex.EncodeToString(h.Sum(nil))
}

// normalizePromptGuardRemoteHost validates the server's remote address and
// returns its canonical host without the source port. net/http supplies an
// IP:port TCP address here; netip both rejects malformed/missing ports and
// normalizes IPv4/IPv6 spellings consistently across reconnects.
func normalizePromptGuardRemoteHost(remoteAddr string) (string, bool) {
	addrPort, err := netip.ParseAddrPort(remoteAddr)
	if err != nil || !addrPort.IsValid() {
		return "", false
	}
	addr := addrPort.Addr()
	if !addr.IsValid() {
		return "", false
	}
	// Treat IPv4-mapped IPv6 spellings as the same IPv4 host. This avoids a
	// needless scope split when a local listener changes address formatting.
	return addr.Unmap().String(), true
}

func writePromptGuardScopePart(h interface{ Write([]byte) (int, error) }, part string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(part)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(part))
}
