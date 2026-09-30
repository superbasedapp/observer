// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package discover

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"sort"
	"strings"
)

// Transport classes. A node reports the transport its client config declared
// (internal/guard/mcpsec vocabulary: "stdio" for a command server, the
// declared remote type - "http", "sse", "streamable-http", ... - for a URL
// server); discovery reduces it to one of these two classes, the only
// distinction the locator identity and the adoption plan need.
const (
	ClassStdio  = "stdio"
	ClassRemote = "remote"
)

// Registry transports (the mcp_server.transport CHECK vocabulary, server
// migration 165). Duplicated as plain strings so this package stays free of
// internal/mcpegress (which dials the network).
const (
	RegistryStreamableHTTP = "streamable_http"
	RegistrySSELegacy      = "sse_legacy"
	RegistryNodeLocalStdio = "node_local_stdio"
)

// stdioTransports and sseTransports are the declared-transport spellings the
// class / registry-transport tables recognise. Any other non-empty remote
// spelling ("http", "streamable-http", "streamableHttp", ...) is a
// streamable-HTTP remote: that is the MCP default for a URL server.
var (
	stdioTransports = map[string]bool{"stdio": true, "local": true, "node_local_stdio": true, "command": true}
	sseTransports   = map[string]bool{"sse": true, "sse_legacy": true, "sse-legacy": true}
)

// TransportClass reduces a declared transport to ClassStdio or ClassRemote.
// An empty transport has no class ("") - the legacy pin feed carries none, and
// a candidate without a class has no adoptable locator.
func TransportClass(transport string) string {
	t := strings.ToLower(strings.TrimSpace(transport))
	switch {
	case t == "":
		return ""
	case stdioTransports[t]:
		return ClassStdio
	default:
		return ClassRemote
	}
}

// RegistryTransport maps a declared transport onto the mcp_server.transport
// vocabulary an adopted row carries ("" when the transport has no class).
func RegistryTransport(transport string) string {
	t := strings.ToLower(strings.TrimSpace(transport))
	switch {
	case t == "":
		return ""
	case stdioTransports[t]:
		return RegistryNodeLocalStdio
	case sseTransports[t]:
		return RegistrySSELegacy
	default:
		return RegistryStreamableHTTP
	}
}

// defaultPorts are the scheme ports NormalizeURL drops.
var defaultPorts = map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443"}

// NormalizeURL is the canonical form of a remote MCP server URL for identity
// and registry matching: lower-cased scheme and host, userinfo DROPPED (it can
// only carry a credential), the scheme's default port dropped, the fragment
// dropped, a trailing slash trimmed from the path, and the query re-encoded
// with sorted keys. ok is false for anything that is not an absolute URL with
// a host. The caller scrubs secrets out of the query BEFORE normalizing (the
// node does, internal/store/mcpinventory.go), so a rotated query token that
// scrub redacts does not move the fingerprint.
func NormalizeURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && defaultPorts[scheme] != port {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]" // a bare IPv6 literal keeps its brackets
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	out := scheme + "://" + host + path
	if q := u.Query(); len(q) > 0 {
		out += "?" + q.Encode() // url.Values.Encode sorts by key
	}
	return out, true
}

// Locator is the canonical locator one configured MCP server is identified
// by. For a remote server URL is set; for a stdio server Command / Args /
// ConfigPathHash are. Args must already be scrubbed.
type Locator struct {
	Transport      string
	URL            string
	Command        string
	Args           []string
	ConfigPathHash string
}

// locatorDomain versions the fingerprint preimage. Bumping it re-keys every
// candidate (a new row per server), so it only moves with a deliberate
// migration of the identity.
const locatorDomain = "sbo-mcp-locator-v1"

// LocatorFingerprint is mcp_discovery_candidate.locator_fingerprint (R13.7):
// the lower-hex sha256 over the canonical locator. Remote = {registry
// transport, normalized url}; stdio = {transport, command, scrubbed args,
// config_path_hash} - NUL-delimited so no two field splits collide. A remote
// locator whose URL does not normalize falls back to its trimmed raw text (it
// is still an identity, just not a matchable one). Never empty: the UNIQUE
// dedupe identity is NOT NULL.
func LocatorFingerprint(l Locator) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
	}
	class := TransportClass(l.Transport)
	switch class {
	case ClassStdio:
		write(locatorDomain, ClassStdio, RegistryNodeLocalStdio, l.Command)
		write(l.Args...)
		h.Write([]byte{1})
		write(l.ConfigPathHash)
	default:
		u, ok := NormalizeURL(l.URL)
		if !ok {
			u = strings.TrimSpace(l.URL)
		}
		write(locatorDomain, ClassRemote, RegistryTransport(l.Transport), u)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PinLocatorFingerprint is the locator identity of a LEGACY pin-feed
// candidate (GuardPinRow carries a name and a client, never a locator): the
// sha256 over the pin's own (client, name) identity under a distinct domain,
// so it can never collide with an inventory fingerprint. Stable across a pin
// hash change (drift re-pins; it must not mint a second candidate).
func PinLocatorFingerprint(client, name string) string {
	h := sha256.New()
	for _, p := range []string{locatorDomain, "guard_pin", client, name} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ConfigPathHash is the lower-hex sha256 of a client config file path - the
// only form a config path ever leaves the node in (R12.10).
func ConfigPathHash(path string) string {
	if path == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}

// ServerNameHashPrefix types the keyed name hash (R14.6) so a future scheme
// can coexist with v1 rows.
const ServerNameHashPrefix = "hmac-sha256:v1:"

// nameKeyDomain derives the per-org HMAC key.
const nameKeyDomain = "sbo-mcp-server-name-v1"

// ServerNameHash is the typed keyed HMAC of an MCP server name (R14.6):
// "hmac-sha256:v1:" + hex(HMAC-SHA256(k, name)) with k = sha256(domain || NUL
// || org_id). It is ALWAYS present on an MCPInventoryRow, including the
// reduced (share-off) shape, and on every mcp_discovery_candidate. The key is
// PER ORG and derivable by that org's server by design: the org recomputes it
// over its own registry names so a hash-only row that names a registered
// server is recognised as registered, while two orgs' hashes of one name
// never correlate. It is pseudonymisation against OTHER orgs, not against the
// org the node is enrolled with (whose registry is the dictionary anyway).
func ServerNameHash(orgID, name string) string {
	key := sha256.Sum256([]byte(nameKeyDomain + "\x00" + orgID))
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(name))
	return ServerNameHashPrefix + hex.EncodeToString(m.Sum(nil))
}

// sortedCopy returns a sorted copy of ss (nil stays nil).
func sortedCopy(ss []string) []string {
	if ss == nil {
		return nil
	}
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}
