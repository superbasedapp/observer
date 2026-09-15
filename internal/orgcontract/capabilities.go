package orgcontract

import (
	"strconv"
	"strings"
)

// Mode-capability advertisement convention (Plane B dual-mode gateway design
// 2026-08-29 §3, Sol S3; P6b coordination). A node advertises which Plane B
// routing-MODE schema it can honor as a capability TOKEN in its policy-ack
// LiveCapabilities list, so the server's capability-gated staged rollout
// (internal/orgserver/planebmode) refuses to flip to Gateway Mode until the
// whole fleet has ACKed a compatible mode capability.
//
// The token is "mode_capability:v<N>", where N is the highest mode-block schema
// version the node's proxy-gateway enforcement point supports (it tracks
// internal/policyfam/providers.SupportedModeSchemaVersion). Using a single
// versioned token (rather than a structured field) keeps it in the SAME
// capability vocabulary as SignedPolicyResource.RequiredCapabilities /
// NormalizeCapabilities, so one LiveCapabilities list carries every capability
// the node reports, mode-capability included.
//
// NODE-SIDE EXPECTATION (the follow-up feed, not built here): the node populates
// PolicyResourceOptions.LiveCapabilities (cmd/observer/policyresource_wire.go)
// with ModeCapabilityToken(providers.SupportedModeSchemaVersion) whenever its
// proxy is capable of honoring an org gateway-mode block, and that list rides
// the policy-ack report's LiveCapabilities field. The server then calls
// planebmode.RecordCapabilityAck with ParseModeCapabilityVersion(list).

// modeCapabilityPrefix is the token stem; the version suffix follows the "v".
const modeCapabilityPrefix = "mode_capability:v"

// ModeCapabilityToken returns the capability token advertising support for mode
// schema version. Versions <= 0 yield the empty string (nothing to advertise).
func ModeCapabilityToken(version int) string {
	if version <= 0 {
		return ""
	}
	return modeCapabilityPrefix + strconv.Itoa(version)
}

// ParseModeCapabilityVersion returns the HIGHEST mode-capability schema version
// advertised in caps, or 0 when none is present. It tolerates case and
// surrounding whitespace and ignores malformed suffixes, so an unrecognised
// token never lowers the reported capability.
func ParseModeCapabilityVersion(caps []string) int64 {
	var best int64
	for _, c := range caps {
		c = strings.ToLower(strings.TrimSpace(c))
		if !strings.HasPrefix(c, modeCapabilityPrefix) {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(c, modeCapabilityPrefix), 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		if n > best {
			best = n
		}
	}
	return best
}
