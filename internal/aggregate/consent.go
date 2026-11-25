package aggregate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"time"
)

// Receipt is the recorded consent receipt (design §9.1, findings #15/#16). It
// is more than a config bool: it pins EXACTLY what the operator consented to —
// the wire schema version, the normalized endpoint, the pricing / cost-method
// / tool-registry versions, the actor/mode, a hash of the disclosure text
// shown, and the covered database scope. The daemon submits only while a
// receipt exists AND its pinned versions still match the live ones; a material
// change (schema bump, endpoint change, registry bump) invalidates it and
// suspends submission until re-consent.
//
// It is a pure value type; persistence lives in the store seam
// (internal/store/aggregate.go) and this package never imports database/sql.
type Receipt struct {
	SchemaVersion       int
	Endpoint            string // normalized via NormalizeEndpoint
	PricingVersion      string
	CostMethodVersion   string
	ToolRegistryVersion int
	Actor               string // ActorInteractive | ActorFlag | ActorManaged
	DisclosureHash      string
	ScopeDBPath         string
	ConsentedAt         time.Time
}

// Consent actor/mode vocabulary (design §9.1). Records HOW consent was given
// so a managed-fleet receipt is distinguishable from an interactive one.
const (
	ActorInteractive = "interactive"
	ActorFlag        = "flag"    // non-interactive `--yes`
	ActorManaged     = "managed" // admin-provisioned receipt (design §9.3)
)

// ConsentStatus enumerates why the rail is or is not permitted to submit
// (design §9.1). Only ConsentValid authorizes an egress; every other value
// keeps the rail inert and names the reason for the CLI to surface.
type ConsentStatus string

const (
	// ConsentValid — enabled, a receipt exists, and every pinned version
	// still matches the live one. This is the ONLY value that authorizes an
	// egress.
	ConsentValid ConsentStatus = "valid"
	// ConsentDisabled — the [aggregate_share] rail is off (the zero value /
	// default). The whole rail is inert.
	ConsentDisabled ConsentStatus = "disabled"
	// ConsentMissing — enabled in config but no consent receipt has been
	// recorded (e.g. a managed `enabled=true` with no provisioned receipt,
	// design §9.3). Inert until `observer aggregate enable`.
	ConsentMissing ConsentStatus = "missing"
	// ConsentRevoked — a receipt exists but was revoked (disable). Inert.
	ConsentRevoked ConsentStatus = "revoked"
	// ConsentSchemaChanged — the wire schema version bumped since consent.
	// Submission suspended until re-consent (finding #16).
	ConsentSchemaChanged ConsentStatus = "schema_changed"
	// ConsentEndpointChanged — the destination endpoint changed since consent
	// (finding #21). Re-consent required.
	ConsentEndpointChanged ConsentStatus = "endpoint_changed"
	// ConsentRegistryChanged — the tool-registry vocabulary version bumped
	// since consent (a new/finer field on the wire, finding #16/#24).
	// Re-consent required.
	ConsentRegistryChanged ConsentStatus = "registry_changed"
)

// LiveState is the current runtime posture the consent receipt is checked
// against each cycle (design §6.6). Passing primitives (not a config struct)
// keeps this package free of the config import and its file-I/O dependencies.
type LiveState struct {
	Enabled             bool
	SchemaVersion       int
	Endpoint            string // normalized via NormalizeEndpoint
	ToolRegistryVersion int
}

// CheckConsent is the material-change gate (design §9.1/§9.6). It returns
// ConsentValid only when the rail is enabled, a non-revoked receipt exists,
// and the receipt's pinned schema/endpoint/registry versions all still match
// the live ones. Every other path names the exact reason so the daemon goes
// inert and the CLI can prompt for the right remedy. Pure and total.
func CheckConsent(live LiveState, receipt *Receipt) ConsentStatus {
	if !live.Enabled {
		return ConsentDisabled
	}
	if receipt == nil {
		return ConsentMissing
	}
	if receipt.SchemaVersion != live.SchemaVersion {
		return ConsentSchemaChanged
	}
	if NormalizeEndpoint(receipt.Endpoint) != NormalizeEndpoint(live.Endpoint) {
		return ConsentEndpointChanged
	}
	if receipt.ToolRegistryVersion != live.ToolRegistryVersion {
		return ConsentRegistryChanged
	}
	return ConsentValid
}

// NormalizeEndpoint canonicalizes an endpoint URL for stable comparison
// between a recorded receipt and the live config: lowercased scheme + host,
// no trailing slash on the path, query/fragment/user-info dropped. A
// non-parseable input is returned trimmed so a garbage value can never
// accidentally compare-equal to a real one.
func NormalizeEndpoint(raw string) string {
	s := strings.TrimSpace(raw)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	path := strings.TrimRight(u.Path, "/")
	return scheme + "://" + host + path
}

// HashDisclosure returns the hex sha256 of the disclosure text the operator
// saw at consent time, so a later change to the disclosure wording is
// detectable (the receipt pins what was actually agreed to).
func HashDisclosure(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
