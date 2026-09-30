package localpdp

import "github.com/marmutapp/superbased-observer/internal/mcpaccess"

// transportAttestation is the transport -> client-attestation table (R2).
// It is walked top-down; an unlisted transport is claimed.
var transportAttestation = []struct {
	transport   Transport
	attestation string
}{
	{TransportStdioWrapper, AttestProcess},
	{TransportIPC, AttestIPC},
	{TransportLoopbackHTTP, AttestConfigured},
	{TransportUnknown, AttestClaimed},
}

// AttestationFor returns the client attestation a transport proves.
func AttestationFor(t Transport) string {
	for _, row := range transportAttestation {
		if row.transport == t {
			return row.attestation
		}
	}
	return AttestClaimed
}

// attestationRank returns the index of a in mcpaccess.ClientAttestationRanks
// (0 = strongest) or len(ranks) for an unknown value (weaker than claimed).
func attestationRank(a string) int {
	for i, r := range mcpaccess.ClientAttestationRanks {
		if r == a {
			return i
		}
	}
	return len(mcpaccess.ClientAttestationRanks)
}

// EffectiveAttestation combines what the relay observed (transport) with
// what the caller/token claimed: the WEAKER of the two. A claim can lower
// the transport's proof (a token minted at `configured` stays configured on
// the stdio wrapper) but never raise it (a loopback caller claiming
// process_attested is configured). An empty claim defers to the transport.
func EffectiveAttestation(t Transport, claimed string) string {
	proven := AttestationFor(t)
	if claimed == "" {
		return proven
	}
	if attestationRank(claimed) > attestationRank(proven) {
		if attestationRank(claimed) >= len(mcpaccess.ClientAttestationRanks) {
			return AttestClaimed
		}
		return claimed
	}
	return proven
}

// ProductScopedHonoured reports whether a product-scoped grant can match at
// attestation a (the R2 rule, table-driven off mcpaccess.ProductAttestations).
func ProductScopedHonoured(a string) bool {
	for _, ok := range mcpaccess.ProductAttestations {
		if ok == a {
			return true
		}
	}
	return false
}
