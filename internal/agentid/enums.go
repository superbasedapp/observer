package agentid

import (
	"fmt"
)

// CredentialAssurance is the CLOSED, ranked "how strong is the credential"
// enum (R2/R8.23.i). Higher values are stronger. The zero value is invalid.
//
// The MCP policy compiler, lint and matcher expand a minimum rank into an
// explicit accepted-value set (CEL has no ordinal over these strings) from
// mcpaccess.CredAssuranceRanks, the same order written strongest first as
// wire names. rankparity_test.go pins the two orders together, so a rank
// added here fails that test until the mcpaccess slice is updated.
type CredentialAssurance int

// Credential assurance levels, weakest first.
const (
	CredUnknown CredentialAssurance = iota
	CredClaimed
	CredUserSessionOnly
	CredSharedSecret
	CredWorkloadBound
	CredNodeEnrolled
	// CredHardwareBound is RESERVED for verified hardware evidence; unused in v1.
	CredHardwareBound
)

var credNames = map[CredentialAssurance]string{
	CredClaimed:         "claimed",
	CredUserSessionOnly: "user_session_only",
	CredSharedSecret:    "shared_secret",
	CredWorkloadBound:   "workload_bound",
	CredNodeEnrolled:    "node_enrolled",
	CredHardwareBound:   "hardware_bound",
}

// String returns the canonical wire name ("" for an invalid value).
func (c CredentialAssurance) String() string { return credNames[c] }

// Valid reports whether c is a member of the closed enum.
func (c CredentialAssurance) Valid() bool { _, ok := credNames[c]; return ok }

// ParseCredentialAssurance maps a wire name to the enum.
func ParseCredentialAssurance(s string) (CredentialAssurance, error) {
	for k, v := range credNames {
		if v == s {
			return k, nil
		}
	}
	return CredUnknown, fmt.Errorf("agentid: unknown credential_assurance %q", s)
}

// MarshalText implements encoding.TextMarshaler (refuses invalid values).
func (c CredentialAssurance) MarshalText() ([]byte, error) {
	if !c.Valid() {
		return nil, fmt.Errorf("agentid: invalid credential_assurance %d", int(c))
	}
	return []byte(c.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler (refuses unknown names).
func (c *CredentialAssurance) UnmarshalText(b []byte) error {
	v, err := ParseCredentialAssurance(string(b))
	if err != nil {
		return err
	}
	*c = v
	return nil
}

// AtLeast reports whether c meets the minimum rank min.
func (c CredentialAssurance) AtLeast(min CredentialAssurance) bool { return c.Valid() && c >= min }

// ClientAttestation is the CLOSED, ranked "which product/process is calling"
// enum (R2/R8.23.i). Higher values are stronger. The zero value is invalid.
//
// mcpaccess.ClientAttestationRanks carries the same order strongest first
// for the MCP policy compiler; rankparity_test.go pins the two together.
type ClientAttestation int

// Client attestation levels, weakest first.
const (
	AttestUnknown ClientAttestation = iota
	AttestClaimed
	AttestConfigured
	AttestIPCBound
	AttestProcessAttested
)

var attestNames = map[ClientAttestation]string{
	AttestClaimed:         "claimed",
	AttestConfigured:      "configured",
	AttestIPCBound:        "ipc_bound",
	AttestProcessAttested: "process_attested",
}

// String returns the canonical wire name ("" for an invalid value).
func (a ClientAttestation) String() string { return attestNames[a] }

// Valid reports whether a is a member of the closed enum.
func (a ClientAttestation) Valid() bool { _, ok := attestNames[a]; return ok }

// ParseClientAttestation maps a wire name to the enum.
func ParseClientAttestation(s string) (ClientAttestation, error) {
	for k, v := range attestNames {
		if v == s {
			return k, nil
		}
	}
	return AttestUnknown, fmt.Errorf("agentid: unknown client_attestation %q", s)
}

// MarshalText implements encoding.TextMarshaler (refuses invalid values).
func (a ClientAttestation) MarshalText() ([]byte, error) {
	if !a.Valid() {
		return nil, fmt.Errorf("agentid: invalid client_attestation %d", int(a))
	}
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler (refuses unknown names).
func (a *ClientAttestation) UnmarshalText(b []byte) error {
	v, err := ParseClientAttestation(string(b))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// AtLeast reports whether a meets the minimum rank min.
func (a ClientAttestation) AtLeast(min ClientAttestation) bool { return a.Valid() && a >= min }

// ProductScoped reports whether a product-scoped grant ("claude-code may call
// X") may be honoured at this attestation: only process_attested or
// ipc_bound. Below that the principal is node-wide (R2, finding-9/10).
func (a ClientAttestation) ProductScoped() bool { return a.AtLeast(AttestIPCBound) }
