package agentid

import (
	"fmt"
)

// CredentialAssurance is the CLOSED, ranked "how strong is the credential"
// enum (R2/R8.23.i). Higher values are stronger. The zero value is invalid.
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

// AcceptedCredAssurances expands a MINIMUM rank into the explicit accepted
// value set, strongest first - what the CEL compiler emits as `in [...]`
// because CEL has no ordinal over these strings (R8.23.i).
func AcceptedCredAssurances(min CredentialAssurance) []string {
	var out []string
	for v := CredHardwareBound; v >= CredClaimed; v-- {
		if v >= min {
			out = append(out, v.String())
		}
	}
	return out
}

// ClientAttestation is the CLOSED, ranked "which product/process is calling"
// enum (R2/R8.23.i). Higher values are stronger. The zero value is invalid.
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

// AcceptedClientAttestations expands a MINIMUM rank into the explicit
// accepted value set, strongest first (CEL `in [...]`, R8.23.i).
func AcceptedClientAttestations(min ClientAttestation) []string {
	var out []string
	for v := AttestProcessAttested; v >= AttestClaimed; v-- {
		if v >= min {
			out = append(out, v.String())
		}
	}
	return out
}
