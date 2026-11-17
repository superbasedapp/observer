package pairing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The format's constants. They are the contract between the install page
// (which mints), the enrolment exchange (which redeems) and the node (which
// takes the code in); a change to any of them is a wire change.
const (
	// Prefix starts every pairing code; the trailing digit is the format
	// version.
	Prefix = "sbp1"
	// EnvVar is the environment variable a node reads a pairing code from.
	EnvVar = "SBO_PAIR_CODE"
	// TTL is how long a minted code is redeemable (plan 06 D-36).
	TTL = 15 * time.Minute
	// MinSecretBits is the entropy floor of a code's secret (plan 06
	// section 19.3: at least 128 bits).
	MinSecretBits = 128
	// MaxCodeLen bounds a code. It is the enrolment exchange's own bound on
	// a one-time token (internal/orgenrol), so every valid pairing code is
	// also a valid enrolment code on the wire.
	MaxCodeLen = 512
	// maxOrgIDLen bounds the decoded organization id.
	maxOrgIDLen = 128
)

// Parse errors. Every failure wraps ErrMalformed except a value that is not
// a pairing code at all (ErrNotPairingCode).
var (
	// ErrNotPairingCode is a value without the pairing prefix.
	ErrNotPairingCode = errors.New("pairing: not a pairing code")
	// ErrMalformed is a value with the prefix that is not a well-formed code.
	ErrMalformed = errors.New("pairing: malformed pairing code")
)

// Code is a parsed pairing code.
type Code struct {
	// OrgID is the organization the code was minted for.
	OrgID string
	// TokenID is the enrolment token's non-secret lookup id.
	TokenID string
	// Secret is the enrolment token's secret half.
	Secret string
}

// Compound is the enrolment token's "<token_id>.<secret>" credential, the
// form the server's token store resolves.
func (c Code) Compound() string { return c.TokenID + "." + c.Secret }

// String formats the code. It is the secret: never log it.
func (c Code) String() string {
	return Prefix + "." + base64.RawURLEncoding.EncodeToString([]byte(c.OrgID)) + "." + c.Compound()
}

// IsPairingCode reports whether s carries the pairing prefix. It does not
// validate the rest: Parse does.
func IsPairingCode(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), Prefix+".")
}

// Format builds the pairing code for orgID from an enrolment token's
// compound "<token_id>.<secret>" credential, checking the result parses (so
// the minting side can never hand out a code the redeeming side refuses).
func Format(orgID, compound string) (string, error) {
	id, secret, ok := strings.Cut(compound, ".")
	if !ok {
		return "", fmt.Errorf("%w: the enrolment credential has no token id", ErrMalformed)
	}
	c := Code{OrgID: orgID, TokenID: id, Secret: secret}
	s := c.String()
	if _, err := Parse(s); err != nil {
		return "", err
	}
	return s, nil
}

// Parse validates and splits a pairing code. Surrounding white space is
// ignored; anything else that does not fit the format is refused.
func Parse(raw string) (Code, error) {
	s := strings.TrimSpace(raw)
	if !IsPairingCode(s) {
		return Code{}, ErrNotPairingCode
	}
	if len(s) > MaxCodeLen {
		return Code{}, fmt.Errorf("%w: longer than %d characters", ErrMalformed, MaxCodeLen)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return Code{}, fmt.Errorf("%w: want %s.<org>.<id>.<secret>", ErrMalformed, Prefix)
	}
	org, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(org) == 0 || len(org) > maxOrgIDLen || !printable(string(org)) {
		return Code{}, fmt.Errorf("%w: the organization part is not valid", ErrMalformed)
	}
	if !isLowerHex(parts[2]) {
		return Code{}, fmt.Errorf("%w: the token id is not valid", ErrMalformed)
	}
	if bits := SecretBits(parts[3]); bits < MinSecretBits {
		return Code{}, fmt.Errorf("%w: the secret carries %d bits, fewer than %d", ErrMalformed, bits, MinSecretBits)
	}
	return Code{OrgID: string(org), TokenID: parts[2], Secret: parts[3]}, nil
}

// SecretBits is the entropy a base64url (unpadded) secret carries, in bits:
// its decoded length times eight, or 0 when it is not base64url.
func SecretBits(secret string) int {
	b, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return 0
	}
	return len(b) * 8
}

func isLowerHex(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}
