package portalmfa

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// RPName is the relying-party name a portal passkey prompt shows.
const RPName = "SuperBased"

// userHandleDomain separates the portal's user handles from any other hash
// of an account id.
const userHandleDomain = "sbci-portal-passkey-user-v1\x00"

// UserHandle is the WebAuthn user.id of an account's portal passkeys: a
// SHA-256 of the account id under a domain tag, so the authenticator stores
// no identifier the portal uses anywhere else.
func UserHandle(accountID string) []byte {
	h := sha256.Sum256([]byte(userHandleDomain + accountID))
	return h[:]
}

// MaxActivePasskeys is how many unrevoked portal passkeys one account may
// hold (the staff cap, L-83, doubled: an account may have a phone, a laptop
// and hardware keys).
const MaxActivePasskeys = 10

// FreshEnrolWindow is how recent the session's primary sign-in must be for
// the account's FIRST passkey: with no second factor yet, a fresh sign-in is
// the only proof the person at the keyboard is the account's owner.
const FreshEnrolWindow = 10 * time.Minute

// CeremonyTTL is how long a portal WebAuthn challenge stays answerable.
const CeremonyTTL = 5 * time.Minute

// MaxLabelRunes bounds a passkey's label.
const MaxLabelRunes = 60

// --- recovery codes ---------------------------------------------------------

// RecoveryCodeCount is how many codes one batch holds.
const RecoveryCodeCount = 10

// recoveryAlphabet is lower-case base32 (RFC 4648): 32 symbols, 5 bits each.
const recoveryAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// recoveryCodeChars is a code's length without its hyphen: 10 symbols, 50
// bits of entropy, written xxxxx-xxxxx.
const recoveryCodeChars = 10

// recoveryHashDomain separates recovery-code hashes from other secrets.
const recoveryHashDomain = "sbci-portal-recovery-v1\x00"

// ErrRecoveryCodeShape is a code that cannot be one of ours.
var ErrRecoveryCodeShape = errors.New("portalmfa: not a recovery code")

// NewRecoveryCodes mints RecoveryCodeCount codes from r (crypto/rand.Reader
// in production), each xxxxx-xxxxx.
func NewRecoveryCodes(r io.Reader) ([]string, error) {
	out := make([]string, 0, RecoveryCodeCount)
	seen := map[string]bool{}
	buf := make([]byte, recoveryCodeChars)
	for len(out) < RecoveryCodeCount {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("portalmfa.NewRecoveryCodes: %w", err)
		}
		var b strings.Builder
		for i, c := range buf {
			if i == recoveryCodeChars/2 {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryAlphabet[c&31])
		}
		code := b.String()
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out, nil
}

// NormalizeRecoveryCode reads a typed code: case, spaces and hyphens are
// ignored. It refuses anything that is not recoveryCodeChars symbols of the
// alphabet.
func NormalizeRecoveryCode(typed string) (string, error) {
	var b strings.Builder
	for _, c := range strings.ToLower(typed) {
		switch {
		case c == '-' || c == ' ' || c == '\t':
			continue
		case strings.ContainsRune(recoveryAlphabet, c):
			b.WriteRune(c)
		default:
			return "", ErrRecoveryCodeShape
		}
		if b.Len() > recoveryCodeChars {
			return "", ErrRecoveryCodeShape
		}
	}
	if b.Len() != recoveryCodeChars {
		return "", ErrRecoveryCodeShape
	}
	return b.String(), nil
}

// HashRecoveryCode is the stored form of a code (hex SHA-256 of the
// normalised code under a domain tag). The code itself is shown once and
// never stored.
func HashRecoveryCode(code string) (string, error) {
	n, err := NormalizeRecoveryCode(code)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(recoveryHashDomain + n))
	return hex.EncodeToString(h[:]), nil
}

// --- what a session proved ---------------------------------------------------

// Method is how a portal session completed its second factor.
type Method string

// The second-factor methods. The vocabulary mirrors the
// browser_sessions.second_factor_method CHECK (cloud 0131).
const (
	// MethodNone: the session has not completed a second factor.
	MethodNone Method = ""
	// MethodPasskey: a passkey assertion (or the registration of the
	// account's first passkey) with user verification.
	MethodPasskey Method = "passkey"
	// MethodRecoveryCode: a one-time recovery code. It unlocks the portal so
	// the person can add a new passkey; it is NOT a multi-factor statement
	// to a tenant (no amr), so an org that requires a second factor still
	// asks for a passkey.
	MethodRecoveryCode Method = "recovery_code"
)

// KnownMethods lists the stored methods.
var KnownMethods = []Method{MethodPasskey, MethodRecoveryCode}

// amrRule is one row of the amr table.
type amrRule struct {
	method         Method
	backupEligible bool
	amr            []string
}

// amrRules is THE table of what a session may tell a tenant, walked top
// down. RFC 8176: "hwk" proof of possession of a hardware-secured key, "swk"
// of a software-secured key, "mfa" multiple factors. A backup-eligible
// passkey can be synced off the device, so it is reported as software-
// secured; a device-bound one as hardware-secured. Nothing is said about the
// user-verification gesture (pin or biometric): WebAuthn does not tell which.
// A recovery code says nothing.
var amrRules = []amrRule{
	{method: MethodPasskey, backupEligible: true, amr: []string{"swk", "mfa"}},
	{method: MethodPasskey, backupEligible: false, amr: []string{"hwk", "mfa"}},
}

// AMRFor is the amr a session that completed method may carry; nil when it
// may carry none.
func AMRFor(method Method, backupEligible bool) []string {
	for _, r := range amrRules {
		if r.method == method && r.backupEligible == backupEligible {
			return append([]string(nil), r.amr...)
		}
	}
	return nil
}

// MultiFactor reports whether amr is a multi-factor statement this package
// signs ("mfa" present). The issuer and the API use it; the tenant applies
// its own reading (internal/orgserver/auth MultiFactorFromAMR).
func MultiFactor(amr []string) bool {
	for _, a := range amr {
		if a == "mfa" {
			return true
		}
	}
	return false
}

// SessionState is what the portal knows about a session's second factor.
type SessionState struct {
	// Enrolled: the account holds at least one active passkey.
	Enrolled bool
	// Method is how this session completed its second factor (MethodNone:
	// not completed).
	Method Method
	// AMR is what the session proved (AMRFor at completion).
	AMR []string
}

// Pending reports whether the session must complete a second factor before
// anything else: the account has a passkey and this session has not used it
// (or a recovery code).
func (s SessionState) Pending() bool { return s.Enrolled && s.Method == MethodNone }

// MultiFactor reports whether the session carries a multi-factor statement.
func (s SessionState) MultiFactor() bool { return MultiFactor(s.AMR) }
