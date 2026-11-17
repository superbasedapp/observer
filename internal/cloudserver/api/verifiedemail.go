package api

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// verifiedemail.go is the ONE seam through which the identity provider's
// statement about the user's address enters the server (operator item A4).
// Unlike accountprofile.go it is not display data: the platform OIDC issuer
// signs this address into a tenant's ID token and refuses unless the provider
// verified it. So it is written only by the WorkOS sign-in leg (the code
// exchange and the step-up re-authentication), refreshed at every one, and a
// failed write fails the sign-in. It is still never a lookup key: account
// resolution stays (provider, subject).

// providerEmail is what WorkOS said about the user's address at one sign-in.
type providerEmail struct {
	// address is the address exactly as WorkOS sent it (trimmed), or "" when
	// it sent none or one unfit to sign.
	address string
	// verified is WorkOS's `email_verified`; false when absent.
	verified bool
}

// newProviderEmail shapes the user object's `email` and `email_verified`
// fields. A missing flag is false: the issuer must never sign an address the
// provider did not positively verify. An address that cannot be a claim
// (empty, over 254 bytes, invalid UTF-8, a control character, no local part
// before an @) becomes "", which clears the stored row, so the issuer refuses
// rather than signing a stale or repaired address. The address is never
// normalized or truncated: a changed address is a different address.
func newProviderEmail(address string, verified *bool) providerEmail {
	return providerEmail{address: claimableAddress(address), verified: verified != nil && *verified}
}

// claimableAddress returns s trimmed when it can be signed as an email claim,
// otherwise "".
func claimableAddress(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 3 || len(s) > store.AccountProfileMaxEmailBytes || !utf8.ValidString(s) || strings.Index(s, "@") < 1 {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return s
}

// rememberProviderEmail stores the provider's statement for accountID. The
// error is the caller's to act on: the sign-in fails rather than leaving a
// stale address for the issuer.
func (s *Server) rememberProviderEmail(ctx context.Context, accountID string, e providerEmail) error {
	return s.store.UpsertVerifiedEmail(ctx, accountID, e.address, e.verified, s.now())
}
