package api

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// accountprofile.go is the ONE seam through which a display identity (the
// developer's own email + name) enters the server. Every sign-in path — the
// WorkOS code exchange, the WorkOS step-up re-authentication, and the dev-auth
// token POST — shapes what it learned into an accountProfile and hands it to
// rememberProfile; nothing else writes `account_profiles`.
//
// Two rules hold everywhere in this file:
//
//   - It is DISPLAY DATA, never a decision input. No branch anywhere reads the
//     email; account resolution stays (provider, subject) → identity_links.
//   - It is NEVER LOGGED. A failed upsert logs the error and the fact, never
//     the value. The email travels from the provider to the account's own row
//     and back to that account's own browser, and nowhere else.
//
// A profile that cannot be shaped or stored is dropped silently: a sign-in must
// never fail because a cosmetic field was malformed.

// accountProfile is a shaped, bounded display identity ready to store. Both
// fields may be empty, which is the honest "the provider told us nothing"
// state — the portal falls back to the account id.
type accountProfile struct {
	email       string
	displayName string
}

// empty reports whether there is nothing worth storing.
func (p accountProfile) empty() bool { return p.email == "" && p.displayName == "" }

// newAccountProfile shapes a provider's raw claims into a storable profile:
// each field is trimmed, NORMALIZED (cloudcontract.NormalizeText — NFC, and a
// hard refusal of control characters, bidi overrides, and invalid UTF-8, which
// is what stops a "name" from carrying a terminal escape or a right-to-left
// spoof into the top bar) and length-bounded. A field that fails normalization
// is DROPPED, not repaired and not fatal.
//
// The display name is "first last" as the provider spells it, falling back to
// the email when the provider gave no name at all — so the chip always renders
// something meaningful whenever anything is known.
func newAccountProfile(email, firstName, lastName string) accountProfile {
	var p accountProfile
	p.email = safeDisplayField(email, store.AccountProfileMaxEmailBytes)

	name := strings.TrimSpace(strings.TrimSpace(firstName) + " " + strings.TrimSpace(lastName))
	p.displayName = safeDisplayField(name, store.AccountProfileMaxNameBytes)
	if p.displayName == "" {
		// No usable name: the email is the best human-readable label there is.
		// It is re-bounded at the NAME limit so the stored display_name honours
		// its own column contract rather than inheriting the email's.
		p.displayName = safeDisplayField(p.email, store.AccountProfileMaxNameBytes)
	}
	return p
}

// safeDisplayField trims, normalizes, and bounds one user-visible string,
// returning "" when the value is absent or unfit to display.
//
// Length and CONTENT are handled differently on purpose. Unfit content (a
// control character, a bidi override, invalid UTF-8) is DROPPED — there is no
// safe repair for a name engineered to spoof, and the fallback chain has an
// honest answer for a missing field. Mere LENGTH is truncated instead, because
// a long name is not hostile and losing it entirely would be a worse answer
// than a shortened one: normalization therefore runs against a generous cap
// (whose job is to reject content, not to enforce the column bound) and the
// result is cut to the real bound on a rune boundary afterwards.
func safeDisplayField(s string, maxBytes int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	safe, err := cloudcontract.NormalizeText("profile", s, maxBytes*4, false)
	if err != nil {
		// Malformed, or absurdly long even for the generous cap. Drop it — and
		// never log the value.
		return ""
	}
	return truncateRunes(safe.String(), maxBytes)
}

// truncateRunes cuts s to at most maxBytes bytes without splitting a rune, so a
// shortened name stays valid UTF-8. (The store bounds again on the way in; this
// keeps the value the SPA is handed on the same contract as the stored one.)
func truncateRunes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// rememberProfile stores the display identity for accountID, best-effort. It is
// called AFTER the session is established, so a storage failure costs the user
// a name in the top bar and nothing else — never the sign-in itself.
func (s *Server) rememberProfile(ctx context.Context, accountID string, p accountProfile) {
	if accountID == "" || p.empty() {
		return
	}
	if err := s.store.UpsertAccountProfile(ctx, accountID, p.email, p.displayName, s.now()); err != nil {
		// The error only — the value it failed to store is never logged.
		s.log.Warn("cloudserver/api: upsert account profile", "err", err)
	}
}

// profileBody renders a stored profile for the SPA, or nil when nothing is
// known. Returning nil (an omitted key) rather than an object of empty strings
// keeps "we have no name for you" distinguishable from "your name is blank",
// which is the difference between the portal rendering the account id and
// rendering an empty chip.
func profileBody(p store.AccountProfile) map[string]string {
	if p.Empty() {
		return nil
	}
	return map[string]string{
		"email":        p.Email,
		"display_name": p.DisplayName,
	}
}

// lookupProfile reads the account's display identity, degrading to "unknown" on
// any error. Every caller is a display path: a failed read must render the
// account id, not fail the request.
func (s *Server) lookupProfile(ctx context.Context, accountID string) store.AccountProfile {
	if accountID == "" {
		return store.AccountProfile{}
	}
	p, err := s.store.AccountProfile(ctx, accountID)
	if err != nil {
		s.log.Warn("cloudserver/api: read account profile", "err", err)
		return store.AccountProfile{}
	}
	return p
}
