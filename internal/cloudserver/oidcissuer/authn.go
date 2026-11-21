package oidcissuer

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// authn.go is the issuer's authentication-freshness decision (OIDC Core
// 3.1.2.1 `prompt` and `max_age`, 2 `auth_time`): given the caller's portal
// session and what the relying party asked for, whether the issuer may issue
// a code from the session it has, must send the browser to sign in (and
// whether that sign-in must be a FRESH primary authentication), or must
// answer login_required. One rule table, walked top-down.
//
// The session's authentication time is when the portal session was
// established by a FRESH primary authentication: an AuthKit sign-in the
// portal sent prompt=login and max_age=0 (so AuthKit was told not to answer
// it from its own session), or the dev-auth stub's login. It is never the time
// a code or token is minted, and never the time an ordinary AuthKit sign-in
// completed, which AuthKit may have answered silently from its own session:
// such a session's authentication time is unknown (zero). An unknown time is
// not an error. The token then carries no auth_time (OIDC Core 2 requires it
// only when max_age was sent), and any request for freshness (prompt=login,
// or any max_age) sends the browser to a fresh sign-in first. Reusing the
// session to issue another token does not move the time.
//
// A forced sign-in comes back to the very authorize request that demanded
// it, which still carries prompt=login / max_age. ReauthParam marks that
// request with the moment the issuer demanded the fresh sign-in; a session
// established at or after that moment (less ReauthSkew) satisfies the demand,
// so the resumed request issues instead of demanding another sign-in
// forever. The marker travels in the browser and is not secret: it is
// honoured only within ReauthWindow of now, so a forged one can at most let a
// session established in the last ReauthWindow satisfy prompt=login, and the
// id_token still carries that session's true auth_time, which is what the
// relying party checks.

// Prompt values (OIDC Core 3.1.2.1).
const (
	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
)

// SupportedPromptValues returns the prompt values the issuer honours, in the
// order discovery advertises them (prompt_values_supported). consent and
// select_account are refused with invalid_request: the issuer has no consent
// screen and no account chooser, so it cannot do what they ask.
func SupportedPromptValues() []string { return []string{PromptNone, PromptLogin} }

// ReauthParam is the authorize parameter the issuer adds to the request it
// resumes after demanding a fresh sign-in: the Unix second of the demand.
const ReauthParam = "sb_reauth_at"

// ReauthWindow bounds how old a ReauthParam may be and still be honoured: the
// lifetime of the portal's sign-in transaction (ten minutes), past which the
// forced sign-in it started cannot complete anyway.
const ReauthWindow = 10 * time.Minute

// ReauthSkew is how far before the demand a session's authentication time
// may fall and still count as the sign-in the demand asked for: the clock
// disagreement tolerated between the replica that demanded the sign-in and
// the one that recorded it (NTP-synchronised hosts on one network). Kept
// small, because a session authenticated within it before the demand passes
// prompt=login on resume; replicas further apart than this send the person
// round the forced sign-in again instead of issuing.
const ReauthSkew = 5 * time.Second

// maxMaxAgeDigits bounds max_age's spelling (ten decimal digits); maxMaxAge
// is the largest value it is read as (a hundred years, far beyond any
// portal session's 24-hour life).
const (
	maxMaxAgeDigits = 10
	maxMaxAge       = 100 * 365 * 24 * time.Hour
)

// Session is what the portal knows about the browser asking to sign in.
type Session struct {
	// AccountID is the portal session's account; "" when the browser holds
	// no portal session.
	AccountID string
	// AuthTime is when the person authenticated to establish that session
	// (a fresh primary sign-in). Zero when it is not known: the token then
	// carries no auth_time, and a request asking for freshness (prompt=login
	// or max_age) is sent to a fresh sign-in.
	AuthTime time.Time
	// AMR is what the session can truthfully say about how the person
	// authenticated (RFC 8176 values); nil when nothing is known. The portal
	// sets it when the session completed its passkey second factor (C2,
	// internal/cloudserver/portalmfa).
	AMR []string
	// SecondFactorPending: the account holds a passkey and this session has
	// not used it. The issuer then never issues (portalmfa.IssueRule).
	SecondFactorPending bool
}

// promptValues returns the space-separated prompt values.
func promptValues(prompt string) []string { return strings.Fields(prompt) }

func hasPrompt(prompt, want string) bool {
	for _, v := range promptValues(prompt) {
		if v == want {
			return true
		}
	}
	return false
}

// promptSupported reports whether every prompt value is one the issuer
// honours.
func promptSupported(prompt string) bool {
	for _, v := range promptValues(prompt) {
		ok := false
		for _, s := range SupportedPromptValues() {
			if v == s {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// promptNoneWithOthers reports the one combination OIDC Core forbids: none
// with any other value.
func promptNoneWithOthers(prompt string) bool {
	vs := promptValues(prompt)
	return len(vs) > 1 && hasPrompt(prompt, PromptNone)
}

// parseMaxAge reads max_age: absent is (0, false, true); a non-negative
// decimal integer is (d, true, true); anything else is not ok.
func parseMaxAge(raw string) (d time.Duration, present, ok bool) {
	if raw == "" {
		return 0, false, true
	}
	if len(raw) > maxMaxAgeDigits {
		return 0, false, false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, false, false
		}
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false, false
	}
	// Past maxMaxAge no session can be older, so the value means "no limit";
	// clamping keeps the Duration from overflowing.
	if n > int64(maxMaxAge/time.Second) {
		return maxMaxAge, true, true
	}
	return time.Duration(n) * time.Second, true, true
}

// parseReauthAt reads ReauthParam: the demand's time when it is a Unix second
// within [now-ReauthWindow, now+ReauthSkew], else zero (ignored).
func parseReauthAt(raw string, now time.Time) time.Time {
	if raw == "" || len(raw) > 20 {
		return time.Time{}
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	at := time.Unix(n, 0).UTC()
	if at.Before(now.Add(-ReauthWindow)) || at.After(now.Add(ReauthSkew)) {
		return time.Time{}
	}
	return at
}

// ResumeQuery returns the authorize query to resume after a fresh sign-in
// demanded at at: q with ReauthParam set (replacing any earlier one).
func ResumeQuery(q url.Values, at time.Time) string {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	out.Set(ReauthParam, strconv.FormatInt(at.Unix(), 10))
	return out.Encode()
}

// authnDecision is what the freshness rules decide.
type authnDecision int

// Freshness decisions.
const (
	// authnIssue: the session satisfies the request; issue a code carrying
	// its auth_time.
	authnIssue authnDecision = iota + 1
	// authnSignIn: no session; send the browser to an ordinary sign-in.
	authnSignIn
	// authnFreshSignIn: send the browser to a sign-in that must be a fresh
	// primary authentication (the identity provider told not to reuse its
	// own session), marking the resumed request with ReauthParam.
	authnFreshSignIn
	// authnLoginRequired: prompt=none, and only a sign-in would do; answer
	// login_required to the client.
	authnLoginRequired
)

// authnFacts is what the freshness rules read.
type authnFacts struct {
	// SignedIn: the browser holds a portal session.
	SignedIn bool
	// AuthTime is the session's authentication time (zero: unknown).
	AuthTime time.Time
	// PromptNone and PromptLogin: the request's prompt carries the value.
	PromptNone, PromptLogin bool
	// MaxAge is the request's max_age; HasMaxAge whether it sent one.
	MaxAge    time.Duration
	HasMaxAge bool
	// ReauthAt is the honoured ReauthParam (zero: none).
	ReauthAt time.Time
	// Now is the issuer's clock.
	Now time.Time
}

// reauthDone: the fresh sign-in this request demanded has happened.
func (f authnFacts) reauthDone() bool {
	return !f.ReauthAt.IsZero() && !f.AuthTime.IsZero() && !f.AuthTime.Before(f.ReauthAt.Add(-ReauthSkew))
}

// stale: the request sent max_age, and the session cannot show an
// authentication within it (its time is unknown, or older than max_age).
// max_age=0 is always stale: it asks for an authentication made for this
// request (the conventional reading, and what AuthKit does with it). Without
// max_age an unknown time is not stale: nobody asked when the person
// authenticated, and the token simply does not say.
func (f authnFacts) stale() bool {
	return f.HasMaxAge && (f.AuthTime.IsZero() || f.MaxAge == 0 || f.Now.Sub(f.AuthTime) > f.MaxAge)
}

// freshnessAsked: the request asked for an authentication of known freshness
// (prompt=login or any max_age), so a code may only be issued from a session
// with a known authentication time (checked in Issuer.Authorize).
func (f authnFacts) freshnessAsked() bool { return f.PromptLogin || f.HasMaxAge }

// authnRule is one row of authnRules.
type authnRule struct {
	ID       string
	Match    func(authnFacts) bool
	Decision authnDecision
}

// authnRules is the freshness decision, walked top-down; the first matching
// row decides. The last row always matches.
var authnRules = []authnRule{
	// No portal session.
	{
		ID: "no-session-prompt-none", Decision: authnLoginRequired,
		Match: func(f authnFacts) bool { return !f.SignedIn && f.PromptNone },
	},
	// The identity provider may still hold its own session; prompt=login and
	// max_age need a primary authentication that happens now, not a silent
	// reuse of that one.
	{
		ID: "no-session-freshness-asked", Decision: authnFreshSignIn,
		Match: func(f authnFacts) bool { return !f.SignedIn && (f.PromptLogin || f.HasMaxAge) },
	},
	{
		ID: "no-session", Decision: authnSignIn,
		Match: func(f authnFacts) bool { return !f.SignedIn },
	},
	// The fresh sign-in this request demanded has happened: issue, whatever
	// prompt=login or max_age say (they asked for exactly this sign-in).
	{
		ID: "reauth-done", Decision: authnIssue,
		Match: func(f authnFacts) bool { return f.reauthDone() },
	},
	{
		ID: "prompt-login", Decision: authnFreshSignIn,
		Match: func(f authnFacts) bool { return f.PromptLogin },
	},
	{
		ID: "stale-prompt-none", Decision: authnLoginRequired,
		Match: func(f authnFacts) bool { return f.stale() && f.PromptNone },
	},
	{
		ID: "stale", Decision: authnFreshSignIn,
		Match: func(f authnFacts) bool { return f.stale() },
	},
	{
		ID: "session-fresh-enough", Decision: authnIssue,
		Match: func(authnFacts) bool { return true },
	},
}

// decideAuthn walks authnRules and returns the decision and the deciding
// row's id.
func decideAuthn(f authnFacts) (authnDecision, string) {
	for _, r := range authnRules {
		if r.Match(f) {
			return r.Decision, r.ID
		}
	}
	return authnFreshSignIn, "no-row"
}

// factsFor derives the facts for a request already past the request rules
// (prompt and max_age well-formed).
func factsFor(r AuthorizeRequest, s Session, now time.Time) authnFacts {
	maxAge, has, _ := parseMaxAge(r.MaxAge)
	return authnFacts{
		SignedIn:    s.AccountID != "",
		AuthTime:    s.AuthTime,
		PromptNone:  hasPrompt(r.Prompt, PromptNone),
		PromptLogin: hasPrompt(r.Prompt, PromptLogin),
		MaxAge:      maxAge,
		HasMaxAge:   has,
		ReauthAt:    parseReauthAt(r.ReauthAt, now),
		Now:         now,
	}
}
