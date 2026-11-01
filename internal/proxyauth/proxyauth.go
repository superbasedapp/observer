package proxyauth

import (
	"crypto/subtle"
	"net/url"
	"strings"
)

// PathPrefix is the path segment a token-scoped base URL carries its token
// under. It is the same spelling as the sandbox MXC port's per-run token
// lane, so one redaction rule masks both.
const PathPrefix = "/t/"

// TokenLen is the length of a client token: 32 random bytes, hex encoded.
const TokenLen = 64

// ValidToken reports whether s has the client token's shape: TokenLen
// lowercase hex characters.
func ValidToken(s string) bool {
	if len(s) != TokenLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Equal compares two tokens in constant time. An empty token never matches.
func Equal(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SplitPath splits a request path that starts with PathPrefix into the token
// and the rest of the path ("/t/<tok>/v1/messages" -> "<tok>", "/v1/messages";
// "/t/<tok>" -> "<tok>", "/"). found is false, and rest is path unchanged,
// for any path outside the prefix.
func SplitPath(path string) (token, rest string, found bool) {
	after, ok := strings.CutPrefix(path, PathPrefix)
	if !ok {
		return "", path, false
	}
	tok, tail, hasTail := strings.Cut(after, "/")
	if !hasTail {
		return tok, "/", true
	}
	return tok, "/" + tail, true
}

// Verdict is the outcome of one request's check.
type Verdict int

const (
	// Pass: the request goes on exactly as it arrived (no token involved).
	Pass Verdict = iota
	// Accept: the request carried the right token; the caller strips the
	// prefix and goes on.
	Accept
	// Refuse: the caller answers Status with Reason and stops.
	Refuse
)

// StatusUnauthorized is the refusal status (a plain integer: the package
// does not import net/http).
const StatusUnauthorized = 401

// Decision is one request's verdict.
type Decision struct {
	Verdict Verdict
	Status  int
	Reason  string
}

// Request is what Decide reads about one request.
type Request struct {
	// Configured is the node's client token, "" when none exists.
	Configured string
	// Required reports that the proxy enforces client authentication
	// (the start-time Enforce result, not the raw config key).
	Required bool
	// Path is the request's path as it arrived.
	Path string
}

// decideRow is one row of the per-request decision table, walked top-down.
type decideRow struct {
	name  string
	match func(r Request, tok string, found bool) bool
	out   Decision
}

// RequiredReason is the refusal reason for a request without the token
// while enforcement is on. It names the setting so an operator looking at
// a refused client knows what to check.
const RequiredReason = "this Observer proxy requires client authentication ([proxy].require_client_auth): route the tool with `observer init` or its `observer <tool>` launcher so its base URL carries the client token"

// MismatchReason is the refusal reason for a token that is not this node's.
// A wrong token and a malformed one read the same.
const MismatchReason = "the Observer proxy client token in the base URL is not valid for this node"

// NoTokenReason is the refusal reason for a well-formed token prefix on a
// node that holds no client token: forwarding it would hand the token to the
// provider in the request path.
const NoTokenReason = "this Observer proxy holds no client token, so a base URL carrying one is refused rather than forwarded; set [proxy].client_auth_routes or remove the /t/<token> segment from the tool's base URL"

var decideTable = []decideRow{
	// No token on this node and a well-formed token prefix: refused locally,
	// never forwarded (the provider would see the token and answer 404).
	{"no token configured, token-shaped prefix", func(r Request, tok string, found bool) bool {
		return r.Configured == "" && found && ValidToken(tok)
	}, Decision{Verdict: Refuse, Status: StatusUnauthorized, Reason: NoTokenReason}},
	// No token on this node otherwise: nothing to check and nothing to
	// strip, so every plain request is byte-identical to the proxy before
	// this package.
	{"no token configured", func(r Request, _ string, _ bool) bool { return r.Configured == "" }, Decision{Verdict: Pass}},
	{"token matches", func(r Request, tok string, found bool) bool { return found && Equal(tok, r.Configured) }, Decision{Verdict: Accept}},
	// A presented token is always verified, required or not: accepting a
	// wrong one would make the credential decorative.
	{"token presented, no match", func(_ Request, _ string, found bool) bool { return found }, Decision{Verdict: Refuse, Status: StatusUnauthorized, Reason: MismatchReason}},
	{"no token, required", func(r Request, _ string, _ bool) bool { return r.Required }, Decision{Verdict: Refuse, Status: StatusUnauthorized, Reason: RequiredReason}},
	{"no token, not required", func(Request, string, bool) bool { return true }, Decision{Verdict: Pass}},
}

// Decide walks the per-request decision table.
func Decide(r Request) Decision {
	tok, _, found := SplitPath(r.Path)
	for _, row := range decideTable {
		if row.match(r, tok, found) {
			return row.out
		}
	}
	return Decision{Verdict: Pass}
}

// EnforceFacts is what the start-time enforcement decision reads.
type EnforceFacts struct {
	// Requested reports that the effective config (local value or an org
	// pin) asks for client authentication.
	Requested bool
	// TokenReady reports that the node holds a valid client token.
	TokenReady bool
	// PlainRoutes names the routes pointed at this proxy that are in the
	// plain (token-less) form. Enforcing would refuse them.
	PlainRoutes []string
}

// Enforcement is the start-time result.
type Enforcement struct {
	Enforce bool
	// Reason says, in plain words, why enforcement is on or off.
	Reason string
	// Blocking lists the plain routes that held enforcement off.
	Blocking []string
}

type enforceRow struct {
	match func(EnforceFacts) bool
	out   func(EnforceFacts) Enforcement
}

var enforceTable = []enforceRow{
	{func(f EnforceFacts) bool { return !f.Requested }, func(EnforceFacts) Enforcement {
		return Enforcement{Reason: "client authentication is not required"}
	}},
	{func(f EnforceFacts) bool { return !f.TokenReady }, func(EnforceFacts) Enforcement {
		return Enforcement{Reason: "client authentication is required but the node has no client token, so the proxy keeps serving every local client"}
	}},
	// Never break a live route: a tool still pointed at the plain form
	// would be refused on its next request.
	{func(f EnforceFacts) bool { return len(f.PlainRoutes) > 0 }, func(f EnforceFacts) Enforcement {
		return Enforcement{
			Reason:   "client authentication is required but these routes do not carry the client token yet, so the proxy keeps serving them: " + strings.Join(f.PlainRoutes, ", "),
			Blocking: append([]string(nil), f.PlainRoutes...),
		}
	}},
	{func(EnforceFacts) bool { return true }, func(EnforceFacts) Enforcement {
		return Enforcement{Enforce: true, Reason: "client authentication is enforced: a request without the client token is refused"}
	}},
}

// Enforce walks the enforcement decision table.
func Enforce(f EnforceFacts) Enforcement {
	for _, row := range enforceTable {
		if row.match(f) {
			return row.out(f)
		}
	}
	return Enforcement{}
}

// WithToken returns base with the token prefix as its first path segment
// ("http://127.0.0.1:8820/v1" -> "http://127.0.0.1:8820/t/<tok>/v1"). An
// existing token prefix is replaced. An empty token returns base without any
// token prefix, and a base that does not parse as an absolute URL is
// returned unchanged.
func WithToken(base, token string) string {
	plain, _ := StripToken(base)
	if token == "" {
		return plain
	}
	u, err := url.Parse(plain)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return base
	}
	path := u.Path
	if path == "/" {
		path = ""
	}
	u.Path = PathPrefix + token + path
	u.RawPath = ""
	return u.String()
}

// StripToken removes the token prefix from raw's path. had reports whether
// there was one. A value that does not parse is returned unchanged.
func StripToken(raw string) (plain string, had bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, false
	}
	_, rest, found := SplitPath(u.Path)
	if !found {
		return raw, false
	}
	if rest == "/" {
		rest = ""
	}
	u.Path = rest
	u.RawPath = ""
	return u.String(), true
}

// TokenOf returns the token of a token-scoped URL, "" for any other value.
func TokenOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	tok, _, found := SplitPath(u.Path)
	if !found {
		return ""
	}
	return tok
}

// HasToken reports whether raw is a URL whose path starts with the token
// prefix.
func HasToken(raw string) bool {
	_, had := StripToken(raw)
	return had
}

// Redacted is what Redact puts in place of a token.
const Redacted = "<redacted>"

// Redact masks the token of a token-scoped URL so it can be printed, logged
// or returned to a dashboard ("http://127.0.0.1:8820/t/<redacted>/v1"). Any
// other value is returned unchanged.
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	tok, rest, found := SplitPath(u.Path)
	if !found || tok == "" {
		return raw
	}
	if rest == "/" {
		rest = ""
	}
	head, _, _ := strings.Cut(raw, u.Host)
	return head + u.Host + PathPrefix + Redacted + rest + tailOf(u)
}

// tailOf is the query and fragment of u as they would print.
func tailOf(u *url.URL) string {
	s := ""
	if u.RawQuery != "" {
		s += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		s += "#" + u.EscapedFragment()
	}
	return s
}

// SameRoute reports whether two base URLs name the same route once any
// token prefix is removed: the route writers rewrite such a value to the
// form they want (plain or token) instead of treating it as somebody else's.
func SameRoute(a, b string) bool {
	pa, _ := StripToken(a)
	pb, _ := StripToken(b)
	return pa == pb
}
