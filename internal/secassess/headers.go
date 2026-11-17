package secassess

import (
	"regexp"
	"strings"
)

// Header names that say their value is a credential (depth plan W5b fix round).
//
// The request helper (internal/secassesssvc/probe/probe.py) stores a header
// whose NAME says it carries a credential as [REDACTED], whatever the value
// looks like: a value such as "opaquetokenvalue123456" has no shape a pattern
// can find, but the name it travels under is the evidence. Observer's stored
// copy of a log record (StoredProbe) and the display pass (ShownProbes) apply
// the same rule again, so a helper that was edited, or a log line written by
// hand, cannot put a credential-named header's value on the screen.
//
// The pattern and the exceptions below are the same words as _CRED_NAME and
// _NOT_CRED in probe.py; a test in internal/secassesssvc reads both and runs
// the helper over a table of names against the Go answer.

// CredentialHeaderPattern is the case-insensitive pattern a header name is
// matched against, anywhere in the name.
const CredentialHeaderPattern = "auth|token|secret|key|sess|sid|cook|pass|pwd|sign|otp|csrf|xsrf|jwt|cred|bearer|hmac" //nolint:gosec // G101: a pattern of header NAMES used for matching, never a credential value

// NotCredentialHeaders are header names (lower case) that match the pattern and
// carry no credential: the challenge a server sends and the CORS flag.
var NotCredentialHeaders = Enum{"www-authenticate", "proxy-authenticate", "access-control-allow-credentials"}

var credentialHeaderRe = regexp.MustCompile("(?i)" + CredentialHeaderPattern)

// CredentialHeaderName reports whether a header's name says its value is a
// credential.
func CredentialHeaderName(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	return credentialHeaderRe.MatchString(low) && !NotCredentialHeaders.Has(low)
}

// credentialHeaderValue is the stored form of a credential-named header's
// value, the same words the helper writes: nothing stays but the shape that
// helps a reader (an authorization scheme, a cookie's names and attributes).
// An empty value has nothing to hide and stays empty.
func credentialHeaderValue(name, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization":
		if scheme, rest, ok := strings.Cut(value, " "); ok && strings.TrimSpace(rest) != "" && len(scheme) <= 16 && ValidHeaderName(scheme) {
			return scheme + " [REDACTED]"
		}
	case "cookie":
		parts := strings.Split(value, ";")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if strings.TrimSpace(p) == "" {
				continue
			}
			if k, _, ok := strings.Cut(p, "="); ok {
				out = append(out, strings.TrimSpace(k)+"=[REDACTED]")
			} else {
				out = append(out, "[REDACTED]")
			}
		}
		return strings.Join(out, "; ")
	case "set-cookie": // the attributes (HttpOnly, SameSite, Path, Secure) are the evidence
		first, attrs, sep := strings.Cut(value, ";")
		out := "[REDACTED]"
		if k, _, ok := strings.Cut(first, "="); ok {
			out = strings.TrimSpace(k) + "=[REDACTED]"
		}
		if sep {
			out += ";" + attrs
		}
		return out
	}
	return "[REDACTED]"
}

// hiddenHeaders returns the headers with every credential-named header's value
// reduced to its stored form and every other value passed through redact as
// the line "Name: value" (so a pattern that needs the name sees it), the name
// cut off again. The input is not modified; redact may be nil.
func hiddenHeaders(in []ProbeHeader, redact func(string) string) []ProbeHeader {
	if in == nil {
		return nil
	}
	out := make([]ProbeHeader, len(in))
	for i, h := range in {
		out[i] = ProbeHeader{N: h.N, V: hiddenHeaderValue(h.N, h.V, redact)}
	}
	return out
}

// hiddenHeaderValue is one header's value as hiddenHeaders keeps it.
func hiddenHeaderValue(name, value string, redact func(string) string) string {
	if CredentialHeaderName(name) {
		return credentialHeaderValue(name, value)
	}
	if redact == nil || value == "" || name == "" {
		return value
	}
	line := name + ": " + value
	if red := redact(line); strings.HasPrefix(red, name+": ") {
		return strings.TrimPrefix(red, name+": ")
	}
	return value
}

// A header condition names text a header's value contains (PTHeader.Value of
// an indicator). The helper keeps no value of a credential-named header, so a
// condition that copies a Set-Cookie line as the agent saw it
// ("sid=sess-1001; Path=/") can never be found in the log, which holds
// "sid=[REDACTED]; Path=/". The condition is therefore compared, and stored, in
// the form the log can hold: the same words the helper writes (the table
// below, one row per case, a test row each). It is deliberately narrow:
//
//   - only a text that opens with a cookie PAIR (name=value, the name not one of
//     the Set-Cookie attributes) is rewritten, because a fragment such as
//     "HttpOnly" or "SameSite=None" is visible in the log and is the evidence of
//     a cookie-flag finding; a text with no "=" (a bare value such as
//     "sess-1002") is left as the agent wrote it, never read as hidden, because
//     reading an unknown word as a hidden value would let any attribute check
//     hold on any cookie;
//   - only Set-Cookie is rewritten; another credential-named header's whole
//     value is hidden and a condition that names it is left as written (it does
//     not hold, and the finding reads No log, which is the truth: the log cannot
//     show a secret).
//
// What this does not do, said so a reader is not told more: the value itself is
// never checked (no log can hold it), only the cookie's name and attributes; the
// condition Observer stores and shows is the rewritten one, so what a card
// says was checked is what was checked; and the rewrite does not make a forged
// log pass more easily, because the log is a file the agent writes and the
// agent can write the rewritten text into it as easily as the original (the
// differential rule, E18, and the helper re-hash are what stand against that).

// cookieAttributes are the attribute names of a Set-Cookie header (lower case),
// which the log keeps visible.
var cookieAttributes = Enum{"expires", "max-age", "domain", "path", "secure", "httponly", "samesite", "partitioned", "priority", "sameparty"}

// hiddenMarker is the text the helper stores where it hides a value.
const hiddenMarker = "[REDACTED]"

// headerConditionRow is one row of the table that turns a header condition's
// text into the form the log can hold: the first row whose Hit holds decides.
type headerConditionRow struct {
	// ID is the row's name in this table (H1 to H3).
	ID string
	// Hit says the row applies to the header name and text.
	Hit func(name, text string) bool
	// Form is the text the condition is compared and stored as.
	Form func(name, text string) string
}

// headerConditionRows is the table.
var headerConditionRows = []headerConditionRow{
	{"H1", func(name, _ string) bool { return !CredentialHeaderName(name) }, keepText},
	{"H2", func(name, text string) bool {
		_, _, ok := cookiePair(name, text)
		return ok
	}, func(_, text string) string {
		pair, rest, _ := cookiePair("set-cookie", text)
		return pair + "=" + hiddenMarker + rest
	}},
	{"H3", func(string, string) bool { return true }, keepText},
}

func keepText(_, text string) string { return text }

// HiddenConditionText is the form a header condition's text is compared and
// stored in (see the table above); it returns the text itself when no row
// changes it.
func HiddenConditionText(name, text string) string {
	for _, r := range headerConditionRows {
		if r.Hit(name, text) {
			return r.Form(name, text)
		}
	}
	return text
}

// cookiePair reads a Set-Cookie condition text that opens with a cookie pair:
// it returns the cookie's name and what follows the pair (the ";" and the
// attributes, or ""), and ok is false for any other header or text. The value
// of the pair must be there (an empty value has nothing to hide).
func cookiePair(name, text string) (pairName, rest string, ok bool) {
	if !strings.EqualFold(strings.TrimSpace(name), "set-cookie") {
		return "", "", false
	}
	first, after, sep := strings.Cut(text, ";")
	k, v, hasEq := strings.Cut(first, "=")
	k = strings.TrimSpace(k)
	if !hasEq || strings.TrimSpace(v) == "" || !cookieNameOK(k) || cookieAttributes.Has(strings.ToLower(k)) {
		return "", "", false
	}
	if sep {
		rest = ";" + after
	}
	return k, rest, true
}

// cookieNameOK reports whether s reads as a cookie name: one to 64 characters of
// the token set (letters, digits and !#$%&'*+-.^_`|~), no space and none of the
// characters that end a pair.
func cookieNameOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}
