package scrub

import "strings"

// bearerProseWords are the English words that follow "Bearer" in prose
// ("Bearer tokens are accepted", "Bearer authentication", "the Bearer of
// bad news"). A Bearer header's value is an opaque credential and is never
// one of these words, so a match whose whole value is one of them is prose
// and is left in place by the storage rows and the bearer_token detector.
// Operator ruling 2026-11-15 (security assessments live run, known defect 3:
// "[REDACTED] are accepted without verifying their HMAC signature").
//
// Keep the list to words that read as prose after "Bearer"; never add a
// word that could plausibly be a real token value.
var bearerProseWords = map[string]struct{}{
	"token": {}, "tokens": {}, "auth": {}, "authentication": {}, "authorization": {},
	"authorisation": {}, "credential": {}, "credentials": {}, "scheme": {}, "schemes": {},
	"header": {}, "headers": {}, "prefix": {}, "of": {}, "is": {}, "are": {}, "was": {},
	"and": {}, "or": {}, "the": {}, "a": {}, "an": {}, "to": {}, "for": {}, "in": {},
	"with": {}, "only": {}, "must": {}, "should": {}, "value": {}, "values": {},
	"string": {}, "type": {}, "format": {}, "here": {}, "access": {},
}

// bearerProseTrim are the punctuation characters the value class of the
// Bearer rows can swallow at the end of a prose word ("Bearer token.").
const bearerProseTrim = ".,/~+-_=" //nolint:gosec // G101: punctuation to trim, not a credential

// isBearerProse reports whether v, the text after "Bearer" and its spaces
// (with or without the "Bearer " prefix), is one prose word from
// bearerProseWords, ignoring case and trailing punctuation.
func isBearerProse(v string) bool {
	w := strings.TrimSpace(v)
	if len(w) >= 6 && strings.EqualFold(w[:6], "bearer") {
		w = strings.TrimSpace(w[6:])
	}
	w = strings.ToLower(strings.TrimRight(w, bearerProseTrim))
	_, ok := bearerProseWords[w]
	return ok
}

// bearerNotProse is the validate func of the Bearer rows: true (redact)
// unless the match is one prose word.
func bearerNotProse(m string) bool { return !isBearerProse(m) }
