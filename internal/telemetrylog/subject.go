package telemetrylog

import "strings"

// OTLP signal names. An OTLP record's subject is sbo.otlp.<org>.<signal> and its
// signal is exactly one of these three. They are defined here (not imported from
// internal/orgserver/telemetry/model) so this pure package stays free of any
// data-plane dependency.
const (
	// SignalTraces is the OTLP traces signal.
	SignalTraces = "traces"
	// SignalLogs is the OTLP logs signal.
	SignalLogs = "logs"
	// SignalMetrics is the OTLP metrics signal.
	SignalMetrics = "metrics"
)

// Subject structure constants.
const (
	subjectRoot = "sbo"
	segPush     = "push"
	segOTLP     = "otlp"
	subjectSep  = "."
)

// PushFilter is the wildcard subject filter that matches every push record
// across every org (sbo.push.*).
const PushFilter = "sbo.push.*"

// OTLPFilter is the wildcard subject filter that matches every OTLP record of
// every signal across every org (sbo.otlp.>).
const OTLPFilter = "sbo.otlp.>"

// PushSubject returns the log subject a push envelope for org is published on:
// "sbo.push.<tok>", where <tok> is the subject-safe encoding of org.
func PushSubject(org string) string {
	return subjectRoot + subjectSep + segPush + subjectSep + encodeToken(org)
}

// OTLPSubject returns the log subject an OTLP batch for org and signal is
// published on: "sbo.otlp.<tok>.<signal>". signal must be one of SignalTraces,
// SignalLogs or SignalMetrics (already subject-safe, so it is appended
// verbatim); org is encoded into a subject-safe token.
func OTLPSubject(org, signal string) string {
	return subjectRoot + subjectSep + segOTLP + subjectSep + encodeToken(org) + subjectSep + signal
}

// KindOf reports the record kind (KindPush or KindOTLP) a subject belongs to,
// with ok=false for any subject that is not a well-formed telemetry log subject.
// It validates only the structure (segment count and roots); SignalOf validates
// the OTLP signal.
func KindOf(subject string) (string, bool) {
	p := strings.Split(subject, subjectSep)
	if len(p) < 3 || p[0] != subjectRoot {
		return "", false
	}
	switch p[1] {
	case segPush:
		if len(p) == 3 {
			return KindPush, true
		}
	case segOTLP:
		if len(p) == 4 {
			return KindOTLP, true
		}
	}
	return "", false
}

// SignalOf returns the OTLP signal of an OTLP subject and true, or ("", false)
// for a push subject, a malformed subject, or an OTLP subject whose signal is
// not one of the three defined signals.
func SignalOf(subject string) (string, bool) {
	p := strings.Split(subject, subjectSep)
	if len(p) != 4 || p[0] != subjectRoot || p[1] != segOTLP {
		return "", false
	}
	if !validSignal(p[3]) {
		return "", false
	}
	return p[3], true
}

// OrgOf returns the org id a subject belongs to (the inverse of the token
// encoding PushSubject / OTLPSubject apply), and true, or ("", false) when
// subject is not a well-formed telemetry log subject or its org token does not
// decode.
func OrgOf(subject string) (string, bool) {
	if _, ok := KindOf(subject); !ok {
		return "", false
	}
	p := strings.Split(subject, subjectSep)
	return decodeToken(p[2])
}

// validSignal reports whether s is one of the three OTLP signal names.
func validSignal(s string) bool {
	switch s {
	case SignalTraces, SignalLogs, SignalMetrics:
		return true
	default:
		return false
	}
}

const upperhex = "0123456789ABCDEF"

// isTokenByte reports whether b is safe to place raw in a NATS subject token:
// the unreserved set [A-Za-z0-9_-]. Everything else — ".", " ", "*", ">" and any
// non-ASCII byte — must be percent-encoded so it can never split or wildcard a
// subject.
func isTokenByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_' || b == '-':
		return true
	default:
		return false
	}
}

// encodeToken renders s as a NATS-safe subject token, percent-encoding every
// byte outside [A-Za-z0-9_-] as "%XX" with uppercase hex. The empty string
// encodes to the empty string.
func encodeToken(s string) string {
	safe := true
	for i := 0; i < len(s); i++ {
		if !isTokenByte(s[i]) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isTokenByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperhex[c>>4])
		b.WriteByte(upperhex[c&0x0f])
	}
	return b.String()
}

// decodeToken reverses encodeToken, returning ok=false for a malformed token (a
// "%" not followed by two hex digits). Both upper- and lower-case hex are
// accepted so the round-trip is stable regardless of casing.
func decodeToken(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, true
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			return "", false
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), true
}

// unhex decodes one hex digit (upper or lower case).
func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
