package parseutil

import (
	"bytes"
	"strings"
	"time"
)

// ParseRFC3339 parses raw as RFC 3339 with or without fractional seconds
// (time.RFC3339Nano, then time.RFC3339), keeping the offset the string
// carries. An empty or unparseable raw yields the zero time.
func ParseRFC3339(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return time.Time{}
}

// ParseRFC3339UTC is ParseRFC3339 converted to UTC.
func ParseRFC3339UTC(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// millisZLayout is the fixed millisecond-precision UTC layout some tools
// write ("2006-01-02T15:04:05.000Z").
const millisZLayout = "2006-01-02T15:04:05.000Z"

// ParseRFC3339UTCMillisZ is ParseRFC3339UTC with one more layout tried
// last, the fixed millisecond-precision "2006-01-02T15:04:05.000Z".
func ParseRFC3339UTCMillisZ(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, millisZLayout} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// LooksLikeUUID reports whether s is a canonical 8-4-4-4-12 hex UUID
// (RFC 4122 layout, any version, either hex case).
func LooksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// SplitLinesKeepTerminator is bufio.ScanLines except the token RETAINS its
// line terminator, so the caller can advance a byte cursor by exactly the
// bytes consumed (CRLF included) instead of assuming one byte per line, and
// can tell a COMPLETE line from an unterminated trailing one by whether the
// token ends in '\n'.
func SplitLinesKeepTerminator(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i+1], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// IsAbsAnyOS reports whether p is absolute on EITHER OS family: a POSIX
// `/...` path, a UNC `\\...` path, or a Windows drive path (`C:\...`,
// `C:/...`). A record written on one OS may be parsed by an observer on
// the other, where filepath.IsAbs applies the wrong rules.
func IsAbsAnyOS(p string) bool {
	if p == "" {
		return false
	}
	if p[0] == '/' || strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return false
	}
	c := p[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
