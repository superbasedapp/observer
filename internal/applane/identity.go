package applane

import "strings"

// The headers an app's SDK sends on a lane call (sdk/typescript gatewayFetch,
// the Python/Go/Java gateway helpers). The same names the org AI gateway
// reads (internal/aigateway/gwhttp).
const (
	// HeaderRequestID carries the SDK's request id; the lane records the
	// call under it and echoes it on the response.
	HeaderRequestID = "X-SBO-Request-Id"
	// HeaderService names the app's service, the scope the org's
	// service-scoped app caps bind on.
	HeaderService = "X-Superbased-Service"
)

// MaxRequestIDLen bounds an honoured request id.
const MaxRequestIDLen = 128

// MaxServiceLen bounds an honoured service name (the org gateway's
// maxAppIDLen).
const MaxServiceLen = 512

// ValidRequestID reports whether id is a request id the lane may record a
// call under and echo: 8 to MaxRequestIDLen characters of
// [A-Za-z0-9._:-]. Anything else is ignored and the proxy mints its own: an
// id lands in api_turns, the synthesized span and a response header, so it
// must never carry a space, a control character or a header delimiter.
func ValidRequestID(id string) bool {
	if len(id) < 8 || len(id) > MaxRequestIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

// NormalizeService returns the service name a lane call carries, trimmed,
// or "" when the value is absent, longer than MaxServiceLen or carries a
// control character. Case is kept for display; cap matching lowercases.
func NormalizeService(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > MaxServiceLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return ""
		}
	}
	return s
}
