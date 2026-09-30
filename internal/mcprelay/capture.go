package mcprelay

import (
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// capture.go is the scrub-for-STORAGE step for L2 payloads (doc3 §9.2's
// scrub.CaptureJSON contract, R12.9). internal/scrub does not carry
// CaptureJSON yet and is outside this lane's file set, so - exactly as the
// front did - the relay ships the SAME contract behind a seam the wiring
// can swap for internal/scrub's once it lands.

// Capturer scrubs a payload for storage and reports what it did.
type Capturer interface {
	CaptureJSON(raw []byte, capBytes int) ([]byte, record.ScrubStatus)
}

// DefaultCaptureCap is the per-field capture cap in bytes.
const DefaultCaptureCap = 64 << 10

// credentialMembers are removed recursively (never restored).
var credentialMembers = map[string]bool{
	"authorization": true, "access_token": true, "refresh_token": true, "id_token": true, "api_key": true, "apikey": true,
	"client_secret": true, "password": true, "secret": true, "private_key": true, "encrypted_content": true,
}

// scrubCapturer is the default Capturer over internal/scrub.
type scrubCapturer struct{ s *scrub.Scrubber }

// NewCapturer returns the default capturer.
func NewCapturer() Capturer { return scrubCapturer{s: scrub.New()} }

// CaptureJSON implements Capturer: structure-walk the JSON (every string
// value scrubbed in isolation, credential-bearing members removed), size-cap
// with a truncation marker; non-JSON input is scrubbed as text
// (text_fallback); any uncertainty yields the redaction placeholder.
func (c scrubCapturer) CaptureJSON(raw []byte, capBytes int) ([]byte, record.ScrubStatus) {
	if capBytes <= 0 {
		capBytes = DefaultCaptureCap
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		txt := c.s.String(string(raw))
		if len(txt) > capBytes {
			return []byte(cutUTF8(txt, capBytes) + "…[truncated]"), record.ScrubTruncated
		}
		return []byte(txt), record.ScrubTextFallback
	}
	out, err := json.Marshal(c.walk(v))
	if err != nil {
		return []byte(`"[REDACTED]"`), record.ScrubRedacted
	}
	if len(out) > capBytes {
		return []byte(cutUTF8(string(out), capBytes) + "…[truncated]"), record.ScrubTruncated
	}
	return out, record.ScrubStructured
}

func (c scrubCapturer) walk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if credentialMembers[strings.ToLower(k)] {
				continue
			}
			out[k] = c.walk(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = c.walk(val)
		}
		return out
	case string:
		return c.s.String(t)
	default:
		return v
	}
}

// cutUTF8 truncates s to at most n bytes on a rune boundary.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
