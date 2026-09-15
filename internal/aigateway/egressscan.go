package aigateway

import (
	"bytes"
	"strings"
)

// Gateway egress-guard scanner (design §2.4 step 4 / §2.7 — tracker P4/P6
// item 2 "wire a real GuardScanner replacing NoopGuardScanner"). This is the
// SEAM plus a real built-in classifier: a GuardScanner whose request- and
// chunk-classification are pluggable funcs. The default org/standalone wiring
// installs a marker-substring classifier (the real, non-noop egress control an
// org can configure today); a richer internal/guard-policy-bundle-backed
// ScanFunc can be dropped into the SAME seam later without touching the
// handler, which only ever sees the GuardScanner interface.
//
// It stays pure (no I/O, no rewriting) so it satisfies the handler's
// pre-first-byte / per-chunk contract — classification only; the handler owns
// the deny (request) and abort (chunk) actions.

// ScanFunc classifies a byte slice (a request body, or one response chunk)
// into a ScanClass. A nil ScanFunc is treated as "always clean".
type ScanFunc func([]byte) ScanClass

// FuncGuardScanner adapts a request ScanFunc + a chunk ScanFunc to the
// GuardScanner interface. Either func may be nil (that side is always clean),
// so a request-only or chunk-only guard is expressible without a bespoke type.
type FuncGuardScanner struct {
	Request ScanFunc
	Chunk   ScanFunc
}

// ScanRequest classifies the request body pre-first-byte.
func (f FuncGuardScanner) ScanRequest(body []byte) ScanClass {
	if f.Request == nil {
		return ScanClean
	}
	return f.Request(body)
}

// ScanChunk classifies one response chunk as it streams.
func (f FuncGuardScanner) ScanChunk(chunk []byte) ScanClass {
	if f.Chunk == nil {
		return ScanClean
	}
	return f.Chunk(chunk)
}

// SubstringMarkers returns a ScanFunc that reports ScanCritical when the input
// contains ANY of the (case-insensitive) markers, else ScanClean. Empty/blank
// markers are ignored; an empty marker set yields an always-clean func. This
// is the built-in egress classifier: an org configures the forbidden markers
// (data-exfil canaries, internal codenames, secret prefixes) and a hit denies
// the request (pre-first-byte) or aborts the stream (per-chunk).
func SubstringMarkers(markers []string) ScanFunc {
	lowered := make([][]byte, 0, len(markers))
	for _, m := range markers {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		lowered = append(lowered, []byte(strings.ToLower(m)))
	}
	if len(lowered) == 0 {
		return nil
	}
	return func(b []byte) ScanClass {
		hay := bytes.ToLower(b)
		for _, m := range lowered {
			if bytes.Contains(hay, m) {
				return ScanCritical
			}
		}
		return ScanClean
	}
}

// NewMarkerEgressScanner builds a GuardScanner that critical-flags both the
// request body and each response chunk against the same marker set. With no
// markers it returns NoopGuardScanner (honest: no scan is performed, and the
// caller can log that the gateway is running without an egress guard) rather
// than a FuncGuardScanner that silently passes everything.
func NewMarkerEgressScanner(markers []string) GuardScanner {
	fn := SubstringMarkers(markers)
	if fn == nil {
		return NoopGuardScanner{}
	}
	return FuncGuardScanner{Request: fn, Chunk: fn}
}
