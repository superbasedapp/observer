package grokbot

import "strings"

// The blob filename codec, transcribed from Grok Bot's own implementation
// (app.asar/dist/electron-main/main.cjs, functions
// encodeClientPersistenceFileName / decodeClientPersistenceFileName).
//
//	const NAMESPACE = "sand.";
//	const ALPHABET  = "abcdefghijklmnopqrstuvwxyz234567";  // RFC4648, LOWERCASE
//	const SUFFIX    = ".blob";
//	const MAX_NAME  = 240;   // encoded length INCLUDING ".blob"
//
// A key that does not start with "sand.", or whose encoded name would exceed
// 240 chars, is REFUSED STORAGE by the app — there is no hashed-fallback
// naming, so a decode failure always means "not one of our files", never "a
// file we should have understood".
const (
	blobAlphabet  = "abcdefghijklmnopqrstuvwxyz234567"
	blobSuffix    = ".blob"
	blobNamespace = "sand."
	// blobMaxName is the app's own cap on the encoded name (including the
	// ".blob" suffix). Reproduced so decodeBlobName rejects anything the
	// app could never have written.
	blobMaxName = 240

	// tmpSuffix is the app's atomic-write staging name. These are swept by
	// the app itself and must never be parsed: a *.tmp file is by
	// definition a half-written blob.
	tmpSuffix = ".tmp"
)

// decodeBlobName reverses the app's base32 filename encoding, applying all
// five of its validation rules: the ".blob" suffix must be present, the length
// cap must hold, every character must be in the alphabet, the trailing bits
// must be zero (a canonical-encoding check that rejects truncated names), and
// the decoded text must start with the "sand." namespace.
//
// ok is false for anything that is not a Grok Bot persistence blob.
func decodeBlobName(name string) (key string, ok bool) {
	if !strings.HasSuffix(name, blobSuffix) || len(name) > blobMaxName {
		return "", false
	}
	body := name[:len(name)-len(blobSuffix)]
	if body == "" {
		return "", false
	}

	out := make([]byte, 0, len(body)*5/8+1)
	var acc, bits uint32
	for i := 0; i < len(body); i++ {
		idx := strings.IndexByte(blobAlphabet, body[i])
		if idx < 0 {
			return "", false
		}
		acc = acc<<5 | uint32(idx)
		bits += 5
		if bits >= 8 {
			out = append(out, byte(acc>>(bits-8)))
			bits -= 8
		}
	}
	// Canonical-encoding check: the app refuses a name whose leftover bits
	// are non-zero, so a truncated/hand-edited name can never decode into a
	// plausible-looking key.
	if bits > 0 && acc&((1<<bits)-1) != 0 {
		return "", false
	}

	key = string(out)
	if !strings.HasPrefix(key, blobNamespace) || !utf8Valid(out) {
		return "", false
	}
	return key, true
}

// utf8Valid mirrors the app's strict ("fatal") UTF-8 decode. Implemented
// without importing unicode/utf8's RuneCountInString semantics so an invalid
// sequence is rejected rather than silently replaced.
func utf8Valid(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		var n int
		switch {
		case c < 0x80:
			n = 1
		case c&0xE0 == 0xC0:
			n = 2
		case c&0xF0 == 0xE0:
			n = 3
		case c&0xF8 == 0xF0:
			n = 4
		default:
			return false
		}
		if i+n > len(b) {
			return false
		}
		for j := 1; j < n; j++ {
			if b[i+j]&0xC0 != 0x80 {
				return false
			}
		}
		// Reject overlong encodings and out-of-range code points.
		switch n {
		case 2:
			if c&0x1E == 0 {
				return false
			}
		case 3:
			if c == 0xE0 && b[i+1] < 0xA0 {
				return false
			}
		case 4:
			if c == 0xF0 && b[i+1] < 0x90 {
				return false
			}
			if c > 0xF4 || (c == 0xF4 && b[i+1] >= 0x90) {
				return false
			}
		}
		i += n
	}
	return true
}

// encodeBlobName is the forward direction, used only by tests to build
// fixtures the way the app would. Kept next to the decoder so the two can
// never drift.
func encodeBlobName(key string) string {
	b := []byte(key)
	var sb strings.Builder
	var acc, bits uint32
	for _, c := range b {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			sb.WriteByte(blobAlphabet[(acc>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		sb.WriteByte(blobAlphabet[(acc<<(5-bits))&31])
	}
	return sb.String() + blobSuffix
}

// sliceKey is a parsed persistence-slice key.
//
// Grammar (from the app's own key builder):
//
//	sand.client.slice.<slice>                                  (global)
//	sand.client.slice.account.<encodedAccountID>.<slice>        (per-account)
//
// where encodedAccountID is encodeURIComponent(id) with "." further replaced
// by "%2E" — which is why an account id never introduces a spurious dot and
// the final dot-split below is unambiguous.
type sliceKey struct {
	// Account is the URL-encoded account id ("" for a global slice).
	Account string
	// Slice is the slice family, e.g. "transcript.replicas" or
	// "roster.last-roster".
	Slice string
	// Param is the slice's trailing parameter — for transcript.replicas,
	// the agent (session) UUID. "" when the slice takes none.
	Param string
}

const (
	sliceKeyPrefix    = "sand.client.slice."
	sliceAccountToken = "account."
	// transcriptSlice is the only slice family this adapter ingests.
	transcriptSlice = "transcript.replicas"
	// rosterSlice is recognised so it can be explicitly, documentedly NOT
	// ingested (see doc.go) rather than silently falling through.
	rosterSlice = "roster.last-roster"
)

// parseSliceKey splits a decoded key into its account / slice / param parts.
func parseSliceKey(key string) (sliceKey, bool) {
	rest, found := strings.CutPrefix(key, sliceKeyPrefix)
	if !found || rest == "" {
		return sliceKey{}, false
	}
	var out sliceKey
	if acct, found := strings.CutPrefix(rest, sliceAccountToken); found {
		// The account id is URL-encoded with "." → "%2E", so the FIRST
		// dot after it reliably terminates the id.
		dot := strings.IndexByte(acct, '.')
		if dot <= 0 || dot == len(acct)-1 {
			return sliceKey{}, false
		}
		out.Account = acct[:dot]
		rest = acct[dot+1:]
	}
	switch {
	case rest == rosterSlice:
		out.Slice = rosterSlice
	case strings.HasPrefix(rest, transcriptSlice+"."):
		out.Slice = transcriptSlice
		out.Param = rest[len(transcriptSlice)+1:]
		if out.Param == "" {
			return sliceKey{}, false
		}
	default:
		out.Slice = rest
	}
	return out, true
}

// transcriptAgentID returns the agent (session) id encoded in a blob
// filename, or "" if the name is not a transcript-replica blob.
func transcriptAgentID(base string) string {
	if strings.HasSuffix(base, tmpSuffix) {
		return ""
	}
	key, ok := decodeBlobName(base)
	if !ok {
		return ""
	}
	sk, ok := parseSliceKey(key)
	if !ok || sk.Slice != transcriptSlice {
		return ""
	}
	return sk.Param
}
