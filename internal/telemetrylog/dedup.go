package telemetrylog

import (
	"crypto/sha256"
	"encoding/hex"
)

// dedupSep is the field separator hashed between the three DedupID parts. It is
// 0x1F (ASCII Unit Separator), a byte that never appears in an org id, a NATS
// subject or a lowercase hex digest, so the three parts can never run together
// into an ambiguous pre-image (org "a" + subject "bc" must not collide with org
// "ab" + subject "c").
const dedupSep = 0x1F

// DedupID returns the content-derived duplicate id for a record: the hex
// SHA-256 over org, subject and hex(SHA-256(payload)), each separated by an
// unambiguous 0x1F byte.
//
// It is content-derived (plan D6) on purpose: a node that retries a push it
// already sent re-hashes the SAME decoded body and produces the SAME id, so the
// broker drops it inside its duplicate window; a retry that has accumulated new
// local rows is a DIFFERENT body and lands as a new record. The id is therefore
// a best-effort optimization, never the idempotency guarantee — natural-key
// idempotency in the apply path is. payload is the DECODED bytes (post-gunzip);
// the caller guarantees that, because DEFLATE output is not stable across Go
// versions and hashing the gzip bytes would defeat cross-version dedup.
func DedupID(org, subject string, payload []byte) string {
	inner := sha256.Sum256(payload)
	innerHex := hex.EncodeToString(inner[:])

	h := sha256.New()
	h.Write([]byte(org))
	h.Write([]byte{dedupSep})
	h.Write([]byte(subject))
	h.Write([]byte{dedupSep})
	h.Write([]byte(innerHex))
	return hex.EncodeToString(h.Sum(nil))
}
