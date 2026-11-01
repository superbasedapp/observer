package guardposture

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Node-local consent records under the posture key (lane sec-deps4 audit
// finding 1).
//
// A few records are the developer's own consent, written only by an
// explicit action on the CLI or the dashboard: the scanners' OSV database
// accept (osv-db-consent.json) and the online checks' disclosure
// (online-disclosure.json). A reader must not take an agent's hand-written
// JSON for that consent, so the accepting process signs the record under
// the posture key with the posture's own construction (HMAC-SHA256 over a
// domain line and the record's canonical bytes), and the reader verifies
// it. Each record has its own domain, so a MAC computed for one record, or
// for the posture, never verifies as another.
//
// The honesty framing is the posture's (auth.go): the key sits beside the
// files, readable by the same user, so a same-user process that reads the
// key can sign a record. What the MAC buys is that a plain write (an echo,
// a copy, a generic JSON writer) no longer counts as consent, and guard
// rule R-165 refuses an agent's write to the record files outright.

// RecordMAC returns the hex MAC of a record's canonical bytes under key,
// separated by domain.
func RecordMAC(domain string, body, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(recordInput(domain, body))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyRecordMAC reports whether sum is the MAC of body under key in
// domain. An empty key, an empty or malformed sum is never valid.
func VerifyRecordMAC(domain string, body, key []byte, sum string) bool {
	if len(key) == 0 || sum == "" || domain == "" {
		return false
	}
	want, err := hex.DecodeString(sum)
	if err != nil {
		return false
	}
	got, _ := hex.DecodeString(RecordMAC(domain, body, key))
	return hmac.Equal(want, got)
}

// recordInput is the MAC input: the domain, a newline, the body.
func recordInput(domain string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString(domain)
	b.WriteByte('\n')
	b.Write(body)
	return b.Bytes()
}
