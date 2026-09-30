package guidance

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: git defines its blob object id as sha1("blob "+decimal(len(body))+"\x00"+body) — this is an object-identity hash fixed by git's own data model, not a security primitive, and there is no algorithm choice to make.
	"encoding/hex"
	"strconv"
)

// GitBlobOID computes the git blob object id for body: the same
// lowercase-hex sha1 `git hash-object` would report for a file whose
// on-disk bytes are exactly body, under git's header convention
// "blob " + decimal(len(body)) + NUL + body.
//
// oidLF is the SAME computation over body with every CRLF ("\r\n")
// normalized to LF ("\n") first — the id git would compute for that
// same file checked out under `core.autocrlf`/a `.gitattributes` text
// normalization rule, which rewrites CRLF to LF on the way into the
// object store. oidLF is populated ONLY when body actually contains at
// least one "\r\n"; a body with no CRLF at all normalizes to itself, so
// oidLF would just duplicate oid, and "" is the more useful "nothing to
// compare" signal for a caller checking two blob ids for a match under
// either line-ending convention.
func GitBlobOID(body []byte) (oid, oidLF string) {
	oid = blobSHA1(body)
	if bytes.Contains(body, []byte("\r\n")) {
		oidLF = blobSHA1(bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n")))
	}
	return oid, oidLF
}

// blobSHA1 hashes body under git's blob object-id header convention.
func blobSHA1(body []byte) string {
	header := "blob " + strconv.Itoa(len(body)) + "\x00"
	h := sha1.New() //nolint:gosec // G401: git's own object model is fixed to sha1 for blob ids — not a security primitive.
	h.Write([]byte(header))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
