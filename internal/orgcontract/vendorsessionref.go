package orgcontract

import "regexp"

// MaxVendorSessionRefRunes bounds a vendor session reference
// (SessionRow.VendorSessionRef, cloud-agents arc CA-D2). Real references are
// short: a Claude Code `cse_...` id, a `ccr.session.id` UUID, a GitHub
// `agent_session_id`, a Cursor `bc-<uuid>`, a Devin or OpenHands session id.
// Anything longer is a mis-decoded field, not an id.
const MaxVendorSessionRefRunes = 128

// vendorSessionRefPattern is the ONE grammar for a vendor session reference,
// enforced identically at both boundaries that write a vendor_session_ref
// column: the node (internal/store/cloudsessions.go::SetSessionExecution, on
// capture) and the org server (internal/orgserver/ingest, on landing a pushed
// row). An ASCII alphanumeric lead, then up to 127 characters from the
// alphanumeric + "." + "_" + ":" + "-" charset.
//
// What it is and is not. The reference is an OPAQUE vendor-minted id, the
// same class as sessions.id and sessions.parent_thread_id, which ship as
// metadata with no grammar at all. This grammar is STRUCTURAL: it keeps
// prose, paths, URLs, e-mail addresses and anything carrying whitespace,
// "/", "@", "=" or "?" out of the column. It does NOT try to tell an id from
// a compact secret (unlike orgcontract.ValidToolVersion, whose digit-led,
// dot-bearing requirement does): a session id is opaque noise by design, so
// no positive shape exists to require. The safeguard is the source: capture
// paths read the reference from a vendor-authored id field, never from a
// credential field.
var vendorSessionRefPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._:-]{0,127}$`)

// ValidVendorSessionRef reports whether ref is a plausible vendor session
// reference under vendorSessionRefPattern. An empty string is never valid:
// the honest "unknown" is the caller writing NULL, not this function passing
// "".
func ValidVendorSessionRef(ref string) bool {
	return vendorSessionRefPattern.MatchString(ref)
}
