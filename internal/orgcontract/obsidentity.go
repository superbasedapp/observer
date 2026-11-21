package orgcontract

import (
	"crypto/sha256"
	"encoding/hex"
)

// obsIdentityDomain separates the obs identity hashes from every other hash
// on the wire.
const obsIdentityDomain = "sbo-obs-identity-v1"

// Obs identity hash kinds (the second domain component).
const (
	ObsIdentityEndUser = "end_user"
	ObsIdentityTenant  = "tenant"
)

// HashObsIdentity returns the grouping key for a hosted app's end user or
// tenant: hex SHA-256 over (domain, kind, orgID, value), NUL-separated. It is
// bound to the org so the same end user hashes differently in two orgs (no
// cross-tenant correlation on a pooled server). It is pseudonymous, not
// anonymous: anyone holding the org id can test a guessed value (end users
// are usually emails or sequential ids), so the hash is as sensitive as the
// value and ships under the same gate (operator ruling D23, review R-A02).
// Empty value -> "".
func HashObsIdentity(kind, orgID, value string) string {
	if value == "" {
		return ""
	}
	h := sha256.New()
	for _, part := range []string{obsIdentityDomain, kind, orgID, value} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PrepareForWire stamps attribution onto a T2 trace row and applies the T2
// trace gate. With raw (the node's ShareOptions.shipsRawContent()) the gated
// fields ship and the end-user and tenant hashes are computed from the raw
// values. Without it every gated field is stripped: ProjectRoot, EndUser,
// Tenant, Tags, Metadata, and also EndUserHash and TenantHash, because an
// unkeyed org-bound hash lets the org test a guessed end user (D23, the end
// user spend tier's rule in internal/store/orgpush.go). A keyed per-node
// HMAC that groups without being testable is a later option. This is the
// ONE place the T2 trace gate lives; the org-push seam calls it per row.
func (r *ObsTraceRow) PrepareForWire(orgID, userEmail string, raw bool) {
	r.OrgID, r.UserEmail = orgID, userEmail
	if !raw {
		r.ProjectRoot = ""
		r.EndUser, r.EndUserHash = "", ""
		r.Tenant, r.TenantHash = "", ""
		r.Tags = nil
		r.Metadata = nil
		return
	}
	if r.EndUserHash == "" {
		r.EndUserHash = HashObsIdentity(ObsIdentityEndUser, orgID, r.EndUser)
	}
	if r.TenantHash == "" {
		r.TenantHash = HashObsIdentity(ObsIdentityTenant, orgID, r.Tenant)
	}
}
