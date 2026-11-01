package orgclient

import "github.com/marmutapp/superbased-observer/internal/orgcontract"

// security_pullcaps.go names the security rail's optional served fields this
// build applies (lane LEFT-SHARED, orgcontract securitypull_served.go): the
// org's approvals of this node's baselines and the org's finding dedupe key
// (which the server serves to a managed member's node only). The server serves a field only
// to a node that names it (ManagedPullCapabilitiesHeader), and the rail is
// pulled only while the security module's consumer is registered, so a build
// without it sends nothing.
func init() {
	managedPullCapabilities["security"] = append(managedPullCapabilities["security"],
		orgcontract.SecurityCapabilityBaselineApprovals, orgcontract.SecurityCapabilityOrgDedupe)
	// The served dedupe key lives only in the node's owner-only key file:
	// the cache keeps the signed body with the key blanked and restores it
	// from that file on load (merge audit finding 4).
	managedPullCacheCodecs["security"] = managedPullCacheCodec{
		strip: orgcontract.StripSecurityOrgDedupeKey,
		restore: func(body []byte) ([]byte, error) {
			return orgcontract.RestoreSecurityOrgDedupeKey(body, func() (orgcontract.SecurityOrgDedupe, bool) {
				if SecurityOrgDedupeKeySource == nil {
					return orgcontract.SecurityOrgDedupe{}, false
				}
				return SecurityOrgDedupeKeySource()
			})
		},
	}
}

// SecurityOrgDedupeKeySource reads the org dedupe key the node holds (its
// owner-only key file, secsvc.ReadOrgDedupe), set by the daemon's security
// wiring. nil (a build or a process without it) holds no key, so a cached
// security document that carried one does not verify and is fetched again.
var SecurityOrgDedupeKeySource func() (orgcontract.SecurityOrgDedupe, bool)
