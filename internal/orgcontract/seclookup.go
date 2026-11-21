package orgcontract

// seclookup.go is the wire shape of the security relay lookup (security
// pillar plan section 8.3 "Managed nodes: the org relay"; spike JSP-11): a
// managed node sends its install-gate online queries only to its org
// server, POST AgentSecurityLookupPath under the enrolment bearer, and
// never to a public source. The server half (relay and mirror modes,
// internal/orgserver/secrelay, lane SEC-E4) answers only while the
// org.security.relay component is configured and the org's super admin chose
// a mode; otherwise the route answers 404 not_supported and the node reads
// every query as online_unknown.
//
// Only public-routable package names are sent; private and invalid names
// never leave the node, not even to the relay.

// AgentSecurityLookupPath is the relay lookup route.
const AgentSecurityLookupPath = "/api/agent/security/lookup"

// SecurityLookupMaxQueries caps one lookup.
const SecurityLookupMaxQueries = 64

// SecurityLookupDefaultPerMinute is the relay's default per-node rate: one
// lookup (one request of up to SecurityLookupMaxQueries names) counts once.
// The install gate and a dependency scan share it, so a scan paces itself
// to half of it (SEC-H2 merge, audit finding 1).
const SecurityLookupDefaultPerMinute = 60

// SecurityLookupReasonNotPublic is the reason of an answer the relay
// refuses because the org's own configuration makes the name private. The
// node reads it as withheld for that package only.
const SecurityLookupReasonNotPublic = "not_public"

// SecurityLookupQuery is one package.
type SecurityLookupQuery struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

// SecurityLookupRequest is the node's batch.
type SecurityLookupRequest struct {
	Queries []SecurityLookupQuery `json:"queries"`
}

// SecurityLookupAnswer is one answer. Status is the install gate's online
// status vocabulary (answered, not_found, failed); FirstPublished is
// RFC3339 or "" (always "" in mirror mode, where registry facts are absent).
type SecurityLookupAnswer struct {
	Ecosystem      string   `json:"ecosystem"`
	Name           string   `json:"name"`
	Version        string   `json:"version,omitempty"`
	Status         string   `json:"status"`
	FirstPublished string   `json:"first_published,omitempty"`
	MalIDs         []string `json:"mal_ids,omitempty"`
	VulnIDs        []string `json:"vuln_ids,omitempty"`
	// MalAllVersions reports that one of MalIDs covers every version of
	// the package (secfeed.OnlineAnswer.MalAllVersions), so an unpinned
	// install of it is malicious, not "some versions".
	MalAllVersions bool   `json:"mal_all,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// SecurityLookupResponse is the relay's answer. Mode is "relay" or
// "mirror".
type SecurityLookupResponse struct {
	Mode    string                 `json:"mode"`
	Answers []SecurityLookupAnswer `json:"answers"`
}

// AgentSecurityContentPath is the prefix of the org mirror's content route
// (lane SEC-E4): GET AgentSecurityContentPath + "<kind>/<file>" serves a
// mirrored kind's vendor-signed envelope (SecurityContentManifestFile) or
// one artifact its manifest names (query parameters os and arch select a
// platform entry), each with an ETag and 304. It answers 404 not_supported
// while the relay is not configured or its mode is off, which a node keeps
// (its last-known-good content stays and is reported stale, never clean).
const AgentSecurityContentPath = "/api/agent/security/content/"

// AgentSecurityShardsPath is the prefix of the org mirror's shard route
// (lane RM-3, OS and CI vulnerability scanning plan 13.5 "or the org server
// on a managed node"): GET AgentSecurityShardsPath + "<Set>/index/<sha256>.json"
// or "<Set>/obj/<sha256>.json.gz" serves one content-addressed object of the
// security.osv_shards kind the org mirrors (osvshardkey.ParseObjectPath is
// the one path check), with the digest as its ETag. It serves a managed
// enrolment whose org's signed security policy turns the package lookup on
// (package_lookup = org_mirror) and answers 403
// SecurityShardsNotEnabledCode otherwise, 404 not_supported while the relay
// is not configured or its mode is off, and 404 not_mirrored for an object
// the org's mirror does not hold.
const AgentSecurityShardsPath = "/api/agent/security/shards/"

// SecurityShardsNotEnabledCode is the shard route's refusal for a caller
// whose org's security policy does not turn the package lookup on.
const SecurityShardsNotEnabledCode = "lookup_not_enabled"

// SecurityContentManifestFile is the envelope's file name on the content
// route (the content channel's own name for it).
const SecurityContentManifestFile = "manifest.json"
