package orgcontract

// EnrollRequest is the body of POST /api/agent/enroll. The agent presents a
// one-time enrolment token (minted by an admin) and a freshly generated
// Ed25519 public key the server binds to the user record.
//
// The token is a compound "<token_id>.<secret>": the admin mints it once and
// hands the whole string to the developer, who runs `observer enroll <org-url>
// <token>`. The server resolves the user from the token_id and verifies the
// secret, so the developer never needs to know their SCIM user id — that is
// why this request carries no user_id field.
type EnrollRequest struct {
	OneTimeToken   string `json:"one_time_token"`   // "<token_id>.<secret>"
	AgentPublicKey string `json:"agent_public_key"` // base64url-encoded Ed25519 public key

	// Capabilities are tokens the enrolling node advertises so the server
	// shapes the signed grant to what this node can verify (today only
	// EnrolCapabilityInitialComponents; see GrantForNode). omitempty on both
	// sides of the compat invariant: an older server decodes the request
	// without DisallowUnknownFields and ignores it, and an older node sends
	// none, so the server never offers it a field it would fail to verify.
	Capabilities []string `json:"capabilities,omitempty"`

	// AttachGrant is the one-step attach grant (internal/attachgrant) the
	// SuperBased cloud handed this machine when its owner clicked Connect
	// for this dashboard (Getting started v2). It replaces OneTimeToken: a
	// request carries one or the other. omitempty both ways: an older server
	// ignores it (and then refuses the request for its missing token, which
	// the node reads as "this server takes no grant"), and an older node
	// never sends it.
	AttachGrant string `json:"attach_grant,omitempty"`
	// AttachProof is the device proof that rides with AttachGrant: the
	// device key the connect request was made with, and its signature over
	// the grant and AgentPublicKey (attachgrant.ProofMessage). A copied
	// grant without the device key is useless.
	AttachProof *AttachProof `json:"attach_proof,omitempty"`
}

// AttachProof is the wire shape of attachgrant.Proof (orgcontract does not
// import the grant package; the server converts).
type AttachProof struct {
	// DevicePublicKey is the raw 32-byte Ed25519 device key, base64url.
	DevicePublicKey string `json:"device_public_key"`
	// Signature is the device key's Ed25519 signature, base64url.
	Signature string `json:"signature"`
}

// EnrollResponse is the 200 body of POST /api/agent/enroll. The bearer is
// a signed JSON envelope (see BearerClaims) the agent stores in its OS
// keychain and presents on every push.
//
// UserID is the server-resolved SCIM user id the compound enrolment token
// bound to. The agent persists it in org_enrolment.user_id (a NOT NULL
// column) — the request carries no user_id, so the server must echo it back
// here for the agent to record its own identity without re-deriving it from
// the bearer claims.
type EnrollResponse struct {
	Bearer          string `json:"bearer"`
	BearerExpiresAt string `json:"bearer_expires_at"` // RFC3339
	OrgID           string `json:"org_id"`
	OrgName         string `json:"org_name"`
	UserID          string `json:"user_id"` // SCIM user id resolved from the token
	UserEmail       string `json:"user_email"`

	// OrgPolicyPublicKey is the base64url Ed25519 public half of the org's
	// POLICY signing key (guard spec §14.2), delivered at enrol time so the
	// agent can pin it (sha256 of the raw key bytes, stored in
	// guard_policy_state) before the first policy-bundle fetch. omitempty on
	// both sides of the compat invariant: a pre-G13 server omits the field
	// and the agent falls back to trust-on-first-fetch pinning; a pre-G13
	// agent ignores the unknown key. Servers without a configured policy
	// signing key also omit it — the field is never required.
	OrgPolicyPublicKey string `json:"org_policy_public_key,omitempty"`

	// Tenancy is the enrolment CLASS this node enrolled under:
	// TenancyIndividual (the default and only behaviour for a BYO node —
	// "Never server-forced" holds absolutely) or TenancyManaged (an
	// org-provisioned node that opts into comprehensive Enterprise-Managed
	// admin control). omitempty on both sides of the compat invariant: a
	// pre-managed server omits it and the node defaults to individual; a
	// pre-managed agent ignores the unknown key. It rides at the same
	// authenticated-TLS trust level as OrgID/OrgName; the managed
	// AUTHORITIES it unlocks live in the SIGNED Grant.Authority, and the node
	// honours them only when it recorded ConsentMode=managed from this field.
	Tenancy string `json:"tenancy,omitempty"`

	// OwnerManaged is true when this organization's only admin and its only
	// developer are the same person (a personal organization, managed by its
	// owner since the 2026-11-19 ruling: orgkind's OwnerManaged row
	// capability). It grants NOTHING: the authority is in the signed Grant,
	// honoured only under managed tenancy as for any team. It changes only
	// the words on the consent screen, so the owner reads that the
	// organization asking is their own. omitempty on both sides of the
	// compat invariant: an older server never sends it (the screen keeps its
	// team wording) and an older agent ignores it.
	OwnerManaged bool `json:"owner_managed,omitempty"`

	// SDKKeys says whether a member's own machine can get the member's SDK
	// key from this organization (POST AgentSDKCredentialPath):
	// SDKKeysMember when it can, SDKKeysAdminOnly when the server issues no
	// member keys and an admin creates app keys instead, SDKKeysNotOnPlan
	// when the organization's plan does not include AI Apps (a hosted server).
	// A node that does not know a value prints its "unknown" wording.
	// enrolling (SR-9): it never gates a request. omitempty on both sides of
	// the compat invariant: an older server never sends it (the node then
	// says it does not know) and an older agent ignores it.
	SDKKeys string `json:"sdk_keys,omitempty"`

	// ConsentMode / ConsentActor record HOW this enrolment was consented to
	// when the server itself knows the answer, which today means exactly one
	// case: an enrolment minted by the ACP-P6c IdP device-code rail
	// (enrolment_tokens.minted_via = 'idp'). ConsentMode is then "idp" and
	// ConsentActor is the VERIFIED address of the member who approved the
	// pairing in a browser after an enterprise-IdP sign-in — the identity
	// that replaces the spoofable local $USER the node would otherwise
	// record. Every other rail leaves both empty and the node resolves the
	// consent mode from tenancy exactly as before.
	//
	// omitempty on both sides of the compat invariant: a pre-P6c server never
	// emits them (the node falls back to token-rail semantics), and a pre-P6c
	// agent ignores the unknown keys.
	//
	// These ride at the ENVELOPE trust level (authenticated TLS, like OrgID
	// and Tenancy). The same two facts are also bound into the SIGNED
	// EnrolmentGrant for an idp mint, so a node holding a grant prefers the
	// signed copy and treats these as the fallback (see
	// orgclient.GrantOffer).
	ConsentMode  string `json:"consent_mode,omitempty"`
	ConsentActor string `json:"consent_actor,omitempty"`

	// Grant is the OPTIONAL enrolment grant (admin-controlled Plane B,
	// docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §2.3/§2.4):
	// the bounded authority this organization is OFFERING the enrolling
	// node. omitempty on both sides of the compat invariant: a
	// pre-governance server omits it (the node enrols ungoverned, exactly
	// as today), and a pre-governance agent ignores the unknown key.
	//
	// It is an OFFER, not a fact: the node writes a grant row only after
	// (a) the org policy key was pinned in this same enrolment, (b) the
	// signature verifies under that key, and (c) a human confirmed it on a
	// TTY (or --accept-governance was passed). Any of those failing means
	// the node enrols WITHOUT governance and says so loudly.
	Grant *EnrolmentGrant `json:"grant,omitempty"`
}

// Tenancy classes carried on EnrollResponse.Tenancy and stored both server-
// side (enrolment_tokens.tenancy) and node-side (org_enrolment.tenancy). The
// empty string is treated as TenancyIndividual everywhere so a pre-managed
// server or a pre-084 node behaves exactly as an individual node.
const (
	TenancyIndividual = "individual"
	TenancyManaged    = "managed"
)

// ValidTenancy reports whether s is a recognised tenancy class. The empty
// string is INVALID here (callers normalise it to TenancyIndividual first);
// this is the mint-time check that refuses an unknown class.
func ValidTenancy(s string) bool {
	return s == TenancyIndividual || s == TenancyManaged
}

// ManagedBindRequest is the body of POST /api/agent/managed-bind, the SECOND
// step of managed enrolment (Arc 4 P6a, plan §9). A node that enrolled under
// TenancyManaged presents its org-salted machine fingerprint so the server can
// bind one managed node to one machine and surface a collision to the admin.
// An individual/BYO node NEVER calls this endpoint and never computes a
// fingerprint — the individual plane sends no machine identity at all, which is
// why this rides its own bearer-authenticated request rather than a field on
// EnrollRequest.
//
// MachineIdentity is the opaque, one-way, org-salted hash from
// internal/machineid.ForOrg — never the raw OS machine id. The agent skips the
// call entirely (rather than sending "") on a host with no stable source, so a
// non-empty value is expected here.
type ManagedBindRequest struct {
	MachineIdentity string `json:"machine_identity"`
}

// ManagedBindResponse is the 200 body of POST /api/agent/managed-bind. Status
// is one of the ManagedBind* values. Collision is true only when the machine
// was already bound to a DIFFERENT active developer: under the server's
// "record" posture the bind still succeeds (evidence, not prevention) and
// Status is ManagedBindCollision, while under "enforce" the server returns 409
// instead of this body.
type ManagedBindResponse struct {
	Status    string `json:"status"`
	Collision bool   `json:"collision"`
}

// ManagedBind* are the ManagedBindResponse.Status values.
const (
	ManagedBindBound      = "bound"      // first binding for this (org, machine)
	ManagedBindRebound    = "rebound"    // same developer re-enrolling the same machine
	ManagedBindReassigned = "reassigned" // prior binding's developer deprovisioned; machine reassigned
	ManagedBindCollision  = "collision"  // machine already bound to a different ACTIVE developer (record posture)
)

// BearerClaims is the JSON envelope signed with the server's Ed25519 key.
// It is JWT-shaped but is not a JWT: there is no algorithm negotiation and
// no JWS library — one key type, one algorithm, decoded by hand. exp/iat
// are Unix seconds.
type BearerClaims struct {
	Iss string `json:"iss"` // issuer: the org server external URL
	Sub string `json:"sub"` // subject: the SCIM user id
	Aud string `json:"aud"` // audience: the org id
	Exp int64  `json:"exp"` // expiry, Unix seconds
	Iat int64  `json:"iat"` // issued-at, Unix seconds
	Jti string `json:"jti"` // unique token id (for the revocation list)
}
