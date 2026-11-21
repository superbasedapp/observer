package orgcontract

// The SDK credential rail (Plane A build-out W2-7, ruling D18; contract
// docs/plans/plane-a-sdk-buildout/contracts/destination.md section 6): a
// signed-in member's own machine asks the org for a scoped SDK key, so the
// superbased SDKs on that machine can send an app's data to the org gateway
// (destination online or both). The machine authenticates with its
// enrolment bearer; the org binds the key to the bearer's member, never to a
// body field.

// AgentSDKCredentialPath is POST (mint) and DELETE (revoke) on the org
// server. Both take an optional SDKCredentialRequest body naming the key the
// calling machine holds, so a member's sign-in or sign-out on one machine
// never ends the key of another (review finding R-B05).
const AgentSDKCredentialPath = "/api/agent/sdk-credential" //nolint:gosec // G101: a route path, not a credential

// SDKCredentialRequest is the optional JSON body of a mint or a revoke.
type SDKCredentialRequest struct {
	// KeyID is the key id of the SDK key this machine holds ("" when it holds
	// none). A mint revokes only that key, once the new one exists; a revoke
	// revokes only that key. A body without it (an older machine): a mint
	// revokes nothing, and a revoke is refused unless it sets All.
	KeyID string `json:"key_id,omitempty"`
	// All asks a revoke to end every live SDK key of the member, the
	// explicit "sign out everywhere" (`observer sdk sign-out --all`). A
	// revoke that names neither a key nor All is refused (400
	// key_id_required), so a machine that holds no key never ends every
	// other machine's key by accident (review E-28, ruling D29). A mint
	// ignores it.
	All bool `json:"all,omitempty"`
}

// SDKCredentialMinted is the 200 body of a mint. Credential is the compound
// "<key_id>.<secret>", sent once and never stored by the org.
type SDKCredentialMinted struct {
	CredID      string `json:"cred_id"`
	KeyID       string `json:"key_id"`
	Credential  string `json:"credential"`
	OrgID       string `json:"org_id"`
	WorkspaceID string `json:"workspace_id"`
	// EnvironmentID is "" for the workspace's default environment.
	EnvironmentID string   `json:"environment_id,omitempty"`
	Scopes        []string `json:"scopes"`
	Signals       []string `json:"signals"`
	// GatewayURL is the org gateway's OTLP base address the SDK sends to
	// ("" when the org published none; the machine then needs
	// [observability.sdk] gateway_url).
	GatewayURL string `json:"gateway_url"`
	MintedAt   string `json:"minted_at"`
	// ExpiresAt is RFC 3339, or "" for no expiry.
	ExpiresAt string `json:"expires_at,omitempty"`
	// CaptureLevel is the capture level the key's workspace applies to what
	// the key sends, as the gateway reads it at mint time: "metadata_only"
	// (L0), "classified_safe" (L1) or "full_redacted" (L2); "" when the org
	// could not read it or predates the field (review L-23). It is the org's
	// workspace policy, shown to the member so a key that keeps no content
	// or end user says so.
	CaptureLevel string `json:"capture_level,omitempty"`
	// Replaced is how many earlier SDK keys of this member the mint revoked:
	// the key the machine named, plus the oldest beyond the member's cap.
	Replaced int `json:"replaced"`
}

// SDKCredentialRevoked is the 200 body of a revoke.
type SDKCredentialRevoked struct {
	// Revoked is how many live SDK keys of this member were revoked.
	Revoked int `json:"revoked"`
}
