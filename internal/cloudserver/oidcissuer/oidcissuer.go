package oidcissuer

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Protocol constants.
const (
	// IssuerPath is the path the issuer lives at on the portal origin. The
	// issuer identifier is the portal origin plus this path; the four
	// endpoints hang below it, so one canonical-host rule covers them all.
	IssuerPath = "/oauth2"
	// AuthorizePath, TokenPath, JWKSPath and DiscoveryPath are the endpoint
	// paths relative to the origin (IssuerPath plus the endpoint).
	AuthorizePath = IssuerPath + "/authorize"
	TokenPath     = IssuerPath + "/token"
	JWKSPath      = IssuerPath + "/jwks.json"
	DiscoveryPath = IssuerPath + "/.well-known/openid-configuration"

	// AlgRS256 is the only id_token signing algorithm (design A6: the tenant
	// rail verifies RSA only).
	AlgRS256 = "RS256"
	// ChallengeMethodS256 is the only PKCE method; plain is refused.
	ChallengeMethodS256 = "S256"
	// ClientIDPrefix starts every client id: "org:" + the org id.
	ClientIDPrefix = "org:"
	// TenantCallbackPath is the tenant rail's redirect path
	// (internal/orgserver/auth DefaultOIDCRedirectPath).
	TenantCallbackPath = "/auth/oidc/callback"

	// CodeTTL is how long an authorization code may be redeemed.
	CodeTTL = 60 * time.Second
	// TokenLifetime is the id_token lifetime the issuer asks for, and
	// MaxTokenLifetime the most the signer will sign.
	TokenLifetime    = 5 * time.Minute
	MaxTokenLifetime = 5 * time.Minute
	// MaxIATSkew bounds how far the signer's clock may disagree with an iat
	// it is asked to sign.
	MaxIATSkew = 60 * time.Second
	// MinRSABits is the smallest RSA modulus the signer loads (design 3.3:
	// RSA 3072).
	MinRSABits = 3072
)

// OAuth 2.0 / OIDC error codes the issuer answers with.
const (
	ErrCodeInvalidRequest          = "invalid_request"
	ErrCodeInvalidClient           = "invalid_client"
	ErrCodeInvalidGrant            = "invalid_grant"
	ErrCodeUnauthorizedClient      = "unauthorized_client"
	ErrCodeUnsupportedResponseType = "unsupported_response_type"
	ErrCodeUnsupportedGrantType    = "unsupported_grant_type"
	ErrCodeInvalidScope            = "invalid_scope"
	ErrCodeAccessDenied            = "access_denied"
	ErrCodeLoginRequired           = "login_required"
	ErrCodeInteractionRequired     = "interaction_required"
	ErrCodeRequestNotSupported     = "request_not_supported"
	ErrCodeTemporarilyUnavailable  = "temporarily_unavailable"
	ErrCodeServerError             = "server_error"
)

// Signing key statuses (oidc_signing_keys.status).
const (
	KeyStaged   = "staged"
	KeyActive   = "active"
	KeyRetiring = "retiring"
	KeyRetired  = "retired"
)

// KnownKeyStatuses returns every signing key status, in lifecycle order. The
// SQL CHECK on oidc_signing_keys.status holds the same values.
func KnownKeyStatuses() []string {
	return []string{KeyStaged, KeyActive, KeyRetiring, KeyRetired}
}

// ErrNotFound is what a Store returns when a client is unknown or a code is
// unknown, already consumed or expired. The issuer never tells those apart to
// a caller.
var ErrNotFound = errors.New("oidcissuer: not found")

// ErrClaimsRefused is what a signer returns when the claims it is asked to
// sign break a rule of ValidateClaims, or name a kid it does not hold.
var ErrClaimsRefused = errors.New("oidcissuer: claims refused")

// Error is an OAuth 2.0 protocol error: the code and description the caller
// sees, the HTTP status it is answered with, and the rule that produced it
// (for logs and tests; never shown to the caller).
type Error struct {
	Code        string
	Description string
	Status      int
	RuleID      string
}

// Error implements error.
func (e *Error) Error() string {
	return fmt.Sprintf("oidcissuer: %s (%s): %s", e.Code, e.RuleID, e.Description)
}

// Client is one registered OIDC client: one per org, public, one redirect URI.
type Client struct {
	ClientID     string
	OrgID        string
	RedirectURIs []string
	Disabled     bool
}

// Member is what the issuer needs to know about the caller and the org at
// authorize and again at token time.
type Member struct {
	// IsMember is false when the caller holds no membership in the org (or
	// the org does not exist; the two are not told apart).
	IsMember bool
	// AccountStatus is accounts.status; only "active" may sign in.
	AccountStatus string
	// OrgStatus is orgs.status (the platform tenant lifecycle vocabulary);
	// only "active" may sign in.
	OrgStatus string
	// RailEnabled is orgs.platform_rail_enabled (false: the org opted out).
	RailEnabled bool
	// Sub is the caller's identity-provider subject (the WorkOS user id).
	Sub string
	// Email is the caller's provider-asserted email, as the identity
	// provider returned it at the caller's latest sign-in.
	Email string
	// EmailVerified is the identity provider's own `email_verified` flag for
	// Email from that same sign-in; false when the provider sent none. The
	// issuer refuses unless it is true (operator item A4).
	EmailVerified bool
	// RequireSecondFactor is orgs.require_second_factor (cloud 0131): the
	// org requires every member to sign in with a passkey second factor
	// (C2). The issuer then issues only to a session whose amr is
	// multi-factor, at authorize and again at token time.
	RequireSecondFactor bool
}

// CodeRecord is one oidc_codes row. Only the hash of the code is stored.
type CodeRecord struct {
	CodeHash  string
	ClientID  string
	OrgID     string
	AccountID string
	Sub       string
	Email     string
	// EmailVerified travels with Email and, like it, is re-read from the
	// member at token time; it is not persisted in oidc_codes.
	EmailVerified bool
	Nonce         string
	CodeChallenge string
	RedirectURI   string
	AMR           []string
	// AuthTime is when the person authenticated to establish the portal
	// session the code was issued from (Session.AuthTime); it becomes the
	// id_token's auth_time. Persisted (oidc_codes.auth_time, cloud 0083).
	AuthTime  time.Time
	CreatedAt time.Time
	ExpiresAt time.Time
	// Support marks a support code (oidc_support_codes, M7a.2): written by
	// the staff process for StaffID, carrying no account, sub or email. Token
	// redeems it through the support branch only.
	Support bool
	StaffID string
}

// JWK is one RSA JSON Web Key (public half only).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// PublicKey is a public key a signer holds, named by its kid.
type PublicKey struct {
	KID string
	JWK JWK
}

// SigningKey is one oidc_signing_keys row.
type SigningKey struct {
	KID       string
	Alg       string
	JWK       JWK
	VMID      string
	Status    string
	NotBefore time.Time // zero: not set (a staged key)
	NotAfter  time.Time // zero: open-ended
}

// Issuance is what is recorded, in one transaction, before an id_token is
// returned: the oidc_issued row and the oidc_audit_mirror outbox row.
type Issuance struct {
	JTI           string
	OrgID         string
	AccountID     string
	Sub           string
	ClientID      string
	KID           string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	MirrorPayload []byte
}

// Store is the issuer's database seam (internal/cloudserver/store OIDCStore
// implements it; tests use an in-memory fake). Every method is one
// transaction.
type Store interface {
	// Client returns the client; ErrNotFound when there is none.
	Client(ctx context.Context, clientID string) (Client, error)
	// Member resolves the caller accountID against org orgID through the
	// caller's own membership (row-level security decides).
	Member(ctx context.Context, accountID, orgID string) (Member, error)
	// PutCode stores a new code.
	PutCode(ctx context.Context, c CodeRecord) error
	// ConsumeCode marks the code consumed and returns it, in one conditional
	// statement; ErrNotFound when the code is unknown, consumed or expired
	// at now.
	ConsumeCode(ctx context.Context, codeHash string, now time.Time) (CodeRecord, error)
	// SigningKeys returns every key that is not retired.
	SigningKeys(ctx context.Context) ([]SigningKey, error)
	// StageSigningKeys registers keys a signer reports as "staged"; a kid
	// already registered is left as it is.
	StageSigningKeys(ctx context.Context, vmID string, keys []PublicKey, now time.Time) error
	// RecordIssuance writes the issued-token row and its audit-mirror outbox
	// row in one transaction. A jti seen before is an error.
	RecordIssuance(ctx context.Context, iss Issuance) error
}

// Signer holds the private keys. It validates the claims it is given
// (ValidateClaims) and refuses anything else.
type Signer interface {
	// Sign returns the compact RS256 JWS of c under the key kid.
	Sign(ctx context.Context, kid string, c Claims) (string, error)
	// PublicKeys returns the public halves of every key the signer holds.
	PublicKeys(ctx context.Context) ([]PublicKey, error)
}
