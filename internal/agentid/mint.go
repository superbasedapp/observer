package agentid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// Token lifetime bounds (C1 / R9.1).
const (
	// DefaultTokenTTL is the default access-token lifetime (5 min).
	DefaultTokenTTL = 300 * time.Second
	// MaxTokenTTL is the hard ceiling an org may configure (60 min).
	MaxTokenTTL = 3600 * time.Second
)

// Size budget (§4.7 / R8.13).
const (
	// AccessTokenTargetBytes is the access-token target; beyond it the mint
	// switches to a reference grant.
	AccessTokenTargetBytes = 4 << 10
	// MaxAuthHeadersBytes is the enforced per-ingress ceiling for the combined
	// Authorization + DPoP headers.
	MaxAuthHeadersBytes = 8 << 10
	// MaxGroups bounds sbo_groups.
	MaxGroups = 64
	// MaxActDepth bounds the RFC 8693 actor chain.
	MaxActDepth = 4
	// MaxAccessTokenBytes is the parse cap for an inbound access token.
	MaxAccessTokenBytes = 8 << 10
)

// ErrTokenTooLarge is returned when a token cannot be brought under budget
// even with a reference grant.
var ErrTokenTooLarge = errors.New("agentid: token exceeds the size budget")

// Generations are the revocation generation claims (§4.6).
type Generations struct {
	Member, Cred, Policy, IssuerEpoch int64
}

// MintOptions carries everything Mint needs beyond doc3 §2.4's positional
// (signer, principal, aud, ttl, grants) arguments.
type MintOptions struct {
	// Issuer is the stable public HTTPS issuer URL (R8.26.f). Required.
	Issuer string
	// Now is the issuance instant (zero -> time.Now()).
	Now time.Time
	// Rand is the jti entropy source (nil -> crypto/rand).
	Rand io.Reader
	// MaxTTL is the org ceiling (zero -> MaxTokenTTL; never above it).
	MaxTTL time.Duration
	// Cnf binds the token (DPoP jkt or mTLS x5t#S256). nil = bearer, the
	// default sender constraint (R9.1).
	Cnf *Confirmation
	// Scope is the space-delimited OAuth scope.
	Scope string
	// Session/Run/AgentInstance are the sbo_session/sbo_run/sbo_agent_instance claims.
	Session, Run, AgentInstance string
	// Gens are the generation claims.
	Gens Generations
	// CredentialID is the credential subject Gens.Cred was read under (the
	// value the minter also records as the issuance credential id). It is
	// stamped as the optional sbo_cred claim so a verifier can hold the
	// token to that credential's invalidation floor (§4.6). "" = no
	// credential subject: the claim is omitted.
	CredentialID string
	// TargetBytes overrides AccessTokenTargetBytes (tests).
	TargetBytes int
}

// Mint issues an RFC 9068 at+jwt for p with exact single audience aud. The
// header is {typ:"at+jwt", alg:<active key's alg>, kid:<active kid>}. ttl <= 0
// means DefaultTokenTTL; a ttl above the org ceiling is clamped to it. When
// the token exceeds the size target, authorization_details collapses to one
// sbo_mcp_grant reference digest (§4.7).
func Mint(kp ServerTokenSigner, p Principal, aud string, ttl time.Duration, grants []GrantDetail, o MintOptions) (string, Claims, error) {
	if kp == nil {
		return "", Claims{}, errors.New("agentid.Mint: nil key provider")
	}
	c, err := buildClaims(p, aud, ttl, grants, o)
	if err != nil {
		return "", Claims{}, err
	}
	kid, s, err := kp.Active()
	if err != nil {
		return "", Claims{}, fmt.Errorf("agentid.Mint: %w", err)
	}
	alg, _ := s.PublicJWK()
	target := o.TargetBytes
	if target <= 0 {
		target = AccessTokenTargetBytes
	}
	tok, err := signClaims(s, alg, kid, c)
	if err != nil {
		return "", Claims{}, err
	}
	if len(tok) > target && len(c.AuthorizationDetails) > 0 {
		digest, derr := GrantSetDigest(c.AuthorizationDetails)
		if derr != nil {
			return "", Claims{}, derr
		}
		c.AuthorizationDetails = []GrantDetail{{Type: GrantDetailTypeReference, Identifier: digest, Locations: []string{aud}}}
		if tok, err = signClaims(s, alg, kid, c); err != nil {
			return "", Claims{}, err
		}
	}
	if len(tok) > target {
		return "", Claims{}, fmt.Errorf("agentid.Mint: %w (%d > %d bytes)", ErrTokenTooLarge, len(tok), target)
	}
	return tok, c, nil
}

func signClaims(s Signer, alg, kid string, c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("agentid.Mint: marshal: %w", err)
	}
	tok, err := jose.Sign(s, jose.Header{Typ: TypAccessToken, Alg: alg, Kid: kid}, payload)
	if err != nil {
		return "", fmt.Errorf("agentid.Mint: %w", err)
	}
	return tok, nil
}

// buildClaims maps the principal onto the claim set.
func buildClaims(p Principal, aud string, ttl time.Duration, grants []GrantDetail, o MintOptions) (Claims, error) {
	if o.Issuer == "" {
		return Claims{}, errors.New("agentid.Mint: issuer is required")
	}
	if aud == "" {
		return Claims{}, errors.New("agentid.Mint: audience is required")
	}
	if p.Agent.ClientID == "" {
		return Claims{}, errors.New("agentid.Mint: principal agent client_id is required")
	}
	if p.Org == "" {
		return Claims{}, errors.New("agentid.Mint: principal org is required")
	}
	if !p.CredAssurance.Valid() || !p.ClientAttestation.Valid() {
		return Claims{}, errors.New("agentid.Mint: principal assurance enums are required")
	}
	if len(p.Groups) > MaxGroups {
		return Claims{}, fmt.Errorf("agentid.Mint: %d groups exceeds the bound %d", len(p.Groups), MaxGroups)
	}
	if len(p.TeamIDs) > MaxTeamIDs {
		return Claims{}, fmt.Errorf("agentid.Mint: %d teams exceeds the bound %d", len(p.TeamIDs), MaxTeamIDs)
	}
	for _, t := range p.TeamIDs {
		if t == "" || len(t) > MaxTeamIDBytes {
			return Claims{}, fmt.Errorf("agentid.Mint: team id must be 1..%d bytes", MaxTeamIDBytes)
		}
	}
	if p.TeamsOverflow && p.TeamIDs != nil {
		// An overflowed roster is signed WITHOUT sbo_team_ids (P11 fold PF2):
		// a token carrying both would read as a trusted roster.
		return Claims{}, errors.New("agentid.Mint: an overflowed team roster carries no sbo_team_ids")
	}
	if p.ProjectHash != "" && (!ValidProjectHash(p.ProjectHash) || p.Node.ID == "") {
		// sbo_project_hash is relay-attested only: a malformed value, or one on
		// a principal with no node actor, is never signed (P11(e)).
		return Claims{}, errors.New("agentid.Mint: sbo_project_hash needs a well-formed hash on a relay (node) principal")
	}
	if o.Cnf != nil && (o.Cnf.JKT == "") == (o.Cnf.X5TS256 == "") {
		return Claims{}, errors.New("agentid.Mint: cnf must carry exactly one of jkt or x5t#S256")
	}
	sub := p.User.ID
	if sub == "" {
		sub = p.Agent.ID // M2M: sub = the agent id (F5)
	}
	if sub == "" {
		return Claims{}, errors.New("agentid.Mint: principal has neither a user nor an agent id")
	}
	maxTTL := o.MaxTTL
	if maxTTL <= 0 || maxTTL > MaxTokenTTL {
		maxTTL = MaxTokenTTL
	}
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	jti, err := newJTI(o.Rand)
	if err != nil {
		return Claims{}, err
	}
	act := &ActClaim{
		Sub:                  p.Agent.ClientID,
		SboKind:              p.Agent.Kind,
		SboProduct:           p.Agent.Product,
		SboCredAssurance:     p.CredAssurance,
		SboClientAttestation: p.ClientAttestation,
	}
	if p.Node.ID != "" {
		act.Act = &ActClaim{Sub: "node:" + p.Node.ID}
	}
	sender := SenderBearer
	if o.Cnf != nil {
		if o.Cnf.JKT != "" {
			sender = SenderDPoP
		} else {
			sender = SenderMTLS
		}
	}
	iat := now.Unix()
	return Claims{
		Iss: o.Issuer, Sub: sub, Aud: aud, ClientID: p.Agent.ClientID, Azp: p.Agent.ClientID,
		Act: act, Scope: o.Scope, AuthorizationDetails: grants, Cnf: o.Cnf,
		SboOrg: p.Org, SboWS: p.WS, SboEnv: p.Env, SboSession: o.Session, SboRun: o.Run,
		SboAgentInstance: o.AgentInstance, SboGroups: p.Groups, SboPosture: p.Posture,
		SboMemberGen: o.Gens.Member, SboCredGen: o.Gens.Cred, SboCred: o.CredentialID, SboPolicyGen: o.Gens.Policy,
		SboIssuerEpoch: o.Gens.IssuerEpoch, SboSender: sender,
		Jti: jti, Iat: iat, Nbf: iat, Exp: now.Add(ttl).Unix(),
		Amr: p.AMR, Acr: p.Acr, AuthTime: p.AuthTime,
		SboTeamIDs: copyTeams(p.TeamIDs), SboTeamOverflow: p.TeamsOverflow, SboProjectHash: p.ProjectHash,
	}, nil
}

// newJTI draws a 128-bit random token id.
func newJTI(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	buf := make([]byte, 16)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("agentid: jti entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GrantSetDigest returns the "grantset:sha256:<hex>" reference id of a grant
// set - the identifier the PDP resolves against the immutable server-side
// policy snapshot (§4.7).
func GrantSetDigest(grants []GrantDetail) (string, error) {
	raw, err := json.Marshal(grants)
	if err != nil {
		return "", fmt.Errorf("agentid.GrantSetDigest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "grantset:sha256:" + hex.EncodeToString(sum[:]), nil
}

// CheckHeaderBudget enforces the 8 KiB combined Authorization + DPoP header
// ceiling per ingress (§4.7).
func CheckHeaderBudget(authorization, dpopProof string) error {
	if n := len(authorization) + len(dpopProof); n > MaxAuthHeadersBytes {
		return fmt.Errorf("agentid: Authorization + DPoP headers are %d bytes, over the %d-byte budget", n, MaxAuthHeadersBytes)
	}
	return nil
}
