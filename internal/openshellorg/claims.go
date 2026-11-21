package openshellorg

import (
	"strings"
	"time"
)

// Profile names one of the issuer's three token profiles (section 5.2).
type Profile string

// The three token profiles.
const (
	// ProfileRun is the node's run token: audience the front, minted by the
	// mint route, held in the node daemon's memory only.
	ProfileRun Profile = "run"
	// ProfileMemberGateway is the front's member gateway token: audience the
	// gateway, minted by the api role in answer to a decide call only.
	ProfileMemberGateway Profile = "member_gateway"
	// ProfileSyncAdmin is the worker's own admin token for the sync, never
	// returned by any route or internal call.
	ProfileSyncAdmin Profile = "sync_admin"
)

// Role values carried in the gateway tokens' roles claim (section 7.1: the
// gateway's user_role and admin_role).
const (
	RoleUser  = "openshell-user"
	RoleAdmin = "openshell-admin"
)

// Token lifetimes and limits (section 5.2).
const (
	// RunTokenTTLDefault is token_ttl_seconds' default.
	RunTokenTTLDefault = 600 * time.Second
	// RunTokenTTLMin and RunTokenTTLMax bound token_ttl_seconds.
	RunTokenTTLMin = 60 * time.Second
	RunTokenTTLMax = 3600 * time.Second
	// MemberGatewayTTL is the member gateway token's fixed lifetime, set by
	// the api role (never by the front).
	MemberGatewayTTL = 60 * time.Second
	// MemberTokenReuseWindow is the per run, per front key or replica window
	// inside which decide returns no fresh member token (G1-R15).
	MemberTokenReuseWindow = 30 * time.Second
	// SyncAdminTTL is the sync admin token's lifetime.
	SyncAdminTTL = 300 * time.Second
	// ClockSkew is the leeway a verifier allows on nbf and exp.
	ClockSkew = 30 * time.Second
)

// SubjectAdmin is the sync admin token's subject.
const SubjectAdmin = "svc:observer-org"

// ScopeMemberGateway is the member gateway token's scope (sandbox only).
const ScopeMemberGateway = "sandbox:read sandbox:write"

// ScopeSyncAdmin is the sync admin token's scope.
const ScopeSyncAdmin = "openshell:all"

// Claims is the JWT claim set every profile uses. Fields a profile does not
// carry stay empty and are omitted on the wire.
type Claims struct {
	Iss   string   `json:"iss"`
	Aud   string   `json:"aud"`
	Sub   string   `json:"sub"`
	Roles []string `json:"roles,omitempty"`
	Scope string   `json:"scope"`
	// SboRun is the node's run id (the new id after a resume).
	SboRun string `json:"sbo_run,omitempty"`
	// SboBox is the box's ledger key: the original run id, equal to SboRun
	// until a resume.
	SboBox string `json:"sbo_box,omitempty"`
	// SboNode is the enrolment node id hash.
	SboNode string `json:"sbo_node,omitempty"`
	// SboGrant is the grant id the run token was minted on.
	SboGrant string `json:"sbo_grant,omitempty"`
	// SboSpec is the recorded spec digest, for a create token.
	SboSpec string   `json:"sbo_spec,omitempty"`
	Amr     []string `json:"amr,omitempty"`
	Jti     string   `json:"jti"`
	Iat     int64    `json:"iat"`
	Nbf     int64    `json:"nbf"`
	Exp     int64    `json:"exp"`
}

// FrontAudience is the run token's audience.
func FrontAudience(gatewayID string) string { return "openshell-front:" + gatewayID }

// GatewayAudience is the gateway tokens' audience (the gateway's configured
// OIDC audience).
func GatewayAudience(gatewayID string) string { return "openshell:" + gatewayID }

// MemberSubject is the subject of a member's run and gateway tokens.
func MemberSubject(memberID string) string { return "member:" + memberID }

// RunScope is the run token's scope for a purpose.
func RunScope(p Purpose) string { return "run:" + string(p) }

// PurposeFromScope reads a run token's purpose back from its scope.
func PurposeFromScope(scope string) (Purpose, bool) {
	rest, ok := strings.CutPrefix(scope, "run:")
	if !ok {
		return "", false
	}
	p := Purpose(rest)
	return p, p.Valid()
}

// ClampRunTTL bounds a configured run token lifetime to [60 s, 3600 s]; zero
// means the default.
func ClampRunTTL(d time.Duration) time.Duration {
	switch {
	case d == 0:
		return RunTokenTTLDefault
	case d < RunTokenTTLMin:
		return RunTokenTTLMin
	case d > RunTokenTTLMax:
		return RunTokenTTLMax
	}
	return d
}

// RunTokenParams are the inputs of a run token.
type RunTokenParams struct {
	Issuer, GatewayID, MemberID string
	Purpose                     Purpose
	RunID, BoxRunID             string
	NodeHash, GrantID, SpecHash string
	Amr                         []string
	Jti                         string
	Now                         time.Time
	TTL                         time.Duration
}

// RunTokenClaims builds a run token's claims. BoxRunID defaults to RunID.
func RunTokenClaims(p RunTokenParams) Claims {
	box := p.BoxRunID
	if box == "" {
		box = p.RunID
	}
	ttl := ClampRunTTL(p.TTL)
	c := Claims{
		Iss: p.Issuer, Aud: FrontAudience(p.GatewayID), Sub: MemberSubject(p.MemberID),
		Scope: RunScope(p.Purpose), SboRun: p.RunID, SboBox: box, SboNode: p.NodeHash,
		SboGrant: p.GrantID, Amr: append([]string(nil), p.Amr...), Jti: p.Jti,
		Iat: p.Now.Unix(), Nbf: p.Now.Unix(), Exp: p.Now.Add(ttl).Unix(),
	}
	if p.Purpose == PurposeCreate {
		c.SboSpec = p.SpecHash
	}
	return c
}

// MemberGatewayClaims builds the member gateway token the api role hands the
// front: the run's member, the user role only, the sandbox scope, 60 s.
func MemberGatewayClaims(issuer, gatewayID, memberID, jti string, now time.Time) Claims {
	return Claims{
		Iss: issuer, Aud: GatewayAudience(gatewayID), Sub: MemberSubject(memberID),
		Roles: []string{RoleUser}, Scope: ScopeMemberGateway, Jti: jti,
		Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(MemberGatewayTTL).Unix(),
	}
}

// SyncAdminClaims builds the worker's sync admin token (300 s).
func SyncAdminClaims(issuer, gatewayID, jti string, now time.Time) Claims {
	return Claims{
		Iss: issuer, Aud: GatewayAudience(gatewayID), Sub: SubjectAdmin,
		Roles: []string{RoleAdmin}, Scope: ScopeSyncAdmin, Jti: jti,
		Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(SyncAdminTTL).Unix(),
	}
}

// CheckRunClaims validates a signature-verified run token's claims against
// the expected issuer and gateway and the current time. It answers the
// purpose and ReasonNone, or ReasonRunTokenInvalid.
func CheckRunClaims(c Claims, issuer, gatewayID string, now time.Time) (Purpose, Reason) {
	if c.Iss != issuer || c.Aud != FrontAudience(gatewayID) {
		return "", ReasonRunTokenInvalid
	}
	if !strings.HasPrefix(c.Sub, "member:") || c.Sub == "member:" || len(c.Roles) != 0 {
		return "", ReasonRunTokenInvalid
	}
	p, ok := PurposeFromScope(c.Scope)
	if !ok || c.SboRun == "" || c.SboBox == "" || c.Jti == "" {
		return "", ReasonRunTokenInvalid
	}
	t := now.Unix()
	skew := int64(ClockSkew / time.Second)
	if c.Exp <= c.Nbf || t >= c.Exp+skew || t+skew < c.Nbf || c.Exp-c.Iat > int64(RunTokenTTLMax/time.Second) {
		return "", ReasonRunTokenInvalid
	}
	return p, ReasonNone
}

// StreamWithinRun is the stream re-check's lifetime bound (lane G3 fixes
// round 1, G3-A5): a stream opened at start, with a run token valid then,
// stays open until start plus the run's max_run_minutes. The token's own
// exp bounds only what it opens; every other check runs on every re-check.
func StreamWithinRun(start, now time.Time, maxRunMinutes int) bool {
	if start.IsZero() || maxRunMinutes <= 0 || start.After(now.Add(ClockSkew)) {
		return false
	}
	return now.Before(start.Add(time.Duration(maxRunMinutes) * time.Minute))
}

// MemberIDFromSubject reads the member id out of a "member:<id>" subject.
func MemberIDFromSubject(sub string) (string, bool) {
	id, ok := strings.CutPrefix(sub, "member:")
	return id, ok && id != ""
}
