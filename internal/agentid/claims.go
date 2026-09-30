package agentid

import (
	"encoding/json"
	"errors"
	"fmt"
)

// TypAccessToken is the RFC 9068 JOSE header typ of an access token.
const TypAccessToken = "at+jwt"

// TypActorAssertion is the JOSE header typ of the node actor assertion (§4.3).
const TypActorAssertion = "sbo-actor+jwt"

// Sender values for the INFORMATIONAL sbo_sender claim (R9.1).
const (
	SenderBearer = "bearer"
	SenderDPoP   = "dpop"
	SenderMTLS   = "mtls"
)

// GrantDetailTypeReference is the RFC 9396 type of the grant-set reference
// that replaces an over-budget authorization_details array (§4.7).
const GrantDetailTypeReference = "sbo_mcp_grant"

// UserRef names the human principal: a member id, an OBO end-user
// (`enduser:<iss>#<sub>`, or `enduser:<oid>` under subject_stability oid -
// EndUserSubject, ruling R-S3-6), or "" for machine-to-machine.
type UserRef struct {
	ID string
}

// AgentRef names the agent_definition acting: its id, its OAuth client id
// (e.g. "agent:claude-code"), kind and product.
type AgentRef struct {
	ID       string
	ClientID string
	Kind     string
	Product  string
}

// NodeRef names the enrolled node (optional).
type NodeRef struct {
	ID        string
	MachineFP string
}

// Principal is the resolved caller the STS mints for (doc3 §2.4).
type Principal struct {
	User              UserRef
	Agent             AgentRef
	Node              NodeRef
	Org, WS, Env      string
	Groups            []string
	Posture           string // teams | enterprise
	CredAssurance     CredentialAssurance
	ClientAttestation ClientAttestation
	// AMR/Acr/AuthTime MUST come only from a fresh user assertion bound into
	// issuance - never inferred from the enrolment bearer (R6).
	AMR      []string
	Acr      string
	AuthTime int64
	// TeamIDs is the member's team roster read SERVER-SIDE at mint (P11(e),
	// R10.9; never client-supplied). nil = not established (the claim is
	// omitted and a team-scoped grant fails closed); a non-nil empty slice =
	// established, no teams (the claim is the empty array).
	TeamIDs []string
	// TeamsOverflow marks a member whose roster exceeds MaxTeamIDs (P11 fold
	// PF2): the mint succeeds WITHOUT sbo_team_ids and stamps
	// sbo_team_overflow, so every team subject is untrusted for that token
	// (a team allow never matches, a team deny / ask always does). It
	// requires TeamIDs == nil.
	TeamsOverflow bool
	// ProjectHash is the RELAY-ATTESTED project hash (sbo_project_hash),
	// set only by the F1 node exchange from the verified actor assertion.
	ProjectHash string
}

// ActClaim is the RFC 8693 delegation (`act`) claim. It carries the two
// assurance enums (R2) and nests the node actor.
type ActClaim struct {
	Sub                  string              `json:"sub"`
	SboKind              string              `json:"sbo_kind,omitempty"`
	SboProduct           string              `json:"sbo_product,omitempty"`
	SboCredAssurance     CredentialAssurance `json:"sbo_cred_assurance,omitempty"`
	SboClientAttestation ClientAttestation   `json:"sbo_client_attestation,omitempty"`
	Act                  *ActClaim           `json:"act,omitempty"`
}

// actWire lets absent enums decode as the (invalid) zero value rather than
// failing, so VerifyProfile can report them precisely.
type actWire struct {
	Sub                  string    `json:"sub"`
	SboKind              string    `json:"sbo_kind,omitempty"`
	SboProduct           string    `json:"sbo_product,omitempty"`
	SboCredAssurance     string    `json:"sbo_cred_assurance,omitempty"`
	SboClientAttestation string    `json:"sbo_client_attestation,omitempty"`
	Act                  *ActClaim `json:"act,omitempty"`
}

// MarshalJSON omits invalid (zero) enums instead of failing.
func (a ActClaim) MarshalJSON() ([]byte, error) {
	w := actWire{Sub: a.Sub, SboKind: a.SboKind, SboProduct: a.SboProduct, Act: a.Act}
	if a.SboCredAssurance.Valid() {
		w.SboCredAssurance = a.SboCredAssurance.String()
	}
	if a.SboClientAttestation.Valid() {
		w.SboClientAttestation = a.SboClientAttestation.String()
	}
	return json.Marshal(w)
}

// UnmarshalJSON refuses unknown enum names; absent names stay zero.
func (a *ActClaim) UnmarshalJSON(b []byte) error {
	var w actWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*a = ActClaim{Sub: w.Sub, SboKind: w.SboKind, SboProduct: w.SboProduct, Act: w.Act}
	if w.SboCredAssurance != "" {
		if err := a.SboCredAssurance.UnmarshalText([]byte(w.SboCredAssurance)); err != nil {
			return err
		}
	}
	if w.SboClientAttestation != "" {
		if err := a.SboClientAttestation.UnmarshalText([]byte(w.SboClientAttestation)); err != nil {
			return err
		}
	}
	return nil
}

// Depth returns the length of the actor chain (1 for a single act).
func (a *ActClaim) Depth() int {
	n := 0
	for cur := a; cur != nil; cur = cur.Act {
		n++
	}
	return n
}

// Confirmation is the RFC 7800 `cnf` claim: DPoP jkt (RFC 9449) OR mTLS
// x5t#S256 (RFC 8705), never both.
type Confirmation struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// GrantDetail is one RFC 9396 authorization_details entry.
type GrantDetail struct {
	Type       string   `json:"type"`
	Identifier string   `json:"identifier,omitempty"`
	Locations  []string `json:"locations,omitempty"`
	Actions    []string `json:"actions,omitempty"`
}

// Claims is the RFC 9068 at+jwt payload (doc3 §2.4 / §6.3). The header
// (typ=at+jwt, alg, kid) is not part of it.
type Claims struct {
	Iss, Sub, Aud, ClientID, Azp string
	Act                          *ActClaim
	Scope                        string
	AuthorizationDetails         []GrantDetail
	Cnf                          *Confirmation
	SboOrg, SboWS, SboEnv        string
	SboSession, SboRun           string
	SboAgentInstance             string
	SboGroups                    []string
	SboPosture                   string
	SboMemberGen, SboCredGen     int64
	SboPolicyGen, SboIssuerEpoch int64
	// SboCred is the OPTIONAL credential subject the minter read
	// sbo_cred_gen under (an agent_credential id, an API key id, or the IdP
	// issuer of an exchanged assertion) - the same value it records as the
	// issuance credential id. A verifier resolves the credential-class
	// invalidation floor from it (§4.6). Absent ("") means no credential
	// subject: the credential floor is 0, never a refusal (a token minted
	// before the claim existed, or a flow without a credential).
	SboCred string
	// SboSender is INFORMATIONAL ONLY (R9.1): how the token was bound. It is
	// never an admission flag.
	SboSender     string
	Jti           string
	Iat, Nbf, Exp int64
	Amr           []string
	Acr           string
	AuthTime      int64
	// SboTeamIDs is the server-side team roster (P11(e)); nil = the claim is
	// ABSENT (roster not established - team-scoped grants fail closed), a
	// non-nil empty slice = PRESENT and empty. See abac.go.
	SboTeamIDs []string
	// SboTeamOverflow is sbo_team_overflow: the member's roster exceeded
	// MaxTeamIDs, so sbo_team_ids is absent and every team subject is
	// untrusted for this token. The claim is PRESENCE-typed: any value
	// decodes as true (the fail-closed reading, and the one agentgateway's
	// has() sees); the mint only ever emits true.
	SboTeamOverflow bool
	// SboProjectHash is the relay-attested project hash; "" = absent.
	// VerifyProfile refuses it on a token that is not relay-originated.
	SboProjectHash string
}

// claimsWire is the JSON shape. aud is raw so the decoder can accept a string
// or a single-element array (R8.26.g) and refuse anything else.
type claimsWire struct {
	Iss                  string          `json:"iss"`
	Sub                  string          `json:"sub"`
	Aud                  json.RawMessage `json:"aud"`
	ClientID             string          `json:"client_id"`
	Azp                  string          `json:"azp,omitempty"`
	Act                  *ActClaim       `json:"act,omitempty"`
	Scope                string          `json:"scope,omitempty"`
	AuthorizationDetails []GrantDetail   `json:"authorization_details,omitempty"`
	Cnf                  *Confirmation   `json:"cnf,omitempty"`
	SboOrg               string          `json:"sbo_org"`
	SboWS                string          `json:"sbo_ws,omitempty"`
	SboEnv               string          `json:"sbo_env,omitempty"`
	SboSession           string          `json:"sbo_session,omitempty"`
	SboRun               string          `json:"sbo_run,omitempty"`
	SboAgentInstance     string          `json:"sbo_agent_instance,omitempty"`
	SboGroups            []string        `json:"sbo_groups,omitempty"`
	SboPosture           string          `json:"sbo_posture,omitempty"`
	SboMemberGen         int64           `json:"sbo_member_gen"`
	SboCredGen           int64           `json:"sbo_cred_gen"`
	SboCred              string          `json:"sbo_cred,omitempty"`
	SboPolicyGen         int64           `json:"sbo_policy_gen"`
	SboIssuerEpoch       int64           `json:"sbo_issuer_epoch"`
	SboSender            string          `json:"sbo_sender,omitempty"`
	Jti                  string          `json:"jti"`
	Iat                  int64           `json:"iat"`
	Nbf                  int64           `json:"nbf,omitempty"`
	Exp                  int64           `json:"exp"`
	Amr                  []string        `json:"amr,omitempty"`
	Acr                  string          `json:"acr,omitempty"`
	AuthTime             int64           `json:"auth_time,omitempty"`
	// SboTeamIDs is a pointer so the empty roster ([]) and the absent claim
	// stay distinct on the wire.
	SboTeamIDs      *[]string `json:"sbo_team_ids,omitempty"`
	SboTeamOverflow *bool     `json:"sbo_team_overflow,omitempty"`
	SboProjectHash  string    `json:"sbo_project_hash,omitempty"`
}

// requiredClaims are the members every at+jwt must carry (RFC 9068 §2.2 plus
// the typed generation claims, §4.6). Presence is checked on the raw payload
// because a zero generation is a legal value.
var requiredClaims = []string{
	"iss", "sub", "aud", "client_id", "iat", "exp", "jti",
	"sbo_org", "sbo_member_gen", "sbo_cred_gen", "sbo_policy_gen", "sbo_issuer_epoch",
}

// MarshalJSON renders the wire payload (aud as a single string).
func (c Claims) MarshalJSON() ([]byte, error) {
	aud, err := json.Marshal(c.Aud)
	if err != nil {
		return nil, err
	}
	return json.Marshal(claimsWire{
		Iss: c.Iss, Sub: c.Sub, Aud: aud, ClientID: c.ClientID, Azp: c.Azp, Act: c.Act,
		Scope: c.Scope, AuthorizationDetails: c.AuthorizationDetails, Cnf: c.Cnf,
		SboOrg: c.SboOrg, SboWS: c.SboWS, SboEnv: c.SboEnv, SboSession: c.SboSession,
		SboRun: c.SboRun, SboAgentInstance: c.SboAgentInstance, SboGroups: c.SboGroups,
		SboPosture: c.SboPosture, SboMemberGen: c.SboMemberGen, SboCredGen: c.SboCredGen, SboCred: c.SboCred,
		SboPolicyGen: c.SboPolicyGen, SboIssuerEpoch: c.SboIssuerEpoch, SboSender: c.SboSender,
		Jti: c.Jti, Iat: c.Iat, Nbf: c.Nbf, Exp: c.Exp, Amr: c.Amr, Acr: c.Acr, AuthTime: c.AuthTime,
		SboTeamIDs: teamsWire(c.SboTeamIDs), SboTeamOverflow: overflowWire(c.SboTeamOverflow),
		SboProjectHash: c.SboProjectHash,
	})
}

// overflowWire renders sbo_team_overflow: present (true) or omitted.
func overflowWire(overflow bool) *bool {
	if !overflow {
		return nil
	}
	t := true
	return &t
}

// teamsWire maps the roster onto its wire pointer (nil = omit the claim).
func teamsWire(ts []string) *[]string {
	if ts == nil {
		return nil
	}
	cp := copyTeams(ts)
	return &cp
}

// errMultiAudience is returned for an aud that is neither a string nor a
// single-element string array.
var errMultiAudience = errors.New("aud must be a single audience")

// UnmarshalJSON accepts aud as a string or a one-element array only.
func (c *Claims) UnmarshalJSON(b []byte) error {
	var w claimsWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	aud, err := singleAudience(w.Aud)
	if err != nil {
		return err
	}
	*c = Claims{
		Iss: w.Iss, Sub: w.Sub, Aud: aud, ClientID: w.ClientID, Azp: w.Azp, Act: w.Act,
		Scope: w.Scope, AuthorizationDetails: w.AuthorizationDetails, Cnf: w.Cnf,
		SboOrg: w.SboOrg, SboWS: w.SboWS, SboEnv: w.SboEnv, SboSession: w.SboSession,
		SboRun: w.SboRun, SboAgentInstance: w.SboAgentInstance, SboGroups: w.SboGroups,
		SboPosture: w.SboPosture, SboMemberGen: w.SboMemberGen, SboCredGen: w.SboCredGen, SboCred: w.SboCred,
		SboPolicyGen: w.SboPolicyGen, SboIssuerEpoch: w.SboIssuerEpoch, SboSender: w.SboSender,
		Jti: w.Jti, Iat: w.Iat, Nbf: w.Nbf, Exp: w.Exp, Amr: w.Amr, Acr: w.Acr, AuthTime: w.AuthTime,
		SboProjectHash: w.SboProjectHash, SboTeamOverflow: w.SboTeamOverflow != nil,
	}
	if w.SboTeamIDs != nil {
		c.SboTeamIDs = copyTeams(*w.SboTeamIDs)
		if c.SboTeamIDs == nil {
			c.SboTeamIDs = []string{}
		}
	}
	return nil
}

// singleAudience decodes an aud member that is a string or a single-element
// string array (the exact-audience rule, R8.26.g).
func singleAudience(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		return "", fmt.Errorf("aud: %w", errMultiAudience)
	}
	if len(arr) != 1 {
		return "", errMultiAudience
	}
	return arr[0], nil
}
