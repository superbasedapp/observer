package orgcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The ACCESS-GRANT rail (docs/plans/request-grants-design-2026-10-03.md §3.1,
// operator decisions D-080..D-095): the org-signed, time-bound, subject-scoped
// exceptions an admin approved for ONE developer, delivered to that developer's
// node over the enrolment bearer (GET /api/agent/grants).
//
// The word "grant" is already taken in this package by the ENROLMENT grant
// (grant.go, sbo-enrolment-grant-v1), so everything on this rail says
// "access grant" (Go: AccessGrant*, wire path /api/agent/grants, rail key
// "grants").
//
// WHY A RAIL OF ITS OWN and not a field on the budget rail: a guard exemption
// is not a cap, and the budget rail's ETag, freshness and fail-closed rules are
// tuned for numbers the node composes. Budget INCREASES do not ride this rail:
// the server folds them into the per-caller budget body (BudgetPolicyCap's
// Grant* tail), so the node keeps composing one number.
//
// WHAT IT CARRIES: the grants that cover THIS caller (their member-wide grants
// plus the grants bound to the machine the request named), each a rule id,
// optional narrowing hashes and a window. No justification text, no request
// context, no other member's anything. It WIDENS enforcement, so it is the
// rail with the strictest acceptance rules (docs/security.md GRANT-1):
// per-caller subject-bound Ed25519 signature under its own domain tag, the
// node's TOFU-pinned org key, a strictly increasing version, IssuedAt
// freshness, and only a SIGNED body may change the node's cache. A 404 never
// clears it; a signed body with an empty Grants list is the only thing that
// empties it.

// AccessGrantsPath is the agent route serving the caller's signed grant
// document.
const AccessGrantsPath = "/api/agent/grants"

// HeaderGrantsVerified is the request header a node sets on GET
// AccessGrantsPath: the version of the grant document it currently holds
// VERIFIED (review M4-01), so the org can say which machine confirmed a grant
// rather than calling an issued grant "in force". A node's own report, a
// display signal only. Compat: a released server ignores an unknown header,
// and a released node never sends it (the register then says so).
const HeaderGrantsVerified = "X-Observer-Grants-Verified"

// Access-grant effects. Exempt lifts an enforced ASK/DENY to FLAG (recorded);
// Soften turns an enforced DENY into ASK, so the developer still confirms each
// call through the seam's own ask path.
const (
	AccessGrantEffectExempt = "exempt"
	AccessGrantEffectSoften = "soften"
)

// Access-grant subject kinds. A member grant covers every machine of the user;
// a machine grant only the named machine identity.
const (
	AccessGrantSubjectMember  = "member"
	AccessGrantSubjectMachine = "machine"
)

// AccessGrantWire is one grant as the node receives it. Every instant is unix
// NANOSECONDS UTC (never RFC3339 text for a compared instant, the server
// migration 110 F8 precedent). ExpiresAtNs 0 is PERPETUAL and MaxUses 0 is
// UNLIMITED: both are explicit sentinels a reader must test with the helper
// methods, never by truthiness of the raw field.
//
// APPEND-ONLY with `omitempty` on every new field: the canonicalisation rule
// of BudgetPolicySigningMessage applies here too (the body is the signed
// JSON string itself, so the rule matters for the SERVER's encoder, which must
// keep emitting the bytes an older node re-hashes).
type AccessGrantWire struct {
	ID              int64  `json:"id"`
	Type            string `json:"type"`
	Effect          string `json:"effect,omitempty"`
	SubjectKind     string `json:"subject_kind"`
	MachineIdentity string `json:"machine_identity,omitempty"`
	RuleID          string `json:"rule_id,omitempty"`
	Lane            string `json:"lane,omitempty"`
	CommandClass    string `json:"command_class,omitempty"`
	OperandHash     string `json:"operand_hash,omitempty"`
	ProjectRootHash string `json:"project_root_hash,omitempty"`
	// Target is the tool / model / feature id for the non-guard types.
	Target      string `json:"target,omitempty"`
	StartsAtNs  int64  `json:"starts_at_ns"`
	ExpiresAtNs int64  `json:"expires_at_ns,omitempty"`
	MaxUses     int64  `json:"max_uses,omitempty"`
	RequestID   int64  `json:"request_id,omitempty"`
	// LockOverride is true when the grant was issued under the locked-rule
	// approval rule (design §2.3, D-082: a super-admin approval, or a policy
	// writer the org's own locked_rule_approver setting admits for a rule the
	// org reads as locked). A node honours a guard exemption on a rule its org
	// bundle LOCKS only when this is set; a grant without it is inert there
	// (request-grants G3). Signed with the rest of the body; an older server
	// never sets it, which is the stricter reading.
	LockOverride bool `json:"lock_override,omitempty"`
}

// Perpetual reports whether the grant has no expiry (D-080: super-admin only).
func (g AccessGrantWire) Perpetual() bool { return g.ExpiresAtNs == 0 }

// AccessGrantBody is the signed body. It lists only grants that cover the
// caller, are not revoked or exhausted (server-side view) and whose expiry is
// in the future. Scheduled grants are included with their future start, so
// they activate offline.
type AccessGrantBody struct {
	// Grants is ordered by id. An EMPTY list in a signed document is the org
	// saying "you hold no grants": the only thing that may empty the cache.
	Grants []AccessGrantWire `json:"grants"`
	// ServerNowNs is the server clock when the body was built. The node pairs
	// it with its own receipt time so a node clock set back can never extend a
	// grant (GRANT-3: remaining TTL at receipt).
	ServerNowNs int64 `json:"server_now_ns"`
	// MaxOfflineS bounds how long the node honours a grant it cannot
	// re-verify (D-087, default 24h; 0 = online only).
	MaxOfflineS int64 `json:"max_offline_s"`
	// IssuedAt dates the document (RFC3339), inside the signature, so a
	// captured document is not a standing credential (the budget rail's M3
	// finding; AccessGrantFresh).
	IssuedAt string `json:"issued_at"`
}

// AccessGrantDoc is the wire document of GET /api/agent/grants.
type AccessGrantDoc struct {
	// OrgID names the org the document was signed for (bound into the
	// signature; the node also refuses a foreign OrgID outright).
	OrgID string `json:"org_id"`
	// Subject is AccessGrantSubject(userID, machine): the caller the body was
	// resolved for, bound into the signature so alice's document never
	// verifies on bob's node.
	Subject string `json:"subject"`
	// Version is org_access_grant_epoch.version, monotonic per org.
	Version int64 `json:"version"`
	// Body is the JSON-encoded AccessGrantBody; the signature covers these
	// exact bytes.
	Body string `json:"body"`
	// BodyHash is hex(SHA-256(Body)), integrity and dedup only.
	BodyHash string `json:"body_hash"`
	// Signature is base64(Ed25519 over AccessGrantSigningMessage).
	Signature string `json:"signature"`
	// PublicKey is base64(Ed25519 public key): the org distribution key the
	// node already pins across rails.
	PublicKey string `json:"public_key"`
}

// AccessGrantSubject renders the signed subject for a caller. The machine half
// is empty for an unmanaged enrolment that sends no machine header; the
// separator is always present so "alice" + "" and "alice|" can never be
// confused with a user id that itself contains the separator.
func AccessGrantSubject(userID, machine string) string {
	return strings.TrimSpace(userID) + "|" + strings.TrimSpace(machine)
}

// accessGrantSigningDomain separates this rail's signatures from every other
// Ed25519 use of the same org key.
const accessGrantSigningDomain = "sbo-access-grant-v1"

// AccessGrantSigningMessage returns SHA-256 over
//
//	domain || 0x00 || orgID || 0x00 || subject || 0x00 || decimal(version) || 0x00 || body
//
// Org, subject and version are all bound: cross-org replay, cross-caller
// replay and an inflated-version replay (which would freeze a node against
// every later revocation via its monotonic short-circuit) all fail.
func AccessGrantSigningMessage(orgID, subject string, version int64, body string) []byte {
	h := sha256.New()
	h.Write([]byte(accessGrantSigningDomain))
	h.Write([]byte{0})
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(subject))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(version, 10)))
	h.Write([]byte{0})
	h.Write([]byte(body))
	return h.Sum(nil)
}

// EncodeAccessGrantBody returns the canonical body bytes. A nil Grants slice
// is encoded as [] so "no grants" is always the explicit empty list.
func EncodeAccessGrantBody(b AccessGrantBody) (string, error) {
	if b.Grants == nil {
		b.Grants = []AccessGrantWire{}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("orgcontract.EncodeAccessGrantBody: %w", err)
	}
	return string(raw), nil
}

// DecodeAccessGrantBody parses a VERIFIED body. A grant with an unknown
// effect, subject kind, or a missing id is dropped (an unknown shape is never
// widened into an exemption); the rest of the document still applies.
func DecodeAccessGrantBody(body string) (AccessGrantBody, error) {
	var b AccessGrantBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return AccessGrantBody{}, fmt.Errorf("orgcontract.DecodeAccessGrantBody: %w", err)
	}
	kept := make([]AccessGrantWire, 0, len(b.Grants))
	for _, g := range b.Grants {
		if g.ID <= 0 {
			continue
		}
		if g.SubjectKind != AccessGrantSubjectMember && g.SubjectKind != AccessGrantSubjectMachine {
			continue
		}
		if g.Effect != "" && g.Effect != AccessGrantEffectExempt && g.Effect != AccessGrantEffectSoften {
			continue
		}
		kept = append(kept, g)
	}
	b.Grants = kept
	return b, nil
}

// SignAccessGrants builds and signs the document for one caller. The org
// server's agent handler is the only production caller.
func SignAccessGrants(priv ed25519.PrivateKey, orgID, subject string, version int64, body AccessGrantBody) (AccessGrantDoc, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return AccessGrantDoc{}, errors.New("orgcontract.SignAccessGrants: bad private key")
	}
	if version < 0 {
		return AccessGrantDoc{}, errors.New("orgcontract.SignAccessGrants: negative version")
	}
	encoded, err := EncodeAccessGrantBody(body)
	if err != nil {
		return AccessGrantDoc{}, err
	}
	sum := sha256.Sum256([]byte(encoded))
	pub, _ := priv.Public().(ed25519.PublicKey)
	return AccessGrantDoc{
		OrgID:     orgID,
		Subject:   subject,
		Version:   version,
		Body:      encoded,
		BodyHash:  hex.EncodeToString(sum[:]),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, AccessGrantSigningMessage(orgID, subject, version, encoded))),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// VerifyAccessGrants checks doc against the node's own enrolment org, its own
// subject and the pinned org key. Every refusal is an error; the caller keeps
// its last verified cache on any error (a refused document never clears).
func VerifyAccessGrants(doc AccessGrantDoc, expectOrgID, expectSubject, pinnedPubB64 string) error {
	if expectOrgID == "" || doc.OrgID != expectOrgID {
		return fmt.Errorf("orgcontract.VerifyAccessGrants: document is for org %q, this node is enrolled with %q", doc.OrgID, expectOrgID)
	}
	if expectSubject == "" || doc.Subject != expectSubject {
		return fmt.Errorf("orgcontract.VerifyAccessGrants: document is for subject %q, this node is %q", doc.Subject, expectSubject)
	}
	if doc.Version < 0 {
		return errors.New("orgcontract.VerifyAccessGrants: negative version")
	}
	pub, err := base64.StdEncoding.DecodeString(pinnedPubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("orgcontract.VerifyAccessGrants: bad public key")
	}
	if doc.Signature == "" {
		return errors.New("orgcontract.VerifyAccessGrants: unsigned document")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return errors.New("orgcontract.VerifyAccessGrants: bad signature encoding")
	}
	sum := sha256.Sum256([]byte(doc.Body))
	if hex.EncodeToString(sum[:]) != doc.BodyHash {
		return errors.New("orgcontract.VerifyAccessGrants: body hash mismatch")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), AccessGrantSigningMessage(doc.OrgID, doc.Subject, doc.Version, doc.Body), sig) {
		return errors.New("orgcontract.VerifyAccessGrants: signature invalid (it must cover this rail's domain tag, this org, this subject AND this version)")
	}
	return nil
}

// AccessGrantMaxAge is the IssuedAt freshness window: a captured document
// older than this is refused even at a cold cache.
const AccessGrantMaxAge = time.Hour

// AccessGrantFresh applies the IssuedAt window. Unlike the budget rail an
// EMPTY IssuedAt is NOT fresh: this rail is new, so no server that predates
// the field can exist, and an undated widening document is exactly the replay
// the field exists to stop.
func AccessGrantFresh(issuedAt string, now time.Time) (bool, string) {
	raw := strings.TrimSpace(issuedAt)
	if raw == "" {
		return false, "issued_at is empty"
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false, "issued_at is not RFC3339: " + raw
	}
	if age := now.Sub(t); age > AccessGrantMaxAge {
		return false, fmt.Sprintf("issued_at %s is %s old, past the %s freshness window (replay)", raw, age.Truncate(time.Second), AccessGrantMaxAge)
	}
	if ahead := t.Sub(now); ahead > BudgetPolicyMaxSkew {
		return false, fmt.Sprintf("issued_at %s is %s in the future, past the %s skew allowance", raw, ahead.Truncate(time.Second), BudgetPolicyMaxSkew)
	}
	return true, ""
}

// ---------------------------------------------------------------------------
// Structured requests (POST /api/agent/requests additive fields, §1.1/§4.3).
// ---------------------------------------------------------------------------

// AccessRequestPayload is the structured ask. Which fields are meaningful is
// decided by the request type's row in internal/accessgrant.RequestTypes; the
// server validates through accessgrant.Validate.
type AccessRequestPayload struct {
	// Guard exemption.
	RuleID          string `json:"rule_id,omitempty"`
	Lane            string `json:"lane,omitempty"`
	CommandClass    string `json:"command_class,omitempty"`
	OperandHash     string `json:"operand_hash,omitempty"`
	ProjectRootHash string `json:"project_root_hash,omitempty"`
	// Effect is the effect the developer asked for (exempt or soften).
	Effect string `json:"effect,omitempty"`
	// Breadth is "rule" (rule-wide), "class" (command class) or "exact"
	// (operand hash) (D-092).
	Breadth string `json:"breadth,omitempty"`
	// Budget increase: the authored budget row and the "+amount" (D-085).
	BudgetID    string  `json:"budget_id,omitempty"`
	DeltaTokens int64   `json:"delta_tokens,omitempty"`
	DeltaUSD    float64 `json:"delta_usd,omitempty"`
	// Target is the tool / model / feature id.
	Target string `json:"target,omitempty"`
	// SupersedesGrantID links an extension request to the grant it extends.
	SupersedesGrantID int64 `json:"supersedes_grant_id,omitempty"`
}

// AccessRequestContext is the auto-attached context block (§1.2). The
// metadata half always ships; the content half (TargetExcerpt, ProjectRoot,
// GitBranch) only under shipsRawContent() or a per-request opt-in, decided in
// ONE place (accessgrant.ShapeContext) before the preview is shown.
type AccessRequestContext struct {
	RuleID          string  `json:"rule_id,omitempty"`
	Category        string  `json:"category,omitempty"`
	Severity        string  `json:"severity,omitempty"`
	Decision        string  `json:"decision,omitempty"`
	Lane            string  `json:"lane,omitempty"`
	Enforced        bool    `json:"enforced,omitempty"`
	Tool            string  `json:"tool,omitempty"`
	Surface         string  `json:"surface,omitempty"`
	TargetHash      string  `json:"target_hash,omitempty"`
	ProjectRootHash string  `json:"project_root_hash,omitempty"`
	SessionID       string  `json:"session_id,omitempty"`
	EventID         int64   `json:"event_id,omitempty"`
	Hits7d          int64   `json:"hits_7d,omitempty"`
	BudgetID        string  `json:"budget_id,omitempty"`
	BudgetPeriod    string  `json:"budget_period,omitempty"`
	BudgetScope     string  `json:"budget_scope,omitempty"`
	CapTokens       int64   `json:"cap_tokens,omitempty"`
	CapUSD          float64 `json:"cap_usd,omitempty"`
	SpentTokens     int64   `json:"spent_tokens,omitempty"`
	SpentUSD        float64 `json:"spent_usd,omitempty"`
	NodeVersion     string  `json:"node_version,omitempty"`
	Tenancy         string  `json:"tenancy,omitempty"`
	// Content-bearing: only under shipsRawContent() or the explicit opt-in.
	TargetExcerpt string `json:"target_excerpt,omitempty"`
	ProjectRoot   string `json:"project_root,omitempty"`
	GitBranch     string `json:"git_branch,omitempty"`
}

// AccessRequestCreate is the POST /api/agent/requests body. The legacy W6
// fields (Kind, Target, Message) keep their meaning, so a pre-design node's
// body decodes unchanged; RequestType and the rest are additive.
type AccessRequestCreate struct {
	Kind               string                `json:"kind,omitempty"`
	Target             string                `json:"target,omitempty"`
	Message            string                `json:"message"`
	RequestType        string                `json:"request_type,omitempty"`
	Payload            *AccessRequestPayload `json:"payload,omitempty"`
	Context            *AccessRequestContext `json:"context,omitempty"`
	RequestedDurationS int64                 `json:"requested_duration_s,omitempty"`
	RequestedUses      int64                 `json:"requested_uses,omitempty"`
	// SubjectKind is the scope the developer asked for (D-092: "this
	// machine" is AccessGrantSubjectMachine; member-wide is approver-only).
	SubjectKind     string `json:"subject_kind,omitempty"`
	MachineIdentity string `json:"machine_identity,omitempty"`
}

// AccessRequestGrantSummary is the grant a request produced, as GET
// /api/agent/requests lists it beside the request row.
//
// The request row's own status records the DECISION ("granted") and never
// moves on afterwards: org_requests has one writer (grantstore) and a revoke
// touches only the grant. Status here is the grant's live state (active,
// scheduled, exhausted, expired, revoked), and a node renders the request's
// outcome from it (demo finding #27, 2026-11-10).
type AccessRequestGrantSummary struct {
	ID          int64  `json:"id"`
	Type        string `json:"type"`
	Effect      string `json:"effect,omitempty"`
	Status      string `json:"status"`
	StartsAtNs  int64  `json:"starts_at_ns"`
	ExpiresAtNs int64  `json:"expires_at_ns,omitempty"`
	MaxUses     int64  `json:"max_uses,omitempty"`
	SubjectKind string `json:"subject_kind"`
	// RevokedAtNs and RevokeReason say when the organization revoked the
	// grant and the reason the admin gave (empty when none). Both optional:
	// a server that predates them sends neither, and an older node ignores
	// them.
	RevokedAtNs  int64  `json:"revoked_at_ns,omitempty"`
	RevokeReason string `json:"revoke_reason,omitempty"`
}
