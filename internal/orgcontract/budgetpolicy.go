package orgcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The per-caller org BUDGET policy body served by GET /api/agent/budget
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3b, wave W3a).
//
// WHY THIS LIVES HERE and not in internal/orgserver: it is a node<->server
// contract, and both ends must derive the SAME signing bytes. orgcontract is
// the package that already owns every such shape (it has zero internal
// dependencies, so a pure node package and a pure server package can both
// import it). The server-side RESOLUTION of which caps apply to a caller is a
// separate, pure package, internal/orgserver/budgetresolve; it produces a
// [BudgetPolicyBody] and never re-declares the wire shape.
//
// WHAT IT CARRIES: numbers and enums only — caps, a period, a timezone, an
// enforcement mode, a threshold ladder, and the SCOPE LABEL that produced each
// cap ("org", "team:<id>", "member:<id>"). No other member's data, no
// per-project breakdown, nobody's spend. Distributing it is a GOVERNANCE act
// of the same class as pinning guard.mode through nodegov, not a content
// disclosure: it names no content-bearing column, it travels on the agent
// POLICY rail rather than on PushEnvelope, and it is refused unless the org's
// signing key matches the node's TOFU pin (see [PublicKeyPinHash]).
//
// It is therefore ORTHOGONAL to the data-extraction posture axis (teams
// posture vs ENTERPRISE posture / store.ShareOptions.EnterpriseGranted,
// design §5.3): CLAUDE.md's node-side-opt-in rule governs whether raw CONTENT
// crosses the wire, and nothing on this rail is content.

// Budget policy period vocabulary. These are the SAME strings the org
// server's `budgets.period` column stores (internal/orgserver/rollup's
// BudgetPeriod* constants); they are re-declared here because orgcontract must
// keep its zero-internal-dependency property, and pinned against rollup by
// internal/orgserver/budgetresolve's vocab test.
const (
	BudgetPolicyPeriodRolling30d    = "rolling_30d"
	BudgetPolicyPeriodCalendarDay   = "calendar_day"
	BudgetPolicyPeriodCalendarMonth = "calendar_month"
)

// Budget policy enforcement vocabulary, ordered report < soft < hard.
const (
	BudgetPolicyEnforcementReport = "report"
	BudgetPolicyEnforcementSoft   = "soft"
	BudgetPolicyEnforcementHard   = "hard"
)

// Budget policy SUBJECT vocabulary (bundle BUD-N). A cap may narrow from "this
// caller's whole spend" to "this caller's spend on ONE tool" or "... on ONE
// model". There are exactly two kinds and there are deliberately no composite
// scopes: a cap that meant "tool X on model Y" would need a resolution order
// against the plain tool cap and the plain model cap, and every such order is a
// judgement the node would have to make about numbers the org authored.
const (
	// BudgetSubjectTool narrows a cap to one adapter id (the `tool` column of
	// token_usage — "claude-code", "codex", ...).
	BudgetSubjectTool = "tool"
	// BudgetSubjectModel narrows a cap to one model id as the capture path
	// recorded it ("claude-sonnet-4-5-20250929", ...).
	BudgetSubjectModel = "model"
)

// BudgetSubject narrows a [BudgetPolicyCap] to one tool or one model. A nil
// Subject is the ordinary whole-caller cap (org / team / member), which is what
// every cap authored before this field existed is.
type BudgetSubject struct {
	// Kind is BudgetSubjectTool or BudgetSubjectModel. An unknown kind is
	// IGNORED by the node, never guessed at — the same rule periodRules
	// applies to an unknown period.
	Kind string `json:"kind"`
	// ID is the subject's identifier, compared case-insensitively after
	// trimming (see [BudgetPolicyCap.SubjectKey]). Tool and model ids reach
	// the node from several adapters with inconsistent casing, and a cap that
	// silently missed because the org typed "Claude-Code" would be a ceiling
	// that reports as in force and enforces nothing.
	ID string `json:"id"`
}

// BudgetPolicyCap is the caller's effective cap for ONE budget period.
//
// A period-keyed LIST exists because the node's four budget windows are
// per-period ([guard.budget] session / daily / weekly / monthly): an org that
// authored both a daily and a monthly cap has two independent numbers, and a
// single-period body could only ever deliver one of them, silently dropping
// the other. Each entry is already resolved — the tightest cap per unit across
// the caller's applicable org / team / member rows — so the node composes, it
// never re-derives.
type BudgetPolicyCap struct {
	// Period is one of the BudgetPolicyPeriod* constants.
	Period string `json:"period"`
	// Timezone is the IANA name the period's calendar boundary is anchored
	// in. "" means UTC.
	Timezone string `json:"timezone"`
	// CapTokens / CapUSD are the tightest cap in each unit. 0 is the "unset"
	// sentinel in BOTH, exactly as in the `budgets` table — a zero cap is
	// never a cap of zero.
	CapTokens int64   `json:"cap_tokens,omitempty"`
	CapUSD    float64 `json:"cap_usd,omitempty"`
	// Enforcement is the STRICTEST mode among the applicable rows of this
	// period (report < soft < hard).
	Enforcement string `json:"enforcement"`
	// Thresholds is the alert ladder of the row that produced the leading
	// cap, e.g. [0.75, 0.9, 1.0].
	Thresholds []float64 `json:"thresholds,omitempty"`
	// ResolvedScope names the row that produced the LEADING cap (tokens when
	// a token cap exists, otherwise USD), so a developer can see which cap
	// bit them: "org", "team:<id>" or "member:<id>".
	ResolvedScope string `json:"resolved_scope"`
	// ScopeTokens / ScopeUSD name the row behind each unit's cap. They are
	// distinct fields rather than one because the tokens cap and the USD cap
	// can legitimately come from different levels.
	ScopeTokens string `json:"scope_tokens,omitempty"`
	ScopeUSD    string `json:"scope_usd,omitempty"`

	// ---- bundle BUD-N additions. APPEND-ONLY: see the canonicalisation rule
	// on [BudgetPolicySigningMessage]. New fields go at the END of this
	// struct, and every one of them carries `omitempty`, so a body that sets
	// none of them marshals byte-for-byte as it did before they existed.

	// Subject narrows this cap to one tool or one model. nil is the ordinary
	// whole-caller cap. A subject cap is a REAL cap: the node enforces it at
	// the same chokepoints as the whole-caller cap, against the same windows,
	// in whichever unit the org authored.
	Subject *BudgetSubject `json:"subject,omitempty"`
	// SpentUSD / SpentTokens are the ORG's own measurement of what this cap's
	// scope has already consumed in the current period — the cross-machine
	// BASELINE (P1-9). A developer with a laptop and a devbox burns one org
	// budget from two nodes, and a node that can only see its own rows
	// enforces a cap that is, in the org's terms, already breached.
	//
	// The node's effective spend for the cap is therefore
	//
	//	org baseline (this number) + this machine's own local spend
	//
	// which is why SpentExcludesMachine below is not optional decoration: if
	// the server could not remove the caller's own machine from its
	// aggregate, this number ALREADY contains the local spend and adding the
	// two would double-count. The node then refuses the baseline outright
	// (posture org_baseline_unverified) and enforces on local spend alone.
	//
	// 0 is "nothing measured", which composes identically to "no baseline" —
	// a zero baseline changes no comparison.
	SpentUSD    float64 `json:"spent_usd,omitempty"`
	SpentTokens int64   `json:"spent_tokens,omitempty"`
	// SpentAsOf is when the server measured Spent*, RFC3339. It is what makes
	// the baseline REFUSABLE: a budget rail that kept applying a number from
	// an outage three hours ago would enforce a fleet-wide ceiling against a
	// picture of the past. The node applies it only inside a staleness window
	// of 2x its own push interval + 60s (internal/orgbudget.BaselineMaxAge) —
	// two cadences plus slack, because one missed push is ordinary and two is
	// a rail that has stopped.
	//
	// Empty or unparsable means STALE, never fresh: an undated number cannot
	// be shown to be current. Stale composes to a zero baseline and the
	// honest posture, never to a refusal to run (ruling: never fail-closed on
	// a missing baseline).
	SpentAsOf string `json:"spent_as_of,omitempty"`
	// SpentExcludesMachine is true when the server EXCLUDED the calling
	// node's own machine identity from Spent*. Only then may the node add its
	// own local spend. False (including the zero value a server that predates
	// this field sends) means the node must not compose the two.
	SpentExcludesMachine bool `json:"spent_excludes_machine,omitempty"`
	// SpentIncludesUnattributed is true when Spent* counted rows the server
	// could not attribute to ANY machine identity. Those rows may or may not
	// be this node's, so the baseline may double-count a little. It is
	// applied anyway — under-enforcing a cap is the worse failure for an
	// enterprise posture — and the fact travels to the posture row
	// (BudgetPostureRow.OrgBaselineUnattributed) so an admin reading
	// "over budget" can see the caveat instead of discovering it.
	SpentIncludesUnattributed bool `json:"spent_includes_unattributed,omitempty"`
}

// SubjectKey returns this cap's normalized subject kind and id, and whether it
// HAS a usable subject at all. Normalisation (trim + ASCII lowercase) happens
// in exactly one place, here, so the server's spelling and the node's captured
// spelling meet on one rule rather than on two.
//
// ok is false for a whole-caller cap (nil Subject), for a kind outside the
// closed vocabulary, and for an empty id — an unknown subject is IGNORED, never
// widened into a cap on everything.
func (c BudgetPolicyCap) SubjectKey() (kind, id string, ok bool) {
	if c.Subject == nil {
		return "", "", false
	}
	kind = strings.ToLower(strings.TrimSpace(c.Subject.Kind))
	id = strings.ToLower(strings.TrimSpace(c.Subject.ID))
	if id == "" {
		return "", "", false
	}
	if kind != BudgetSubjectTool && kind != BudgetSubjectModel {
		return "", "", false
	}
	return kind, id, true
}

// BudgetPolicyBody is the signed body. Its top-level cap fields mirror the
// LEADING [BudgetPolicyCap] (the entry that binds first: strictest
// enforcement, then shortest period) so a reader that only understands one
// cap still gets the one that actually bites; Caps carries every period.
type BudgetPolicyBody struct {
	// Version is org_budget_policy_version.version — bumped by every budget
	// mutation, so a node can cheaply detect "nothing changed".
	Version int64 `json:"version"`
	// ResolvedScope / CapTokens / CapUSD / Period / Timezone / Enforcement /
	// Thresholds mirror the leading entry of Caps.
	ResolvedScope string    `json:"resolved_scope"`
	CapTokens     int64     `json:"cap_tokens,omitempty"`
	CapUSD        float64   `json:"cap_usd,omitempty"`
	Period        string    `json:"period"`
	Timezone      string    `json:"timezone"`
	Enforcement   string    `json:"enforcement"`
	Thresholds    []float64 `json:"thresholds,omitempty"`
	// Caps is every resolved period, shortest window first.
	Caps []BudgetPolicyCap `json:"caps,omitempty"`
	// IssuedAt is when the org MINTED this document, RFC3339, inside the
	// signed body so only the org can set it (fundamentals finding M3).
	//
	// WHY IT IS NEEDED when the body is already signed and version-checked:
	// version monotonicity refuses an OLDER document, but an EQUAL-version
	// one is legitimately re-served on every poll, so a correctly signed
	// document stays valid forever. An intermediary holding yesterday's
	// explicit-none can therefore replay it at a node with a COLD cache — a
	// restart, a fresh install — which has no cached version to compare
	// against and would run uncapped believing the org said so. A timestamp
	// dates the document; nothing else on this body does.
	//
	// It is deliberately NOT part of the ETag (see BudgetPolicyDigest): the
	// document is re-minted on every request, so an ETag over it would change
	// every second and destroy the 304 fast path this rail depends on.
	//
	// Empty means a server that predates the field. A node treats that as
	// "undated", which is the compatibility direction, and the deploy-order
	// constraint in docs/budgets.md covers it.
	IssuedAt string `json:"issued_at,omitempty"`
}

// BudgetPolicyDefaultMaxAge is the freshness window a node applies to
// IssuedAt when [guard.budget].max_document_age is unset. One hour: long
// enough that a node missing several poll cycles still accepts the next
// document it sees, short enough that a captured document is not a
// standing credential.
const BudgetPolicyDefaultMaxAge = time.Hour

// BudgetPolicyMaxSkew is how far into the FUTURE an issued_at may sit before
// the node refuses it. Node and org clocks drift, and refusing a document
// because the server is 20 seconds ahead would be an outage manufactured out
// of NTP jitter — but an issued_at hours ahead is a document minted to outlive
// its freshness window, which is the attack the window exists to stop.
const BudgetPolicyMaxSkew = 5 * time.Minute

// BudgetPolicyFresh reports whether a document's IssuedAt falls inside the
// acceptance window, and names the reason when it does not.
//
// An EMPTY IssuedAt is FRESH: it means a server that predates the field, and
// refusing those would break every node the moment it upgraded ahead of its
// org server. That is the compatibility direction, and it is stated here
// rather than at the call site so both ends of the rail read one rule.
//
// An UNPARSABLE IssuedAt is not fresh. Empty is a server that never spoke;
// garbage is a server (or something in between) that spoke and cannot be
// understood, and those are different facts.
func BudgetPolicyFresh(issuedAt string, maxAge time.Duration, now time.Time) (bool, string) {
	raw := strings.TrimSpace(issuedAt)
	if raw == "" {
		return true, ""
	}
	if maxAge <= 0 {
		maxAge = BudgetPolicyDefaultMaxAge
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false, "issued_at is not RFC3339: " + raw
	}
	if age := now.Sub(t); age > maxAge {
		return false, fmt.Sprintf("issued_at %s is %s old, past the %s freshness window (replay)",
			raw, age.Truncate(time.Second), maxAge)
	}
	if ahead := t.Sub(now); ahead > BudgetPolicyMaxSkew {
		return false, fmt.Sprintf("issued_at %s is %s in the future, past the %s skew allowance",
			raw, ahead.Truncate(time.Second), BudgetPolicyMaxSkew)
	}
	return true, ""
}

// BudgetPolicyScopeNone is the ResolvedScope of a SIGNED EXPLICIT NONE: the
// org has authored no budget covering this caller, and says so in a document
// the node can verify.
//
// It exists because the alternative — a 404 — is UNSIGNED, and an unsigned
// answer is exactly what a fail-closed node must not trust (org-budget ruling
// R2). Anyone who can intercept this rail can synthesise a 404; nobody can
// synthesise this document without the org's key. It is the same move the
// pricing rail already made with PricingSourceNoPricing ("the org SIGNED an
// empty price list"), and for the same reason: "we have nothing for you" and
// "we could not tell you" must be different, verifiable facts.
//
// A none body carries the org's current budget-policy Version, so it also
// participates in the replay/monotonicity check: an old capped document cannot
// be replayed over a newer none.
const BudgetPolicyScopeNone = "none"

// EmptyBudgetPolicyBody returns the signed-explicit-none body for a caller no
// budget applies to. It is a constructor rather than a literal at the call
// site so the shape of "none" has one definition on both ends of the wire.
//
// Everything except Version and ResolvedScope is deliberately zero: no period,
// no enforcement, no caps. [BudgetPolicyBody.Empty] is the predicate that
// recognises it, and the node's composition treats it as "no ceiling
// authored", never as a ceiling of zero.
func EmptyBudgetPolicyBody(version int64) BudgetPolicyBody {
	return BudgetPolicyBody{Version: version, ResolvedScope: BudgetPolicyScopeNone}
}

// Empty reports whether this body authors NO cap at all — the signed explicit
// none, or any body whose cap list and legacy single-period fields are both
// absent.
//
// The rule mirrors the one the node's composer applies when it expands a body
// into caps (internal/orgbudget's capsOf: the list when present, else the
// legacy top-level period), so "the composer will find no caps here" and "this
// body is empty" can never disagree.
func (b BudgetPolicyBody) Empty() bool {
	return len(b.Caps) == 0 && b.Period == ""
}

// BudgetPolicyDoc is the wire document: the body's fields inline (the
// embedded struct flattens in JSON) plus the org's Ed25519 signature.
type BudgetPolicyDoc struct {
	BudgetPolicyBody
	// Signature is base64 (std encoding, matching every other org rail) over
	// [BudgetPolicySigningMessage].
	Signature string `json:"signature"`
}

// budgetPolicySigningDomain domain-separates budget-policy signatures from
// every other Ed25519 use in the protocol. One org key signs several rails, so
// a signature minted on one must never verify on another.
const budgetPolicySigningDomain = "sbo-budget-policy-v1"

// BudgetPolicySigningMessage returns the canonical bytes signed over a budget
// policy body:
//
//	SHA-256( domain || 0x00 || orgID || 0x00 || subject || 0x00 || bodyJSON )
//
// Binding the ORG and the SUBJECT is the property this rail needs and the
// resource rail does not: the body is resolved PER CALLER, so a genuinely
// signed body handed to a different member (or a different tenant) would
// otherwise be a valid document granting them somebody else's cap. The body
// carries its own Version, so version binding comes for free with bodyJSON —
// which is what closes the ROUTING-SIG-1 class of replay (an old body served
// under an inflated version) on this rail.
//
// bodyJSON is encoding/json's rendering of the struct: field order is the
// struct's declaration order and there are no maps anywhere in the shape, so
// it is deterministic without a canonicaliser.
//
// THE CANONICALISATION RULE, stated once for both ends (bundle BUD-N):
//
//  1. A new field is APPENDED at the end of its struct, never inserted, and
//     carries `omitempty`. encoding/json emits declaration order, so appending
//     leaves every byte of an existing body untouched and `omitempty` keeps a
//     zero-valued new field out of the bytes entirely. An OLD body therefore
//     still verifies on a NEW node: the new node unmarshals it, the new fields
//     stay zero, and the re-marshalled bytes are identical.
//  2. The reverse direction is the one that needs a deploy order. An OLD node
//     verifying a body that POPULATES a new field drops the field on unmarshal,
//     re-marshals shorter bytes, and the signature does not verify — it reports
//     fetch_state=unverified and keeps its own numbers (fail-open). A server
//     must therefore not populate Subject / Spent* for a caller whose agent is
//     too old to know them; gate emission on the reported agent version the
//     same way [server].min_agent_version already reads it. On a MANAGED node
//     that has never cached a verified body this is not merely a degraded cap,
//     it is B-625 refusing requests, so the gate is a requirement and not an
//     optimisation.
//  3. A pointer field (Subject) is nil-not-empty-struct: `*BudgetSubject` with
//     omitempty vanishes when nil, whereas an embedded struct would render
//     `{"kind":"","id":""}` on every whole-caller cap and change every body's
//     bytes at once.
func BudgetPolicySigningMessage(orgID, subject string, body BudgetPolicyBody) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.BudgetPolicySigningMessage: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(budgetPolicySigningDomain))
	h.Write([]byte{0})
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(subject))
	h.Write([]byte{0})
	h.Write(raw)
	return h.Sum(nil), nil
}

// SignBudgetPolicy returns the wire document for one caller.
func SignBudgetPolicy(priv ed25519.PrivateKey, orgID, subject string, body BudgetPolicyBody) (BudgetPolicyDoc, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return BudgetPolicyDoc{}, errors.New("orgcontract.SignBudgetPolicy: bad private key size")
	}
	msg, err := BudgetPolicySigningMessage(orgID, subject, body)
	if err != nil {
		return BudgetPolicyDoc{}, err
	}
	return BudgetPolicyDoc{
		BudgetPolicyBody: body,
		Signature:        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	}, nil
}

// ErrBudgetPolicySignature is returned by [VerifyBudgetPolicy] when the
// document does not verify under pub for this (orgID, subject). The node maps
// it to "refuse the body and keep the previous one", never to "apply an
// unsigned cap".
var ErrBudgetPolicySignature = errors.New("orgcontract: budget policy signature does not verify")

// VerifyBudgetPolicy checks doc's signature against pub for the (orgID,
// subject) it was minted for. pub is the org's policy signing key, which the
// node accepts only when PublicKeyPinHash(pub) equals its TOFU pin — this
// function deliberately does NOT re-check that pin, so the pin stays owned by
// the one place that established it.
func VerifyBudgetPolicy(pub ed25519.PublicKey, orgID, subject string, doc BudgetPolicyDoc) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("orgcontract.VerifyBudgetPolicy: bad public key size")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return fmt.Errorf("orgcontract.VerifyBudgetPolicy: %w", err)
	}
	msg, err := BudgetPolicySigningMessage(orgID, subject, doc.BudgetPolicyBody)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrBudgetPolicySignature
	}
	return nil
}

// BudgetPolicyDigest is the ETag substrate for GET /api/agent/budget: the
// sha256 hex of the signed body WITHOUT IssuedAt. Everything else is in,
// INCLUDING each cap's SpentAsOf.
//
// It hashes the BODY and not merely Version deliberately. Version bumps on
// every budget mutation, but a caller's effective body also changes when their
// TEAM MEMBERSHIP changes — an ETag over the version alone would answer 304 to
// a node whose cap had genuinely changed. (Membership changes now bump the
// version too, per finding M3, but the ETag does not depend on that holding.)
//
// IssuedAt is EXCLUDED, and that exclusion is the whole reason this hashes the
// body rather than the document. The document is re-minted per request, so its
// timestamp — and therefore its signature — differs on every poll; an ETag
// over either would change every second and every conditional GET would be a
// full 200. The 304 fast path is what makes a per-caller rail affordable, so
// the validator has to identify the CONTENT, not the minting.
//
// Excluding it costs nothing security-wise: the ETag is a cache validator the
// node itself supplies and compares, never a trust decision. Freshness is
// judged by BudgetPolicyFresh over the SIGNED IssuedAt, and a 304 changes
// nothing about the document already in force.
//
// EACH CAP'S SpentAsOf IS INCLUDED, and this REVERSES an earlier decision that
// excluded it by analogy with IssuedAt. The analogy was wrong, and the way it
// was wrong is worth keeping rather than quietly deleting, because it is the
// shape of every "this timestamp is only decoration" argument.
//
// IssuedAt is decoration for the validator: nothing downstream reads it as
// evidence that the CONTENT is current — BudgetPolicyFresh reads it to bound
// replay, and a replayed document is refused whatever the ETag did. SpentAsOf
// is not decoration. It is the sole input to internal/orgbudget's `stale` rule,
// so it is not describing the body, it is GOVERNING the body: past
// BaselineMaxAge (two push cadences plus a minute) the node stops applying the
// cross-machine baseline entirely.
//
// Excluding it therefore built a trap that sprang exactly where the feature is
// load-bearing (P1, adversarial review). Take a laptop and an idle devbox: the
// devbox spends $12.34 and stops. The laptop's first poll gets a 200 stamped
// T0; every later poll re-measures the same $12.34 server-side, digests
// identically and answers 304, so the node keeps the T0 stamp. Five minutes
// later the cap flips `stale`, the baseline composes to ZERO, and the node
// enforces the org's cap against its own local spend alone — silently
// UNDER-counting by the $12.34 the org can see and the node no longer applies.
// A STABLE baseline is the common shape (the other machine is usually idle),
// so the bug bit whenever the feature was doing its job and never when the
// baseline was absent.
//
// WHY THIS FIX AND NOT A NODE-SIDE ONE. The alternative was to let the node
// read a 304 as "re-measured, unchanged" and refresh the stamp itself. It is
// TRUE today — the handler measures, signs and digests before it ever compares
// If-None-Match — but it makes the node's arithmetic depend on an invariant
// living in another package that nothing enforces, and it would have the node
// locally rewriting a field INSIDE a signed body whose only defence is that
// signature. This costs one number in a hash instead.
//
// WHAT IT COSTS is the part worth being precise about, because the old comment
// treated the 304 as if it saved the server's work: it does not. The handler
// builds the body, measures the spend, signs the document and computes this
// digest on EVERY request, before the conditional branch. A 304 saves a few
// hundred bytes of response and one ed25519 verify on the node — not a query,
// not a signature, not the measurement. And the server stamps SpentAsOf
// TRUNCATED TO THE MINUTE, so a caller polling faster than once a minute still
// rides the 304; at the 120-second default cadence a member WITH a baseline
// gets a small 200 per poll, and a member with none keeps 304ing forever
// (their caps carry no SpentAsOf to move).
func BudgetPolicyDigest(doc BudgetPolicyDoc) (string, error) {
	// IssuedAt is blanked on a COPY of the body — the caps slice is shared with
	// the caller's document, and this function must never mutate a body the
	// caller is about to verify or persist. Nothing in Caps is blanked any
	// more, so the slice is only ever read.
	body := doc.BudgetPolicyBody
	body.IssuedAt = ""
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("orgcontract.BudgetPolicyDigest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
