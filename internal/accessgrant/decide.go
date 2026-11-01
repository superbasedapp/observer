package accessgrant

import (
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Tier is the approval level a grant needs (§2.3).
type Tier string

// Tiers.
const (
	// TierKey: the type's approver key is enough.
	TierKey Tier = "key"
	// TierSuperAdmin: the approver must also be an org super-admin.
	TierSuperAdmin Tier = "super_admin"
)

// Proposal is the grant an approver is about to issue (possibly narrowed or
// widened from the request).
type Proposal struct {
	Type            string
	Effect          string
	SubjectKind     string
	UserID          string
	MachineIdentity string
	RuleID          string
	Lane            string
	CommandClass    string
	OperandHash     string
	ProjectRootHash string
	BudgetID        string
	DeltaTokens     int64
	DeltaUSD        float64
	Target          string
	// StartsAt zero means now. ExpiresAt zero means PERPETUAL (D-080),
	// unless UntilPeriodEnd is set.
	StartsAt  time.Time
	ExpiresAt time.Time
	// UntilPeriodEnd asks for a budget increase that lasts exactly until the
	// end of the budget's current period (D-081's maximum). Decide resolves
	// the expiry from the SERVER's period end at decide time, so the ask
	// cannot go stale between the request and the grant (T-785: a request
	// for "until the period ends" carried a fixed number of seconds measured
	// when it was sent, which already overshot the period end by the time
	// an approver granted it).
	UntilPeriodEnd bool
	// MaxUses 0 is unlimited.
	MaxUses int64
}

// Perpetual reports whether the proposal has no expiry.
func (p Proposal) Perpetual() bool { return p.ExpiresAt.IsZero() && !p.UntilPeriodEnd }

// Approver is who is deciding, as the server resolved them.
type Approver struct {
	UserID string
	// HasKey is whether they hold the type's approver key (in scope).
	HasKey bool
	// SuperAdmin is the org super-admin flag (rbac/superadmin.go).
	SuperAdmin bool
	// OnlyKeyHolder is true when no OTHER active member holds the type's
	// key, which is the one case a super-admin may approve their own request
	// (D-086, audited self_approved=true).
	OnlyKeyHolder bool
}

// RuleFacts are what the org knows about the rule a guard exemption names.
type RuleFacts struct {
	// Known is false when the server cannot tell (no bundle data); the
	// decision then treats the rule as LOCKED, the stricter reading.
	Known bool
	// Locked is true for a rule the developer cannot self-approve.
	Locked bool
	// Severity is the rule's severity ("critical", "high", ...).
	Severity string
}

// Facts are the inputs Decide needs beyond the proposal itself.
type Facts struct {
	Now time.Time
	// Requested is the original ask, nil for a proactive grant.
	Requested *Normalized
	// RequesterID is the member who asked ("" for a proactive grant).
	RequesterID string
	Rule        RuleFacts
	// BudgetPeriodEnd bounds a budget increase (D-081); zero = unknown, in
	// which case the window is bounded by MaxBudgetFallback.
	BudgetPeriodEnd time.Time
	// BaseCapTokens / BaseCapUSD are the granted budget row's current caps
	// (a delta needs a cap in that unit to raise).
	BaseCapTokens int64
	BaseCapUSD    float64
	Approver      Approver
	// Target is what the org knows about a tool / model / feature grant's
	// target (decideTarget, target.go).
	Target TargetFacts
}

// MaxBudgetFallback bounds a budget increase whose period end is unknown.
const MaxBudgetFallback = 31 * 24 * time.Hour

// Decision is Decide's verdict. Problems non-empty means refuse.
type Decision struct {
	Tier Tier `json:"tier"`
	// TierReasons explains a super-admin tier.
	TierReasons []string  `json:"tier_reasons,omitempty"`
	Problems    []Problem `json:"problems,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
	// Widened is true when the proposal grants MORE than was asked; the
	// handler then needs an explicit confirm, and the audit row records it.
	Widened bool `json:"widened"`
	// WidenedBy lists how.
	WidenedBy []string `json:"widened_by,omitempty"`
	// SelfApproved is the D-086 solo super-admin exception.
	SelfApproved bool `json:"self_approved"`
	// LockOverride is whether the grant is issued under the locked-rule
	// approval rule and may therefore reach a rule the node's org bundle
	// locks (decideLockOverride; carried on the wire as
	// AccessGrantWire.LockOverride).
	LockOverride bool `json:"lock_override"`
	// StartsAt / ExpiresAt are the normalized window.
	StartsAt  time.Time `json:"-"`
	ExpiresAt time.Time `json:"-"`
	// CapTokens / CapUSD are the absolute caps a budget increase resolves to
	// at approval (D-085).
	CapTokens int64   `json:"cap_tokens,omitempty"`
	CapUSD    float64 `json:"cap_usd,omitempty"`
}

// tierRule is one row of the super-admin table (§2.3; D-080, D-082).
type tierRule struct {
	reason string
	needs  func(p Proposal, f Facts, s Settings) bool
}

var tierRules = []tierRule{
	{
		reason: "a perpetual grant needs a super-admin",
		needs:  func(p Proposal, _ Facts, _ Settings) bool { return p.Perpetual() },
	},
	{
		reason: "exempting a rule your organization locked needs a super-admin",
		needs: func(p Proposal, f Facts, s Settings) bool {
			locked := f.Rule.Locked || !f.Rule.Known
			return p.Type == TypeGuardExemption && locked && s.LockedRuleApprover != ApproverPolicyWriter
		},
	},
	{
		// A rule the org cannot classify may be critical, so it is read as
		// one here too (the server resolves severity; nothing node-sent).
		reason: "lifting a critical rule needs a super-admin (soften keeps the per-call confirm)",
		needs: func(p Proposal, f Facts, _ Settings) bool {
			return p.Type == TypeGuardExemption && (strings.EqualFold(f.Rule.Severity, "critical") || !f.Rule.Known) &&
				p.Effect == orgcontract.AccessGrantEffectExempt
		},
	},
	{
		// Security plan 7.2 (lane SEC-E3): a critical code finding's
		// exception is the super admin's; a finding whose severity the org
		// cannot read is treated as critical.
		reason: "an exception for a critical code finding needs a super-admin",
		needs: func(p Proposal, f Facts, _ Settings) bool {
			return p.Type == TypeFindingException && (strings.EqualFold(f.Rule.Severity, "critical") || !f.Rule.Known)
		},
	},
}

// decideStage is one step of Decide; the stages run in order and each adds
// to the decision (CLAUDE.md #5: a table of stages, not one long ladder).
type decideStage func(d *Decision, t RequestType, p Proposal, f Facts, s Settings)

var decideStages = []decideStage{
	decideTier, decideApprover, decideSubject, decidePayload, decideTarget, decideWindow, decideUses, decideBudget, decideLockOverride,
}

// Decide applies every grant rule to a proposal: who may approve it, whether
// it is well-formed, its window, and whether it widens the request.
func Decide(p Proposal, f Facts, s Settings) Decision {
	d := Decision{Tier: TierKey}
	t, ok := TypeByID(p.Type)
	if !ok || !t.Grantable() {
		msg := fmt.Sprintf("%q cannot be granted; resolve or decline it instead", p.Type)
		if t.AnsweredByNote() {
			msg = fmt.Sprintf("%q is answered with a note, not granted; answer or decline it instead", p.Type)
		}
		d.Problems = append(d.Problems, Problem{Field: "type", Code: CodeUnknown, Message: msg})
		return d
	}
	for _, stage := range decideStages {
		stage(&d, t, p, f, s)
	}
	if f.Requested != nil {
		d.WidenedBy = widenings(p, d, *f.Requested)
		d.Widened = len(d.WidenedBy) > 0
	}
	return d
}

func decideTier(d *Decision, _ RequestType, p Proposal, f Facts, s Settings) {
	for _, r := range tierRules {
		if r.needs(p, f, s) {
			d.Tier = TierSuperAdmin
			d.TierReasons = append(d.TierReasons, r.reason)
		}
	}
}

func decideApprover(d *Decision, t RequestType, p Proposal, f Facts, _ Settings) {
	if !f.Approver.HasKey {
		d.Problems = append(d.Problems, Problem{
			Field: "approver", Code: CodeForbidden,
			Message: fmt.Sprintf("approving a %s needs the %s permission", strings.ToLower(t.Label), t.ApproverKey),
		})
	}
	if d.Tier == TierSuperAdmin && !f.Approver.SuperAdmin {
		d.Problems = append(d.Problems, Problem{Field: "approver", Code: CodeTier, Message: strings.Join(d.TierReasons, "; ")})
	}
	// D-086 holds on EVERY path that issues a grant: a request, a proactive
	// grant and an extension alike. The approver is compared with the member
	// the grant is FOR (the grantee) and with whoever asked, so a route with
	// no request row (proactive, extend) cannot skip the check. There is no
	// org setting that switches it off; the one exception is the solo
	// super-admin, audited self_approved, and a type marked NoSelfApproval
	// (a finding exception) does not have even that one.
	if !selfApproval(p, f) {
		return
	}
	if t.NoSelfApproval {
		d.Problems = append(d.Problems, Problem{
			Field: "approver", Code: CodeSelf,
			Message: fmt.Sprintf("you cannot approve a %s for yourself, even as the only approver; it stays pending until another approver decides it", strings.ToLower(t.Label)),
		})
		return
	}
	if f.Approver.SuperAdmin && f.Approver.OnlyKeyHolder {
		d.SelfApproved = true
		d.Warnings = append(d.Warnings, "you are approving an exception for yourself; this is recorded as a self-approval")
		return
	}
	d.Problems = append(d.Problems, Problem{
		Field: "approver", Code: CodeSelf,
		Message: "you cannot approve an exception for yourself; another approver must decide it",
	})
}

// selfApproval reports whether the approver would be granting themselves
// something: they are the grantee, or they raised the request.
func selfApproval(p Proposal, f Facts) bool {
	who := strings.TrimSpace(f.Approver.UserID)
	if who == "" {
		return false
	}
	return who == strings.TrimSpace(p.UserID) || who == strings.TrimSpace(f.RequesterID)
}

func decideSubject(d *Decision, _ RequestType, p Proposal, _ Facts, _ Settings) {
	if strings.TrimSpace(p.UserID) == "" {
		d.Problems = append(d.Problems, Problem{Field: "user_id", Code: CodeRequired, Message: "a grant needs a member"})
	}
	switch p.SubjectKind {
	case orgcontract.AccessGrantSubjectMember:
	case orgcontract.AccessGrantSubjectMachine:
		if strings.TrimSpace(p.MachineIdentity) == "" {
			d.Problems = append(d.Problems, Problem{
				Field: "machine_identity", Code: CodeRequired,
				Message: "a machine grant needs the machine identity",
			})
		}
	default:
		d.Problems = append(d.Problems, Problem{Field: "subject_kind", Code: CodeBadValue, Message: "subject must be member or machine"})
	}
}

// decidePayload checks the structured fields, now required: the approver is
// filling in whatever the request left out.
func decidePayload(d *Decision, t RequestType, p Proposal, _ Facts, _ Settings) {
	d.Problems = append(d.Problems, validatePayload(t, orgcontract.AccessRequestPayload{
		RuleID: p.RuleID, Lane: p.Lane, CommandClass: p.CommandClass, OperandHash: p.OperandHash,
		ProjectRootHash: p.ProjectRootHash, Effect: p.Effect, BudgetID: p.BudgetID,
		DeltaTokens: p.DeltaTokens, DeltaUSD: p.DeltaUSD, Target: p.Target,
	}, stageGrant)...)
	if t.ID == TypeGuardExemption && p.Effect == "" {
		d.Problems = append(d.Problems, Problem{Field: "effect", Code: CodeRequired, Message: "choose exempt or soften"})
	}
	if t.ID != TypeGuardExemption && p.Effect != "" {
		d.Problems = append(d.Problems, Problem{Field: "effect", Code: CodeBadValue, Message: "only a guardrail exemption has an effect"})
	}
}

func decideWindow(d *Decision, t RequestType, p Proposal, f Facts, s Settings) {
	d.StartsAt, d.ExpiresAt = p.StartsAt, p.ExpiresAt
	if d.StartsAt.IsZero() || d.StartsAt.Before(f.Now) {
		d.StartsAt = f.Now
	}
	if p.UntilPeriodEnd {
		if t.Max != MaxBudgetPeriod {
			d.Problems = append(d.Problems, Problem{
				Field: "expires_at", Code: CodeBadValue,
				Message: "only a budget increase can last until the end of its budget period",
			})
			return
		}
		d.ExpiresAt = budgetPeriodBound(d.StartsAt, f)
		if !d.ExpiresAt.After(d.StartsAt) {
			d.Problems = append(d.Problems, Problem{Field: "expires_at", Code: CodeOutOfRange, Message: "the budget period ends before the grant would start"})
		}
		return
	}
	if p.Perpetual() {
		return
	}
	switch {
	case !d.ExpiresAt.After(d.StartsAt):
		d.Problems = append(d.Problems, Problem{Field: "expires_at", Code: CodeOutOfRange, Message: "the grant must end after it starts"})
	case t.Max == MaxFixed && d.ExpiresAt.Sub(d.StartsAt) > s.MaxFor(t):
		d.Problems = append(d.Problems, Problem{
			Field: "expires_at", Code: CodeOutOfRange,
			Message: fmt.Sprintf("a %s may last at most %s; longer means perpetual (super-admin)", strings.ToLower(t.Label), HumanDuration(s.MaxFor(t))),
		})
	case t.Max == MaxBudgetPeriod:
		end := budgetPeriodBound(d.StartsAt, f)
		if d.ExpiresAt.After(end) {
			d.Problems = append(d.Problems, Problem{
				Field: "expires_at", Code: CodeOutOfRange,
				Message: fmt.Sprintf("a budget increase may last at most until the end of the current budget period (%s); choose a shorter window or until the period ends", end.UTC().Format(time.RFC3339)),
			})
		}
	}
}

// budgetPeriodBound is the latest a budget increase may end: the current
// period's end, or MaxBudgetFallback from the start when the period is
// unknown.
func budgetPeriodBound(start time.Time, f Facts) time.Time {
	if f.BudgetPeriodEnd.IsZero() {
		return start.Add(MaxBudgetFallback)
	}
	return f.BudgetPeriodEnd
}

func decideUses(d *Decision, _ RequestType, p Proposal, _ Facts, _ Settings) {
	if p.MaxUses < 0 || p.MaxUses > MaxUses {
		d.Problems = append(d.Problems, Problem{Field: "max_uses", Code: CodeOutOfRange, Message: fmt.Sprintf("uses must be between 0 (unlimited) and %d", MaxUses)})
	}
	if p.MaxUses > 0 && p.Perpetual() {
		d.Problems = append(d.Problems, Problem{
			Field: "max_uses", Code: CodeBadValue,
			Message: "a use-limited grant needs an expiry, so an unused grant cannot linger forever",
		})
	}
	if p.MaxUses > 0 && p.SubjectKind == orgcontract.AccessGrantSubjectMember {
		d.Warnings = append(d.Warnings, fmt.Sprintf("uses are counted per machine: %d per machine of this member", p.MaxUses))
	}
}

// decideLockOverride decides whether a guard exemption may reach a rule the
// member's node LOCKS (orchestrator ruling for G3: never override an
// org-locked rule unless the grant was issued under the super-admin rule).
// The super-admin rule is the locked-rule row of the tier table (§2.3,
// D-082). It is stamped ONLY for a rule the org reads as locked (an unknown
// rule reads as locked, the stricter reading the tier table uses too), and
// then only when the approval qualified: a super-admin, or a policy writer
// where the org's own locked_rule_approver setting admits policy writers. A
// super-admin exempting an unlocked rule carries no lock override (review
// C156-05): the grant then never reaches a rule the org locks. A grant
// decided without it is inert on a locked rule.
func decideLockOverride(d *Decision, t RequestType, _ Proposal, f Facts, s Settings) {
	if t.ID != TypeGuardExemption {
		return
	}
	locked := f.Rule.Locked || !f.Rule.Known
	d.LockOverride = locked && (f.Approver.SuperAdmin || s.LockedRuleApprover == ApproverPolicyWriter)
}

// decideBudget resolves a budget increase to its absolute cap now (D-085).
func decideBudget(d *Decision, t RequestType, p Proposal, f Facts, _ Settings) {
	if t.ID != TypeBudgetIncrease {
		return
	}
	if p.DeltaTokens > 0 && f.BaseCapTokens <= 0 {
		d.Problems = append(d.Problems, Problem{Field: "delta", Code: CodeBadValue, Message: "this budget has no token cap to raise"})
	}
	if p.DeltaUSD > 0 && f.BaseCapUSD <= 0 {
		d.Problems = append(d.Problems, Problem{Field: "delta", Code: CodeBadValue, Message: "this budget has no dollar cap to raise"})
	}
	d.CapTokens, d.CapUSD = ResolveDelta(f.BaseCapTokens, f.BaseCapUSD, p.DeltaTokens, p.DeltaUSD)
}

// widenings lists every way the proposal grants more than the request asked.
func widenings(p Proposal, d Decision, r Normalized) []string {
	var out []string
	if p.Perpetual() {
		out = append(out, "perpetual")
	} else if r.Duration > 0 && d.ExpiresAt.Sub(d.StartsAt) > r.Duration+time.Minute {
		out = append(out, "longer")
	}
	if r.Uses > 0 && (p.MaxUses == 0 || p.MaxUses > r.Uses) {
		out = append(out, "more uses")
	}
	if r.SubjectKind == orgcontract.AccessGrantSubjectMachine && p.SubjectKind == orgcontract.AccessGrantSubjectMember {
		out = append(out, "all machines")
	}
	rp := r.Payload
	if p.Type == TypeGuardExemption {
		// The handler pins the rule to the request's own; a different rule is
		// still read as widening, never silently substituted (C156-05).
		if rp.RuleID != "" && p.RuleID != rp.RuleID {
			out = append(out, "a different rule than the one asked about")
		}
		if rp.Effect == orgcontract.AccessGrantEffectSoften && p.Effect == orgcontract.AccessGrantEffectExempt {
			out = append(out, "exempt instead of soften")
		}
		if rp.OperandHash != "" && p.OperandHash == "" {
			out = append(out, "any command instead of the exact one")
		}
		if rp.CommandClass != "" && p.CommandClass == "" && p.OperandHash == "" {
			out = append(out, "rule-wide instead of the command class")
		}
		if rp.ProjectRootHash != "" && p.ProjectRootHash == "" {
			out = append(out, "every project")
		}
		if rp.Lane != "" && rp.Lane != LaneAll && (p.Lane == "" || p.Lane == LaneAll) {
			out = append(out, "every lane")
		}
	}
	// A request that named no amount left it to the approver (FilledLater:
	// a dollar cap where the org shows developers token usage only), so the
	// approver's amount is the answer to the ask, not a widening of it.
	askedAmount := rp.DeltaTokens > 0 || rp.DeltaUSD > 0
	if p.Type == TypeBudgetIncrease && askedAmount && (p.DeltaTokens > rp.DeltaTokens || p.DeltaUSD > rp.DeltaUSD+1e-9) {
		out = append(out, "a larger increase")
	}
	return out
}

// ResolveDelta turns a "+amount" into the absolute cap it means (D-085). A
// unit with no cap (0, the unset sentinel) stays unset.
func ResolveDelta(baseTokens int64, baseUSD float64, deltaTokens int64, deltaUSD float64) (int64, float64) {
	capTok, capUSD := int64(0), 0.0
	if baseTokens > 0 {
		capTok = baseTokens
		if deltaTokens > 0 {
			capTok += deltaTokens
		}
	}
	if baseUSD > 0 {
		capUSD = baseUSD
		if deltaUSD > 0 {
			capUSD += deltaUSD
		}
	}
	return capTok, capUSD
}

// ExtensionProblems checks that an extension moves a grant's end LATER. An
// extension supersedes the grant with a window starting now, so a shorter
// window would silently cut it; shortening is a revoke-and-reissue, which is
// audited as such. A perpetual extension always extends; a perpetual grant
// can only be shortened by revoking it.
func ExtensionProblems(currentExpiresAtNs int64, next time.Time) []Problem {
	switch {
	case next.IsZero():
		return nil
	case currentExpiresAtNs == 0:
		return []Problem{{
			Field: "expires_at", Code: CodeOutOfRange,
			Message: "this grant has no expiry, so an extension with an end would shorten it; revoke it and issue a new one instead",
		}}
	case next.UnixNano() <= currentExpiresAtNs:
		return []Problem{{
			Field: "expires_at", Code: CodeOutOfRange,
			Message: fmt.Sprintf("an extension must end after the current expiry (%s); revoke the grant to shorten it",
				time.Unix(0, currentExpiresAtNs).UTC().Format("2006-01-02 15:04 UTC")),
		}}
	}
	return nil
}
