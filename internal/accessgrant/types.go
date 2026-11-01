package accessgrant

import (
	"strings"
	"time"
)

// Request types: the closed vocabulary (§1.1). Every rule that differs by type
// is a column of RequestTypes, never a switch on these strings elsewhere.
const (
	TypeBudgetIncrease = "budget_increase"
	TypeGuardExemption = "guard_exemption"
	TypeToolAllow      = "tool_allow"
	TypeModelAccess    = "model_access"
	TypeFeatureEnable  = "feature_enable"
	// TypePageAccess shows ONE node dashboard page or tab the org hides on
	// the developer's machine (T-435, backlog item 4: the admin decides).
	TypePageAccess = "page_access"
	// TypeConfigEdit lets the developer edit ONE AI tool setting (or every
	// setting of one tool) their org's AI tool policy locks or does not grant
	// (T-436, backlog items 2d / 8: the admin decides).
	TypeConfigEdit = "config_edit"
	// TypeComponentEnable asks the org to let one component run on a
	// managed node (modular packaging plan 6.2.1, lane MP-GOV, T-670): the
	// "Request from your organization" path of a component the node's
	// node.components policy leaves inert or denies with a grantable entry.
	TypeComponentEnable = "component_enable"
	// TypeFindingException asks the org to accept ONE code security finding
	// on a managed node for a while (security plan 5.12 and 7.5, lane
	// SEC-E3): the target is the finding's opaque wire handle (finding_ref,
	// orgcontract.SecurityFindingRow.FindingRef), the rule id names its
	// rule. The node applies an honoured grant to its local exception
	// register (secsvc.SyncOrgExceptions); it is never rule-wide.
	TypeFindingException = "finding_exception"
	TypeOther            = "other"
)

// Approver permission keys. They are the org server's rbac vocabulary,
// restated here because this package must not import the org server; pinned
// against rbac by the org-side vocab test.
const (
	KeyWriteBudgets    = "write:budgets"
	KeyWritePolicy     = "write:policy"
	KeyAdminDeployment = "admin:deployment"
	// KeyWriteSecurity decides finding exceptions (security plan 7.6, lane
	// SEC-E3): triage and exceptions are one grant.
	KeyWriteSecurity = "write:security"
)

// Landing names the chokepoint a grant of a type is enforced at.
type Landing string

// Landings.
const (
	// LandBudgetRail folds the grant into the per-caller budget body (§3.3).
	LandBudgetRail Landing = "budget_rail"
	// LandGrantRail delivers the grant on the access-grant rail (§3.1).
	LandGrantRail Landing = "grant_rail"
	// LandNone means the type cannot be granted, only resolved or declined.
	LandNone Landing = "none"
	// LandAnswer means the approver ANSWERS the request: a note the
	// developer reads closes it as resolved (T-437). Nothing is enforced and
	// no grant is minted; the answer is the terminal state the developer
	// sees on their Requests page.
	LandAnswer Landing = "answer"
)

// grantingLandings are the landings that mint a grant (Grantable).
var grantingLandings = map[Landing]bool{LandBudgetRail: true, LandGrantRail: true}

// Field names a structured field a request type requires.
type Field string

// Structured fields.
const (
	FieldRuleID   Field = "rule_id"
	FieldBudgetID Field = "budget_id"
	FieldDelta    Field = "delta"
	FieldTarget   Field = "target"
)

// MaxRule says how a type's maximum duration is bounded (D-081).
type MaxRule string

// Maximum-duration rules.
const (
	// MaxFixed bounds the window by RequestType.MaxDuration.
	MaxFixed MaxRule = "fixed"
	// MaxBudgetPeriod bounds the window by the end of the budget's current
	// period (the caller supplies it).
	MaxBudgetPeriod MaxRule = "budget_period"
)

// RequestType is one row of the request-type table.
type RequestType struct {
	ID string
	// Label is the human name every surface shows.
	Label string
	// ApproverKey is the permission key an approver must hold (D-088:
	// model access is a policy writer's decision).
	ApproverKey string
	// Landing is where a grant of this type is enforced.
	Landing Landing
	// Required lists the structured fields a GRANTABLE request must carry.
	// A request missing one is still accepted (a pre-design node's legacy
	// kind, §1.1) but cannot be granted until the approver fills it in.
	Required []Field
	// FilledLater lists the Required fields a developer may leave out of a
	// request: the org server fills them from what it knows about the
	// caller, else the approver picks them. A grant still needs every
	// Required field (Decide). A budget id is one (D-334): a developer on an
	// org-managed node cannot know it, so a request never fails for lacking
	// one; the amount is another, because a dollar cap cannot be asked for
	// in dollars where the org shows developers token usage only.
	FilledLater []Field
	// Max bounds a grant's window; MaxDuration applies when Max is MaxFixed.
	Max         MaxRule
	MaxDuration time.Duration
	// LegacyKind is the W6 kind a pre-design node posts for this type.
	LegacyKind string
	// ExpiryRequired refuses a request that names no duration (the 24h
	// default is not applied): the developer states how long they ask for
	// (finding exceptions, security plan 7.5).
	ExpiryRequired bool
	// NoSelfApproval refuses a self-approval of this type on every path,
	// overriding the D-086 solo-super-admin carve-out: the request stays
	// pending until another approver decides it (security plan 5.12 and
	// 7.5: a finding exception is never its requester's own decision).
	NoSelfApproval bool
}

// Grantable reports whether a request of this type can mint a grant.
func (t RequestType) Grantable() bool { return grantingLandings[t.Landing] }

// AnsweredByNote reports whether the approver closes a request of this type
// with a note instead of a grant (LandAnswer): resolving it needs the note.
func (t RequestType) AnsweredByNote() bool { return t.Landing == LandAnswer }

// Names reports whether a grant of this type carries field f.
func (t RequestType) Names(f Field) bool { return hasField(t.Required, f) }

// fillable reports whether a request may leave f for later (FilledLater).
func (t RequestType) fillable(f Field) bool { return hasField(t.FilledLater, f) }

func hasField(fs []Field, f Field) bool {
	for _, x := range fs {
		if x == f {
			return true
		}
	}
	return false
}

const day = 24 * time.Hour

// DefaultDuration is the window a request asks for when it names none, and
// the approver form's preset (D-081: 24h).
const DefaultDuration = 24 * time.Hour

// RequestTypes is THE table (CLAUDE.md #5). Maxima are D-081; approver keys
// are §1.1 with D-088 for model access.
var RequestTypes = []RequestType{
	{
		ID: TypeBudgetIncrease, Label: "Budget increase", ApproverKey: KeyWriteBudgets,
		Landing: LandBudgetRail, Required: []Field{FieldBudgetID, FieldDelta},
		FilledLater: []Field{FieldBudgetID, FieldDelta},
		Max:         MaxBudgetPeriod, LegacyKind: "raise_budget",
	},
	{
		ID: TypeGuardExemption, Label: "Guardrail exemption", ApproverKey: KeyWritePolicy,
		Landing: LandGrantRail, Required: []Field{FieldRuleID},
		Max: MaxFixed, MaxDuration: 30 * day,
	},
	{
		ID: TypeToolAllow, Label: "Tool access", ApproverKey: KeyWritePolicy,
		Landing: LandGrantRail, Required: []Field{FieldTarget},
		Max: MaxFixed, MaxDuration: 90 * day, LegacyKind: "allow_tool",
	},
	{
		ID: TypeModelAccess, Label: "Model access", ApproverKey: KeyWritePolicy,
		Landing: LandGrantRail, Required: []Field{FieldTarget},
		Max: MaxFixed, MaxDuration: 90 * day,
	},
	{
		ID: TypeFeatureEnable, Label: "Feature access", ApproverKey: KeyAdminDeployment,
		Landing: LandGrantRail, Required: []Field{FieldTarget},
		Max: MaxFixed, MaxDuration: 90 * day, LegacyKind: "enable_feature",
	},
	{
		// T-435: the developer asks to see a page or tab their org hides;
		// the grant shows it read-only until it ends (approver: whoever
		// edits developer dashboards).
		ID: TypePageAccess, Label: "Hidden page access", ApproverKey: KeyWritePolicy,
		Landing: LandGrantRail, Required: []Field{FieldTarget},
		Max: MaxFixed, MaxDuration: 90 * day,
	},
	{
		// T-436: the developer asks to edit an AI tool setting the org's
		// policy locks (or grants no editing of); the grant opens it until it
		// ends, then the policy applies again (approver: whoever writes the
		// AI tool policy).
		ID: TypeConfigEdit, Label: "AI tool setting edit", ApproverKey: KeyWritePolicy,
		Landing: LandGrantRail, Required: []Field{FieldTarget},
		Max: MaxFixed, MaxDuration: 30 * day,
	},
	{
		// MP-GOV (plan 6.2.1 conflict table): the grant activates one
		// component for its window on a managed node whose grant carries
		// components.govern. It overrides the policy's unlisted rule and a
		// deny entry marked grantable, never a non-grantable deny, the local
		// ceiling or a component this build lacks (the one resolver
		// decides). Approved by whoever may change the deployment.
		ID: TypeComponentEnable, Label: "Component access", ApproverKey: KeyAdminDeployment,
		Landing: LandGrantRail, Required: []Field{FieldTarget},
		Max: MaxFixed, MaxDuration: 90 * day,
	},
	{
		// Lane SEC-E3 (security plan 5.12 and 7.5): one code finding on a
		// managed node, for a stated while (expiry required). Decided with
		// write:security; a perpetual or critical-finding exception needs
		// the super admin (tierRules), never its requester (D-086), and a
		// perpetual one falls due for re-review every 90 days (ReviewDue).
		ID: TypeFindingException, Label: "Code finding exception", ApproverKey: KeyWriteSecurity,
		Landing: LandGrantRail, Required: []Field{FieldRuleID, FieldTarget},
		Max: MaxFixed, MaxDuration: 90 * day, ExpiryRequired: true, NoSelfApproval: true,
	},
	{
		// T-437: an "other" ask was never grantable and landed nowhere; it
		// is answered with a note the developer reads (LandAnswer).
		ID: TypeOther, Label: "Something else", ApproverKey: KeyWritePolicy,
		Landing: LandAnswer, Max: MaxFixed, LegacyKind: "other",
	},
}

// TypeByID returns the row for id (ok=false for an unknown type).
func TypeByID(id string) (RequestType, bool) {
	id = strings.TrimSpace(id)
	for _, t := range RequestTypes {
		if t.ID == id {
			return t, true
		}
	}
	return RequestType{}, false
}

// TypeForLegacyKind maps a W6 kind onto its request type ("" maps to other).
// An unknown kind maps to other: a request is never refused for its kind.
func TypeForLegacyKind(kind string) RequestType {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		kind = "other"
	}
	for _, t := range RequestTypes {
		if t.LegacyKind == kind {
			return t
		}
	}
	other, _ := TypeByID(TypeOther)
	return other
}

// LegacyKindFor returns the W6 kind to store beside a structured request, so
// the legacy queue column stays meaningful ("other" when the type has none).
func LegacyKindFor(typeID string) string {
	if t, ok := TypeByID(typeID); ok && t.LegacyKind != "" {
		return t.LegacyKind
	}
	return "other"
}
