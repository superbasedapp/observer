package accessgrant

import (
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Problem codes (closed).
const (
	CodeRequired   = "required"
	CodeUnknown    = "unknown"
	CodeBadValue   = "bad_value"
	CodeTooLong    = "too_long"
	CodeOutOfRange = "out_of_range"
	CodeDisabled   = "disabled"
	CodeForbidden  = "forbidden"
	CodeTier       = "needs_super_admin"
	CodeSelf       = "self_approval"
)

// Problem is one refusal. A non-empty problem list means nothing happens.
type Problem struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error renders a problem list as one message.
func Error(probs []Problem) string {
	parts := make([]string, 0, len(probs))
	for _, p := range probs {
		parts = append(parts, p.Message)
	}
	return strings.Join(parts, "; ")
}

// Bounds on developer-typed and machine-ish strings.
const (
	MaxJustificationBytes = 2048
	MaxTargetBytes        = 200
	MaxRuleIDBytes        = 64
	MaxHashBytes          = 128
	MaxExcerptBytes       = 512
	MaxUses               = 1000
)

// Breadth vocabulary (D-092).
const (
	BreadthRule  = "rule"
	BreadthClass = "class"
	BreadthExact = "exact"
)

// Lane vocabulary for a guard exemption. "" and LaneAll match every lane.
const (
	LaneAll    = "all"
	LaneTool   = "tool"
	LanePrompt = "prompt"
	LaneProxy  = "proxy"
)

var lanes = map[string]bool{"": true, LaneAll: true, LaneTool: true, LanePrompt: true, LaneProxy: true}

// Request is a developer's ask as the server validates it.
type Request struct {
	Type          string
	Payload       orgcontract.AccessRequestPayload
	DurationS     int64
	Uses          int64
	SubjectKind   string
	Machine       string
	Justification string
}

// Normalized is a validated request with its defaults filled in.
type Normalized struct {
	Request
	// Duration is the requested window (default 24h, clamped to the type's
	// maximum under the org's settings; never perpetual, D-080).
	Duration time.Duration
	// Warnings are non-fatal adjustments the developer should see.
	Warnings []string
}

// Validate checks a STRUCTURED request (one that named a request type).
// Required fields are enforced; the window is defaulted and clamped; the
// subject defaults to "this machine" (D-092) and falls back to the member when
// the node has no machine identity (an unmanaged enrolment).
func Validate(req Request, s Settings) (Normalized, []Problem) {
	var probs []Problem
	out := Normalized{Request: req}
	t, ok := TypeByID(req.Type)
	if !ok {
		return out, []Problem{{
			Field: "request_type", Code: CodeUnknown,
			Message: fmt.Sprintf("request_type %q is not one of the known request types", req.Type),
		}}
	}
	if s.TypeDisabled(t.ID) {
		probs = append(probs, Problem{
			Field: "request_type", Code: CodeDisabled,
			Message: fmt.Sprintf("your organization does not accept %s requests", strings.ToLower(t.Label)),
		})
	}
	just := strings.TrimSpace(req.Justification)
	switch {
	case just == "":
		probs = append(probs, Problem{Field: "message", Code: CodeRequired, Message: "a justification is required"})
	case len(just) > MaxJustificationBytes:
		probs = append(probs, Problem{
			Field: "message", Code: CodeTooLong,
			Message: fmt.Sprintf("the justification must be at most %d bytes", MaxJustificationBytes),
		})
	}
	out.Justification = just

	// Window: never perpetual from a developer (D-080); default 24h (D-081).
	switch {
	case req.DurationS < 0:
		probs = append(probs, Problem{Field: "requested_duration_s", Code: CodeOutOfRange, Message: "the duration cannot be negative"})
	case req.DurationS == 0 && t.ExpiryRequired:
		probs = append(probs, Problem{Field: "requested_duration_s", Code: CodeRequired, Message: "say how long you need it: a " + strings.ToLower(t.Label) + " always has an expiry"})
	case req.DurationS == 0:
		out.Duration = DefaultDuration
	default:
		out.Duration = time.Duration(req.DurationS) * time.Second
	}
	if max := s.MaxFor(t); max > 0 && out.Duration > max {
		out.Warnings = append(out.Warnings, fmt.Sprintf("the requested duration was shortened to the %s maximum for %s", HumanDuration(max), strings.ToLower(t.Label)))
		out.Duration = max
	}
	out.DurationS = int64(out.Duration / time.Second)
	if req.Uses < 0 || req.Uses > MaxUses {
		probs = append(probs, Problem{
			Field: "requested_uses", Code: CodeOutOfRange,
			Message: fmt.Sprintf("uses must be between 0 (unlimited) and %d", MaxUses),
		})
	}

	// Subject: this machine by default; member-wide is approver-only.
	switch req.SubjectKind {
	case "", orgcontract.AccessGrantSubjectMachine:
		if strings.TrimSpace(req.Machine) == "" {
			out.SubjectKind = orgcontract.AccessGrantSubjectMember
			out.Warnings = append(out.Warnings, "this node has no machine identity, so the request covers all of your machines")
		} else {
			out.SubjectKind = orgcontract.AccessGrantSubjectMachine
		}
	case orgcontract.AccessGrantSubjectMember:
		probs = append(probs, Problem{
			Field: "subject_kind", Code: CodeForbidden,
			Message: "only an approver can widen a grant to all of your machines; ask for this machine",
		})
	default:
		probs = append(probs, Problem{Field: "subject_kind", Code: CodeBadValue, Message: "subject_kind must be machine"})
	}

	probs = append(probs, validatePayload(t, req.Payload, stageRequest)...)
	return out, probs
}

// payloadStage says whose form validatePayload is checking, which decides the
// presence checks; the shape checks always run.
type payloadStage int

const (
	// stageRequest is a developer's ask: a FilledLater field may be absent
	// (the server or the approver fills it in).
	stageRequest payloadStage = iota
	// stageGrant is an approver's grant: every Required field is present.
	stageGrant
)

// validatePayload checks a type's structured fields at one stage.
func validatePayload(t RequestType, p orgcontract.AccessRequestPayload, stage payloadStage) []Problem {
	var probs []Problem
	need := map[Field]bool{}
	for _, f := range t.Required {
		need[f] = stage == stageGrant || !t.fillable(f)
	}
	if len(p.RuleID) > MaxRuleIDBytes {
		probs = append(probs, Problem{Field: "rule_id", Code: CodeTooLong, Message: "rule_id is too long"})
	}
	if need[FieldRuleID] && strings.TrimSpace(p.RuleID) == "" {
		probs = append(probs, Problem{Field: "rule_id", Code: CodeRequired, Message: "a rule id is required"})
	}
	for _, f := range []struct{ name, v string }{
		{"operand_hash", p.OperandHash}, {"project_root_hash", p.ProjectRootHash}, {"command_class", p.CommandClass},
	} {
		if len(f.v) > MaxHashBytes {
			probs = append(probs, Problem{Field: f.name, Code: CodeTooLong, Message: f.name + " is too long"})
		}
	}
	if !lanes[p.Lane] {
		probs = append(probs, Problem{Field: "lane", Code: CodeBadValue, Message: "lane must be tool, prompt, proxy or all"})
	}
	switch p.Effect {
	case "", orgcontract.AccessGrantEffectExempt, orgcontract.AccessGrantEffectSoften:
	default:
		probs = append(probs, Problem{Field: "effect", Code: CodeBadValue, Message: "effect must be exempt or soften"})
	}
	switch p.Breadth {
	case "", BreadthRule:
	case BreadthClass:
		if strings.TrimSpace(p.CommandClass) == "" {
			probs = append(probs, Problem{Field: "command_class", Code: CodeRequired, Message: "a command-class request needs the command class"})
		}
	case BreadthExact:
		if strings.TrimSpace(p.OperandHash) == "" {
			probs = append(probs, Problem{Field: "operand_hash", Code: CodeRequired, Message: "an exact-command request needs the operand hash"})
		}
	default:
		probs = append(probs, Problem{Field: "breadth", Code: CodeBadValue, Message: "breadth must be rule, class or exact"})
	}
	if need[FieldBudgetID] && strings.TrimSpace(p.BudgetID) == "" {
		probs = append(probs, Problem{Field: "budget_id", Code: CodeRequired, Message: "a budget id is required"})
	}
	if p.DeltaTokens < 0 || p.DeltaUSD < 0 {
		probs = append(probs, Problem{Field: "delta", Code: CodeOutOfRange, Message: "a budget increase cannot be negative"})
	}
	if need[FieldDelta] && p.DeltaTokens <= 0 && p.DeltaUSD <= 0 {
		probs = append(probs, Problem{Field: "delta", Code: CodeRequired, Message: "name how much more budget you need"})
	}
	if len(p.Target) > MaxTargetBytes {
		probs = append(probs, Problem{Field: "target", Code: CodeTooLong, Message: fmt.Sprintf("target must be at most %d bytes", MaxTargetBytes)})
	}
	if need[FieldTarget] && strings.TrimSpace(p.Target) == "" {
		probs = append(probs, Problem{Field: "target", Code: CodeRequired, Message: "name the tool, model or feature"})
	}
	return probs
}

// DefaultEffect is the effect an approver form preselects for a guard rule of
// the given severity (D-091): soften (still confirm each call) for high and
// critical rules, exempt ("lift") otherwise.
func DefaultEffect(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "high", "critical":
		return orgcontract.AccessGrantEffectSoften
	default:
		return orgcontract.AccessGrantEffectExempt
	}
}
