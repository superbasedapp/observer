// Package planebadmission is the Plane-B judged-admission policy FAMILY body
// (Plane B dual-mode gateway design 2026-08-29 §4.6, operator-ruled IN; gap
// register 2026-09-02 G1-JUDGED-ADM). It is its OWN policy object — "Coding
// Agents · Policies · Admission" — that shares the admission engine as a
// library (internal/policyfam/admission compiles the inner spec; internal/obs/
// admission evaluates it) but never Plane A's policy objects, UI surface, or
// event stream.
//
// Two consumers read a compiled spec:
//
//   - the org AI Gateway runs it on Gateway-Mode requests as request-path
//     step "judged admission" (gwhttp.Handler.Admission), with the judge routed
//     ONLY through an org-configured gateway upstream (JudgeUpstreamID) — the
//     surviving lesson of the 2026-08-13 incident: never an unreviewed
//     third-party default and never the personal plane's route;
//   - the node proxy lane, ONLY when NodeLane is true AND the node is
//     managed and holds the enforce.admission authority (P-228). Default OFF
//     is byte-identical to the hardcoded exclusion (obsUpstreamLane); the flip
//     rides this signed body and nothing else, so it can never happen by
//     accident, and an individual node never runs it.
//
// Scope (P-228) says which requests the judge reads: user_prompts (the
// default, also for a body with no scope key) judges only a request whose
// newest turn is the developer's own prompt; all_calls judges every
// request's new trailing segment, tool results included. Both seams classify
// through internal/promptturn and decide through internal/promptadmit.
//
// Pure package: wire shape + compile/validate only; no SQL/HTTP/fsnotify.
package planebadmission

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/promptadmit"
)

// Family is the policy-resource family name.
const Family = "planeb.admission"

// DefaultMaxBytes bounds the inner admission body when the caller passes no
// cap (maxBytes <= 0); the inner compiler refuses a zero cap.
const DefaultMaxBytes int64 = 1 << 20

// DefaultLatencyBudgetMS bounds the judge round trip on the gateway request
// path (deterministic layers run first and are unbounded-cheap).
const DefaultLatencyBudgetMS = 1500

// Body is the org-wire JSON shape.
type Body struct {
	// Admission is the inner admission policy body (policyfam/admission wire
	// shape: mode / layers / criteria / judge rubric).
	Admission json.RawMessage `json:"admission"`
	// NodeLane flips judged admission ON for node proxies in Node Mode (§4.6
	// "even in Node Mode the admin may flip the posture"). Default false.
	NodeLane bool `json:"node_lane"`
	// JudgeUpstreamID names the gateway upstream the judge is dialed through.
	// Required whenever the AI gateway judges the policy: judged criteria,
	// not off, and not a node-lane-only body (NodeLaneOnly).
	JudgeUpstreamID string `json:"judge_upstream_id,omitempty"`
	// JudgeModel is the model the judge upstream is asked for (optional; the
	// wiring's default judge model applies when empty).
	JudgeModel string `json:"judge_model,omitempty"`
	// LatencyBudgetMS bounds the judge round trip; 0 ⇒ DefaultLatencyBudgetMS.
	LatencyBudgetMS int `json:"latency_budget_ms,omitempty"`
	// Scope is the closed enum user_prompts | all_calls; absent means
	// user_prompts. The canonical form omits the default, so a body written
	// before the key existed hashes exactly as it did.
	Scope string `json:"scope,omitempty"`
}

// PolicySpec is the compiled form.
type PolicySpec struct {
	Admission       admission.PolicySpec
	NodeLane        bool
	JudgeUpstreamID string
	JudgeModel      string
	LatencyBudgetMS int
	// LatencyBudgetExplicit is true when the body set latency_budget_ms. A
	// seam whose judge sits behind more hops (the node lane's org relay) may
	// use a larger default when the admin did not choose one.
	LatencyBudgetExplicit bool
	// Scope is always resolved (never empty).
	Scope promptadmit.Scope
}

// ErrJudgeUpstreamRequired names the one Plane-B-specific validation rule.
var ErrJudgeUpstreamRequired = errors.New("planebadmission: judge_upstream_id is required when the AI gateway judges the policy (judged criteria, not off, node_lane off); a node-lane-only policy is judged through the organization's judge relay instead")

// CompileBody parses + validates a body and returns the compiled spec plus
// the canonical bytes to sign/hash (the inner admission body re-canonicalised
// by its own compiler, so two textually different bodies with the same
// meaning hash the same).
func CompileBody(raw []byte, maxBytes int64) (PolicySpec, []byte, error) {
	if maxBytes > 0 && int64(len(raw)) > maxBytes {
		return PolicySpec{}, nil, fmt.Errorf("planebadmission: body is %d bytes, max %d", len(raw), maxBytes)
	}
	var b Body
	if err := json.Unmarshal(raw, &b); err != nil {
		return PolicySpec{}, nil, fmt.Errorf("planebadmission: invalid JSON: %w", err)
	}
	if len(b.Admission) == 0 {
		return PolicySpec{}, nil, errors.New("planebadmission: admission body is required")
	}
	innerMax := maxBytes
	if innerMax <= 0 {
		innerMax = DefaultMaxBytes
	}
	inner, innerCanon, err := admission.CompileBody(b.Admission, innerMax)
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("planebadmission: admission: %w", err)
	}
	if b.LatencyBudgetMS < 0 {
		return PolicySpec{}, nil, errors.New("planebadmission: latency_budget_ms must not be negative")
	}
	scope, err := promptadmit.ParseScope(strings.TrimSpace(b.Scope))
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("planebadmission: %w", err)
	}
	spec := PolicySpec{
		Admission:             inner,
		NodeLane:              b.NodeLane,
		JudgeUpstreamID:       strings.TrimSpace(b.JudgeUpstreamID),
		JudgeModel:            strings.TrimSpace(b.JudgeModel),
		LatencyBudgetMS:       b.LatencyBudgetMS,
		LatencyBudgetExplicit: b.LatencyBudgetMS != 0,
		Scope:                 scope,
	}
	if spec.LatencyBudgetMS == 0 {
		spec.LatencyBudgetMS = DefaultLatencyBudgetMS
	}
	// The gateway upstream is required only when the gateway judges the
	// policy (lane adm-p2 fix round 1, M2): a node_lane body with judged
	// criteria and no judge_upstream_id is node-lane only, judged through
	// the org's relay (purpose coding_admission), which never reads the
	// field. Before this, every judged body needed an upstream, so every
	// body already published still compiles to the same spec.
	if inner.Mode != admission.ModeOff && admission.RequiresJudge(inner) && spec.JudgeUpstreamID == "" && !spec.NodeLane {
		return PolicySpec{}, nil, ErrJudgeUpstreamRequired
	}
	canonScope := ""
	if scope != promptadmit.ScopeUserPrompts {
		canonScope = string(scope)
	}
	// An absent latency_budget_ms stays ABSENT in the canonical bytes the org
	// server signs: writing the defaulted 1500 here made every node see an
	// explicit budget, so the node lane's larger relay default never applied
	// (fix round 1, F1).
	canon, err := json.Marshal(Body{
		Admission: innerCanon, NodeLane: spec.NodeLane, JudgeUpstreamID: spec.JudgeUpstreamID,
		JudgeModel: spec.JudgeModel, LatencyBudgetMS: b.LatencyBudgetMS, Scope: canonScope,
	})
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("planebadmission: canonicalise: %w", err)
	}
	return spec, canon, nil
}

// NodeJudgeCapability is the live-capability token a node advertises when it
// can run the node lane's judge through the org-controlled relay (purpose
// coding_admission). The org server requires it of a body that sets
// node_lane with judged criteria, so a node that cannot honour the flip NACKs
// capability_mismatch instead of accepting the body and judging nothing.
const NodeJudgeCapability = "planeb_judge"

// NodeEngineCapability is the live-capability token a node advertises when
// its build links the admission engine (fix round 2, N5). A strict node_lane
// body requires it even with no judged criteria: a build without the engine
// would otherwise accept the body and refuse every prompt
// (promptadmit.EngineMissing), so it NACKs capability_mismatch instead.
const NodeEngineCapability = "planeb_engine"

// RequiredNodeCapabilities is the live-capability set a node must advertise to
// accept s (the org server stamps it on the signed resource). Gateway-only
// bodies (node_lane off) and mode-off bodies need nothing; judged criteria
// need the org-relay judge (which implies the engine); a strict body needs at
// least the engine.
func RequiredNodeCapabilities(s PolicySpec) []string {
	if !s.NodeLane || s.Admission.Mode == admission.ModeOff {
		return nil
	}
	switch {
	case RequiresJudge(s):
		return []string{NodeJudgeCapability}
	case s.Admission.Strict:
		return []string{NodeEngineCapability}
	default:
		return nil
	}
}

// NodeLaneOnly reports whether the body's judged criteria run only on the
// node lane: it has judged criteria, turns node_lane on and names no gateway
// judge upstream. The AI gateway has no judge route for them, so it skips
// them and applies only the deterministic layers (GatewaySpec).
func NodeLaneOnly(s PolicySpec) bool {
	return s.NodeLane && RequiresJudge(s) && s.JudgeUpstreamID == ""
}

// GatewaySpec is the spec the AI gateway evaluates: s itself, except that a
// node-lane-only body loses its judged criteria (the gateway cannot judge
// them), keeping the prefilter, the deterministic criteria and every other
// setting (lanes fix N1: before, the gateway skipped such a body whole,
// deny list included). Unchanged for every body that could be published
// before NodeLaneOnly existed. The returned spec never shares the criteria
// slice with s.
func GatewaySpec(s PolicySpec) PolicySpec {
	if !NodeLaneOnly(s) {
		return s
	}
	out := s
	out.Admission.Criteria = nil
	for _, c := range s.Admission.Criteria {
		if !c.Type.Judged() {
			out.Admission.Criteria = append(out.Admission.Criteria, c)
		}
	}
	return out
}

// RequiresJudge reports whether the compiled spec has judged criteria.
func RequiresJudge(s PolicySpec) bool { return admission.RequiresJudge(s.Admission) }

// Enforces reports whether the inner policy asks for enforce mode.
func Enforces(s PolicySpec) bool { return s.Admission.Mode == admission.ModeEnforce }
