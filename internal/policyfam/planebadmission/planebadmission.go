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
//   - the org AI Gateway runs it on every Gateway-Mode request as request-path
//     step "judged admission" (gwhttp.Handler.Admission), with the judge routed
//     ONLY through an org-configured gateway upstream (JudgeUpstreamID) — the
//     surviving lesson of the 2026-08-13 incident: never an unreviewed
//     third-party default and never the personal plane's route;
//   - the node proxy lane, ONLY when NodeLane is true. Default OFF is
//     byte-identical to today's hardcoded exclusion (obsUpstreamLane); the flip
//     rides this signed body and nothing else, so it can never happen by
//     accident.
//
// Pure package: wire shape + compile/validate only; no SQL/HTTP/fsnotify.
package planebadmission

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
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
	// Required whenever the inner policy has judged criteria and is not off.
	JudgeUpstreamID string `json:"judge_upstream_id,omitempty"`
	// JudgeModel is the model the judge upstream is asked for (optional; the
	// wiring's default judge model applies when empty).
	JudgeModel string `json:"judge_model,omitempty"`
	// LatencyBudgetMS bounds the judge round trip; 0 ⇒ DefaultLatencyBudgetMS.
	LatencyBudgetMS int `json:"latency_budget_ms,omitempty"`
}

// PolicySpec is the compiled form.
type PolicySpec struct {
	Admission       admission.PolicySpec
	NodeLane        bool
	JudgeUpstreamID string
	JudgeModel      string
	LatencyBudgetMS int
}

// ErrJudgeUpstreamRequired names the one Plane-B-specific validation rule.
var ErrJudgeUpstreamRequired = errors.New("planebadmission: judge_upstream_id is required when the policy has judged criteria and is not off")

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
	spec := PolicySpec{
		Admission:       inner,
		NodeLane:        b.NodeLane,
		JudgeUpstreamID: strings.TrimSpace(b.JudgeUpstreamID),
		JudgeModel:      strings.TrimSpace(b.JudgeModel),
		LatencyBudgetMS: b.LatencyBudgetMS,
	}
	if spec.LatencyBudgetMS == 0 {
		spec.LatencyBudgetMS = DefaultLatencyBudgetMS
	}
	if inner.Mode != admission.ModeOff && admission.RequiresJudge(inner) && spec.JudgeUpstreamID == "" {
		return PolicySpec{}, nil, ErrJudgeUpstreamRequired
	}
	canon, err := json.Marshal(Body{
		Admission: innerCanon, NodeLane: spec.NodeLane, JudgeUpstreamID: spec.JudgeUpstreamID,
		JudgeModel: spec.JudgeModel, LatencyBudgetMS: spec.LatencyBudgetMS,
	})
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("planebadmission: canonicalise: %w", err)
	}
	return spec, canon, nil
}

// RequiresJudge reports whether the compiled spec has judged criteria.
func RequiresJudge(s PolicySpec) bool { return admission.RequiresJudge(s.Admission) }

// Enforces reports whether the inner policy asks for enforce mode.
func Enforces(s PolicySpec) bool { return s.Admission.Mode == admission.ModeEnforce }
