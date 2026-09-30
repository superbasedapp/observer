package localpdp

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
)

// Engine is the node PDP. Tables is the hot-swappable current table; a nil
// Holder or nil current table refuses every call (VerdictError, typed).
type Engine struct {
	Tables *Holder
}

var (
	_ Decider  = (*Engine)(nil)
	_ Filterer = (*Engine)(nil)
)

// effectClassOf maps an action onto the mcp_decision.effect_class value
// (mirrors mcpaccess's private actionResource table through a deny probe).
func effectClassOf(a mcpaccess.Action) string {
	return mcpaccess.NodeDecisionTable{}.Evaluate(mcpaccess.EvalInput{Action: a}).EffectClass
}

func errorVerdict(d Decision, code int, msg string) Decision {
	d.Verdict = VerdictError
	d.Reason = msg
	d.Error = &RPCError{Code: code, Message: msg}
	return d
}

// CheckRequest decides req. Order: table availability -> method dispatch
// (stripped tasks/* refused) -> vserver -> addressed name -> require
// invariants + grant evaluation -> observe/enforce. Only the grant
// evaluation is a POLICY verdict subject to observe-mode would-deny.
func (e *Engine) CheckRequest(_ context.Context, req Request) Decision {
	spec, known := methods[req.Method]
	base := Decision{
		Effect: string(mcpaccess.EffectDeny), DecisionClass: spec.Class, Action: spec.Action,
		VServer: req.VServerID, Attestation: EffectiveAttestation(req.Principal.Transport, req.Principal.ClientAttestation),
	}
	if !known {
		base.DecisionClass = ClassGoverned
		return errorVerdict(base, CodeMethodNotFound, "method "+req.Method+" is not dispatched by the node PDP")
	}
	base.EffectClass = effectClassOf(spec.Action)
	if spec.Stripped {
		base.Stripped = true
		return errorVerdict(base, CodeMethodNotFound, "method "+req.Method+" is stripped on the node relay (no task-binding contract, R8.27.b)")
	}
	t := e.Tables.Current()
	if t == nil {
		return errorVerdict(base, CodeUnavailable, "no tools.mcp_access table loaded (node PDP unavailable blocks in observe and enforce)")
	}
	base.Mode, base.PolicyGen, base.PolicyHash, base.PolicyVersion = t.Mode, t.PolicyGen(), t.Meta.BodyHash, t.Meta.Version
	if _, ok := t.Node.Registry.VServerByID(req.VServerID); !ok {
		return errorVerdict(base, CodeForbidden, "unknown vserver "+req.VServerID)
	}
	params, ok := decodeParams(req.Params)
	if !ok {
		return errorVerdict(base, CodeInvalidParams, "params: malformed JSON object")
	}
	name := req.Tool
	if name == "" && spec.Target != nil {
		name = spec.Target(params)
	}
	if spec.NameRequired && name == "" {
		return errorVerdict(base, CodeInvalidParams, "method "+req.Method+" needs an addressed name")
	}
	base.Name, base.Server = name, req.Server

	// POLICY verdict (observe-mode would-deny applies here only).
	in := mcpaccess.EvalInput{Principal: req.Principal.Access(), VServer: req.VServerID, Action: spec.Action, Server: req.Server, Name: name}
	if spec.Class == ClassCatalogue {
		in.Name = ""
	}
	d := t.Node.Evaluate(in)
	base.Effect, base.EffectClass, base.MatchedGrant, base.Reason = string(d.Effect), d.EffectClass, d.MatchedGrant, d.Reason
	if base.EffectClass == "" {
		base.EffectClass = effectClassOf(spec.Action)
	}
	base.StrictAudit = t.AuditStrict[req.VServerID] || t.Grants[d.MatchedGrant].AuditClass == "strict"
	if d.Effect != mcpaccess.EffectAllow {
		if t.Mode == ModeObserve {
			base.WouldDeny = true
			base.Reason = "observe: would-deny (" + base.Reason + ")"
		} else {
			base.Verdict = VerdictDeny
			if d.Effect == mcpaccess.EffectAsk {
				base.Error = &RPCError{Code: CodeApprovalRequired, Message: "approval required: " + base.Reason}
			} else {
				base.Error = &RPCError{Code: CodeForbidden, Message: "denied by policy: " + base.Reason}
			}
			return base
		}
	}
	base.Verdict = VerdictPass
	return base
}

// Filter is the response-phase catalogue filter. It is a POLICY verdict, so
// in observe mode nothing is filtered; with no table loaded everything is
// (deny-all, matching CheckRequest's refusal).
func (e *Engine) Filter(req Request, names []string) []string {
	spec, ok := methods[req.Method]
	if !ok || spec.Class != ClassCatalogue {
		return nil
	}
	t := e.Tables.Current()
	if t == nil {
		return []string{}
	}
	if t.Mode == ModeObserve {
		return names
	}
	vis := spec.VisibleAction
	if vis == "" {
		vis = spec.Action
	}
	out := make([]string, 0, len(names))
	p := req.Principal.Access()
	for _, n := range names {
		d := t.Node.Evaluate(mcpaccess.EvalInput{Principal: p, VServer: req.VServerID, Action: vis, Server: req.Server, Name: n})
		if d.Effect == mcpaccess.EffectAllow || d.Effect == mcpaccess.EffectAsk {
			out = append(out, n)
		}
	}
	return out
}
