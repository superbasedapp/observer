package mcpaccess

import (
	"fmt"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

// CELEvaluator evaluates a compiled VServerRules with cel-go, applying the
// agentgateway RBAC algorithm (authorization.rs:254-274) verbatim:
//
//	no rules            => allow
//	any deny matches    => deny
//	any require fails   => deny
//	any allow matches   => allow
//	allow rules exist   => deny (allowlist)
//	only deny rules     => ALLOW (denylist)
//
// An expression that errors at evaluation (a missing claim, a wrong type)
// counts as NOT matched - for a require that is a deny, for an allow it is
// no allow, for a deny it is no deny (the reason a deny must be a simple
// positive predicate, R6). The last branch is what the sentinel defends
// against: it is reachable only when a rule list has no allow, which
// CompileCEL never emits.
type CELEvaluator struct {
	rules []compiledRule
}

type compiledRule struct {
	kind RuleKind
	prog cel.Program
	src  string
}

// celEnv declares the three context objects agentgateway exposes to an
// mcpAuthorization rule as dyn maps.
func celEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("jwt", cel.DynType),
		cel.Variable("mcp", cel.DynType),
		cel.Variable("extauthz", cel.DynType),
	)
}

// NewCELEvaluator compiles every rule; a rule that does not parse or
// type-check is a hard error (the renderer must never emit one, R6: invalid
// CEL is only WARNed by agentgateway over xDS).
func NewCELEvaluator(v VServerRules) (*CELEvaluator, error) {
	env, err := celEnv()
	if err != nil {
		return nil, fmt.Errorf("mcpaccess.NewCELEvaluator: env: %w", err)
	}
	ev := &CELEvaluator{}
	for i, r := range v.Rules {
		ast, iss := env.Compile(r.Expr)
		if iss != nil && iss.Err() != nil {
			return nil, fmt.Errorf("mcpaccess.NewCELEvaluator: rule %d (%s) %q: %w", i, r.Kind, r.Expr, iss.Err())
		}
		prog, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("mcpaccess.NewCELEvaluator: rule %d program: %w", i, err)
		}
		ev.rules = append(ev.rules, compiledRule{kind: r.Kind, prog: prog, src: r.Expr})
	}
	return ev, nil
}

// ValidateCEL compiles every rule of every vserver and returns the first
// parse/type error, or nil. It is the publish-time guard that stands in for
// the pinned evaluator (the real-binary golden is the CI proof).
func ValidateCEL(s CELRuleSet) error {
	for _, v := range s.VServers {
		if _, err := NewCELEvaluator(v); err != nil {
			return err
		}
	}
	return nil
}

func (e *CELEvaluator) eval(r compiledRule, activation map[string]any) bool {
	out, _, err := r.prog.Eval(activation)
	if err != nil {
		return false
	}
	b, ok := out.(ref.Val)
	if !ok {
		return false
	}
	return b == types.True
}

// Allowed runs the RBAC algorithm over the activation (jwt / mcp /
// extauthz objects). The second result names the branch taken.
func (e *CELEvaluator) Allowed(activation map[string]any) (bool, string) {
	if len(e.rules) == 0 {
		return true, "no rules: allow-all"
	}
	hasAllow := false
	for _, r := range e.rules {
		if r.kind == RuleDeny && e.eval(r, activation) {
			return false, "deny rule matched: " + r.src
		}
	}
	for _, r := range e.rules {
		if r.kind == RuleRequire && !e.eval(r, activation) {
			return false, "require unmatched: " + r.src
		}
	}
	for _, r := range e.rules {
		if r.kind == RuleAllow {
			hasAllow = true
			if e.eval(r, activation) {
				return true, "allow rule matched: " + r.src
			}
		}
	}
	if hasAllow {
		return false, "no allow matched (allowlist)"
	}
	return true, "only deny rules: allow (denylist)"
}

// Activation renders the CEL context for one request in the shape
// agentgateway materializes: jwt = the minted claim set, mcp = one resource
// object keyed by kind (crates/agentgateway/src/mcp/rbac.rs ResourceType).
func Activation(in EvalInput) map[string]any {
	p := in.Principal
	var aud any
	if len(p.Audience) == 1 {
		aud = p.Audience[0] // our mint emits a scalar-string aud
	} else {
		l := make([]any, len(p.Audience))
		for i, a := range p.Audience {
			l[i] = a
		}
		aud = l
	}
	groups := make([]any, len(p.Groups))
	for i, g := range p.Groups {
		groups[i] = g
	}
	jwt := map[string]any{
		"iss": p.Issuer, "sub": p.Subject, "aud": aud, "client_id": p.ClientID,
		"sbo_org": p.Org, "sbo_policy_gen": p.PolicyGen, "sbo_env": p.Env, "sbo_ws": p.Workspace,
		"sbo_groups": groups,
		"act": map[string]any{
			"sbo_product": p.Product, "sbo_kind": p.AgentKind,
			"sbo_cred_assurance": p.CredAssurance, "sbo_client_attestation": p.ClientAttestation,
		},
	}
	// The P11(e) context claims are materialized ONLY when present - exactly
	// what a minted token carries - so has() sees the same absence
	// agentgateway does.
	if p.TeamsKnown {
		teams := make([]any, len(p.TeamIDs))
		for i, t := range p.TeamIDs {
			teams[i] = t
		}
		jwt["sbo_team_ids"] = teams
	}
	if p.TeamsOverflow {
		jwt["sbo_team_overflow"] = true
	}
	if p.ProjectHash != "" {
		jwt["sbo_project_hash"] = p.ProjectHash
	}
	mcp := map[string]any{}
	if obj := actionResource[in.Action].celObject; obj != "" {
		// agentgateway reports the member's TARGET NAME (TargetName of
		// the server id), the same mapping the compiled literal uses.
		mcp[obj] = map[string]any{"name": in.Name, "target": celTarget(in.Server)}
	}
	return map[string]any{"jwt": jwt, "mcp": mcp, "extauthz": map[string]any{}}
}

// EvaluateCEL is the CEL target of the conformance corpus: it compiles the
// vserver's rules and returns allow/deny for in. For a PDP-owned action it
// reports ok=false (not applicable).
func EvaluateCEL(s CELRuleSet, in EvalInput) (allowed bool, reason string, ok bool, err error) {
	if !CELApplicable(in.Action) {
		return false, "action is PDP-owned; not rendered into CEL", false, nil
	}
	v, found := s.ByVServer(in.VServer)
	if !found {
		return false, "unknown vserver", true, nil
	}
	ev, err := NewCELEvaluator(v)
	if err != nil {
		return false, "", true, err
	}
	a, r := ev.Allowed(Activation(in))
	return a, r, true, nil
}
