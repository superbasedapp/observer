package mcpaccess

import "sort"

// AuthZENSubject / AuthZENResource / AuthZENAction / AuthZENRequest are the
// OpenID AuthZEN evaluation request shape (subject / resource / action /
// context). The PUBLISHED HTTP endpoint is P9/v2 (plan §6.4); this is the
// in-process fourth conformance target only.
type AuthZENSubject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthZENResource is the addressed resource.
type AuthZENResource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthZENAction is the action name (the Action vocabulary).
type AuthZENAction struct {
	Name string `json:"name"`
}

// AuthZENRequest is one evaluation request.
type AuthZENRequest struct {
	Subject  AuthZENSubject  `json:"subject"`
	Resource AuthZENResource `json:"resource"`
	Action   AuthZENAction   `json:"action"`
	Context  map[string]any  `json:"context,omitempty"`
}

// AuthZENResponse is the evaluation response: Decision plus the reason
// context.
type AuthZENResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// AuthZENEvaluator collects EVERY matching grant and resolves by precedence
// (the "collect then resolve" strategy, distinct from the node table's
// first-match walk and the fast path's bucket lookup).
type AuthZENEvaluator struct {
	registry Registry
	grants   []Grant
}

// CompileAuthZEN compiles spec into the evaluator.
func CompileAuthZEN(spec Spec, now int64) (AuthZENEvaluator, error) {
	n, err := Normalize(spec, now)
	if err != nil {
		return AuthZENEvaluator{}, err
	}
	return AuthZENEvaluator{registry: n.Registry, grants: n.Grants}, nil
}

// Decide evaluates an EvalInput (the corpus form).
func (a AuthZENEvaluator) Decide(in EvalInput) Decision {
	if ok, why := requireInvariantsHold(a.registry, in); !ok {
		return denyDecision(in, "invariant: "+why)
	}
	var matched []Grant
	for _, g := range a.grants {
		if grantMatches(g, a.registry, in) {
			matched = append(matched, g)
		}
	}
	if len(matched) == 0 {
		return denyDecision(in, "authzen: no grant matched (default-deny)")
	}
	sort.SliceStable(matched, func(i, j int) bool { return precedenceLess(matched[i], matched[j]) })
	return decisionFor(matched[0], "authzen: strongest of all matches")
}

// Evaluate answers an AuthZEN-shaped request. The subject properties carry
// the Principal fields by their JSON names; the resource id is the name, the
// resource properties carry "vserver" and "server". Decision is true for
// allow AND ask (ask is "not denied" - the PDP parks it); the effect is in
// Context["effect"].
func (a AuthZENEvaluator) Evaluate(req AuthZENRequest) AuthZENResponse {
	in := EvalInput{Action: Action(req.Action.Name), Name: req.Resource.ID}
	in.VServer, _ = req.Resource.Properties["vserver"].(string)
	in.Server, _ = req.Resource.Properties["server"].(string)
	in.Principal = principalFromProps(req.Subject.ID, req.Subject.Properties)
	d := a.Decide(in)
	return AuthZENResponse{Decision: !d.Denied(), Context: map[string]any{
		"effect": string(d.Effect), "matched_grant": d.MatchedGrant, "effect_class": d.EffectClass, "reason": d.Reason,
	}}
}

func principalFromProps(id string, props map[string]any) Principal {
	p := Principal{Subject: id}
	str := func(k string) string { s, _ := props[k].(string); return s }
	list := func(k string) []string {
		var out []string
		switch v := props[k].(type) {
		case []string:
			out = v
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
		}
		return out
	}
	p.Issuer, p.Org, p.ClientID = str("issuer"), str("org"), str("client_id")
	p.Product, p.AgentKind, p.Env, p.Workspace = str("product"), str("agent_kind"), str("env"), str("ws")
	p.CredAssurance, p.ClientAttestation = str("cred_assurance"), str("client_attestation")
	p.Groups, p.Audience = list("groups"), list("audience")
	p.TeamIDs, p.ProjectHash = list("team_ids"), str("project_hash")
	p.TeamsKnown, _ = props["teams_known"].(bool)
	p.TeamsOverflow, _ = props["teams_overflow"].(bool)
	switch v := props["policy_gen"].(type) {
	case int64:
		p.PolicyGen = v
	case int:
		p.PolicyGen = int64(v)
	case float64:
		p.PolicyGen = int64(v)
	}
	return p
}

// AuthZENRequestFor renders an EvalInput as the AuthZEN request shape.
func AuthZENRequestFor(in EvalInput) AuthZENRequest {
	p := in.Principal
	props := map[string]any{
		"issuer": p.Issuer, "org": p.Org, "audience": p.Audience, "policy_gen": p.PolicyGen,
		"client_id": p.ClientID, "product": p.Product, "agent_kind": p.AgentKind, "env": p.Env, "ws": p.Workspace,
		"groups": p.Groups, "cred_assurance": p.CredAssurance, "client_attestation": p.ClientAttestation,
		"team_ids": p.TeamIDs, "teams_known": p.TeamsKnown, "teams_overflow": p.TeamsOverflow, "project_hash": p.ProjectHash,
	}
	return AuthZENRequest{
		Subject:  AuthZENSubject{Type: "principal", ID: p.Subject, Properties: props},
		Resource: AuthZENResource{Type: actionResource[in.Action].celObject, ID: in.Name, Properties: map[string]any{"vserver": in.VServer, "server": in.Server}},
		Action:   AuthZENAction{Name: string(in.Action)},
	}
}
