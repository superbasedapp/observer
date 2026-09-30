package mcpaccess

// subjectMatches reports whether g's subject selector matches the request's
// principal. A product-scoped selector is honoured only at an attested client
// attestation (R2): at configured/claimed the principal is node-wide and the
// product predicate does not match.
//
// A P11(e) context-gated kind (team / project) is decided in three steps:
// the principal's TRUSTED claim when present; else the vserver's DECLARED
// scope when the kind has one (project: a direct client gets only the
// vserver-declared project scope); else NO context, and the grant is
// fail-closed - a deny / ask matches, an allow does not (failClosedEffect).
func subjectMatches(g Grant, r Registry, in EvalInput) bool {
	if g.Subject.Kind == SubjectAny || g.Subject.Kind == "" {
		return true
	}
	rule, ok := subjectRule(g.Subject.Kind)
	if !ok {
		return false
	}
	p := in.Principal
	if rule.attested && !contains(ProductAttestations, p.ClientAttestation) {
		return false
	}
	if !rule.contextGated() || rule.present(p) {
		return contains(rule.get(p), g.Subject.Value)
	}
	if rule.declared != nil {
		if v, ok := r.VServerByID(in.VServer); ok {
			if d := rule.declared(v); len(d) > 0 {
				return contains(d, g.Subject.Value)
			}
		}
	}
	return failClosedEffect(g.Effect)
}

// conditionsHold reports whether the grant's floors accept p.
func conditionsHold(g Grant, p Principal) bool {
	if f := g.Conditions.RequiresCredAssurance; f != "" && !contains(AcceptedAtLeast(CredAssuranceRanks, f), p.CredAssurance) {
		return false
	}
	if f := g.Conditions.RequiresClientAttestation; f != "" && !contains(AcceptedAtLeast(ClientAttestationRanks, f), p.ClientAttestation) {
		return false
	}
	return true
}

// resourceMatches reports whether g's resource selector covers in.
func resourceMatches(g Grant, r Registry, in EvalInput) bool {
	if g.Action != in.Action || g.Resource.VServer != in.VServer {
		return false
	}
	if g.Resource.Server != "" {
		v, ok := r.VServerByID(g.Resource.VServer)
		if !ok {
			return false
		}
		target := g.Resource.Server
		for _, s := range v.Servers {
			if s.ID == g.Resource.Server {
				target = s.Target
			}
		}
		if in.Server != target && in.Server != g.Resource.Server {
			return false
		}
	}
	if !g.Resource.AnyName() && g.Resource.Name != in.Name {
		return false
	}
	if SnapshotScoped(g.Action) && !snapshotApproves(r, g, in) {
		return false
	}
	return true
}

// candidateServers lists the members a request under g could be served by:
// the grant's own server when it names one, else the member in.Server
// resolves to, else (server unknown) every member of the vserver.
func candidateServers(r Registry, g Grant, in EvalInput) []Server {
	v, ok := r.VServerByID(g.Resource.VServer)
	if !ok {
		return nil
	}
	ref := g.Resource.Server
	if ref == "" {
		ref = in.Server
	}
	if ref == "" {
		return v.Servers
	}
	if s, ok := v.ServerByRef(ref); ok {
		return []Server{s}
	}
	return nil
}

// snapshotApproves is the R9.8 snapshot-membership guard the three PDP
// targets share (the CEL target renders the same rule as an explicit
// per-member allowlist): a snapshot-scoped name applies only when some
// candidate member either carries no approved snapshot (nothing pinned: the
// pre-adoption state) or approves the name. When every candidate is pinned
// and none lists the name - the newly-named tool under ALERT drift - the
// grant does not match and the request falls through to default-deny.
// A request naming a server that is not a member has no candidate and does
// not match.
func snapshotApproves(r Registry, g Grant, in EvalInput) bool {
	for _, s := range candidateServers(r, g, in) {
		if !s.Pinned() || s.Snapshot.Approves(in.Name) {
			return true
		}
	}
	return false
}

// grantMatches is the one definition of "this grant applies to this
// request" the three PDP targets share; they differ in how they COMPOSE
// matches into a verdict.
func grantMatches(g Grant, r Registry, in EvalInput) bool {
	return resourceMatches(g, r, in) && subjectMatches(g, r, in) && conditionsHold(g, in.Principal)
}

// requireInvariantsHold is the PDP-side twin of the CEL require rules
// (R8.23.c): issuer, org, exact single audience (R8.26.g) and the policy_gen
// floor. A principal that fails them is denied before any grant is
// consulted.
func requireInvariantsHold(r Registry, in EvalInput) (bool, string) {
	p := in.Principal
	if p.Issuer != r.Issuer {
		return false, "issuer mismatch"
	}
	if p.Org != r.Org {
		return false, "org mismatch"
	}
	v, ok := r.VServerByID(in.VServer)
	if !ok {
		return false, "unknown vserver"
	}
	if len(p.Audience) != 1 || p.Audience[0] != r.AudienceOf(v) {
		return false, "audience is not exactly the vserver audience"
	}
	if p.PolicyGen < r.PolicyGen {
		return false, "stale sbo_policy_gen"
	}
	return true, ""
}

func decisionFor(g Grant, reason string) Decision {
	return Decision{Effect: g.Effect, MatchedGrant: g.ID, EffectClass: effectClassFor(g), Reason: reason}
}

// effectClassFor maps a grant onto the mcp_decision.effect_class vocabulary.
func effectClassFor(g Grant) string {
	if g.Effect == EffectAsk {
		return "ask"
	}
	return actionResource[g.Action].effectClass
}

func denyDecision(in EvalInput, reason string) Decision {
	return Decision{Effect: EffectDeny, EffectClass: actionResource[in.Action].effectClass, Reason: reason}
}
