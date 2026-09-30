package mcpaccess

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RuleKind is the typed rule object kind (agentgateway RuleTypeSerde).
type RuleKind string

// Rule kinds. There is deliberately no "plain string" kind: a bare string
// deserializes as an ALLOW on agentgateway (authorization.rs
// RuleSerde::PlainString), the exact B2 blocker.
const (
	RuleRequire RuleKind = "require"
	RuleAllow   RuleKind = "allow"
	RuleDeny    RuleKind = "deny"
)

// Rule is one typed mcpAuthorization rule object.
type Rule struct {
	Kind RuleKind `json:"-"`
	Expr string   `json:"-"`
	// GrantID names the grant the rule was compiled from ("" for a require
	// invariant or the sentinel). It is never rendered.
	GrantID string `json:"-"`
}

// MarshalJSON renders the typed object {"<kind>": "<expr>"}.
func (r Rule) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{string(r.Kind): r.Expr})
}

// UnmarshalJSON accepts ONLY a single-key typed object; a bare string (an
// ALLOW on agentgateway) or a multi-key object is refused.
func (r *Rule) UnmarshalJSON(b []byte) error {
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("mcpaccess.Rule: a rule is a typed {require|allow|deny: expr} object, never a bare string: %w", err)
	}
	if len(m) != 1 {
		return fmt.Errorf("mcpaccess.Rule: a rule has exactly one of require/allow/deny, got %d keys", len(m))
	}
	for k, v := range m {
		switch RuleKind(k) {
		case RuleRequire, RuleAllow, RuleDeny:
			*r = Rule{Kind: RuleKind(k), Expr: v}
			return nil
		}
		return fmt.Errorf("mcpaccess.Rule: unknown rule kind %q", k)
	}
	return nil
}

// SentinelExpr is the deny-all sentinel allow expression.
const SentinelExpr = "false"

// VServerRules is the compiled rule list of one virtual server.
type VServerRules struct {
	VServerID string `json:"vserver_id"`
	Slug      string `json:"slug"`
	Audience  string `json:"audience"`
	Rules     []Rule `json:"rules"`
}

// Split returns the rules grouped by kind (the internal/mcpgw/agwadapter
// RuleSet shape: Require / Allow / Deny string slices).
func (v VServerRules) Split() (require, allow, deny []string) {
	for _, r := range v.Rules {
		switch r.Kind {
		case RuleRequire:
			require = append(require, r.Expr)
		case RuleAllow:
			allow = append(allow, r.Expr)
		case RuleDeny:
			deny = append(deny, r.Expr)
		}
	}
	return require, allow, deny
}

// CELRuleSet is CompileCEL's output: one rule list per vserver in the
// registry (a vserver with no grant still gets its invariants + sentinel, so
// it is default-deny, never allow-all).
type CELRuleSet struct {
	PolicyGen int64          `json:"policy_gen"`
	VServers  []VServerRules `json:"vservers"`
}

// ByVServer resolves one vserver's rules.
func (s CELRuleSet) ByVServer(id string) (VServerRules, bool) {
	for _, v := range s.VServers {
		if v.VServerID == id {
			return v, true
		}
	}
	return VServerRules{}, false
}

// CompileCEL compiles spec into the agentgateway mcpAuthorization rule lists
// (plan §11.4 "Concrete compiler output"). Per vserver, in order:
//
//  1. require: jwt.iss == <issuer> && jwt.sbo_org == <org>
//  2. require: exact single audience (scalar OR single-element list; a
//     multi-audience token matches neither disjunct) && jwt.sbo_policy_gen >=
//     <floor>
//  3. one allow per allow/ask grant (ask is PDP-owned: the ext_mcp leg parks
//     the call and the approved retry must pass this last filter)
//  4. one deny per deny grant, as a POSITIVE predicate
//  5. the deny-all sentinel {allow: 'false'}
//
// Only CELApplicable actions are rendered; the PDP-owned actions are decided
// by the three PDP targets.
func CompileCEL(spec Spec, now int64) (CELRuleSet, error) {
	n, err := Normalize(spec, now)
	if err != nil {
		return CELRuleSet{}, err
	}
	return compileCELNormalized(n), nil
}

func compileCELNormalized(n Normalized) CELRuleSet {
	out := CELRuleSet{PolicyGen: n.Registry.PolicyGen}
	for _, v := range n.Registry.VServers {
		aud := n.Registry.AudienceOf(v)
		vr := VServerRules{VServerID: v.ID, Slug: v.Slug, Audience: aud}
		vr.Rules = append(vr.Rules,
			Rule{Kind: RuleRequire, Expr: fmt.Sprintf("jwt.iss == %s && jwt.sbo_org == %s", celString(n.Registry.Issuer), celString(n.Registry.Org))},
			Rule{Kind: RuleRequire, Expr: fmt.Sprintf("((jwt.aud == %[1]s) || (size(jwt.aud) == 1 && jwt.aud[0] == %[1]s)) && jwt.sbo_policy_gen >= %[2]d", celString(aud), n.Registry.PolicyGen)},
		)
		var allows, denies []Rule
		for _, g := range n.Grants {
			if g.Resource.VServer != v.ID || !CELApplicable(g.Action) {
				continue
			}
			expr := grantExpr(g, v)
			switch g.Effect {
			case EffectDeny:
				denies = append(denies, Rule{Kind: RuleDeny, Expr: expr, GrantID: g.ID})
			default: // allow, ask
				allows = append(allows, Rule{Kind: RuleAllow, Expr: expr, GrantID: g.ID})
			}
		}
		vr.Rules = append(vr.Rules, allows...)
		vr.Rules = append(vr.Rules, denies...)
		vr.Rules = append(vr.Rules, Rule{Kind: RuleAllow, Expr: SentinelExpr})
		out.VServers = append(out.VServers, vr)
	}
	return out
}

// grantExpr renders one grant's predicate: subject && floors && resource.
func grantExpr(g Grant, v VServer) string {
	var parts []string
	if g.Subject.Kind != SubjectAny && g.Subject.Kind != "" {
		rule, _ := subjectRule(g.Subject.Kind)
		switch {
		case rule.contextGated():
			parts = append(parts, contextGatedExpr(rule, g, v))
		case rule.list:
			parts = append(parts, fmt.Sprintf("%s in %s", celString(g.Subject.Value), rule.path))
		default:
			parts = append(parts, fmt.Sprintf("%s == %s", rule.path, celString(g.Subject.Value)))
		}
		if rule.attested {
			parts = append(parts, "jwt.act.sbo_client_attestation in "+celList(ProductAttestations))
		}
	}
	if f := g.Conditions.RequiresCredAssurance; f != "" {
		parts = append(parts, "jwt.act.sbo_cred_assurance in "+celList(AcceptedAtLeast(CredAssuranceRanks, f)))
	}
	if f := g.Conditions.RequiresClientAttestation; f != "" {
		parts = append(parts, "jwt.act.sbo_client_attestation in "+celList(AcceptedAtLeast(ClientAttestationRanks, f)))
	}
	obj := "mcp." + actionResource[g.Action].celObject
	if SnapshotScoped(g.Action) {
		if expr, ok := snapshotExpr(g, v, obj); ok {
			return strings.Join(append(parts, expr), " && ")
		}
	}
	if g.Resource.Server != "" {
		target := g.Resource.Server
		for _, s := range v.Servers {
			if s.ID == g.Resource.Server {
				target = s.Target
			}
		}
		parts = append(parts, fmt.Sprintf("%s.target == %s", obj, celString(celTarget(target))))
	}
	if g.Resource.AnyName() {
		// Scope the rule to the resource TYPE: a missing mcp.<kind> object
		// errors and an erroring predicate never matches.
		parts = append(parts, fmt.Sprintf("%s.name != \"\"", obj))
	} else {
		parts = append(parts, fmt.Sprintf("%s.name == %s", obj, celString(g.Resource.Name)))
	}
	return strings.Join(parts, " && ")
}

// contextGatedExpr renders a P11(e) team / project subject predicate so the
// CEL target agrees with subjectMatches on all three context states, with
// explicit has() guards instead of an erroring claim read (a missing claim
// must decide, not error):
//
//   - claim PRESENT: the claim decides (`"T" in jwt.sbo_team_ids` /
//     `jwt.sbo_project_hash == "P"`);
//   - claim ABSENT and the vserver DECLARES a scope for the kind (project):
//     the rule is a constant over the declared set - true when the value is
//     declared, false otherwise;
//   - claim ABSENT, no declared scope: fail-closed - true for a deny / ask
//     grant, false for an allow.
//
// The absent branch is therefore a constant per (grant, vserver): it renders
// as `(!has(C) || X)` when it is true and `(has(C) && X)` when it is false -
// both positive, non-erroring predicates (R6).
//
// A kind with an untrusted marker (the team kind's sbo_team_overflow, P11
// fold PF2) treats the claim as ABSENT whenever the marker is present:
// `(!has(C) || has(O) || X)` / `(has(C) && !has(O) && X)`.
func contextGatedExpr(rule subjectClaimRule, g Grant, v VServer) string {
	var match string
	if rule.list {
		match = fmt.Sprintf("%s in %s", celString(g.Subject.Value), rule.path)
	} else {
		match = fmt.Sprintf("%s == %s", rule.path, celString(g.Subject.Value))
	}
	absent := failClosedEffect(g.Effect)
	if rule.declared != nil {
		if d := rule.declared(v); len(d) > 0 {
			absent = contains(d, g.Subject.Value)
		}
	}
	if rule.untrustedPath != "" {
		if absent {
			return fmt.Sprintf("(!has(%s) || has(%s) || %s)", rule.path, rule.untrustedPath, match)
		}
		return fmt.Sprintf("(has(%s) && !has(%s) && %s)", rule.path, rule.untrustedPath, match)
	}
	if absent {
		return fmt.Sprintf("(!has(%s) || %s)", rule.path, match)
	}
	return fmt.Sprintf("(has(%s) && %s)", rule.path, match)
}

// snapshotExpr renders the R9.8 snapshot-membership guard of a snapshot-
// scoped grant when at least one member it can reach carries an approved
// snapshot; ok=false when none does (the legacy name-only rendering
// applies). The predicate is a disjunction over the reachable members, one
// POSITIVE conjunct each - never a negation (R6):
//
//   - a pinned member: (mcp.tool.target == T && mcp.tool.name in [approved...])
//     for an any-name grant, or mcp.tool.target == T for a named grant the
//     member approves (a named grant it does not approve contributes no
//     disjunct);
//   - an unpinned member: mcp.tool.target == T (&& mcp.tool.name != "" for an
//     any-name grant), nothing being pinned there.
//
// T is always the member's agentgateway target name (TargetName of its
// Target), never the raw registry id: agentgateway refuses '_' in a target
// name, so a raw srv_<hex> id would never equal what it reports.
//
// A named grant keeps its mcp.tool.name == "x" equality in front. When no
// member can serve the grant (every candidate is pinned and none approves
// the name, or a pinned candidate has an empty tool list) the rule renders
// as the always-false literal: the grant exists in the rule list but can
// never match, which is exactly what the PDP targets compute for it.
func snapshotExpr(g Grant, v VServer, obj string) (string, bool) {
	var cands []Server
	if g.Resource.Server != "" {
		if s, ok := v.ServerByRef(g.Resource.Server); ok {
			cands = []Server{s}
		}
	} else {
		cands = v.Servers
	}
	pinned := false
	for _, s := range cands {
		if s.Pinned() {
			pinned = true
		}
	}
	if !pinned {
		return "", false
	}
	var alts []string
	for _, s := range cands {
		target := fmt.Sprintf("%s.target == %s", obj, celString(celTarget(s.Target)))
		switch {
		case !s.Pinned() && g.Resource.AnyName():
			alts = append(alts, fmt.Sprintf("(%s && %s.name != \"\")", target, obj))
		case !s.Pinned():
			alts = append(alts, target)
		case g.Resource.AnyName():
			if len(s.Snapshot.Tools) == 0 {
				continue
			}
			approved := append([]string(nil), s.Snapshot.Tools...)
			sort.Strings(approved)
			alts = append(alts, fmt.Sprintf("(%s && %s.name in %s)", target, obj, celList(approved)))
		case s.Snapshot.Approves(g.Resource.Name):
			alts = append(alts, target)
		}
	}
	if len(alts) == 0 {
		return SentinelExpr, true
	}
	body := alts[0]
	if len(alts) > 1 {
		body = "(" + strings.Join(alts, " || ") + ")"
	}
	if g.Resource.AnyName() {
		return body, true
	}
	return fmt.Sprintf("%s.name == %s && %s", obj, celString(g.Resource.Name), body), true
}

// celString renders a CEL double-quoted string literal.
func celString(s string) string { return strconv.Quote(s) }

func celList(vs []string) string {
	q := make([]string, len(vs))
	for i, v := range vs {
		q[i] = celString(v)
	}
	return "[" + strings.Join(q, ",") + "]"
}

// RenderJSON renders one vserver's rules as the JSON `{"rules":[...]}`
// object (the mcpAuthorization value).
func RenderJSON(v VServerRules) ([]byte, error) {
	return json.Marshal(map[string]any{"rules": v.Rules})
}

// RenderYAML renders one vserver's rules as the local-dialect YAML block
//
//	mcpAuthorization:
//	  rules:
//	  - { require: '...' }
//
// with single-quoted flow scalars (a CEL expression carries double quotes),
// byte-compatible with docs/plans/agent-access-research/fixtures/
// compiler-golden.yaml. indent is the number of leading spaces of the
// `mcpAuthorization:` key.
func RenderYAML(v VServerRules, indent int) string {
	pad := strings.Repeat(" ", indent)
	var b bytes.Buffer
	b.WriteString(pad + "mcpAuthorization:\n")
	b.WriteString(pad + "  rules:\n")
	for _, r := range v.Rules {
		b.WriteString(fmt.Sprintf("%s  - { %s: '%s' }\n", pad, r.Kind, strings.ReplaceAll(r.Expr, "'", "''")))
	}
	return b.String()
}

// Hash is a stable content hash input: the canonical JSON of the rule set
// (vservers sorted by id). The caller hashes it (compiled_hash).
func (s CELRuleSet) Canonical() ([]byte, error) {
	c := s
	c.VServers = append([]VServerRules(nil), s.VServers...)
	sort.Slice(c.VServers, func(i, j int) bool { return c.VServers[i].VServerID < c.VServers[j].VServerID })
	return json.Marshal(c)
}
