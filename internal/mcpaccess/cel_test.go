package mcpaccess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func goldenSpec() Spec {
	return Spec{
		Registry: Registry{
			Issuer: "https://auth.acme.superbased.app", Org: "acme", GatewayBaseURI: "https://mcp-gw.acme.superbased.app", PolicyGen: 41,
			VServers: []VServer{{ID: "vs-gh", Slug: "gh", SenderConstraint: "bearer", Servers: []Server{{ID: "gh", Target: "gh", CredentialMode: "service"}}}},
		},
		Grants: []Grant{
			{ID: "g1", Ord: 1, Subject: Subject{Kind: SubjectProduct, Value: "claude-code"}, Resource: Resource{VServer: "vs-gh", Name: "create_issue"}, Action: ActionCall, Effect: EffectAllow, Enabled: true},
			{ID: "g2", Ord: 2, Subject: Subject{Kind: SubjectAny}, Resource: Resource{VServer: "vs-gh", Name: "delete_repo"}, Action: ActionCall, Effect: EffectDeny, Enabled: true},
		},
	}
}

// TestCompileCELMatchesCommittedGolden pins the renderer byte-for-byte
// against the rules block of docs/plans/agent-access-research/fixtures/
// compiler-golden.yaml (comments stripped): typed objects, the exact
// single-audience disjunct, the product+attestation allow, the typed deny,
// the sentinel.
func TestCompileCELMatchesCommittedGolden(t *testing.T) {
	set, err := CompileCEL(goldenSpec(), 0)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := set.ByVServer("vs-gh")
	if !ok {
		t.Fatal("no vs-gh")
	}
	got := RenderYAML(v, 8)
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "plans", "agent-access-research", "fixtures", "compiler-golden.yaml"))
	if os.IsNotExist(err) {
		// docs/ is private-only: the public tree (scripts/release.sh) ships
		// this package without the research fixtures.
		t.Skip("compiler-golden.yaml is not in this tree (public build)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, line := range strings.Split(string(raw), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(trim, "mcpAuthorization:") || strings.HasPrefix(trim, "rules:") || strings.HasPrefix(trim, "- {") {
			want = append(want, line)
		}
	}
	if strings.TrimRight(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rendered YAML differs from compiler-golden.yaml\n--- got\n%s--- want\n%s", got, strings.Join(want, "\n"))
	}
	require, allow, deny := v.Split()
	if len(require) != 2 || len(allow) != 2 || len(deny) != 1 || allow[len(allow)-1] != SentinelExpr {
		t.Fatalf("split = %d/%d/%d, last allow %q", len(require), len(allow), len(deny), allow[len(allow)-1])
	}
}

// TestRenderJSONNeverEmitsBareStrings: every rule is an object with exactly
// one of require/allow/deny (a bare string is an ALLOW on agentgateway).
func TestRenderJSONNeverEmitsBareStrings(t *testing.T) {
	set, _ := CompileCEL(goldenSpec(), 0)
	b, err := RenderJSON(set.VServers[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []map[string]string `json:"rules"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("rules must be objects: %v\n%s", err, b)
	}
	for i, r := range doc.Rules {
		if len(r) != 1 {
			t.Fatalf("rule %d has %d keys", i, len(r))
		}
		for k := range r {
			if k != "require" && k != "allow" && k != "deny" {
				t.Fatalf("rule %d key %q", i, k)
			}
		}
	}
	if doc.Rules[len(doc.Rules)-1]["allow"] != SentinelExpr {
		t.Fatal("sentinel is not last")
	}
}

// TestAgentgatewayPrecedenceProof drives the cel-go RBAC re-implementation
// with hand-built rule sets to pin WHY the sentinel exists: no rules and a
// deny-only set both ALLOW (authorization.rs:254-274); adding the sentinel
// makes them deny.
func TestAgentgatewayPrecedenceProof(t *testing.T) {
	in := EvalInput{VServer: "vs-gh", Action: ActionCall, Name: "create_issue", Principal: Principal{
		Issuer: "https://auth.acme.superbased.app", Org: "acme", Audience: []string{"https://mcp-gw.acme.superbased.app/mcp/gh"}, PolicyGen: 41,
		Product: "claude-code", ClientAttestation: "process_attested",
	}}
	act := Activation(in)
	cases := []struct {
		name  string
		rules []Rule
		want  bool
	}{
		{"no rules => allow-all", nil, true},
		{"deny-only => allow (denylist)", []Rule{{Kind: RuleDeny, Expr: `mcp.tool.name == "delete_repo"`}}, true},
		{"deny-only + sentinel => deny", []Rule{{Kind: RuleDeny, Expr: `mcp.tool.name == "delete_repo"`}, {Kind: RuleAllow, Expr: SentinelExpr}}, false},
		{"require unmet => deny even with a matching allow", []Rule{{Kind: RuleRequire, Expr: `jwt.sbo_org == "other"`}, {Kind: RuleAllow, Expr: `mcp.tool.name == "create_issue"`}}, false},
		{"deny wins over allow", []Rule{{Kind: RuleAllow, Expr: `mcp.tool.name == "create_issue"`}, {Kind: RuleDeny, Expr: `jwt.act.sbo_product == "claude-code"`}}, false},
		{"erroring deny does not deny (missing claim)", []Rule{{Kind: RuleDeny, Expr: `jwt.nope.x == "y"`}, {Kind: RuleAllow, Expr: `mcp.tool.name == "create_issue"`}}, true},
		{"erroring allow does not allow", []Rule{{Kind: RuleAllow, Expr: `mcp.resource.name == "create_issue"`}, {Kind: RuleAllow, Expr: SentinelExpr}}, false},
		{"bare 'false' sentinel alone denies", []Rule{{Kind: RuleAllow, Expr: SentinelExpr}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, err := NewCELEvaluator(VServerRules{Rules: c.rules})
			if err != nil {
				t.Fatal(err)
			}
			got, why := ev.Allowed(act)
			if got != c.want {
				t.Fatalf("allowed=%v (%s), want %v", got, why, c.want)
			}
		})
	}
}

func TestValidateCELRefusesMalformedRules(t *testing.T) {
	bad := CELRuleSet{VServers: []VServerRules{{VServerID: "x", Rules: []Rule{{Kind: RuleAllow, Expr: `mcp.tool.name == `}}}}}
	if err := ValidateCEL(bad); err == nil {
		t.Fatal("malformed CEL validated")
	}
	good, _ := CompileCEL(goldenSpec(), 0)
	if err := ValidateCEL(good); err != nil {
		t.Fatal(err)
	}
}

// TestEveryVServerGetsInvariantsAndSentinel: a vserver with no grant is
// default-deny, never allow-all.
func TestEveryVServerGetsInvariantsAndSentinel(t *testing.T) {
	spec := goldenSpec()
	spec.Registry.VServers = append(spec.Registry.VServers, VServer{ID: "vs-empty", Slug: "empty", SenderConstraint: "dpop"})
	set, err := CompileCEL(spec, 0)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := set.ByVServer("vs-empty")
	if len(v.Rules) != 3 || v.Rules[0].Kind != RuleRequire || v.Rules[1].Kind != RuleRequire || v.Rules[2].Expr != SentinelExpr {
		t.Fatalf("rules = %+v", v.Rules)
	}
	if !strings.Contains(v.Rules[1].Expr, `"https://mcp-gw.acme.superbased.app/mcp/empty"`) {
		t.Fatalf("audience not derived: %s", v.Rules[1].Expr)
	}
	canon, err := set.Canonical()
	if err != nil || !json.Valid(canon) {
		t.Fatalf("canonical: %v", err)
	}
}
