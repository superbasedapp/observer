package mcpaccess

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestValidTargetNameMatchesAgentgateway pins ValidTargetName to the pinned
// agentgateway v1.5.0's own validate_mcp_target_name test vectors
// (crates/agentgateway/src/types/agent.rs, the four
// validate_mcp_target_name_* tests) plus the live-defect id.
func TestValidTargetNameMatchesAgentgateway(t *testing.T) {
	for _, c := range []struct {
		name string
		ok   bool
	}{
		// accepts_section_name_compliant (verbatim)
		{"time", true},
		{"everything", true},
		{"my-target", true},
		{"svc.ns", true},
		{"a", true},
		{"a1", true},
		{"123", true},
		{"a-b.c-d", true},
		{"a.b.c", true},
		// rejects_reserved_delimiters (verbatim)
		{"bad+name", false},
		{"+leading", false},
		{"trailing+", false},
		{"foo_bar", false},
		{"_lead", false},
		{"trail_", false},
		// rejects_invalid_section_name_shapes (verbatim)
		{"", false},
		{"Foo", false},
		{"foo!", false},
		{"-leading", false},
		{"trailing-", false},
		{".leading", false},
		{"trailing.", false},
		{"a..b", false},
		{"a/b", false},
		{"a b", false},
		// the regex's label rule beyond the vectors, and the live ids
		{"a.-b", false},
		{"a-.b", false},
		{"srv_303c8f9ab45f0015", false},
		{"srv-303c8f9ab45f0015", true},
		// enforces_max_length
		{strings.Repeat("a", MaxTargetNameLen), true},
		{strings.Repeat("a", MaxTargetNameLen+1), false},
	} {
		if got := ValidTargetName(c.name); got != c.ok {
			t.Errorf("ValidTargetName(%q) = %v, want %v", c.name, got, c.ok)
		}
	}
}

func TestTargetName(t *testing.T) {
	long := strings.Repeat("a", MaxTargetNameLen)
	for _, c := range []struct {
		name, id, want string
		err            bool
	}{
		{"registry id srv_<16 hex> (the live defect)", "srv_303c8f9ab45f0015", "srv-303c8f9ab45f0015", false},
		{"registry fallback id srv_<hex nanos>", "srv_18a2b3c4d5e6f708", "srv-18a2b3c4d5e6f708", false},
		{"already a target name, no '_'", "github", "github", false},
		{"dots survive", "io.acme.gh", "io.acme.gh", false},
		{"'_' and '.' together", "srv_a.b_c", "srv-a.b-c", false},
		{"digits only", "0123", "0123", false},
		{"plain id at the max length", long, long, false},
		// ESCAPED: '-', upper case, "__", other bytes, a plain-alphabet id
		// whose image is not a valid name.
		{"id with '-' (a target name, but the plain image of srv_gh)", "srv-gh", "x--" + b32("srv-gh"), false},
		{"upper case is not folded", "SRV_ABC", "x--" + b32("SRV_ABC"), false},
		{"double underscore", "srv__a", "x--" + b32("srv__a"), false},
		{"leading underscore", "_srv", "x--" + b32("_srv"), false},
		{"trailing underscore", "srv_", "x--" + b32("srv_"), false},
		{"dot next to underscore", "a._b", "x--" + b32("a._b"), false},
		{"plus", "a+b", "x--" + b32("a+b"), false},
		{"slash and space", "a/b c", "x--" + b32("a/b c"), false},
		{"non-ASCII", "sérvér", "x--" + b32("sérvér"), false},
		{"escaped at the length edge (156 bytes)", strings.Repeat("-", 156), "x--" + b32(strings.Repeat("-", 156)), false},
		{"escaped over the length edge (157 bytes)", strings.Repeat("-", 157), "", true},
		{"plain id over the max length", long + "a", "x--" + b32(long+"a"), true},
		{"empty", "", "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := TargetName(c.id)
			if c.err {
				if err == nil || !errors.Is(err, ErrNoTargetName) {
					t.Fatalf("TargetName(%q) = %q, %v; want ErrNoTargetName", c.id, got, err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("TargetName(%q) = %q, %v; want %q", c.id, got, err, c.want)
			}
			if !ValidTargetName(got) {
				t.Fatalf("TargetName(%q) = %q is not a valid agentgateway target name", c.id, got)
			}
		})
	}
}

func b32(s string) string { return strings.ToLower(targetB32.EncodeToString([]byte(s))) }

// TestTargetNameNeverCollides is the injectivity property over the id
// shapes that meet in one vserver: every registry-shaped id, its '-' twin,
// case variants, "__" variants and the escaped form's own spelling map to
// DISTINCT valid names - the collision attempts (srv_a vs srv-a, x--<b32>
// spelled as an id) do not collide.
func TestTargetNameNeverCollides(t *testing.T) {
	ids := []string{
		"srv_303c8f9ab45f0015", "srv-303c8f9ab45f0015", "SRV_303C8F9AB45F0015", "srv__303c8f9ab45f0015",
		"srv_a", "srv-a", "srv.a", "srv__a", "srv_a_", "srv_a.b", "srv-a.b",
		"github", "gh", "g_h", "g-h", "g__h", "echo", "x", "x--",
		"x--" + b32("srv-a"), // the escaped name of srv-a, used as an id itself
		"x__" + b32("srv-a"), // its '_' spelling (plain-domain-shaped, but "__")
		"x_" + b32("srv-a"),  // plain: maps to x-<...>, one '-'
	}
	for i := 0; i < 64; i++ {
		ids = append(ids, fmt.Sprintf("srv_%016x", 0x303c8f9ab45f0000+i), fmt.Sprintf("srv-%016x", 0x303c8f9ab45f0000+i))
	}
	seen := map[string]string{}
	for _, id := range ids {
		name, err := TargetName(id)
		if err != nil {
			t.Fatalf("TargetName(%q): %v", id, err)
		}
		if !ValidTargetName(name) {
			t.Fatalf("TargetName(%q) = %q is invalid", id, name)
		}
		if prev, dup := seen[name]; dup && prev != id {
			t.Fatalf("collision: %q and %q both map to %q", prev, id, name)
		}
		seen[name] = id
	}
}

// TestCELTargetLiteralIsTheHopTargetName: a vserver whose member is a
// registry-shaped srv_<hex> server (Target = the id, as regstore.RegistryView
// renders it) compiles `mcp.tool.target == "<TargetName(id)>"` - the name
// the A2 hop gives the target, never the raw id agentgateway refuses - on
// both the server-scoped path (grantExpr) and the snapshot-scoped path
// (snapshotExpr), and the CEL evaluator (whose activation reports the same
// mapping) agrees with the PDP targets on a call resolved to that server.
func TestCELTargetLiteralIsTheHopTargetName(t *testing.T) {
	const id, other = "srv_303c8f9ab45f0015", "srv_0000000000000001"
	hopName, err := TargetName(id)
	if err != nil {
		t.Fatal(err)
	}
	literal := `mcp.tool.target == "` + hopName + `"`
	princ := Principal{Issuer: "https://auth.acme.superbased.app", Org: "acme", Audience: []string{"https://mcp-gw.acme.superbased.app/mcp/gh"}, PolicyGen: 41, Product: "claude-code"}
	for _, c := range []struct {
		name string
		pin  *ApprovedSnapshot
	}{
		{"server-scoped grant (grantExpr)", nil},
		{"snapshot-pinned member (snapshotExpr)", &ApprovedSnapshot{ID: "sn1", Tools: []string{"create_issue"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			spec := Spec{
				Registry: Registry{
					Issuer: "https://auth.acme.superbased.app", Org: "acme", GatewayBaseURI: "https://mcp-gw.acme.superbased.app", PolicyGen: 41,
					VServers: []VServer{{ID: "vs-gh", Slug: "gh", SenderConstraint: "bearer", Servers: []Server{
						{ID: id, Target: id, CredentialMode: "service", Snapshot: c.pin},
						{ID: other, Target: other, CredentialMode: "service"},
					}}},
				},
				Grants: []Grant{{
					ID: "g1", Ord: 1, Subject: Subject{Kind: SubjectAny}, Resource: Resource{VServer: "vs-gh", Server: id, Name: "create_issue"},
					Action: ActionCall, Effect: EffectAllow, Enabled: true,
				}},
			}
			set, err := CompileCEL(spec, 0)
			if err != nil {
				t.Fatal(err)
			}
			v, _ := set.ByVServer("vs-gh")
			var hit bool
			for _, r := range v.Rules {
				if strings.Contains(r.Expr, id) {
					t.Fatalf("a rule carries the raw id agentgateway refuses: %s", r.Expr)
				}
				hit = hit || (r.GrantID == "g1" && strings.Contains(r.Expr, literal))
			}
			if !hit {
				t.Fatalf("no g1 rule compares %s:\n%s", literal, RenderYAML(v, 0))
			}
			for _, e := range []struct {
				server string
				denied bool
			}{{id, false}, {other, true}} {
				sim, err := Simulate(spec, EvalInput{Principal: princ, VServer: "vs-gh", Action: ActionCall, Server: e.server, Name: "create_issue"}, 0)
				if err != nil {
					t.Fatal(err)
				}
				if !sim.Agree || sim.Decision.Denied() != e.denied {
					t.Fatalf("server %s: agree=%v denied=%v (want %v): %+v", e.server, sim.Agree, sim.Decision.Denied(), e.denied, sim.Targets)
				}
			}
		})
	}
}
