package mcpaccess

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// pinnedSpec is the golden registry with gh PINNED to an approved snapshot
// listing tools (the registry view of an approved server), an any-tool
// allow for attested claude-code and the typed delete_repo deny.
func pinnedSpec(snapshotID string, tools ...string) Spec {
	s := goldenSpec()
	s.Registry.PolicyGen = 42
	s.Registry.VServers = []VServer{{
		ID: "vs-gh", Slug: "gh", SenderConstraint: "bearer",
		Servers: []Server{{ID: "gh", Target: "gh", CredentialMode: "service", Snapshot: &ApprovedSnapshot{ID: snapshotID, Tools: tools}}},
	}}
	s.Grants = []Grant{
		{ID: "g-any", Ord: 1, Subject: Subject{Kind: SubjectProduct, Value: "claude-code"}, Resource: Resource{VServer: "vs-gh"}, Action: ActionCall, Effect: EffectAllow, Enabled: true},
		{ID: "g-deny-dr", Ord: 2, Subject: Subject{Kind: SubjectAny}, Resource: Resource{VServer: "vs-gh", Name: "delete_repo"}, Action: ActionCall, Effect: EffectDeny, Enabled: true},
	}
	return s
}

func pinnedInput(action Action, name string) EvalInput {
	return EvalInput{VServer: "vs-gh", Action: action, Name: name, Server: "gh", Principal: Principal{
		Issuer: "https://auth.acme.superbased.app", Org: "acme", Audience: []string{"https://mcp-gw.acme.superbased.app/mcp/gh"}, PolicyGen: 42,
		Subject: "u1", Product: "claude-code", ClientAttestation: "process_attested",
	}}
}

// simulateAgreed runs Simulate and asserts all four targets are applicable
// and agree.
func simulateAgreed(t *testing.T, spec Spec, in EvalInput) Simulation {
	t.Helper()
	sim, err := Simulate(spec, in, 0)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if len(sim.Targets) != 4 {
		t.Fatalf("targets = %+v", sim.Targets)
	}
	for _, tv := range sim.Targets {
		if !tv.Applicable {
			t.Fatalf("target %s not applicable: %+v", tv.Target, sim.Targets)
		}
	}
	if !sim.Agree {
		t.Fatalf("the four targets disagree: %+v", sim.Targets)
	}
	return sim
}

// TestSnapshotDriftLifecycle is the R9.8 proof over ALL FOUR targets: with
// gh pinned, an approved tool is allowed; under ALERT drift the upstream
// may advertise a new tool but the ACTIVE snapshot (and so the registry
// view, and so the spec) is unchanged, so the known tool keeps flowing and
// the newly-named one default-denies; adopting a snapshot that lists the
// new name moves it into the allowable set; a name still unlisted keeps
// denying. Adoption changes the compiled rule set (the publication is
// republished to pick it up); the ALERT observation did not.
func TestSnapshotDriftLifecycle(t *testing.T) {
	approved := pinnedSpec("snap-gh-1", "create_issue", "delete_repo")
	adopted := pinnedSpec("snap-gh-2", "create_issue", "delete_repo", "exfiltrate_repo")
	stages := []struct {
		name  string
		spec  Spec
		tool  string
		want  Effect
		grant string
	}{
		{"pinned: approved create_issue allowed", approved, "create_issue", EffectAllow, "g-any"},
		{"pinned: approved delete_repo hits the typed deny", approved, "delete_repo", EffectDeny, "g-deny-dr"},
		{"alert drift: the known tool keeps flowing (spec unchanged)", approved, "create_issue", EffectAllow, "g-any"},
		{"alert drift: the newly-named tool default-denies on every target", approved, "exfiltrate_repo", EffectDeny, ""},
		{"adopted: the new name is in the allowable set", adopted, "exfiltrate_repo", EffectAllow, "g-any"},
		{"adopted: a still-unlisted name keeps denying", adopted, "wipe_org", EffectDeny, ""},
	}
	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			sim := simulateAgreed(t, st.spec, pinnedInput(ActionCall, st.tool))
			if sim.Decision.Effect != st.want || sim.Decision.MatchedGrant != st.grant {
				t.Fatalf("decision = %+v, want %s/%q", sim.Decision, st.want, st.grant)
			}
			if HasErrors(sim.Problems) {
				t.Fatalf("problems %v", sim.Problems)
			}
		})
	}
	canon := func(s Spec) string {
		set, err := CompileCEL(s, 0)
		if err != nil {
			t.Fatal(err)
		}
		b, err := set.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if canon(approved) == canon(adopted) {
		t.Fatal("adoption must change the compiled rule set (the next reload picks it up)")
	}
	if canon(approved) != canon(pinnedSpec("snap-gh-1", "create_issue", "delete_repo")) {
		t.Fatal("an ALERT observation (same active snapshot) must not change the compiled rule set")
	}
	// A request naming a server that is not a member has no candidate and
	// denies on every target (the PDP data plane refuses it as a security
	// gate even earlier).
	rogue := pinnedInput(ActionCall, "create_issue")
	rogue.Server = "rogue"
	if sim := simulateAgreed(t, approved, rogue); !sim.Decision.Denied() || sim.Decision.MatchedGrant != "" {
		t.Fatalf("rogue server: %+v", sim.Decision)
	}
}

// TestSnapshotVisibilityFollowsApprovedSet: tools/list visibility (server
// unresolved, the PDP's catalogue path) hides a newly-named tool and a
// denied one, and shows the approved allowed ones.
func TestSnapshotVisibilityFollowsApprovedSet(t *testing.T) {
	fast, err := CompileFastPath(pinnedSpec("snap-gh-1", "create_issue", "delete_repo", "merge_pr"), 0)
	if err != nil {
		t.Fatal(err)
	}
	got := fast.Visible(pinnedInput(ActionCall, "").Principal, "vs-gh", ActionCall, "", []string{"create_issue", "exfiltrate_repo", "delete_repo", "merge_pr"})
	if strings.Join(got, ",") != "create_issue,merge_pr" {
		t.Fatalf("visible = %v", got)
	}
}

// TestSnapshotCELRendersExplicitAllowlist pins the CEL shape: an any-tool
// grant over a pinned member renders an explicit per-member allowlist
// conjunct (mcp.tool.target == T && mcp.tool.name in [...]) with the
// approved names sorted, a named grant keeps its equality and gains the
// target, no negation is ever emitted, an unpinned sibling member renders
// its own type-scoped disjunct, and cel-go agrees the unapproved name is
// denied.
func TestSnapshotCELRendersExplicitAllowlist(t *testing.T) {
	spec := pinnedSpec("snap-gh-1", "delete_repo", "create_issue")
	set, err := CompileCEL(spec, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCEL(set); err != nil {
		t.Fatal(err)
	}
	v, _ := set.ByVServer("vs-gh")
	if len(v.Rules) != 5 {
		t.Fatalf("rules = %+v", v.Rules)
	}
	allow, deny := v.Rules[2], v.Rules[3]
	wantAllow := `jwt.act.sbo_product == "claude-code" && jwt.act.sbo_client_attestation in ["process_attested","ipc_bound"] && (mcp.tool.target == "gh" && mcp.tool.name in ["create_issue","delete_repo"])`
	if allow.Kind != RuleAllow || allow.Expr != wantAllow {
		t.Fatalf("allow = %s %q\nwant %q", allow.Kind, allow.Expr, wantAllow)
	}
	if deny.Kind != RuleDeny || deny.Expr != `mcp.tool.name == "delete_repo" && mcp.tool.target == "gh"` {
		t.Fatalf("deny = %s %q", deny.Kind, deny.Expr)
	}
	for _, r := range v.Rules {
		if strings.Contains(r.Expr, "!(") || strings.Contains(r.Expr, "!mcp") || strings.Contains(r.Expr, "!jwt") {
			t.Fatalf("negation rendered: %q", r.Expr)
		}
	}
	for tool, want := range map[string]bool{"create_issue": true, "exfiltrate_repo": false, "delete_repo": false} {
		allowed, why, ok, err := EvaluateCEL(set, pinnedInput(ActionCall, tool))
		if err != nil || !ok || allowed != want {
			t.Fatalf("%s: allowed=%v ok=%v err=%v (%s)", tool, allowed, ok, err, why)
		}
	}

	// A mixed vserver: the pinned member gets the allowlist, the unpinned
	// sibling its type-scoped disjunct; the named deny lists both targets.
	mixed := spec
	mixed.Registry.VServers = []VServer{{ID: "vs-gh", Slug: "gh", SenderConstraint: "bearer", Servers: []Server{
		{ID: "gh", Target: "gh", Snapshot: &ApprovedSnapshot{ID: "snap-gh-1", Tools: []string{"create_issue", "delete_repo"}}},
		// Registry-shaped id: the CEL names it by its agentgateway target
		// name, TargetName("gh_ent") = "gh-ent".
		{ID: "gh_ent", Target: "gh_ent"},
	}}}
	mset, err := CompileCEL(mixed, 0)
	if err != nil {
		t.Fatal(err)
	}
	mv, _ := mset.ByVServer("vs-gh")
	if !strings.HasSuffix(mv.Rules[2].Expr, `((mcp.tool.target == "gh" && mcp.tool.name in ["create_issue","delete_repo"]) || (mcp.tool.target == "gh-ent" && mcp.tool.name != ""))`) {
		t.Fatalf("mixed allow = %q", mv.Rules[2].Expr)
	}
	if mv.Rules[3].Expr != `mcp.tool.name == "delete_repo" && (mcp.tool.target == "gh" || mcp.tool.target == "gh-ent")` {
		t.Fatalf("mixed deny = %q", mv.Rules[3].Expr)
	}
	in := pinnedInput(ActionCall, "exfiltrate_repo")
	in.Server = "gh_ent"
	if sim := simulateAgreed(t, mixed, in); sim.Decision.Effect != EffectAllow {
		t.Fatalf("unpinned member must enforce nothing: %+v", sim.Decision)
	}
}

// TestSnapshotUnmatchableGrants: a pinned member with an EMPTY approved set
// and a named grant outside the approved set both render the always-false
// literal and never match; the named case is reported as a
// unapproved_tool_name WARN (compiles, cannot match until adopted).
func TestSnapshotUnmatchableGrants(t *testing.T) {
	empty := pinnedSpec("snap-gh-0")
	set, err := CompileCEL(empty, 0)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := set.ByVServer("vs-gh")
	// The subject conjuncts stay in front; the resource part is the
	// always-false literal, so the rule can never match.
	if !strings.HasSuffix(v.Rules[2].Expr, " && "+SentinelExpr) || v.Rules[3].Expr != SentinelExpr {
		t.Fatalf("empty approved set must render unmatchable rules: %+v", v.Rules)
	}
	if sim := simulateAgreed(t, empty, pinnedInput(ActionCall, "create_issue")); !sim.Decision.Denied() || sim.Decision.MatchedGrant != "" {
		t.Fatalf("decision = %+v", sim.Decision)
	}

	named := pinnedSpec("snap-gh-1", "create_issue", "delete_repo")
	named.Grants = append(named.Grants, Grant{
		ID: "g-unadopted", Ord: 3, Subject: Subject{Kind: SubjectAny},
		Resource: Resource{VServer: "vs-gh", Server: "gh", Name: "exfiltrate_repo"}, Action: ActionCall, Effect: EffectAllow, Enabled: true,
	})
	ps := Lint(named, 0)
	if HasErrors(ps) || !Has(ps, CodeUnapprovedToolName) {
		t.Fatalf("problems = %v", ps)
	}
	for _, p := range ps {
		if p.Code == CodeUnapprovedToolName && (p.GrantID != "g-unadopted" || p.Severity != SeverityWarn) {
			t.Fatalf("warn on the wrong grant: %+v", p)
		}
	}
	nset, _ := CompileCEL(named, 0)
	nv, _ := nset.ByVServer("vs-gh")
	if nv.Rules[3].GrantID != "g-unadopted" || nv.Rules[3].Expr != SentinelExpr {
		t.Fatalf("unadopted rule = %+v", nv.Rules[3])
	}
	if sim := simulateAgreed(t, named, pinnedInput(ActionCall, "exfiltrate_repo")); !sim.Decision.Denied() || sim.Decision.MatchedGrant != "" {
		t.Fatalf("decision = %+v", sim.Decision)
	}
	// Adoption lifts the WARN.
	named.Registry.VServers[0].Servers[0].Snapshot = &ApprovedSnapshot{ID: "snap-gh-2", Tools: []string{"create_issue", "delete_repo", "exfiltrate_repo"}}
	if ps := Lint(named, 0); Has(ps, CodeUnapprovedToolName) {
		t.Fatalf("warn survives adoption: %v", ps)
	}
}

// TestTaskActionGrantsRefusedByAllCompilers: a grant on tasks/get,
// tasks/update or tasks/cancel is a typed feature_unavailable ERROR from
// every compiler (CEL, node table, AuthZEN, fast path, Simulate) with a
// message that names the A2 front's native task path; a task REQUEST with
// no grant still evaluates (default-deny) on every target.
func TestTaskActionGrantsRefusedByAllCompilers(t *testing.T) {
	for _, a := range []Action{ActionTasksGet, ActionTasksUpdate, ActionTasksCancel} {
		t.Run(string(a), func(t *testing.T) {
			s := goldenSpec()
			s.Grants[0].Action, s.Grants[0].Resource.Name = a, "task-1"
			assertAllCompilersRefuse(t, s, CodeFeatureUnavailable)
			var le *LintError
			_, err := CompileCEL(s, 0)
			if !errors.As(err, &le) {
				t.Fatal(err)
			}
			var msg string
			for _, p := range le.Problems {
				if p.Code == CodeFeatureUnavailable && p.GrantID == "g1" {
					msg = p.Message
				}
			}
			for _, want := range []string{string(a), "A2 front", "method_name None", "R8.30.g", "default-den"} {
				if !strings.Contains(msg, want) {
					t.Fatalf("message lacks %q: %s", want, msg)
				}
			}
			if !CELUngrantable(a) || !CELApplicable(a) {
				t.Fatalf("capability table: ungrantable=%v applicable=%v", CELUngrantable(a), CELApplicable(a))
			}
		})
	}
	sim := simulateAgreed(t, goldenSpec(), EvalInput{
		VServer: "vs-gh", Action: ActionTasksCancel, Name: "task-1", Server: "gh",
		Principal: pinnedInput(ActionCall, "").Principal,
	})
	if !sim.Decision.Denied() || sim.Decision.EffectClass != "tasks" {
		t.Fatalf("task request must default-deny: %+v", sim.Decision)
	}
}

// TestCELTaskObjectCarriesNoMethodDiscriminator documents WHY task grants
// are refused: the agentgateway CEL context for a task request is
// mcp.task{target,name} (crates/agentgateway/src/mcp/mod.rs
// MCPInfo::from(&ResourceType) leaves method_name None) and every task
// method builds the identical resource, so the activations for tasks/get,
// tasks/update and tasks/cancel are indistinguishable and one rule matches
// all three.
func TestCELTaskObjectCarriesNoMethodDiscriminator(t *testing.T) {
	get := Activation(EvalInput{VServer: "vs-gh", Action: ActionTasksGet, Name: "task-1", Server: "gh"})
	update := Activation(EvalInput{VServer: "vs-gh", Action: ActionTasksUpdate, Name: "task-1", Server: "gh"})
	cancel := Activation(EvalInput{VServer: "vs-gh", Action: ActionTasksCancel, Name: "task-1", Server: "gh"})
	if !reflect.DeepEqual(get, update) || !reflect.DeepEqual(get, cancel) {
		t.Fatalf("task activations differ:\nget=%v\nupdate=%v\ncancel=%v", get, update, cancel)
	}
	if _, ok := get["mcp"].(map[string]any)["task"]; !ok {
		t.Fatalf("no mcp.task object: %v", get)
	}
	ev, err := NewCELEvaluator(VServerRules{Rules: []Rule{{Kind: RuleAllow, Expr: `mcp.task.name == "task-1"`}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, act := range map[string]map[string]any{"tasks/get": get, "tasks/update": update, "tasks/cancel": cancel} {
		if ok, why := ev.Allowed(act); !ok {
			t.Fatalf("%s: a task-name-only rule must match every task method (%s)", name, why)
		}
	}
}
