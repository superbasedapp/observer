package localpdp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
	famcp "github.com/marmutapp/superbased-observer/internal/policyfam/mcpaccess"
)

// CorpusDir is the Lane B conformance corpus (internal/mcpaccess/testdata/
// corpus) the node PDP's verdicts are pinned against.
const corpusDir = "../../mcpaccess/testdata/corpus"

type corpusFile struct {
	Name              string              `json:"name"`
	Spec              mcpaccess.Spec      `json:"spec"`
	PrincipalDefaults mcpaccess.Principal `json:"principal_defaults"`
	Rows              []corpusRow         `json:"rows"`
}

type corpusRow struct {
	Name      string              `json:"name"`
	Principal json.RawMessage     `json:"principal,omitempty"`
	Input     mcpaccess.EvalInput `json:"input"`
	Want      mcpaccess.Effect    `json:"want"`
	WantGrant string              `json:"want_grant,omitempty"`
}

func (r corpusRow) principal(t *testing.T, def mcpaccess.Principal) mcpaccess.Principal {
	t.Helper()
	p := def
	p.Audience = append([]string(nil), def.Audience...)
	p.Groups = append([]string(nil), def.Groups...)
	if len(r.Principal) == 0 {
		return p
	}
	if err := json.Unmarshal(r.Principal, &p); err != nil {
		t.Fatalf("row %q principal: %v", r.Name, err)
	}
	var probe map[string]json.RawMessage
	_ = json.Unmarshal(r.Principal, &probe)
	if raw, ok := probe["groups"]; ok && string(raw) == "[]" {
		p.Groups = nil
	}
	return p
}

func loadCorpus(t *testing.T) []corpusFile {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(corpusDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("corpus glob: %v (%d files)", err, len(files))
	}
	var out []corpusFile
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c corpusFile
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, c)
	}
	return out
}

// transportProving is the reverse of the attestation table: the transport
// that proves an attestation, so a corpus principal's claimed attestation is
// the effective one.
func transportProving(att string) Transport {
	for _, row := range transportAttestation {
		if row.attestation == att {
			return row.transport
		}
	}
	return TransportUnknown
}

// methodFor maps a corpus action onto a request the engine dispatches.
func methodFor(in mcpaccess.EvalInput) (method string, tool string, params json.RawMessage) {
	switch in.Action {
	case mcpaccess.ActionCall:
		return "tools/call", in.Name, nil
	case mcpaccess.ActionRead:
		return "resources/read", "", json.RawMessage(`{"uri":` + strconvQuote(in.Name) + `}`)
	case mcpaccess.ActionList:
		return "tools/list", "", nil
	case mcpaccess.ActionDiscover:
		return "ping", "", nil
	case mcpaccess.ActionSubscribe:
		return "resources/subscribe", "", json.RawMessage(`{"uri":` + strconvQuote(in.Name) + `}`)
	case mcpaccess.ActionTasksGet:
		return "tasks/get", "", nil
	case mcpaccess.ActionTasksUpdate:
		return "tasks/update", "", nil
	case mcpaccess.ActionTasksCancel:
		return "tasks/cancel", "", nil
	}
	return "", "", nil
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func principalFrom(p mcpaccess.Principal) Principal {
	return Principal{
		Issuer: p.Issuer, Org: p.Org, Audience: p.Audience, PolicyGen: p.PolicyGen,
		Subject: p.Subject, ClientID: p.ClientID, Product: p.Product, AgentKind: p.AgentKind,
		Env: p.Env, Workspace: p.Workspace, Groups: p.Groups, CredAssurance: p.CredAssurance,
		ClientAttestation: p.ClientAttestation, Transport: transportProving(p.ClientAttestation),
		TeamIDs: p.TeamIDs, TeamsKnown: p.TeamsKnown, ProjectHash: p.ProjectHash, TeamsOverflow: p.TeamsOverflow,
	}
}

func compileEnforce(t *testing.T, spec mcpaccess.Spec) *Engine {
	t.Helper()
	tbl, err := Compile(famcp.PolicySpec{Mode: famcp.ModeEnforce, Spec: spec}, Meta{Version: 3, BodyHash: "h", EnforceAllowed: true}, 0)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	h := &Holder{}
	h.Swap(tbl)
	return &Engine{Tables: h}
}

// TestCorpusVerdictsMatchSimulate pins the node PDP to mcpaccess.Simulate on
// the Lane B corpus: same effect and same attributed grant on every row, a
// resources/read name resolved from params exactly as the gateway resolves
// it, tasks/* rows stripped (never a policy verdict), and in enforce mode
// the verdict is deny exactly when the effect is not allow.
func TestCorpusVerdictsMatchSimulate(t *testing.T) {
	ctx := context.Background()
	for _, c := range loadCorpus(t) {
		t.Run(c.Name, func(t *testing.T) {
			eng := compileEnforce(t, c.Spec)
			for _, row := range c.Rows {
				t.Run(row.Name, func(t *testing.T) {
					in := row.Input
					in.Principal = row.principal(t, c.PrincipalDefaults)
					method, tool, params := methodFor(in)
					if method == "" {
						t.Fatalf("no method for action %q", in.Action)
					}
					req := Request{VServerID: in.VServer, Method: method, Tool: tool, Params: params, Server: in.Server, Principal: principalFrom(in.Principal)}
					d := eng.CheckRequest(ctx, req)
					if _, _, stripped, _ := MethodClass(method); stripped {
						if d.Verdict != VerdictError || !d.Stripped || d.Error == nil || d.Error.Code != CodeMethodNotFound {
							t.Fatalf("stripped method %s: got %+v", method, d)
						}
						return
					}
					if _, known := c.Spec.Registry.VServerByID(in.VServer); !known {
						// A vserver the table does not know is a NON-policy
						// refusal on the node (as on the gateway): blocks in
						// both modes, never a would-deny.
						if d.Verdict != VerdictError || d.Error == nil || d.Error.Code != CodeForbidden {
							t.Fatalf("unknown vserver: got %+v", d)
						}
						return
					}
					simIn := in
					if d.DecisionClass == ClassCatalogue {
						simIn.Name = ""
					}
					sim, err := mcpaccess.Simulate(c.Spec, simIn, 0)
					if err != nil {
						t.Fatalf("Simulate: %v", err)
					}
					if d.Effect != string(sim.Decision.Effect) || d.MatchedGrant != sim.Decision.MatchedGrant {
						t.Fatalf("node pdp effect/grant %s/%q, Simulate %s/%q (%s)", d.Effect, d.MatchedGrant, sim.Decision.Effect, sim.Decision.MatchedGrant, d.Reason)
					}
					if d.DecisionClass != ClassCatalogue && d.Effect != string(row.Want) {
						t.Fatalf("effect %s, want %s", d.Effect, row.Want)
					}
					if d.Attestation != in.Principal.ClientAttestation && in.Principal.ClientAttestation != "" {
						t.Fatalf("attestation %q, want %q", d.Attestation, in.Principal.ClientAttestation)
					}
					wantDeny := d.Effect != string(mcpaccess.EffectAllow)
					if (d.Verdict == VerdictDeny) != wantDeny || d.WouldDeny {
						t.Fatalf("enforce verdict %s (would_deny=%v) for effect %s", d.Verdict, d.WouldDeny, d.Effect)
					}
					if d.Effect == string(mcpaccess.EffectAsk) && !d.Ask() {
						t.Fatal("ask effect must report Ask()")
					}
				})
			}
		})
	}
}

// productSpec is a one-grant registry: product claude-code may call
// create_issue on vs-gh.
func productSpec() mcpaccess.Spec {
	return mcpaccess.Spec{
		Registry: mcpaccess.Registry{
			Issuer: "https://auth", Org: "acme", GatewayBaseURI: "https://gw", PolicyGen: 1,
			VServers: []mcpaccess.VServer{{ID: "vs-gh", Slug: "gh", SenderConstraint: "bearer", Servers: []mcpaccess.Server{{ID: "gh", Target: "gh", CredentialMode: "service"}}}},
		},
		Grants: []mcpaccess.Grant{
			{
				ID: "g-prod", Ord: 1, Subject: mcpaccess.Subject{Kind: mcpaccess.SubjectProduct, Value: "claude-code"},
				Resource: mcpaccess.Resource{VServer: "vs-gh", Name: "create_issue"}, Action: mcpaccess.ActionCall, Effect: mcpaccess.EffectAllow, Enabled: true,
			},
			{
				ID: "g-any-ask", Ord: 2, Subject: mcpaccess.Subject{Kind: mcpaccess.SubjectAny},
				Resource: mcpaccess.Resource{VServer: "vs-gh", Name: "force_push"}, Action: mcpaccess.ActionCall, Effect: mcpaccess.EffectAsk, Enabled: true, AuditClass: "strict",
			},
		},
	}
}

func nodeReq(t *testing.T, tbl *Table, transport Transport, claimed, tool string) Request {
	t.Helper()
	p, ok := tbl.NodePrincipal(NodeIdentity{Subject: "dev-1", Product: "claude-code", ClientID: "agent:claude-code"}, "vs-gh", transport)
	if !ok {
		t.Fatal("NodePrincipal: unknown vserver")
	}
	p.ClientAttestation = claimed
	return Request{VServerID: "vs-gh", Method: "tools/call", Tool: tool, Server: "gh", Principal: p}
}

// TestProductScopedGrantAttestationGate is the R2 gate as a table: a
// product-scoped grant is honoured only when the transport proves
// process_attested / ipc_bound, and a self-claimed attestation never raises
// what the transport proved.
func TestProductScopedGrantAttestationGate(t *testing.T) {
	eng := compileEnforce(t, productSpec())
	tbl := eng.Tables.Current()
	cases := []struct {
		name      string
		transport Transport
		claimed   string
		wantPass  bool
		wantAtt   string
	}{
		{"stdio wrapper honours product grant", TransportStdioWrapper, "", true, AttestProcess},
		{"ipc honours product grant", TransportIPC, "", true, AttestIPC},
		{"loopback http is configured: product grant not honoured", TransportLoopbackHTTP, "", false, AttestConfigured},
		{"unknown transport is claimed: not honoured", TransportUnknown, "", false, AttestClaimed},
		{"loopback claiming process_attested stays configured", TransportLoopbackHTTP, AttestProcess, false, AttestConfigured},
		{"stdio with a configured token claim lowers", TransportStdioWrapper, AttestConfigured, false, AttestConfigured},
		{"stdio with an ipc token claim still honoured", TransportStdioWrapper, AttestIPC, true, AttestIPC},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := eng.CheckRequest(context.Background(), nodeReq(t, tbl, c.transport, c.claimed, "create_issue"))
			if d.Attestation != c.wantAtt {
				t.Fatalf("attestation %q, want %q", d.Attestation, c.wantAtt)
			}
			if d.Forwardable() != c.wantPass {
				t.Fatalf("forwardable=%v, want %v (%s)", d.Forwardable(), c.wantPass, d.Reason)
			}
			if c.wantPass && d.MatchedGrant != "g-prod" {
				t.Fatalf("matched %q, want g-prod", d.MatchedGrant)
			}
			if !c.wantPass && (d.Error == nil || d.Error.Code != CodeForbidden) {
				t.Fatalf("deny must carry -32003: %+v", d.Error)
			}
		})
	}
}

// TestEngineRefusalsBlockInBothModes: unknown method, stripped tasks, no
// table, unknown vserver and a missing name are NON-policy refusals that
// block in observe mode too (R8.27.h).
func TestEngineRefusalsBlockInBothModes(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []famcp.PolicySpec{{Mode: famcp.ModeObserve, Spec: productSpec()}, {Mode: famcp.ModeEnforce, Spec: productSpec()}} {
		tbl, err := Compile(mode, Meta{EnforceAllowed: true}, 0)
		if err != nil {
			t.Fatal(err)
		}
		h := &Holder{}
		h.Swap(tbl)
		eng := &Engine{Tables: h}
		good := nodeReq(t, tbl, TransportStdioWrapper, "", "create_issue")
		cases := []struct {
			name string
			mut  func(r *Request)
			code int
		}{
			{"unknown method", func(r *Request) { r.Method = "tools/execute" }, CodeMethodNotFound},
			{"stripped tasks/get", func(r *Request) { r.Method = "tasks/get" }, CodeMethodNotFound},
			{"unknown vserver", func(r *Request) { r.VServerID = "vs-nope" }, CodeForbidden},
			{"name required", func(r *Request) { r.Tool = ""; r.Params = nil }, CodeInvalidParams},
			{"malformed params", func(r *Request) { r.Tool = ""; r.Params = json.RawMessage(`{"name":`) }, CodeInvalidParams},
		}
		for _, c := range cases {
			t.Run(mode.Mode+"/"+c.name, func(t *testing.T) {
				r := good
				c.mut(&r)
				d := eng.CheckRequest(ctx, r)
				if d.Verdict != VerdictError || d.Error == nil || d.Error.Code != c.code || d.WouldDeny {
					t.Fatalf("got %+v", d)
				}
			})
		}
		if d := eng.CheckRequest(ctx, good); !d.Forwardable() {
			t.Fatalf("%s: good request refused: %s", mode.Mode, d.Reason)
		}
	}
	empty := &Engine{Tables: &Holder{}}
	d := empty.CheckRequest(ctx, Request{VServerID: "vs-gh", Method: "tools/call", Tool: "x"})
	if d.Verdict != VerdictError || d.Error.Code != CodeUnavailable {
		t.Fatalf("no table must be unavailable: %+v", d)
	}
	var nilEngine Engine
	if d := nilEngine.CheckRequest(ctx, Request{Method: "ping", VServerID: "vs-gh"}); d.Verdict != VerdictError {
		t.Fatalf("nil holder must refuse: %+v", d)
	}
}

// TestObserveModeWouldDenyForwards: in observe mode a policy deny/ask is
// recorded as would-deny and the call still forwards; ask in enforce mode
// renders approval_required; strict audit follows the grant's audit_class.
func TestObserveModeWouldDenyForwards(t *testing.T) {
	ctx := context.Background()
	obs, err := Compile(famcp.PolicySpec{Mode: famcp.ModeObserve, Spec: productSpec()}, Meta{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	h := &Holder{}
	h.Swap(obs)
	eng := &Engine{Tables: h}
	d := eng.CheckRequest(ctx, nodeReq(t, obs, TransportLoopbackHTTP, "", "create_issue"))
	if !d.Forwardable() || !d.WouldDeny || d.Mode != ModeObserve || d.Error != nil {
		t.Fatalf("observe would-deny: %+v", d)
	}
	d = eng.CheckRequest(ctx, nodeReq(t, obs, TransportStdioWrapper, "", "force_push"))
	if !d.Forwardable() || !d.WouldDeny || !d.StrictAudit || d.MatchedGrant != "g-any-ask" {
		t.Fatalf("observe ask: %+v", d)
	}
	// Enforce requested but not preauthorized => observe.
	inert, err := Compile(famcp.PolicySpec{Mode: famcp.ModeEnforce, Spec: productSpec()}, Meta{EnforceAllowed: false}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if inert.Mode != ModeObserve {
		t.Fatalf("inert table mode %s, want observe", inert.Mode)
	}
	enf := compileEnforce(t, productSpec())
	d = enf.CheckRequest(ctx, nodeReq(t, enf.Tables.Current(), TransportStdioWrapper, "", "force_push"))
	if d.Verdict != VerdictDeny || !d.Ask() || d.Error == nil || d.Error.Code != CodeApprovalRequired || !d.StrictAudit {
		t.Fatalf("enforce ask: %+v", d)
	}
	if d.PolicyVersion != 3 || d.PolicyHash != "h" || d.PolicyGen != 1 {
		t.Fatalf("policy identity not stamped: %+v", d)
	}
}

// TestFilterCatalogue: enforce filters to allow/ask names; observe returns
// everything; no table returns none; non-catalogue returns nil.
func TestFilterCatalogue(t *testing.T) {
	enf := compileEnforce(t, productSpec())
	tbl := enf.Tables.Current()
	req := nodeReq(t, tbl, TransportStdioWrapper, "", "")
	req.Method = "tools/list"
	names := []string{"create_issue", "force_push", "delete_repo"}
	got := enf.Filter(req, names)
	if len(got) != 2 || got[0] != "create_issue" || got[1] != "force_push" {
		t.Fatalf("enforce visible %v", got)
	}
	req.Principal.Transport = TransportLoopbackHTTP
	if got := enf.Filter(req, names); len(got) != 1 || got[0] != "force_push" {
		t.Fatalf("loopback visible %v (product grant must not be honoured)", got)
	}
	obs, _ := Compile(famcp.PolicySpec{Mode: famcp.ModeObserve, Spec: productSpec()}, Meta{}, 0)
	h := &Holder{}
	h.Swap(obs)
	if got := (&Engine{Tables: h}).Filter(req, names); len(got) != 3 {
		t.Fatalf("observe must not filter: %v", got)
	}
	if got := (&Engine{Tables: &Holder{}}).Filter(req, names); got == nil || len(got) != 0 {
		t.Fatalf("no table must hide everything: %v", got)
	}
	req.Method = "tools/call"
	if got := enf.Filter(req, names); got != nil {
		t.Fatalf("non-catalogue must be nil: %v", got)
	}
}

// TestNodePrincipalUnknownVServer: NodePrincipal reports ok=false rather
// than fabricating an audience.
func TestNodePrincipalUnknownVServer(t *testing.T) {
	eng := compileEnforce(t, productSpec())
	if _, ok := eng.Tables.Current().NodePrincipal(NodeIdentity{Subject: "x"}, "vs-nope", TransportIPC); ok {
		t.Fatal("unknown vserver must not yield a principal")
	}
	p, _ := eng.Tables.Current().NodePrincipal(NodeIdentity{Subject: "x"}, "vs-gh", TransportIPC)
	if p.CredAssurance != "node_enrolled" || p.Audience[0] != "https://gw/mcp/gh" || p.ClientAttestation != AttestIPC {
		t.Fatalf("principal %+v", p)
	}
}
