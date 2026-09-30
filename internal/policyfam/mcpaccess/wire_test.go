package mcpaccess

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	core "github.com/marmutapp/superbased-observer/internal/mcpaccess"
)

const registryJSON = `{"issuer":"https://auth.acme.superbased.app","org":"acme","gateway_base_uri":"https://mcp-gw.acme.superbased.app","policy_gen":41,
  "vservers":[{"id":"vs-gh","slug":"gh","sender_constraint":"bearer","servers":[{"id":"gh","target":"gh","credential_mode":"service"}]}]}`

func body(mode, grants string) string {
	m := ""
	if mode != "" {
		m = `"mode":"` + mode + `",`
	}
	return `{` + m + `"registry":` + registryJSON + `,"grants":[` + grants + `]}`
}

const allowGrant = `{"id":"g1","ord":1,"subject":{"kind":"product","value":"claude-code"},"resource":{"vserver":"vs-gh","name":"create_issue"},"action":"call","effect":"allow","enabled":true}`

func TestCompileBodyRows(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		bad      bool
		lintCode string
		check    func(t *testing.T, s PolicySpec)
	}{
		{name: "observe by default", raw: body("", allowGrant), check: func(t *testing.T, s PolicySpec) {
			if Enforces(s) || s.Mode != ModeObserve || len(s.CEL.VServers) != 1 || len(s.CEL.VServers[0].Rules) != 4 {
				t.Fatalf("spec = %+v", s)
			}
		}},
		{name: "enforce", raw: body("enforce", allowGrant), check: func(t *testing.T, s PolicySpec) {
			if !Enforces(s) {
				t.Fatal("not enforce")
			}
		}},
		{name: "empty grants is deny-all with a WARN", raw: body("enforce", ""), check: func(t *testing.T, s PolicySpec) {
			if !core.Has(s.Problems, core.CodeEmptyGrantSet) {
				t.Fatalf("problems %v", s.Problems)
			}
		}},
		{name: "bad mode", raw: body("audit", allowGrant), bad: true},
		{name: "stray top-level key", raw: `{"registry":` + registryJSON + `,"grants":[],"rules":[]}`, bad: true},
		{name: "stray condition key (never dropped)", raw: body("", strings.Replace(allowGrant, `"enabled":true`, `"enabled":true,"conditions":{"window":"9-5"}`, 1)), bad: true},
		{name: "judge effect -> feature_unavailable", raw: body("", strings.Replace(allowGrant, `"effect":"allow"`, `"effect":"judge"`, 1)), bad: true, lintCode: core.CodeFeatureUnavailable},
		{name: "taint -> feature_unavailable", raw: body("", strings.Replace(allowGrant, `"enabled":true`, `"enabled":true,"conditions":{"taint":true}`, 1)), bad: true, lintCode: core.CodeFeatureUnavailable},
		{name: "wildcard action", raw: body("", strings.Replace(allowGrant, `"action":"call"`, `"action":"*"`, 1)), bad: true, lintCode: core.CodeWildcardAction},
		{name: "passthrough on dpop vserver (R14.11)", raw: strings.Replace(strings.Replace(body("", allowGrant), `"sender_constraint":"bearer"`, `"sender_constraint":"dpop"`, 1), `"credential_mode":"service"`, `"credential_mode":"passthrough"`, 1), bad: true, lintCode: core.CodePassthroughOnNonBearer},
		{name: "trailing data", raw: body("", allowGrant) + `{}`, bad: true},
		{name: "not json", raw: `{`, bad: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, canon, err := CompileBody([]byte(c.raw), 1<<20)
			if c.bad {
				if err == nil {
					t.Fatal("compiled, want error")
				}
				if c.lintCode != "" {
					var le *core.LintError
					if !errors.As(err, &le) || !core.Has(le.Problems, c.lintCode) {
						t.Fatalf("err = %v, want *LintError with %s", err, c.lintCode)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(canon) || !strings.Contains(string(canon), `"registry"`) {
				t.Fatalf("canonical %s", canon)
			}
			c.check(t, spec)
		})
	}
	// Canonical bytes are stable across textual variants.
	_, c1, e1 := CompileBody([]byte(body("observe", allowGrant)), 0)
	_, c2, e2 := CompileBody([]byte(strings.ReplaceAll(body("", allowGrant), `"grants"`, ` "grants"`)), 0)
	if e1 != nil || e2 != nil || string(c1) != string(c2) {
		t.Fatalf("canonical bytes differ or errored: %v %v\n%s\n%s", e1, e2, c1, c2)
	}
	// Grant order does not change the canonical bytes (they are signed/hashed).
	deny := `{"id":"g0","ord":0,"subject":{"kind":"any"},"resource":{"vserver":"vs-gh","name":"delete_repo"},"action":"call","effect":"deny","enabled":true}`
	_, o1, _ := CompileBody([]byte(body("", allowGrant+","+deny)), 0)
	_, o2, _ := CompileBody([]byte(body("", deny+","+allowGrant)), 0)
	if string(o1) != string(o2) || !strings.Contains(string(o1), `"id":"g0","ord":0`) {
		t.Fatalf("canonical bytes depend on grant order:\n%s\n%s", o1, o2)
	}
	if _, _, err := CompileBody([]byte(body("", allowGrant)), 10); err == nil {
		t.Fatal("size cap not enforced")
	}
}

// TestDecodeBodyRefusesUnavailableFeatures is the Sol P2 finding-4 contract:
// the PUBLIC decoder runs the lint and returns the typed *core.LintError for
// every error-severity problem (judge / taint / requires_mfa / a task-action
// grant -> feature_unavailable; wildcard action; passthrough on a non-bearer
// vserver), never a valid Body every compiler would later refuse. A clean
// body still decodes.
func TestDecodeBodyRefusesUnavailableFeatures(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		code string
	}{
		{"judge effect", body("", strings.Replace(allowGrant, `"effect":"allow"`, `"effect":"judge"`, 1)), core.CodeFeatureUnavailable},
		{"taint condition", body("", strings.Replace(allowGrant, `"enabled":true`, `"enabled":true,"conditions":{"taint":true}`, 1)), core.CodeFeatureUnavailable},
		{"requires_mfa", body("", strings.Replace(allowGrant, `"enabled":true`, `"enabled":true,"conditions":{"requires_mfa":true}`, 1)), core.CodeFeatureUnavailable},
		{"tasks/get grant (no CEL method discriminator)", body("", strings.Replace(allowGrant, `"action":"call"`, `"action":"tasks/get"`, 1)), core.CodeFeatureUnavailable},
		{"tasks/cancel grant", body("", strings.Replace(allowGrant, `"action":"call"`, `"action":"tasks/cancel"`, 1)), core.CodeFeatureUnavailable},
		{"wildcard action", body("", strings.Replace(allowGrant, `"action":"call"`, `"action":"*"`, 1)), core.CodeWildcardAction},
		{"passthrough on dpop vserver (R14.11)", strings.Replace(strings.Replace(body("", allowGrant), `"sender_constraint":"bearer"`, `"sender_constraint":"dpop"`, 1), `"credential_mode":"service"`, `"credential_mode":"passthrough"`, 1), core.CodePassthroughOnNonBearer},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := DecodeBody([]byte(c.raw), 0)
			if err == nil {
				t.Fatalf("DecodeBody accepted the body: %+v", b)
			}
			var le *core.LintError
			if !errors.As(err, &le) || !core.Has(le.Problems, c.code) {
				t.Fatalf("err = %v, want *LintError with %s", err, c.code)
			}
			if len(b.Grants) != 0 || b.Mode != "" {
				t.Fatalf("a refused body must be empty: %+v", b)
			}
		})
	}
	if _, err := DecodeBody([]byte(body("enforce", allowGrant)), 0); err != nil {
		t.Fatalf("clean body refused: %v", err)
	}
	// Warnings never refuse the decoder: an empty grant set decodes.
	if _, err := DecodeBody([]byte(body("", "")), 0); err != nil {
		t.Fatalf("warn-only body refused: %v", err)
	}
}

// TestCompileBodyCanonicalisesApprovedSnapshot: a member's approved
// snapshot rides the decoded body into the compilers (the R9.8 drift
// guard's input - the compiled CEL carries the explicit allowlist) but is
// LIVE registry state, not signed policy: the canonical bytes strip it, so
// tool order, the pin itself and a re-adoption all leave the compiled_hash
// unchanged (adoption is picked up by reload, never by republish) and the
// caller's view is never mutated.
func TestCompileBodyCanonicalisesApprovedSnapshot(t *testing.T) {
	pinned := func(id string, tools string) string {
		return strings.Replace(body("enforce", strings.Replace(allowGrant, `"name":"create_issue"`, `"name":""`, 1)),
			`"credential_mode":"service"`, `"credential_mode":"service","snapshot":{"id":"`+id+`","tools":[`+tools+`]}`, 1)
	}
	spec, canon, err := CompileBody([]byte(pinned("snap-1", `"delete_repo","create_issue"`)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canon), `"snapshot"`) {
		t.Fatalf("canonical bytes must not carry the live pin: %s", canon)
	}
	if got := spec.Spec.Registry.VServers[0].Servers[0].Snapshot.Tools; strings.Join(got, ",") != "delete_repo,create_issue" {
		t.Fatalf("caller's view mutated: %v", got)
	}
	if rule := spec.CEL.VServers[0].Rules[2].Expr; !strings.Contains(rule, `mcp.tool.target == "gh" && mcp.tool.name in ["create_issue","delete_repo"]`) {
		t.Fatalf("compiled CEL lacks the allowlist: %s", rule)
	}
	_, c2, err := CompileBody([]byte(pinned("snap-1", `"create_issue","delete_repo"`)), 0)
	if err != nil || string(c2) != string(canon) {
		t.Fatalf("tool order must not change the canonical bytes: %v\n%s\n%s", err, canon, c2)
	}
	spec3, c3, err := CompileBody([]byte(pinned("snap-2", `"create_issue","delete_repo","exfiltrate_repo"`)), 0)
	if err != nil || string(c3) != string(canon) {
		t.Fatalf("adopting a new snapshot must NOT change the canonical bytes (reload, not republish): %v\n%s\n%s", err, canon, c3)
	}
	if rule := spec3.CEL.VServers[0].Rules[2].Expr; !strings.Contains(rule, `"exfiltrate_repo"`) {
		t.Fatalf("the compiled CEL must carry the newly adopted name: %s", rule)
	}
	_, c4, err := CompileBody([]byte(body("enforce", strings.Replace(allowGrant, `"name":"create_issue"`, `"name":""`, 1))), 0)
	if err != nil || string(c4) != string(canon) {
		t.Fatalf("an unpinned view must hash like the pinned one: %v\n%s\n%s", err, canon, c4)
	}
}

func TestLintReportsWithoutRefusing(t *testing.T) {
	ps, err := Lint([]byte(body("", strings.Replace(allowGrant, `"effect":"allow"`, `"effect":"judge"`, 1))), 0)
	if err != nil || !core.Has(ps, core.CodeFeatureUnavailable) {
		t.Fatalf("lint = %v, %v", ps, err)
	}
	if _, err := Lint([]byte(`{"mode":"nope"}`), 0); !errors.Is(err, ErrMode) {
		t.Fatalf("lint bad mode = %v", err)
	}
}

// TestSchemaHintDecodes: a body using exactly the keys the hint names must
// decode, so a renamed json tag fails here until the hint is updated.
func TestSchemaHintDecodes(t *testing.T) {
	raw := `{"mode":"enforce","registry":{"issuer":"i","org":"o","gateway_base_uri":"https://g","policy_gen":1,
	  "vservers":[{"id":"v","slug":"s","audience":"https://g/mcp/s","sender_constraint":"bearer","servers":[{"id":"x","target":"x","credential_mode":"service","snapshot":{"id":"snap","tools":["t"]}}]}]},
	  "grants":[{"id":"g","ord":1,"subject":{"kind":"user","value":"u"},"resource":{"vserver":"v","server":"x","name":"t"},"action":"call","effect":"allow",
	  "hierarchy_level":0,"audit_class":"normal","conditions":{"requires_cred_assurance":"claimed","requires_client_attestation":"claimed","expires_at":0},"enabled":true}]}`
	if _, err := DecodeBody([]byte(raw), 0); err != nil {
		t.Fatalf("hint body does not decode: %v", err)
	}
	for _, k := range []string{`"mode"`, `"registry"`, `"grants"`, `"vservers"`, `"servers"`, `"snapshot"`, `"tools"`, `"subject"`, `"resource"`, `"conditions"`, `"requires_client_attestation"`, `"sender_constraint"`} {
		if !strings.Contains(SchemaHint(), k) {
			t.Fatalf("hint lacks %s", k)
		}
	}
}
