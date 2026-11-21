package sandboxopenshell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// effectivepolicy_fu9_test.go pins the gateway policy reads against the
// real OpenShell v0.1.6 answers live check FU8-L1 saved (2026-11-03, a
// fresh Ubuntu 24.04 VM; lane FU9, tracker F-040). The fixtures under
// testdata/openshell-0.1.6 are those answers byte for byte; they hold no
// secret and no address.

// fu9Fixture reads one real answer.
func fu9Fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "openshell-0.1.6", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fu9Replace returns the fixture with one exact substring replaced (the
// substring must be there, so a fixture edit cannot silently turn a case
// into a copy of the untouched answer).
func fu9Replace(t *testing.T, name, old, repl string) []byte {
	t.Helper()
	b := string(fu9Fixture(t, name))
	if !strings.Contains(b, old) {
		t.Fatalf("%s holds no %q", name, old)
	}
	return []byte(strings.Replace(b, old, repl, 1))
}

// TestGatewayPolicyRealAnswers walks row PS over the real settings and
// global policy answers, in both gateway modes, one case per shape: an
// untouched gateway passes, a widening setting or a loaded global policy
// is refused, a superseded or never-set global policy is absent.
func TestGatewayPolicyRealAnswers(t *testing.T) {
	t.Parallel()
	const (
		txt  = "settings-global.txt"
		js   = "settings-global.json"
		mode = "proposal_approval_mode = <unset>"
		prop = "agent_policy_proposals_enabled = <unset>"
		jm   = `"proposal_approval_mode": "<unset>"`
		jp   = `"agent_policy_proposals_enabled": "<unset>"`
	)
	type global struct {
		ok  bool
		out []byte
	}
	none := global{false, fu9Fixture(t, "global-none.err")}
	loadedFull := fu9Replace(t, "global-after-delete-full.json", `"status": "superseded"`, `"status": "loaded"`)
	cases := []struct {
		name     string
		settings []byte
		global   global
		want     string // the verdict in both modes ("" passes)
	}{
		{"untouched gateway, text settings", fu9Fixture(t, txt), none, ""},
		{"untouched gateway, json settings", fu9Fixture(t, js), none, ""},
		{"auto approval, the other setting unset (text)", fu9Replace(t, txt, mode, "proposal_approval_mode = auto"), none, VerdictGatewayAutoApproval},
		{"auto approval, the other setting unset (json)", fu9Replace(t, js, jm, `"proposal_approval_mode": "auto"`), none, VerdictGatewayAutoApproval},
		{"proposals on, the other setting unset (text)", fu9Replace(t, txt, prop, "agent_policy_proposals_enabled = true"), none, VerdictGatewayPolicyProposals},
		{"proposals on, the other setting unset (json)", fu9Replace(t, js, jp, `"agent_policy_proposals_enabled": "true"`), none, VerdictGatewayPolicyProposals},
		{"explicit defaults after a restore", fu9Replace(t, txt, mode, "proposal_approval_mode = manual"), none, ""},
		{"global loaded, metadata only", fu9Fixture(t, txt), global{true, fu9Fixture(t, "global-set-loaded.json")}, VerdictGatewayGlobalPolicy},
		{"global loaded, --full", fu9Fixture(t, txt), global{true, loadedFull}, VerdictGatewayGlobalPolicy},
		{"global superseded, metadata only", fu9Fixture(t, txt), global{true, fu9Fixture(t, "global-after-delete.json")}, ""},
		{"global superseded, --full", fu9Fixture(t, txt), global{true, fu9Fixture(t, "global-after-delete-full.json")}, ""},
	}
	for _, c := range cases {
		s, err := ParseGatewaySettings(c.settings)
		f := GatewayPolicyFacts{SettingsRead: err == nil, Settings: s, Global: ClassifyGlobalPolicy(c.global.ok, c.global.out)}
		for _, m := range []string{GatewayExternal, GatewayManaged} {
			if v, r, rule := GatewayPolicyVerdict(m, f); v != c.want {
				t.Errorf("%s (%s): got %q (%s %s), settings err %v, want %q", c.name, m, v, rule, r, err, c.want)
			}
		}
	}
}

// TestClassifyGlobalRevision: the revision answer's status table and its
// closed shape, one case per row, from the real answers.
func TestClassifyGlobalRevision(t *testing.T) {
	t.Parallel()
	const (
		del  = "global-after-delete.json"
		delF = "global-after-delete-full.json"
		sup  = `"status": "superseded"`
	)
	cases := []struct {
		name string
		ok   bool
		in   []byte
		want GlobalPolicy
	}{
		{"none ever set (exit 1)", false, fu9Fixture(t, "global-none.err"), GlobalPolicyAbsent},
		{"loaded", true, fu9Fixture(t, "global-set-loaded.json"), GlobalPolicyPresent},
		{"loaded with its policy", true, fu9Replace(t, delF, sup, `"status": "loaded"`), GlobalPolicyPresent},
		{"superseded", true, fu9Fixture(t, del), GlobalPolicyAbsent},
		{"superseded with its policy", true, fu9Fixture(t, delF), GlobalPolicyAbsent},
		{"another status", true, fu9Replace(t, del, sup, `"status": "pending"`), GlobalPolicyUnknown},
		{"a status in upper case", true, fu9Replace(t, del, sup, `"status": "LOADED"`), GlobalPolicyUnknown},
		{"a status that is not a string", true, fu9Replace(t, del, sup, `"status": 2`), GlobalPolicyUnknown},
		{"a null status", true, fu9Replace(t, del, sup, `"status": null`), GlobalPolicyUnknown},
		{"another member", true, fu9Replace(t, del, sup, sup+`, "active": true`), GlobalPolicyUnknown},
		{"a sandbox scope", true, fu9Replace(t, del, `"scope": "global"`, `"scope": "sandbox"`), GlobalPolicyUnknown},
		{"a policy that is not an object", true, fu9Replace(t, del, sup, sup+`, "policy": "set"`), GlobalPolicyUnknown},
		{"a duplicate status", true, fu9Replace(t, del, sup, `"status": "loaded", `+sup), GlobalPolicyUnknown},
		{"trailing data", true, append(fu9Fixture(t, del), []byte(`{}`)...), GlobalPolicyUnknown},
	}
	for _, c := range cases {
		if got := ClassifyGlobalPolicy(c.ok, c.in); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// fu9NetRules are the compiled rules of the live check's net.yaml: one
// host on 443, enforced, no address range and no program (the YAML the
// live check set lists none).
func fu9NetRules() []NetRule {
	return []NetRule{{
		Key: NetRuleKey, Name: NetRuleKey,
		Endpoints: []NetEndpoint{{Host: "github.com", Entry: "github.com", Ports: []int{443}}},
	}}
}

// fu9WideRules are the compiled rules of wide.yaml: net.yaml plus
// pastebin.com on 443 and 8443.
func fu9WideRules() []NetRule {
	r := fu9NetRules()
	r[0].Endpoints = append(r[0].Endpoints, NetEndpoint{Host: "pastebin.com", Entry: "pastebin.com", Ports: []int{443, 8443}})
	return r
}

// TestEffectivePolicyRealAnswers compares the real `policy get <box> --full
// -o json` answers with their compiled rules: each matches its own (the
// baseline /var/log and /dev/urandom the gateway adds and "port" for one
// port are no widening), a narrower answer matches a wider compilation,
// and the wider answer against the narrower compilation names the host.
func TestEffectivePolicyRealAnswers(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		file    string
		rules   []NetRule
		verdict EffectiveVerdict
		detail  string
	}{
		{"no network, proxy_only", "full.json", nil, EffectiveMatch, ""},
		{"no network, a compiled rule", "full.json", fu9NetRules(), EffectiveMatch, ""},
		{"one port", "net-full.json", fu9NetRules(), EffectiveMatch, ""},
		{"one port and a ports list", "wide-full.json", fu9WideRules(), EffectiveMatch, ""},
		{"narrower than compiled", "net-full.json", fu9WideRules(), EffectiveMatch, ""},
		{"wider than compiled", "wide-full.json", fu9NetRules(), EffectiveExtraHost, "pastebin.com"},
		{"a rule on proxy_only", "net-full.json", nil, EffectiveExtraRule, NetRuleKey},
	} {
		v, d := EffectiveVerdictOf(c.rules, fu9Fixture(t, c.file))
		if v != c.verdict || !strings.Contains(d, c.detail) {
			t.Errorf("%s: got %s %q, want %s containing %q", c.name, v, d, c.verdict, c.detail)
		}
	}
	// A port the answer adds is still caught on the real shape.
	wider := fu9Replace(t, "net-full.json", `"port": 443`, `"ports": [443, 22]`)
	if v, _ := EffectiveVerdictOf(fu9NetRules(), wider); v != EffectiveExtraPort {
		t.Errorf("an added port: %s", v)
	}
	audit := fu9Replace(t, "net-full.json", `"enforcement": "enforce"`, `"enforcement": "audit"`)
	if v, _ := EffectiveVerdictOf(fu9NetRules(), audit); v != EffectiveNotEnforced {
		t.Errorf("an audit endpoint: %s", v)
	}
}

// TestNearNameFoldsEveryPunctuation (FU8-R11): a setting or section name
// spelled with any separator is a near miss, so the answer is unreadable.
func TestNearNameFoldsEveryPunctuation(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false,"x":{"proposal.approval.mode":"auto"}}`,
		`{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false,"proposal/approval/mode":"auto"}`,
		"proposal_approval_mode manual\nagent_policy_proposals_enabled false\nproposal.approval.mode auto\n",
	} {
		if s, err := ParseGatewaySettings([]byte(in)); err == nil {
			t.Errorf("%q read as %+v", in, s)
		}
	}
	answer := `{"policy":{"network_policies":{},"network.policies":{"r":{"endpoints":[{"host":"pastebin.com","port":443,"enforcement":"enforce"}]}}}}`
	if v, _ := EffectiveVerdictOf(nil, []byte(answer)); v != EffectiveUnreadable {
		t.Errorf("a dotted section name: %s", v)
	}
	if got := nearName("Proposal.Approval:Mode/"); got != "proposalapprovalmode" {
		t.Errorf("nearName = %q", got)
	}
}
