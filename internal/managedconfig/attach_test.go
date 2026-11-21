package managedconfig

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/attachrule"
)

const acmeURL = "https://observer.acme.example"

// TestCanonicalOrgURL is one row per accepted shape and one per
// orgURLChecks row (plus the pre-parse refusals).
func TestCanonicalOrgURL(t *testing.T) {
	t.Parallel()
	valid := []struct{ in, want string }{
		{acmeURL, acmeURL},
		{acmeURL + "/", acmeURL},
		{"HTTPS://Observer.ACME.example", acmeURL},
		{acmeURL + ":443", acmeURL},
		{acmeURL + ":8443", acmeURL + ":8443"},
		{"https://10.0.0.7", "https://10.0.0.7"},
		{"https://[2001:DB8::1]:8443", "https://[2001:db8::1]:8443"},
	}
	for _, tc := range valid {
		got, err := CanonicalOrgURL(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("CanonicalOrgURL(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	invalid := []struct{ in, why string }{
		{"", "empty"},
		{"https://" + strings.Repeat("a", maxOrgURLLen), "longer than"},
		{"https://acme example", "space, control"},
		{"https://acme.example\\@evil.example", "backslash"},
		{"https://acmÃƒÂ©.example", "non-ASCII"},
		{"https://acme.example:abc", "does not parse"},
		{"http://observer.acme.example", "must use https"},
		{"observer.acme.example", "must use https"},
		{"https:observer.acme.example", "is not a server address"},
		{"https://admin:secret@observer.acme.example", "must not carry credentials"},
		{"https://observer.acme.example?org=1", "must not carry a query"},
		{"https://observer.acme.example?", "must not carry a query"},
		{"https://observer.acme.example#x", "must not carry a fragment"},
		{"https://observer.acme.example#", "must not carry a fragment"},
		{"https://observer.acme.example/enrol/abc", "must not carry a path"},
		{"https://observer.acme.example/..%2f", "must not carry a path"},
		{"https://", "has no host"},
		{"https://acme%C3%A9.example", "has an invalid host name"},
		{"https://observer.acme.example:", "has an empty port"},
		{"https://observer.acme.example:0", "has an invalid port"},
		{"https://observer.acme.example:0443", "has an invalid port"},
		{"https://observer.acme.example.", "has an invalid host name"},
		{"https://-acme.example", "has an invalid host name"},
		{"https://acme_corp.example", "has an invalid host name"},
		{"https://[fe80::1%25eth0]", "must not percent-encode the host"},
	}
	covered := map[string]bool{}
	for _, tc := range invalid {
		_, err := CanonicalOrgURL(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.why) {
			t.Errorf("CanonicalOrgURL(%q) err = %v, want %q", tc.in, err, tc.why)
		}
		covered[tc.why] = true
	}
	for _, c := range orgURLChecks {
		if !covered[c.why] {
			t.Errorf("orgURLChecks row %q has no test case", c.why)
		}
	}
}

// TestParseAttachMethod is one row per attachMethods row plus refusals.
func TestParseAttachMethod(t *testing.T) {
	t.Parallel()
	for _, r := range attachMethods {
		if m, err := ParseAttachMethod(string(r.method)); err != nil || m != r.method {
			t.Errorf("method %q: %q, %v", r.method, m, err)
		}
	}
	for _, bad := range []string{"", "IDP", " idp", "code", "pairing_code", "link"} {
		if _, err := ParseAttachMethod(bad); err == nil || !strings.Contains(err.Error(), "is not one of idp") {
			t.Errorf("method %q accepted or wrong error: %v", bad, err)
		}
	}
	if got := AttachMethods(); len(got) != len(attachMethods) || got[0] != AttachMethodIdP {
		t.Errorf("AttachMethods() = %v", got)
	}
}

// TestDecideAttachTable is one row per attachRules row.
func TestDecideAttachTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		probe  Probe
		status AttachStatus
		failed string
		policy *AttachPolicy
	}{
		{name: "no source", probe: Probe{}, status: AttachStatusNone},
		{name: "ownership check failed", probe: Probe{Found: true, Source: "/etc/superbased/managed.toml", FailedCheck: "not_root_owned"}, status: AttachStatusInvalid, failed: "not_root_owned"},
		{name: "ceiling only", probe: tomlProbe(validDoc), status: AttachStatusNone},
		{name: "locked policy", probe: tomlProbe(validDoc + "[attach]\norg_url = \"" + acmeURL + "/\"\nlocked = true\n"), status: AttachStatusValid, policy: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP, Locked: true}},
		{name: "malformed attach keys", probe: tomlProbe("[attach]\nmethod = \"idp\"\n"), status: AttachStatusInvalid, failed: "parse"},
	}
	covered := map[AttachStatus]bool{}
	for _, tc := range cases {
		r := DecideAttach(tc.probe)
		if r.Status != tc.status || r.FailedCheck != tc.failed {
			t.Errorf("%s: status=%s failed=%q err=%q", tc.name, r.Status, r.FailedCheck, r.Err)
			continue
		}
		switch {
		case tc.policy == nil && r.Policy != nil:
			t.Errorf("%s: unexpected policy %+v", tc.name, r.Policy)
		case tc.policy != nil && (r.Policy == nil || *r.Policy != *tc.policy):
			t.Errorf("%s: policy %+v, want %+v", tc.name, r.Policy, tc.policy)
		}
		if r.Source != tc.probe.Source {
			t.Errorf("%s: source %q, want %q", tc.name, r.Source, tc.probe.Source)
		}
		covered[tc.status] = true
	}
	for _, r := range attachRules {
		if !covered[r.status] {
			t.Errorf("attach rule %q has no row", r.name)
		}
	}
}

// TestAttachKeysPerFormat: each key's valid and invalid values in each of
// the three source formats.
func TestAttachKeysPerFormat(t *testing.T) {
	t.Parallel()
	jsonProbe := func(doc string) Probe { return Probe{Found: true, Source: "plist", Format: "json", Data: []byte(doc)} }
	regProbe := func(v RegistryValues) Probe {
		return Probe{Found: true, Source: "HKLM", Format: "registry", Registry: &v}
	}
	cases := []struct {
		name    string
		probe   Probe
		want    *AttachPolicy
		wantErr string
	}{
		// org URL
		{name: "toml url only, method defaults to idp, unlocked", probe: tomlProbe("[attach]\norg_url = \"" + acmeURL + "\"\n"), want: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP}},
		{name: "toml http url", probe: tomlProbe("[attach]\norg_url = \"http://observer.acme.example\"\n"), wantErr: "must use https"},
		{name: "toml url with credentials", probe: tomlProbe("[attach]\norg_url = \"https://a:b@observer.acme.example\"\n"), wantErr: "credentials"},
		{name: "toml empty url", probe: tomlProbe("[attach]\norg_url = \"\"\n"), wantErr: "empty"},
		{name: "json url", probe: jsonProbe(`{"OrgURL":"` + acmeURL + `:8443"}`), want: &AttachPolicy{OrgURL: acmeURL + ":8443", Method: AttachMethodIdP}},
		{name: "json url with path", probe: jsonProbe(`{"OrgURL":"` + acmeURL + `/x"}`), wantErr: "path"},
		{name: "registry url", probe: regProbe(RegistryValues{HaveOrgURL: true, OrgURL: acmeURL}), want: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP}},
		{name: "registry url with query", probe: regProbe(RegistryValues{HaveOrgURL: true, OrgURL: acmeURL + "?a=1"}), wantErr: "query"},
		// attach method
		{name: "toml method idp", probe: tomlProbe("[attach]\norg_url = \"" + acmeURL + "\"\nmethod = \"idp\"\n"), want: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP}},
		{name: "toml unknown method", probe: tomlProbe("[attach]\norg_url = \"" + acmeURL + "\"\nmethod = \"code\"\n"), wantErr: "is not one of"},
		{name: "json unknown method", probe: jsonProbe(`{"OrgURL":"` + acmeURL + `","AttachMethod":"IdP"}`), wantErr: "is not one of"},
		{name: "registry method", probe: regProbe(RegistryValues{HaveOrgURL: true, OrgURL: acmeURL, HaveAttachMethod: true, AttachMethod: "idp"}), want: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP}},
		{name: "registry unknown method", probe: regProbe(RegistryValues{HaveOrgURL: true, OrgURL: acmeURL, HaveAttachMethod: true, AttachMethod: "magic"}), wantErr: "is not one of"},
		{name: "method without url", probe: jsonProbe(`{"AttachMethod":"idp"}`), wantErr: "needs the org URL"},
		// lock
		{name: "toml locked", probe: tomlProbe("[attach]\norg_url = \"" + acmeURL + "\"\nlocked = true\n"), want: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP, Locked: true}},
		{name: "toml locked false", probe: tomlProbe("[attach]\norg_url = \"" + acmeURL + "\"\nlocked = false\n"), want: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP}},
		{name: "toml locked not a boolean", probe: tomlProbe("[attach]\norg_url = \"" + acmeURL + "\"\nlocked = \"yes\"\n"), wantErr: "managedconfig:"},
		{name: "json locked", probe: jsonProbe(`{"OrgURL":"` + acmeURL + `","Locked":true}`), want: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP, Locked: true}},
		{name: "json locked not a boolean", probe: jsonProbe(`{"OrgURL":"` + acmeURL + `","Locked":1}`), wantErr: "managed preferences"},
		{name: "registry locked 1", probe: regProbe(RegistryValues{HaveOrgURL: true, OrgURL: acmeURL, HaveLocked: true, Locked: 1}), want: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP, Locked: true}},
		{name: "registry locked 0", probe: regProbe(RegistryValues{HaveOrgURL: true, OrgURL: acmeURL, HaveLocked: true}), want: &AttachPolicy{OrgURL: acmeURL, Method: AttachMethodIdP}},
		{name: "registry locked 2", probe: regProbe(RegistryValues{HaveOrgURL: true, OrgURL: acmeURL, HaveLocked: true, Locked: 2}), wantErr: "must be 0 or 1"},
		{name: "lock without url", probe: tomlProbe("[attach]\nlocked = true\n"), wantErr: "needs the org URL"},
		// strictness shared with the ceiling
		{name: "toml unknown attach key", probe: tomlProbe("[attach]\norg_url = \"" + acmeURL + "\"\nask_who = \"it\"\n"), wantErr: "unknown keys attach.ask_who"},
		{name: "toml empty attach table", probe: tomlProbe(validDoc + "[attach]\n"), wantErr: "declares no keys"},
		{name: "json unknown key", probe: jsonProbe(`{"OrgURL":"` + acmeURL + `","Lock":true}`), wantErr: "unknown field"},
		{name: "registry unknown value", probe: regProbe(RegistryValues{HaveOrgURL: true, OrgURL: acmeURL, Unknown: []string{"Lock"}}), wantErr: "unknown registry values Lock"},
	}
	for _, tc := range cases {
		r := DecideAttach(tc.probe)
		if tc.wantErr != "" {
			if r.Status != AttachStatusInvalid || r.FailedCheck != "parse" || !strings.Contains(r.Err, tc.wantErr) {
				t.Errorf("%s: status=%s failed=%q err=%q, want invalid with %q", tc.name, r.Status, r.FailedCheck, r.Err, tc.wantErr)
			}
			continue
		}
		if r.Status != AttachStatusValid || r.Policy == nil || *r.Policy != *tc.want {
			t.Errorf("%s: status=%s policy=%+v err=%q, want %+v", tc.name, r.Status, r.Policy, r.Err, tc.want)
		}
	}
}

// TestAttachOnlySourceHasNoCeiling: a source carrying only attach keys is a
// valid source with no ceiling in every format (it never drops the machine
// to core only), while a source with neither stays malformed.
func TestAttachOnlySourceHasNoCeiling(t *testing.T) {
	t.Parallel()
	probes := map[string]Probe{
		"toml":     tomlProbe("[attach]\norg_url = \"" + acmeURL + "\"\nlocked = true\n"),
		"json":     {Found: true, Format: "json", Data: []byte(`{"OrgURL":"` + acmeURL + `","Locked":true}`)},
		"registry": {Found: true, Format: "registry", Registry: &RegistryValues{HaveOrgURL: true, OrgURL: acmeURL, HaveLocked: true, Locked: 1}},
	}
	for name, p := range probes {
		r := Decide(p, nil)
		if r.Status != StatusNone || !r.UpdatesAllowed || r.Ceiling != nil {
			t.Errorf("%s: ceiling status=%s updates=%v err=%q, want none", name, r.Status, r.UpdatesAllowed, r.Err)
		}
		if a := DecideAttach(p); a.Status != AttachStatusValid || !a.Policy.Locked {
			t.Errorf("%s: attach %+v", name, a)
		}
	}
	for name, p := range map[string]Probe{
		"toml empty attach table": tomlProbe("[attach]\n"),
		"json empty":              {Found: true, Format: "json", Data: []byte(`{}`)},
		"registry empty":          {Found: true, Format: "registry", Registry: &RegistryValues{}},
	} {
		if r := Decide(p, nil); r.Status != StatusInvalidCoreOnly {
			t.Errorf("%s: ceiling status %s, want %s", name, r.Status, StatusInvalidCoreOnly)
		}
	}
	// A ceiling and an attach policy in one source both apply.
	both := tomlProbe(validDoc + "[attach]\norg_url = \"" + acmeURL + "\"\n")
	if r := Decide(both, nil); r.Status != StatusValid {
		t.Errorf("ceiling beside attach keys: %s %q", r.Status, r.Err)
	}
}

// TestAttachRuleIntegration: managed facts feed internal/attachrule's input
// and the precedence table decides (19.3 rule 3).
func TestAttachRuleIntegration(t *testing.T) {
	t.Parallel()
	const source = "/etc/superbased/managed.toml"
	locked := DecideAttach(Probe{Found: true, Source: source, Format: "toml", Data: []byte("[attach]\norg_url = \"" + acmeURL + "\"\nlocked = true\n")})
	unlocked := DecideAttach(Probe{Found: true, Source: source, Format: "toml", Data: []byte("[attach]\norg_url = \"" + acmeURL + "\"\n")})
	invalid := DecideAttach(Probe{Found: true, Source: source, FailedCheck: "group_or_world_writable"})
	other := OrgDestination("https://observer.other.example", "")
	enrolledManaged := OrgDestination(acmeURL, "Acme")
	enrolledManaged.Tenancy = attachrule.TenancyManaged

	cases := []struct {
		name    string
		res     AttachResult
		current attachrule.Destination
		intent  attachrule.Intent
		request string
		row     int
		outcome attachrule.Outcome
		reason  attachrule.RefusalReason
	}{
		{name: "locked: attach elsewhere is refused", res: locked, intent: attachrule.IntentAttach, request: "https://observer.other.example", row: 1, outcome: attachrule.OutcomeRefuse, reason: attachrule.RefusalLocked},
		{name: "locked: attach elsewhere over http is refused", res: locked, intent: attachrule.IntentAttach, request: "http://observer.acme.example", row: 1, outcome: attachrule.OutcomeRefuse, reason: attachrule.RefusalLocked},
		{name: "locked: the locked org, spelled differently, is allowed", res: locked, intent: attachrule.IntentAttach, request: "HTTPS://Observer.Acme.example:443/", row: 1, outcome: attachrule.OutcomeAllow},
		{name: "locked: re-attach while attached there is allowed", res: locked, current: enrolledManaged, intent: attachrule.IntentAttach, request: acmeURL, row: 1, outcome: attachrule.OutcomeAllow},
		{name: "locked: disconnect is refused", res: locked, current: enrolledManaged, intent: attachrule.IntentDisconnect, row: 1, outcome: attachrule.OutcomeRefuse, reason: attachrule.RefusalLocked},
		{name: "locked: identity only is allowed", res: locked, current: enrolledManaged, intent: attachrule.IntentIdentityOnly, row: 1, outcome: attachrule.OutcomeAllow},
		{name: "unlocked: no lock, attach elsewhere follows row 6", res: unlocked, intent: attachrule.IntentAttach, request: "https://observer.other.example", row: 6, outcome: attachrule.OutcomeAllow},
		{name: "unlocked: disconnect follows row 3", res: unlocked, current: other, intent: attachrule.IntentDisconnect, row: 3, outcome: attachrule.OutcomeAllow},
		{name: "invalid source carries no lock (the caller refuses first)", res: invalid, intent: attachrule.IntentDisconnect, row: 3, outcome: attachrule.OutcomeAllow},
	}
	for _, tc := range cases {
		in := attachrule.Input{Current: tc.current, Lock: tc.res.Lock(), Intent: tc.intent}
		if tc.request != "" {
			in.Requested = OrgDestination(tc.request, "")
		}
		d := attachrule.Decide(in)
		if d.Row != tc.row || d.Outcome != tc.outcome {
			t.Errorf("%s: row %d outcome %d, want row %d outcome %d", tc.name, d.Row, d.Outcome, tc.row, tc.outcome)
			continue
		}
		if tc.reason == attachrule.RefusalNone {
			continue
		}
		if d.Refusal == nil || d.Refusal.Reason != tc.reason {
			t.Errorf("%s: refusal %+v, want reason %d", tc.name, d.Refusal, tc.reason)
			continue
		}
		if d.Refusal.LockOrgName != "observer.acme.example" || !strings.Contains(d.Refusal.AskWho, source) {
			t.Errorf("%s: refusal names %q / %q, want the org host and the managing source", tc.name, d.Refusal.LockOrgName, d.Refusal.AskWho)
		}
	}
	if unlocked.DefaultOrgURL() != acmeURL || invalid.DefaultOrgURL() != "" || (AttachResult{}).DefaultOrgURL() != "" {
		t.Errorf("DefaultOrgURL: %q %q", unlocked.DefaultOrgURL(), invalid.DefaultOrgURL())
	}
	if (AttachResult{Status: AttachStatusValid, Policy: &AttachPolicy{OrgURL: acmeURL, Locked: true}}).Lock().AskWho != "your organization's administrator" {
		t.Error("a lock with no source must still say who to ask")
	}
}
