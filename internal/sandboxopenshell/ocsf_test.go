package sandboxopenshell

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// testBoxID is a sentinel OpenShell sandbox id.
const testBoxID = "0a415311-0000-4000-8000-000000000000"

// r7Body is the denied event lane O0's GO receipt recorded (R7
// example_denied), with a sentinel metadata uid and time.
const r7Body = `{"class_uid":4001,"action":"Denied","dst_endpoint":{"domain":"example.com"},"firewall_rule":null,"status_detail":"policy_dns_ineligible","metadata":{"uid":"m-1"},"time":1793000000000}`

func r7Record() OCSFRecord {
	return OCSFRecord{
		Body:     r7Body,
		Attrs:    map[string]string{"ocsf.class_uid": "4001", "ocsf.metadata.uid": "m-1", "openshell.sandbox.id": testBoxID},
		Resource: map[string]string{"openshell.sandbox.id": testBoxID, "service.name": "openshell-sandbox"},
	}
}

func event(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseOCSFDenial(t *testing.T) {
	t.Parallel()
	d, ok := ParseOCSFDenial(r7Record())
	if !ok || d.SandboxID != testBoxID || d.Host != "example.com" || d.Port != 0 || d.UID != "m-1" || d.Detail != "policy_dns_ineligible" || d.RuleType != "" {
		t.Fatalf("R7 record: %+v %v", d, ok)
	}
	// The detail is kept but bounded (O5 sweep R1).
	long := r7Record()
	long.Body = strings.Replace(long.Body, "policy_dns_ineligible", strings.Repeat("x", 4*maxOCSFDetail), 1)
	if d, ok := ParseOCSFDenial(long); !ok || len(d.Detail) != maxOCSFDetail {
		t.Fatalf("long detail: %d %v", len(d.Detail), ok)
	}
	if !d.At.Equal(time.UnixMilli(1793000000000)) {
		t.Fatalf("time %v", d.At)
	}
	cases := []struct {
		name string
		mut  func(*OCSFRecord)
		ok   bool
		host string
		port int
	}{
		{"allowed action", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, `"Denied"`, `"Allowed"`, 1) }, false, "", 0},
		{"blocked action", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, `"Denied"`, `"Blocked"`, 1) }, true, "example.com", 0},
		{"action id only", func(r *OCSFRecord) {
			r.Body = event(t, map[string]any{"class_uid": 4001, "action_id": 2, "dst_endpoint": map[string]any{"domain": "example.com", "port": 443}})
		}, true, "example.com", 443},
		{"process class", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "4001", "1007", 1) }, false, "", 0},
		{"class from the attribute", func(r *OCSFRecord) {
			r.Body = event(t, map[string]any{"action": "Denied", "dst_endpoint": map[string]any{"domain": "example.com"}})
		}, true, "example.com", 0},
		{"http class with url", func(r *OCSFRecord) {
			r.Body = event(t, map[string]any{"class_uid": 4002, "action": "Denied", "http_request": map[string]any{"url": map[string]any{"hostname": "Registry.NPMJS.org.", "port": 8080}}})
		}, true, "registry.npmjs.org", 8080},
		{"address only", func(r *OCSFRecord) {
			r.Body = event(t, map[string]any{"class_uid": 4001, "action": "Denied", "dst_endpoint": map[string]any{"ip": "10.0.0.5", "port": 22}})
		}, true, "10.0.0.5", 22},
		{"no destination", func(r *OCSFRecord) {
			r.Body = event(t, map[string]any{"class_uid": 4001, "action": "Denied"})
		}, false, "", 0},
		{"id on the resource only", func(r *OCSFRecord) { delete(r.Attrs, "openshell.sandbox.id") }, true, "example.com", 0},
		{"no box id", func(r *OCSFRecord) {
			delete(r.Attrs, "openshell.sandbox.id")
			delete(r.Resource, "openshell.sandbox.id")
		}, false, "", 0},
		{"malformed box id", func(r *OCSFRecord) { r.Attrs["openshell.sandbox.id"] = "../../etc" }, false, "", 0},
		{"not json", func(r *OCSFRecord) { r.Body = "OCSF NET:OPEN [INFO] DENIED example.com" }, false, "", 0},
		{"oversized", func(r *OCSFRecord) { r.Body = `{"class_uid":4001,"pad":"` + strings.Repeat("a", maxOCSFBody) + `"}` }, false, "", 0},
		// Audit finding O3-A6: the name reaches the audit only as
		// printable ASCII, and a literal is spelled canonically.
		{"escape in the name", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", `\u001b[31mexample.com`, 1) }, false, "", 0},
		{"space in the name", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", "exa mple.com", 1) }, false, "", 0},
		{"newline in the name", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", `example.com\nforged`, 1) }, false, "", 0},
		{"non-ASCII name", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", "ex\u00e4mple.com", 1) }, false, "", 0},
		{"bracketed IPv6 literal", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", "[2606:4700::1]", 1) }, true, "2606:4700::1", 0},
		{"IPv4-mapped literal", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", "::ffff:10.0.0.1", 1) }, true, "10.0.0.1", 0},
		// O5 sweep R1 (adversarial row A5): attribute-sourced fields are
		// bounded, so a forged record cannot pin megabytes in the hold.
		{"oversized uid attribute", func(r *OCSFRecord) { r.Attrs["ocsf.metadata.uid"] = strings.Repeat("u", maxOCSFUID+1) }, false, "", 0},
		{"uid with a space", func(r *OCSFRecord) { r.Attrs["ocsf.metadata.uid"] = "m 1" }, false, "", 0},
		{"oversized gateway name", func(r *OCSFRecord) { r.Resource["openshell.gateway.name"] = strings.Repeat("g", maxOCSFGateway+1) }, false, "", 0},
		{"short gateway name", func(r *OCSFRecord) { r.Resource["openshell.gateway.name"] = "sbo-managed" }, true, "example.com", 0},
		// O5 sweep R2: a wildcard or a non-LDH name never reaches the
		// audit, so the refusal page never offers a wildcard grant.
		{"wildcard name", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", "*.example.com", 1) }, false, "", 0},
		{"bare wildcard", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", "*", 1) }, false, "", 0},
		{"underscore label", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", "a_b.example.com", 1) }, false, "", 0},
		{"leading hyphen label", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", "-a.example.com", 1) }, false, "", 0},
		{"empty label", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", "a..example.com", 1) }, false, "", 0},
		{"port out of range", func(r *OCSFRecord) {
			r.Body = event(t, map[string]any{"class_uid": 4001, "action": "Denied", "dst_endpoint": map[string]any{"domain": "example.com", "port": 70000}})
		}, true, "example.com", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := r7Record()
			tc.mut(&r)
			d, ok := ParseOCSFDenial(r)
			if ok != tc.ok {
				t.Fatalf("ok %v, want %v (%+v)", ok, tc.ok, d)
			}
			if ok && (d.Host != tc.host || d.Port != tc.port) {
				t.Fatalf("host %q port %d, want %q %d", d.Host, d.Port, tc.host, tc.port)
			}
		})
	}
}

// TestParseOCSFRecordKinds (O5 audit finding O5-A6): a real denial whose
// destination name cannot be recorded (a wildcard, an underscore, a
// non-printable or over-long name) is told apart from a record that is no
// denial at all, so the receiver counts it as the run's dropped denial
// rather than losing it silently. It carries the box id and nothing of the
// name.
func TestParseOCSFRecordKinds(t *testing.T) {
	t.Parallel()
	name := func(h string) func(*OCSFRecord) {
		return func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, "example.com", h, 1) }
	}
	cases := []struct {
		name string
		mut  func(*OCSFRecord)
		kind OCSFParse
	}{
		{"recordable name", func(*OCSFRecord) {}, OCSFDenied},
		{"literal address", name("10.0.0.5"), OCSFDenied},
		{"wildcard name", name("*.example.com"), OCSFDeniedUnnamed},
		{"underscore label", name("a_b.example.com"), OCSFDeniedUnnamed},
		{"space in the name", name("exa mple.com"), OCSFDeniedUnnamed},
		{"over-long name", name(strings.Repeat("a.", 130) + "com"), OCSFDeniedUnnamed},
		{"allowed action", func(r *OCSFRecord) { r.Body = strings.Replace(r.Body, `"Denied"`, `"Allowed"`, 1) }, OCSFNotDenial},
		{"no box id", func(r *OCSFRecord) {
			delete(r.Attrs, "openshell.sandbox.id")
			delete(r.Resource, "openshell.sandbox.id")
		}, OCSFNotDenial},
		{"no destination", func(r *OCSFRecord) { r.Body = event(t, map[string]any{"class_uid": 4001, "action": "Denied"}) }, OCSFNotDenial},
		{"oversized uid", func(r *OCSFRecord) { r.Attrs["ocsf.metadata.uid"] = strings.Repeat("u", maxOCSFUID+1) }, OCSFNotDenial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := r7Record()
			tc.mut(&r)
			d, kind := ParseOCSFRecord(r)
			if kind != tc.kind {
				t.Fatalf("kind %d, want %d (%+v)", kind, tc.kind, d)
			}
			if kind == OCSFDeniedUnnamed && (d.SandboxID != testBoxID || d.Host != "" || d.Detail != "") {
				t.Fatalf("an unnamed denial carries %+v", d)
			}
			if _, ok := ParseOCSFDenial(r); ok != (tc.kind == OCSFDenied) {
				t.Fatalf("ParseOCSFDenial ok %v for kind %d", ok, kind)
			}
		})
	}
}

// TestOCSFDetailCutOnRune (O5 audit finding O5-A6, Info): the bounded
// detail never ends in half a multi-byte character.
func TestOCSFDetailCutOnRune(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc"},
		{"abä", 3, "ab"},
		{"€€", 4, "€"},
		{"€", 1, ""},
	}
	for _, tc := range cases {
		if got := cutUTF8(tc.in, tc.n); got != tc.want || !utf8.ValidString(got) {
			t.Fatalf("cutUTF8(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

// TestOCSFMappingRows: one case per row of ocsfRuleRows, each naming the
// row it must be decided by.
func TestOCSFMappingRows(t *testing.T) {
	t.Parallel()
	internet := RunEgress{
		Tier: vocab.TierInternet, Hosts: []string{"api.github.com", "*.npmjs.org"}, AllowCIDRs: []string{"10.20.0.0/16"},
		ProviderHosts: []string{"llm.corp.example"}, HostAddrs: []netip.Addr{netip.MustParseAddr("203.0.113.7")},
	}
	den := func(host string, port int, addr string, ruleType string) OCSFDenial {
		d := OCSFDenial{SandboxID: testBoxID, Host: host, Port: port, RuleType: ruleType}
		if addr != "" {
			d.Addr = netip.MustParseAddr(addr)
		}
		return d
	}
	with := func(t vocab.Tier) RunEgress { r := internet; r.Tier = t; return r }
	cases := []struct {
		row       string
		d         OCSFDenial
		run       RunEgress
		rule, key string
	}{
		{"M1 tier none", den("api.github.com", 443, "", ""), with(vocab.TierNone), OCSFRuleTierNone, OCSFKeyEgress},
		{"M2 provider host", den("api.anthropic.com", 443, "", ""), internet, OCSFRuleProviderHost, OCSFKeyEgress},
		{"M2 provider host", den("eu.llm.corp.example", 443, "", ""), with(vocab.TierProxyOnly), OCSFRuleProviderHost, OCSFKeyEgress},
		{"M3 tier proxy_only", den("example.com", 443, "", ""), with(vocab.TierProxyOnly), OCSFRuleTierNone, OCSFKeyEgress},
		{"M4 SSRF floor", den("metadata.example", 80, "169.254.169.254", ""), internet, OCSFRuleSSRFFloor, OCSFKeyEgress},
		{"M4 SSRF floor", den("api.github.com", 443, "", "ssrf"), internet, OCSFRuleSSRFFloor, OCSFKeyEgress},
		{"M4 SSRF floor", den("::1", 443, "::1", ""), internet, OCSFRuleSSRFFloor, OCSFKeyEgress},
		{"M5 host-local", den("api.github.com", 443, "203.0.113.7", ""), internet, OCSFRuleHostLocal, OCSFKeyEgress},
		{"M6 literal private", den("10.0.0.5", 22, "10.0.0.5", ""), internet, OCSFRulePrivateRange, OCSFKeyEgressAllowCIDRs},
		{"M7 literal IP", den("93.184.216.34", 443, "93.184.216.34", ""), internet, OCSFRuleLiteralIP, OCSFKeyEgressAllowHosts},
		{"M7 literal IP", den("2606:4700::1", 443, "2606:4700::1", ""), internet, OCSFRuleLiteralIP, OCSFKeyEgressAllowHosts},
		{"M8 not listed", den("example.com", 443, "", ""), internet, OCSFRuleAllowListMiss, OCSFKeyEgressAllowHosts},
		{"M8 not listed", den("npmjs.org", 443, "", ""), internet, OCSFRuleAllowListMiss, OCSFKeyEgressAllowHosts},
		{"M8 not listed", den("api.github.com", 443, "", ""), RunEgress{Tier: vocab.TierInternet, NoHost: true}, OCSFRuleAllowListMiss, OCSFKeyEgressAllowHosts},
		{"M9 port", den("api.github.com", 22, "", ""), internet, OCSFRulePortNotAllowed, OCSFKeyEgressAllowHosts},
		{"M10 resolved private", den("registry.npmjs.org", 443, "192.168.4.4", ""), internet, OCSFRulePrivateRange, OCSFKeyEgressAllowCIDRs},
		{"M10 resolved private", den("registry.npmjs.org", 443, "64:ff9b::c0a8:404", ""), internet, OCSFRulePrivateRange, OCSFKeyEgressAllowCIDRs},
		{"M11 fallback", den("api.github.com", 443, "", ""), internet, OCSFRuleSSRFFloor, OCSFKeyEgress},
		{"M11 fallback", den("api.github.com", 443, "10.20.1.1", ""), internet, OCSFRuleSSRFFloor, OCSFKeyEgress},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.row+"/"+tc.d.Host, func(t *testing.T) {
			rule, key, row := MapOCSFDenial(tc.d, tc.run)
			if rule != tc.rule || key != tc.key || row != tc.row {
				t.Fatalf("got %s %s (%s), want %s %s (%s)", rule, key, row, tc.rule, tc.key, tc.row)
			}
		})
		covered[tc.row] = true
	}
	for _, r := range OCSFRuleRows() {
		if !covered[r.ID] {
			t.Errorf("row %s has no case", r.ID)
		}
	}
	// Audit finding O3-A6: literals parsed from the event map as literals.
	for _, tc := range []struct{ domain, rule string }{
		{"[2606:4700::1]", OCSFRuleLiteralIP},
		{"::ffff:10.0.0.1", OCSFRulePrivateRange},
	} {
		r := r7Record()
		r.Body = strings.Replace(r.Body, "example.com", tc.domain, 1)
		d, ok := ParseOCSFDenial(r)
		if !ok {
			t.Fatalf("%s: not parsed", tc.domain)
		}
		if rule, _, _ := MapOCSFDenial(d, internet); rule != tc.rule {
			t.Errorf("%s: %s, want %s", tc.domain, rule, tc.rule)
		}
	}
	// The R7 event of a proxy_only box (lane O0's live shape) maps.
	d, _ := ParseOCSFDenial(r7Record())
	if rule, key, _ := MapOCSFDenial(d, RunEgress{Tier: vocab.TierProxyOnly}); rule != OCSFRuleTierNone || key != OCSFKeyEgress {
		t.Fatalf("R7 event on proxy_only: %s %s", rule, key)
	}
}

func TestClassifyOCSFExport(t *testing.T) {
	t.Parallel()
	want := OCSFReceiverEndpoint()
	cases := []struct {
		name string
		e    OCSFExport
		st   OCSFExportState
		says string
	}{
		{"unread", OCSFExport{}, OCSFExportUnknown, "could not be read"},
		{"off", OCSFExport{Read: true, OTLPEndpoint: want}, OCSFExportMissing, OCSFKeyEnabled},
		{"no endpoint", OCSFExport{Read: true, Enabled: true}, OCSFExportMissing, want},
		{"other endpoint", OCSFExport{Read: true, Enabled: true, Endpoint: "http://127.0.0.1:4317"}, OCSFExportMissing, "not to Observer's receiver"},
		{"https endpoint", OCSFExport{Read: true, Enabled: true, Endpoint: "https://127.0.0.1:14317"}, OCSFExportMissing, "not to Observer's receiver"},
		{"localhost spelling", OCSFExport{Read: true, Enabled: true, Endpoint: "http://localhost:14317"}, OCSFExportMissing, "not to Observer's receiver"},
		{"own endpoint", OCSFExport{Read: true, Enabled: true, Endpoint: want}, OCSFExportPresent, ""},
		{"own endpoint with slash", OCSFExport{Read: true, Enabled: true, Endpoint: want + "/"}, OCSFExportPresent, ""},
		{"inherited endpoint", OCSFExport{Read: true, Enabled: true, OTLPEndpoint: want}, OCSFExportPresent, ""},
		{"own endpoint overrides", OCSFExport{Read: true, Enabled: true, Endpoint: "http://10.0.0.2:4317", OTLPEndpoint: want}, OCSFExportMissing, "not to Observer's receiver"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, why := ClassifyOCSFExport(tc.e, want)
			if st != tc.st || !strings.Contains(why, tc.says) {
				t.Fatalf("%s %q, want %s containing %q", st, why, tc.st, tc.says)
			}
		})
	}
	if want != "http://127.0.0.1:14317" {
		t.Fatalf("receiver endpoint %q (the README step 1 value and the live script name it)", want)
	}
}

func TestParseSandboxID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
		ok       bool
	}{
		{`{"id":"` + testBoxID + `","name":"x"}`, testBoxID, true},
		{`{"sandbox":{"id":"` + strings.ToUpper(testBoxID) + `"}}`, testBoxID, true},
		{`{"id":"not an id"}`, "", false},
		{`{"id":""}`, "", false},
		{`not json`, "", false},
	}
	for _, tc := range cases {
		got, ok := ParseSandboxID([]byte(tc.in))
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: %q %v, want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestClassifyOCSFReceiver: one case per row of the receiver table (audit
// finding O3-A1).
func TestClassifyOCSFReceiver(t *testing.T) {
	t.Parallel()
	ok := OCSFReceiverFacts{Listener: true, ListenerOurUID: true, Marker: true, MarkerOwnsListener: true, SinkReady: true}
	cases := []struct {
		name string
		mut  func(*OCSFReceiverFacts)
		want OCSFReceiverState
		says string
	}{
		{"an IPv6 wildcard listener only", func(f *OCSFReceiverFacts) { *f = OCSFReceiverFacts{V6AnyListener: true} }, OCSFReceiverUncertain, "cannot tell whether it is dual-stack"},
		{"nothing listens", func(f *OCSFReceiverFacts) { *f = OCSFReceiverFacts{} }, OCSFReceiverAbsent, "observer start"},
		{"the daemon's receiver beside an IPv6-only listener", func(f *OCSFReceiverFacts) { f.V6AnyListener = true }, OCSFReceiverListening, ""},
		{"another user's listener", func(f *OCSFReceiverFacts) { f.ListenerOurUID = false }, OCSFReceiverTaken, "another user's"},
		{"no daemon marker", func(f *OCSFReceiverFacts) { f.Marker = false }, OCSFReceiverTaken, "not this Observer daemon's receiver"},
		{"marker's process does not hold the socket", func(f *OCSFReceiverFacts) { f.MarkerOwnsListener = false }, OCSFReceiverTaken, "not this Observer daemon's receiver"},
		{"relay not serving", func(f *OCSFReceiverFacts) { f.SinkReady = false }, OCSFReceiverNotReady, "not wired"},
		{"listening", func(*OCSFReceiverFacts) {}, OCSFReceiverListening, ""},
	}
	if len(cases) != len(ocsfReceiverRows)+2 {
		t.Fatalf("%d cases for %d rows (two rows are reached twice)", len(cases), len(ocsfReceiverRows))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ok
			tc.mut(&f)
			st, why := ClassifyOCSFReceiver(f)
			if st != tc.want || !strings.Contains(why, tc.says) {
				t.Fatalf("%s %q, want %s naming %q", st, why, tc.want, tc.says)
			}
		})
	}
}

// TestOCSFGatewayMatches: a record from another gateway is never the run's
// (audit finding O3-A2); an unknown side does not decide.
func TestOCSFGatewayMatches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		record, run string
		want        bool
	}{
		{"openshell", "openshell", true},
		{"other", "openshell", false},
		{"", "openshell", true},
		{"openshell", "", true},
	}
	for _, tc := range cases {
		if got := OCSFGatewayMatches(tc.record, tc.run); got != tc.want {
			t.Errorf("%q vs %q: %v, want %v", tc.record, tc.run, got, tc.want)
		}
	}
	r := r7Record()
	r.Resource["openshell.gateway.name"] = "openshell"
	if d, ok := ParseOCSFDenial(r); !ok || d.Gateway != "openshell" {
		t.Fatalf("gateway %q %v", d.Gateway, ok)
	}
}

// TestOCSFExportReasonsNameKeysAndFile is audit finding O3-A9: every reason
// names the file, and the unknown one names both keys.
func TestOCSFExportReasonsNameKeysAndFile(t *testing.T) {
	t.Parallel()
	const path = "/home/dev/.config/openshell/gateway.toml"
	want := OCSFReceiverEndpoint()
	for _, e := range []OCSFExport{{Path: path}, {Read: true, Path: path}, {Read: true, Enabled: true, Path: path}, {Read: true, Enabled: true, Endpoint: "http://127.0.0.1:1", Path: path}} {
		_, why := ClassifyOCSFExport(e, want)
		if !strings.Contains(why, path) || !strings.Contains(why, want) {
			t.Errorf("%+v: %q names neither the file nor the endpoint", e, why)
		}
	}
	if _, why := ClassifyOCSFExport(OCSFExport{Path: path}, want); !strings.Contains(why, OCSFKeyEnabled) || !strings.Contains(why, "[openshell.gateway.otlp.ocsf] endpoint") {
		t.Errorf("unknown: %q does not name both keys", why)
	}
}
