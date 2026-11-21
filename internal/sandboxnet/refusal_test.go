package sandboxnet

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// gatewayRuleConstants names every gateway rule constant of the package by
// its identifier. TestGatewayRuleConstantsAreListed keeps it equal to the
// constants the source declares, so a new rule cannot be added without a
// row here and, through TestGatewayRuleTable, a row in the mapping table.
var gatewayRuleConstants = map[string]string{
	"RuleNil":                      RuleNil,
	"RuleUnspecified":              RuleUnspecified,
	"RuleThisNetwork":              RuleThisNetwork,
	"RuleLoopback":                 RuleLoopback,
	"RuleLinkLocalUnicast":         RuleLinkLocalUnicast,
	"RuleLinkLocalMulticast":       RuleLinkLocalMulticast,
	"RuleInterfaceLocalMulticast":  RuleInterfaceLocalMulticast,
	"RuleMulticast":                RuleMulticast,
	"RuleLimitedBroadcast":         RuleLimitedBroadcast,
	"RuleIPv4Compatible":           RuleIPv4Compatible,
	"RuleHostLocal":                RuleHostLocal,
	"RulePrivate":                  RulePrivate,
	"RuleSharedAddress":            RuleSharedAddress,
	"RuleUniqueLocal":              RuleUniqueLocal,
	"RuleSiteLocal":                RuleSiteLocal,
	"RuleHostNotListed":            RuleHostNotListed,
	"RuleHostNameInvalid":          RuleHostNameInvalid,
	"RuleModelProviderHost":        RuleModelProviderHost,
	"RuleModelProviderAddress":     RuleModelProviderAddress,
	"RuleLiteralIP":                RuleLiteralIP,
	"RuleProviderAddressesUnknown": RuleProviderAddressesUnknown,
	"RulePortNotAllowed":           RulePortNotAllowed,
	"RuleSNIAbsent":                RuleSNIAbsent,
	"RuleSNIMismatch":              RuleSNIMismatch,
	"ruleLocalAddrsUnavailable":    ruleLocalAddrsUnavailable,
}

// TestGatewayRuleTable is one case per gateway rule constant: the closed
// rule and the deciding key it maps to.
func TestGatewayRuleTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		gateway string
		rule    RefusalRule
		key     string
	}{
		{RuleHostNotListed, RefusalAllowListMiss, KeyEgressAllowHosts},
		{RuleHostNameInvalid, RefusalAllowListMiss, KeyEgressAllowHosts},
		{RuleLiteralIP, RefusalLiteralIP, KeyEgressAllowHosts},
		{RulePortNotAllowed, RefusalPortNotAllowed, KeyEgressAllowHosts},
		{RuleSNIAbsent, RefusalTLSServerName, KeyEgressAllowHosts},
		{RuleSNIMismatch, RefusalTLSServerName, KeyEgressAllowHosts},
		{RuleModelProviderHost, RefusalProviderHost, KeyProviderDirect},
		{RuleModelProviderAddress, RefusalProviderHost, KeyProviderDirect},
		{RuleProviderAddressesUnknown, RefusalProviderHost, KeyProviderDirect},
		{ruleLocalAddrsUnavailable, RefusalHostLocal, KeyEgress},
		{RuleHostLocal, RefusalHostLocal, KeyEgress},
		{RulePrivate, RefusalPrivateRange, KeyEgressAllowCIDRs},
		{RuleSharedAddress, RefusalPrivateRange, KeyEgressAllowCIDRs},
		{RuleUniqueLocal, RefusalPrivateRange, KeyEgressAllowCIDRs},
		{RuleSiteLocal, RefusalPrivateRange, KeyEgressAllowCIDRs},
		{RuleNil, RefusalSSRFFloor, KeyEgress},
		{RuleUnspecified, RefusalSSRFFloor, KeyEgress},
		{RuleThisNetwork, RefusalSSRFFloor, KeyEgress},
		{RuleLoopback, RefusalSSRFFloor, KeyEgress},
		{RuleLinkLocalUnicast, RefusalSSRFFloor, KeyEgress},
		{RuleLinkLocalMulticast, RefusalSSRFFloor, KeyEgress},
		{RuleInterfaceLocalMulticast, RefusalSSRFFloor, KeyEgress},
		{RuleMulticast, RefusalSSRFFloor, KeyEgress},
		{RuleLimitedBroadcast, RefusalSSRFFloor, KeyEgress},
		{RuleIPv4Compatible, RefusalSSRFFloor, KeyEgress},
	}
	if len(cases) != len(gatewayRuleConstants) {
		t.Fatalf("%d cases for %d gateway rule constants", len(cases), len(gatewayRuleConstants))
	}
	for _, tc := range cases {
		rule, key, ok := MapGatewayRule(tc.gateway)
		if !ok || rule != tc.rule || key != tc.key {
			t.Errorf("MapGatewayRule(%q) = %q, %q, %v; want %q, %q", tc.gateway, rule, key, ok, tc.rule, tc.key)
		}
	}
	// The provider block's literal-ip names its own key.
	if rule, key := mapAt(stageProvider, RuleLiteralIP); rule != RefusalLiteralIP || key != KeyProviderDirect {
		t.Errorf("provider literal-ip = %q, %q", rule, key)
	}
	if rule, key := mapAt(stageHosts, RuleLiteralIP); rule != RefusalLiteralIP || key != KeyEgressAllowHosts {
		t.Errorf("hosts literal-ip = %q, %q", rule, key)
	}
	// An unknown name is never dropped.
	if rule, key := mapAt(stagePolicy, "no-such-rule"); rule != RefusalSSRFFloor || key != KeyEgress {
		t.Errorf("unknown = %q, %q", rule, key)
	}
}

// TestGatewayRuleTableCoversEveryRule fails when a gateway rule constant
// has no row, or more than one, in the mapping table.
func TestGatewayRuleTableCoversEveryRule(t *testing.T) {
	t.Parallel()
	rows := map[string]int{}
	for _, r := range gatewayRuleRows {
		rows[r.gateway]++
		if !r.rule.Valid() {
			t.Errorf("row %q maps to %q, outside the vocabulary", r.gateway, r.rule)
		}
	}
	for name, v := range gatewayRuleConstants {
		if rows[v] != 1 {
			t.Errorf("gateway rule %s (%q) has %d rows in gatewayRuleRows, want 1", name, v, rows[v])
		}
	}
	if len(rows) != len(gatewayRuleConstants) {
		t.Errorf("gatewayRuleRows has %d names, %d gateway constants exist", len(rows), len(gatewayRuleConstants))
	}
}

// ruleConstName matches a gateway rule constant identifier.
var ruleConstName = regexp.MustCompile(`^[Rr]ule[A-Z]`)

// TestGatewayRuleConstantsAreListed parses the package source and fails
// when it declares a rule constant gatewayRuleConstants does not name (or
// the map names one the source no longer declares).
func TestGatewayRuleConstantsAreListed(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var declared []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				for _, n := range s.(*ast.ValueSpec).Names {
					if ruleConstName.MatchString(n.Name) {
						declared = append(declared, n.Name)
					}
				}
			}
		}
	}
	sort.Strings(declared)
	var listed []string
	for n := range gatewayRuleConstants {
		listed = append(listed, n)
	}
	sort.Strings(listed)
	if strings.Join(declared, ",") != strings.Join(listed, ",") {
		t.Fatalf("declared rule constants\n  %v\nlisted\n  %v", declared, listed)
	}
}

// TestRefusalVocabulary pins the closed vocabulary and its next steps.
func TestRefusalVocabulary(t *testing.T) {
	t.Parallel()
	want := []string{"allow-list-miss", "private-range", "provider-host", "host-local", "tier-none", "ssrf-floor", "literal-ip", "port-not-allowed", "tls-server-name"}
	if len(RefusalRules) != len(want) {
		t.Fatalf("vocabulary = %v", RefusalRules)
	}
	for i, r := range RefusalRules {
		if string(r) != want[i] || !r.Valid() {
			t.Errorf("RefusalRules[%d] = %q, want %q", i, r, want[i])
		}
		if NextStep(r) == "" {
			t.Errorf("%q has no next step", r)
		}
	}
	if RefusalRule("allow_list_miss").Valid() || NextStep("bogus") != "" {
		t.Error("a name outside the vocabulary passed")
	}
	for _, r := range gatewayRuleRows {
		if r.rule == RefusalTierNone {
			t.Errorf("gateway rule %q maps to tier-none; the gateway never runs at tier none", r.gateway)
		}
	}
}

// TestRefusalJSONGolden pins the structured 403 body byte for byte.
func TestRefusalJSONGolden(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		r       Refusal
		message string
		want    string
	}{
		{
			name:    "allow-list miss",
			r:       Refusal{Host: "evil.example", Port: 443, Rule: RefusalAllowListMiss, Key: KeyEgressAllowHosts},
			message: "sandbox egress gateway: destination refused by rule host-not-listed (this run may reach only registry.npmjs.org)",
			want:    `{"error":"egress_refused","rule":"allow-list-miss","key":"terminal.sandbox.egress_allow_hosts","host":"evil.example","next_step":"add the host to terminal.sandbox.egress_allow_hosts in the owner's config (if an organization pin narrowed the list, ask the organization)","message":"sandbox egress gateway: destination refused by rule host-not-listed (this run may reach only registry.npmjs.org)"}` + "\n",
		},
		{
			name:    "private range keeps the bracketed key unescaped",
			r:       Refusal{Host: "10.0.0.5", Port: 443, Rule: RefusalPrivateRange, Key: KeyEgressAllowCIDRs},
			message: "sandbox egress gateway: destination refused by rule private-rfc1918 (to allow a private destination, add its CIDR to [terminal.sandbox].egress_allow_cidrs)",
			want:    `{"error":"egress_refused","rule":"private-range","key":"terminal.sandbox.egress_allow_cidrs","host":"10.0.0.5","next_step":"add the destination's CIDR to terminal.sandbox.egress_allow_cidrs","message":"sandbox egress gateway: destination refused by rule private-rfc1918 (to allow a private destination, add its CIDR to [terminal.sandbox].egress_allow_cidrs)"}` + "\n",
		},
		{
			name:    "ssrf floor with html characters",
			r:       Refusal{Host: "<127.0.0.1>&", Rule: RefusalSSRFFloor, Key: KeyEgress},
			message: "sandbox egress gateway: destination refused by rule loopback",
			want:    `{"error":"egress_refused","rule":"ssrf-floor","key":"terminal.sandbox.egress","host":"<127.0.0.1>&","next_step":"none: loopback, link-local and similar addresses are never reachable from a sandboxed run","message":"sandbox egress gateway: destination refused by rule loopback"}` + "\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(RefusalJSON(tc.r, tc.message))
			if got != tc.want {
				t.Fatalf("body\n got %s\nwant %s", got, tc.want)
			}
			var b RefusalBody
			if err := json.Unmarshal([]byte(got), &b); err != nil || b.Message != tc.message {
				t.Fatalf("round trip: %v %+v", err, b)
			}
		})
	}
}

// TestWriteRefusal pins the status and headers of the structured 403.
func TestWriteRefusal(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	WriteRefusal(w, Refusal{Host: "h.example", Rule: RefusalAllowListMiss, Key: KeyEgressAllowHosts}, "m")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	var b RefusalBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || b.Error != RefusalErrorCode || b.Host != "h.example" {
		t.Fatalf("body %v %+v", err, b)
	}
}

// TestRefusalLimiter is the per-(run, host)-per-minute bound and the
// per-run cap, one row per rule.
func TestRefusalLimiter(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 10, 30, 12, 0, 5, 0, time.UTC)
	type step struct {
		run, host string
		at        time.Time
		want      bool
	}
	cases := []struct {
		name  string
		max   int
		steps []step
	}{
		{"first passes, repeat in the same minute does not", 0, []step{
			{"r", "a.example", t0, true},
			{"r", "a.example", t0.Add(30 * time.Second), false},
		}},
		{"the next minute passes again", 0, []step{
			{"r", "a.example", t0, true},
			{"r", "a.example", t0.Add(time.Minute), true},
		}},
		{"another host or run passes", 0, []step{
			{"r", "a.example", t0, true},
			{"r", "b.example", t0, true},
			{"s", "a.example", t0, true},
		}},
		{"per-run cap", 2, []step{
			{"r", "a.example", t0, true},
			{"r", "b.example", t0, true},
			{"r", "c.example", t0, false},
			{"s", "c.example", t0, true},
		}},
		{"an earlier minute does not pass", 0, []step{
			{"r", "a.example", t0.Add(time.Minute), true},
			{"r", "b.example", t0, false},
		}},
		{"another run's later minute does not drop this run's (N1-A3)", 0, []step{
			{"s", "a.example", t0.Add(time.Minute), true},
			{"r", "a.example", t0, true},
			{"r", "b.example", t0, true},
		}},
		{"another run's cap does not count against this run (N1-A3)", 1, []step{
			{"s", "a.example", t0, true},
			{"s", "b.example", t0, false},
			{"r", "b.example", t0, true},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewRefusalLimiter(tc.max)
			for i, s := range tc.steps {
				if got := l.Allow(s.run, s.host, s.at); got != s.want {
					t.Fatalf("step %d: Allow(%q, %q) = %v, want %v", i, s.run, s.host, got, s.want)
				}
			}
		})
	}
}

// TestRefusalLimiterEvictsIdleRuns (audit N1-A3): the per-run state is
// bounded; a new run past the bound evicts the runs idle since an earlier
// minute, and is refused only while every kept run is active this minute.
func TestRefusalLimiterEvictsIdleRuns(t *testing.T) {
	t.Parallel()
	l := NewRefusalLimiter(0)
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for i := range maxLimiterRuns {
		if !l.Allow("run-"+strconv.Itoa(i), "a.example", t0) {
			t.Fatalf("run %d refused", i)
		}
	}
	if l.Allow("late", "a.example", t0) {
		t.Fatal("a run past the bound passed while every kept run was active")
	}
	if !l.Allow("late", "a.example", t0.Add(time.Minute)) {
		t.Fatal("a run past the bound did not evict the idle runs")
	}
	if n := len(l.runs); n != 1 {
		t.Fatalf("%d runs kept after eviction, want 1", n)
	}
}

// TestRefusalLimiterBoundsDistinctHosts: a box cycling through random
// names gets at most the per-run cap through in a minute.
func TestRefusalLimiterBoundsDistinctHosts(t *testing.T) {
	t.Parallel()
	l := NewRefusalLimiter(0)
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	n := 0
	for i := 0; i < 10000; i++ {
		if l.Allow("r", strings.Repeat("x", i%50)+".example"+string(rune('a'+i%26)), at) {
			n++
		}
	}
	if n != DefaultRefusalsPerMinute {
		t.Fatalf("%d passed, want %d", n, DefaultRefusalsPerMinute)
	}
}

// TestRefusalLimiterCheck (lane OC, audit finding OC-A2) names each drop:
// only a host the run's minute already passed is not lost; the cap, an
// earlier minute and a full run table each lose a distinct refusal, which
// a caller keeping a dropped count counts.
func TestRefusalLimiterCheck(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 10, 30, 12, 0, 30, 0, time.UTC)
	l := NewRefusalLimiter(2)
	steps := []struct {
		run, host string
		at        time.Time
		want      RefusalVerdict
		lost      bool
	}{
		{"r", "a.example", t0, RefusalPass, false},
		{"r", "a.example", t0, RefusalSeen, false},
		{"r", "b.example", t0, RefusalPass, false},
		{"r", "c.example", t0, RefusalCapped, true},
		{"r", "d.example", t0.Add(-time.Minute), RefusalEarlier, true},
	}
	for i, s := range steps {
		got := l.Check(s.run, s.host, s.at)
		if got != s.want || got.Lost() != s.lost {
			t.Fatalf("step %d: %v lost=%v, want %v lost=%v", i, got, got.Lost(), s.want, s.lost)
		}
	}
	full := NewRefusalLimiter(0)
	for i := range maxLimiterRuns {
		full.Check("run-"+strconv.Itoa(i), "a.example", t0)
	}
	if got := full.Check("late", "a.example", t0); got != RefusalRunsFull || !got.Lost() {
		t.Fatalf("a full run table: %v", got)
	}
}

// TestNextStepFor (audit finding FU5-A3): one case per refusalKeyNextSteps
// row, and a key no row names falls back to the rule's own text.
func TestNextStepFor(t *testing.T) {
	t.Parallel()
	for _, r := range refusalKeyNextSteps {
		if got := NextStepFor(r.rule, r.key); got != r.text {
			t.Errorf("%s/%s: %q", r.rule, r.key, got)
		}
		if NextStepFor(r.rule, r.key) == NextStep(r.rule) {
			t.Errorf("%s/%s: the row repeats the rule's own text", r.rule, r.key)
		}
	}
	if got := NextStepFor(RefusalAllowListMiss, KeyEgressAllowHosts); got != NextStep(RefusalAllowListMiss) {
		t.Errorf("the owner's list: %q", got)
	}
}
