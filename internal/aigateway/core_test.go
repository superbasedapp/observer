package aigateway

import (
	"reflect"
	"strings"
	"testing"
)

func testRateCard() RateCard {
	return RateCard{
		Version: "test-v1",
		Rates: map[string]ModelRate{
			"claude-opus-4-8": {InPerMTok: 5, OutPerMTok: 25, CacheReadPerMTok: 0.5, CacheWritePerMTok: 6.25},
			"gpt-5.6":         {InPerMTok: 0.2, OutPerMTok: 1.2},
		},
	}
}

func TestRateCardLookupAndEstimate(t *testing.T) {
	rc := testRateCard()

	// Exact + family-prefix fallback.
	if _, ok := rc.Rate("claude-opus-4-8"); !ok {
		t.Error("exact lookup failed")
	}
	if _, ok := rc.Rate("claude-opus-4-8-20260114"); !ok {
		t.Error("family-prefix fallback failed")
	}
	if _, ok := rc.Rate("unknown-model"); ok {
		t.Error("unknown model should not resolve")
	}

	// Estimate: 1M in @5 + 1M out @25 = 30.
	usd, ok := rc.EstimateUSD("claude-opus-4-8", Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000})
	if !ok {
		t.Fatal("estimate ok=false")
	}
	if usd != 30 {
		t.Errorf("estimate = %v, want 30", usd)
	}
	// Unpriced model: authoritative tokens still, but no dollars.
	if _, ok := rc.EstimateUSD("nope", Usage{OutputTokens: 100}); ok {
		t.Error("unpriced model must return ok=false")
	}
}

func TestWorstCaseAndRefund(t *testing.T) {
	rc := testRateCard()
	// worst case: 1000 in @5/M + 4096 out @25/M.
	got := WorstCaseCostUSD(rc, "claude-opus-4-8", 1000, 4096)
	want := 1000.0/1e6*5 + 4096.0/1e6*25
	if got != want {
		t.Errorf("worst case = %v, want %v", got, want)
	}
	// Refund clamps at zero on overrun.
	if r := RefundUSD(0.10, 0.03); r != 0.07 {
		t.Errorf("refund = %v, want 0.07", r)
	}
	if r := RefundUSD(0.03, 0.10); r != 0 {
		t.Errorf("overrun refund = %v, want 0 (clamped)", r)
	}
}

func TestBudgetDenyBody(t *testing.T) {
	o := ReservationOutcome{DeniedLevel: LevelOrg, DeniedScopeID: "org-1", RemainingUSD: 1.5, CapUSD: 100}
	b := NewBudgetDenyBody(o)
	if b.Reason != ReasonBudgetExceeded {
		t.Errorf("reason = %q", b.Reason)
	}
	if !b.Estimated {
		t.Error("deny body must be labeled estimated")
	}
	if !strings.Contains(b.Error, "org") {
		t.Errorf("deny message should name the level: %q", b.Error)
	}
	if b.Level != "org" || b.ScopeID != "org-1" {
		t.Errorf("deny body scope = %q/%q", b.Level, b.ScopeID)
	}
}

func TestModelPolicyResolve(t *testing.T) {
	p := ModelPolicy{
		DefaultAllow:           []string{"gpt-5.6"},
		RoleTiers:              map[string][]string{"senior": {"claude-opus-4-8"}},
		TeamTiers:              map[string][]string{"platform": {"*"}},
		MaxOutputTokens:        map[string]int{"claude-opus-4-8": 8192},
		DefaultMaxOutputTokens: 2048,
	}
	tests := []struct {
		name       string
		pr         Principal
		model      string
		wantAllow  bool
		wantMaxTok int
	}{
		{"default tier", Principal{}, "gpt-5.6", true, 2048},
		{"role grants opus", Principal{Roles: []string{"senior"}}, "claude-opus-4-8", true, 8192},
		{"no tier denies opus", Principal{}, "claude-opus-4-8", false, 0},
		{"team wildcard grants anything", Principal{Teams: []string{"platform"}}, "some-model", true, 2048},
		{"empty model denied", Principal{}, "", false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := p.Resolve(tc.pr, tc.model)
			if v.Allowed != tc.wantAllow {
				t.Errorf("allowed = %v, want %v (%s)", v.Allowed, tc.wantAllow, v.Reason)
			}
			if tc.wantAllow && v.MaxOutputTokens != tc.wantMaxTok {
				t.Errorf("maxTok = %d, want %d", v.MaxOutputTokens, tc.wantMaxTok)
			}
		})
	}
}

func TestModelPolicyFailsClosed(t *testing.T) {
	// An empty policy grants nothing — a misconfigured policy never silently
	// permits arbitrary models (Luna L11 fail-closed default).
	var empty ModelPolicy
	if v := empty.Resolve(Principal{Roles: []string{"anything"}}, "gpt-5.6"); v.Allowed {
		t.Error("empty policy must deny")
	}
}

func TestEffectiveMaxOutputTokens(t *testing.T) {
	p := ModelPolicy{MaxOutputTokens: map[string]int{"claude-opus-4-8": 8192}, DefaultMaxOutputTokens: 2048}
	// Requested below cap: honored.
	if got := p.EffectiveMaxOutputTokens("claude-opus-4-8", 1000, 32000); got != 1000 {
		t.Errorf("got %d, want 1000", got)
	}
	// Requested above cap: clamped to per-model cap.
	if got := p.EffectiveMaxOutputTokens("claude-opus-4-8", 20000, 32000); got != 8192 {
		t.Errorf("got %d, want 8192", got)
	}
	// Unknown model: default cap.
	if got := p.EffectiveMaxOutputTokens("mystery", 0, 32000); got != 2048 {
		t.Errorf("got %d, want 2048", got)
	}
	// No policy cap: hard ceiling.
	var bare ModelPolicy
	if got := bare.EffectiveMaxOutputTokens("x", 0, 32000); got != 32000 {
		t.Errorf("got %d, want 32000", got)
	}
}

func TestParserForKind(t *testing.T) {
	tests := []struct {
		kind ProviderKind
		want Parser
		ok   bool
	}{
		{KindAnthropic, ParserAnthropic, true},
		{KindOpenAICompatible, ParserOpenAI, true},
		{KindAzureOpenAI, ParserOpenAI, true}, // fixes the wrong-parser-fallthrough
		{KindOpenRouter, ParserOpenAI, true},
		{KindLocal, ParserOpenAI, true},
		{KindCustom, ParserOpenAI, true},
		{"bedrock_native", ParserUnsupported, false},
		{"", ParserUnsupported, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.kind), func(t *testing.T) {
			got, ok := ParserForKind(tc.kind)
			if ok != tc.ok || got != tc.want {
				t.Errorf("ParserForKind(%q) = %v,%v want %v,%v", tc.kind, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestPseudonymousMemberID(t *testing.T) {
	a := PseudonymousMemberID("org-1", "user-1")
	b := PseudonymousMemberID("org-1", "user-1")
	c := PseudonymousMemberID("org-1", "user-2")
	if a == "" || len(a) != 32 {
		t.Errorf("pseudonym = %q, want 32 hex", a)
	}
	if a != b {
		t.Error("pseudonym not stable")
	}
	if a == c {
		t.Error("different members must get different pseudonyms")
	}
	if strings.Contains(a, "user-1") {
		t.Error("pseudonym must not contain the raw user id")
	}
	if PseudonymousMemberID("org", "") != "" {
		t.Error("empty user id yields empty pseudonym")
	}
}

func TestUpstreamNormalize(t *testing.T) {
	u := Upstream{Kind: "  ANTHROPIC ", CredentialMode: "", DataControl: "bogus"}.Normalize()
	if u.Kind != KindAnthropic {
		t.Errorf("kind = %q", u.Kind)
	}
	if u.CredentialMode != CredentialSingleOrg {
		t.Errorf("cred mode = %q, want single_org default", u.CredentialMode)
	}
	if u.DataControl != DataControlUnspecified {
		t.Errorf("data control = %q, want unspecified for unknown", u.DataControl)
	}
}

func TestValidators(t *testing.T) {
	if !ValidEconomicOwner(OwnerDeveloper) || ValidEconomicOwner("nope") {
		t.Error("economic-owner validation wrong")
	}
	if NormalizeDataControl("zdr") != DataControlZDR {
		t.Error("data-control normalize wrong")
	}
	if NormalizeCredentialMode("per_developer") != CredentialPerDeveloper {
		t.Error("credential mode normalize wrong")
	}
	if !ValidKind(KindAzureOpenAI) || ValidKind("nope") {
		t.Error("kind validation wrong")
	}
}

func TestStreamLimitsAndAbort(t *testing.T) {
	l := StreamLimits{}.Normalize()
	if l.MaxDuration != DefaultMaxStreamDuration || l.MaxBodyBytes != DefaultMaxBodyBytes ||
		l.PerKeyConcurrency != DefaultPerKeyConcurrency || l.GlobalConcurrency != DefaultGlobalConcurrency {
		t.Error("normalize did not fill defaults")
	}
	if AbortOnScan(ScanClean) || AbortOnScan(ScanNonCritical) {
		t.Error("only critical hits abort")
	}
	if !AbortOnScan(ScanCritical) {
		t.Error("critical hit must abort")
	}
}

func TestConcurrencyLimiter(t *testing.T) {
	lim := NewConcurrencyLimiter(StreamLimits{PerKeyConcurrency: 2, GlobalConcurrency: 3})
	if r := lim.Acquire("k1"); r != LimitNone {
		t.Fatalf("acquire 1 = %q", r)
	}
	if r := lim.Acquire("k1"); r != LimitNone {
		t.Fatalf("acquire 2 = %q", r)
	}
	// k1 at per-key cap.
	if r := lim.Acquire("k1"); r != LimitPerKey {
		t.Errorf("acquire 3 for k1 = %q, want per_key", r)
	}
	// k2 fills the global cap (inflight=3).
	if r := lim.Acquire("k2"); r != LimitNone {
		t.Fatalf("acquire k2 = %q", r)
	}
	if r := lim.Acquire("k2"); r != LimitGlobal {
		t.Errorf("acquire over global = %q, want global", r)
	}
	if lim.Inflight() != 3 {
		t.Errorf("inflight = %d, want 3", lim.Inflight())
	}
	lim.Release("k1")
	if r := lim.Acquire("k2"); r != LimitNone {
		t.Errorf("after release, acquire = %q", r)
	}
}

// TestAuditEventIsMetadataOnly pins the operator ruling (design §2.4.7): the
// gateway stores NO request/response content. It fails if a future edit adds a
// field whose name suggests a body/prompt/completion/content column.
func TestAuditEventIsMetadataOnly(t *testing.T) {
	forbidden := []string{"body", "prompt", "completion", "content", "message", "text", "payload", "response", "header"}
	rt := reflect.TypeOf(AuditEvent{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Errorf("AuditEvent.%s looks like a content field (%q) — the gateway is metadata-only", rt.Field(i).Name, bad)
			}
		}
	}
}
