package planlimits

import (
	"encoding/base64"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

var t0 = time.Unix(1_760_000_000, 0).UTC()

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustValid(t *testing.T, s Snapshot) {
	t.Helper()
	if err := Validate(s); err != nil {
		t.Fatalf("invalid snapshot: %v (%+v)", err, s)
	}
}

func ok200(key string, body string) map[string]Response {
	return map[string]Response{key: {Key: key, Status: 200, Body: []byte(body)}}
}

func fakeJWT(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(claims)) + ".sig"
}

func TestRungTableCoversEveryKind(t *testing.T) {
	for _, k := range AllKinds() {
		if RungOf(k) == "" {
			t.Errorf("kind %q has no rung", k)
		}
	}
}

func TestMicrosFromDecimal(t *testing.T) {
	cases := []struct {
		in    string
		scale int
		want  int64
	}{
		{"110.00", 0, 110_000_000},
		{"0.12", 0, 120_000},
		{"-1000", 2, -10_000_000},
		{"22500", 2, 225_000_000},
		{"3.000001", 0, 3_000_001},
	}
	for _, c := range cases {
		got, err := MicrosFromDecimal(c.in, c.scale)
		if err != nil || got != c.want {
			t.Errorf("MicrosFromDecimal(%q,%d) = %d, %v; want %d", c.in, c.scale, got, err, c.want)
		}
	}
	for _, bad := range []string{"abc", "", "1e400"} {
		if _, err := MicrosFromDecimal(bad, 0); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := newSnap("x", "", KindOfficialAPI, ConfExact, t0)
	ok.Balances = []Balance{{Kind: "prepaid", Unit: UnitUSDMicros, Amount: 1}}
	mustValid(t, ok)
	bad := ok
	bad.Rung = RungBrowser
	if Validate(bad) == nil {
		t.Error("rung mismatch must fail")
	}
	if Validate(newSnap("x", "", KindOfficialAPI, ConfExact, t0)) == nil {
		t.Error("ok snapshot without numbers must fail")
	}
	man := newSnap("x", "", KindManual, ConfExact, t0)
	man.Windows = []Window{{Key: "monthly", Unit: UnitPercent, UsedFrac: F(0.5)}}
	if Validate(man) == nil {
		t.Error("manual must be estimated")
	}
	dup := ok
	dup.Windows = []Window{{Key: "5h", Unit: UnitPercent, UsedFrac: F(0.1)}, {Key: "5h", Unit: UnitPercent, UsedFrac: F(0.2)}}
	if Validate(dup) == nil {
		t.Error("duplicate window must fail")
	}
}

func TestEveryAccountSourceHasADriver(t *testing.T) {
	for _, s := range Sources {
		_, has := Drivers[s.ID]
		if s.Passive && has {
			t.Errorf("passive source %s must not have a driver", s.ID)
		}
		if !s.Passive && !has {
			t.Errorf("source %s has no driver", s.ID)
		}
		if s.Kind == KindBrowser && len(s.Local) > 0 {
			t.Errorf("source %s: a browser session is pasted, never read from this machine", s.ID)
		}
		if len(s.Hosts) > 0 && s.Command != "" {
			t.Errorf("source %s: a source is either network or a vendor command", s.ID)
		}
	}
}

func TestOpenRouter(t *testing.T) {
	s, err := parseOpenRouter(ParseInput{Now: t0, Responses: map[string]Response{
		"key":     {Status: 200, Body: fixture(t, "openrouter_key_capped.json")},
		"credits": {Status: 200, Body: fixture(t, "openrouter_credits.json")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	w, ok := FindWindow(s, "key_cap")
	if !ok || *w.Limit != 500_000_000 || !approx(*w.UsedFrac, 45.457405021/500) || *w.Length != 30*24*time.Hour {
		t.Fatalf("key_cap %+v", w)
	}
	if b, _ := FindBalance(s, "prepaid"); b.Amount != 18_420_000 {
		t.Errorf("prepaid %+v", b)
	}
	s, err = ParseOpenRouterKey(fixture(t, "openrouter_key_unlimited.json"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := FindWindow(s, "key_cap"); ok || len(s.Spend) != 4 {
		t.Errorf("unlimited key: windows %+v spend %d", s.Windows, len(s.Spend))
	}
	if _, err := ParseOpenRouterCredits([]byte(`{"data":{"total_credits":"many","total_usage":1}}`)); !errors.Is(err, ErrShape) {
		t.Errorf("non-number credits: %v", err)
	}
	// The balance left is asked with the key itself (D-681); the management
	// key is an optional fallback for credits.
	reqs, _ := planOpenRouter(PlanInput{Secrets: map[string]string{"key": "K"}})
	if len(reqs) != 2 || reqs[0].SecretHeaders["Authorization"] != "Bearer K" || reqs[0].Header["Authorization"] != "" ||
		reqs[1].Key != "credits" || !reqs[1].Optional || reqs[1].SecretHeaders["Authorization"] != "Bearer K" {
		t.Errorf("plan %+v", reqs)
	}
	reqs, _ = planOpenRouter(PlanInput{Secrets: map[string]string{"key": "K", "mgmt": "M"}})
	if len(reqs) != 3 || reqs[2].Key != "credits_mgmt" || reqs[2].SecretHeaders["Authorization"] != "Bearer M" {
		t.Errorf("plan with management key %+v", reqs)
	}
	// A key OpenRouter refuses credits for falls back to the management key.
	s, err = parseOpenRouter(ParseInput{Now: t0, Responses: map[string]Response{
		"key":          {Status: 200, Body: fixture(t, "openrouter_key_unlimited.json")},
		"credits":      {Status: 403},
		"credits_mgmt": {Status: 200, Body: fixture(t, "openrouter_credits.json")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := FindBalance(s, "prepaid"); !ok || b.Amount != 18_420_000 {
		t.Errorf("fallback prepaid %+v", b)
	}
	if _, err := planOpenRouter(PlanInput{}); !errors.Is(err, ErrAuth) {
		t.Errorf("missing key must be ErrAuth: %v", err)
	}
}

func TestDeepSeek(t *testing.T) {
	doc := `{"is_available":true,"balance_infos":[{"currency":"CNY","total_balance":"110.00","granted_balance":"10.00","topped_up_balance":"100.00"}]}`
	s, err := ParseDeepSeekBalance([]byte(doc), t0)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if b, _ := FindBalance(s, "total"); b.Unit != UnitCNYMicros || b.Amount != 110_000_000 {
		t.Errorf("total %+v", b)
	}
	two := `{"is_available":false,"balance_infos":[{"currency":"USD","total_balance":"3.12","granted_balance":"0.12","topped_up_balance":"3.00"},{"currency":"CNY","total_balance":"0.00","granted_balance":"0.00","topped_up_balance":"0.00"}]}`
	s, _ = ParseDeepSeekBalance([]byte(two), t0)
	if s.Status != StatusThrottled || len(s.Balances) != 6 {
		t.Errorf("status %s balances %d", s.Status, len(s.Balances))
	}
	for _, bad := range []string{
		`{"is_available":true,"balance_infos":[{"currency":"USD","total_balance":3.12,"granted_balance":"0","topped_up_balance":"0"}]}`,
		`{"is_available":true,"balance_infos":[{"currency":"GBP","total_balance":"1","granted_balance":"0","topped_up_balance":"1"}]}`,
		`{"error":{"message":"Authentication Fails"}}`,
		`{"is_available":true,"balance_infos":[]}`,
	} {
		if _, err := ParseDeepSeekBalance([]byte(bad), t0); !errors.Is(err, ErrShape) {
			t.Errorf("want ErrShape for %s, got %v", bad, err)
		}
	}
}

func TestMoonshotAndKimiCode(t *testing.T) {
	doc := `{"code":0,"data":{"available_balance":49.58894,"voucher_balance":46.58893,"cash_balance":3.00001},"scode":"0x0","status":true}`
	s, err := ParseMoonshotBalance("global", []byte(doc), t0)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if b, _ := FindBalance(s, "total"); b.Amount != 49_588_940 || b.Unit != UnitUSDMicros {
		t.Errorf("total %+v", b)
	}
	deficit := `{"code":0,"data":{"available_balance":50,"voucher_balance":50,"cash_balance":-0.42},"scode":"0x0","status":true}`
	s, _ = ParseMoonshotBalance("china", []byte(deficit), t0)
	if b, _ := FindBalance(s, "cash"); b.Amount != -420_000 || b.Unit != UnitCNYMicros {
		t.Errorf("cash deficit %+v", b)
	}
	if _, err := ParseMoonshotBalance("evil", []byte(doc), t0); err == nil {
		t.Error("unknown region must be refused")
	}
	if reqs, _ := planMoonshot(PlanInput{Params: map[string]string{"region": "china"}, Secrets: map[string]string{"key": "K"}}); !strings.HasPrefix(reqs[0].URL, "https://api.moonshot.cn/") {
		t.Errorf("china host %v", reqs)
	}

	counts := `{"usage":{"limit":"2048","used":"375","remaining":"1673","resetTime":"2026-01-09T15:23:13.373329235Z"},
	 "limits":[{"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},
	   "detail":{"limit":"200","used":"19","remaining":"181","resetTime":"2026-01-06T15:05:24.374187075Z"}}]}`
	s, err = ParseKimiCodeUsages([]byte(counts), t0)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if s.Rung != RungExperimental {
		t.Errorf("undocumented endpoint must be rung 2, got %s", s.Rung)
	}
	w5, _ := FindWindow(s, "5h")
	wk, _ := FindWindow(s, "weekly")
	if !approx(*w5.UsedFrac, 19.0/200) || !approx(*wk.UsedFrac, 375.0/2048) {
		t.Errorf("5h %+v weekly %+v", w5, wk)
	}
	ratio := `{"usages":{"limit_5h":{"used_ratio":0,"reset_time":"2026-09-16T20:15:44Z"},
	 "limit_7d":{"used_ratio":0.125,"reset_time":"2026-09-20T00:00:00Z"},
	 "limit_month_total":{"used_ratio":0.0056,"reset_time":"2026-10-17T00:00:00Z"}},
	 "user":{"membership":{"level":"LEVEL_ADVANCED"}}}`
	s, err = ParseKimiCodeUsages([]byte(ratio), t0)
	if err != nil || len(s.Windows) != 3 || s.PlanCode != "LEVEL_ADVANCED" {
		t.Errorf("ratio form %+v %v", s, err)
	}
	if _, err := ParseKimiCodeUsages([]byte(`{}`), t0); !errors.Is(err, ErrShape) {
		t.Error("empty body must fail, never zero")
	}
}

func TestXAI(t *testing.T) {
	cases := map[string]int64{`"-1000"`: 10_000_000, `"2500"`: -25_000_000, `"0"`: 0, `"-27481"`: 274_810_000}
	for val, want := range cases {
		got, err := ParseXAIBalance([]byte(`{"total":{"val":` + val + `}}`))
		if err != nil || got != want {
			t.Errorf("%s: got %d %v want %d", val, got, err, want)
		}
	}
	for _, bad := range []string{`{"total":{"val":"abc"}}`, `{"total":{}}`, `{}`} {
		if _, err := ParseXAIBalance([]byte(bad)); err == nil {
			t.Errorf("%s must fail (never $0)", bad)
		}
	}
	s, err := parseXAI(ParseInput{Now: t0, Responses: map[string]Response{
		"balance": {Status: 200, Body: []byte(`{"total":{"val":"-27481"}}`)},
		"invoice": {Status: 200, Body: []byte(`{"coreInvoice":{"amountAfterVat":"13364"},"effectiveSpendingLimit":"20000","billingCycle":{"year":2025,"month":11}}`)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if b, _ := FindBalance(s, "prepaid"); b.Amount != 141_170_000 || s.Confidence != ConfEstimated {
		t.Errorf("live remaining %+v conf %s", b, s.Confidence)
	}
	if w, ok := FindWindow(s, "spend_limit"); !ok || !approx(*w.UsedFrac, 133.64/200) || w.ResetsAt.Format("2006-01-02") != "2025-12-01" {
		t.Errorf("spend limit %+v", w)
	}
	// Invoice failure: posted only, exact.
	s, _ = parseXAI(ParseInput{Now: t0, Responses: map[string]Response{
		"balance": {Status: 200, Body: []byte(`{"total":{"val":"-1000"}}`)},
		"invoice": {Status: 500},
	}})
	if s.Confidence != ConfExact || len(s.Balances) != 1 {
		t.Errorf("posted-only %+v", s)
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a?x=1", "a%2F"} {
		if _, err := XAITeamURL(bad, ""); err == nil {
			t.Errorf("team id %q must be refused", bad)
		}
	}
}

func TestCopilotBilling(t *testing.T) {
	doc := `{"timePeriod":{"year":2026,"month":10},"user":"octo","usageItems":[
	 {"grossQuantity":320,"discountQuantity":300,"netAmount":0.8},{"grossQuantity":10,"discountQuantity":0,"netAmount":0.4}]}`
	in := ParseInput{Now: t0, Params: map[string]string{}, Responses: map[string]Response{"premium": {Status: 200, Body: []byte(doc)}, "ai_credit": {Status: 404}}}
	s, err := parseCopilotBilling(in)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	w, _ := FindWindow(s, "monthly:premium_requests")
	if *w.Used != 330 || w.Limit != nil || w.ResetsAt.Format("2006-01-02") != "2026-11-01" {
		t.Errorf("window %+v (no allowance means no limit)", w)
	}
	if s.Spend[0].Amount != 1_200_000 {
		t.Errorf("net spend %d", s.Spend[0].Amount)
	}
	in.Params["allowance"] = "300"
	s, _ = parseCopilotBilling(in)
	w, _ = FindWindow(s, "monthly:premium_requests")
	if *w.Limit != 300 || !approx(*w.UsedFrac, 1.1) || s.Confidence != ConfEstimated {
		t.Errorf("allowance %+v conf %s", w, s.Confidence)
	}
	empty := ParseInput{Now: t0, Responses: ok200("premium", `{"timePeriod":{"year":2026,"month":10},"usageItems":[]}`)}
	s, err = parseCopilotBilling(empty)
	if err != nil || s.Status != StatusBilledElse || len(s.Windows) != 0 {
		t.Errorf("org billed must be billed_elsewhere, never zero: %+v %v", s, err)
	}
	if _, err := planCopilotBilling(PlanInput{Now: t0, Params: map[string]string{"username": "../x"}, Secrets: map[string]string{"pat": "P"}}); err == nil {
		t.Error("bad username must be refused")
	}
	reqs, err := planCopilotBilling(PlanInput{Now: t0, Params: map[string]string{"username": "octo-cat"}, Secrets: map[string]string{"pat": "P"}})
	if err != nil || !strings.Contains(reqs[0].URL, "/users/octo-cat/settings/billing/premium_request/usage?year=") {
		t.Errorf("plan %v %v", reqs, err)
	}
}

func TestHTTPStatusClassification(t *testing.T) {
	cases := map[int]error{401: ErrAuth, 403: ErrAuth, 429: ErrRateLimited, 503: ErrRateLimited, 404: ErrGone, 500: ErrTransient}
	for code, want := range cases {
		_, err := parseDeepSeek(ParseInput{Responses: map[string]Response{"main": {Status: code}}})
		if !errors.Is(err, want) {
			t.Errorf("%d: %v want %v", code, err, want)
		}
	}
}

func TestClaudeOAuthNeverRefreshes(t *testing.T) {
	now := time.Date(2026, 7, 2, 20, 0, 0, 0, time.UTC)
	creds := `{"claudeAiOauth":{"accessToken":"FAKE-ACCESS","refreshToken":"FAKE-REFRESH","expiresAt":1783036800000,"scopes":["user:inference","user:profile"],"rateLimitTier":"default_claude_max_20x"}}`
	reqs, err := planClaudeOAuth(PlanInput{Now: now, Local: map[string][]byte{"creds": []byte(creds)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].SecretHeaders["Authorization"] != "Bearer FAKE-ACCESS" || reqs[0].Header["Authorization"] != "" {
		t.Fatalf("token must only ride SecretHeaders: %+v", reqs)
	}
	for _, r := range reqs {
		if strings.Contains(r.URL, "refresh") || strings.Contains(string(r.Body), "FAKE-REFRESH") {
			t.Fatal("never refresh another app's token")
		}
	}
	if _, err := planClaudeOAuth(PlanInput{Now: time.UnixMilli(1783036800000 - 30_000), Local: map[string][]byte{"creds": []byte(creds)}}); !errors.Is(err, ErrAuth) {
		t.Errorf("inside the 60 s margin must be ErrAuth: %v", err)
	}
	noScope := strings.Replace(creds, `"user:profile"`, `"x"`, 1)
	if _, err := planClaudeOAuth(PlanInput{Now: now, Local: map[string][]byte{"creds": []byte(noScope)}}); !errors.Is(err, ErrAuth) {
		t.Errorf("scope: %v", err)
	}
	if _, err := planClaudeOAuth(PlanInput{Now: now}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no file: %v", err)
	}
	usage := `{"five_hour":{"utilization":11.0,"resets_at":"2026-07-03T00:30:00.282668+00:00"},
	 "seven_day":{"utilization":9.0,"resets_at":"2026-07-08T09:00:00.282694+00:00"},"seven_day_opus":null,
	 "extra_usage":{"is_enabled":true,"monthly_limit":2050,"used_credits":325,"currency":"USD"},
	 "limits":[{"kind":"weekly_scoped","percent":5,"resets_at":"2026-07-08T09:00:00.283070+00:00","scope":{"model":{"display_name":"Fable"}}}]}`
	s, err := parseClaudeOAuth(ParseInput{Now: now, Local: map[string][]byte{"creds": []byte(creds)}, Responses: ok200("usage", usage)})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if s.Rung != RungExperimental || s.PlanCode != "max_20x" {
		t.Errorf("rung %s plan %s", s.Rung, s.PlanCode)
	}
	if _, ok := FindWindow(s, "model:opus"); ok {
		t.Error("null window must be absent")
	}
	if _, ok := FindWindow(s, "model:fable"); !ok {
		t.Error("scoped weekly window missing")
	}
	if ex, _ := FindWindow(s, "extra_usage"); *ex.Used != 3_250_000 || *ex.Limit != 20_500_000 {
		t.Errorf("cents to micros %+v", ex)
	}
}

func TestChatGPTWebUsage(t *testing.T) {
	now := time.Unix(1776200000, 0)
	auth := `{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"access_token":"` + fakeJWT(`{"exp":`+strconv.FormatInt(now.Unix()+3600, 10)+`}`) + `","refresh_token":"FAKE","account_id":"acct-TEST"}}`
	reqs, err := planWham(PlanInput{Now: now, Local: map[string][]byte{"auth": []byte(auth)}})
	if err != nil || reqs[0].SecretHeaders["ChatGPT-Account-Id"] != "acct-TEST" {
		t.Fatalf("plan %+v %v", reqs, err)
	}
	if _, err := planWham(PlanInput{Now: now.Add(56 * time.Minute), Local: map[string][]byte{"auth": []byte(auth)}}); !errors.Is(err, ErrAuth) {
		t.Errorf("within 5 minutes of expiry must skip: %v", err)
	}
	if _, err := planWham(PlanInput{Now: now, Local: map[string][]byte{"auth": []byte(`{"OPENAI_API_KEY":"sk-FAKE"}`)}}); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("api key mode: %v", err)
	}
	team := `{"plan_type":"team","rate_limit":{"limit_reached":true,
	  "primary_window":{"used_percent":100,"limit_window_seconds":604800,"reset_at":1786161204},"secondary_window":null},
	 "credits":{"has_credits":true,"unlimited":false,"balance":21},
	 "additional_rate_limits":[{"limit_name":"GPT-5.3-Codex-Spark","metered_feature":"gpt_5_3_codex_spark",
	   "rate_limit":{"secondary_window":{"used_percent":100,"reset_at":1767407914,"limit_window_seconds":604800}}}]}`
	s, err := ParseWhamUsage([]byte(team), now)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if _, ok := FindWindow(s, "5h"); ok || s.Status != StatusThrottled {
		t.Errorf("weekly-only must not synthesize 5h; status %s", s.Status)
	}
	if b, _ := FindBalance(s, "credits"); b.Amount != 21 {
		t.Errorf("credits %+v", b)
	}
	if _, ok := FindWindow(s, "model:gpt_5_3_codex_spark:weekly"); !ok {
		t.Error("extra limit missing")
	}
}

func TestCursorApp(t *testing.T) {
	now := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
	jwt := fakeJWT(`{"sub":"auth0|user_TEST","exp":1736990000}`)
	reqs, err := planCursor(PlanInput{Now: now, Local: map[string][]byte{"token": []byte(jwt)}})
	if err != nil || !strings.HasPrefix(reqs[0].SecretHeaders["Cookie"], "WorkosCursorSessionToken=user_TEST%3A%3A") {
		t.Fatalf("plan %+v %v", reqs, err)
	}
	if _, err := CursorCookie(jwt, time.Unix(1736990000-30, 0)); !errors.Is(err, ErrAuth) {
		t.Errorf("near expiry: %v", err)
	}
	pro := `{"billingCycleStart":"2025-01-01T00:00:00.000Z","billingCycleEnd":"2025-02-01T00:00:00.000Z","membershipType":"pro",
	 "individualUsage":{"plan":{"enabled":true,"used":1500,"limit":5000,"totalPercentUsed":30.0,"autoPercentUsed":0.36},
	   "onDemand":{"enabled":true,"used":500,"limit":10000}}}`
	s, err := ParseCursorSummary([]byte(pro), now)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	c, _ := FindWindow(s, "cycle")
	if !approx(*c.UsedFrac, 0.30) || *c.Used != 15_000_000 || *c.Length != 31*24*time.Hour {
		t.Errorf("cycle %+v", c)
	}
	if a, _ := FindWindow(s, "cycle:auto"); !approx(*a.UsedFrac, 0.0036) {
		t.Errorf("percent units: %+v", a)
	}
	ent := `{"membershipType":"enterprise","billingCycleEnd":"2026-05-01T00:00:00.000Z",
	 "individualUsage":{"overall":{"enabled":true,"used":7384,"limit":10000}},
	 "teamUsage":{"pooled":{"enabled":true,"used":12725135,"limit":28122000}}}`
	s, _ = ParseCursorSummary([]byte(ent), now)
	if _, ok := FindWindow(s, "team_pool"); !ok {
		t.Error("pooled missing")
	}
}

func TestWindsurfCache(t *testing.T) {
	now := time.Unix(1774000000, 0)
	v := `{"planName":"Pro","endTimestamp":1774029950000,
	 "quotaUsage":{"dailyRemainingPercent":9,"weeklyRemainingPercent":54,"dailyResetAtUnix":1774080000,"weeklyResetAtUnix":1774166400}}`
	s, err := parseWindsurf(ParseInput{Now: now, Local: map[string][]byte{"plan": []byte(v)}})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	d, _ := FindWindow(s, "daily")
	if !approx(*d.UsedFrac, 0.91) || d.ResetsAt.Unix() != 1774080000 || s.Rung != RungExperimental {
		t.Errorf("daily %+v rung %s", d, s.Rung)
	}
	legacy := `{"planName":"Pro","endTimestamp":1774029950000,"usage":{"messages":50000,"usedMessages":35650}}`
	s, err = ParseWindsurfPlanInfo([]byte(legacy), now)
	if err != nil || !approx(*s.Windows[0].UsedFrac, 0.713) {
		t.Errorf("legacy %+v %v", s.Windows, err)
	}
	if reqs, err := Drivers[SourceWindsurfCache].Plan(PlanInput{}); err != nil || len(reqs) != 0 {
		t.Error("the Windsurf cache source makes no network call")
	}
}

func TestCLIReporters(t *testing.T) {
	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	kiro := "\x1b[1mEstimated Usage\x1b[0m | resets on 2026-06-01 | \x1b[mKIRO FREE\x1b[0m\n\n" +
		"Bonus credits: 45.53/2000 credits used, expires in 19 days\n\n" +
		"\x1b[1mCredits\x1b[0m (0.17 of 50 covered in plan)\n" +
		"████ 0%\n\nOverages: \x1b[1mDisabled\x1b[0m\n"
	s, err := parseCLI(t, SourceKiroCLI, kiro, now)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := FindWindow(s, "monthly")
	if s.PlanLabel != "KIRO FREE" || *w.Used != 0.17 || *w.Limit != 50 || w.ResetsAt.Format("2006-01-02") != "2026-06-01" {
		t.Errorf("kiro %q %+v", s.PlanLabel, w)
	}
	managed := "Plan: Q Developer Pro\nYour plan is managed by admin\n"
	if s, err := ParseKiroUsage(managed, now); err != nil || s.Status != StatusPlanOnly {
		t.Errorf("managed %+v %v", s, err)
	}
	if _, err := ParseKiroUsage("Failed to initialize auth portal.\nkiro-cli login", now); !errors.Is(err, ErrAuth) {
		t.Errorf("login: %v", err)
	}
	if _, err := ParseKiroUsage("something else", now); !errors.Is(err, ErrShape) {
		t.Errorf("unknown: %v", err)
	}

	amp := "Signed in as fixture@example.test (example)\n" +
		"Amp Free: 61% remaining today (resets daily) - https://ampcode.com/settings#amp-free\n" +
		"Subscription Gigawatt: 73% other usage and 91% orb usage remaining - resets upon renewal in 1 month\n" +
		"Individual credits: $17.23 remaining (set up auto-reload) - https://ampcode.com/settings\n" +
		"Workspace meow: $5.33 remaining - https://ampcode.com/workspaces/meow\n"
	s, err = parseCLI(t, SourceAmpCLI, amp, now)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := FindWindow(s, "cycle:agent"); !approx(*a.UsedFrac, 0.27) {
		t.Errorf("agent %+v", a)
	}
	if b, _ := FindBalance(s, "prepaid"); b.Amount != 17_230_000 {
		t.Errorf("individual %+v", b)
	}
	if strings.Contains(s.PlanLabel, "fixture@") {
		t.Error("the identity line must never be stored")
	}
	tier := "Signed in as user@example.com\n" +
		"Amp Megawatt Tier: agent usage $18.57 of $20 remaining (93%), orb usage 732.8h of 750h remaining (98%) - period 2026-09-13 to 2026-10-13, resets upon renewal in 27 days\n"
	s, _ = ParseAmpUsage(tier, now)
	if a, _ := FindWindow(s, "cycle:agent"); s.PlanLabel != "Megawatt" || !approx(*a.UsedFrac, 1.43/20) || a.ResetsAt.Format("2006-01-02") != "2026-10-13" {
		t.Errorf("tier %q %+v", s.PlanLabel, a)
	}
	if _, err := ParseAmpUsage("Please sign in to continue", now); !errors.Is(err, ErrAuth) {
		t.Errorf("amp login: %v", err)
	}

	box := "╭ Account ╮\n│ 319,054 credits remaining   Max Plan │\n│ 450,000 credits / month │\n\n   9 days remaining in this billing cycle (ends 6/9/2026)\n"
	s, err = parseCLI(t, SourceAugmentCLI, box, now)
	if err != nil {
		t.Fatal(err)
	}
	w = s.Windows[0]
	if *w.Remaining != 319054 || *w.Limit != 450000 || *w.Used != 130946 || w.ResetsAt.Format("2006-01-02") != "2026-06-09" {
		t.Errorf("auggie %+v", w)
	}
	if _, err := ParseAuggieStatus("Authentication failed. Run auggie login", now); !errors.Is(err, ErrAuth) {
		t.Errorf("auggie login %v", err)
	}
	// The CLI argv is fixed by the table; no shell, no user input.
	reqs, _ := Drivers[SourceKiroCLI].Plan(PlanInput{Params: map[string]string{"x": "; rm -rf /"}})
	if strings.Join(reqs[0].Argv, " ") != "kiro-cli chat --no-interactive /usage" || reqs[0].Kind != ReqExec {
		t.Errorf("argv %v", reqs[0].Argv)
	}
}

func parseCLI(t *testing.T, src, out string, now time.Time) (Snapshot, error) {
	t.Helper()
	s, err := Drivers[src].Parse(ParseInput{Now: now, Responses: map[string]Response{"out": {Body: []byte(out)}}})
	if err == nil {
		mustValid(t, s)
	}
	return s, err
}

func TestManualEntry(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	s, err := ManualSnapshot(ProviderCursor, map[string]string{"plan": "Pro", "unit": "usd", "allowance": "20", "renews_day": "2"}, now)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	w := s.Windows[0]
	if *w.Limit != 20_000_000 || w.Used != nil || w.ResetsAt.Format("2006-01-02") != "2026-11-02" || s.Confidence != ConfEstimated {
		t.Errorf("manual %+v", w)
	}
	// Observed spend fills "used" (already micros); a typed value wins.
	s, _ = ManualSnapshot(ProviderCursor, map[string]string{"unit": "usd", "allowance": "20", ParamObservedUsed: "5000000"}, now)
	if !approx(*s.Windows[0].UsedFrac, 0.25) {
		t.Errorf("observed %+v", s.Windows[0])
	}
	s, _ = ManualSnapshot(ProviderCursor, map[string]string{"unit": "usd", "allowance": "20", "used": "10", ParamObservedUsed: "5000000"}, now)
	if !approx(*s.Windows[0].UsedFrac, 0.5) {
		t.Errorf("typed %+v", s.Windows[0])
	}
	for _, bad := range []map[string]string{{"unit": "usd"}, {"unit": "yen", "allowance": "1"}, {"unit": "usd", "allowance": "-1"}} {
		if _, err := ManualSnapshot(ProviderOther, bad, now); err == nil {
			t.Errorf("%v must fail", bad)
		}
	}
	cases := []struct {
		window string
		day    int
		start  string
		end    string
	}{
		{"monthly", 31, "2026-09-30", "2026-10-31"},
		{"monthly", 13, "2026-10-13", "2026-11-13"},
		{"monthly", 20, "2026-09-20", "2026-10-20"},
		{"weekly", 0, "2026-10-12", "2026-10-19"},
		{"daily", 0, "2026-10-13", "2026-10-14"},
	}
	for _, c := range cases {
		st, en := ManualWindowStart(c.window, c.day, now)
		if st.Format("2006-01-02") != c.start || en.Format("2006-01-02") != c.end {
			t.Errorf("%s/%d: %s..%s want %s..%s", c.window, c.day, st.Format("2006-01-02"), en.Format("2006-01-02"), c.start, c.end)
		}
	}
}
