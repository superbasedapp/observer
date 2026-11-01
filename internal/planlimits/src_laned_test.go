package planlimits

import (
	"bufio"
	"bytes"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fixtureD reads a lane D fixture.
func fixtureD(t *testing.T, name string) []byte {
	t.Helper()
	return fixture(t, "laned/"+name)
}

// laneDInputs are complete plan inputs for every lane D network source.
func laneDInputs(t *testing.T) map[string]PlanInput {
	return map[string]PlanInput{
		SourceOpenAIAdmin:    {Now: t0, Secrets: map[string]string{"mgmt": "sk-admin-fixture"}, Params: map[string]string{"project_id": "proj_abc123"}},
		SourceOpenAIGrants:   {Now: t0, Secrets: map[string]string{"key": "sk-fixture"}},
		SourceAnthropicAdmin: {Now: t0, Secrets: map[string]string{"mgmt": "sk-ant-admin-fixture"}},
		SourceBedrockBudget: {Now: t0, Secrets: map[string]string{"aws_secret": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}, Params: map[string]string{
			"access_key_id": "AKIAIOSFODNN7EXAMPLE", "account_id": "123456789012", "budget_name": "bedrock-monthly",
		}},
		SourceNousHermes: {Now: t0, Local: map[string][]byte{"auth": fixtureD(t, "nous_auth.json")}},
		SourceMuseWeb:    {Now: t0, Secrets: map[string]string{"session": "Cookie: llama_dev_sess=fixture-session"}, Params: map[string]string{"team_id": "1234567890"}},
	}
}

// secretValues are the credential strings that must only travel in
// SecretHeaders.
var secretValuesD = []string{"sk-admin-fixture", "sk-fixture", "sk-ant-admin-fixture", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "fixture-nous-token", "fixture-session", "fixture-refresh-never-used"}

func TestLaneDPlansStayInsideTheirHosts(t *testing.T) {
	for id, in := range laneDInputs(t) {
		src, ok := SourceByID(id)
		if !ok {
			t.Fatalf("%s: no source row", id)
		}
		reqs, err := Drivers[id].Plan(in)
		if err != nil || len(reqs) == 0 {
			t.Fatalf("%s: plan %v %v", id, reqs, err)
		}
		for _, r := range reqs {
			u, err := url.Parse(r.URL)
			if err != nil || u.Scheme != "https" {
				t.Fatalf("%s: url %q", id, r.URL)
			}
			hostOK := false
			for _, h := range src.Hosts {
				hostOK = hostOK || h == u.Host
			}
			if !hostOK {
				t.Errorf("%s: host %q not in %v", id, u.Host, src.Hosts)
			}
			if len(r.SecretHeaders) == 0 {
				t.Errorf("%s: no secret header", id)
			}
			plain := r.URL + string(r.Body)
			for k, v := range r.Header {
				plain += k + v
			}
			for _, s := range secretValuesD {
				if strings.Contains(plain, s) {
					t.Errorf("%s: secret %q outside SecretHeaders", id, s)
				}
			}
		}
		// A missing credential is a sign-in problem, never a request.
		bare := in
		bare.Secrets, bare.Local = nil, nil
		if _, err := Drivers[id].Plan(bare); !errors.Is(err, ErrAuth) && !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: missing credential: %v", id, err)
		}
	}
}

// TestLaneDAuthHeaders pins how each credential travels.
func TestLaneDAuthHeaders(t *testing.T) {
	cases := []struct {
		src, header, prefix string
	}{
		{SourceOpenAIAdmin, "Authorization", "Bearer sk-admin-fixture"},
		{SourceOpenAIGrants, "Authorization", "Bearer sk-fixture"},
		{SourceAnthropicAdmin, "x-api-key", "sk-ant-admin-fixture"},
		{SourceBedrockBudget, "Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20251009/us-east-1/budgets/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature="},
		{SourceNousHermes, "Authorization", "Bearer fixture-nous-token"},
		{SourceMuseWeb, "Cookie", "llama_dev_sess=fixture-session"},
	}
	ins := laneDInputs(t)
	for _, c := range cases {
		reqs, err := Drivers[c.src].Plan(ins[c.src])
		if err != nil {
			t.Fatal(err)
		}
		got := reqs[0].SecretHeaders[c.header]
		if !strings.HasPrefix(got, c.prefix) || len(reqs[0].SecretHeaders) != 1 {
			t.Errorf("%s: %s = %q (all %d), want prefix %q", c.src, c.header, got, len(reqs[0].SecretHeaders), c.prefix)
		}
	}
}

func TestLaneDPlanURLs(t *testing.T) {
	ins := laneDInputs(t)
	want := map[string]string{
		SourceOpenAIAdmin:    "https://api.openai.com/v1/organization/costs?bucket_width=1d&limit=31&project_ids=proj_abc123&start_time=1759276800",
		SourceOpenAIGrants:   "https://api.openai.com/v1/dashboard/billing/credit_grants",
		SourceAnthropicAdmin: "https://api.anthropic.com/v1/organizations/cost_report?bucket_width=1d&limit=31&starting_at=2025-10-01T00%3A00%3A00Z",
		SourceBedrockBudget:  "https://budgets.amazonaws.com/",
		SourceNousHermes:     "https://portal.nousresearch.com/api/oauth/account",
		SourceMuseWeb:        "https://dev.meta.ai/api/portal/teams/1234567890/subscription-quota",
	}
	for id, u := range want {
		reqs, _ := Drivers[id].Plan(ins[id])
		if reqs[0].URL != u {
			t.Errorf("%s: url %q, want %q", id, reqs[0].URL, u)
		}
	}
	reqs, _ := Drivers[SourceBedrockBudget].Plan(ins[SourceBedrockBudget])
	r := reqs[0]
	if r.Method != "POST" || r.Header["X-Amz-Target"] != "AWSBudgetServiceGateway.DescribeBudget" ||
		r.Header["Content-Type"] != "application/x-amz-json-1.1" || r.Header["X-Amz-Date"] != "20251009T085320Z" ||
		string(r.Body) != `{"AccountId":"123456789012","BudgetName":"bedrock-monthly"}` {
		t.Errorf("bedrock request %+v %s", r.Header, r.Body)
	}
	areqs, _ := Drivers[SourceAnthropicAdmin].Plan(ins[SourceAnthropicAdmin])
	if areqs[0].Header["anthropic-version"] != AnthropicAdminVersion {
		t.Errorf("anthropic version header %v", areqs[0].Header)
	}

	// Parameters that could escape a path or a query are refused.
	bad := []struct {
		src, key, val string
	}{
		{SourceOpenAIAdmin, "project_id", "proj_x&limit=1"},
		{SourceMuseWeb, "team_id", "../teams"},
		{SourceBedrockBudget, "account_id", "12345"},
		{SourceBedrockBudget, "access_key_id", "akia lower"},
		{SourceBedrockBudget, "budget_name", "a:b"},
	}
	for _, b := range bad {
		in := ins[b.src]
		p := map[string]string{}
		for k, v := range in.Params {
			p[k] = v
		}
		p[b.key] = b.val
		in.Params = p
		if _, err := Drivers[b.src].Plan(in); err == nil {
			t.Errorf("%s: %s=%q must be refused", b.src, b.key, b.val)
		}
	}
}

// TestSigV4KnownVectors checks the signer against AWS's published examples
// (the SigV4 test suite get-vanilla case and the IAM ListUsers walkthrough).
func TestSigV4KnownVectors(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	const akid, sec = "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	cases := []struct {
		name string
		in   SigV4Input
		sig  string
	}{
		{
			name: "get-vanilla",
			in:   SigV4Input{Method: "GET", Host: "example.amazonaws.com", Path: "/", Region: "us-east-1", Service: "service"},
			sig:  "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		},
		{
			name: "iam-listusers",
			in: SigV4Input{
				Method: "GET", Host: "iam.amazonaws.com", Path: "/", Query: "Action=ListUsers&Version=2010-05-08",
				Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}, Region: "us-east-1", Service: "iam",
			},
			sig: "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
		},
	}
	for _, c := range cases {
		c.in.AccessKeyID, c.in.Secret, c.in.Time = akid, sec, at
		auth, date := SigV4Sign(c.in)
		if date != "20150830T123600Z" || !strings.HasSuffix(auth, "Signature="+c.sig) {
			t.Errorf("%s: %s (%s)", c.name, auth, date)
		}
	}
}

func TestLaneDParsers(t *testing.T) {
	reset := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	cases := []struct {
		name  string
		parse func() (Snapshot, error)
		check func(t *testing.T, s Snapshot)
	}{
		{"openai costs", func() (Snapshot, error) { return ParseOpenAICosts(fixtureD(t, "openai_costs.json"), t0) }, func(t *testing.T, s Snapshot) {
			if len(s.Spend) != 2 || s.Spend[0] != (Spend{Period: "month", Unit: UnitUSDMicros, Amount: 3_850_000, Scope: "account"}) ||
				s.Spend[1].Period != "day" || s.Spend[1].Amount != 2_100_000 {
				t.Errorf("spend %+v", s.Spend)
			}
		}},
		{"openai credit grants", func() (Snapshot, error) {
			return ParseOpenAICreditGrants(fixtureD(t, "openai_credit_grants.json"), t0)
		}, func(t *testing.T, s Snapshot) {
			if b, _ := FindBalance(s, "available"); b.Amount != 12_750_000 || s.Kind != KindUndocumented || s.Rung != RungExperimental {
				t.Errorf("grants %+v", s)
			}
		}},
		{"anthropic cost report", func() (Snapshot, error) {
			return ParseAnthropicCostReport(fixtureD(t, "anthropic_cost_report.json"), t0)
		}, func(t *testing.T, s Snapshot) {
			if s.Spend[0].Amount != 198_450_000 || s.Spend[1].Period != "day" || s.Spend[1].Amount != 50_000_000 {
				t.Errorf("spend %+v", s.Spend)
			}
		}},
		{"aws budget", func() (Snapshot, error) { return ParseAWSBudget(fixtureD(t, "aws_budget.json"), t0) }, func(t *testing.T, s Snapshot) {
			w, _ := FindWindow(s, "monthly")
			if *w.Used != 87_420_000 || *w.Limit != 250_000_000 || *w.Remaining != 162_580_000 || !w.ResetsAt.Equal(reset("2025-11-01T00:00:00Z")) {
				t.Errorf("budget %+v", w)
			}
			if s.Spend[0].Period != "month" || s.Spend[0].Amount != 87_420_000 {
				t.Errorf("spend %+v", s.Spend)
			}
		}},
		{"grok billing", func() (Snapshot, error) { return ParseGrokBilling(fixtureD(t, "grok_billing.json"), t0) }, func(t *testing.T, s Snapshot) {
			w, ok := FindWindow(s, "monthly")
			if !ok || *w.Used != 123_450_000 || *w.Limit != 999_000_000 || *w.Length != 31*24*time.Hour {
				t.Errorf("monthly %+v", s.Windows)
			}
			od, ok := FindWindow(s, "on_demand")
			if !ok || *od.Used != 0 || *od.Limit != 50_000_000 {
				t.Errorf("an empty cents object is a confirmed zero: %+v", od)
			}
		}},
		{"jetbrains quota", func() (Snapshot, error) {
			return ParseJetBrainsQuota(fixtureD(t, "jetbrains_quota.xml"), t0)
		}, func(t *testing.T, s Snapshot) {
			w, _ := FindWindow(s, "monthly")
			if !approx(*w.Used, 2.5) || !approx(*w.Limit, 10) || !approx(*w.Remaining, 7.5) || w.Unit != UnitAICredits || *w.Length != 720*time.Hour {
				t.Errorf("monthly %+v", w)
			}
			if b, _ := FindBalance(s, "credits"); b.Amount != 54 || s.Confidence != ConfEstimated {
				t.Errorf("top-up %+v", s)
			}
		}},
		{"nous account", func() (Snapshot, error) { return ParseNousAccount(fixtureD(t, "nous_account.json"), t0) }, func(t *testing.T, s Snapshot) {
			w, _ := FindWindow(s, "monthly")
			if *w.Used != 165_000_000 || *w.Remaining != 55_000_000 || s.PlanLabel != "Ultra" {
				t.Errorf("monthly %+v %q", w, s.PlanLabel)
			}
			if b, _ := FindBalance(s, "topup"); b.Amount != 19_250_000 {
				t.Errorf("top-up %+v", s.Balances)
			}
		}},
		{"muse team quota", func() (Snapshot, error) { return ParseMuseTeamQuota(fixtureD(t, "muse_quota.json"), t0) }, func(t *testing.T, s Snapshot) {
			five, _ := FindWindow(s, "5h")
			week, _ := FindWindow(s, "weekly")
			if !approx(*five.UsedFrac, 0.3) || *five.Length != 5*time.Hour || !approx(*week.UsedFrac, 0.45) || s.PlanLabel != "Muse Code Power Usage" {
				t.Errorf("muse %+v", s)
			}
		}},
		{"coderabbit", func() (Snapshot, error) {
			return ParseCodeRabbitUsage(string(fixtureD(t, "coderabbit_usage.txt")), t0)
		}, func(t *testing.T, s Snapshot) {
			w := s.Windows[0]
			if *w.Used != 25 || w.Limit != nil || w.ResetsAt.Format("2006-01-02") != "2025-10-31" || s.PlanLabel != "Pro" {
				t.Errorf("coderabbit %+v", s)
			}
		}},
		{"arkcli", func() (Snapshot, error) { return ParseArkcliUsage(string(fixtureD(t, "arkcli_usage.json")), t0) }, func(t *testing.T, s Snapshot) {
			keys := []string{}
			for _, w := range s.Windows {
				keys = append(keys, w.Key)
			}
			if strings.Join(keys, ",") != "agent:5h,agent:weekly,agent:monthly,5h,weekly,monthly" {
				t.Errorf("keys %v (unknown products and unsubscribed buckets must be skipped)", keys)
			}
			if m, _ := FindWindow(s, "monthly"); m.ResetsAt != nil {
				t.Errorf("a -1 reset is no reset: %v", m.ResetsAt)
			}
			if w, _ := FindWindow(s, "weekly"); w.ResetsAt.Unix() != 1760313600 {
				t.Errorf("millisecond reset %v", w.ResetsAt)
			}
		}},
	}
	for _, c := range cases {
		s, err := c.parse()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		mustValid(t, s)
		c.check(t, s)
	}
}

func TestLaneDShapeErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"openai costs html", func() error { _, e := ParseOpenAICosts([]byte("<html>"), t0); return e }(), ErrShape},
		{"openai costs no data", func() error { _, e := ParseOpenAICosts([]byte(`{"object":"page"}`), t0); return e }(), ErrShape},
		{"openai costs paged", func() error {
			_, e := ParseOpenAICosts([]byte(`{"data":[{"results":[]}],"has_more":true}`), t0)
			return e
		}(), ErrShape},
		{"openai costs bad currency", func() error {
			_, e := ParseOpenAICosts([]byte(`{"data":[{"results":[{"amount":{"value":1,"currency":"xyz"}}]}]}`), t0)
			return e
		}(), ErrShape},
		{"openai grants", func() error { _, e := ParseOpenAICreditGrants([]byte(`{"total_granted":5}`), t0); return e }(), ErrShape},
		{"anthropic", func() error { _, e := ParseAnthropicCostReport([]byte(`{"data":[]}`), t0); return e }(), ErrShape},
		{"anthropic amount", func() error {
			_, e := ParseAnthropicCostReport([]byte(`{"data":[{"results":[{"currency":"USD","amount":"lots"}]}]}`), t0)
			return e
		}(), ErrShape},
		{"aws budget", func() error { _, e := ParseAWSBudget([]byte(`{}`), t0); return e }(), ErrShape},
		{"aws usage budget", func() error {
			_, e := ParseAWSBudget([]byte(`{"Budget":{"BudgetType":"USAGE","TimeUnit":"MONTHLY"}}`), t0)
			return e
		}(), ErrNotApplicable},
		{"grok", func() error { _, e := ParseGrokBilling([]byte(`{"billingCycle":{}}`), t0); return e }(), ErrShape},
		{"jetbrains", func() error { _, e := ParseJetBrainsQuota([]byte(`<application/>`), t0); return e }(), ErrShape},
		{"nous", func() error { _, e := ParseNousAccount([]byte(`{"subscription":{}}`), t0); return e }(), ErrShape},
		{"nous error", func() error {
			_, e := ParseNousAccount([]byte(`{"error":"x","purchased_credits_remaining":1}`), t0)
			return e
		}(), ErrShape},
		{"muse no quota", func() error { _, e := ParseMuseTeamQuota([]byte(`{}`), t0); return e }(), ErrNotApplicable},
		{"muse stale", func() error {
			_, e := ParseMuseTeamQuota([]byte(`{"subscription_quota":{"weekly_weighted_used":"1","weekly_weighted_limit":"2","weekly_resets_at":1}}`), t0)
			return e
		}(), ErrShape},
		{"coderabbit", func() error { _, e := ParseCodeRabbitUsage("something else", t0); return e }(), ErrShape},
		{"coderabbit signed out", func() error {
			_, e := ParseCodeRabbitUsage("Error: not authenticated. Run coderabbit auth login", t0)
			return e
		}(), ErrAuth},
		{"arkcli", func() error { _, e := ParseArkcliUsage(`{"items":[]}`, t0); return e }(), ErrShape},
		{"arkcli signed out", func() error { _, e := ParseArkcliUsage(`{"viewer":{"auth_method":"none"},"items":[]}`, t0); return e }(), ErrAuth},
		{"arkcli login text", func() error { _, e := ParseArkcliUsage("Error: not logged in", t0); return e }(), ErrAuth},
	}
	for _, c := range cases {
		if !errors.Is(c.err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, c.err, c.want)
		}
	}
}

// TestLaneDHeadlines pins the remaining-first headline (D-681) for every
// provider of this lane that has a source, and used-only where the vendor
// reports only spend.
func TestLaneDHeadlines(t *testing.T) {
	mk := func(s Snapshot, err error) Snapshot {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// Nous Portal (balance group): total usable credits lead.
	h := headlineOf(t, mk(ParseNousAccount(fixtureD(t, "nous_account.json"), t0)))
	wantLeft(t, "nous", h, UnitUSDMicros, 74_250_000, nil)
	if h.Basis != "balance:total" {
		t.Errorf("nous basis %q", h.Basis)
	}
	// Nous with only purchased credits: they are what is left.
	h = headlineOf(t, mk(ParseNousAccount([]byte(`{"subscription":null,"purchased_credits_remaining":"3.25"}`), t0)))
	wantLeft(t, "nous purchased only", h, UnitUSDMicros, 3_250_000, nil)

	// OpenAI legacy grants: 12.75 left of 18 granted, 5.25 used.
	h = headlineOf(t, mk(ParseOpenAICreditGrants(fixtureD(t, "openai_credit_grants.json"), t0)))
	wantLeft(t, "openai grants", h, UnitUSDMicros, 12_750_000, F(5_250_000))

	// AWS budget: 162.58 left of 250, 87.42 used.
	h = headlineOf(t, mk(ParseAWSBudget(fixtureD(t, "aws_budget.json"), t0)))
	wantLeft(t, "aws budget", h, UnitUSDMicros, 162_580_000, F(87_420_000))

	// Grok: the monthly credit window, 875.55 left.
	h = headlineOf(t, mk(ParseGrokBilling(fixtureD(t, "grok_billing.json"), t0)))
	wantLeft(t, "grok", h, UnitUSDMicros, 875_550_000, F(123_450_000))

	// JetBrains: 7.5 AI credits left of 10.
	h = headlineOf(t, mk(ParseJetBrainsQuota(fixtureD(t, "jetbrains_quota.xml"), t0)))
	wantLeft(t, "jetbrains", h, UnitAICredits, 7.5, F(2.5))

	// Percent plans: the tightest window's share left.
	for _, c := range []struct {
		name  string
		s     Snapshot
		left  float64
		basis string
	}{
		{"muse", mk(ParseMuseTeamQuota(fixtureD(t, "muse_quota.json"), t0)), 0.55, "window:weekly"},
		{"doubao", mk(ParseArkcliUsage(string(fixtureD(t, "arkcli_usage.json")), t0)), 0.375, "window:weekly"},
	} {
		h := headlineOf(t, c.s)
		if h.Kind != HeadlinePercentLeft || !approx(*h.Value, c.left) || h.Basis != c.basis {
			t.Errorf("%s: %+v", c.name, h)
		}
	}

	// Spend-only vendors say so.
	for _, c := range []struct {
		name string
		s    Snapshot
		used float64
	}{
		{"openai admin", mk(ParseOpenAICosts(fixtureD(t, "openai_costs.json"), t0)), 3_850_000},
		{"anthropic admin", mk(ParseAnthropicCostReport(fixtureD(t, "anthropic_cost_report.json"), t0)), 198_450_000},
		{"coderabbit", mk(ParseCodeRabbitUsage(string(fixtureD(t, "coderabbit_usage.txt")), t0)), 25},
	} {
		h := headlineOf(t, c.s)
		if h.Kind != HeadlineUsedOnly || !approx(*h.Value, c.used) {
			t.Errorf("%s: %+v", c.name, h)
		}
	}
}

func TestLaneDThrottledAndNotApplicable(t *testing.T) {
	s, err := ParseGrokBilling([]byte(`{"monthlyLimit":{"val":1000},"usage":{"totalUsed":{"val":1000}},"on_demand_enabled":false}`), t0)
	if err != nil || s.Status != StatusThrottled {
		t.Errorf("grok over its limit: %+v %v", s, err)
	}
	s, err = ParseOpenAICreditGrants([]byte(`{"total_available":0,"total_granted":5}`), t0)
	if err != nil || s.Status != StatusThrottled {
		t.Errorf("no credit left: %+v %v", s, err)
	}
	s, err = ParseCodeRabbitUsage("Usage billing : active\nPeriod resets : 2025-10-31\n", t0)
	if err != nil || s.Status != StatusPlanOnly {
		t.Errorf("no review count: %+v %v", s, err)
	}
	mustValid(t, s)
	for _, c := range []struct {
		body string
		want error
	}{
		{`{"__type":"NotFoundException","Message":"no budget"}`, ErrNotApplicable},
		{`{"__type":"AccessDeniedException"}`, ErrAuth},
	} {
		_, err := parseBedrockBudget(ParseInput{Now: t0, Responses: map[string]Response{"budget": {Status: 400, Body: []byte(c.body)}}})
		if !errors.Is(err, c.want) {
			t.Errorf("bedrock 400 %s: %v", c.body, err)
		}
	}
}

func TestNousNeverUsesAnExpiredOrForeignToken(t *testing.T) {
	expired := PlanInput{Now: t0.Add(2 * time.Hour), Local: map[string][]byte{"auth": fixtureD(t, "nous_auth.json")}}
	if _, err := Drivers[SourceNousHermes].Plan(expired); !errors.Is(err, ErrAuth) {
		t.Errorf("expired token must not be sent (never refreshed): %v", err)
	}
	pool := []byte(`{"credential_pool":{"nous":[
		{"access_token":"old","expires_at":"2025-10-09T08:00:00Z"},
		{"access_token":"current","expires_at":"2025-10-09T10:00:00Z","priority":1}]}}`)
	reqs, err := Drivers[SourceNousHermes].Plan(PlanInput{Now: t0, Local: map[string][]byte{"auth": pool}})
	if err != nil || reqs[0].SecretHeaders["Authorization"] != "Bearer current" {
		t.Errorf("pool selection %v %v", reqs, err)
	}
	// The stored portal_base_url is ignored: the host is fixed.
	reqs, _ = Drivers[SourceNousHermes].Plan(PlanInput{Now: t0, Local: map[string][]byte{"auth": fixtureD(t, "nous_auth.json")}})
	if !strings.HasPrefix(reqs[0].URL, "https://portal.nousresearch.com/") {
		t.Errorf("url %s", reqs[0].URL)
	}
}

// fakeGrokAgent replays agent lines and records what the client sent.
func fakeGrokAgent(lines ...string) (*bytes.Buffer, *strings.Reader) {
	return &bytes.Buffer{}, strings.NewReader(strings.Join(lines, "\n") + "\n")
}

func TestGrokAgentConversation(t *testing.T) {
	billing := strings.TrimSpace(string(fixtureD(t, "grok_billing.json")))
	w, r := fakeGrokAgent(
		`{"jsonrpc":"2.0","method":"session/update","params":{}}`,
		`{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentCapabilities":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"path":"/etc/passwd"}}`,
		`{"jsonrpc":"2.0","id":1,"result":`+billing+`}`,
	)
	s, err := Drivers[SourceGrokAgent].Converse(w, r, PlanInput{Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	sent := bufio.NewScanner(w)
	var methods []string
	for sent.Scan() {
		line := sent.Text()
		if !strings.Contains(line, `"jsonrpc":"2.0"`) {
			t.Errorf("not JSON-RPC 2.0: %s", line)
		}
		for _, m := range []string{"initialize", "x.ai/billing", "session/new", "session/prompt", "fs/"} {
			if strings.Contains(line, `"method":"`+m) {
				methods = append(methods, m)
			}
		}
		if strings.Contains(line, "initialize") && (!strings.Contains(line, `"name":"`+GrokClientName+`"`) || !strings.Contains(line, `"terminal":false`)) {
			t.Errorf("initialize must name Observer honestly and offer no tools: %s", line)
		}
	}
	if strings.Join(methods, ",") != "initialize,x.ai/billing" {
		t.Errorf("methods sent %v", methods)
	}
	if strings.Join(Drivers[SourceGrokAgent].Argv, " ") != "grok agent stdio" {
		t.Errorf("argv %v", Drivers[SourceGrokAgent].Argv)
	}

	for _, c := range []struct {
		line string
		want error
	}{
		{`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`, ErrNotApplicable},
		{`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Authentication required to fetch billing data. Run 'grok login' to authenticate."}}`, ErrAuth},
		{`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}}`, ErrShape},
	} {
		w, r := fakeGrokAgent(`{"jsonrpc":"2.0","id":0,"result":{}}`, c.line)
		if _, err := converseGrok(w, r, PlanInput{Now: t0}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.line, err)
		}
	}
	w, r = fakeGrokAgent(`{"jsonrpc":"2.0","id":0,"result":{}}`)
	if _, err := converseGrok(w, r, PlanInput{Now: t0}); !errors.Is(err, ErrTransient) {
		t.Errorf("closed agent: %v", err)
	}
}

func TestLaneDCommandsAreFixed(t *testing.T) {
	for _, c := range []struct{ src, argv string }{
		{SourceCodeRabbitCLI, "coderabbit usage"},
		{SourceDoubaoArkcli, "arkcli usage plan --format json"},
	} {
		reqs, err := Drivers[c.src].Plan(PlanInput{Params: map[string]string{"x": "; rm -rf /"}})
		if err != nil || reqs[0].Kind != ReqExec || strings.Join(reqs[0].Argv, " ") != c.argv {
			t.Errorf("%s: %v %v", c.src, reqs, err)
		}
		src, _ := SourceByID(c.src)
		if src.Command != reqs[0].Argv[0] {
			t.Errorf("%s: command %q", c.src, src.Command)
		}
	}
	// The JetBrains source reads one local file and makes no network call.
	if reqs, err := Drivers[SourceJetBrainsQuota].Plan(PlanInput{}); err != nil || len(reqs) != 0 {
		t.Error("the JetBrains quota source makes no network call")
	}
	if _, err := Drivers[SourceJetBrainsQuota].Parse(ParseInput{Now: t0}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no quota file: %v", err)
	}
}

func TestLaneDGapsAndKinds(t *testing.T) {
	gaps := map[string]string{
		"azure_openai": GapNoQuotaAPI, "gemini": GapVendorEnded, "antigravity": GapNeedsProcess,
		"vertex_ai": GapCloudCredsOnly, "pi": GapTrafficOnly,
	}
	for id, g := range gaps {
		p, _ := ProviderByID(id)
		if p.Gap != g || CoverageOf(id) != CoverageManual {
			t.Errorf("%s: gap %q coverage %q", id, p.Gap, CoverageOf(id))
		}
	}
	cov := map[string]Coverage{
		ProviderOpenAIAPI: CoverageOfficial, ProviderAnthropicAPI: CoverageOfficial, ProviderAWSBedrock: CoverageOfficial,
		ProviderGrok: CoverageOfficial, ProviderCodeRabbit: CoverageOfficial, ProviderDoubao: CoverageOfficial,
		ProviderJetBrainsAI: CoverageExperimental, ProviderNousPortal: CoverageExperimental, ProviderMuseCode: CoverageSession,
	}
	for id, c := range cov {
		if got := CoverageOf(id); got != c {
			t.Errorf("%s coverage %q, want %q", id, got, c)
		}
	}
}
