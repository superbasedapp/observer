package planlimits

import (
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// Lane C2 tests: fixture only, never a live call. Fixtures in
// testdata/lanec2 are Observer's own JSON built from the response shapes
// the reference project documents.

func c2fix(t *testing.T, name string) []byte {
	t.Helper()
	return fixture(t, "lanec2/"+name)
}

// c2resp builds a 200 response map from key -> fixture name.
func c2resp(t *testing.T, m map[string]string) map[string]Response {
	t.Helper()
	out := map[string]Response{}
	for k, f := range m {
		out[k] = Response{Key: k, Status: 200, Body: c2fix(t, f)}
	}
	return out
}

// c2StepFunToken builds an Oasis token pair whose refresh half carries a
// device_id claim.
func c2StepFunToken() string {
	enc := base64.RawURLEncoding.EncodeToString
	jwt := func(claims string) string { return enc([]byte(`{"alg":"HS256"}`)) + "." + enc([]byte(claims)) + ".sig" }
	return jwt(`{"sub":"u1"}`) + "..." + jwt(`{"device_id":"dev123"}`)
}

// c2Cases is one plan case per lane C2 source: the secrets and params a
// user hands over, and the secret header names each request must carry.
var c2PlanCases = []struct {
	src        string
	secrets    map[string]string
	params     map[string]string
	wantURL    string // the first request's URL
	wantSecret []string
}{
	{
		SourceXAPIUsage,
		map[string]string{"key": "AAAA"},
		nil,
		"https://api.x.com/2/usage/tweets?usage.fields=cap_reset_day,project_cap,project_usage",
		[]string{"Authorization"},
	},
	{
		SourceXAPISession,
		map[string]string{"session": "Cookie: auth_token=a1; ct0=c0; twid=x"},
		map[string]string{"account_id": "17"},
		"https://console.x.com/api/accounts/17/credits",
		[]string{"Cookie", "X-CSRF-Token"},
	},
	{
		SourceStepFunSession,
		map[string]string{"session": c2StepFunToken()},
		nil,
		stepfunBase + "QueryStepPlanRateLimit",
		[]string{"Cookie", "oasis-webid"},
	},
	{
		SourceHelmcodeSession,
		map[string]string{"session": "sid=1"},
		map[string]string{"tenant": "nan_builders"},
		"https://cloud-api.nan.builders/api/usage/quota",
		[]string{"Cookie"},
	},
	{
		SourceLongCatSession,
		map[string]string{"session": "passport=1"},
		nil,
		"https://longcat.chat/api/v1/user-current",
		[]string{"Cookie"},
	},
	{
		SourceNotionSession,
		map[string]string{"session": "tokenvalue"},
		map[string]string{"workspace_id": "0123456789ABCDEF0123456789abcdef"},
		"https://app.notion.com/api/v3/getCreditRateLimitStatus",
		[]string{"Cookie"},
	},
	{
		SourceReplicateSession,
		map[string]string{"session": "sessionid=s1; csrftoken=c"},
		map[string]string{"account_name": "acme", "account_type": "organization"},
		"https://replicate.com/api/organizations/acme/invoices",
		[]string{"Cookie"},
	},
	{
		SourceRaycastSession,
		map[string]string{"session": "__raycast_session=r1; other=x"},
		nil,
		"https://www.raycast.com/frontend_api/current_user/ai_credits",
		[]string{"Cookie"},
	},
	{
		SourceLithosAISession,
		map[string]string{"session": "__Host-console_session=s; __Host-console_csrf=k"},
		map[string]string{"org_id": "org_1"},
		"https://console.lithosai.cloud/api/billing",
		[]string{"Cookie", "X-Console-Csrf"},
	},
	{
		SourceWorkBuddySession,
		map[string]string{"session": "wb=1"},
		map[string]string{"user_agent": "User-Agent: Mozilla/5.0 (X11) Chrome/143.0.0.0"},
		"https://www.workbuddy.cn/billing/meter/get-user-resource-summary",
		[]string{"Cookie"},
	},
	{
		SourceTinyAPISession,
		map[string]string{"session": "__Secure-authjs.session-token=t"},
		nil,
		"https://tinyapi.rest/api/user/credits",
		[]string{"Cookie"},
	},
	{
		SourceParallelSession,
		map[string]string{"session": "session=p"},
		nil,
		"https://platform.parallel.ai/api/rpc/billing/payments/refresh-balance",
		[]string{"Cookie"},
	},
	{
		SourceClaudePlatformSession,
		map[string]string{"session": "sk-session"},
		map[string]string{"org_id": "6f1e-ab"},
		"https://platform.claude.com/api/organizations/6f1e-ab/prepaid/credits",
		[]string{"Cookie"},
	},
}

func TestLaneC2Plans(t *testing.T) {
	for _, c := range c2PlanCases {
		t.Run(c.src, func(t *testing.T) {
			def, ok := SourceByID(c.src)
			if !ok {
				t.Fatal("no source row")
			}
			d := Drivers[c.src]
			reqs, err := d.Plan(PlanInput{Secrets: c.secrets, Params: c.params, Now: t0})
			if err != nil || len(reqs) == 0 {
				t.Fatalf("plan: %v %v", reqs, err)
			}
			if reqs[0].URL != c.wantURL {
				t.Errorf("url %q, want %q", reqs[0].URL, c.wantURL)
			}
			for _, r := range reqs {
				u, err := url.Parse(r.URL)
				if err != nil || u.Scheme != "https" || !slices.Contains(def.Hosts, u.Host) {
					t.Errorf("request %s host %q not in %v", r.Key, r.URL, def.Hosts)
				}
				for _, h := range []string{"Cookie", "Authorization"} {
					if _, leak := r.Header[h]; leak {
						t.Errorf("request %s carries %s in plain headers", r.Key, h)
					}
				}
				var got []string
				for k := range r.SecretHeaders {
					got = append(got, k)
				}
				slices.Sort(got)
				want := slices.Clone(c.wantSecret)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("request %s secret headers %v, want %v", r.Key, got, want)
				}
			}
			// A missing secret is a sign-in problem, never a crash.
			if _, err := d.Plan(PlanInput{Params: c.params, Now: t0}); !errors.Is(err, ErrAuth) {
				t.Errorf("missing secret: %v, want ErrAuth", err)
			}
		})
	}
}

// TestLaneC2AuthHeaders pins how each auth method travels: the bearer key,
// the pasted Cookie (normalised, bare values named), and the CSRF echoes.
func TestLaneC2AuthHeaders(t *testing.T) {
	cases := []struct {
		name, src string
		secrets   map[string]string
		params    map[string]string
		want      map[string]string
	}{
		{
			"x api key is a bearer", SourceXAPIUsage,
			map[string]string{"key": " AAAA "},
			nil,
			map[string]string{"Authorization": "Bearer AAAA"},
		},
		{
			"x console echoes ct0", SourceXAPISession,
			map[string]string{"session": "auth_token=a1; ct0=c0"},
			map[string]string{"account_id": "17"},
			map[string]string{"Cookie": "auth_token=a1; ct0=c0", "X-CSRF-Token": "c0"},
		},
		{
			"stepfun token rides as a cookie with its device id", SourceStepFunSession,
			map[string]string{"session": "Oasis-Token=" + c2StepFunToken() + "; other=1"},
			nil,
			map[string]string{"Cookie": "Oasis-Token=" + c2StepFunToken() + "; Oasis-Webid=dev123", "oasis-webid": "dev123"},
		},
		{
			"notion bare token is token_v2", SourceNotionSession,
			map[string]string{"session": "abc"},
			map[string]string{"workspace_id": "0123456789abcdef0123456789abcdef"},
			map[string]string{"Cookie": "token_v2=abc"},
		},
		{
			"raycast keeps only its session cookies", SourceRaycastSession,
			map[string]string{"session": "Cookie: a=1; __raycast_session=r1; csrf_token=c; b=2"},
			nil,
			map[string]string{"Cookie": "__raycast_session=r1; csrf_token=c"},
		},
		{
			"lithosai echoes the console csrf", SourceLithosAISession,
			map[string]string{"session": "__Host-console_session=s; __Host-console_csrf=k"},
			map[string]string{"org_id": "org_1"},
			map[string]string{"Cookie": "__Host-console_session=s; __Host-console_csrf=k", "X-Console-Csrf": "k"},
		},
		{
			"claude console bare value is sessionKey", SourceClaudePlatformSession,
			map[string]string{"session": "sk-1"},
			map[string]string{"org_id": "o1"},
			map[string]string{"Cookie": "sessionKey=sk-1"},
		},
	}
	for _, c := range cases {
		reqs, err := Drivers[c.src].Plan(PlanInput{Secrets: c.secrets, Params: c.params, Now: t0})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for k, v := range c.want {
			if got := reqs[0].SecretHeaders[k]; got != v {
				t.Errorf("%s: %s = %q, want %q", c.name, k, got, v)
			}
		}
	}
}

// TestLaneC2PlanRefusals: inputs that must never reach a URL or a request.
func TestLaneC2PlanRefusals(t *testing.T) {
	cases := []struct {
		name, src string
		secrets   map[string]string
		params    map[string]string
		auth      bool // the refusal is a sign-in problem
	}{
		{"x console needs ct0", SourceXAPISession, map[string]string{"session": "auth_token=a"}, map[string]string{"account_id": "1"}, true},
		{"x console id cannot escape the path", SourceXAPISession, map[string]string{"session": "auth_token=a; ct0=c"}, map[string]string{"account_id": "../me"}, false},
		{"lithosai needs both cookies", SourceLithosAISession, map[string]string{"session": "__Host-console_session=s"}, map[string]string{"org_id": "o"}, true},
		{"notion needs a uuid", SourceNotionSession, map[string]string{"session": "t"}, map[string]string{"workspace_id": "my space"}, false},
		{"replicate name cannot escape the path", SourceReplicateSession, map[string]string{"session": "sessionid=s"}, map[string]string{"account_name": "../x"}, false},
		{"replicate account type is a closed set", SourceReplicateSession, map[string]string{"session": "sessionid=s"}, map[string]string{"account_name": "a", "account_type": "team"}, false},
		{"helmcode tenant is a closed set", SourceHelmcodeSession, map[string]string{"session": "s=1"}, map[string]string{"tenant": "evil"}, false},
		{"workbuddy needs a browser user agent", SourceWorkBuddySession, map[string]string{"session": "s=1"}, map[string]string{"user_agent": "curl/8"}, false},
		{"claude console org id", SourceClaudePlatformSession, map[string]string{"session": "s"}, map[string]string{"org_id": "a/b"}, false},
		{"raycast needs its session cookie", SourceRaycastSession, map[string]string{"session": "csrf_token=c"}, nil, true},
	}
	for _, c := range cases {
		reqs, err := Drivers[c.src].Plan(PlanInput{Secrets: c.secrets, Params: c.params, Now: t0})
		if err == nil || reqs != nil {
			t.Errorf("%s: planned %v", c.name, reqs)
			continue
		}
		if errors.Is(err, ErrAuth) != c.auth {
			t.Errorf("%s: %v, auth=%v", c.name, err, c.auth)
		}
	}
}

func TestLaneC2Parse(t *testing.T) {
	cases := []struct {
		src    string
		resp   map[string]string
		params map[string]string
		check  func(t *testing.T, s Snapshot)
	}{
		{SourceXAPIUsage, map[string]string{"main": "xapi_usage.json"}, nil, func(t *testing.T, s Snapshot) {
			w, _ := FindWindow(s, "monthly")
			if w.Unit != UnitPercent || !approx(*w.UsedFrac, 0.25) || !w.ResetsAt.Equal(time.Date(2025, 10, 19, 0, 0, 0, 0, time.UTC)) {
				t.Errorf("x usage window %+v", w)
			}
			h := headlineOf(t, s)
			if h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.75) {
				t.Errorf("x usage headline %+v", h)
			}
		}},
		{SourceXAPISession, map[string]string{"credits": "xapi_credits.json"}, nil, func(t *testing.T, s Snapshot) {
			wantLeft(t, "x console", headlineOf(t, s), UnitUSDMicros, 49_750_000, nil)
			if b, _ := FindBalance(s, "granted"); b.Amount != 7_250_000 {
				t.Errorf("free credits %+v", b)
			}
		}},
		{SourceStepFunSession, map[string]string{"limits": "stepfun_coding.json", "plan": "stepfun_plan.json"}, nil, func(t *testing.T, s Snapshot) {
			w5, _ := FindWindow(s, "5h")
			ww, _ := FindWindow(s, "weekly")
			if !approx(*w5.UsedFrac, 0.25) || w5.ResetsAt.Unix() != 1760010000 || *w5.Length != 5*time.Hour ||
				!approx(*ww.UsedFrac, 0.6) || *ww.Length != 7*24*time.Hour {
				t.Errorf("stepfun windows %+v %+v", w5, ww)
			}
			if s.PlanLabel != "Plus" || s.PlanCode != "coding_plan" {
				t.Errorf("stepfun plan %q %q", s.PlanLabel, s.PlanCode)
			}
			h := headlineOf(t, s)
			if h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.4) || h.Basis != "window:weekly" {
				t.Errorf("stepfun headline %+v", h)
			}
		}},
		{SourceStepFunSession, map[string]string{"limits": "stepfun_credit.json"}, nil, func(t *testing.T, s Snapshot) {
			w, ok := FindWindow(s, "credits")
			if !ok || *w.Limit != 500 || *w.Remaining != 400 || *w.Used != 100 || w.ResetsAt.Unix() != 1762000000 {
				t.Errorf("stepfun credit window %+v", w)
			}
			if _, ok := FindWindow(s, "5h"); ok {
				t.Error("a zero window on a credit plan means none, never used up")
			}
			wantLeft(t, "stepfun credits", headlineOf(t, s), UnitCredits, 400, F(100))
		}},
		{SourceHelmcodeSession, map[string]string{"quota": "helmcode_quota.json", "billing": "helmcode_billing.json", "credits": "helmcode_credits.json"}, nil, func(t *testing.T, s Snapshot) {
			if len(s.Windows) != 2 {
				t.Fatalf("helmcode windows %+v", s.Windows)
			}
			r, ok := FindWindow(s, "4h:helm-rolling")
			if !ok || *r.Length != 4*time.Hour || !approx(*r.UsedFrac, 0.8) {
				t.Errorf("rolling tier %+v", r)
			}
			m, _ := FindWindow(s, "monthly:helm-monthly")
			if !m.ResetsAt.Equal(time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)) {
				t.Errorf("monthly %+v", m)
			}
			if b, _ := FindBalance(s, "prepaid"); b.Unit != UnitEURMicros || b.Amount != 12_500_000 {
				t.Errorf("helmcode balance %+v", b)
			}
			wantLeft(t, "helmcode", headlineOf(t, s), UnitTokens, 60_000_000, F(240_000_000))
		}},
		{SourceHelmcodeSession, map[string]string{"quota": "helmcode_quota.json"}, nil, func(t *testing.T, s Snapshot) {
			if len(s.Windows) != 1 {
				t.Errorf("without premium billing the rolling tier is hidden: %+v", s.Windows)
			}
		}},
		{SourceLongCatSession, map[string]string{"user": "longcat_user.json", "summary": "longcat_summary.json", "usage": "longcat_usage.json", "fuel": "longcat_fuel.json"}, nil, func(t *testing.T, s Snapshot) {
			q, _ := FindWindow(s, "quota")
			if *q.Limit != 1_000_000 || *q.Used != 250_000 {
				t.Errorf("token pack wins over the legacy aggregate: %+v", q)
			}
			f, _ := FindWindow(s, "fuel_pack")
			if *f.Remaining != 80_000 || *f.Limit != 200_000 || f.ResetsAt.Unix() != 1762000000 {
				t.Errorf("fuel %+v", f)
			}
			wantLeft(t, "longcat", headlineOf(t, s), UnitTokens, 80_000, F(120_000))
		}},
		{SourceLongCatSession, map[string]string{"user": "longcat_user.json", "usage": "longcat_usage.json"}, nil, func(t *testing.T, s Snapshot) {
			q, _ := FindWindow(s, "quota")
			if *q.Limit != 500_000 || *q.Used != 400_000 {
				t.Errorf("legacy fallback %+v", q)
			}
		}},
		{SourceNotionSession, map[string]string{"main": "notion_status.json"}, nil, func(t *testing.T, s Snapshot) {
			r, ok := FindWindow(s, "6h")
			if !ok || *r.Length != 6*time.Hour || !r.ResetsAt.Equal(t0.Add(12600*time.Second)) || *r.Used != 42.5 || *r.Limit != 100 {
				t.Errorf("notion rolling %+v", r)
			}
			m, _ := FindWindow(s, "monthly")
			if m.ResetsAt.Unix() != 1762000000 || *m.Used != 18 {
				t.Errorf("notion monthly %+v", m)
			}
			wantLeft(t, "notion", headlineOf(t, s), UnitCredits, 57.5, F(42.5))
		}},
		{SourceReplicateSession, map[string]string{"invoices": "replicate_invoices.json", "credit": "replicate_credit.json"}, nil, func(t *testing.T, s Snapshot) {
			if s.Spend[0].Amount != 12_400_000 {
				t.Errorf("closed invoices never displace this month's spend: %+v", s.Spend)
			}
			wantLeft(t, "replicate", headlineOf(t, s), UnitUSDMicros, 80_000_000, F(12_400_000))
		}},
		{SourceReplicateSession, map[string]string{"invoices": "replicate_invoices.json"}, nil, func(t *testing.T, s Snapshot) {
			h := headlineOf(t, s)
			if h.Kind != HeadlineUsedOnly || *h.Value != 12_400_000 || h.Basis != "spend:month" {
				t.Errorf("replicate without credit says used only: %+v", h)
			}
		}},
		{SourceRaycastSession, map[string]string{"main": "raycast_credits.json"}, nil, func(t *testing.T, s Snapshot) {
			if s.PlanLabel != "Pro+" || s.PlanCode != "pro_plus" {
				t.Errorf("raycast plan %q %q", s.PlanLabel, s.PlanCode)
			}
			w, _ := FindWindow(s, "monthly")
			if !w.ResetsAt.Equal(time.Date(2025, 11, 3, 10, 0, 0, 0, time.UTC)) {
				t.Errorf("raycast renewal %+v", w)
			}
			wantLeft(t, "raycast", headlineOf(t, s), UnitCredits, 337.38, F(162.62))
		}},
		{SourceLithosAISession, map[string]string{"billing": "lithosai_billing.json", "spend": "lithosai_spend.json"}, nil, func(t *testing.T, s Snapshot) {
			wantLeft(t, "lithosai", headlineOf(t, s), UnitUSDMicros, 2_570_000, F(1_250_000))
			if len(s.Spend) != 2 || s.Spend[1].Period != "day" || s.Spend[1].Amount != 250_000 {
				t.Errorf("lithosai spend %+v", s.Spend)
			}
		}},
		{SourceWorkBuddySession, map[string]string{"main": "workbuddy_summary.json"}, nil, func(t *testing.T, s Snapshot) {
			if s.PlanLabel != "Pro" {
				t.Errorf("workbuddy plan %q", s.PlanLabel)
			}
			wantLeft(t, "workbuddy", headlineOf(t, s), UnitCredits, 550, F(50))
		}},
		{SourceTinyAPISession, map[string]string{"main": "tinyapi_credits.json"}, nil, func(t *testing.T, s Snapshot) {
			wantLeft(t, "tinyapi", headlineOf(t, s), UnitCredits, 1234, nil)
		}},
		{SourceParallelSession, map[string]string{"main": "parallel_balance.json"}, nil, func(t *testing.T, s Snapshot) {
			wantLeft(t, "parallel", headlineOf(t, s), UnitUSDMicros, 12_340_000, nil)
		}},
		{SourceClaudePlatformSession, map[string]string{"credits": "claudeplatform_credits.json", "spend": "claudeplatform_spend.json"}, nil, func(t *testing.T, s Snapshot) {
			h := headlineOf(t, s)
			wantLeft(t, "claude platform", h, UnitUSDMicros, 324_750_000, F(18_900_000))
			if h.Basis != "balance:prepaid" {
				t.Errorf("the balance left leads, not a grant: %+v", h)
			}
			sub, _ := FindWindow(s, "grant:subscription")
			pur, _ := FindWindow(s, "grant:purchased")
			if *sub.Limit != 200_000_000 || *sub.Remaining != 124_750_000 || *pur.Remaining != 200_000_000 || sub.ResetsAt != nil {
				t.Errorf("grants %+v %+v", sub, pur)
			}
			if len(s.Windows) != 2 {
				t.Errorf("an expired grant is dropped: %+v", s.Windows)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.src, func(t *testing.T) {
			s, err := Drivers[c.src].Parse(ParseInput{Params: c.params, Responses: c2resp(t, c.resp), Now: t0})
			if err != nil {
				t.Fatal(err)
			}
			if s.Source != c.src {
				t.Errorf("source %q", s.Source)
			}
			mustValid(t, s)
			c.check(t, s)
		})
	}
}

// TestLaneC2ShapeErrors: a 2xx body without the expected shape is the
// driver canary, never a zero.
func TestLaneC2ShapeErrors(t *testing.T) {
	cases := []struct {
		src  string
		key  string
		body string
	}{
		{SourceXAPIUsage, "main", `{"data":{"project_cap":"10"}}`},
		{SourceXAPISession, "credits", `{"credits":{"balance":"lots"}}`},
		{SourceXAPISession, "credits", `{"credits":{"balance":1},"freeCredits":{}}`},
		{SourceStepFunSession, "limits", `{"status":1,"five_hour_usage_reset_time":"1760010000"}`},
		{SourceStepFunSession, "limits", `{"code":5}`},
		{SourceHelmcodeSession, "quota", `{"models":[]}`},
		{SourceHelmcodeSession, "quota", `{"periodStart":"2025-10-01","models":[{"model":"m","cap":"x","tokensUsed":1}]}`},
		{SourceLongCatSession, "user", `{"code":"weird"}`},
		{SourceNotionSession, "main", `{"status":"within_limit"}`},
		{SourceNotionSession, "main", `{"window":{"used":"a","limit":1}}`},
		{SourceReplicateSession, "invoices", `{"invoices":[{"type":"monthly-usage","total_cost_before_adjustments":"n/a"}]}`},
		{SourceRaycastSession, "main", `{"next_credits_at":"2025-11-01T00:00:00Z"}`},
		{SourceLithosAISession, "billing", `{"balanceNanos":"2.5"}`},
		{SourceWorkBuddySession, "main", `{"code":10001,"data":{}}`},
		{SourceTinyAPISession, "main", `{"success":false}`},
		{SourceParallelSession, "main", `{"kind":"error","data":{"balance":1}}`},
		{SourceClaudePlatformSession, "credits", `{"amount":1.5}`},
		{SourceClaudePlatformSession, "credits", `{"amount":1,"currency":"XYZ"}`},
	}
	for _, c := range cases {
		_, err := Drivers[c.src].Parse(ParseInput{Responses: ok200(c.key, c.body), Now: t0})
		if !errors.Is(err, ErrShape) {
			t.Errorf("%s %s: %v, want ErrShape", c.src, c.body, err)
		}
	}
}

// TestLaneC2SessionStates: a sign-in page, a refused session and the
// vendors' own "not for this account" and "limit reached" answers.
func TestLaneC2SessionStates(t *testing.T) {
	parse := func(src, key string, r Response) (Snapshot, error) {
		return Drivers[src].Parse(ParseInput{Responses: map[string]Response{key: r}, Now: t0})
	}
	if _, err := parse(SourceParallelSession, "main", Response{Status: 200, Body: []byte("<!doctype html><title>Sign in</title>")}); !errors.Is(err, ErrAuth) {
		t.Errorf("a sign-in page is a lost session: %v", err)
	}
	if _, err := parse(SourceTinyAPISession, "main", Response{Status: 401}); !errors.Is(err, ErrAuth) {
		t.Errorf("401: %v", err)
	}
	if _, err := parse(SourceXAPISession, "credits", Response{Status: 400, Body: []byte(`{"errors":[{"code":215,"message":"Bad Authentication data."}]}`)}); !errors.Is(err, ErrAuth) {
		t.Errorf("x console code 215 is an expired session: %v", err)
	}
	if _, err := parse(SourceNotionSession, "main", Response{Status: 200, Body: []byte(`{"status":"not_applicable"}`)}); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("notion not applicable: %v", err)
	}
	if _, err := parse(SourceLongCatSession, "user", Response{Status: 200, Body: []byte(`{"code":401,"message":"login"}`)}); !errors.Is(err, ErrAuth) {
		t.Errorf("longcat code 401: %v", err)
	}
	if _, err := parse(SourceStepFunSession, "limits", Response{Status: 200, Body: []byte(`{"status":0,"message":"auth failed: oasis-token is embezzled"}`)}); !errors.Is(err, ErrAuth) {
		t.Errorf("stepfun refused token: %v", err)
	}
	s, err := parse(SourceNotionSession, "main", Response{Status: 200, Body: []byte(`{"window":{"window":"6h","used":120,"limit":100}}`)})
	if err != nil || s.Status != StatusThrottled {
		t.Errorf("notion over the allowance: %v %+v", err, s)
	}
	mustValid(t, s)
	s, err = parse(SourceStepFunSession, "limits", Response{Status: 200, Body: []byte(`{"status":1,"plan_family":2,"five_hour_usage_reset_time":"0","weekly_usage_reset_time":"0"}`)})
	if err != nil || s.Status != StatusPlanOnly {
		t.Errorf("a credit plan with no balance yet: %v %+v", err, s)
	}
	mustValid(t, s)
	s, err = parse(SourceXAPIUsage, "main", Response{Status: 200, Body: []byte(`{"data":{"project_cap":"100","project_usage":"100","cap_reset_day":31}}`)})
	if err != nil || s.Status != StatusThrottled {
		t.Errorf("x cap reached: %v %+v", err, s)
	}
}

func TestLaneC2Helpers(t *testing.T) {
	if got := StepFunWebID(c2StepFunToken()); got != "dev123" {
		t.Errorf("StepFunWebID = %q", got)
	}
	if got := StepFunWebID("not-a-jwt"); got != "" {
		t.Errorf("StepFunWebID(no claim) = %q", got)
	}
	if id, ok := NotionWorkspaceID("01234567-89ab-cdef-0123-456789ABCDEF"); !ok || id != "01234567-89ab-cdef-0123-456789abcdef" {
		t.Errorf("NotionWorkspaceID = %q %v", id, ok)
	}
	ua, ok := WorkBuddyUserAgent("user-agent: Mozilla/5.0 (Macintosh)\r\nX-Evil: 1")
	if !ok || strings.ContainsAny(ua, "\r\n") {
		t.Errorf("WorkBuddyUserAgent = %q %v", ua, ok)
	}
	for _, c := range []struct {
		now  time.Time
		day  int
		want time.Time
	}{
		{t0, 19, time.Date(2025, 10, 19, 0, 0, 0, 0, time.UTC)},
		{t0, 3, time.Date(2025, 11, 3, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC), 31, time.Date(2026, 2, 28, 0, 0, 0, 0, time.UTC)},
	} {
		if got := nextMonthDay(c.now, c.day); !got.Equal(c.want) {
			t.Errorf("nextMonthDay(%v, %d) = %v, want %v", c.now, c.day, got, c.want)
		}
	}
}
