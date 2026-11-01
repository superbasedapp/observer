package planlimits

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// lbParse runs a lane B source's parser over one fixture as the "main"
// response, plus any extra responses.
func lbParse(t *testing.T, src, fx string, extra map[string]Response, params map[string]string) (Snapshot, error) {
	t.Helper()
	r := map[string]Response{}
	if fx != "" {
		r["main"] = Response{Key: "main", Status: 200, Body: fixture(t, "laneb/"+fx)}
	}
	for k, v := range extra {
		r[k] = v
	}
	return Drivers[src].Parse(ParseInput{Params: params, Responses: r, Now: t0})
}

// lbMust is lbParse that must succeed with a valid snapshot of the right
// source and kind.
func lbMust(t *testing.T, src, fx string, extra map[string]Response, params map[string]string) Snapshot {
	t.Helper()
	s, err := lbParse(t, src, fx, extra, params)
	if err != nil {
		t.Fatalf("%s: %v", src, err)
	}
	mustValid(t, s)
	d, _ := SourceByID(src)
	if s.Source != src || s.Provider != d.Provider || s.Kind != d.Kind {
		t.Fatalf("%s: snapshot names %s/%s/%s", src, s.Provider, s.Source, s.Kind)
	}
	return s
}

func lbWindow(t *testing.T, s Snapshot, key string) Window {
	t.Helper()
	w, ok := FindWindow(s, key)
	if !ok {
		t.Fatalf("%s: no window %q in %+v", s.Source, key, s.Windows)
	}
	return w
}

func lbNear(t *testing.T, what string, got *float64, want float64) {
	t.Helper()
	if got == nil || !approx(*got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

// --- base URL policy (ledger SUBS-5) -------------------------------------------

func TestCheckBaseURL(t *testing.T) {
	cases := []struct {
		raw, want string
		ok        bool
	}{
		{"https://gw.example.com", "https://gw.example.com", true},
		{"https://GW.Example.com/", "https://gw.example.com", true},
		{"https://gw.example.com:8443/litellm/", "https://gw.example.com:8443/litellm", true},
		{"https://10.0.0.5:4000", "https://10.0.0.5:4000", true},
		{"http://127.0.0.1:4000", "http://127.0.0.1:4000", true},
		{"http://[::1]:4000/v1", "http://[::1]:4000/v1", true},
		{"http://localhost:4000", "http://localhost:4000", true},
		{"HTTP://LOCALHOST", "http://localhost", true},
		{"  https://gw.example.com  ", "https://gw.example.com", true},
		{"", "", false},
		{"gw.example.com", "", false},
		{"//gw.example.com", "", false},
		{"ftp://gw.example.com", "", false},
		{"file:///etc/passwd", "", false},
		{"http://gw.example.com", "", false},
		{"http://192.168.1.5:4000", "", false},
		{"http://127.0.0.2", "", false},
		{"http://localhost.evil.test", "", false},
		{"https://user:pw@gw.example.com", "", false},
		{"https://user@gw.example.com", "", false},
		{"https://gw.example.com/?a=1", "", false},
		{"https://gw.example.com/?", "", false},
		{"https://gw.example.com/#frag", "", false},
		{"https://gw.example.com/#", "", false},
		{"https://gw.example.com:0", "", false},
		{"https://gw.example.com:70000", "", false},
		{"https://gw.example.com:", "", false},
		{"https://gw.example.com/a b", "", false},
		{"https://gw.example.com\\@evil.test", "", false},
		{"https://gw.example.com/\r\nX: 1", "", false},
		{"mailto:a@b.c", "", false},
	}
	for _, c := range cases {
		u, err := CheckBaseURL(c.raw)
		if (err == nil) != c.ok {
			t.Errorf("CheckBaseURL(%q) err=%v, want ok=%v", c.raw, err, c.ok)
			continue
		}
		if !c.ok {
			if !errors.Is(err, ErrBadBaseURL) {
				t.Errorf("CheckBaseURL(%q): %v is not ErrBadBaseURL", c.raw, err)
			}
			continue
		}
		if u.String() != c.want {
			t.Errorf("CheckBaseURL(%q) = %q, want %q", c.raw, u.String(), c.want)
		}
	}
}

// TestGatewaySourcesAreWellFormed: every self-hosted source needs a required
// base_url and has no fixed host; every fixed-host source has hosts.
func TestGatewaySourcesAreWellFormed(t *testing.T) {
	gateways := 0
	for _, s := range Sources {
		if s.UserBaseURL {
			gateways++
			if len(s.Hosts) != 0 {
				t.Errorf("%s: a gateway source must not list fixed hosts", s.ID)
			}
			if len(s.Params) == 0 || s.Params[0].Key != ParamBaseURL || !s.Params[0].Required {
				t.Errorf("%s: a gateway source needs a required %s first", s.ID, ParamBaseURL)
			}
		}
	}
	if gateways != 6 {
		t.Errorf("gateway sources = %d, want 6 (litellm, bifrost, aixy, llm proxy, clawrouter, sub2api)", gateways)
	}
}

// --- plan: URL, host, secret placement, missing secret --------------------------

func TestLaneBPlans(t *testing.T) {
	base := map[string]string{ParamBaseURL: "https://gw.example.com:8443/v1/"}
	cases := []struct {
		src     string
		params  map[string]string
		secrets map[string]string
		url     string
		header  string // the secret header name
		value   string // its exact value
	}{
		{SourceLiteLLMGateway, base, map[string]string{"key": "K"}, "https://gw.example.com:8443/key/info", "Authorization", "Bearer K"},
		{SourceBifrostGateway, map[string]string{ParamBaseURL: "https://bf.example.com/gateway/"}, map[string]string{"key": "vk-1"}, "https://bf.example.com/gateway/api/governance/virtual-keys/quota", "x-bf-vk", "vk-1"},
		{SourceAixyAPI, nil, map[string]string{"key": "K"}, "https://api.aixy-gateway.com/v1/usage", "Authorization", "Bearer K"},
		{SourceAixyGateway, base, map[string]string{"key": "K"}, "https://gw.example.com:8443/v1/usage", "Authorization", "Bearer K"},
		{SourceLLMProxyGateway, map[string]string{ParamBaseURL: "http://127.0.0.1:8000"}, map[string]string{"key": "K"}, "http://127.0.0.1:8000/v1/quota-stats", "Authorization", "Bearer K"},
		{SourceClawRouterAPI, nil, map[string]string{"key": "K"}, "https://clawrouter.openclaw.ai/v1/usage", "Authorization", "Bearer K"},
		{SourceClawRouterGateway, base, map[string]string{"key": "K"}, "https://gw.example.com:8443/v1/usage", "Authorization", "Bearer K"},
		{SourceSub2APIGateway, base, map[string]string{"key": "K"}, "https://gw.example.com:8443/v1/usage?days=30&timezone=UTC", "Authorization", "Bearer K"},
		{SourceDeepgram, map[string]string{"project_id": "proj-1"}, map[string]string{"key": "K"}, "https://api.deepgram.com/v1/projects/proj-1/balances", "Authorization", "Token K"},
		{SourceHyper, nil, map[string]string{"key": "K"}, "https://hyper.charm.land/v1/credits", "Authorization", "Bearer K"},
		{SourceGitKrakenSession, nil, map[string]string{"session": "Authorization: Bearer tok"}, "https://api.gitkraken.dev/v1/ai-tasks/usage", "Authorization", "Bearer tok"},
		{SourceDevPass, nil, map[string]string{"key": "K"}, "https://api.llmgateway.io/v1/key", "Authorization", "Bearer K"},
		{SourceAtlasCloud, nil, map[string]string{"key": "K"}, "https://api.atlascloud.ai/public/v1/balance", "Authorization", "Bearer K"},
		{SourceVercelGateway, nil, map[string]string{"key": "K"}, "https://ai-gateway.vercel.sh/v1/credits", "Authorization", "Bearer K"},
		{SourceXKiro, nil, map[string]string{"key": "K"}, "https://api.xkiro.com/v1/usage", "Authorization", "Bearer K"},
		{SourceTavily, nil, map[string]string{"key": "K"}, "https://api.tavily.com/usage", "Authorization", "Bearer K"},
		{SourceLinkup, nil, map[string]string{"key": "K"}, "https://api.linkup.so/v1/credits/balance", "Authorization", "Bearer K"},
		{SourceExa, map[string]string{"api_key_id": "key-1"}, map[string]string{"mgmt": "S"}, "https://admin-api.exa.ai/team-management/api-keys/key-1/usage?end_date=2025-10-09T08%3A53%3A20.000Z&start_date=2025-10-01T00%3A00%3A00.000Z", "x-api-key", "S"},
		{SourceCosmic, map[string]string{"project_id": "p1"}, map[string]string{"pat": "cos_x"}, "https://dapi.cosmicjs.com/v3/projects/usage?project_id=p1", "Authorization", "Bearer cos_x"},
		{SourceAerostack, nil, map[string]string{"pat": "jwt"}, "https://api.aerostack.dev/api/billing/usage", "Authorization", "Bearer jwt"},
		{SourceSailResearch, nil, map[string]string{"key": "K"}, "https://api.sailresearch.com/v2/usage/summary?range=30d", "Authorization", "Bearer K"},
		{SourceSofya, nil, map[string]string{"key": "K"}, "https://sofya.co/v1/auth/me", "Authorization", "Bearer K"},
		{SourceFal, nil, map[string]string{"key": "K"}, "https://api.fal.ai/v1/account/billing?expand=credits", "Authorization", "Key K"},
		{SourceFlora, map[string]string{"workspace_id": "ws_abc123"}, map[string]string{"key": "ak_x"}, "https://app.flora.ai/api/v1/workspaces/ws_abc123/usage?end_date=2025-10-09&start_date=2025-10-01", "Authorization", "Bearer ak_x"},
	}
	for _, c := range cases {
		src, ok := SourceByID(c.src)
		if !ok {
			t.Fatalf("%s: no source row", c.src)
		}
		drv := Drivers[c.src]
		reqs, err := drv.Plan(PlanInput{Params: c.params, Secrets: c.secrets, Now: t0})
		if err != nil || len(reqs) == 0 {
			t.Fatalf("%s: plan %v %v", c.src, reqs, err)
		}
		r := reqs[0]
		if r.URL != c.url {
			t.Errorf("%s: url %q, want %q", c.src, r.URL, c.url)
		}
		if got := r.SecretHeaders[c.header]; got != c.value || len(r.SecretHeaders) != 1 {
			t.Errorf("%s: secret headers %v, want only %s", c.src, r.SecretHeaders, c.header)
		}
		for k, v := range r.Header {
			for _, sv := range c.secrets {
				if strings.Contains(v, SessionBearer(sv)) {
					t.Errorf("%s: plain header %s carries the secret", c.src, k)
				}
			}
		}
		anchor := r.Base
		if src.UserBaseURL {
			b, err := CheckBaseURL(c.params[ParamBaseURL])
			if err != nil || anchor != b.String() {
				t.Errorf("%s: anchor %q, want the checked base", c.src, anchor)
			}
			if !strings.HasPrefix(r.URL, strings.TrimSuffix(b.String(), "/v1")) {
				t.Errorf("%s: url %q is not under the base", c.src, r.URL)
			}
		} else {
			if anchor != "" {
				t.Errorf("%s: a fixed-host request must not name a base", c.src)
			}
			host := strings.SplitN(strings.TrimPrefix(r.URL, "https://"), "/", 2)[0]
			if !strings.HasPrefix(r.URL, "https://") || !containsStr(src.Hosts, host) {
				t.Errorf("%s: host %q not in %v", c.src, host, src.Hosts)
			}
		}
		// A missing secret is a sign-in problem, never a request.
		if _, err := drv.Plan(PlanInput{Params: c.params, Now: t0}); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: missing secret err=%v, want ErrAuth", c.src, err)
		}
	}
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// TestLaneBPlanRefusals: bad ids and bad base URLs never become a request.
func TestLaneBPlanRefusals(t *testing.T) {
	key := map[string]string{"key": "K", "mgmt": "K", "pat": "K"}
	cases := []struct {
		src    string
		params map[string]string
	}{
		{SourceLiteLLMGateway, nil},
		{SourceLiteLLMGateway, map[string]string{ParamBaseURL: "http://gw.example.com"}},
		{SourceBifrostGateway, map[string]string{ParamBaseURL: "https://u:p@gw.example.com"}},
		{SourceSub2APIGateway, map[string]string{ParamBaseURL: "https://gw.example.com?x=1"}},
		{SourceDeepgram, map[string]string{"project_id": "../x"}},
		{SourceExa, map[string]string{"api_key_id": "a/b"}},
		{SourceCosmic, map[string]string{"project_id": "p&x=1"}},
		{SourceFlora, map[string]string{"workspace_id": "ws_a/../b"}},
		{SourceFlora, map[string]string{"workspace_id": "abc"}},
	}
	for _, c := range cases {
		if reqs, err := Drivers[c.src].Plan(PlanInput{Params: c.params, Secrets: key, Now: t0}); err == nil {
			t.Errorf("%s %v: want refusal, got %v", c.src, c.params, reqs)
		}
	}
	// The optional LiteLLM user and team reads ride on the same base.
	reqs, err := Drivers[SourceLiteLLMGateway].Plan(PlanInput{
		Params: map[string]string{ParamBaseURL: "https://gw.example.com", "user_id": "u 1", "team_id": "t&1"}, Secrets: key, Now: t0,
	})
	if err != nil || len(reqs) != 3 {
		t.Fatalf("litellm optional reads: %v %v", reqs, err)
	}
	if reqs[1].URL != "https://gw.example.com/user/info?user_id=u+1" || !reqs[1].Optional ||
		reqs[2].URL != "https://gw.example.com/team/info?team_id=t%261" || reqs[2].Base != "https://gw.example.com" {
		t.Errorf("litellm optional reads: %+v", reqs[1:])
	}
	// GitKraken's optional org header is plain, the token secret.
	reqs, _ = Drivers[SourceGitKrakenSession].Plan(PlanInput{Params: map[string]string{"org_id": "org-9"}, Secrets: map[string]string{"session": "tok"}})
	if reqs[0].Header["gk-org-id"] != "org-9" || reqs[0].SecretHeaders["Authorization"] != "Bearer tok" {
		t.Errorf("gitkraken headers %+v", reqs[0])
	}
	// Cosmic sends the dashboard origin it is documented to need.
	reqs, _ = Drivers[SourceCosmic].Plan(PlanInput{Params: map[string]string{"project_id": "p1"}, Secrets: key})
	if reqs[0].Header["Origin"] != "https://app.cosmicjs.com" {
		t.Errorf("cosmic origin %+v", reqs[0].Header)
	}
}

// --- parse: realistic fixtures ----------------------------------------------------

func TestParseLiteLLM(t *testing.T) {
	s := lbMust(t, SourceLiteLLMGateway, "litellm_key.json", map[string]Response{
		"user": {Status: 200, Body: fixture(t, "laneb/litellm_user.json")},
		"team": {Status: 200, Body: fixture(t, "laneb/litellm_team.json")},
	}, nil)
	k := lbWindow(t, s, "budget:key")
	lbNear(t, "key used", k.Used, 42_500_000)
	lbNear(t, "key limit", k.Limit, 100_000_000)
	lbNear(t, "key remaining", k.Remaining, 57_500_000)
	if k.Length == nil || *k.Length != 30*24*time.Hour || k.ResetsAt == nil {
		t.Errorf("key window length/reset %+v", k)
	}
	u := lbWindow(t, s, "budget:user")
	lbNear(t, "user used", u.Used, 212_350_000)
	if u.Length != nil {
		t.Error("a user budget with no duration claims no length")
	}
	lbWindow(t, s, "budget:team")
	if len(s.Spend) != 3 || s.Spend[0].Period != "cycle" || s.Spend[1].Period != "all_time" {
		t.Errorf("spend %+v", s.Spend)
	}
	// A failed optional read keeps the key reading.
	s = lbMust(t, SourceLiteLLMGateway, "litellm_key.json", map[string]Response{"user": {Status: 403}}, nil)
	if len(s.Windows) != 1 {
		t.Errorf("optional failure: %+v", s.Windows)
	}
}

func TestParseBifrost(t *testing.T) {
	s := lbMust(t, SourceBifrostGateway, "bifrost_quota.json", nil, nil)
	m := lbWindow(t, s, "budget:month")
	lbNear(t, "month used", m.Used, 42_170_000)
	lbNear(t, "month limit", m.Limit, 125_000_000)
	if m.Length != nil || m.ResetsAt != nil {
		t.Errorf("a calendar month claims no fixed length or reset: %+v", m)
	}
	h := lbWindow(t, s, "budget:hour")
	if h.Length == nil || *h.Length != time.Hour || h.ResetsAt == nil || !h.ResetsAt.After(t0) {
		t.Errorf("hour budget %+v", h)
	}
	if _, ok := FindWindow(s, "budget:open"); ok {
		t.Error("max_limit 0 is unlimited, never a window")
	}
	tok := lbWindow(t, s, "rate_limit:rl_1:tokens")
	if tok.Unit != UnitTokens || *tok.Limit != 1_000_000 {
		t.Errorf("token rate %+v", tok)
	}
	lbWindow(t, s, "rate_limit:rl_1:requests")
	if _, ok := FindWindow(s, "rate_limit:merged:tokens"); ok {
		t.Error("the merged rate_limit is used only without rate_limits")
	}
	lbWindow(t, s, "budget:openai:p1")
	if s.Status != StatusOK {
		t.Errorf("status %s", s.Status)
	}
	inactive, _ := lbParse(t, SourceBifrostGateway, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"is_active":false,"budgets":[]}`)}}, nil)
	if inactive.Status != StatusThrottled {
		t.Errorf("inactive key: %+v", inactive)
	}
}

func TestParseAixy(t *testing.T) {
	for _, src := range []string{SourceAixyAPI, SourceAixyGateway} {
		s := lbMust(t, src, "aixy_usage.json", nil, nil)
		m := lbWindow(t, s, "monthly:project")
		lbNear(t, src+" hard used (spent+reserved)", m.Used, 30_000_000)
		lbNear(t, src+" hard remaining", m.Remaining, 70_000_000)
		if m.Length == nil || m.ResetsAt == nil {
			t.Errorf("%s: monthly length/reset %+v", src, m)
		}
		d := lbWindow(t, s, "daily:api_key")
		lbNear(t, src+" monitor used", d.Used, 1_000_000)
		if len(s.Spend) != 1 || s.Spend[0].Amount != 1_250_000 || s.Spend[0].Period != "week" {
			t.Errorf("%s: spend %+v", src, s.Spend)
		}
	}
}

func TestParseLLMProxy(t *testing.T) {
	s := lbMust(t, SourceLLMProxyGateway, "llmproxy_quota.json", nil, nil)
	o := lbWindow(t, s, "quota:openai:default")
	lbNear(t, "openai used frac (remaining 42%)", o.UsedFrac, 0.58)
	if o.ResetsAt == nil {
		t.Error("future reset kept")
	}
	lbNear(t, "anthropic used frac", lbWindow(t, s, "quota:anthropic:0").UsedFrac, 0.20)
	if len(s.Spend) != 1 || s.Spend[0].Amount != 15_500_000 || s.Confidence != ConfEstimated {
		t.Errorf("approximate spend %+v %s", s.Spend, s.Confidence)
	}
}

func TestParseClawRouter(t *testing.T) {
	s := lbMust(t, SourceClawRouterAPI, "clawrouter_usage.json", nil, nil)
	w := lbWindow(t, s, "monthly")
	lbNear(t, "spent micros", w.Used, 6000)
	lbNear(t, "remaining micros", w.Remaining, 24_994_000)
	if w.ResetsAt == nil || !w.ResetsAt.Equal(time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("reset %v", w.ResetsAt)
	}
	un, err := lbParse(t, SourceClawRouterGateway, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"budget":{"configured":false,"ledger":"unmetered","limitMicros":null}}`)}}, nil)
	if err != nil || un.Status != StatusUnmetered {
		t.Errorf("unmetered: %+v %v", un, err)
	}
	mustValid(t, un)
}

func TestParseSub2API(t *testing.T) {
	s := lbMust(t, SourceSub2APIGateway, "sub2api_subscription.json", nil, nil)
	d := lbWindow(t, s, "daily")
	lbNear(t, "daily used", d.Used, 2_000_000)
	lbNear(t, "daily limit", d.Limit, 10_000_000)
	if d.Length == nil || *d.Length != 24*time.Hour {
		t.Errorf("daily length %+v", d)
	}
	lbWindow(t, s, "weekly")
	lbWindow(t, s, "monthly")
	f := lbWindow(t, s, "5h")
	lbNear(t, "5h remaining", f.Remaining, 15_000_000)
	lbWindow(t, s, "rate_limit:weekly")
	if b, ok := FindBalance(s, "wallet"); !ok || b.Amount != 8_000_000 || s.PlanLabel != "Team plan" {
		t.Errorf("wallet/plan %+v %q", s.Balances, s.PlanLabel)
	}
	q, err := lbParse(t, SourceSub2APIGateway, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"mode":"quota_limited","isValid":true,"unit":"USD","quota":{"limit":100,"used":100,"remaining":0}}`)}}, nil)
	if err != nil || q.Status != StatusThrottled {
		t.Errorf("quota used up: %+v %v", q, err)
	}
	if _, err := lbParse(t, SourceSub2APIGateway, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"isValid":false}`)}}, nil); !errors.Is(err, ErrAuth) {
		t.Errorf("invalid key: %v", err)
	}
}

func TestParseDeepgram(t *testing.T) {
	s := lbMust(t, SourceDeepgram, "deepgram_balances.json", nil, nil)
	if len(s.Balances) != 1 || s.Balances[0].Amount != 1_300_000_000 || s.Balances[0].Unit != UnitUSDMicros {
		t.Errorf("usd balances summed, hours dropped: %+v", s.Balances)
	}
	none, err := lbParse(t, SourceDeepgram, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"balances":[]}`)}}, nil)
	if err != nil || none.Status != StatusPlanOnly {
		t.Errorf("no balance: %+v %v", none, err)
	}
}

func TestParseDevPass(t *testing.T) {
	s := lbMust(t, SourceDevPass, "devpass_key.json", nil, nil)
	c := lbWindow(t, s, "cycle")
	lbNear(t, "cycle used", c.Used, 25_000_000)
	lbNear(t, "cycle remaining", c.Remaining, 212_000_000)
	p := lbWindow(t, s, "weekly:premium")
	if p.ResetsAt == nil || p.Length == nil || *p.Length != 7*24*time.Hour {
		t.Errorf("premium %+v", p)
	}
	if _, ok := FindWindow(s, "key_cap"); ok {
		t.Error("a null key limit is no cap")
	}
	if s.PlanCode != "pro" || len(s.Spend) != 1 || s.Spend[0].Amount != 31_420_000 {
		t.Errorf("plan/spend %q %+v", s.PlanCode, s.Spend)
	}
}

func TestParseXKiroTavilyCosmicAerostack(t *testing.T) {
	x := lbMust(t, SourceXKiro, "xkiro_usage.json", nil, nil)
	d := lbWindow(t, x, "daily")
	lbNear(t, "xkiro remaining", d.Remaining, 4_875_965)
	if d.ResetsAt == nil || !d.ResetsAt.Equal(time.Date(2025, 10, 10, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("xkiro reset %v", d.ResetsAt)
	}
	if b, ok := FindBalance(x, "wallet"); !ok || b.Amount != 4_812_300 {
		t.Errorf("xkiro wallet %+v", x.Balances)
	}

	tv := lbMust(t, SourceTavily, "tavily_usage.json", nil, nil)
	lbNear(t, "tavily plan used", lbWindow(t, tv, "monthly").Used, 500)
	lbNear(t, "tavily key remaining", lbWindow(t, tv, "key_cap").Remaining, 50)
	lbWindow(t, tv, "monthly:paygo")
	if tv.PlanLabel != "Bootstrap" || lbWindow(t, tv, "monthly").ResetsAt != nil {
		t.Errorf("tavily plan %q (no reset time claimed)", tv.PlanLabel)
	}

	c := lbMust(t, SourceCosmic, "cosmic_usage.json", nil, nil)
	lbNear(t, "cosmic input frac", lbWindow(t, c, "cycle:ai_input_tokens").UsedFrac, 0.25)
	lbNear(t, "cosmic output limit", lbWindow(t, c, "cycle:ai_output_tokens").Limit, 1_500_000)
	un, err := lbParse(t, SourceCosmic, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"usage":{"ai":{"input_tokens":5}},"plan_info":{"ai_tokens":{"max_input":"Unlimited"}}}`)}}, nil)
	if err != nil || un.Status != StatusUnmetered {
		t.Errorf("cosmic unlimited %+v %v", un, err)
	}

	a := lbMust(t, SourceAerostack, "aerostack_usage.json", nil, nil)
	lbNear(t, "aerostack ai tokens frac", lbWindow(t, a, "monthly:ai_tokens").UsedFrac, 0.15)
	if _, ok := FindWindow(a, "monthly:mcp_proxy_calls"); ok {
		t.Error("a null limit is no window")
	}
	if b, ok := FindBalance(a, "wallet"); !ok || b.Amount != 5_000_000 || a.PlanLabel != "starter" {
		t.Errorf("aerostack wallet cents / tier %+v %q", a.Balances, a.PlanLabel)
	}
}

func TestParseSailExaGitKraken(t *testing.T) {
	s := lbMust(t, SourceSailResearch, "sail_summary.json", nil, nil)
	if b, ok := FindBalance(s, "prepaid"); !ok || b.Amount != 123_456_700 {
		t.Errorf("sail balance from cents %+v", s.Balances)
	}
	if len(s.Spend) != 1 || s.Spend[0].Amount != 12_340_000 || s.Spend[0].Period != "30d" {
		t.Errorf("sail spend %+v", s.Spend)
	}
	out, err := Drivers[SourceSailResearch].Parse(ParseInput{Responses: map[string]Response{"main": {Status: 402}}, Now: t0})
	if err != nil || out.Status != StatusThrottled {
		t.Errorf("sail 402 is credits used up: %+v %v", out, err)
	}
	if _, err := lbParse(t, SourceSailResearch, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"object":"usage.summary","available":true,"has_metronome_customer":false}`)}}, nil); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("no billing account: %v", err)
	}

	e, err := lbParse(t, SourceExa, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"total_cost_usd":45.67,"period":{"start":"x","end":"y"},"cost_breakdown":[]}`)}}, nil)
	if err != nil || len(e.Spend) != 1 || e.Spend[0].Amount != 45_670_000 || e.Spend[0].Period != "month" {
		t.Errorf("exa spend %+v %v", e, err)
	}

	g := lbMust(t, SourceGitKrakenSession, "gitkraken_usage.json", nil, nil)
	w := lbWindow(t, g, "weekly")
	lbNear(t, "gitkraken remaining", w.Remaining, 387_500)
	lbWindow(t, g, "weekly:org_pool")
	unl, err := lbParse(t, SourceGitKrakenSession, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"data":{"used":5,"limit":-1},"error":null}`)}}, nil)
	if err != nil || unl.Status != StatusUnmetered {
		t.Errorf("gitkraken unlimited %+v %v", unl, err)
	}
}

// TestLaneBShapeErrors: a 2xx body without the documented shape is a shape
// error, never a zero.
func TestLaneBShapeErrors(t *testing.T) {
	cases := []struct{ src, body string }{
		{SourceLiteLLMGateway, `{"key":"x"}`},
		{SourceBifrostGateway, `{"name":"x"}`},
		{SourceAixyAPI, `{"object":"key.usage","currency":"EUR","budgets":[]}`},
		{SourceAixyGateway, `{"object":"other"}`},
		{SourceLLMProxyGateway, `{"summary":{}}`},
		{SourceClawRouterAPI, `{"budget":{}}`},
		{SourceClawRouterGateway, `{"budget":{"configured":true,"limitMicros":0,"spentMicros":1}}`},
		{SourceSub2APIGateway, `{"isValid":true,"unit":"GBP"}`},
		{SourceSub2APIGateway, `{"isValid":true}`},
		{SourceDeepgram, `{"projects":[]}`},
		{SourceDeepgram, `{"balances":[{"amount":5,"units":"hour"}]}`},
		{SourceHyper, `{"balance":"42.5"}`},
		{SourceHyper, `{"balance":-1}`},
		{SourceGitKrakenSession, `{"data":{"used":1},"error":null}`},
		{SourceGitKrakenSession, `{"data":{"used":1,"limit":5},"error":"nope"}`},
		{SourceDevPass, `{"data":{"usage":"1","devPlan":"gold"}}`},
		{SourceAtlasCloud, `{"object":"balance","scope":"team","available":{"value":"1","currency":"usd"}}`},
		{SourceAtlasCloud, `{"object":"balance","scope":"account","available":{"value":1,"currency":"usd"}}`},
		{SourceVercelGateway, `{"balance":95.5,"total_used":"1"}`},
		{SourceXKiro, `{"object":"usage","free_tokens":{}}`},
		{SourceXKiro, `{"object":"other"}`},
		{SourceTavily, `{"key":{"usage":1,"limit":2}}`},
		{SourceLinkup, `{"balance":"12.5"}`},
		{SourceLinkup, `{}`},
		{SourceExa, `{"total_cost_usd":-1}`},
		{SourceCosmic, `{"usage":{"ai":{"input_tokens":5}},"plan_info":{"ai_tokens":{"max_input":"lots"}}}`},
		{SourceAerostack, `{"tier":"x","usage":{}}`},
		{SourceSailResearch, `{"object":"usage.summary","available":true,"has_metronome_customer":true,"balance_unavailable":true,"effective_range":"1h","period_spend":1}`},
		{SourceSailResearch, `{"object":"usage"}`},
		{SourceSofya, `{"email":"x"}`},
		{SourceFal, `{"credits":{"current_balance":true}}`},
		{SourceFal, `{"credits":{"current_balance":1,"currency":"XYZ"}}`},
		{SourceFlora, `{"currency":"USD","available_cost":"7"}`},
		{SourceFlora, `<html>`},
	}
	for _, c := range cases {
		_, err := lbParse(t, c.src, "", map[string]Response{"main": {Status: 200, Body: []byte(c.body)}}, nil)
		if !errors.Is(err, ErrShape) {
			t.Errorf("%s %s: err=%v, want ErrShape", c.src, c.body, err)
		}
	}
	// fal's documented "200 without credits" is a retry, never a zero.
	if _, err := lbParse(t, SourceFal, "", map[string]Response{"main": {Status: 200, Body: []byte(`{"username":"x"}`)}}, nil); !errors.Is(err, ErrTransient) {
		t.Errorf("fal without credits: %v", err)
	}
	// An auth failure is classified for every source.
	for _, id := range []string{SourceLiteLLMGateway, SourceTavily, SourceGitKrakenSession, SourceFlora} {
		if _, err := lbParse(t, id, "", map[string]Response{"main": {Status: 401}}, nil); !errors.Is(err, ErrAuth) {
			t.Errorf("%s 401: %v", id, err)
		}
	}
}

// --- remaining first (D-681) -----------------------------------------------------

// TestLaneBHeadlines pins the card headline for every balance-group provider
// in lane B (what is LEFT first, used second when known), and the honest
// used-only headline for a provider that reports usage only.
func TestLaneBHeadlines(t *testing.T) {
	body := func(s string) map[string]Response {
		return map[string]Response{"main": {Status: 200, Body: []byte(s)}}
	}
	parse := func(src, fx string, extra map[string]Response) Snapshot {
		t.Helper()
		s, err := lbParse(t, src, fx, extra, nil)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		mustValid(t, s)
		return s
	}

	// Charm Hyper: Hypercredits left.
	wantLeft(t, "charm_hyper", headlineOf(t, parse(SourceHyper, "", body(`{"balance":42.5}`))), UnitCredits, 43, nil)
	// Atlas Cloud: the available balance.
	wantLeft(t, "atlas_cloud", headlineOf(t, parse(SourceAtlasCloud, "", body(`{"object":"balance","scope":"account","available":{"value":"95.50","currency":"usd"}}`))), UnitUSDMicros, 95_500_000, nil)
	// Vercel AI Gateway: the balance left, lifetime spend as used.
	wantLeft(t, "vercel_ai_gateway", headlineOf(t, parse(SourceVercelGateway, "", body(`{"balance":"95.50","total_used":"4.50"}`))), UnitUSDMicros, 95_500_000, F(4_500_000))
	// Linkup: the prepaid balance.
	wantLeft(t, "linkup", headlineOf(t, parse(SourceLinkup, "", body(`{"balance":123.456}`))), UnitUSDMicros, 123_456_000, nil)
	// Sail Research: the balance left, recent spend as used.
	wantLeft(t, "sail_research", headlineOf(t, parse(SourceSailResearch, "sail_summary.json", nil)), UnitUSDMicros, 123_456_700, F(12_340_000))
	// Sofya: available credits (plan and purchased are parts, never "of").
	h := headlineOf(t, parse(SourceSofya, "sofya_me.json", nil))
	wantLeft(t, "sofya", h, UnitCredits, 1034, nil)
	if h.Of != nil {
		t.Errorf("sofya: purchased credits are a part, not the amount bought: %+v", h)
	}
	// fal: the credit balance.
	wantLeft(t, "fal", headlineOf(t, parse(SourceFal, "", body(`{"username":"t","credits":{"current_balance":"12.75","currency":"USD"}}`))), UnitUSDMicros, 12_750_000, nil)
	// FLORA (workspace): available, month spend as used.
	wantLeft(t, "flora", headlineOf(t, parse(SourceFlora, "flora_workspace.json", nil)), UnitUSDMicros, 128_400_000, F(12_500_000))
	// FLORA (member): available of the monthly member allowance.
	h = headlineOf(t, parse(SourceFlora, "flora_caller.json", nil))
	wantLeft(t, "flora member", h, UnitUSDMicros, 7_250_000, F(42_750_000))
	if h.Of == nil || *h.Of != 50_000_000 {
		t.Errorf("flora member of: %+v", h)
	}

	// Usage-group vendors with a balance or a budget also lead with what is left.
	wantLeft(t, "deepgram", headlineOf(t, parse(SourceDeepgram, "deepgram_balances.json", nil)), UnitUSDMicros, 1_300_000_000, nil)
	wantLeft(t, "clawrouter", headlineOf(t, parse(SourceClawRouterAPI, "clawrouter_usage.json", nil)), UnitUSDMicros, 24_994_000, F(6000))
	wantLeft(t, "litellm", headlineOf(t, parse(SourceLiteLLMGateway, "litellm_key.json", nil)), UnitUSDMicros, 57_500_000, F(42_500_000))

	// Exa reports month-to-date spend only: the card says so.
	h = headlineOf(t, parse(SourceExa, "", body(`{"total_cost_usd":45.67}`)))
	if h.Kind != HeadlineUsedOnly || h.Value == nil || *h.Value != 45_670_000 || h.Basis != "spend:month" {
		t.Errorf("exa used only: %+v", h)
	}
	// LiteLLM with no budget anywhere: spend only, never a pretend balance.
	h = headlineOf(t, parse(SourceLiteLLMGateway, "", body(`{"info":{"spend":3.5,"max_budget":null}}`)))
	if h.Kind != HeadlineUsedOnly || *h.Value != 3_500_000 {
		t.Errorf("litellm spend only: %+v", h)
	}
}
