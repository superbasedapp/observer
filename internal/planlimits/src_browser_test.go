package planlimits

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Lane C1 tests: fixture only, never a live call. Fixtures in
// testdata/lanec1 are our own JSON and HTML built from the shapes CodexBar
// documents.

func c1Fix(t *testing.T, name string) []byte {
	t.Helper()
	return fixture(t, "lanec1/"+name)
}

// c1R builds a response map from key/body pairs (status 200).
func c1R(kv ...any) map[string]Response {
	out := map[string]Response{}
	for i := 0; i+1 < len(kv); i += 2 {
		k := kv[i].(string)
		switch b := kv[i+1].(type) {
		case []byte:
			out[k] = Response{Key: k, Status: 200, Body: b}
		case string:
			out[k] = Response{Key: k, Status: 200, Body: []byte(b)}
		case int:
			out[k] = Response{Key: k, Status: b}
		}
	}
	return out
}

// c1PlanCase is one source's planning input with a recognisable secret.
type c1PlanCase struct {
	src    string
	params map[string]string
	secret map[string]string
}

// The secret value in every case contains SECRET so the test can prove it
// never leaks into a plain header or the URL.
var c1PlanCases = []c1PlanCase{
	{c1SrcOpenCode, map[string]string{c1ParamWorkspace: "wrk_01ABC"}, map[string]string{SecretSession: "auth=SECRET1; __Host-console_session=SECRET2"}},
	{c1SrcAliCodingAPI, map[string]string{c1ParamRegion: c1RegionCN}, map[string]string{SecretKey: "sk-SECRET"}},
	{c1SrcAliCodingWeb, nil, map[string]string{SecretSession: "login_aliyunid_csrf=SECRETCSRF; cna=anon1; sec_token=SECRETTOK"}},
	{c1SrcAliTokenWeb, map[string]string{c1ParamRegion: c1RegionCN}, map[string]string{SecretSession: "login_aliyunid_ticket=SECRET"}},
	{c1SrcQwenCloud, nil, map[string]string{SecretSession: "login_qwencloud_ticket=SECRET; csrf=SECRETCSRF"}},
	{c1SrcDevin, map[string]string{c1ParamOrg: "org_abc123"}, map[string]string{SecretSession: "Authorization: Bearer auth1_SECRET"}},
	{c1SrcManus, nil, map[string]string{SecretSession: "foo=1; session_id=SECRET"}},
	{c1SrcT3Chat, nil, map[string]string{SecretSession: "Cookie: convex-session=SECRET"}},
	{c1SrcLangdock, nil, map[string]string{SecretSession: "auth_token=SECRET"}},
	{c1SrcOllamaAPI, nil, map[string]string{SecretKey: "SECRET"}},
	{c1SrcZed, nil, map[string]string{SecretSession: "zed.session=SECRET"}},
	{c1SrcPerplexity, nil, map[string]string{SecretSession: "SECRET"}},
	{c1SrcMiMo, nil, map[string]string{SecretSession: "api-platform_serviceToken=SECRET; userId=42"}},
	{c1SrcSakana, nil, map[string]string{SecretSession: "session=SECRET"}},
	{c1SrcAbacus, nil, map[string]string{SecretSession: "sessionid=SECRET"}},
	{c1SrcMistral, nil, map[string]string{SecretSession: "ory_session_abc=SECRET; csrftoken=SECRETCSRF; other=SECRETX"}},
	{c1SrcQoder, map[string]string{c1ParamRegion: c1RegionChina}, map[string]string{SecretSession: "qoder_session=SECRET"}},
}

// TestLaneC1PlansStayInsideTheirHosts: every HTTP request goes to a host the
// source row names, every secret travels only in SecretHeaders (or, for a
// console sec_token copied from the paste, the form body), and a missing
// secret is a sign-in error before anything is sent.
func TestLaneC1PlansStayInsideTheirHosts(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range c1PlanCases {
		seen[c.src] = true
		src, ok := SourceByID(c.src)
		if !ok {
			t.Fatalf("%s: no source row", c.src)
		}
		reqs, err := Drivers[c.src].Plan(PlanInput{Params: c.params, Secrets: c.secret, Now: t0})
		if err != nil || len(reqs) == 0 {
			t.Fatalf("%s: plan %v %v", c.src, reqs, err)
		}
		for _, r := range reqs {
			u, err := url.Parse(r.URL)
			if err != nil || u.Scheme != "https" {
				t.Errorf("%s: url %q", c.src, r.URL)
				continue
			}
			okHost := false
			for _, h := range src.Hosts {
				okHost = okHost || h == u.Host
			}
			if !okHost {
				t.Errorf("%s: host %s not in %v", c.src, u.Host, src.Hosts)
			}
			if strings.Contains(r.URL, "SECRET") {
				t.Errorf("%s: secret in URL", c.src)
			}
			for k, v := range r.Header {
				if strings.Contains(v, "SECRET") {
					t.Errorf("%s: secret in plain header %s", c.src, k)
				}
			}
			if len(r.SecretHeaders) == 0 {
				t.Errorf("%s: request %s carries no credential", c.src, r.Key)
			}
		}
		if _, err := Drivers[c.src].Plan(PlanInput{Params: c.params, Now: t0}); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: missing secret must be ErrAuth, got %v", c.src, err)
		}
	}
	for _, s := range Sources {
		if len(s.Hosts) > 0 && c1Owned(s.ID) && !seen[s.ID] {
			t.Errorf("lane C1 source %s has no planning case", s.ID)
		}
	}
}

// c1Owned reports a lane C1 source id.
func c1Owned(id string) bool {
	for _, c := range []string{
		c1SrcOpenCode, c1SrcAliCodingAPI, c1SrcAliCodingWeb, c1SrcAliTokenCLI, c1SrcAliTokenWeb, c1SrcQwenCloud,
		c1SrcDevin, c1SrcManus, c1SrcT3Chat, c1SrcLangdock, c1SrcOllamaAPI, c1SrcZed, c1SrcPerplexity, c1SrcMiMo,
		c1SrcSakana, c1SrcAbacus, c1SrcMistral, c1SrcQoder,
	} {
		if c == id {
			return true
		}
	}
	return false
}

// TestLaneC1AuthHeaders pins how each auth method travels: a bearer key, a
// key in vendor headers, a pasted Cookie, a pasted bearer token, and a vendor
// CLI with no credential at all.
func TestLaneC1AuthHeaders(t *testing.T) {
	plan := func(src string, params, secrets map[string]string) []Request {
		t.Helper()
		reqs, err := Drivers[src].Plan(PlanInput{Params: params, Secrets: secrets, Now: t0})
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		return reqs
	}
	cases := []struct {
		name string
		reqs []Request
		want map[string]string
	}{
		{
			"own key, bearer (ollama)", plan(c1SrcOllamaAPI, nil, map[string]string{SecretKey: " K "}),
			map[string]string{"Authorization": "Bearer K"},
		},
		{
			"own key, vendor headers (alibaba)", plan(c1SrcAliCodingAPI, nil, map[string]string{SecretKey: "K"}),
			map[string]string{"Authorization": "Bearer K", "x-api-key": "K", "X-DashScope-API-Key": "K"},
		},
		{
			"pasted cookie (zed)", plan(c1SrcZed, nil, map[string]string{SecretSession: "Cookie: zed.session=abc"}),
			map[string]string{"Cookie": "zed.session=abc"},
		},
		{
			"pasted bearer (devin)", plan(c1SrcDevin, map[string]string{c1ParamOrg: "org-1"}, map[string]string{SecretSession: "Bearer tok"}),
			map[string]string{"Authorization": "Bearer tok"},
		},
		{
			"cookie to bearer (manus)", plan(c1SrcManus, nil, map[string]string{SecretSession: "a=1; session_id=xyz"}),
			map[string]string{"Authorization": "Bearer xyz"},
		},
		{
			"bare manus token", plan(c1SrcManus, nil, map[string]string{SecretSession: "xyz"}),
			map[string]string{"Authorization": "Bearer xyz"},
		},
	}
	for _, c := range cases {
		got := c.reqs[0].SecretHeaders
		if len(got) != len(c.want) {
			t.Errorf("%s: secret headers %v, want %v", c.name, got, c.want)
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s = %q, want %q", c.name, k, got[k], v)
			}
		}
	}
	// The vendor CLI carries no credential: Bailian's own sign-in is used.
	cli := plan(c1SrcAliTokenCLI, map[string]string{c1ParamRegion: c1RegionCN, c1ParamVariant: c1VariantPersonal}, nil)
	if cli[0].Kind != ReqExec || cli[0].Argv[0] != "bl" || len(cli[0].SecretHeaders) != 0 ||
		!strings.Contains(strings.Join(cli[0].Argv, " "), "--console-region cn-beijing --console-site domestic --output json") ||
		cli[0].Argv[1] != "console" {
		t.Errorf("bailian cli %+v", cli[0])
	}
	if src, _ := SourceByID(c1SrcAliTokenCLI); src.Command != "bl" || len(src.Hosts) != 0 {
		t.Errorf("bailian cli row %+v", src)
	}
	if _, err := Drivers[c1SrcAliTokenCLI].Plan(PlanInput{Params: map[string]string{c1ParamVariant: "family"}}); err == nil {
		t.Error("unknown variant must be refused")
	}
	// Perplexity: a bare token rides under every session cookie name.
	pp := plan(c1SrcPerplexity, nil, map[string]string{SecretSession: "tok"})
	for _, n := range c1PerplexityNames {
		if !strings.Contains(pp[0].SecretHeaders["Cookie"], n+"=tok") {
			t.Errorf("perplexity bare token missing %s: %q", n, pp[0].SecretHeaders["Cookie"])
		}
	}
	// Mistral: the console host gets only the session and CSRF cookies.
	ms := plan(c1SrcMistral, nil, map[string]string{SecretSession: "ory_session_a=s; csrftoken=c; other=x"})
	if len(ms) != 2 || ms[1].SecretHeaders["Cookie"] != "csrftoken=c; ory_session_a=s" || ms[1].SecretHeaders["X-CSRFToken"] != "c" ||
		ms[0].SecretHeaders["X-CSRFTOKEN"] != "c" || !strings.Contains(ms[0].SecretHeaders["Cookie"], "other=x") {
		t.Errorf("mistral plan %+v", ms)
	}
	if ms := plan(c1SrcMistral, nil, map[string]string{SecretSession: "ory_session_a=s"}); len(ms) != 1 {
		t.Errorf("mistral without csrf must skip the console read: %d", len(ms))
	}
	for _, c := range []struct {
		src    string
		params map[string]string
		paste  string
	}{
		{c1SrcMistral, nil, "csrftoken=c"},
		{c1SrcMiMo, nil, "userId=1"},
		{c1SrcManus, nil, "a=1; b=2"},
	} {
		if _, err := Drivers[c.src].Plan(PlanInput{Params: c.params, Secrets: map[string]string{SecretSession: c.paste}}); !errors.Is(err, ErrAuth) {
			t.Errorf("%s with %q must be ErrAuth, got %v", c.src, c.paste, err)
		}
	}
	for _, c := range []struct {
		src    string
		params map[string]string
	}{
		{c1SrcDevin, map[string]string{c1ParamOrg: "../x"}},
		{c1SrcOpenCode, map[string]string{c1ParamWorkspace: "wrk_1/../x"}},
		{c1SrcQoder, map[string]string{c1ParamRegion: "mars"}},
		{c1SrcAliCodingWeb, map[string]string{c1ParamRegion: "mars"}},
	} {
		if _, err := Drivers[c.src].Plan(PlanInput{Params: c.params, Secrets: map[string]string{SecretSession: "a=b"}}); err == nil {
			t.Errorf("%s with %v must be refused", c.src, c.params)
		}
	}
}

func TestLaneC1OpenCode(t *testing.T) {
	reqs, _ := c1PlanOpenCode(PlanInput{Params: map[string]string{c1ParamWorkspace: "https://opencode.ai/workspace/wrk_9Z/usage"}, Secrets: map[string]string{SecretSession: "a=b"}})
	if len(reqs) != 3 || reqs[0].Header["x-org-id"] != "wrk_9Z" || reqs[0].Optional || !reqs[1].Optional || !reqs[2].Optional {
		t.Fatalf("plan %+v", reqs)
	}
	s, err := c1ParseOpenCode(ParseInput{Now: t0, Responses: c1R("go", c1Fix(t, "opencode_go_status.json"), "billing", c1Fix(t, "opencode_billing.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	w5, _ := FindWindow(s, "5h")
	mo, _ := FindWindow(s, "monthly")
	if len(s.Windows) != 3 || w5.Unit != UnitUSDMicros || !approx(*w5.Limit, 12_000_000) || *w5.Length != 5*time.Hour ||
		mo.ResetsAt == nil || mo.ResetsAt.Month() != time.November {
		t.Errorf("windows %+v", s.Windows)
	}
	if b, ok := FindBalance(s, "prepaid"); !ok || b.Amount != 27_867_810 {
		t.Errorf("zen balance %+v", b)
	}
	weekUsed := 703_325_271.0 / 100 // the meter is in micro-cents
	wantLeft(t, "opencode go", headlineOf(t, s), UnitUSDMicros, 30_000_000-weekUsed, F(weekUsed))

	// No Go plan, pay-as-you-go: the prepaid balance leads, 30-day spend second.
	s, err = c1ParseOpenCode(ParseInput{Now: t0, Responses: c1R("go", "null", "billing", c1Fix(t, "opencode_billing.json"), "summary", c1Fix(t, "opencode_summary.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	wantLeft(t, "opencode payg", headlineOf(t, s), UnitUSDMicros, 27_867_810, F(12_345_000))

	for name, c := range map[string]struct {
		resp map[string]Response
		want error
	}{
		"no meters":   {c1R("go", `{"access":{"plan":"go"}}`), ErrShape},
		"not json":    {c1R("go", `<html>`), ErrShape},
		"seat billed": {c1R("go", `{"access":null}`, "billing", `{"billingMode":"seat","mode":"invoiceable"}`), ErrNotApplicable},
		"signed out":  {c1R("go", 401), ErrAuth},
	} {
		if _, err := c1ParseOpenCode(ParseInput{Now: t0, Responses: c.resp}); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
}

func TestLaneC1AlibabaCodingPlan(t *testing.T) {
	s, err := c1ParseAliCodingAPI(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "alibaba_coding.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if s.PlanLabel != "Alibaba Coding Plan Pro" || len(s.Windows) != 3 {
		t.Errorf("snapshot %+v", s)
	}
	if w, _ := FindWindow(s, "5h"); w.ResetsAt == nil || w.ResetsAt.Unix() != 1_790_000_300 || *w.Limit != 1000 {
		t.Errorf("5h %+v", w)
	}
	wantLeft(t, "alibaba coding", headlineOf(t, s), UnitRequests, 4200, F(800))

	// The console wraps its payload in a JSON string and lists instances;
	// the active one is read, never an expired sibling.
	s, err = c1ParseAliCodingWeb(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "alibaba_coding_console.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if w, ok := FindWindow(s, "5h"); !ok || *w.Used != 10 || s.PlanLabel != "Lite" {
		t.Errorf("console %+v", s)
	}

	s, err = c1ParseAliCodingWeb(ParseInput{Now: t0, Responses: c1R("main", `{"data":{"codingPlanInstanceInfos":[{"planName":"Pro","status":"VALID"}]}}`)})
	if err != nil || s.Status != StatusPlanOnly || s.PlanLabel != "Pro" {
		t.Errorf("active plan without counters: %+v %v", s, err)
	}
	mustValid(t, s)

	login := `{"code":"ConsoleNeedLogin","message":"please log in"}`
	if _, err := c1ParseAliCodingWeb(ParseInput{Now: t0, Responses: c1R("main", login)}); !errors.Is(err, ErrAuth) {
		t.Errorf("session login: %v", err)
	}
	if _, err := c1ParseAliCodingAPI(ParseInput{Now: t0, Responses: c1R("main", login)}); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("key route that needs a console session: %v", err)
	}
	if _, err := c1ParseAliCodingAPI(ParseInput{Now: t0, Responses: c1R("main", `{"data":{}}`)}); !errors.Is(err, ErrShape) {
		t.Errorf("no counters: %v", err)
	}

	// The session plan: form body with the console envelope, sec_token from
	// the paste, CSRF headers secret.
	reqs, _ := c1PlanAliCodingWeb(PlanInput{Now: t0, Secrets: map[string]string{SecretSession: "login_aliyunid_csrf=C1; cna=anon; sec_token=T1"}})
	r := reqs[0]
	form, err := url.ParseQuery(string(r.Body))
	if err != nil || form.Get("sec_token") != "T1" || form.Get("region") != "ap-southeast-1" ||
		!strings.Contains(form.Get("params"), `"commodityCode":"sfm_codingplan_public_intl"`) ||
		!strings.Contains(form.Get("params"), `"X-Anonymous-Id":"anon"`) ||
		r.SecretHeaders["x-xsrf-token"] != "C1" || r.Method != "POST" ||
		!strings.HasPrefix(r.URL, "https://bailian-singapore-cs.alibabacloud.com/data/api.json?") {
		t.Errorf("console plan %+v form %v", r, form)
	}
	again, _ := c1PlanAliCodingWeb(PlanInput{Now: t0, Secrets: map[string]string{SecretSession: "login_aliyunid_csrf=C1; cna=anon; sec_token=T1"}})
	if string(again[0].Body) != string(r.Body) {
		t.Error("planning must be repeatable for the same time")
	}
}

func TestLaneC1TokenPlanAndQwen(t *testing.T) {
	resp := c1R("usage", c1Fix(t, "token_usage.json"), "subscription", c1Fix(t, "token_subscription.json"), "quota_config", c1Fix(t, "token_quota_config.json"))
	for _, c := range []struct {
		name  string
		parse func(ParseInput) (Snapshot, error)
	}{{"token plan", c1ParseAliTokenWeb}, {"qwen cloud", c1ParseQwenCloud}} {
		s, err := c.parse(ParseInput{Now: t0, Responses: resp})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		mustValid(t, s)
		if s.PlanLabel != "Pro" || len(s.Windows) != 2 {
			t.Errorf("%s: %+v", c.name, s)
		}
		if _, ok := FindWindow(s, "monthly"); ok {
			t.Errorf("%s: a -1 ratio is unknown, never a window", c.name)
		}
		wantLeft(t, c.name, headlineOf(t, s), UnitCredits, 48, F(112))
	}
	// Without the tier, the windows stay percentages.
	s, err := c1ParseQwenCloud(ParseInput{Now: t0, Responses: c1R("usage", c1Fix(t, "token_usage.json"))})
	if err != nil {
		t.Fatal(err)
	}
	if h := headlineOf(t, s); h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.3) {
		t.Errorf("percent headline %+v", h)
	}
	for name, c := range map[string]struct {
		body string
		want error
	}{
		"empty success":  {`{"code":"200","data":{}}`, ErrTransient},
		"not logged in":  {`{"code":"NotLogin","message":"Please login"}`, ErrAuth},
		"login html":     {`<html><body>Please sign in</body></html>`, ErrAuth},
		"other html":     {`<html><body>maintenance</body></html>`, ErrShape},
		"gateway failed": {`{"success":false,"code":"Throttling.User"}`, ErrTransient},
	} {
		if _, err := c1ParseAliTokenWeb(ParseInput{Now: t0, Responses: c1R("usage", c.body)}); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
	reqs, _ := c1PlanQwenCloud(PlanInput{Now: t0, Secrets: map[string]string{SecretSession: "a=1; sec_token=T2"}})
	if len(reqs) != 3 || reqs[0].Optional || !reqs[1].Optional || !reqs[2].Optional {
		t.Fatalf("qwen plan %+v", reqs)
	}
	form, _ := url.ParseQuery(string(reqs[1].Body))
	if form.Get("product") != "sfm_bailian" || form.Get("action") != "IntlBroadScopeAspnGateway" || form.Get("sec_token") != "T2" ||
		!strings.Contains(form.Get("params"), c1QwenSoloCommodity) || !strings.Contains(reqs[1].URL, "subscription") {
		t.Errorf("qwen subscription form %v", form)
	}
}

func TestLaneC1BailianCLI(t *testing.T) {
	s, err := c1ParseAliTokenCLI(ParseInput{Now: t0, Responses: c1R("out", c1Fix(t, "bailian_cli.txt"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if len(s.Windows) != 3 || s.Kind != KindVendorCLI || s.Rung != RungOfficial {
		t.Errorf("cli %+v", s)
	}
	if h := headlineOf(t, s); h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.3) || h.Basis != "window:weekly" {
		t.Errorf("cli headline %+v", h)
	}
	for out, want := range map[string]error{
		"Error: not logged in, run bl login": ErrAuth,
		"segmentation fault":                 ErrShape,
		`{"per5HourPercentage":"x"}`:         ErrTransient,
	} {
		if _, err := c1ParseAliTokenCLI(ParseInput{Now: t0, Responses: c1R("out", out)}); !errors.Is(err, want) {
			t.Errorf("%q: want %v, got %v", out, want, err)
		}
	}
}

func TestLaneC1Devin(t *testing.T) {
	reqs, _ := c1PlanDevin(PlanInput{Params: map[string]string{c1ParamOrg: "org_abc123"}, Secrets: map[string]string{SecretSession: "tok"}})
	if reqs[0].URL != "https://app.devin.ai/api/org_abc123/billing/quota/usage" || reqs[0].Header["x-cog-org-id"] != "org_abc123" {
		t.Errorf("plan %+v", reqs[0])
	}
	s, err := c1ParseDevin(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "devin_usage.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if d, ok := FindWindow(s, "daily"); !ok || !approx(*d.UsedFrac, 0.12) || d.ResetsAt.Unix() != 1_790_000_000 {
		t.Errorf("daily %+v", d)
	}
	if b, _ := FindBalance(s, "prepaid"); b.Amount != 70_870_000 {
		t.Errorf("extra usage balance %+v", b)
	}
	if h := headlineOf(t, s); h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.58) {
		t.Errorf("headline %+v", h)
	}
	s, _ = c1ParseDevin(ParseInput{Now: t0, Responses: c1R("main", `{"daily_percentage":99,"weekly_percentage":5,"hide_daily_quota":true,"overage_balance_cents":7087}`)})
	if _, ok := FindWindow(s, "daily"); ok {
		t.Error("a hidden daily quota is not shown")
	}
	if b, _ := FindBalance(s, "prepaid"); b.Amount != 70_870_000 {
		t.Errorf("cents balance %+v", b)
	}
	if _, err := c1ParseDevin(ParseInput{Now: t0, Responses: c1R("main", `{"detail":"nope"}`)}); !errors.Is(err, ErrShape) {
		t.Errorf("no readings: %v", err)
	}
}

func TestLaneC1Manus(t *testing.T) {
	s, err := c1ParseManus(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "manus_credits.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if b, _ := FindBalance(s, "credits"); b.Amount != 4200 || b.Unit != UnitCredits {
		t.Errorf("credits %+v", b)
	}
	wantLeft(t, "manus", headlineOf(t, s), UnitCredits, 100, F(200))
	s, _ = c1ParseManus(ParseInput{Now: t0, Responses: c1R("main", `{"maxRefreshCredits":300,"refreshCredits":300,"nextRefreshTime":812000000}`)})
	if w, ok := FindWindow(s, "daily"); !ok || w.ResetsAt.Unix() != 812_000_000+c1AppleEpoch {
		t.Errorf("reference-epoch reset %+v", w)
	}
	if _, err := c1ParseManus(ParseInput{Now: t0, Responses: c1R("main", `{"error":"bad"}`)}); !errors.Is(err, ErrShape) {
		t.Errorf("no credit fields: %v", err)
	}
}

func TestLaneC1T3Chat(t *testing.T) {
	s, err := c1ParseT3Chat(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "t3chat.jsonl"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if w, ok := FindWindow(s, "4h"); !ok || *w.Length != 4*time.Hour || s.PlanLabel != "T3 Pro" {
		t.Errorf("t3 %+v", s)
	}
	if w, ok := FindWindow(s, "extra_usage"); !ok || w.ResetsAt.Unix() != 1_792_000_000 {
		t.Errorf("overage %+v", w)
	}
	if h := headlineOf(t, s); h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.65) {
		t.Errorf("headline %+v", h)
	}
	if _, err := c1ParseT3Chat(ParseInput{Now: t0, Responses: c1R("main", `{"json":{}}`)}); !errors.Is(err, ErrShape) {
		t.Errorf("no customer data: %v", err)
	}
}

func TestLaneC1Langdock(t *testing.T) {
	s, err := c1ParseLangdock(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "langdock_usage.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if h := headlineOf(t, s); h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.45) || h.Basis != "window:weekly" {
		t.Errorf("headline %+v", h)
	}
	s, err = c1ParseLangdock(ParseInput{Now: t0, Responses: c1R("main", `[{"result":{"data":{"json":{"hasIncludedUsageLimits":false,"planUsage":null}}}}]`)})
	if err != nil || s.Status != StatusPlanOnly {
		t.Errorf("no included limits: %+v %v", s, err)
	}
	for body, want := range map[string]error{
		`[{"error":{"json":{"data":{"code":"UNAUTHORIZED"}}}}]`:      ErrAuth,
		`[{"error":{"json":{"data":{"code":"TOO_MANY_REQUESTS"}}}}]`: ErrRateLimited,
		`{"result":{}}`: ErrShape,
		`[{"result":{"data":{"json":{"planUsage":{"weeklyUsagePercent":5}}}}}]`: ErrShape,
	} {
		if _, err := c1ParseLangdock(ParseInput{Now: t0, Responses: c1R("main", body)}); !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", body, want, err)
		}
	}
}

func TestLaneC1Ollama(t *testing.T) {
	s, err := c1ParseOllama(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "ollama_balance.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if b, _ := FindBalance(s, "prepaid"); b.Amount != 10_000_000 {
		t.Errorf("purchased credits %+v", b)
	}
	wantLeft(t, "ollama", headlineOf(t, s), UnitUSDMicros, 52_500_000, F(7_500_000))
	s, _ = c1ParseOllama(ParseInput{Now: t0, Responses: c1R("main", `{"purchased":{"balance_usd":"3.25"}}`)})
	wantLeft(t, "ollama purchased only", headlineOf(t, s), UnitUSDMicros, 3_250_000, nil)
	for _, bad := range []string{`{"included":{"allowance_usd":"lots","balance_usd":1}}`, `{}`, `[]`} {
		if _, err := c1ParseOllama(ParseInput{Now: t0, Responses: c1R("main", bad)}); !errors.Is(err, ErrShape) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestLaneC1Zed(t *testing.T) {
	s, err := c1ParseZed(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "zed_usage.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if _, ok := FindWindow(s, "cycle:edit_predictions"); ok || s.PlanCode != "zed_pro" {
		t.Errorf("unlimited predictions have no window: %+v", s)
	}
	wantLeft(t, "zed", headlineOf(t, s), UnitUSDMicros, 37_660_000, F(12_340_000))
	s, _ = c1ParseZed(ParseInput{Now: t0, Responses: c1R("main", `{"plan":"free","current_usage":{"edit_predictions":{"used":120,"limit":{"limited":2000}},"token_spend":{"spend_in_cents":0,"limit_in_cents":null}}}`)})
	mustValid(t, s)
	if w, ok := FindWindow(s, "cycle:edit_predictions"); !ok || *w.Limit != 2000 {
		t.Errorf("limited predictions %+v", s.Windows)
	}
	if _, ok := FindWindow(s, "spend_limit"); ok {
		t.Error("no spend limit set means no spend window")
	}
	if _, err := c1ParseZed(ParseInput{Now: t0, Responses: c1R("main", `{"plan":"","current_usage":{}}`)}); !errors.Is(err, ErrShape) {
		t.Errorf("shape: %v", err)
	}
}

func TestLaneC1Perplexity(t *testing.T) {
	s, err := c1ParsePerplexity(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "perplexity_credits.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if b, _ := FindBalance(s, "available"); b.Amount != 12_500_000 || s.PlanCode != "pro" {
		t.Errorf("balance %+v plan %s", b, s.PlanCode)
	}
	if w, ok := FindWindow(s, "bonus"); !ok || *w.Limit != 2_000_000 || *w.Used != 0 {
		t.Errorf("an expired promo grant is dropped: %+v", w)
	}
	if _, ok := FindWindow(s, "purchased"); ok {
		t.Error("no purchased credits means no purchased window")
	}
	wantLeft(t, "perplexity", headlineOf(t, s), UnitUSDMicros, 1_500_000, F(3_500_000))
	if _, err := c1ParsePerplexity(ParseInput{Now: t0, Responses: c1R("main", `{"balance_cents":"x","total_usage_cents":1,"credit_grants":[]}`)}); !errors.Is(err, ErrShape) {
		t.Errorf("shape: %v", err)
	}
}

func TestLaneC1MiMo(t *testing.T) {
	s, err := c1ParseMiMo(ParseInput{Now: t0, Responses: c1R("balance", c1Fix(t, "mimo_balance.json"), "plan", c1Fix(t, "mimo_plan.json"), "usage", c1Fix(t, "mimo_usage.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if w, ok := FindWindow(s, "monthly"); !ok || *w.Used != 300 || w.ResetsAt.Month() != time.November || s.PlanCode != "lite" {
		t.Errorf("token plan %+v", s)
	}
	if b, _ := FindBalance(s, "granted"); b.Amount != 25_500_000 || b.Unit != UnitCNYMicros {
		t.Errorf("granted %+v", b)
	}
	// A balance vendor leads with the balance left, in its own currency.
	wantLeft(t, "mimo", headlineOf(t, s), UnitCNYMicros, 125_500_000, nil)
	for body, want := range map[string]error{
		`{"code":401,"message":"login"}`:                     ErrAuth,
		`{"code":0,"data":{"balance":"1","currency":"GBP"}}`: ErrShape,
		`{"code":500}`: ErrTransient,
		`{"data":{}}`:  ErrShape,
	} {
		if _, err := c1ParseMiMo(ParseInput{Now: t0, Responses: c1R("balance", body)}); !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", body, want, err)
		}
	}
}

func TestLaneC1Sakana(t *testing.T) {
	s, err := c1ParseSakana(ParseInput{Now: t0, Responses: c1R("billing", c1Fix(t, "sakana_billing.html"), "payg", c1Fix(t, "sakana_payg.html"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	w, _ := FindWindow(s, "5h")
	want := time.Date(2026, 10, 15, 15, 30, 0, 0, time.UTC)
	if !approx(*w.UsedFrac, 0.42) || w.ResetsAt == nil || !w.ResetsAt.Equal(want) || s.PlanLabel != "Standard" {
		t.Errorf("5h %+v plan %q", w, s.PlanLabel)
	}
	if b, _ := FindBalance(s, "prepaid"); b.Amount != 1_012_340_000 || len(s.Spend) != 1 || s.Spend[0].Amount != 5_670_000 {
		t.Errorf("payg %+v %+v", s.Balances, s.Spend)
	}
	if h := headlineOf(t, s); h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.58) {
		t.Errorf("headline %+v", h)
	}
	for body, want := range map[string]error{
		`<html><body><a>Sign in to continue</a></body></html>`: ErrAuth,
		`<p>5-hour</p><p>lots used</p>`:                        ErrShape,
		`<html><body>maintenance</body></html>`:                ErrShape,
	} {
		if _, err := c1ParseSakana(ParseInput{Now: t0, Responses: c1R("billing", body)}); !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", body, want, err)
		}
	}
}

func TestLaneC1Abacus(t *testing.T) {
	s, err := c1ParseAbacus(ParseInput{Now: t0, Responses: c1R("points", c1Fix(t, "abacus_points.json"), "billing", c1Fix(t, "abacus_billing.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if w, _ := FindWindow(s, "monthly"); w.ResetsAt == nil || s.PlanLabel != "Pro" {
		t.Errorf("abacus %+v", s)
	}
	wantLeft(t, "abacus", headlineOf(t, s), UnitCredits, 15000, F(5000))
	if _, err := c1ParseAbacus(ParseInput{Now: t0, Responses: c1R("points", `{"success":false,"error":"Session expired"}`)}); !errors.Is(err, ErrAuth) {
		t.Errorf("expired: %v", err)
	}
	if _, err := c1ParseAbacus(ParseInput{Now: t0, Responses: c1R("points", `{"success":true,"result":{"totalComputePoints":1}}`)}); !errors.Is(err, ErrShape) {
		t.Errorf("shape: %v", err)
	}
}

func TestLaneC1Mistral(t *testing.T) {
	s, err := c1ParseMistral(ParseInput{Now: t0, Responses: c1R("credits", c1Fix(t, "mistral_credits.json"), "vibe", c1Fix(t, "mistral_vibe.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if b, _ := FindBalance(s, "available"); b.Amount != 10_250_000 || b.Unit != UnitEURMicros {
		t.Errorf("available %+v", b)
	}
	if h := headlineOf(t, s); h.Kind != HeadlinePercentLeft || !approx(*h.Value, 0.6) {
		t.Errorf("headline %+v", h)
	}
	// Without the console read the wallet left leads.
	s, _ = c1ParseMistral(ParseInput{Now: t0, Responses: c1R("credits", c1Fix(t, "mistral_credits.json"))})
	wantLeft(t, "mistral wallet", headlineOf(t, s), UnitEURMicros, 10_250_000, nil)
	if _, err := c1ParseMistral(ParseInput{Now: t0, Responses: c1R("credits", `{"wallet_amount":1,"currency":"XYZ"}`)}); !errors.Is(err, ErrShape) {
		t.Errorf("shape: %v", err)
	}
}

func TestLaneC1Qoder(t *testing.T) {
	reqs, _ := c1PlanQoder(PlanInput{Params: map[string]string{c1ParamRegion: c1RegionChina}, Secrets: map[string]string{SecretSession: "a=b"}})
	if reqs[0].URL != "https://qoder.com.cn/api/v2/me/usages/big_model_credits" || reqs[0].Header["Origin"] != "https://qoder.com.cn" {
		t.Errorf("plan %+v", reqs[0])
	}
	s, err := c1ParseQoder(ParseInput{Now: t0, Responses: c1R("main", c1Fix(t, "qoder_credits.json"))})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if w, ok := FindWindow(s, "cycle:shared"); !ok || *w.Limit != 500 {
		t.Errorf("shared pool %+v", s.Windows)
	}
	wantLeft(t, "qoder", headlineOf(t, s), UnitCredits, 750, F(250))
	for _, bad := range []string{`{}`, `{"totalQuota":{"quotaSummary":{"usedValue":-1,"limitValue":10}}}`} {
		if _, err := c1ParseQoder(ParseInput{Now: t0, Responses: c1R("main", bad)}); !errors.Is(err, ErrShape) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// TestLaneC1RowsAreCovered: every lane C1 provider has a live source, no
// gap, and every lane source passes the shared row checks.
func TestLaneC1RowsAreCovered(t *testing.T) {
	want := map[string]Coverage{
		"opencode": CoverageSession, "alibaba_coding_plan": CoverageExperimental, "alibaba_token_plan": CoverageOfficial,
		"qwen_cloud": CoverageSession, "devin": CoverageSession, "manus": CoverageSession, "t3_chat": CoverageSession,
		"langdock": CoverageSession, "ollama": CoverageExperimental, "zed": CoverageSession, "perplexity": CoverageSession,
		"xiaomi_mimo": CoverageSession, "sakana": CoverageSession, "abacus": CoverageSession, "mistral": CoverageSession,
		"qoder": CoverageSession,
	}
	for id, cov := range want {
		p, ok := ProviderByID(id)
		if !ok || p.Gap != GapNone {
			t.Errorf("%s: row %+v", id, p)
		}
		if got := CoverageOf(id); got != cov {
			t.Errorf("%s: coverage %s, want %s", id, got, cov)
		}
	}
	for _, s := range Sources {
		if !c1Owned(s.ID) {
			continue
		}
		if s.Kind == KindBrowser && (len(s.Secrets) != 1 || s.Secrets[0].Key != SecretSession || !s.Experimental()) {
			t.Errorf("%s: a browser source takes one pasted session and is experimental", s.ID)
		}
		if s.Kind == KindOfficialAPI || s.Kind == KindAdminAPI {
			t.Errorf("%s: no lane C1 endpoint is vendor-documented", s.ID)
		}
	}
}
