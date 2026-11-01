package planlimits

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// src_lanec1.go holds lane C1 of the full provider catalogue (D-681): the
// vendors CodexBar reads mostly through a signed-in browser. Under the D-640
// ladder a browser session is rung 3: the user pastes a Cookie header (or, for
// Devin, a bearer token) and Observer never imports cookies from a browser,
// reads a keychain or another process. Where the vendor also answers the
// user's own key or its own CLI, that source comes first.
//
// Facts (endpoints, field names, units) come from the reference project
// CodexBar (MIT, discovery source); the code and fixtures are our own. Every
// identifier here carries a c1 prefix so parallel lanes in this package
// never collide.

// Lane C1 source ids.
const (
	c1SrcOpenCode       = "opencode.session"
	c1SrcAliCodingAPI   = "alibaba_coding_plan.api"
	c1SrcAliCodingWeb   = "alibaba_coding_plan.session"
	c1SrcAliTokenCLI    = "alibaba_token_plan.cli"
	c1SrcAliTokenWeb    = "alibaba_token_plan.session"
	c1SrcQwenCloud      = "qwen_cloud.session"
	c1SrcDevin          = "devin.session"
	c1SrcManus          = "manus.session"
	c1SrcT3Chat         = "t3_chat.session"
	c1SrcLangdock       = "langdock.session"
	c1SrcOllamaAPI      = "ollama.api"
	c1SrcZed            = "zed.session"
	c1SrcPerplexity     = "perplexity.session"
	c1SrcMiMo           = "xiaomi_mimo.session"
	c1SrcSakana         = "sakana.session"
	c1SrcAbacus         = "abacus.session"
	c1SrcMistral        = "mistral.session"
	c1SrcQoder          = "qoder.session"
	c1ParamVariant      = "variant"
	c1VariantTeam       = "team"
	c1VariantPersonal   = "personal"
	c1ParamRegion       = "region"
	c1ParamWorkspace    = "workspace_id"
	c1ParamOrg          = "org_id"
	c1RegionIntl        = "intl"
	c1RegionCN          = "cn"
	c1RegionGlobal      = "global"
	c1RegionChina       = "china"
	c1ConsoleProduct    = "sfm_bailian"
	c1AliCodingAPIName  = "zeldaEasy.broadscope-bailian.codingPlan.queryCodingPlanInstanceInfoV2"
	c1PlanUsageAPI      = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/usage"
	c1PlanSubAPI        = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/subscription"
	c1PlanQuotaCfgAPI   = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/quota-config"
	c1QwenSoloCommodity = "sfm_tokenplansolo_public_intl"
)

func init() {
	sess := []SecretSpec{{Key: SecretSession, Required: true}}
	aliRegion := ParamSpec{Key: c1ParamRegion, Choices: []string{c1RegionIntl, c1RegionCN}}
	addSources(
		SourceDef{
			ID: c1SrcOpenCode, Provider: "opencode", Kind: KindBrowser, Order: 70, Secrets: sess,
			Params: []ParamSpec{{Key: c1ParamWorkspace, Required: true}},
			Hosts:  []string{"opencode.ai"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcAliCodingAPI, Provider: "alibaba_coding_plan", Kind: KindUndocumented, Order: 50,
			Secrets: []SecretSpec{{Key: SecretKey, Required: true}}, Params: []ParamSpec{aliRegion},
			Hosts:       []string{"modelstudio.console.alibabacloud.com", "bailian.console.aliyun.com"},
			MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcAliCodingWeb, Provider: "alibaba_coding_plan", Kind: KindBrowser, Order: 70, Secrets: sess,
			Params:      []ParamSpec{aliRegion},
			Hosts:       []string{"bailian-singapore-cs.alibabacloud.com", "bailian-cs.console.aliyun.com"},
			MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcAliTokenCLI, Provider: "alibaba_token_plan", Kind: KindVendorCLI, Command: "bl", Order: 20,
			Params: []ParamSpec{
				aliRegion,
				{Key: c1ParamVariant, Choices: []string{c1VariantTeam, c1VariantPersonal}},
			},
			MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcAliTokenWeb, Provider: "alibaba_token_plan", Kind: KindBrowser, Order: 70, Secrets: sess,
			Params:      []ParamSpec{aliRegion},
			Hosts:       []string{"bailian-singapore-cs.alibabacloud.com", "bailian-cs.console.aliyun.com"},
			MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcQwenCloud, Provider: "qwen_cloud", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"cs-data.qwencloud.com"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcDevin, Provider: "devin", Kind: KindBrowser, Order: 70, Secrets: sess,
			Params: []ParamSpec{{Key: c1ParamOrg, Required: true}},
			Hosts:  []string{"app.devin.ai"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcManus, Provider: "manus", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"api.manus.im"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcT3Chat, Provider: "t3_chat", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"t3.chat"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcLangdock, Provider: "langdock", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"app.langdock.com"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcOllamaAPI, Provider: "ollama", Kind: KindUndocumented, Order: 50,
			Secrets: []SecretSpec{{Key: SecretKey, Required: true}},
			Hosts:   []string{"ollama.com"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcZed, Provider: "zed", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"cloud.zed.dev"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcPerplexity, Provider: "perplexity", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"www.perplexity.ai"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcMiMo, Provider: "xiaomi_mimo", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"platform.xiaomimimo.com"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcSakana, Provider: "sakana", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"console.sakana.ai"}, MinInterval: 15 * time.Minute,
		},
		SourceDef{
			ID: c1SrcAbacus, Provider: "abacus", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"apps.abacus.ai"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcMistral, Provider: "mistral", Kind: KindBrowser, Order: 70, Secrets: sess,
			Hosts: []string{"admin.mistral.ai", "console.mistral.ai"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: c1SrcQoder, Provider: "qoder", Kind: KindBrowser, Order: 70, Secrets: sess,
			Params: []ParamSpec{{Key: c1ParamRegion, Choices: []string{c1RegionGlobal, c1RegionChina}}},
			Hosts:  []string{"qoder.com", "qoder.com.cn"}, MinInterval: 10 * time.Minute,
		},
	)

	register(c1SrcOpenCode, Driver{Plan: c1PlanOpenCode, Parse: c1ParseOpenCode})
	register(c1SrcAliCodingAPI, Driver{Plan: c1PlanAliCodingAPI, Parse: c1ParseAliCodingAPI})
	register(c1SrcAliCodingWeb, Driver{Plan: c1PlanAliCodingWeb, Parse: c1ParseAliCodingWeb})
	register(c1SrcAliTokenCLI, Driver{Plan: c1PlanAliTokenCLI, Parse: c1ParseAliTokenCLI})
	register(c1SrcAliTokenWeb, Driver{Plan: c1PlanAliTokenWeb, Parse: c1ParseAliTokenWeb})
	register(c1SrcQwenCloud, Driver{Plan: c1PlanQwenCloud, Parse: c1ParseQwenCloud})
	register(c1SrcDevin, Driver{Plan: c1PlanDevin, Parse: c1ParseDevin})
	register(c1SrcManus, Driver{Plan: c1PlanManus, Parse: c1ParseManus})
	register(c1SrcT3Chat, Driver{Plan: c1PlanT3Chat, Parse: c1ParseT3Chat})
	register(c1SrcLangdock, Driver{Plan: c1PlanLangdock, Parse: c1ParseLangdock})
	register(c1SrcOllamaAPI, Driver{Plan: keyedGET("https://ollama.com/api/balance", SecretKey, AuthBearer, "", nil), Parse: c1ParseOllama})
	register(c1SrcZed, Driver{Plan: c1PlanZed, Parse: c1ParseZed})
	register(c1SrcPerplexity, Driver{Plan: c1PlanPerplexity, Parse: c1ParsePerplexity})
	register(c1SrcMiMo, Driver{Plan: c1PlanMiMo, Parse: c1ParseMiMo})
	register(c1SrcSakana, Driver{Plan: c1PlanSakana, Parse: c1ParseSakana})
	register(c1SrcAbacus, Driver{Plan: c1PlanAbacus, Parse: c1ParseAbacus})
	register(c1SrcMistral, Driver{Plan: c1PlanMistral, Parse: c1ParseMistral})
	register(c1SrcQoder, Driver{Plan: c1PlanQoder, Parse: c1ParseQoder})
}

// --- shared helpers ---------------------------------------------------------------

// c1Req builds one HTTP request. Plain headers ride in Header; anything made
// from the pasted session rides in sec and is never logged.
func c1Req(key, method, u string, h, sec map[string]string, body []byte, optional bool) Request {
	hh := map[string]string{"Accept": "application/json"}
	for k, v := range h {
		hh[k] = v
	}
	return Request{Key: key, Kind: ReqHTTP, Method: method, URL: u, Header: hh, SecretHeaders: sec, Body: body, Optional: optional}
}

// c1Cookie returns the pasted session as a Cookie header value, or ErrAuth.
func c1Cookie(in PlanInput) (string, error) {
	raw, err := secret(in, SecretSession)
	if err != nil {
		return "", err
	}
	c := SessionCookie(raw)
	if c == "" {
		return "", fmt.Errorf("%w: session empty", ErrAuth)
	}
	return c, nil
}

// c1CookieValue returns one cookie's value from a Cookie header ("" when
// absent). Names compare case-insensitively.
func c1CookieValue(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// c1CookiesWithPrefix returns the "name=value" pairs whose name starts with prefix.
func c1CookiesWithPrefix(header, prefix string) []string {
	var out []string
	for _, part := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if ok && strings.HasPrefix(strings.ToLower(k), strings.ToLower(prefix)) && strings.TrimSpace(v) != "" {
			out = append(out, k+"="+strings.TrimSpace(v))
		}
	}
	return out
}

// c1Bare reports whether a paste is a bare token rather than a Cookie header.
func c1Bare(s string) bool { return !strings.ContainsAny(s, "=;") }

// c1Expand decodes JSON strings embedded inside a decoded value, the way the
// Alibaba consoles nest their payloads ("data": "{\"...\"}").
func c1Expand(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = c1Expand(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = c1Expand(e)
		}
		return out
	case string:
		s := strings.TrimSpace(x)
		if len(s) > 1 && (s[0] == '{' || s[0] == '[') {
			dec := json.NewDecoder(strings.NewReader(s))
			dec.UseNumber()
			var y any
			if dec.Decode(&y) == nil {
				return c1Expand(y)
			}
		}
	}
	return v
}

// c1FindKey returns the first non-null value stored under any of keys,
// searching depth first (object keys in sorted order, so the walk is
// deterministic).
func c1FindKey(v any, keys ...string) J {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range keys {
			if e, ok := x[k]; ok && e != nil {
				return J{e}
			}
		}
		for _, k := range sortedKeys(x) {
			if r := c1FindKey(x[k], keys...); r.Exists() {
				return r
			}
		}
	case []any:
		for _, e := range x {
			if r := c1FindKey(e, keys...); r.Exists() {
				return r
			}
		}
	}
	return J{}
}

// c1FindObj returns the first object for which match is true, depth first.
func c1FindObj(v any, match func(map[string]any) bool) map[string]any {
	switch x := v.(type) {
	case map[string]any:
		if match(x) {
			return x
		}
		for _, k := range sortedKeys(x) {
			if r := c1FindObj(x[k], match); r != nil {
				return r
			}
		}
	case []any:
		for _, e := range x {
			if r := c1FindObj(e, match); r != nil {
				return r
			}
		}
	}
	return nil
}

// c1HasAny is a c1FindObj matcher: the object carries any of keys.
func c1HasAny(keys ...string) func(map[string]any) bool {
	return func(m map[string]any) bool {
		for _, k := range keys {
			if _, ok := m[k]; ok {
				return true
			}
		}
		return false
	}
}

// c1Obj returns the object behind j, nil when j is not an object.
func c1Obj(j J) map[string]any {
	m, _ := j.v.(map[string]any)
	return m
}

// c1First returns the first present value of m under keys.
func c1First(m map[string]any, keys ...string) J {
	for _, k := range keys {
		if e, ok := m[k]; ok && e != nil {
			return J{e}
		}
	}
	return J{}
}

// c1Str returns a trimmed string value, "" when absent or not a string.
func c1Str(j J) string {
	s, ok := j.v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// c1TraceID derives a UUID-shaped trace id from the planning time, so the
// planner stays pure and repeatable.
func c1TraceID(now time.Time) string {
	sum := sha256.Sum256([]byte(now.UTC().Format(time.RFC3339Nano)))
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}

// c1LooksLikeLogin reports an HTML sign-in page.
func c1LooksLikeLogin(body []byte) bool {
	t := strings.ToLower(string(body))
	return strings.Contains(t, "<html") && (strings.Contains(t, "login") || strings.Contains(t, "sign in") || strings.Contains(t, "signin"))
}

// --- OpenCode console (rung 3) ------------------------------------------------------

var c1WorkspaceRe = regexp.MustCompile(`^(?:wrk|org)_[A-Za-z0-9]+$`)

// c1OpenCodeWorkspace accepts a raw wrk_/org_ id or a workspace or console URL.
func c1OpenCodeWorkspace(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = ""
		for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
			if c1WorkspaceRe.MatchString(seg) {
				s = seg
			}
		}
	}
	if !c1WorkspaceRe.MatchString(s) {
		return "", fmt.Errorf("planlimits: invalid OpenCode workspace id")
	}
	return s, nil
}

func c1PlanOpenCode(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	ws, err := c1OpenCodeWorkspace(in.Params[c1ParamWorkspace])
	if err != nil {
		return nil, err
	}
	// The console scopes every read to one workspace through x-org-id; the
	// id is the user's (no discovery request), so all three reads are
	// planned up front and the two money reads are optional.
	h := map[string]string{"x-org-id": ws}
	sec := map[string]string{"Cookie": c}
	base := "https://opencode.ai/console/api/"
	return []Request{
		c1Req("go", "GET", base+"go/status", h, sec, nil, false),
		c1Req("billing", "GET", base+"billing/status", h, sec, nil, true),
		c1Req("summary", "GET", base+"usage/summary?range=30d", h, sec, nil, true),
	}, nil
}

// c1OpenCodeMeters binds the console meters to window keys by declared length.
var c1OpenCodeMeters = []struct {
	in, key string
	length  time.Duration
	rolling bool
}{
	{"fiveHour", "5h", 5 * time.Hour, true},
	{"week", "weekly", 7 * 24 * time.Hour, true},
	{"month", "monthly", 0, false},
}

// c1ParseOpenCode maps the console's Go meters (micro-cents, 1e-8 USD), the
// prepaid Zen balance and, for a pay-as-you-go workspace, its 30-day spend.
func c1ParseOpenCode(in ParseInput) (Snapshot, error) {
	body, err := need(in, "go")
	if err != nil {
		return Snapshot{}, err
	}
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	s := newSnap("opencode", c1SrcOpenCode, KindBrowser, ConfExact, in.Now)
	// A JSON null, or "access": null, is the console's "no Go plan here".
	_, hasAccess := c1Obj(j)["access"]
	noQuota := !j.Exists() || (hasAccess && !j.At("access").Exists())
	if !noQuota {
		meters := j.At("access.meters")
		if !meters.Exists() {
			return Snapshot{}, shapeErr("opencode go status", nil)
		}
		s.PlanCode = "go"
		endsAt := j.At("access.endsAt").Time()
		for _, m := range c1OpenCodeMeters {
			mj := meters.At(m.in)
			used, ok1 := mj.At("usedMicroCents").Num()
			lim, ok2 := mj.At("limitMicroCents").Num()
			if !ok1 || !ok2 || lim <= 0 {
				continue
			}
			reset := mj.At("resetsAt").Time()
			if reset == nil && m.in == "month" {
				reset = endsAt
			}
			w, _ := AmountWindow(m.key, UnitUSDMicros, F(used/100), F(lim/100), nil, reset, m.length)
			w.Rolling = m.rolling
			s.Windows = append(s.Windows, w)
		}
		if len(s.Windows) == 0 {
			return Snapshot{}, shapeErr("opencode go status: no meters", nil)
		}
	}
	payg := false
	if r, ok := in.Responses["billing"]; ok && httpErr(r, true) == nil {
		if b, err := ParseJ(r.Body); err == nil {
			mode, _ := b.At("mode").Str()
			billing, _ := b.At("billingMode").Str()
			payg = mode == "pay-as-you-go"
			if payg && billing == "prepaid" {
				if m, ok := b.At("balanceMicroCents").Micros(8); ok {
					s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: m})
				}
			}
		}
	}
	if noQuota {
		if !payg {
			return Snapshot{}, fmt.Errorf("%w: no Go plan and no pay-as-you-go billing", ErrNotApplicable)
		}
		s.PlanCode = "payg"
		if r, ok := in.Responses["summary"]; ok && httpErr(r, true) == nil {
			if sj, err := ParseJ(r.Body); err == nil {
				if m, ok := sj.At("totalCostMicroCents").Micros(8); ok {
					s.Spend = append(s.Spend, Spend{Period: "30d", Unit: UnitUSDMicros, Amount: m, Scope: "account"})
				}
			}
		}
	}
	return s, requireAny(s, "opencode")
}

// --- Alibaba consoles (Coding Plan, Token Plan, Qwen Cloud) --------------------------

// c1AliRegion is one Alibaba console region.
type c1AliRegion struct {
	gateway, rpc, site, soloSite, regionID, commodity, solo string
	codingDash, codingReferer, planDash, rpcAction, cliSite string
}

// c1AliRegions binds the region parameter to the console hosts and codes.
var c1AliRegions = map[string]c1AliRegion{
	"":           c1AliIntl,
	c1RegionIntl: c1AliIntl,
	c1RegionCN: {
		gateway: "bailian.console.aliyun.com", rpc: "bailian-cs.console.aliyun.com",
		site: "BAILIAN_ALIYUN", soloSite: "BAILIAN_ALIYUN", regionID: "cn-beijing",
		commodity: "sfm_codingplan_public_cn", solo: "sfm_tokenplansolo_public_cn",
		codingDash:    "https://bailian.console.aliyun.com/cn-beijing/?tab=model#/efm/coding_plan",
		codingReferer: "https://bailian.console.aliyun.com/cn-beijing/?tab=model",
		planDash:      "https://bailian.console.aliyun.com/cn-beijing?tab=plan#/efm/subscription/token-plan/personal",
		rpcAction:     "BroadScopeAspnGateway", cliSite: "domestic",
	},
}

var c1AliIntl = c1AliRegion{
	gateway: "modelstudio.console.alibabacloud.com", rpc: "bailian-singapore-cs.alibabacloud.com",
	// The console's own spelling of the personal site code (sic).
	site: "MODELSTUDIO_ALIBABACLOUD", soloSite: "MODELSTUDIO_ALBABACLOUD", regionID: "ap-southeast-1",
	commodity: "sfm_codingplan_public_intl", solo: "sfm_tokenplansolo_public_intl",
	codingDash:    "https://modelstudio.console.alibabacloud.com/ap-southeast-1/?tab=coding-plan#/efm/coding_plan",
	codingReferer: "https://modelstudio.console.alibabacloud.com/ap-southeast-1/?tab=coding-plan",
	planDash:      "https://modelstudio.console.alibabacloud.com/ap-southeast-1/?tab=plan#/efm/subscription/token-plan/personal",
	rpcAction:     "IntlBroadScopeAspnGateway", cliSite: "international",
}

func c1Region(in map[string]string) (c1AliRegion, error) {
	r, ok := c1AliRegions[in[c1ParamRegion]]
	if !ok {
		return c1AliRegion{}, fmt.Errorf("planlimits: alibaba region %q", in[c1ParamRegion])
	}
	return r, nil
}

// c1ConsoleURL is the console gateway's data endpoint for one api.
func c1ConsoleURL(host, action, api string) string {
	q := url.Values{}
	q.Set("action", action)
	q.Set("product", c1ConsoleProduct)
	q.Set("api", api)
	q.Set("_v", "undefined")
	return "https://" + host + "/data/api.json?" + q.Encode()
}

// c1ConsoleCall is one form POST to an Alibaba-family console gateway.
type c1ConsoleCall struct {
	key, host, action, api, feURL, origin, referer, site, region, secToken, cookie string
	data                                                                           map[string]any
	extraCorner                                                                    map[string]any
	withProduct, optional                                                          bool
	now                                                                            time.Time
}

// c1ConsoleRequest builds the form POST the console pages send: a params JSON
// envelope with the cornerstone block, the region and, when the paste
// carries one, the sec_token.
func c1ConsoleRequest(c c1ConsoleCall) Request {
	corner := map[string]any{
		"feTraceId": c1TraceID(c.now), "feURL": c.feURL, "protocol": "V2", "console": "ONE_CONSOLE",
		"productCode": "p_efm", "domain": c1HostOf(c.feURL), "consoleSite": c.site,
		"userNickName": "", "userPrincipalName": "", "xsp_lang": "en-US",
	}
	for k, v := range c.extraCorner {
		corner[k] = v
	}
	if cna := c1CookieValue(c.cookie, "cna"); cna != "" {
		corner["X-Anonymous-Id"] = cna
	}
	data := map[string]any{"cornerstoneParam": corner}
	for k, v := range c.data {
		data[k] = v
	}
	params, _ := json.Marshal(map[string]any{"Api": c.api, "V": "1.0", "Data": data})
	form := url.Values{}
	form.Set("params", string(params))
	form.Set("region", c.region)
	if c.withProduct {
		form.Set("product", c1ConsoleProduct)
		form.Set("action", c.action)
		form.Set("language", "en-US")
	}
	if c.secToken != "" {
		form.Set("sec_token", c.secToken)
	}
	// The CSRF headers are copied from the session's own cookie, so they ride
	// with the secret headers.
	sec := map[string]string{"Cookie": c.cookie}
	csrf := c1CookieValue(c.cookie, "login_aliyunid_csrf")
	if csrf == "" {
		csrf = c1CookieValue(c.cookie, "csrf")
	}
	if csrf != "" {
		sec["x-xsrf-token"], sec["x-csrf-token"] = csrf, csrf
	}
	h := map[string]string{
		"Accept": "application/json, text/plain, */*", "Content-Type": "application/x-www-form-urlencoded",
		"X-Requested-With": "XMLHttpRequest", "Origin": c.origin, "Referer": c.referer,
	}
	return c1Req(c.key, "POST", c1ConsoleURL(c.host, c.action, c.api), h, sec, []byte(form.Encode()), c.optional)
}

// c1HostOf returns the host of a URL, "" when unparsable.
func c1HostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Host
}

// c1ConsoleRoot decodes a console body and expands embedded JSON. An HTML
// sign-in page is ErrAuth.
func c1ConsoleRoot(body []byte) (any, error) {
	j, err := ParseJ(body)
	if err != nil {
		if c1LooksLikeLogin(body) {
			return nil, fmt.Errorf("%w: console sign-in page", ErrAuth)
		}
		return nil, err
	}
	return c1Expand(j.v), nil
}

// c1ConsoleCheck classifies a console error envelope. keyMode is the own-key
// route, where "sign in to the console" means this account cannot report
// through a key at all.
func c1ConsoleCheck(root any, keyMode bool) error {
	login := func() error {
		if keyMode {
			return fmt.Errorf("%w: the console answers this account only for a signed-in session", ErrNotApplicable)
		}
		return fmt.Errorf("%w: console sign-in needed", ErrAuth)
	}
	if v := c1FindKey(root, "statusCode", "status_code", "code", "Code", "errorCode"); v.Exists() {
		if n, ok := v.Num(); ok {
			switch {
			case n == 401 || n == 403:
				return login()
			case n != 0 && n != 200:
				return fmt.Errorf("%w: console code %v", ErrTransient, n)
			}
		} else if s := strings.ToLower(c1Str(v)); strings.Contains(s, "login") || strings.Contains(s, "authori") {
			return login()
		}
	}
	if m := strings.ToLower(c1Str(c1FindKey(root, "message", "msg", "statusMessage", "Message", "errorMsg"))); strings.Contains(m, "log in") || strings.Contains(m, "login") {
		return login()
	}
	failed := c1FindObj(root, func(m map[string]any) bool {
		for _, k := range []string{"success", "Success"} {
			if b, ok := m[k].(bool); ok && !b {
				return true
			}
		}
		return false
	})
	if failed != nil {
		return fmt.Errorf("%w: console reported a failure", ErrTransient)
	}
	return nil
}

// Coding Plan --------------------------------------------------------------------

func c1PlanAliCodingAPI(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	r, err := c1Region(in.Params)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("action", c1AliCodingAPIName)
	q.Set("product", "broadscope-bailian")
	q.Set("api", "queryCodingPlanInstanceInfoV2")
	q.Set("currentRegionId", r.regionID)
	body, _ := json.Marshal(map[string]any{"queryCodingPlanInstanceInfoRequest": map[string]any{"commodityCode": r.commodity}})
	h := map[string]string{"Content-Type": "application/json", "Origin": "https://" + r.gateway, "Referer": r.codingDash}
	sec := map[string]string{"Authorization": "Bearer " + k, "x-api-key": k, "X-DashScope-API-Key": k}
	return []Request{c1Req("main", "POST", "https://"+r.gateway+"/data/api.json?"+q.Encode(), h, sec, body, false)}, nil
}

func c1PlanAliCodingWeb(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	r, err := c1Region(in.Params)
	if err != nil {
		return nil, err
	}
	return []Request{c1ConsoleRequest(c1ConsoleCall{
		key: "main", host: r.rpc, action: r.rpcAction, api: c1AliCodingAPIName, feURL: r.codingDash,
		origin: "https://" + r.gateway, referer: r.codingReferer, site: r.site, region: r.regionID,
		secToken: c1CookieValue(c, "sec_token"), cookie: c, now: in.Now,
		data: map[string]any{"queryCodingPlanInstanceInfoRequest": map[string]any{"commodityCode": r.commodity, "onlyLatestOne": true}},
	})}, nil
}

func c1ParseAliCodingAPI(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return c1AliCodingSnapshot(body, c1SrcAliCodingAPI, KindUndocumented, true, in.Now)
}

func c1ParseAliCodingWeb(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return c1AliCodingSnapshot(body, c1SrcAliCodingWeb, KindBrowser, false, in.Now)
}

// c1AliCodingWindows binds the quota counters to windows by declared length.
var c1AliCodingWindows = []struct {
	key                string
	used, total, reset []string
	length             time.Duration
}{
	{
		"5h",
		[]string{"per5HourUsedQuota", "perFiveHourUsedQuota"},
		[]string{"per5HourTotalQuota", "perFiveHourTotalQuota"},
		[]string{"per5HourQuotaNextRefreshTime", "perFiveHourQuotaNextRefreshTime"},
		5 * time.Hour,
	},
	{"weekly", []string{"perWeekUsedQuota"}, []string{"perWeekTotalQuota"}, []string{"perWeekQuotaNextRefreshTime"}, 7 * 24 * time.Hour},
	{
		"monthly",
		[]string{"perBillMonthUsedQuota", "perMonthUsedQuota"},
		[]string{"perBillMonthTotalQuota", "perMonthTotalQuota"},
		[]string{"perBillMonthQuotaNextRefreshTime", "perMonthQuotaNextRefreshTime"},
		0,
	},
}

var c1AliQuotaKeys = []string{"per5HourUsedQuota", "per5HourTotalQuota", "perWeekUsedQuota", "perWeekTotalQuota", "perBillMonthUsedQuota", "perBillMonthTotalQuota"}

// c1ActiveScore ranks a plan instance: valid or active beats unknown beats
// expired.
func c1ActiveScore(m map[string]any, now time.Time) int {
	switch strings.ToUpper(c1Str(c1First(m, "status", "instanceStatus"))) {
	case "VALID", "ACTIVE":
		return 3
	case "EXPIRED", "INVALID", "INACTIVE", "DISABLED", "TERMINATED", "STOPPED":
		return -1
	}
	if b, ok := c1First(m, "isActive", "active").Bool(); ok {
		if b {
			return 3
		}
		return -1
	}
	if t := c1First(m, "endTime", "periodEndTime", "expireTime", "expirationTime").Time(); t != nil && t.After(now) {
		return 1
	}
	return 0
}

// c1AliQuota finds the quota block inside v.
func c1AliQuota(v any) map[string]any {
	if q := c1Obj(c1FindKey(v, "codingPlanQuotaInfo", "coding_plan_quota_info")); q != nil {
		return q
	}
	return c1FindObj(v, c1HasAny(c1AliQuotaKeys...))
}

// c1AliCodingSnapshot maps queryCodingPlanInstanceInfoV2: request counts per
// 5 hours, week and billing month for the active plan instance.
func c1AliCodingSnapshot(body []byte, src string, kind SourceKind, keyMode bool, now time.Time) (Snapshot, error) {
	root, err := c1ConsoleRoot(body)
	if err != nil {
		return Snapshot{}, err
	}
	if err := c1ConsoleCheck(root, keyMode); err != nil {
		return Snapshot{}, err
	}
	s := newSnap("alibaba_coding_plan", src, kind, ConfExact, now)
	var inst map[string]any
	best := 0
	infos := c1FindKey(root, "codingPlanInstanceInfos", "coding_plan_instance_infos").Arr()
	for _, it := range infos {
		m := c1Obj(it)
		if m == nil {
			continue
		}
		if sc := c1ActiveScore(m, now); inst == nil || sc > best {
			inst, best = m, sc
		}
	}
	var quota map[string]any
	if inst != nil {
		quota = c1AliQuota(inst)
	}
	if quota == nil && !(len(infos) > 1 && best > 0) {
		quota = c1AliQuota(root)
	}
	name := ""
	if inst != nil {
		name = c1Str(c1First(inst, "planName", "instanceName", "packageName"))
	}
	if name == "" {
		name = c1Str(c1FindKey(root, "planName", "plan_name", "packageName", "package_name"))
	}
	s.PlanLabel = SanitizeLabel(name)
	for _, w := range c1AliCodingWindows {
		if quota == nil {
			break
		}
		used, ok1 := c1First(quota, w.used...).Num()
		total, ok2 := c1First(quota, w.total...).Num()
		if !ok1 || !ok2 || total <= 0 {
			continue
		}
		win, _ := AmountWindow(w.key, UnitRequests, F(used), F(total), nil, c1First(quota, w.reset...).Time(), w.length)
		win.Rolling = w.length > 0
		s.Windows = append(s.Windows, win)
	}
	if len(s.Windows) == 0 {
		if inst != nil && best > 0 && s.PlanLabel != "" {
			s.Status = StatusPlanOnly // an active plan that exposes no counters
			return s, nil
		}
		return Snapshot{}, shapeErr("alibaba coding plan: no quota counters", nil)
	}
	return s, nil
}

// Token Plan and Qwen Cloud (rolling windows) -----------------------------------------

// c1RollingKeys binds the personal-plan ratios to windows by declared length.
var c1RollingKeys = []struct {
	ratio, reset, total, key string
	length                   time.Duration
}{
	{"per5HourPercentage", "per5HourResetTime", "five_hour", "5h", 5 * time.Hour},
	{"per1WeekPercentage", "per1WeekResetTime", "weekly", "weekly", 7 * 24 * time.Hour},
	{"per1MonthPercentage", "per1MonthResetTime", "monthly", "monthly", 0},
}

// c1PlanDisplay names the known personal tiers.
var c1PlanDisplay = map[string]string{"lite": "Lite", "standard": "Standard", "pro": "Pro", "max": "Max"}

// c1RollingSnapshot maps a personal token-plan usage body: used ratios
// (0..1) per window, plus credit limits when the subscription names the tier
// and the quota config lists it. A success envelope without windows (the
// gateway answers that intermittently) is transient, never zero.
func c1RollingSnapshot(provider, src string, kind SourceKind, usage any, sub, cfg any, now time.Time) (Snapshot, error) {
	u := c1FindObj(usage, c1HasAny("per5HourPercentage", "per1WeekPercentage", "per1MonthPercentage"))
	if u == nil {
		return Snapshot{}, fmt.Errorf("%w: usage windows temporarily unavailable", ErrTransient)
	}
	s := newSnap(provider, src, kind, ConfExact, now)
	code := ""
	if p := c1FindObj(sub, c1HasAny("specCode", "spec_code", "planName", "plan_name")); p != nil {
		code = strings.ToLower(c1Str(c1First(p, "specCode", "spec_code", "planName", "plan_name")))
	}
	var totals map[string]any
	if code != "" {
		totals = c1Obj(c1FindKey(cfg, code))
	}
	if code != "" {
		s.PlanCode = SanitizeLabel(code)
		s.PlanLabel = c1PlanDisplay[code]
	}
	for _, k := range c1RollingKeys {
		r, ok := J{u[k.ratio]}.Num()
		if !ok || r < 0 {
			continue // -1 and absent both mean unknown, never zero
		}
		r = min(r, 1)
		reset := J{u[k.reset]}.Time()
		var w Window
		total := 0.0
		if totals != nil {
			names := []string{k.total}
			if k.total == "five_hour" {
				names = append(names, "fiveHour")
			}
			total, _ = c1First(totals, names...).Num()
		}
		if total > 0 {
			w = Window{Key: k.key, Unit: UnitCredits, Used: F(r * total), Limit: F(total), Remaining: F(total - r*total), UsedFrac: F(r), ResetsAt: reset}
			if k.length > 0 {
				w.Length = dur(k.length)
			}
		} else {
			w = PercentWindow(k.key, r*100, reset, k.length)
		}
		w.Rolling = k.length > 0
		s.Windows = append(s.Windows, w)
	}
	if len(s.Windows) == 0 {
		return Snapshot{}, fmt.Errorf("%w: usage windows temporarily unavailable", ErrTransient)
	}
	return s, nil
}

// c1OptionalRoot decodes an optional console response; nil when absent or bad.
func c1OptionalRoot(in ParseInput, key string) any {
	r, ok := in.Responses[key]
	if !ok || httpErr(r, true) != nil {
		return nil
	}
	root, err := c1ConsoleRoot(r.Body)
	if err != nil || c1ConsoleCheck(root, false) != nil {
		return nil
	}
	return root
}

// c1PersonalCalls plans the three personal token-plan reads.
func c1PersonalCalls(c c1ConsoleCall, solo string) []Request {
	usage, sub, cfg := c, c, c
	usage.key, usage.api = "usage", c1PlanUsageAPI
	sub.key, sub.api, sub.optional = "subscription", c1PlanSubAPI, true
	sub.data = map[string]any{"commodityCode": solo}
	cfg.key, cfg.api, cfg.optional = "quota_config", c1PlanQuotaCfgAPI, true
	return []Request{c1ConsoleRequest(usage), c1ConsoleRequest(sub), c1ConsoleRequest(cfg)}
}

func c1ParsePersonal(in ParseInput, provider, src string) (Snapshot, error) {
	body, err := need(in, "usage")
	if err != nil {
		return Snapshot{}, err
	}
	root, err := c1ConsoleRoot(body)
	if err != nil {
		return Snapshot{}, err
	}
	if err := c1ConsoleCheck(root, false); err != nil {
		return Snapshot{}, err
	}
	return c1RollingSnapshot(provider, src, KindBrowser, root, c1OptionalRoot(in, "subscription"), c1OptionalRoot(in, "quota_config"), in.Now)
}

func c1PlanAliTokenWeb(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	r, err := c1Region(in.Params)
	if err != nil {
		return nil, err
	}
	return c1PersonalCalls(c1ConsoleCall{
		host: r.rpc, action: r.rpcAction, feURL: r.planDash, origin: "https://" + r.gateway, referer: r.planDash,
		site: r.soloSite, region: r.regionID, secToken: c1CookieValue(c, "sec_token"), cookie: c, now: in.Now,
		withProduct: true, extraCorner: map[string]any{"switchUserType": 3},
	}, r.solo), nil
}

func c1ParseAliTokenWeb(in ParseInput) (Snapshot, error) {
	return c1ParsePersonal(in, "alibaba_token_plan", c1SrcAliTokenWeb)
}

func c1PlanQwenCloud(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	dash := "https://home.qwencloud.com/billing/subscription/token-plan-individual"
	return c1PersonalCalls(c1ConsoleCall{
		host: "cs-data.qwencloud.com", action: "IntlBroadScopeAspnGateway", feURL: dash,
		origin: "https://home.qwencloud.com", referer: dash, site: "QWENCLOUD", region: "ap-southeast-1",
		secToken: c1CookieValue(c, "sec_token"), cookie: c, now: in.Now, withProduct: true,
	}, c1QwenSoloCommodity), nil
}

func c1ParseQwenCloud(in ParseInput) (Snapshot, error) {
	return c1ParsePersonal(in, "qwen_cloud", c1SrcQwenCloud)
}

// Bailian CLI (rung 1) ------------------------------------------------------------

// c1BailianArgv is the fixed argv per plan variant; the region only picks
// two fixed flag values.
var c1BailianArgv = map[string][]string{
	"":                {"bl", "usage", "token-plan"},
	c1VariantTeam:     {"bl", "usage", "token-plan"},
	c1VariantPersonal: {"bl", "console", "call", "--api", c1PlanUsageAPI, "--data", "{}"},
}

func c1PlanAliTokenCLI(in PlanInput) ([]Request, error) {
	argv, ok := c1BailianArgv[in.Params[c1ParamVariant]]
	if !ok {
		return nil, fmt.Errorf("planlimits: alibaba token plan variant %q", in.Params[c1ParamVariant])
	}
	r, err := c1Region(in.Params)
	if err != nil {
		return nil, err
	}
	full := append(append([]string(nil), argv...), "--console-region", r.regionID, "--console-site", r.cliSite, "--output", "json")
	return []Request{{Key: "out", Kind: ReqExec, Argv: full, Env: []string{"NO_COLOR=1"}, Timeout: 15 * time.Second}}, nil
}

// c1ParseAliTokenCLI reads the JSON the Bailian CLI prints. A sign-in prompt
// is ErrAuth; text with no JSON is a shape error.
func c1ParseAliTokenCLI(in ParseInput) (Snapshot, error) {
	r, ok := in.Responses["out"]
	if !ok {
		return Snapshot{}, fmt.Errorf("%w: no output", ErrTransient)
	}
	if r.Err != nil {
		return Snapshot{}, r.Err
	}
	return c1BailianOutput(string(r.Body), in.Now)
}

// c1BailianOutput parses one Bailian CLI run.
func c1BailianOutput(out string, now time.Time) (Snapshot, error) {
	t := StripANSI(out)
	i := strings.IndexAny(t, "{[")
	if i < 0 {
		low := strings.ToLower(t)
		if strings.Contains(low, "login") || strings.Contains(low, "sign in") || strings.Contains(low, "not authenticated") {
			return Snapshot{}, errNotSignedIn("bl")
		}
		return Snapshot{}, errNoMatch("bl")
	}
	j, err := ParseJ([]byte(t[i:]))
	if err != nil {
		return Snapshot{}, err
	}
	root := c1Expand(j.v)
	if err := c1ConsoleCheck(root, false); err != nil {
		return Snapshot{}, err
	}
	return c1RollingSnapshot("alibaba_token_plan", c1SrcAliTokenCLI, KindVendorCLI, root, nil, nil, now)
}

// --- Devin (rung 3, pasted bearer token) ----------------------------------------------

var c1DevinOrgRe = regexp.MustCompile(`^org[-_][A-Za-z0-9_-]+$`)

func c1PlanDevin(in PlanInput) ([]Request, error) {
	raw, err := secret(in, SecretSession)
	if err != nil {
		return nil, err
	}
	tok := SessionBearer(raw)
	if tok == "" {
		return nil, fmt.Errorf("%w: session empty", ErrAuth)
	}
	org := strings.TrimSpace(in.Params[c1ParamOrg])
	if !c1DevinOrgRe.MatchString(org) {
		return nil, fmt.Errorf("planlimits: invalid Devin organization id")
	}
	return []Request{c1Req("main", "GET", "https://app.devin.ai/api/"+org+"/billing/quota/usage",
		map[string]string{"x-cog-org-id": org}, bearer(tok), nil, false)}, nil
}

// c1ParseDevin maps billing/quota/usage: used percentages (0..100) per day
// and week, and the extra usage balance in dollars.
func c1ParseDevin(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	s := newSnap("devin", c1SrcDevin, KindBrowser, ConfExact, in.Now)
	hide, _ := j.At("hide_daily_quota").Bool()
	for _, w := range []struct {
		pct, reset, key string
		length          time.Duration
		skip            bool
	}{
		{"daily_percentage", "daily_reset_at", "daily", 24 * time.Hour, hide},
		{"weekly_percentage", "weekly_reset_at", "weekly", 7 * 24 * time.Hour, false},
	} {
		p, ok := j.At(w.pct).Num()
		if w.skip || !ok || p < 0 {
			continue
		}
		s.Windows = append(s.Windows, PercentWindow(w.key, min(p, 100), j.At(w.reset).Time(), w.length))
	}
	if m, ok := j.At("overage_balance").Micros(0); ok && m >= 0 {
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: m})
	} else if m, ok := j.At("overage_balance_cents").Micros(2); ok && m >= 0 {
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: m})
	}
	return s, requireAny(s, "devin")
}

// --- Manus (rung 3) -----------------------------------------------------------------

// c1ManusToken pulls session_id out of a pasted Cookie header, or takes a bare
// token as is.
func c1ManusToken(raw string) string {
	c := SessionCookie(raw)
	if v := c1CookieValue(c, "session_id"); v != "" {
		return v
	}
	if c1Bare(c) {
		return SessionBearer(c)
	}
	return ""
}

func c1PlanManus(in PlanInput) ([]Request, error) {
	raw, err := secret(in, SecretSession)
	if err != nil {
		return nil, err
	}
	tok := c1ManusToken(raw)
	if tok == "" {
		return nil, fmt.Errorf("%w: the paste has no session_id cookie", ErrAuth)
	}
	h := map[string]string{
		"Content-Type": "application/json", "Connect-Protocol-Version": "1",
		"Origin": "https://manus.im", "Referer": "https://manus.im/",
	}
	return []Request{c1Req("main", "POST", "https://api.manus.im/user.v1.UserService/GetAvailableCredits", h, bearer(tok), []byte("{}"), false)}, nil
}

var c1ManusCreditKeys = []string{"totalCredits", "freeCredits", "periodicCredits", "addonCredits", "refreshCredits", "maxRefreshCredits", "proMonthlyCredits", "eventCredits"}

// c1AppleEpoch is 2001-01-01 in Unix seconds: Manus sends numeric reset
// times on that reference epoch.
const c1AppleEpoch = 978_307_200

// c1ParseManus maps GetAvailableCredits: the monthly plan credits left
// (periodicCredits of proMonthlyCredits), the refresh allotment left and the
// total credit balance.
func c1ParseManus(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	d := c1Obj(j.First("data", "result", "response", "availableCredits"))
	if d == nil {
		d = c1Obj(j)
	}
	if d == nil || !c1HasAny(c1ManusCreditKeys...)(d) {
		return Snapshot{}, shapeErr("manus: no credit fields", nil)
	}
	s := newSnap("manus", c1SrcManus, KindBrowser, ConfExact, in.Now)
	num := func(k string) (float64, bool) { return J{d[k]}.Num() }
	if lim, ok := num("proMonthlyCredits"); ok && lim > 0 {
		if left, ok := num("periodicCredits"); ok {
			w, _ := AmountWindow("monthly", UnitCredits, F(max(lim-left, 0)), F(lim), F(max(left, 0)), nil, 0)
			s.Windows = append(s.Windows, w)
		}
	}
	if lim, ok := num("maxRefreshCredits"); ok && lim > 0 {
		if left, ok := num("refreshCredits"); ok {
			var reset *time.Time
			switch v := d["nextRefreshTime"].(type) {
			case json.Number:
				if f, err := v.Float64(); err == nil && f > 0 {
					reset = unixPtr(int64(f) + c1AppleEpoch)
				}
			case string:
				reset = parseISO(v)
			}
			key, length := "refresh", time.Duration(0)
			if iv := strings.ToLower(c1Str(J{d["refreshInterval"]})); iv == "" || strings.Contains(iv, "day") || strings.Contains(iv, "daily") {
				key, length = "daily", 24*time.Hour
			}
			w, _ := AmountWindow(key, UnitCredits, F(max(lim-left, 0)), F(lim), F(max(left, 0)), reset, length)
			s.Windows = append(s.Windows, w)
		}
	}
	if total, ok := num("totalCredits"); ok {
		s.Balances = append(s.Balances, Balance{Kind: "credits", Unit: UnitCredits, Amount: int64(total)})
	}
	if free, ok := num("freeCredits"); ok {
		s.Balances = append(s.Balances, Balance{Kind: "granted", Unit: UnitCredits, Amount: int64(free)})
	}
	return s, requireAny(s, "manus")
}

// --- T3 Chat (rung 3) ---------------------------------------------------------------

// c1T3Input is the tRPC batch input the settings page sends.
const c1T3Input = `{"0":{"json":{"sessionId":null},"meta":{"values":{"sessionId":["undefined"]}}}}`

func c1PlanT3Chat(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"Accept": "*/*", "Referer": "https://t3.chat/settings/customization", "Origin": "https://t3.chat",
		"trpc-accept": "application/jsonl", "x-trpc-source": "web-client", "x-trpc-batch": "true",
		"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
	}
	u := "https://t3.chat/api/trpc/getCustomerData?batch=1&input=" + url.QueryEscape(c1T3Input)
	return []Request{c1Req("main", "GET", u, h, map[string]string{"Cookie": c}, nil, false)}, nil
}

// c1ParseT3Chat scans the JSON lines for the customer data object: a 4-hour
// base bucket and the monthly overage budget, both used percentages.
func c1ParseT3Chat(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	var d map[string]any
	for _, line := range strings.Split(string(body), "\n") {
		j, err := ParseJ([]byte(line))
		if err != nil {
			continue
		}
		d = c1FindObj(j.v, func(m map[string]any) bool {
			_, a := m["usageFourHourPercentage"]
			_, b := m["usageMonthPercentage"]
			_, c := m["subscription"]
			_, e := m["usageBand"]
			return a || b || (c && e)
		})
		if d != nil {
			break
		}
	}
	if d == nil {
		return Snapshot{}, shapeErr("t3 chat: no customer data", nil)
	}
	s := newSnap("t3_chat", c1SrcT3Chat, KindBrowser, ConfExact, in.Now)
	sub := c1Obj(J{d["subscription"]})
	if p := c1Str(c1First(sub, "productName")); p != "" {
		s.PlanLabel = SanitizeLabel(p)
	} else if p := c1Str(J{d["subTier"]}); p != "" {
		s.PlanLabel = SanitizeLabel(p)
	}
	if p, ok := (J{d["usageFourHourPercentage"]}).Num(); ok {
		reset := c1First(d, "usageFourHourNextResetAt", "usageWindowNextResetAt").Time()
		w := PercentWindow("4h", min(max(p, 0), 100), reset, 4*time.Hour)
		w.Rolling = true
		s.Windows = append(s.Windows, w)
	}
	if p, ok := c1First(d, "usageMonthPercentage", "usagePeriodPercentage").Num(); ok {
		s.Windows = append(s.Windows, PercentWindow("extra_usage", min(max(p, 0), 100), c1First(sub, "currentPeriodEnd").Time(), 0))
	}
	return s, requireAny(s, "t3 chat")
}

// --- Langdock (rung 3) --------------------------------------------------------------

const c1LangdockInput = `{"0":{"json":null,"meta":{"values":["undefined"],"v":1}}}`

func c1PlanLangdock(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	u := "https://app.langdock.com/api/trpc/usageSettings.getPersonalUsage?batch=1&input=" + url.QueryEscape(c1LangdockInput)
	h := map[string]string{"Referer": "https://app.langdock.com/settings/account/usage"}
	return []Request{c1Req("main", "GET", u, h, map[string]string{"Cookie": c}, nil, false)}, nil
}

// c1TRPCCode maps a tRPC error code to a driver error.
var c1TRPCCode = map[string]error{
	"UNAUTHORIZED":          ErrAuth,
	"FORBIDDEN":             ErrAuth,
	"TOO_MANY_REQUESTS":     ErrRateLimited,
	"INTERNAL_SERVER_ERROR": ErrTransient,
	"TIMEOUT":               ErrTransient,
}

// c1ParseLangdock maps getPersonalUsage: 5-hour and weekly used percentages.
// An account without included limits has a plan but no meter.
func c1ParseLangdock(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	env := j.At("0")
	if len(j.Arr()) != 1 {
		return Snapshot{}, shapeErr("langdock: not a single batch result", nil)
	}
	if e := env.At("error"); e.Exists() {
		code := c1Str(e.At("json.data.code"))
		if base, ok := c1TRPCCode[code]; ok {
			return Snapshot{}, fmt.Errorf("%w: langdock %s", base, code)
		}
		return Snapshot{}, fmt.Errorf("%w: langdock refused the request", ErrTransient)
	}
	p := env.At("result.data.json")
	if c1Obj(p) == nil {
		return Snapshot{}, shapeErr("langdock usage", nil)
	}
	s := newSnap("langdock", c1SrcLangdock, KindBrowser, ConfPercentOnly, in.Now)
	plan := p.At("planUsage")
	if has, ok := p.At("hasIncludedUsageLimits").Bool(); (ok && !has) || !plan.Exists() {
		s.Status = StatusPlanOnly
		return s, nil
	}
	enabled, ok := plan.At("sessionUsageLimitsEnabled").Bool()
	if !ok {
		return Snapshot{}, shapeErr("langdock plan usage", nil)
	}
	if enabled {
		pct, ok := plan.At("sessionUsagePercent").Num()
		if !ok {
			return Snapshot{}, shapeErr("langdock session percent", nil)
		}
		w := PercentWindow("5h", min(max(pct, 0), 200), plan.At("sessionResetsAt").Time(), 5*time.Hour)
		w.Rolling = true
		s.Windows = append(s.Windows, w)
	}
	pct, ok := plan.At("weeklyUsagePercent").Num()
	if !ok {
		return Snapshot{}, shapeErr("langdock weekly percent", nil)
	}
	w := PercentWindow("weekly", min(max(pct, 0), 200), plan.At("weeklyResetsAt").Time(), 7*24*time.Hour)
	w.Rolling = true
	s.Windows = append(s.Windows, w)
	return s, nil
}

// --- Ollama (rung 2, own key) ---------------------------------------------------------

// c1ParseOllama maps GET /api/balance: the included monthly dollars (allowance
// and what is left of it) and the purchased credit balance, kept apart.
func c1ParseOllama(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if c1Obj(j) == nil {
		return Snapshot{}, shapeErr("ollama balance", nil)
	}
	s := newSnap("ollama", c1SrcOllamaAPI, KindUndocumented, ConfExact, in.Now)
	if inc := j.At("included"); inc.Exists() {
		allow, ok1 := inc.At("allowance_usd").Micros(0)
		left, ok2 := inc.At("balance_usd").Micros(0)
		if !ok1 || !ok2 || allow < 0 {
			return Snapshot{}, shapeErr("ollama included", nil)
		}
		if allow > 0 {
			l := max(left, 0)
			w, _ := AmountWindow("monthly", UnitUSDMicros, F(float64(max(allow-l, 0))), F(float64(allow)), F(float64(l)), inc.At("period.until").Time(), 0)
			s.Windows = append(s.Windows, w)
		}
	}
	if pur := j.At("purchased"); pur.Exists() {
		m, ok := pur.At("balance_usd").Micros(0)
		if !ok {
			return Snapshot{}, shapeErr("ollama purchased", nil)
		}
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: m})
	}
	return s, requireAny(s, "ollama")
}

// --- Zed (rung 3) -------------------------------------------------------------------

func c1PlanZed(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	return []Request{c1Req("main", "GET", "https://cloud.zed.dev/frontend/billing/usage", nil, map[string]string{"Cookie": c}, nil, false)}, nil
}

// c1ParseZed maps frontend/billing/usage: edit predictions this cycle, token
// spend in cents and the spend limit when one is set.
func c1ParseZed(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	plan := c1Str(j.At("plan"))
	use := j.At("current_usage")
	if plan == "" || c1Obj(use) == nil {
		return Snapshot{}, shapeErr("zed billing usage", nil)
	}
	s := newSnap("zed", c1SrcZed, KindBrowser, ConfExact, in.Now)
	s.PlanCode = SanitizeLabel(strings.ToLower(plan))
	ep := use.At("edit_predictions")
	if used, ok := ep.At("used").Num(); ok && used >= 0 {
		lim, ok := ep.At("limit").Num()
		if !ok {
			lim, ok = ep.At("limit.limited").Num()
		}
		if ok && lim > 0 {
			w, _ := AmountWindow("cycle:edit_predictions", UnitRequests, F(used), F(lim), nil, nil, 0)
			s.Windows = append(s.Windows, w)
		}
	}
	spend := use.At("token_spend")
	if c, ok := spend.At("spend_in_cents").Micros(2); ok && c >= 0 {
		s.Spend = append(s.Spend, Spend{Period: "cycle", Unit: UnitUSDMicros, Amount: c, Scope: "account"})
		if capM, ok := spend.At("limit_in_cents").Micros(2); ok && capM > 0 {
			w, _ := AmountWindow("spend_limit", UnitUSDMicros, F(float64(c)), F(float64(capM)), nil, nil, 0)
			s.Windows = append(s.Windows, w)
		}
	}
	if len(s.Windows)+len(s.Spend) == 0 {
		s.Status = StatusUnmetered // an unlimited plan with no token spend reported
	}
	return s, nil
}

// --- Perplexity (rung 3) ------------------------------------------------------------

// c1PerplexityNames are the session cookie names Perplexity uses; a bare
// token is sent under all of them so one request covers every login type.
var c1PerplexityNames = []string{"__Secure-authjs.session-token", "authjs.session-token", "__Secure-next-auth.session-token", "next-auth.session-token"}

func c1PlanPerplexity(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	if c1Bare(c) {
		parts := make([]string, len(c1PerplexityNames))
		for i, n := range c1PerplexityNames {
			parts[i] = n + "=" + c
		}
		c = strings.Join(parts, "; ")
	}
	h := map[string]string{"Origin": "https://www.perplexity.ai", "Referer": "https://www.perplexity.ai/account/usage"}
	return []Request{c1Req("main", "GET", "https://www.perplexity.ai/rest/billing/credits?version=2.18&source=default", h, map[string]string{"Cookie": c}, nil, false)}, nil
}

// c1ParsePerplexity maps rest/billing/credits (cents). Usage is drawn from
// recurring credits first, then purchased, then promotional, as the vendor
// bills it; each pool becomes a window and the balance stays apart.
func c1ParsePerplexity(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	cents := func(keys ...string) (int64, bool) { return j.First(keys...).Micros(2) }
	bal, ok1 := cents("balance_cents", "balanceCents")
	usage, ok2 := cents("total_usage_cents", "totalUsageCents")
	grants := j.First("credit_grants", "creditGrants")
	if !ok1 || !ok2 || grants.Arr() == nil {
		return Snapshot{}, shapeErr("perplexity credits", nil)
	}
	var recurring, promo, purchased int64
	for _, g := range grants.Arr() {
		typ, _ := g.At("type").Str()
		amt, ok := g.First("amount_cents", "amountCents").Micros(2)
		if !ok {
			return Snapshot{}, shapeErr("perplexity grant", nil)
		}
		switch typ {
		case "recurring":
			recurring += amt
		case "purchased":
			purchased += amt
		case "promotional":
			if exp := g.First("expires_at_ts", "expiresAtTs").Time(); exp == nil || exp.After(in.Now) {
				promo += amt
			}
		}
	}
	if p, ok := cents("current_period_purchased_cents", "currentPeriodPurchasedCents"); ok && p > purchased {
		purchased = p
	}
	s := newSnap("perplexity", c1SrcPerplexity, KindBrowser, ConfExact, in.Now)
	left := max(usage, 0)
	take := func(pool int64) int64 { u := min(left, max(pool, 0)); left -= u; return u }
	renewal := j.First("renewal_date_ts", "renewalDateTs").Time()
	for _, p := range []struct {
		key   string
		pool  int64
		reset *time.Time
	}{{"monthly", recurring, renewal}, {"purchased", purchased, nil}, {"bonus", promo, nil}} {
		used := take(p.pool)
		if p.pool > 0 {
			w, _ := AmountWindow(p.key, UnitUSDMicros, F(float64(used)), F(float64(p.pool)), nil, p.reset, 0)
			s.Windows = append(s.Windows, w)
		}
	}
	// The recurring grant names the tier: under $50 a month is Pro, more is Max.
	switch {
	case recurring <= 0:
	case recurring < 50_000_000:
		s.PlanCode = "pro"
	default:
		s.PlanCode = "max"
	}
	s.Balances = append(s.Balances, Balance{Kind: "available", Unit: UnitUSDMicros, Amount: bal})
	return s, nil
}

// --- Xiaomi MiMo (rung 3) -----------------------------------------------------------

func c1PlanMiMo(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	if c1CookieValue(c, "api-platform_serviceToken") == "" || c1CookieValue(c, "userId") == "" {
		return nil, fmt.Errorf("%w: the paste needs the api-platform_serviceToken and userId cookies", ErrAuth)
	}
	h := map[string]string{
		"Accept": "application/json, text/plain, */*", "x-timeZone": "UTC+00:00",
		"Origin": "https://platform.xiaomimimo.com", "Referer": "https://platform.xiaomimimo.com/#/console/balance",
	}
	sec := map[string]string{"Cookie": c}
	base := "https://platform.xiaomimimo.com/api/v1/"
	return []Request{
		c1Req("balance", "GET", base+"balance", h, sec, nil, false),
		c1Req("plan", "GET", base+"tokenPlan/detail", h, sec, nil, true),
		c1Req("usage", "GET", base+"tokenPlan/usage", h, sec, nil, true),
	}, nil
}

// c1MiMoEnvelope opens a {code, message, data} body. Code 401 and 403 are
// sign-in failures.
func c1MiMoEnvelope(body []byte) (J, error) {
	j, err := ParseJ(body)
	if err != nil {
		return J{}, err
	}
	code, ok := j.At("code").Num()
	if !ok {
		return J{}, shapeErr("mimo envelope", nil)
	}
	switch code {
	case 0:
		return j.At("data"), nil
	case 401, 403:
		return J{}, fmt.Errorf("%w: mimo code %v", ErrAuth, code)
	}
	return J{}, fmt.Errorf("%w: mimo code %v", ErrTransient, code)
}

// c1ParseMiMo maps the balance (paid and granted parts, in the account's
// currency) and, when present, the token plan's monthly credits.
func c1ParseMiMo(in ParseInput) (Snapshot, error) {
	body, err := need(in, "balance")
	if err != nil {
		return Snapshot{}, err
	}
	d, err := c1MiMoEnvelope(body)
	if err != nil {
		return Snapshot{}, err
	}
	cur := c1Str(d.At("currency"))
	unit := CurrencyUnit(cur)
	total, ok := d.At("balance").Micros(0)
	if unit == "" || !ok {
		return Snapshot{}, shapeErr("mimo balance "+cur, nil)
	}
	s := newSnap("xiaomi_mimo", c1SrcMiMo, KindBrowser, ConfExact, in.Now)
	s.Balances = append(s.Balances, Balance{Kind: "total", Unit: unit, Amount: total})
	if m, ok := d.At("cashBalance").Micros(0); ok {
		s.Balances = append(s.Balances, Balance{Kind: "cash", Unit: unit, Amount: m})
	}
	if m, ok := d.At("giftBalance").Micros(0); ok {
		s.Balances = append(s.Balances, Balance{Kind: "granted", Unit: unit, Amount: m})
	}
	var reset *time.Time
	expired := false
	if r, ok := in.Responses["plan"]; ok && httpErr(r, true) == nil {
		if pd, err := c1MiMoEnvelope(r.Body); err == nil && pd.Exists() {
			s.PlanCode = SanitizeLabel(c1Str(pd.At("planCode")))
			if t, err := time.Parse("2006-01-02 15:04:05", c1Str(pd.At("currentPeriodEnd"))); err == nil {
				reset = &t
			}
			expired, _ = pd.At("expired").Bool()
		}
	}
	if r, ok := in.Responses["usage"]; ok && httpErr(r, true) == nil && !expired {
		if ud, err := c1MiMoEnvelope(r.Body); err == nil {
			it := ud.At("monthUsage.items.0")
			used, ok1 := it.At("used").Num()
			lim, ok2 := it.At("limit").Num()
			if ok1 && ok2 && lim > 0 {
				w, _ := AmountWindow("monthly", UnitCredits, F(used), F(lim), nil, reset, 0)
				s.Windows = append(s.Windows, w)
			}
		}
	}
	return s, nil
}

// --- Sakana (rung 3, server-rendered billing page) -------------------------------------

func c1PlanSakana(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	h := map[string]string{"Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.9"}
	sec := map[string]string{"Cookie": c}
	return []Request{
		c1Req("billing", "GET", "https://console.sakana.ai/billing", h, sec, nil, false),
		c1Req("payg", "GET", "https://console.sakana.ai/billing?tab=payAsYouGo", h, sec, nil, true),
	}, nil
}

var (
	c1SakanaBoundary = regexp.MustCompile(`(?i)<p[^>]*>\s*(?:5-hour|Weekly)\s*</p>|<div[^>]*data-slot=(?:"card"|'card'|"card-title"|'card-title')[^>]*>`)
	c1SakanaPct      = regexp.MustCompile(`(?i)<p[^>]*>\s*([0-9]+(?:\.[0-9]+)?)% used\s*</p>`)
	c1SakanaReset    = regexp.MustCompile(`(?i)<p[^>]*>\s*Resets on ([^<]+?)\s*</p>`)
	c1SakanaPlan     = regexp.MustCompile(`(?is)<div[^>]*data-slot="card-title"[^>]*>.*?<span>\s*([^<]+?)\s*</span>`)
	c1SakanaBalance  = regexp.MustCompile(`(?is)<h2[^>]*>\s*Credit balance\s*</h2>.{0,900}?<p[^>]*tabular-nums[^"]*"[^>]*>\$?([0-9][0-9,]*(?:\.[0-9]+)?)</p>`)
	c1SakanaUsage    = regexp.MustCompile(`(?is)<h2[^>]*>\s*Usage\s*</h2>\s*<span[^>]*>\s*Total(?:<!--\s*-->)?:\s*(?:<!--\s*-->)?\$?([0-9][0-9,]*(?:\.[0-9]+)?)\s*</span>`)
	c1SakanaLabels   = []struct {
		label, key string
		length     time.Duration
	}{{"5-hour", "5h", 5 * time.Hour}, {"Weekly", "weekly", 7 * 24 * time.Hour}}
)

// c1SakanaWindow reads one quota card: the "% used" line and the UTC
// "Resets on" date after the card's label, up to the next card.
func c1SakanaWindow(html, label, key string, length time.Duration) (Window, bool, error) {
	at := regexp.MustCompile(`(?i)<p[^>]*>\s*` + regexp.QuoteMeta(label) + `\s*</p>`).FindStringIndex(html)
	if at == nil {
		return Window{}, false, nil
	}
	rest := html[at[1]:]
	if b := c1SakanaBoundary.FindStringIndex(rest); b != nil {
		rest = rest[:b[0]]
	}
	m := c1SakanaPct.FindStringSubmatch(rest)
	if m == nil {
		return Window{}, false, shapeErr("sakana "+label+" percent", nil)
	}
	var pct float64
	if _, err := fmt.Sscanf(m[1], "%g", &pct); err != nil || pct < 0 || pct > 100 {
		return Window{}, false, shapeErr("sakana "+label+" percent", err)
	}
	var reset *time.Time
	if r := c1SakanaReset.FindStringSubmatch(rest); r != nil {
		if t, err := time.Parse("January 2, 2006 at 3:04 PM", strings.TrimSpace(r[1])); err == nil {
			reset = &t
		}
	}
	w := PercentWindow(key, pct, reset, length)
	w.Rolling = true
	return w, true, nil
}

// c1ParseSakana maps the server-rendered billing page (no JavaScript needed)
// and, when it loads, the pay-as-you-go tab's credit balance and usage total.
func c1ParseSakana(in ParseInput) (Snapshot, error) {
	body, err := need(in, "billing")
	if err != nil {
		return Snapshot{}, err
	}
	html := string(body)
	s := newSnap("sakana", c1SrcSakana, KindBrowser, ConfPercentOnly, in.Now)
	for _, l := range c1SakanaLabels {
		w, ok, err := c1SakanaWindow(html, l.label, l.key, l.length)
		if err != nil {
			return Snapshot{}, err
		}
		if ok {
			s.Windows = append(s.Windows, w)
		}
	}
	if len(s.Windows) == 0 {
		if c1LooksLikeLogin(body) {
			return Snapshot{}, fmt.Errorf("%w: sakana sign-in page", ErrAuth)
		}
		return Snapshot{}, shapeErr("sakana: no quota windows", nil)
	}
	if m := c1SakanaPlan.FindStringSubmatch(html); m != nil {
		s.PlanLabel = SanitizeLabel(m[1])
	}
	if r, ok := in.Responses["payg"]; ok && httpErr(r, true) == nil {
		payg := string(r.Body)
		if m := c1SakanaBalance.FindStringSubmatch(payg); m != nil {
			if v, err := MicrosFromDecimal(strings.ReplaceAll(m[1], ",", ""), 0); err == nil {
				s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: v})
				if u := c1SakanaUsage.FindStringSubmatch(payg); u != nil {
					if v, err := MicrosFromDecimal(strings.ReplaceAll(u[1], ",", ""), 0); err == nil {
						s.Spend = append(s.Spend, Spend{Period: "30d", Unit: UnitUSDMicros, Amount: v, Scope: "account"})
					}
				}
			}
		}
	}
	return s, nil
}

// --- Abacus AI (rung 3) -------------------------------------------------------------

func c1PlanAbacus(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	h := map[string]string{"Content-Type": "application/json"}
	sec := map[string]string{"Cookie": c}
	return []Request{
		c1Req("points", "GET", "https://apps.abacus.ai/api/_getOrganizationComputePoints", h, sec, nil, false),
		c1Req("billing", "POST", "https://apps.abacus.ai/api/_getBillingInfo", h, sec, []byte("{}"), true),
	}, nil
}

// c1AbacusResult opens a {success, result, error} body.
func c1AbacusResult(body []byte) (J, error) {
	j, err := ParseJ(body)
	if err != nil {
		return J{}, err
	}
	if ok, _ := j.At("success").Bool(); ok && c1Obj(j.At("result")) != nil {
		return j.At("result"), nil
	}
	msg := strings.ToLower(c1Str(j.At("error")))
	for _, w := range []string{"expired", "session", "login", "authenticat", "unauthorized", "forbidden"} {
		if strings.Contains(msg, w) {
			return J{}, fmt.Errorf("%w: abacus sign-in needed", ErrAuth)
		}
	}
	return J{}, shapeErr("abacus result", nil)
}

// c1ParseAbacus maps the organisation's compute credits (total and left) and
// the billing date and tier when the optional billing read answers.
func c1ParseAbacus(in ParseInput) (Snapshot, error) {
	body, err := need(in, "points")
	if err != nil {
		return Snapshot{}, err
	}
	p, err := c1AbacusResult(body)
	if err != nil {
		return Snapshot{}, err
	}
	total, ok1 := p.At("totalComputePoints").Num()
	left, ok2 := p.At("computePointsLeft").Num()
	if !ok1 || !ok2 {
		return Snapshot{}, shapeErr("abacus compute points", nil)
	}
	s := newSnap("abacus", c1SrcAbacus, KindBrowser, ConfExact, in.Now)
	var reset *time.Time
	if r, ok := in.Responses["billing"]; ok && httpErr(r, true) == nil {
		if b, err := c1AbacusResult(r.Body); err == nil {
			reset = parseISO(c1Str(b.At("nextBillingDate")))
			s.PlanLabel = SanitizeLabel(c1Str(b.At("currentTier")))
		}
	}
	if total > 0 {
		w, _ := AmountWindow("monthly", UnitCredits, nil, F(total), F(left), reset, 0)
		s.Windows = append(s.Windows, w)
	} else {
		s.Status = StatusPlanOnly
	}
	return s, nil
}

// --- Mistral (rung 3) ---------------------------------------------------------------

const c1MistralVibeInput = `{"0":{"json":null,"meta":{"values":["undefined"],"v":1}}}`

func c1PlanMistral(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	ory := c1CookiesWithPrefix(c, "ory_session_")
	if len(ory) == 0 {
		return nil, fmt.Errorf("%w: the paste needs an ory_session cookie", ErrAuth)
	}
	csrf := c1CookieValue(c, "csrftoken")
	sec := map[string]string{"Cookie": c}
	if csrf != "" {
		sec["X-CSRFTOKEN"] = csrf
	}
	h := map[string]string{"Accept": "*/*", "Origin": "https://admin.mistral.ai", "Referer": "https://admin.mistral.ai/organization/billing"}
	reqs := []Request{c1Req("credits", "GET", "https://admin.mistral.ai/api/billing/credits", h, sec, nil, false)}
	if csrf != "" {
		// The console host gets only the session and CSRF cookies; every other
		// admin cookie stays with its own origin.
		vibe := map[string]string{"Cookie": strings.Join(append([]string{"csrftoken=" + csrf}, ory...), "; "), "X-CSRFToken": csrf}
		u := "https://console.mistral.ai/api-ui/trpc/billing.vibeUsage?batch=1&input=" + url.QueryEscape(c1MistralVibeInput)
		reqs = append(reqs, c1Req("vibe", "GET", u, map[string]string{"Accept": "*/*"}, vibe, nil, true))
	}
	return reqs, nil
}

// c1ParseMistral maps the admin credit wallet (available = wallet + credit
// notes - usage not yet billed) and, when the console answers, the Vibe plan's
// monthly used percentage.
func c1ParseMistral(in ParseInput) (Snapshot, error) {
	body, err := need(in, "credits")
	if err != nil {
		return Snapshot{}, err
	}
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	cur := c1Str(j.At("currency"))
	unit := CurrencyUnit(cur)
	wallet, ok := j.At("wallet_amount").Micros(0)
	if unit == "" || !ok {
		return Snapshot{}, shapeErr("mistral credits "+cur, nil)
	}
	notes, _ := j.At("credit_notes_amount").Micros(0)
	ongoing, _ := j.At("ongoing_usage_balance").Micros(0)
	s := newSnap("mistral", c1SrcMistral, KindBrowser, ConfExact, in.Now)
	s.Balances = []Balance{
		{Kind: "available", Unit: unit, Amount: wallet + notes - ongoing},
		{Kind: "wallet", Unit: unit, Amount: wallet},
	}
	if r, ok := in.Responses["vibe"]; ok && httpErr(r, true) == nil {
		if v, err := ParseJ(r.Body); err == nil {
			d := v.At("0.result.data.json")
			if p, ok := d.At("usage_percentage").Num(); ok && p >= 0 && p <= 100 {
				s.Windows = append(s.Windows, PercentWindow("monthly", p, d.At("reset_at").Time(), 0))
			}
		}
	}
	return s, nil
}

// --- Qoder (rung 3) -----------------------------------------------------------------

// c1QoderHosts binds the region parameter to the site.
var c1QoderHosts = map[string]string{"": "qoder.com", c1RegionGlobal: "qoder.com", c1RegionChina: "qoder.com.cn"}

func c1PlanQoder(in PlanInput) ([]Request, error) {
	c, err := c1Cookie(in)
	if err != nil {
		return nil, err
	}
	host, ok := c1QoderHosts[in.Params[c1ParamRegion]]
	if !ok {
		return nil, fmt.Errorf("planlimits: qoder region %q", in.Params[c1ParamRegion])
	}
	origin := "https://" + host
	h := map[string]string{
		"Accept": "application/json, text/plain, */*", "Origin": origin, "Referer": origin + "/account/usage",
		"X-Requested-With": "XMLHttpRequest", "Bx-V": "2.5.35",
	}
	return []Request{c1Req("main", "GET", origin+"/api/v2/me/usages/big_model_credits", h, map[string]string{"Cookie": c}, nil, false)}, nil
}

// c1QoderPool reads one quota summary (used, limit, optional remaining).
func c1QoderPool(j J) (used, limit float64, remaining *float64, err error) {
	sum := j.First("quotaSummary", "quota_summary")
	u, ok1 := sum.First("usedValue", "used_value").Num()
	l, ok2 := sum.First("limitValue", "limit_value").Num()
	if !ok1 || !ok2 || u < 0 || l < 0 {
		return 0, 0, nil, shapeErr("qoder quota summary", nil)
	}
	return u, l, sum.First("remainingValue", "remaining_value").NumP(), nil
}

// c1ParseQoder maps the big model credits this cycle, with the shared team
// pool as its own window when the account has one.
func c1ParseQoder(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	s := newSnap("qoder", c1SrcQoder, KindBrowser, ConfExact, in.Now)
	reset := j.First("nextResetAt", "next_reset_at").Time()
	for _, p := range []struct{ key, a, b string }{{"cycle", "totalQuota", "total_quota"}, {"cycle:shared", "sharedQuota", "shared_quota"}} {
		pool := j.First(p.a, p.b)
		if !pool.Exists() {
			if p.key == "cycle" {
				return Snapshot{}, shapeErr("qoder total quota", nil)
			}
			continue
		}
		used, lim, rem, err := c1QoderPool(pool)
		if err != nil {
			return Snapshot{}, err
		}
		if lim > 0 {
			w, _ := AmountWindow(p.key, UnitCredits, F(used), F(lim), rem, reset, 0)
			s.Windows = append(s.Windows, w)
		}
	}
	if len(s.Windows) == 0 {
		s.Status = StatusPlanOnly
	}
	return s, nil
}
