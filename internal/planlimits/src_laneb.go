package planlimits

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// src_laneb.go holds lane B: API-key vendors (part 2) and self-hosted
// gateways. A self-hosted gateway has no fixed host: its source row sets
// UserBaseURL and the account carries a required base_url parameter, checked
// by CheckBaseURL when the account is saved and again by the egress package
// on every request (ledger SUBS-5). A vendor that also runs a hosted gateway
// (Aixy, ClawRouter) gets a second source with that fixed host.
//
// Endpoints, field names and units are facts taken from each vendor's own
// documentation (DocURL) or, for the undocumented ones, from the reference
// project's notes. Wayfinder and llmman have no source: neither is a plan or
// a balance (catalog.go Gap not_a_plan).

// Lane B source ids.
const (
	SourceLLMProxyGateway   = "llm_proxy.gateway"
	SourceLiteLLMGateway    = "litellm.gateway"
	SourceBifrostGateway    = "bifrost.gateway"
	SourceAixyAPI           = "aixy.api"
	SourceAixyGateway       = "aixy.gateway"
	SourceDeepgram          = "deepgram.api"
	SourceClawRouterAPI     = "clawrouter.api"
	SourceClawRouterGateway = "clawrouter.gateway"
	SourceSub2APIGateway    = "sub2api.gateway"
	SourceHyper             = "charm_hyper.api"
	SourceGitKrakenSession  = "gitkraken_ai.session"
	SourceDevPass           = "devpass.api"
	SourceAtlasCloud        = "atlas_cloud.api"
	SourceVercelGateway     = "vercel_ai_gateway.api"
	SourceXKiro             = "xkiro.api"
	SourceTavily            = "tavily.api"
	SourceLinkup            = "linkup.api"
	SourceExa               = "exa.admin"
	SourceCosmic            = "cosmic_ai.api"
	SourceAerostack         = "aerostack.api"
	SourceSailResearch      = "sail_research.api"
	SourceSofya             = "sofya.api"
	SourceFal               = "fal.api"
	SourceFlora             = "flora.api"
)

// Fixed bases of the hosted defaults.
const (
	aixyHostedBase       = "https://api.aixy-gateway.com"
	clawRouterHostedBase = "https://clawrouter.openclaw.ai"
)

// gatewayParams is the parameter list every self-hosted gateway source starts
// with: the required base URL.
func gatewayParams(more ...ParamSpec) []ParamSpec {
	return append([]ParamSpec{{Key: ParamBaseURL, Required: true}}, more...)
}

func init() {
	key := []SecretSpec{{Key: SecretKey, Required: true}}
	addSources([]SourceDef{
		// Self-hosted gateways: the host is the account's base URL.
		{
			ID: SourceLiteLLMGateway, Provider: "litellm", Kind: KindOfficialAPI, Order: 20, UserBaseURL: true,
			Secrets: key, Params: gatewayParams(ParamSpec{Key: "user_id"}, ParamSpec{Key: "team_id"}),
			MinInterval: 5 * time.Minute, DocURL: "https://docs.litellm.ai/docs/proxy/virtual_keys",
		},
		{
			ID: SourceBifrostGateway, Provider: "bifrost", Kind: KindOfficialAPI, Order: 20, UserBaseURL: true,
			Secrets: key, Params: gatewayParams(), MinInterval: 5 * time.Minute,
			DocURL: "https://github.com/maximhq/bifrost/blob/main/docs/openapi/schemas/management/governance.yaml",
		},
		{
			ID: SourceAixyAPI, Provider: "aixy", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"api.aixy-gateway.com"}, MinInterval: 5 * time.Minute,
			DocURL: "https://docs.aixy-gateway.com/observe/usage",
		},
		{
			ID: SourceAixyGateway, Provider: "aixy", Kind: KindOfficialAPI, Order: 21, UserBaseURL: true,
			Secrets: key, Params: gatewayParams(), MinInterval: 5 * time.Minute,
			DocURL: "https://docs.aixy-gateway.com/observe/usage",
		},
		{
			ID: SourceLLMProxyGateway, Provider: "llm_proxy", Kind: KindUndocumented, Order: 50, UserBaseURL: true,
			Secrets: key, Params: gatewayParams(), MinInterval: 5 * time.Minute,
		},
		{
			ID: SourceClawRouterAPI, Provider: "clawrouter", Kind: KindUndocumented, Order: 50, Secrets: key,
			Hosts: []string{"clawrouter.openclaw.ai"}, MinInterval: 10 * time.Minute,
		},
		{
			ID: SourceClawRouterGateway, Provider: "clawrouter", Kind: KindUndocumented, Order: 51, UserBaseURL: true,
			Secrets: key, Params: gatewayParams(), MinInterval: 10 * time.Minute,
		},
		{
			ID: SourceSub2APIGateway, Provider: "sub2api", Kind: KindUndocumented, Order: 50, UserBaseURL: true,
			Secrets: key, Params: gatewayParams(), MinInterval: 5 * time.Minute,
		},

		// Fixed-host vendors with a documented endpoint and the user's key.
		{
			ID: SourceDeepgram, Provider: "deepgram", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Params: []ParamSpec{{Key: "project_id", Required: true}}, Hosts: []string{"api.deepgram.com"},
			MinInterval: 15 * time.Minute, DocURL: "https://developers.deepgram.com/reference/manage/billing/list",
		},
		{
			ID: SourceHyper, Provider: "charm_hyper", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"hyper.charm.land"}, MinInterval: 10 * time.Minute,
			DocURL: "https://hyper.charm.land/docs/api/credits.html",
		},
		{
			ID: SourceDevPass, Provider: "devpass", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"api.llmgateway.io"}, MinInterval: 5 * time.Minute,
			DocURL: "https://docs.llmgateway.io/developers/devpass-usage",
		},
		{
			ID: SourceAtlasCloud, Provider: "atlas_cloud", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"api.atlascloud.ai"}, MinInterval: 10 * time.Minute,
			DocURL: "https://www.atlascloud.ai/docs/public-api/balance",
		},
		{
			ID: SourceVercelGateway, Provider: "vercel_ai_gateway", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"ai-gateway.vercel.sh"}, MinInterval: 10 * time.Minute,
			DocURL: "https://vercel.com/docs/ai-gateway/sdks-and-apis/rest-api#check-credit-balance",
		},
		{
			ID: SourceXKiro, Provider: "xkiro", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"api.xkiro.com"}, MinInterval: 5 * time.Minute, DocURL: "https://docs.xkiro.com/api/usage/",
		},
		{
			// Tavily allows 10 usage calls per 10 minutes.
			ID: SourceTavily, Provider: "tavily", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"api.tavily.com"}, MinInterval: 15 * time.Minute,
			DocURL: "https://docs.tavily.com/documentation/api-reference/endpoint/usage",
		},
		{
			ID: SourceLinkup, Provider: "linkup", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"api.linkup.so"}, MinInterval: 10 * time.Minute,
			DocURL: "https://docs.linkup.so/pages/documentation/endpoints/account/balance",
		},
		{
			ID: SourceExa, Provider: "exa", Kind: KindAdminAPI, Order: 20,
			Secrets: []SecretSpec{{Key: SecretMgmt, Required: true}},
			Params:  []ParamSpec{{Key: "api_key_id", Required: true}}, Hosts: []string{"admin-api.exa.ai"},
			MinInterval: 15 * time.Minute, DocURL: "https://exa.ai/docs/reference/team-management/get-api-key-usage",
		},
		{
			ID: SourceAerostack, Provider: "aerostack", Kind: KindOfficialAPI, Order: 20,
			Secrets: []SecretSpec{{Key: SecretPAT, Required: true}}, Hosts: []string{"api.aerostack.dev"},
			MinInterval: 10 * time.Minute, DocURL: "https://docs.aerostack.dev/billing/",
		},
		{
			ID: SourceSailResearch, Provider: "sail_research", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"api.sailresearch.com"}, MinInterval: 10 * time.Minute,
			DocURL: "https://docs.sailresearch.com/usage-endpoints",
		},
		{
			ID: SourceSofya, Provider: "sofya", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"sofya.co"}, MinInterval: 10 * time.Minute, DocURL: "https://sofya.co/docs",
		},
		{
			ID: SourceFal, Provider: "fal", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Hosts: []string{"api.fal.ai"}, MinInterval: 10 * time.Minute,
			DocURL: "https://fal.ai/docs/platform-apis/v1/account/billing",
		},
		{
			ID: SourceFlora, Provider: "flora", Kind: KindOfficialAPI, Order: 20, Secrets: key,
			Params: []ParamSpec{{Key: "workspace_id", Required: true}}, Hosts: []string{"app.flora.ai"},
			MinInterval: 10 * time.Minute, DocURL: "https://developer.flora.ai/reference/operations/getworkspaceusage/",
		},

		// Rung 2: the user's own token against an endpoint the vendor has not
		// documented (Cosmic's dashboard route, used only by its own CLI).
		{
			ID: SourceCosmic, Provider: "cosmic_ai", Kind: KindUndocumented, Order: 50,
			Secrets: []SecretSpec{{Key: SecretPAT, Required: true}},
			Params:  []ParamSpec{{Key: "project_id", Required: true}}, Hosts: []string{"dapi.cosmicjs.com"},
			MinInterval: 15 * time.Minute,
		},

		// Rung 3: GitKraken has no API key for AI usage; the user pastes the
		// bearer token the account page itself sends.
		{
			ID: SourceGitKrakenSession, Provider: "gitkraken_ai", Kind: KindBrowser, Order: 60,
			Secrets: []SecretSpec{{Key: SecretSession, Required: true}}, Params: []ParamSpec{{Key: "org_id"}},
			Hosts: []string{"api.gitkraken.dev"}, MinInterval: 15 * time.Minute,
		},
	}...)

	register(SourceLiteLLMGateway, Driver{Plan: planLiteLLM, Parse: parseLiteLLM})
	register(SourceBifrostGateway, Driver{Plan: planBifrost, Parse: parseBifrost})
	register(SourceAixyAPI, Driver{Plan: planAixy(false), Parse: parseAixyFor(SourceAixyAPI)})
	register(SourceAixyGateway, Driver{Plan: planAixy(true), Parse: parseAixyFor(SourceAixyGateway)})
	register(SourceLLMProxyGateway, Driver{Plan: planLLMProxy, Parse: parseLLMProxy})
	register(SourceClawRouterAPI, Driver{Plan: planClawRouter(false), Parse: parseClawRouterFor(SourceClawRouterAPI)})
	register(SourceClawRouterGateway, Driver{Plan: planClawRouter(true), Parse: parseClawRouterFor(SourceClawRouterGateway)})
	register(SourceSub2APIGateway, Driver{Plan: planSub2API, Parse: parseSub2API})
	register(SourceDeepgram, Driver{Plan: planDeepgram, Parse: parseDeepgram})
	register(SourceHyper, Driver{Plan: planSimpleGET("https://hyper.charm.land/v1/credits"), Parse: parseHyper})
	register(SourceDevPass, Driver{Plan: planSimpleGET("https://api.llmgateway.io/v1/key"), Parse: parseDevPass})
	register(SourceAtlasCloud, Driver{Plan: planSimpleGET("https://api.atlascloud.ai/public/v1/balance"), Parse: parseAtlasCloud})
	register(SourceVercelGateway, Driver{Plan: planSimpleGET("https://ai-gateway.vercel.sh/v1/credits"), Parse: parseVercel})
	register(SourceXKiro, Driver{Plan: planSimpleGET("https://api.xkiro.com/v1/usage"), Parse: parseXKiro})
	register(SourceTavily, Driver{Plan: planSimpleGET("https://api.tavily.com/usage"), Parse: parseTavily})
	register(SourceLinkup, Driver{Plan: planSimpleGET("https://api.linkup.so/v1/credits/balance"), Parse: parseLinkup})
	register(SourceExa, Driver{Plan: planExa, Parse: parseExa})
	register(SourceCosmic, Driver{Plan: planCosmic, Parse: parseCosmic})
	register(SourceAerostack, Driver{
		Plan:  keyedGET("https://api.aerostack.dev/api/billing/usage", SecretPAT, AuthBearer, "", nil),
		Parse: parseAerostack,
	})
	register(SourceSailResearch, Driver{Plan: planSimpleGET("https://api.sailresearch.com/v2/usage/summary?range=30d"), Parse: parseSail})
	register(SourceSofya, Driver{Plan: planSimpleGET("https://sofya.co/v1/auth/me"), Parse: parseSofya})
	register(SourceFal, Driver{Plan: planFal, Parse: parseFal})
	register(SourceFlora, Driver{Plan: planFlora, Parse: parseFlora})
	register(SourceGitKrakenSession, Driver{Plan: planGitKraken, Parse: parseGitKraken})
}

// --- user-supplied gateway base URL (ledger SUBS-5) ----------------------------

// ParamBaseURL is the account parameter holding a self-hosted gateway's base
// URL.
const ParamBaseURL = "base_url"

// ErrBadBaseURL is returned for a base URL outside the gateway policy.
var ErrBadBaseURL = errors.New("planlimits: base URL not allowed")

// loopbackHosts are the only hosts plain http may reach.
var loopbackHosts = map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true}

// baseRule is one row of the base URL policy, walked top-down; the first
// failing row names the reason.
type baseRule struct {
	why string
	bad func(raw string, u *url.URL) bool
}

// baseRules is the base URL policy: https, or plain http only to a loopback
// host; any port; no user info, no query, no fragment.
var baseRules = []baseRule{
	{"must not contain spaces or control characters", func(raw string, _ *url.URL) bool {
		return strings.IndexFunc(raw, func(r rune) bool { return r <= 0x20 || r == 0x7f || r == '\\' }) >= 0
	}},
	{"must be an absolute http or https address", func(_ string, u *url.URL) bool {
		s := strings.ToLower(u.Scheme)
		return (s != "https" && s != "http") || u.Opaque != "" || u.Host == "" || u.Hostname() == ""
	}},
	{"must not carry a user name or password", func(_ string, u *url.URL) bool { return u.User != nil }},
	{"must not carry a query", func(raw string, u *url.URL) bool {
		return u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "?")
	}},
	{"must not carry a fragment", func(raw string, u *url.URL) bool { return u.Fragment != "" || strings.Contains(raw, "#") }},
	{"has an invalid port", func(_ string, u *url.URL) bool {
		p := u.Port()
		if p == "" {
			return strings.HasSuffix(u.Host, ":")
		}
		n, err := strconv.Atoi(p)
		return err != nil || n < 1 || n > 65535
	}},
	{"may use plain http only to this machine (127.0.0.1, ::1 or localhost)", func(_ string, u *url.URL) bool {
		return strings.EqualFold(u.Scheme, "http") && !loopbackHosts[strings.ToLower(u.Hostname())]
	}},
}

// CheckBaseURL checks a self-hosted gateway's base URL against the policy and
// returns it parsed, with the scheme and host lower-cased and any trailing
// slash dropped from the path.
func CheckBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: base URL is required", ErrBadBaseURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: base URL is not a valid address", ErrBadBaseURL)
	}
	for _, r := range baseRules {
		if r.bad(raw, u) {
			return nil, fmt.Errorf("%w: base URL %s", ErrBadBaseURL, r.why)
		}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// gatewayGET builds one GET to path under the account's base URL, carrying
// the base in Request.Base for the egress check. With stripV1 a
// trailing /v1 on the base (an OpenAI-style base the user copied) is dropped
// before path is joined.
func gatewayGET(in PlanInput, path string, stripV1 bool, secretHeaders map[string]string) (Request, error) {
	u, err := CheckBaseURL(in.Params[ParamBaseURL])
	if err != nil {
		return Request{}, err
	}
	anchor := u.String()
	root := anchor
	if stripV1 {
		root = strings.TrimSuffix(root, "/v1")
	}
	r := getReq("main", root+path, secretHeaders, nil)
	r.Base = anchor
	return r, nil
}

// --- shared lane B helpers -----------------------------------------------------

// laneSnap starts a snapshot for a source row, the provider and kind taken
// from the row so they can never disagree.
func laneSnap(src string, now time.Time) Snapshot {
	d, _ := SourceByID(src)
	return newSnap(d.Provider, d.ID, d.Kind, ConfExact, now)
}

// getReq builds one GET with an Accept header and the given secret headers.
func getReq(key, u string, secretHeaders, extra map[string]string) Request {
	h := map[string]string{"Accept": "application/json"}
	for k, v := range extra {
		h[k] = v
	}
	return Request{Key: key, Kind: ReqHTTP, Method: "GET", URL: u, Header: h, SecretHeaders: secretHeaders}
}

// parseKey decodes the response body for key as JSON.
func parseKey(in ParseInput, key string) (J, error) {
	body, err := need(in, key)
	if err != nil {
		return J{}, err
	}
	return ParseJ(body)
}

// parseMain decodes the "main" response body as JSON.
func parseMain(in ParseInput) (J, error) { return parseKey(in, "main") }

// nonNeg reads a finite number that is zero or more; ok=false otherwise.
func nonNeg(j J) (float64, bool) {
	v, ok := j.Num()
	if !ok || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

// isJSONNumber reports whether the value is a JSON number (not a string).
func isJSONNumber(j J) bool {
	_, ok := j.v.(json.Number)
	return ok
}

// usdF reads a money amount as micros, as a window float; nil when unknown.
func usdF(j J) *float64 {
	m, ok := j.Micros(0)
	if !ok {
		return nil
	}
	return F(float64(m))
}

// pathSegment refuses an id that could escape a URL path segment or query.
func pathSegment(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v == "." || v == ".." || len(v) > 128 || strings.ContainsAny(v, "/\\?#%&= \t") {
		return "", false
	}
	return url.PathEscape(v), true
}

// keyPart turns a vendor id into a short window key part.
func keyPart(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if b.Len() >= 48 {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

// addWindow appends w unless its key is already taken (a vendor listing the
// same limit twice).
func addWindow(s *Snapshot, w Window) {
	if _, dup := FindWindow(*s, w.Key); dup {
		return
	}
	s.Windows = append(s.Windows, w)
}

// spanUnits are the fixed span suffixes a gateway may use beyond what
// time.ParseDuration reads.
var spanUnits = map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour}

// parseSpan reads a fixed span: a Go duration ("1h30m") or N days / weeks
// ("7d", "1w"). Calendar spans (months, quarters, years) have no fixed length
// and return ok=false.
func parseSpan(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, true
	}
	per, ok := spanUnits[s[len(s)-1:]]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, false
	}
	return time.Duration(n) * per, true
}

// strAt reads a string at path, "" when absent.
func strAt(j J, path string) string {
	v, _ := j.At(path).Str()
	return v
}

// throttleIfFull marks a snapshot throttled when any window is used up.
func throttleIfFull(s *Snapshot) {
	for _, w := range s.Windows {
		if f, ok := usedFrac(w); ok && f >= 1 {
			s.Status = StatusThrottled
		}
	}
}

// --- LiteLLM: key, user and team budgets ------------------------------------

func planLiteLLM(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	main, err := gatewayGET(in, "/key/info", true, bearer(k))
	if err != nil {
		return nil, err
	}
	reqs := []Request{main}
	for _, o := range []struct{ param, key, path string }{
		{"user_id", "user", "/user/info?user_id="},
		{"team_id", "team", "/team/info?team_id="},
	} {
		id := strings.TrimSpace(in.Params[o.param])
		if id == "" {
			continue
		}
		r, err := gatewayGET(in, o.path+url.QueryEscape(id), true, bearer(k))
		if err != nil {
			return nil, err
		}
		r.Key, r.Optional = o.key, true
		reqs = append(reqs, r)
	}
	return reqs, nil
}

// liteLLMBudget maps one LiteLLM spend and budget object (a key's, a user's
// or a team's info) onto spend and, when it has a budget, a budget window.
// ok=false when it carries no spend.
func liteLLMBudget(s *Snapshot, j J, key, scope string) bool {
	spend := usdF(j.At("spend"))
	if spend == nil {
		return false
	}
	length, fixed := parseSpan(strAt(j, "budget_duration"))
	period := "all_time"
	if fixed {
		period = "cycle"
	}
	s.Spend = append(s.Spend, Spend{Period: period, Unit: UnitUSDMicros, Amount: int64(*spend), Scope: scope})
	limit := usdF(j.At("max_budget"))
	if limit == nil || *limit <= 0 {
		return true // no budget: spend only
	}
	if !fixed {
		length = 0
	}
	if w, ok := AmountWindow(key, UnitUSDMicros, spend, limit, nil, j.At("budget_reset_at").Time(), length); ok {
		addWindow(s, w)
	}
	return true
}

func parseLiteLLM(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	s := laneSnap(SourceLiteLLMGateway, in.Now)
	if !liteLLMBudget(&s, j.At("info"), "budget:key", "key") {
		return Snapshot{}, shapeErr("litellm key info", nil)
	}
	if u, err := parseKey(in, "user"); err == nil {
		liteLLMBudget(&s, u.At("user_info"), "budget:user", "account")
	}
	if t, err := parseKey(in, "team"); err == nil {
		liteLLMBudget(&s, t.At("team_info"), "budget:team", "team")
	}
	throttleIfFull(&s)
	return s, nil
}

// --- Bifrost: virtual key budgets and rate limits ------------------------------

func planBifrost(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	r, err := gatewayGET(in, "/api/governance/virtual-keys/quota", false, map[string]string{"x-bf-vk": k})
	if err != nil {
		return nil, err
	}
	return []Request{r}, nil
}

// fixedReset returns last+length rolled forward past now; nil when the span
// is not fixed or there is no last reset.
func fixedReset(last *time.Time, length time.Duration, now time.Time) *time.Time {
	if last == nil || length <= 0 {
		return nil
	}
	r := last.Add(length)
	for i := 0; !r.After(now) && i < 10_000; i++ {
		r = r.Add(length)
	}
	if !r.After(now) {
		return nil
	}
	return &r
}

// bifrostBudget maps one budget object; max_limit 0 is unlimited (no window).
// An active override raises the limit by its amount.
func bifrostBudget(s *Snapshot, b J, prefix string, now time.Time) {
	limit, ok := nonNeg(b.At("max_limit"))
	if !ok || limit <= 0 {
		return
	}
	if over, ok := nonNeg(b.At("override_amount")); ok && over > 0 {
		left, _ := nonNeg(b.At("override_cycles_remaining"))
		if mode := strAt(b, "override_mode"); mode == "forever" || (mode == "cycles" && left > 0) {
			limit += over
		}
	}
	used, ok := nonNeg(b.At("current_usage"))
	if !ok {
		return
	}
	length, fixed := parseSpan(strAt(b, "reset_duration"))
	if !fixed {
		length = 0
	}
	w, ok := AmountWindow(prefix+keyPart(strAt(b, "id")), UnitUSDMicros,
		F(float64(microsFromFloat(used))), F(float64(microsFromFloat(limit))), nil,
		fixedReset(b.At("last_reset").Time(), length, now), length)
	if ok {
		addWindow(s, w)
	}
}

// bifrostRate maps one rate limit's token and request dimensions.
func bifrostRate(s *Snapshot, r J, now time.Time) {
	for _, d := range []struct {
		dim  string
		unit Unit
	}{{"token", UnitTokens}, {"request", UnitRequests}} {
		limit, okL := nonNeg(r.At(d.dim + "_max_limit"))
		used, okU := nonNeg(r.At(d.dim + "_current_usage"))
		if !okL || !okU || limit <= 0 {
			continue
		}
		length, fixed := parseSpan(strAt(r, d.dim+"_reset_duration"))
		if !fixed {
			length = 0
		}
		key := "rate_limit:" + keyPart(strAt(r, "id")) + ":" + d.dim + "s"
		if w, ok := AmountWindow(key, d.unit, F(used), F(limit), nil, fixedReset(r.At(d.dim+"_last_reset").Time(), length, now), length); ok {
			w.Rolling = fixed
			addWindow(s, w)
		}
	}
}

func parseBifrost(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	active, okActive := j.At("is_active").Bool()
	if !okActive && j.At("budgets").Arr() == nil {
		return Snapshot{}, shapeErr("bifrost quota", nil)
	}
	s := laneSnap(SourceBifrostGateway, in.Now)
	for _, b := range j.At("budgets").Arr() {
		bifrostBudget(&s, b, "budget:", in.Now)
	}
	limits := j.At("rate_limits").Arr()
	if len(limits) == 0 && j.At("rate_limit").Exists() {
		limits = []J{j.At("rate_limit")} // the merged view, only when the parts are absent
	}
	for _, r := range limits {
		bifrostRate(&s, r, in.Now)
	}
	for _, scope := range []struct{ list, name string }{{"provider_configs", "provider"}, {"model_configs", "model_name"}} {
		for _, c := range j.At(scope.list).Arr() {
			for _, b := range c.At("budgets").Arr() {
				bifrostBudget(&s, b, "budget:"+keyPart(strAt(c, scope.name))+":", in.Now)
			}
		}
	}
	throttleIfFull(&s)
	if okActive && !active {
		s.Status = StatusThrottled // the gateway refuses an inactive key
	}
	if len(s.Windows) == 0 && s.Status == StatusOK {
		s.Status = StatusUnmetered
	}
	return s, nil
}

// --- Aixy: key budgets (hosted or self-hosted) -----------------------------------

func planAixy(selfHosted bool) func(PlanInput) ([]Request, error) {
	return func(in PlanInput) ([]Request, error) {
		k, err := secret(in, SecretKey)
		if err != nil {
			return nil, err
		}
		if !selfHosted {
			return []Request{getReq("main", aixyHostedBase+"/v1/usage", bearer(k), nil)}, nil
		}
		r, err := gatewayGET(in, "/v1/usage", true, bearer(k))
		if err != nil {
			return nil, err
		}
		return []Request{r}, nil
	}
}

// aixyIntervals maps a budget interval to a window key prefix.
var aixyIntervals = map[string]string{"daily": "daily", "weekly": "weekly", "monthly": "monthly", "lifetime": "budget"}

func parseAixyFor(src string) func(ParseInput) (Snapshot, error) {
	return func(in ParseInput) (Snapshot, error) {
		j, err := parseMain(in)
		if err != nil {
			return Snapshot{}, err
		}
		if strAt(j, "object") != "key.usage" || strAt(j, "currency") != "USD" {
			return Snapshot{}, shapeErr("aixy key usage", nil)
		}
		s := laneSnap(src, in.Now)
		for _, b := range j.At("budgets").Arr() {
			aixyBudget(&s, b)
		}
		if strAt(j, "usage.window") == "7d" {
			if m, ok := j.At("usage.spend_usd").Micros(0); ok && m >= 0 {
				s.Spend = append(s.Spend, Spend{Period: "week", Unit: UnitUSDMicros, Amount: m, Scope: "key"})
			}
		}
		if len(s.Windows)+len(s.Spend) == 0 {
			return Snapshot{}, shapeErr("aixy: no budgets or usage", nil)
		}
		return s, nil
	}
}

// aixyBudget maps one budget. A hard budget counts reserved spend as used and
// reports what is left after reservations; a monitor budget reports spend.
func aixyBudget(s *Snapshot, b J) {
	prefix, ok := aixyIntervals[strAt(b, "interval")]
	if !ok {
		return
	}
	limit := usdF(b.At("limit_usd"))
	if limit == nil || *limit <= 0 {
		return
	}
	var used, left *float64
	hard := strAt(b, "enforcement") == "hard"
	switch {
	case hard && strAt(b, "availability.status") == "available":
		spent, reserved := usdF(b.At("availability.spent_usd")), usdF(b.At("availability.reserved_usd"))
		if spent != nil && reserved != nil {
			used = F(*spent + *reserved)
		}
		left = usdF(b.At("availability.remaining_usd"))
	case strAt(b, "spend_status") == "available":
		used, left = usdF(b.At("spend_usd")), usdF(b.At("remaining_usd"))
	}
	starts, resets := b.At("starts_at").Time(), b.At("resets_at").Time()
	var length time.Duration
	if starts != nil && resets != nil && resets.After(*starts) {
		length = resets.Sub(*starts)
	}
	key := prefix + ":" + keyPart(strAt(b, "scope"))
	if _, dup := FindWindow(*s, key); dup {
		key += ":" + keyPart(strAt(b, "id"))
	}
	if w, ok := AmountWindow(key, UnitUSDMicros, used, limit, left, resets, length); ok {
		addWindow(s, w)
		if hard && w.Remaining != nil && *w.Remaining <= 0 {
			s.Status = StatusThrottled
		}
	}
}

// --- LLM-API-Key-Proxy: per-provider quota groups ----------------------------------

func planLLMProxy(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	r, err := gatewayGET(in, "/v1/quota-stats", true, bearer(k))
	if err != nil {
		return nil, err
	}
	return []Request{r}, nil
}

func parseLLMProxy(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	providers := j.At("providers")
	if providers.Keys() == nil {
		return Snapshot{}, shapeErr("llm proxy providers", nil)
	}
	s := laneSnap(SourceLLMProxyGateway, in.Now)
	var cost float64
	haveCost := false
	for _, p := range providers.Keys() {
		groups := providers.At(p).At("quota_groups")
		names, list := []string{}, []J{}
		for i, g := range groups.Arr() {
			names, list = append(names, strconv.Itoa(i)), append(list, g)
		}
		for _, n := range groups.Keys() {
			names, list = append(names, n), append(list, groups.At(n))
		}
		for i, g := range list {
			// remaining_percent is what is LEFT, on a 0..100 scale.
			rem, ok := nonNeg(g.At("remaining_percent"))
			if !ok || rem > 100 {
				continue
			}
			w := PercentWindow("quota:"+keyPart(p)+":"+keyPart(names[i]), 100-rem, nil, 0)
			if t := g.At("reset_time").Time(); t != nil && t.After(in.Now) {
				w.ResetsAt = t
			}
			addWindow(&s, w)
		}
		if v, ok := nonNeg(providers.At(p).At("approx_cost")); ok {
			cost, haveCost = cost+v, true
		}
	}
	if v, ok := nonNeg(j.At("summary.approx_cost")); ok {
		cost, haveCost = v, true
	}
	if haveCost {
		// The proxy calls its cost approximate, over everything it has seen.
		s.Spend = []Spend{{Period: "all_time", Unit: UnitUSDMicros, Amount: microsFromFloat(cost), Scope: "account"}}
		s.Confidence = ConfEstimated
	}
	sort.SliceStable(s.Windows, func(a, b int) bool { return s.Windows[a].Key < s.Windows[b].Key })
	throttleIfFull(&s)
	if err := requireAny(s, "llm proxy"); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// --- ClawRouter: monthly policy budget (hosted or self-hosted) -----------------------

func planClawRouter(selfHosted bool) func(PlanInput) ([]Request, error) {
	return func(in PlanInput) ([]Request, error) {
		k, err := secret(in, SecretKey)
		if err != nil {
			return nil, err
		}
		if !selfHosted {
			return []Request{getReq("main", clawRouterHostedBase+"/v1/usage", bearer(k), nil)}, nil
		}
		r, err := gatewayGET(in, "/v1/usage", true, bearer(k))
		if err != nil {
			return nil, err
		}
		return []Request{r}, nil
	}
}

// clawReset reads the month a budget windowKey names ("<..>/2026-07") and
// returns the start of the next month in UTC.
func clawReset(windowKey string) *time.Time {
	t, err := time.Parse("2006-01", windowKey[strings.LastIndex(windowKey, "/")+1:])
	if err != nil {
		return nil
	}
	r := time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	return &r
}

func parseClawRouterFor(src string) func(ParseInput) (Snapshot, error) {
	return func(in ParseInput) (Snapshot, error) {
		j, err := parseMain(in)
		if err != nil {
			return Snapshot{}, err
		}
		configured, ok := j.At("budget.configured").Bool()
		if !ok {
			return Snapshot{}, shapeErr("clawrouter budget", nil)
		}
		s := laneSnap(src, in.Now)
		if !configured {
			s.Status = StatusUnmetered
			return s, nil
		}
		// All amounts are integer micro-dollars already.
		limit, okL := nonNeg(j.At("budget.limitMicros"))
		spent, okS := nonNeg(j.At("budget.spentMicros"))
		if !okL || !okS || limit <= 0 {
			return Snapshot{}, shapeErr("clawrouter budget amounts", nil)
		}
		w, _ := AmountWindow("monthly", UnitUSDMicros, F(spent), F(limit), j.At("budget.remainingMicros").NumP(), clawReset(strAt(j, "budget.windowKey")), 0)
		s.Windows = []Window{w}
		s.Spend = []Spend{{Period: "month", Unit: UnitUSDMicros, Amount: int64(spent), Scope: "key"}}
		throttleIfFull(&s)
		return s, nil
	}
}

// --- sub2api: subscription, quota and rate-limit windows --------------------------

func planSub2API(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	r, err := gatewayGET(in, "/v1/usage?days=30&timezone=UTC", true, bearer(k))
	if err != nil {
		return nil, err
	}
	return []Request{r}, nil
}

// sub2apiRateKeys maps a rate-limit window to its window key and length.
var sub2apiRateKeys = map[string]struct {
	key    string
	length time.Duration
}{
	"5h": {"5h", 5 * time.Hour},
	"1d": {"rate_limit:daily", 24 * time.Hour},
	"7d": {"rate_limit:weekly", 7 * 24 * time.Hour},
}

// sub2apiSubs are the subscription windows, by declared length.
var sub2apiSubs = []struct {
	name   string
	length time.Duration
}{{"daily", 24 * time.Hour}, {"weekly", 7 * 24 * time.Hour}, {"monthly", 30 * 24 * time.Hour}}

func parseSub2API(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	if v, ok := j.At("isValid").Bool(); ok && !v {
		return Snapshot{}, fmt.Errorf("%w: key not valid", ErrAuth)
	}
	code := "USD"
	if u := strAt(j, "unit"); u != "" {
		code = u
	}
	unit := CurrencyUnit(code)
	if unit == "" {
		return Snapshot{}, shapeErr("sub2api unit", nil)
	}
	money := func(p string) *float64 {
		v, ok := nonNeg(j.At(p))
		if !ok {
			return nil
		}
		return F(float64(microsFromFloat(v)))
	}
	s := laneSnap(SourceSub2APIGateway, in.Now)
	s.PlanLabel = SanitizeLabel(strAt(j, "planName"))
	for _, sub := range sub2apiSubs {
		lim, used := money("subscription."+sub.name+"_limit_usd"), money("subscription."+sub.name+"_usage_usd")
		if lim == nil || *lim <= 0 || used == nil {
			continue
		}
		if w, ok := AmountWindow(sub.name, unit, used, lim, nil, nil, sub.length); ok {
			addWindow(&s, w)
		}
	}
	if lim := money("quota.limit"); lim != nil && *lim > 0 {
		if w, ok := AmountWindow("key_cap", unit, money("quota.used"), lim, money("quota.remaining"), nil, 0); ok {
			addWindow(&s, w)
		}
	}
	for _, r := range j.At("rate_limits").Arr() {
		rk, ok := sub2apiRateKeys[strAt(r, "window")]
		lim, okL := nonNeg(r.At("limit"))
		if !ok || !okL || lim <= 0 {
			continue
		}
		var used, rem *float64
		if v, ok := nonNeg(r.At("used")); ok {
			used = F(float64(microsFromFloat(v)))
		}
		if v, ok := nonNeg(r.At("remaining")); ok {
			rem = F(float64(microsFromFloat(v)))
		}
		if w, ok := AmountWindow(rk.key, unit, used, F(float64(microsFromFloat(lim))), rem, r.At("reset_at").Time(), rk.length); ok {
			w.Rolling = true
			addWindow(&s, w)
		}
	}
	if b, ok := j.At("balance").Num(); ok && !math.IsNaN(b) && !math.IsInf(b, 0) {
		s.Balances = append(s.Balances, Balance{Kind: "wallet", Unit: unit, Amount: microsFromFloat(b)})
	}
	throttleIfFull(&s)
	if err := requireAny(s, "sub2api"); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// --- Deepgram: project balances ------------------------------------------------

func planDeepgram(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	pid, ok := pathSegment(in.Params["project_id"])
	if !ok {
		return nil, errors.New("planlimits: invalid Deepgram project id")
	}
	u := "https://api.deepgram.com/v1/projects/" + pid + "/balances"
	return []Request{getReq("main", u, map[string]string{"Authorization": "Token " + k}, nil)}, nil
}

// parseDeepgram sums a project's outstanding balances per currency (several
// purchases in one currency add up; currencies never do). A balance in a
// unit that is not a currency is not shown.
func parseDeepgram(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	list := j.At("balances").Arr()
	if list == nil {
		return Snapshot{}, shapeErr("deepgram balances", nil)
	}
	sums := map[Unit]int64{}
	var order []Unit
	for _, b := range list {
		unit := CurrencyUnit(strAt(b, "units"))
		m, ok := b.At("amount").Micros(0)
		if unit == "" || !ok {
			continue
		}
		if _, seen := sums[unit]; !seen {
			order = append(order, unit)
		}
		sums[unit] += m
	}
	s := laneSnap(SourceDeepgram, in.Now)
	for _, u := range order {
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: u, Amount: sums[u]})
	}
	if len(s.Balances) == 0 {
		if len(list) == 0 {
			s.Status = StatusPlanOnly // no prepaid balance on this project
			return s, nil
		}
		return Snapshot{}, shapeErr("deepgram: no balance in a currency", nil)
	}
	return s, nil
}

// --- Charm Hyper: Hypercredits balance ----------------------------------------------

func parseHyper(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	v, ok := nonNeg(j.At("balance"))
	if !ok || !isJSONNumber(j.At("balance")) {
		return Snapshot{}, shapeErr("hyper balance", nil)
	}
	s := laneSnap(SourceHyper, in.Now)
	// Hypercredits are credits, never converted to money.
	s.Balances = []Balance{{Kind: "credits", Unit: UnitCredits, Amount: int64(math.Round(v))}}
	if v <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- DevPass: plan credits, premium weekly window, key spend -------------------------

// devPassPlans is the closed set of plan codes the vendor documents.
var devPassPlans = map[string]bool{"none": true, "lite": true, "pro": true, "max": true}

func parseDevPass(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	d := j.At("data")
	plan := strAt(d, "devPlan")
	usage, okUsage := d.At("usage").Micros(0)
	if !devPassPlans[plan] || !okUsage {
		return Snapshot{}, shapeErr("devpass key", nil)
	}
	s := laneSnap(SourceDevPass, in.Now)
	s.PlanCode = plan
	if plan == "none" {
		s.PlanCode = "payg"
	}
	s.Spend = []Spend{{Period: "all_time", Unit: UnitUSDMicros, Amount: usage, Scope: "key"}}
	if lim := usdF(d.At("limit")); lim != nil && *lim > 0 {
		if w, ok := AmountWindow("key_cap", UnitUSDMicros, F(float64(usage)), lim, nil, nil, 0); ok {
			addWindow(&s, w)
		}
	}
	if plan != "none" {
		// Plan credits are an allowance in dollars for the billing cycle; the
		// vendor gives no cycle end, so no reset is claimed.
		if lim := usdF(d.At("devPlanCreditsLimit")); lim != nil && *lim > 0 {
			if w, ok := AmountWindow("cycle", UnitUSDMicros, usdF(d.At("devPlanCreditsUsed")), lim, usdF(d.At("devPlanCreditsRemaining")), nil, 0); ok {
				addWindow(&s, w)
			}
		}
		if lim := usdF(d.At("devPlanPremiumWeeklyLimit")); lim != nil && *lim > 0 {
			reset := d.At("devPlanPremiumWeekResetsAt").Time()
			if w, ok := AmountWindow("weekly:premium", UnitUSDMicros, usdF(d.At("devPlanPremiumCreditsUsed")), lim, nil, reset, 7*24*time.Hour); ok {
				w.Rolling = true
				addWindow(&s, w)
			}
		}
	}
	throttleIfFull(&s)
	return s, nil
}

// --- Atlas Cloud: account balance ------------------------------------------------------

func parseAtlasCloud(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	unit := CurrencyUnit(strAt(j, "available.currency"))
	val, isStr := j.At("available.value").v.(string)
	if strAt(j, "object") != "balance" || strAt(j, "scope") != "account" || !isStr || unit == "" {
		return Snapshot{}, shapeErr("atlas cloud balance", nil)
	}
	m, err := MicrosFromDecimal(val, 0)
	if err != nil {
		return Snapshot{}, shapeErr("atlas cloud value", err)
	}
	s := laneSnap(SourceAtlasCloud, in.Now)
	s.PlanCode = "payg"
	s.Balances = []Balance{{Kind: "available", Unit: unit, Amount: m}}
	if m <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- Vercel AI Gateway: team credits ----------------------------------------------------

func parseVercel(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	// Both are documented as decimal strings; a bare number is a changed shape.
	bal, ok1 := j.At("balance").v.(string)
	used, ok2 := j.At("total_used").v.(string)
	if !ok1 || !ok2 {
		return Snapshot{}, shapeErr("vercel credits", nil)
	}
	b, err := MicrosFromDecimal(bal, 0)
	if err != nil {
		return Snapshot{}, shapeErr("vercel balance", err)
	}
	u, err := MicrosFromDecimal(used, 0)
	if err != nil || u < 0 {
		return Snapshot{}, shapeErr("vercel total_used", err)
	}
	s := laneSnap(SourceVercelGateway, in.Now)
	s.Balances = []Balance{{Kind: "prepaid", Unit: UnitUSDMicros, Amount: b}}
	s.Spend = []Spend{{Period: "all_time", Unit: UnitUSDMicros, Amount: u, Scope: "team"}}
	if b <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- xKiro: daily free tokens and wallet --------------------------------------------------

func parseXKiro(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	if strAt(j, "object") != "usage" {
		return Snapshot{}, shapeErr("xkiro object", nil)
	}
	s := laneSnap(SourceXKiro, in.Now)
	s.PlanCode = "payg"
	if p := strAt(j, "plan"); p != "" {
		s.PlanLabel, s.PlanCode = SanitizeLabel(p), SanitizeLabel(strings.ToLower(p))
	}
	ft := j.At("free_tokens")
	if lim, ok := nonNeg(ft.At("limit_per_day")); ok && lim > 0 {
		var used, rem *float64
		if v, ok := nonNeg(ft.At("used_today")); ok {
			used = F(v)
		}
		if v, ok := nonNeg(ft.At("remaining")); ok {
			rem = F(v)
		}
		// Documented: the free allowance resets at 00:00 UTC.
		now := in.Now.UTC()
		reset := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
		if w, ok := AmountWindow("daily", UnitTokens, used, F(lim), rem, &reset, 24*time.Hour); ok {
			addWindow(&s, w)
		}
	}
	if bal, ok := j.At("wallet.balance_usd").Str(); ok {
		if m, err := MicrosFromDecimal(bal, 0); err == nil {
			s.Balances = append(s.Balances, Balance{Kind: "wallet", Unit: UnitUSDMicros, Amount: m})
		}
	}
	throttleIfFull(&s)
	if err := requireAny(s, "xkiro"); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// --- Tavily: plan, key and pay-as-you-go credits ---------------------------------------------

// tavilyWindows maps the documented credit counters to window keys. Plan
// credits reset monthly on the 1st; the vendor gives no time zone, so no
// reset time is claimed.
var tavilyWindows = []struct{ key, used, limit string }{
	{"monthly", "account.plan_usage", "account.plan_limit"},
	{"key_cap", "key.usage", "key.limit"},
	{"monthly:paygo", "account.paygo_usage", "account.paygo_limit"},
}

func parseTavily(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	used, okU := nonNeg(j.At("account.plan_usage"))
	lim, okL := nonNeg(j.At("account.plan_limit"))
	if !okU || !okL {
		return Snapshot{}, shapeErr("tavily plan usage", nil)
	}
	s := laneSnap(SourceTavily, in.Now)
	s.PlanLabel = SanitizeLabel(strAt(j, "account.current_plan"))
	for _, w := range tavilyWindows {
		u, ok1 := nonNeg(j.At(w.used))
		l, ok2 := nonNeg(j.At(w.limit))
		if !ok1 || !ok2 || l <= 0 {
			continue
		}
		if win, ok := AmountWindow(w.key, UnitCredits, F(u), F(l), nil, nil, 0); ok {
			addWindow(&s, win)
		}
	}
	// Plan credits used up is a limit only when no pay-as-you-go room is left.
	if lim > 0 && used >= lim {
		if pw, ok := FindWindow(s, "monthly:paygo"); !ok || (pw.Remaining != nil && *pw.Remaining <= 0) {
			s.Status = StatusThrottled
		}
	}
	if len(s.Windows) == 0 {
		s.Status = StatusUnmetered
	}
	return s, nil
}

// --- Linkup: prepaid balance ----------------------------------------------------------

func parseLinkup(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	b := j.At("balance")
	m, ok := b.Micros(0)
	if !ok || !isJSONNumber(b) {
		return Snapshot{}, shapeErr("linkup balance", nil)
	}
	s := laneSnap(SourceLinkup, in.Now)
	s.PlanCode = "payg"
	s.Balances = []Balance{{Kind: "prepaid", Unit: UnitUSDMicros, Amount: m}}
	if m <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- Exa: month-to-date spend of one API key (team management key) -------------------

func planExa(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretMgmt)
	if err != nil {
		return nil, err
	}
	id, ok := pathSegment(in.Params["api_key_id"])
	if !ok {
		return nil, errors.New("planlimits: invalid Exa API key id")
	}
	now := in.Now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	q := url.Values{}
	q.Set("start_date", start.Format("2006-01-02T15:04:05.000Z"))
	q.Set("end_date", now.Truncate(time.Second).Format("2006-01-02T15:04:05.000Z"))
	u := "https://admin-api.exa.ai/team-management/api-keys/" + id + "/usage?" + q.Encode()
	return []Request{getReq("main", u, map[string]string{"x-api-key": k}, nil)}, nil
}

func parseExa(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	if _, ok := nonNeg(j.At("total_cost_usd")); !ok {
		return Snapshot{}, shapeErr("exa total_cost_usd", nil)
	}
	m, _ := j.At("total_cost_usd").Micros(0)
	s := laneSnap(SourceExa, in.Now)
	s.Spend = []Spend{{Period: "month", Unit: UnitUSDMicros, Amount: m, Scope: "key"}}
	return s, nil
}

// --- Cosmic: AI token allowance of one project -----------------------------------------

// cosmicSuffix maps an allowance suffix to its multiplier.
var cosmicSuffix = map[byte]float64{'k': 1e3, 'K': 1e3, 'm': 1e6, 'M': 1e6}

// cosmicAllowance reads an allowance: a number, "300k" / "1.5M", or
// "unlimited". ok=false when it cannot be read.
func cosmicAllowance(j J) (v float64, unlimited, ok bool) {
	if isJSONNumber(j) {
		x, ok := nonNeg(j)
		return x, false, ok
	}
	s, isStr := j.Str()
	s = strings.TrimSpace(s)
	if !isStr || s == "" {
		return 0, false, false
	}
	if strings.EqualFold(s, "unlimited") {
		return 0, true, true
	}
	mult := 1.0
	if m, ok := cosmicSuffix[s[len(s)-1]]; ok {
		mult, s = m, strings.TrimSpace(s[:len(s)-1])
	}
	x, err := strconv.ParseFloat(s, 64)
	if err != nil || x < 0 || math.IsNaN(x) || math.IsInf(x, 0) {
		return 0, false, false
	}
	return x * mult, false, true
}

func planCosmic(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretPAT)
	if err != nil {
		return nil, err
	}
	pid, ok := pathSegment(in.Params["project_id"])
	if !ok {
		return nil, errors.New("planlimits: invalid Cosmic project id")
	}
	u := "https://dapi.cosmicjs.com/v3/projects/usage?project_id=" + pid
	return []Request{getReq("main", u, bearer(k), map[string]string{"Origin": "https://app.cosmicjs.com"})}, nil
}

func parseCosmic(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	s := laneSnap(SourceCosmic, in.Now)
	unlimited := 0
	// The vendor states no reset or period for these allowances, so the
	// windows are the plan's cycle with no length claimed.
	for _, w := range []struct{ key, used, limit string }{
		{"cycle:ai_input_tokens", "usage.ai.input_tokens", "plan_info.ai_tokens.max_input"},
		{"cycle:ai_output_tokens", "usage.ai.output_tokens", "plan_info.ai_tokens.max_output"},
	} {
		lim, unl, ok := cosmicAllowance(j.At(w.limit))
		if unl {
			unlimited++
			continue
		}
		used, okU := nonNeg(j.At(w.used))
		if !ok || !okU || lim <= 0 {
			continue
		}
		if win, ok := AmountWindow(w.key, UnitTokens, F(used), F(lim), nil, nil, 0); ok {
			addWindow(&s, win)
		}
	}
	if len(s.Windows) == 0 {
		if unlimited > 0 {
			s.Status = StatusUnmetered
			return s, nil
		}
		return Snapshot{}, shapeErr("cosmic: no token allowance", nil)
	}
	return s, nil
}

// --- Aerostack: monthly plan allowances -------------------------------------------------

// aerostackMeters maps the documented usage meters to window keys and units.
var aerostackMeters = []struct {
	in, key string
	unit    Unit
}{
	{"ai_tokens", "monthly:ai_tokens", UnitTokens},
	{"api_requests", "monthly:api_requests", UnitRequests},
	{"gateway_requests", "monthly:gateway_requests", UnitRequests},
	{"mcp_proxy_calls", "monthly:mcp_proxy_calls", UnitRequests},
}

func parseAerostack(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	s := laneSnap(SourceAerostack, in.Now)
	if t := strAt(j, "tier"); t != "" {
		s.PlanLabel, s.PlanCode = SanitizeLabel(t), SanitizeLabel(strings.ToLower(t))
	}
	reset := j.At("current_period_end").Time()
	for _, m := range aerostackMeters {
		used, okU := nonNeg(j.At("usage." + m.in + ".used"))
		lim, okL := nonNeg(j.At("usage." + m.in + ".limit"))
		if !okU || !okL || lim <= 0 {
			continue
		}
		if w, ok := AmountWindow(m.key, m.unit, F(used), F(lim), nil, reset, 0); ok {
			addWindow(&s, w)
		}
	}
	if c, ok := j.At("wallet.balance_cents").Micros(2); ok {
		s.Balances = append(s.Balances, Balance{Kind: "wallet", Unit: UnitUSDMicros, Amount: c})
	}
	// Going over an allowance is not throttled: Aerostack documents a grace
	// buffer.
	if err := requireAny(s, "aerostack"); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// --- Sail Research: organisation balance and recent spend ---------------------------------

// sailRanges maps the reported range to a spend period; a range not listed
// is not reported as spend.
var sailRanges = map[string]string{"24h": "day", "7d": "week", "30d": "30d", "period": "cycle"}

func parseSail(in ParseInput) (Snapshot, error) {
	if r, ok := in.Responses["main"]; ok && r.Err == nil && r.Status == 402 {
		// Documented: the key is disabled because the credits are used up.
		s := laneSnap(SourceSailResearch, in.Now)
		s.Status = StatusThrottled
		return s, nil
	}
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	if strAt(j, "object") != "usage.summary" {
		return Snapshot{}, shapeErr("sail research object", nil)
	}
	if a, ok := j.At("available").Bool(); ok && !a {
		return Snapshot{}, fmt.Errorf("%w: usage summary unavailable", ErrTransient)
	}
	if c, ok := j.At("has_metronome_customer").Bool(); ok && !c {
		return Snapshot{}, fmt.Errorf("%w: no billing account", ErrNotApplicable)
	}
	s := laneSnap(SourceSailResearch, in.Now)
	// Both amounts are in (fractional) US cents.
	if u, _ := j.At("balance_unavailable").Bool(); !u {
		if m, ok := j.At("balance").Micros(2); ok {
			s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: m})
		}
	}
	if p, ok := sailRanges[strAt(j, "effective_range")]; ok {
		if _, ok := nonNeg(j.At("period_spend")); ok {
			m, _ := j.At("period_spend").Micros(2)
			s.Spend = append(s.Spend, Spend{Period: p, Unit: UnitUSDMicros, Amount: m, Scope: "account"})
		}
	}
	if err := requireAny(s, "sail research"); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// --- Sofya: account credits -----------------------------------------------------------

// sofyaBalances maps the documented credit fields to balance kinds. credits
// is what is left in total; plan and purchased credits are its two parts
// (purchased credits are spent last), so neither is the amount "bought".
var sofyaBalances = []struct{ path, kind string }{{"credits", "credits"}, {"plan_credits", "granted"}, {"purchased_credits", "topup"}}

func parseSofya(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	s := laneSnap(SourceSofya, in.Now)
	for _, b := range sofyaBalances {
		if v, ok := nonNeg(j.At(b.path)); ok {
			s.Balances = append(s.Balances, Balance{Kind: b.kind, Unit: UnitCredits, Amount: int64(math.Round(v))})
		}
	}
	if len(s.Balances) == 0 {
		return Snapshot{}, shapeErr("sofya: no credits", nil)
	}
	if free, ok := j.At("is_free_tier").Bool(); ok {
		s.PlanCode = "payg"
		if free {
			s.PlanCode = "free"
		}
	}
	if b, ok := FindBalance(s, "credits"); ok && b.Amount <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- fal: prepaid credit balance ------------------------------------------------------

func planFal(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	// fal's documented scheme is "Key <key>", not Bearer.
	return []Request{getReq("main", "https://api.fal.ai/v1/account/billing?expand=credits", map[string]string{"Authorization": "Key " + k}, nil)}, nil
}

func parseFal(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	c := j.At("credits")
	if !c.Exists() {
		// A reply without the credits object means "try again"; never zero.
		return Snapshot{}, fmt.Errorf("%w: no credit balance this time", ErrTransient)
	}
	m, ok := c.At("current_balance").Micros(0)
	if !ok {
		return Snapshot{}, shapeErr("fal current_balance", nil)
	}
	unit := UnitUSDMicros
	if cur := strAt(c, "currency"); cur != "" {
		if unit = CurrencyUnit(cur); unit == "" {
			return Snapshot{}, shapeErr("fal currency", nil)
		}
	}
	s := laneSnap(SourceFal, in.Now)
	s.PlanCode = "payg"
	s.Balances = []Balance{{Kind: "prepaid", Unit: unit, Amount: m}}
	if m <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- FLORA: workspace balance and month spend ---------------------------------------------

// validFloraWorkspace accepts ws_ followed by letters and digits only.
func validFloraWorkspace(v string) bool {
	if !strings.HasPrefix(v, "ws_") || len(v) <= 3 || len(v) > 128 {
		return false
	}
	for _, r := range v[3:] {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func planFlora(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	ws := strings.TrimSpace(in.Params["workspace_id"])
	if !validFloraWorkspace(ws) {
		return nil, errors.New("planlimits: invalid FLORA workspace id")
	}
	now := in.Now.UTC()
	q := url.Values{}
	q.Set("start_date", time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02"))
	q.Set("end_date", now.Format("2006-01-02"))
	u := "https://app.flora.ai/api/v1/workspaces/" + ws + "/usage?" + q.Encode()
	return []Request{getReq("main", u, bearer(k), nil)}, nil
}

func parseFlora(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	unit := UnitUSDMicros
	if cur := strAt(j, "currency"); cur != "" {
		if unit = CurrencyUnit(cur); unit == "" {
			return Snapshot{}, shapeErr("flora currency", nil)
		}
	}
	avail, ok := j.At("available_cost").Micros(0)
	if !ok || !isJSONNumber(j.At("available_cost")) {
		return Snapshot{}, shapeErr("flora available_cost", nil)
	}
	s := laneSnap(SourceFlora, in.Now)
	s.Balances = []Balance{{Kind: "available", Unit: unit, Amount: avail}}
	scope := strAt(j, "balance_scope")
	// A member's own monthly allowance: what is available is what is left of
	// it, so the allowance is the "out of" amount.
	if scope == "caller" && strAt(j, "member_limit.period") == "month" {
		if lim, ok := j.At("member_limit.limit_cost").Micros(0); ok && lim > 0 {
			s.Balances = append(s.Balances, Balance{Kind: "allowance", Unit: unit, Amount: lim})
		}
	}
	if strAt(j, "spend.status") == "available" {
		if _, ok := nonNeg(j.At("spend.total_cost")); ok {
			m, _ := j.At("spend.total_cost").Micros(0)
			sc := "team"
			if scope == "caller" {
				sc = "account"
			}
			s.Spend = append(s.Spend, Spend{Period: "month", Unit: unit, Amount: m, Scope: sc})
		}
	}
	if avail <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- GitKraken AI: weekly credits (pasted session token) -------------------------------------

func planGitKraken(in PlanInput) ([]Request, error) {
	raw, err := secret(in, SecretSession)
	if err != nil {
		return nil, err
	}
	tok := SessionBearer(raw)
	if tok == "" {
		return nil, fmt.Errorf("%w: session missing", ErrAuth)
	}
	extra := map[string]string{"Client-Name": "superbased-observer"}
	if org := strings.TrimSpace(in.Params["org_id"]); org != "" {
		if strings.ContainsAny(org, "\r\n\x00") || len(org) > 128 {
			return nil, errors.New("planlimits: invalid GitKraken organization id")
		}
		extra["gk-org-id"] = org
	}
	return []Request{getReq("main", "https://api.gitkraken.dev/v1/ai-tasks/usage", bearer(tok), extra)}, nil
}

func parseGitKraken(in ParseInput) (Snapshot, error) {
	j, err := parseMain(in)
	if err != nil {
		return Snapshot{}, err
	}
	if j.At("error").Exists() {
		return Snapshot{}, shapeErr("gitkraken error", nil)
	}
	d := j.At("data")
	used, okU := nonNeg(d.At("used"))
	lim, okL := d.At("limit").Num()
	if !okU || !okL {
		return Snapshot{}, shapeErr("gitkraken usage", nil)
	}
	s := laneSnap(SourceGitKrakenSession, in.Now)
	reset := d.At("resetsOn").Time()
	week := 7 * 24 * time.Hour
	switch {
	case lim < 0: // -1: unlimited
		s.PlanCode = "unlimited"
	case lim == 0: // no allowance on this account
		s.Status = StatusPlanOnly
	default:
		w, _ := AmountWindow("weekly", UnitCredits, F(used), F(lim), nil, reset, week)
		addWindow(&s, w)
	}
	pu, ok1 := nonNeg(d.At("organization.used"))
	pl, ok2 := nonNeg(d.At("organization.limit"))
	if ok1 && ok2 && pl > 0 {
		if w, ok := AmountWindow("weekly:org_pool", UnitCredits, F(pu), F(pl), nil, reset, week); ok {
			addWindow(&s, w)
		}
	}
	if s.Status == StatusOK {
		throttleIfFull(&s)
		if len(s.Windows) == 0 {
			s.Status = StatusUnmetered
		}
	}
	return s, nil
}
