package planlimits

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// src_lanec2.go holds lane C2 of the full catalogue: mostly vendors whose
// numbers live behind a signed-in web console (D-640 rung 3, a session the
// user pastes), plus the documented X API usage endpoint (rung 1).
//
// Facts (endpoints, field names, units) were read from the reference
// project CodexBar (MIT); the code and the fixtures are Observer's own. A
// flow that needs one response before the next request can be built (a
// token exchange, a page scrape for a server action id) does not fit the
// plan-then-parse driver shape; those vendors carry a Gap in catalog.go and
// where a stable id is enough, the user types it once as a parameter.
//
// Observer never reads a browser's cookie store: every session here is
// pasted by the user and lives in the keychain.

// Lane C2 source ids.
const (
	SourceStepFunSession        = "stepfun.session"
	SourceHelmcodeSession       = "helmcode.session"
	SourceLongCatSession        = "longcat.session"
	SourceXAPIUsage             = "x_api.usage"
	SourceXAPISession           = "x_api.session"
	SourceNotionSession         = "notion_ai.session"
	SourceReplicateSession      = "replicate.session"
	SourceRaycastSession        = "raycast.session"
	SourceLithosAISession       = "lithosai.session"
	SourceWorkBuddySession      = "workbuddy.session"
	SourceTinyAPISession        = "tinyapi.session"
	SourceParallelSession       = "parallel.session"
	SourceClaudePlatformSession = "claude_platform.session"
)

// sessionSecrets is the secret list of every pasted-session source.
var sessionSecrets = []SecretSpec{{Key: SecretSession, Required: true}}

func init() {
	addSources(
		SourceDef{
			ID: SourceXAPIUsage, Provider: "x_api", Kind: KindOfficialAPI, Order: 20,
			Secrets: []SecretSpec{{Key: SecretKey, Required: true}}, Hosts: []string{"api.x.com"},
			MinInterval: 30 * time.Minute, DocURL: "https://docs.x.com/x-api/usage/get-usage",
		},
		SourceDef{
			ID: SourceXAPISession, Provider: "x_api", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Params: []ParamSpec{{Key: "account_id", Required: true}},
			Hosts: []string{"console.x.com"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceStepFunSession, Provider: "stepfun", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Hosts: []string{"platform.stepfun.com"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceHelmcodeSession, Provider: "helmcode", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets,
			Params:  []ParamSpec{{Key: "tenant", Choices: []string{"helmcode_cloud", "nan_builders"}}},
			Hosts:   []string{"cloud-api.helmcode.com", "cloud-api.nan.builders"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceLongCatSession, Provider: "longcat", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Hosts: []string{"longcat.chat"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceNotionSession, Provider: "notion_ai", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Params: []ParamSpec{{Key: "workspace_id", Required: true}},
			Hosts: []string{"app.notion.com"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceReplicateSession, Provider: "replicate", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets,
			Params: []ParamSpec{
				{Key: "account_name", Required: true},
				{Key: "account_type", Choices: []string{"user", "organization"}},
			},
			Hosts: []string{"replicate.com"}, MinInterval: 15 * time.Minute,
		},
		SourceDef{
			ID: SourceRaycastSession, Provider: "raycast", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Hosts: []string{"www.raycast.com"}, MinInterval: 15 * time.Minute,
		},
		SourceDef{
			ID: SourceLithosAISession, Provider: "lithosai", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Params: []ParamSpec{{Key: "org_id", Required: true}},
			Hosts: []string{"console.lithosai.cloud"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceWorkBuddySession, Provider: "workbuddy", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Params: []ParamSpec{{Key: "user_agent", Required: true}},
			Hosts: []string{"www.workbuddy.cn"}, MinInterval: 15 * time.Minute,
		},
		SourceDef{
			ID: SourceTinyAPISession, Provider: "tinyapi", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Hosts: []string{"tinyapi.rest"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceParallelSession, Provider: "parallel", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Hosts: []string{"platform.parallel.ai"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceClaudePlatformSession, Provider: "claude_platform", Kind: KindBrowser, Order: 60,
			Secrets: sessionSecrets, Params: []ParamSpec{{Key: "org_id", Required: true}},
			Hosts: []string{"platform.claude.com"}, MinInterval: 10 * time.Minute,
		},
	)
	register(SourceXAPIUsage, Driver{Plan: planXAPIUsage, Parse: parseXAPIUsage})
	register(SourceXAPISession, Driver{Plan: planXAPISession, Parse: parseXAPISession})
	register(SourceStepFunSession, Driver{Plan: planStepFun, Parse: parseStepFun})
	register(SourceHelmcodeSession, Driver{Plan: planHelmcode, Parse: parseHelmcode})
	register(SourceLongCatSession, Driver{Plan: planLongCat, Parse: parseLongCat})
	register(SourceNotionSession, Driver{Plan: planNotion, Parse: parseNotion})
	register(SourceReplicateSession, Driver{Plan: planReplicate, Parse: parseReplicate})
	register(SourceRaycastSession, Driver{Plan: planRaycast, Parse: parseRaycast})
	register(SourceLithosAISession, Driver{Plan: planLithosAI, Parse: parseLithosAI})
	register(SourceWorkBuddySession, Driver{Plan: planWorkBuddy, Parse: parseWorkBuddy})
	register(SourceTinyAPISession, Driver{Plan: planTinyAPI, Parse: parseTinyAPI})
	register(SourceParallelSession, Driver{Plan: planParallel, Parse: parseParallel})
	register(SourceClaudePlatformSession, Driver{Plan: planClaudePlatform, Parse: parseClaudePlatform})
}

// --- shared helpers -----------------------------------------------------------

// cookieValue returns the value of cookie name in a Cookie header value, ""
// when absent.
func cookieValue(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.TrimSpace(k) == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// keepCookies keeps only the named cookies of a header value, in order.
func keepCookies(header string, names ...string) string {
	var out []string
	for _, part := range strings.Split(header, ";") {
		k, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		for _, n := range names {
			if strings.TrimSpace(k) == n {
				out = append(out, strings.TrimSpace(part))
			}
		}
	}
	return strings.Join(out, "; ")
}

// pastedCookie reads the pasted session as a Cookie header value. A bare
// value with no "=" is taken as the vendor's session cookie named bare.
// Missing is ErrAuth.
func pastedCookie(in PlanInput, bare string) (string, error) {
	raw, err := secret(in, SecretSession)
	if err != nil {
		return "", err
	}
	c := SessionCookie(raw)
	if bare != "" && !strings.Contains(c, "=") {
		c = bare + "=" + c
	}
	if c == "" {
		return "", fmt.Errorf("%w: session empty", ErrAuth)
	}
	return c, nil
}

// requireCookies fails with ErrAuth when a named cookie is missing.
func requireCookies(header string, names ...string) error {
	for _, n := range names {
		if cookieValue(header, n) == "" {
			return fmt.Errorf("%w: the pasted session has no %s cookie", ErrAuth, n)
		}
	}
	return nil
}

// webHeaders are the plain headers a console request carries.
func webHeaders(origin, referer string) map[string]string {
	h := map[string]string{"Accept": "application/json"}
	if origin != "" {
		h["Origin"] = origin
	}
	if referer != "" {
		h["Referer"] = referer
	}
	return h
}

// jsonPost marks a header map as carrying a JSON body.
func jsonPost(h map[string]string) map[string]string {
	h["Content-Type"] = "application/json"
	return h
}

// sessionBody returns a session request's body. A 2xx answer that is an
// HTML page is a console's sign-in page: the session is gone, not a shape
// change.
func sessionBody(in ParseInput, key string) ([]byte, error) {
	b, err := need(in, key)
	if err != nil {
		return nil, err
	}
	if t := strings.TrimSpace(string(b)); strings.HasPrefix(t, "<") {
		return nil, fmt.Errorf("%w: sign-in page instead of data", ErrAuth)
	}
	return b, nil
}

// optionalJ parses an optional response; ok=false when it failed or is not JSON.
func optionalJ(in ParseInput, key string) (J, bool) {
	r, ok := in.Responses[key]
	if !ok || httpErr(r, true) != nil {
		return J{}, false
	}
	j, err := ParseJ(r.Body)
	return j, err == nil
}

// safeID matches the vendor ids lane C2 places in a URL path.
var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// pathID validates an id typed by the user before it reaches a URL path.
func pathID(v, what string) (string, error) {
	v = strings.TrimSpace(v)
	if !safeID.MatchString(v) {
		return "", fmt.Errorf("planlimits: invalid %s", what)
	}
	return v, nil
}

// roundCount rounds a count to an integer balance amount.
func roundCount(f float64) int64 { return int64(math.Round(f)) }

// --- X API: documented usage endpoint (rung 1) ----------------------------------

func planXAPIUsage(in PlanInput) ([]Request, error) {
	return keyedGET("https://api.x.com/2/usage/tweets?usage.fields=cap_reset_day,project_cap,project_usage",
		SecretKey, AuthBearer, "", nil)(in)
}

// nextMonthDay returns the next instant at or after now when day of month d
// (clamped to the month's length) begins, in UTC.
func nextMonthDay(now time.Time, d int) time.Time {
	now = now.UTC()
	at := func(y int, m time.Month) time.Time {
		last := time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
		return time.Date(y, m, min(d, last), 0, 0, 0, 0, time.UTC)
	}
	t := at(now.Year(), now.Month())
	if !t.After(now) {
		t = at(now.Year(), now.Month()+1)
	}
	return t
}

// ParseXAPIUsage maps GET /2/usage/tweets. The cap counts posts, a unit the
// card has no word for, so the window is a percent of the monthly cap.
func ParseXAPIUsage(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	d := j.At("data")
	capV, okCap := d.At("project_cap").Num()
	used, okUsed := d.At("project_usage").Num()
	if !okCap || !okUsed || capV < 0 || used < 0 {
		return Snapshot{}, shapeErr("x api usage: project cap or usage", nil)
	}
	s := newSnap("x_api", SourceXAPIUsage, KindOfficialAPI, ConfExact, now)
	if capV == 0 {
		s.Status = StatusUnmetered
		return s, nil
	}
	w := Window{Key: "monthly", Unit: UnitPercent, UsedFrac: F(min(used/capV, 2))}
	if day, ok := d.At("cap_reset_day").Num(); ok && day >= 1 && day <= 31 {
		r := nextMonthDay(now, int(day))
		w.ResetsAt = &r
	}
	s.Windows = []Window{w}
	if used >= capV {
		s.Status = StatusThrottled
	}
	return s, nil
}

func parseXAPIUsage(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseXAPIUsage(body, in.Now)
}

// --- X API: developer console session (rung 3) ----------------------------------

func planXAPISession(in PlanInput) ([]Request, error) {
	c, err := pastedCookie(in, "")
	if err != nil {
		return nil, err
	}
	if err := requireCookies(c, "auth_token", "ct0"); err != nil {
		return nil, err
	}
	id, err := pathID(in.Params["account_id"], "X API account id")
	if err != nil {
		return nil, err
	}
	return []Request{{
		Key: "credits", Kind: ReqHTTP, Method: "GET", URL: "https://console.x.com/api/accounts/" + id + "/credits",
		Header:        webHeaders("", ""),
		SecretHeaders: map[string]string{"Cookie": c, "X-CSRF-Token": cookieValue(c, "ct0")},
	}}, nil
}

// xConsoleSessionErr reports the console's "session expired" answer: HTTP
// 400 with error code 215.
func xConsoleSessionErr(r Response) bool {
	if r.Status != 400 {
		return false
	}
	j, err := ParseJ(r.Body)
	if err != nil {
		return false
	}
	for _, e := range j.At("errors").Arr() {
		if c, ok := e.At("code").Num(); ok && c == 215 {
			return true
		}
	}
	return false
}

// ParseXAPICredits maps the console credits body. Both balances are plain
// dollars; a negative balance keeps its sign.
func ParseXAPICredits(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	paid, ok := j.At("credits.balance").Micros(0)
	if !ok {
		return Snapshot{}, shapeErr("x api credits balance", nil)
	}
	s := newSnap("x_api", SourceXAPISession, KindBrowser, ConfExact, now)
	total := paid
	s.Balances = []Balance{{Kind: "cash", Unit: UnitUSDMicros, Amount: paid}}
	if fc := j.At("freeCredits"); fc.Exists() {
		free, ok := fc.At("balance").Micros(0)
		if !ok {
			return Snapshot{}, shapeErr("x api free credits balance", nil)
		}
		total += free
		s.Balances = append(s.Balances, Balance{Kind: "granted", Unit: UnitUSDMicros, Amount: free})
	}
	s.Balances = append([]Balance{{Kind: "prepaid", Unit: UnitUSDMicros, Amount: total}}, s.Balances...)
	s.PlanCode = "prepaid"
	if total <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

func parseXAPISession(in ParseInput) (Snapshot, error) {
	if r, ok := in.Responses["credits"]; ok && xConsoleSessionErr(r) {
		return Snapshot{}, fmt.Errorf("%w: console session expired", ErrAuth)
	}
	body, err := sessionBody(in, "credits")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseXAPICredits(body, in.Now)
}

// --- StepFun (pasted Oasis token) --------------------------------------------------

const stepfunBase = "https://platform.stepfun.com/api/step.openapi.devcenter.Dashboard/"

// stepfunToken reads the pasted Oasis token: a bare token, or a Cookie
// header carrying Oasis-Token.
func stepfunToken(raw string) string {
	c := SessionCookie(raw)
	if v := cookieValue(c, "Oasis-Token"); v != "" {
		return v
	}
	return SessionBearer(raw)
}

// StepFunWebID returns the device id StepFun binds a token to: the
// device_id claim of the token's JWT payload (the refresh half of an
// "access...refresh" pair first). The claim is only read, never verified;
// StepFun authenticates the token. "" when no claim is found.
func StepFunWebID(token string) string {
	halves := strings.Split(token, "...")
	for i := len(halves) - 1; i >= 0; i-- {
		parts := strings.Split(halves[i], ".")
		if len(parts) < 2 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
		if err != nil {
			continue
		}
		var claims struct {
			DeviceID string `json:"device_id"`
		}
		if json.Unmarshal(raw, &claims) == nil && claims.DeviceID != "" && !strings.ContainsAny(claims.DeviceID, ";\r\n") {
			return claims.DeviceID
		}
	}
	return ""
}

func planStepFun(in PlanInput) ([]Request, error) {
	raw, err := secret(in, SecretSession)
	if err != nil {
		return nil, err
	}
	tok := stepfunToken(raw)
	if tok == "" {
		return nil, fmt.Errorf("%w: StepFun token empty", ErrAuth)
	}
	sec := map[string]string{"Cookie": "Oasis-Token=" + tok}
	if web := StepFunWebID(tok); web != "" {
		sec["Cookie"] += "; Oasis-Webid=" + web
		sec["oasis-webid"] = web
	}
	h := func() map[string]string {
		return jsonPost(map[string]string{"Accept": "application/json", "oasis-appid": "10300", "oasis-platform": "web"})
	}
	return []Request{
		{Key: "limits", Kind: ReqHTTP, Method: "POST", URL: stepfunBase + "QueryStepPlanRateLimit", Header: h(), SecretHeaders: sec, Body: []byte("{}")},
		{Key: "plan", Kind: ReqHTTP, Method: "POST", URL: stepfunBase + "GetStepPlanStatus", Header: h(), SecretHeaders: sec, Body: []byte("{}"), Optional: true},
	}, nil
}

// stepfunLeftWindow builds a percent window from a "left" fraction (0..1).
func stepfunLeftWindow(key string, left float64, reset *time.Time, length time.Duration) Window {
	w := PercentWindow(key, min(max((1-left)*100, 0), 200), reset, length)
	w.Rolling = length > 0
	return w
}

// ParseStepFunRateLimit maps QueryStepPlanRateLimit. A Coding Plan carries
// live 5-hour and weekly windows ("left" fractions); a Token Plan carries a
// credit pool instead and its window fields come back as zero, which means
// "no window", never "used up".
func ParseStepFunRateLimit(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	st, ok := j.At("status").Num()
	if !ok {
		return Snapshot{}, shapeErr("stepfun: status", nil)
	}
	if st != 1 {
		msg, _ := j.First("message", "desc").Str()
		if strings.Contains(strings.ToLower(msg), "auth") || strings.Contains(strings.ToLower(msg), "token") {
			return Snapshot{}, fmt.Errorf("%w: stepfun refused the token", ErrAuth)
		}
		return Snapshot{}, shapeErr("stepfun: status not ok", nil)
	}
	s := newSnap("stepfun", SourceStepFunSession, KindBrowser, ConfExact, now)
	reset := func(v J) *time.Time { return v.Time() }
	r5, rw := reset(j.At("five_hour_usage_reset_time")), reset(j.At("weekly_usage_reset_time"))
	credit := j.At("plan_credit_rate_limit")
	subLeft, hasSub := credit.At("subscription_credit_left_rate").Num()
	topLeft, hasTop := credit.At("topup_credit_left_rate").Num()
	buckets := credit.At("credit_buckets").Arr()
	family, _ := j.At("plan_family").Num()
	creditPlan := r5 == nil && rw == nil && (hasSub || hasTop || len(buckets) > 0 || family == 2)
	if !creditPlan {
		l5, ok5 := j.At("five_hour_usage_left_rate").Num()
		lw, okw := j.At("weekly_usage_left_rate").Num()
		if !ok5 || !okw {
			return Snapshot{}, shapeErr("stepfun: window rates", nil)
		}
		s.PlanCode = "coding_plan"
		s.Windows = []Window{
			stepfunLeftWindow("5h", l5, r5, 5*time.Hour),
			stepfunLeftWindow("weekly", lw, rw, 7*24*time.Hour),
		}
		return s, nil
	}
	s.PlanCode = "token_plan"
	creditReset := reset(credit.At("subscription_credit_reset_time"))
	var total, residual float64
	valid := len(buckets) > 0
	for _, b := range buckets {
		t, okT := b.At("credit_total").Num()
		r, okR := b.At("credit_residual").Num()
		if !okT || !okR || t <= 0 || r < 0 || r > t {
			valid = false
			break
		}
		total, residual = total+t, residual+r
	}
	switch {
	case valid:
		w, _ := AmountWindow("credits", UnitCredits, nil, F(total), F(residual), creditReset, 0)
		s.Windows = []Window{w}
	case hasSub:
		s.Windows = []Window{stepfunLeftWindow("credits", subLeft, creditReset, 0)}
	case hasTop:
		s.Windows = []Window{stepfunLeftWindow("credits", topLeft, creditReset, 0)}
	default:
		s.Status = StatusPlanOnly // a credit plan with no balance reported yet
	}
	return s, nil
}

func parseStepFun(in ParseInput) (Snapshot, error) {
	body, err := need(in, "limits")
	if err != nil {
		return Snapshot{}, err
	}
	s, err := ParseStepFunRateLimit(body, in.Now)
	if err != nil {
		return s, err
	}
	if p, ok := optionalJ(in, "plan"); ok {
		if name, ok := p.At("subscription.name").Str(); ok {
			s.PlanLabel = SanitizeLabel(name)
		}
	}
	return s, nil
}

// --- Helmcode (pasted dashboard session) ---------------------------------------------

// helmcodeTenants binds the tenant parameter to the tenant's API and site.
var helmcodeTenants = map[string]struct {
	api, site string
	credits   bool // only Helmcode Cloud has a prepaid balance
}{
	"":               {"cloud-api.helmcode.com", "cloud.helmcode.com", true},
	"helmcode_cloud": {"cloud-api.helmcode.com", "cloud.helmcode.com", true},
	"nan_builders":   {"cloud-api.nan.builders", "cloud.nan.builders", false},
}

func planHelmcode(in PlanInput) ([]Request, error) {
	t, ok := helmcodeTenants[in.Params["tenant"]]
	if !ok {
		return nil, fmt.Errorf("planlimits: helmcode tenant %q", in.Params["tenant"])
	}
	c, err := pastedCookie(in, "")
	if err != nil {
		return nil, err
	}
	sec := map[string]string{"Cookie": c}
	h := webHeaders("https://"+t.site, "https://"+t.site+"/dashboard")
	base := "https://" + t.api + "/api/"
	reqs := []Request{
		{Key: "quota", Kind: ReqHTTP, Method: "GET", URL: base + "usage/quota", Header: h, SecretHeaders: sec},
		{Key: "billing", Kind: ReqHTTP, Method: "GET", URL: base + "billing", Header: h, SecretHeaders: sec, Optional: true},
	}
	if t.credits {
		reqs = append(reqs, Request{Key: "credits", Kind: ReqHTTP, Method: "GET", URL: base + "billing/credits", Header: h, SecretHeaders: sec, Optional: true})
	}
	return reqs, nil
}

// helmcodeModelKey turns a model name into a window key segment.
func helmcodeModelKey(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(SanitizeLabel(name)) {
		if r == ':' || r == ' ' {
			r = '_'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ParseHelmcodeQuota maps /api/usage/quota (and the optional billing and
// credits bodies, nil when absent). Each model with a positive cap is a
// token window: a rolling tier keyed by its declared hours, the rest by the
// billing month. Rolling tiers only count when billing says premium.
func ParseHelmcodeQuota(quota []byte, billing, credits *J, now time.Time) (Snapshot, error) {
	j, err := ParseJ(quota)
	if err != nil {
		return Snapshot{}, err
	}
	start, okStart := j.At("periodStart").Str()
	models := j.At("models").Arr()
	if !okStart || models == nil {
		return Snapshot{}, shapeErr("helmcode quota: periodStart or models", nil)
	}
	premium := false
	if billing != nil {
		premium, _ = billing.At("subscription.premium").Bool()
	}
	var fallback *time.Time
	if t := (J{start}).Time(); t != nil {
		f := time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
		fallback = &f
	}
	s := newSnap("helmcode", SourceHelmcodeSession, KindBrowser, ConfExact, now)
	seen := map[string]bool{}
	for _, m := range models {
		name, ok := m.At("model").Str()
		capV, okCap := m.At("cap").Num()
		used, okUsed := m.At("tokensUsed").Num()
		if !ok || SanitizeLabel(name) == "" || !okCap || !okUsed || capV < 0 || used < 0 {
			return Snapshot{}, shapeErr("helmcode quota: model row", nil)
		}
		if capV <= 0 {
			continue // an unlimited model: no invented percentage
		}
		reset := m.At("periodEnd").Time()
		if reset == nil {
			reset = fallback
		}
		key := "monthly:" + helmcodeModelKey(name)
		var length time.Duration
		if hrs, ok := m.At("windowHours").Num(); ok {
			if !premium {
				continue
			}
			if hrs < 1 || hrs > 8760 {
				return Snapshot{}, shapeErr("helmcode quota: windowHours", nil)
			}
			length = time.Duration(hrs) * time.Hour
			key = fmt.Sprintf("%dh:%s", int(hrs), helmcodeModelKey(name))
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		w, _ := AmountWindow(key, UnitTokens, F(used), F(capV), m.At("remaining").NumP(), reset, length)
		w.Rolling = length > 0
		s.Windows = append(s.Windows, w)
	}
	if credits != nil {
		cur, ok := credits.At("currency").Str()
		if !ok {
			cur = "EUR" // the dashboard's default when the field is omitted
		}
		if unit := CurrencyUnit(cur); unit != "" {
			if m, ok := credits.At("balanceMicros").Num(); ok && m == math.Trunc(m) {
				s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: unit, Amount: int64(m)})
			}
		}
	}
	if len(s.Windows)+len(s.Balances) == 0 {
		s.Status = StatusUnmetered
	}
	return s, nil
}

func parseHelmcode(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "quota")
	if err != nil {
		return Snapshot{}, err
	}
	var billing, credits *J
	if b, ok := optionalJ(in, "billing"); ok {
		billing = &b
	}
	if c, ok := optionalJ(in, "credits"); ok {
		credits = &c
	}
	return ParseHelmcodeQuota(body, billing, credits, in.Now)
}

// --- LongCat (pasted session) ------------------------------------------------------

func planLongCat(in PlanInput) ([]Request, error) {
	c, err := pastedCookie(in, "")
	if err != nil {
		return nil, err
	}
	sec := map[string]string{"Cookie": c}
	h := func() map[string]string {
		return webHeaders("https://longcat.chat", "https://longcat.chat/platform/usage")
	}
	const base = "https://longcat.chat"
	return []Request{
		{Key: "user", Kind: ReqHTTP, Method: "GET", URL: base + "/api/v1/user-current", Header: h(), SecretHeaders: sec},
		{Key: "summary", Kind: ReqHTTP, Method: "POST", URL: base + "/api/pay/quota/metering/token-packs/summary", Header: jsonPost(h()), SecretHeaders: sec, Body: []byte("{}"), Optional: true},
		{Key: "usage", Kind: ReqHTTP, Method: "GET", URL: base + "/api/lc-platform/v1/tokenUsage", Header: h(), SecretHeaders: sec, Optional: true},
		{Key: "fuel", Kind: ReqHTTP, Method: "GET", URL: base + "/api/lc-platform/v1/pending-fuel-packages", Header: h(), SecretHeaders: sec, Optional: true},
	}, nil
}

// longcatData unwraps LongCat's {code, data} envelope. Codes 401/403 are a
// refused session; any other code but 0/200 is a shape error.
func longcatData(body []byte) (J, error) {
	j, err := ParseJ(body)
	if err != nil {
		return J{}, err
	}
	if c := j.At("code"); c.Exists() {
		code, ok := c.Num()
		switch {
		case !ok:
			return J{}, shapeErr("longcat: code", nil)
		case code == 401 || code == 403:
			return J{}, fmt.Errorf("%w: longcat code %v", ErrAuth, code)
		case code != 0 && code != 200:
			return J{}, shapeErr(fmt.Sprintf("longcat: code %v", code), nil)
		}
	}
	if d := j.At("data"); d.Exists() {
		return d, nil
	}
	return j, nil
}

// ParseLongCat maps the LongCat answers: the active token pack is the
// primary quota (the legacy tokenUsage aggregate can report stale zeros, so
// it is only the fallback), pending fuel packs a second window.
func ParseLongCat(user []byte, summary, usage, fuel *J, now time.Time) (Snapshot, error) {
	if _, err := longcatData(user); err != nil {
		return Snapshot{}, err
	}
	s := newSnap("longcat", SourceLongCatSession, KindBrowser, ConfExact, now)
	var total float64
	var used *float64
	lot := J{}
	if summary != nil {
		lot = summary.At("currentLot")
	}
	st, _ := lot.At("status").Str()
	if t, ok := lot.At("totalToken").Num(); strings.EqualFold(st, "ACTIVE") && ok && t > 0 {
		total, used = t, lot.At("consumedToken").NumP()
	} else {
		if usage == nil {
			return Snapshot{}, shapeErr("longcat: no active token pack and no token usage", nil)
		}
		u := usage.At("usage")
		if !u.Exists() {
			u = *usage
		}
		t, ok := u.At("totalToken").Num()
		if !ok {
			return Snapshot{}, shapeErr("longcat: totalToken", nil)
		}
		total, used = t, u.At("usedToken").NumP()
		if used == nil {
			if a, ok := u.At("availableToken").Num(); ok {
				used = F(t - a)
			}
		}
	}
	if total > 0 {
		if w, ok := AmountWindow("quota", UnitTokens, used, F(total), nil, nil, 0); ok {
			s.Windows = append(s.Windows, w)
		}
	}
	if fuel != nil {
		if ft, ok := fuel.At("totalQuota").Num(); ok && ft > 0 {
			var left float64
			saw := false
			var reset *time.Time
			for _, p := range fuel.At("list").Arr() {
				if a, ok := p.At("availableToken").Num(); ok {
					left += a
					saw = true
				}
				if t := p.At("expireTime").Time(); t != nil && (reset == nil || t.Before(*reset)) {
					reset = t
				}
			}
			var rem *float64
			if saw {
				rem = F(left)
			}
			if w, ok := AmountWindow("fuel_pack", UnitTokens, nil, F(ft), rem, reset, 0); ok && rem != nil {
				s.Windows = append(s.Windows, w)
			}
		}
	}
	if len(s.Windows) == 0 {
		s.Status = StatusPlanOnly
	}
	return s, nil
}

func parseLongCat(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "user")
	if err != nil {
		return Snapshot{}, err
	}
	opt := func(k string) *J {
		r, ok := in.Responses[k]
		if !ok || httpErr(r, true) != nil {
			return nil
		}
		d, err := longcatData(r.Body)
		if err != nil {
			return nil
		}
		return &d
	}
	return ParseLongCat(body, opt("summary"), opt("usage"), opt("fuel"), in.Now)
}

// --- Notion AI (pasted session) -------------------------------------------------------

var notionUUID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// NotionWorkspaceID normalises a workspace id (dashed or undashed UUID) to
// the dashed form Notion expects; ok=false when it is not a UUID.
func NotionWorkspaceID(v string) (string, bool) {
	v = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(v), "-", ""))
	if !notionUUID.MatchString(v) {
		return "", false
	}
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:], true
}

func planNotion(in PlanInput) ([]Request, error) {
	c, err := pastedCookie(in, "token_v2")
	if err != nil {
		return nil, err
	}
	if err := requireCookies(c, "token_v2"); err != nil {
		return nil, err
	}
	id, ok := NotionWorkspaceID(in.Params["workspace_id"])
	if !ok {
		return nil, errors.New("planlimits: invalid Notion workspace id")
	}
	body, _ := json.Marshal(map[string]string{"spaceId": id})
	return []Request{{
		Key: "main", Kind: ReqHTTP, Method: "POST", URL: "https://app.notion.com/api/v3/getCreditRateLimitStatus",
		Header: jsonPost(webHeaders("https://app.notion.com", "https://app.notion.com/")), Body: body,
		SecretHeaders: map[string]string{"Cookie": c},
	}}, nil
}

var (
	notionWindowToken = regexp.MustCompile(`^([1-9][0-9]*)([mhdw])$`)
	notionUnitMinutes = map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}
)

// ParseNotionAllowance maps getCreditRateLimitStatus: the rolling window
// keyed by its declared length ("6h") and the billing-period window as
// monthly. Amounts are AI credits against the reported limit.
func ParseNotionAllowance(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if st, _ := j.At("status").Str(); strings.EqualFold(st, "not_applicable") {
		return Snapshot{}, fmt.Errorf("%w: Notion AI allowances apply to Business and Enterprise workspaces", ErrNotApplicable)
	}
	rw, bw := j.At("window"), j.At("billingPeriodWindow")
	if !rw.Exists() && !bw.Exists() {
		return Snapshot{}, shapeErr("notion: no usage windows", nil)
	}
	s := newSnap("notion_ai", SourceNotionSession, KindBrowser, ConfExact, now)
	add := func(v J, key string, reset *time.Time, length time.Duration, rolling bool) error {
		if !v.Exists() {
			return nil
		}
		used, okU := v.At("used").Num()
		lim, okL := v.At("limit").Num()
		if !okU || !okL {
			return shapeErr("notion: window used or limit", nil)
		}
		if lim <= 0 {
			return nil
		}
		w, _ := AmountWindow(key, UnitCredits, F(used), F(lim), nil, reset, length)
		w.Rolling = rolling
		s.Windows = append(s.Windows, w)
		if used >= lim {
			s.Status = StatusThrottled
		}
		return nil
	}
	if rw.Exists() {
		key, length := "rolling", time.Duration(0)
		tok, _ := rw.At("window").Str()
		if m := notionWindowToken.FindStringSubmatch(strings.ToLower(strings.TrimSpace(tok))); m != nil {
			key = m[0]
			if n, err := strconv.Atoi(m[1]); err == nil {
				length = time.Duration(n) * notionUnitMinutes[m[2]]
			}
		}
		var reset *time.Time
		if sec, ok := j.At("resetsInSeconds").Num(); ok && sec >= 0 {
			t := now.UTC().Add(time.Duration(sec) * time.Second)
			reset = &t
		}
		if err := add(rw, key, reset, length, true); err != nil {
			return Snapshot{}, err
		}
	}
	if err := add(bw, "monthly", bw.At("periodEndMs").Time(), 0, false); err != nil {
		return Snapshot{}, err
	}
	if len(s.Windows) == 0 {
		s.Status = StatusUnmetered
	}
	return s, nil
}

func parseNotion(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseNotionAllowance(body, in.Now)
}

// --- Replicate (pasted session) ---------------------------------------------------------

var replicateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

// replicateKinds binds the account type parameter to the API path segment.
var replicateKinds = map[string]string{"": "users", "user": "users", "organization": "organizations"}

func planReplicate(in PlanInput) ([]Request, error) {
	kind, ok := replicateKinds[in.Params["account_type"]]
	if !ok {
		return nil, fmt.Errorf("planlimits: replicate account type %q", in.Params["account_type"])
	}
	name := strings.TrimSpace(in.Params["account_name"])
	if !replicateName.MatchString(name) || strings.Contains(name, "..") {
		return nil, errors.New("planlimits: invalid Replicate account name")
	}
	c, err := pastedCookie(in, "sessionid")
	if err != nil {
		return nil, err
	}
	if err := requireCookies(c, "sessionid"); err != nil {
		return nil, err
	}
	base := "https://replicate.com/api/" + kind + "/" + url.PathEscape(name)
	h := webHeaders("", "")
	sec := map[string]string{"Cookie": c}
	return []Request{
		{Key: "invoices", Kind: ReqHTTP, Method: "GET", URL: base + "/invoices", Header: h, SecretHeaders: sec},
		{Key: "credit", Kind: ReqHTTP, Method: "GET", URL: base + "/unused-credit", Header: h, SecretHeaders: sec, Optional: true},
	}, nil
}

// ParseReplicateBilling maps the invoices list (the open monthly-usage
// invoice is this month's spend) and the optional unused credit (nil when
// absent). Spend is required; a missing number is never zero.
func ParseReplicateBilling(invoices []byte, credit *J, now time.Time) (Snapshot, error) {
	j, err := ParseJ(invoices)
	if err != nil {
		return Snapshot{}, err
	}
	list := j.At("invoices").Arr()
	if list == nil {
		return Snapshot{}, shapeErr("replicate: invoices", nil)
	}
	var current *J
	for i := range list {
		inv := list[i]
		if t, _ := inv.At("type").Str(); t != "monthly-usage" {
			continue
		}
		end := inv.At("ended_before")
		if !end.Exists() {
			current = &list[i]
			break
		}
		if t := end.Time(); t != nil && t.After(now) {
			current = &list[i]
			break
		}
	}
	if current == nil {
		return Snapshot{}, shapeErr("replicate: no open monthly-usage invoice", nil)
	}
	spent, ok := current.At("total_cost_before_adjustments").Micros(0)
	if !ok || spent < 0 {
		return Snapshot{}, shapeErr("replicate: total_cost_before_adjustments", nil)
	}
	s := newSnap("replicate", SourceReplicateSession, KindBrowser, ConfExact, now)
	s.Spend = []Spend{{Period: "month", Unit: UnitUSDMicros, Amount: spent, Scope: "account"}}
	if credit != nil {
		if b, ok := credit.At("unused_credit").Micros(0); ok && b >= 0 {
			s.Balances = []Balance{{Kind: "prepaid", Unit: UnitUSDMicros, Amount: b}}
		}
	}
	return s, nil
}

func parseReplicate(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "invoices")
	if err != nil {
		return Snapshot{}, err
	}
	var credit *J
	if c, ok := optionalJ(in, "credit"); ok {
		credit = &c
	}
	return ParseReplicateBilling(body, credit, in.Now)
}

// --- Raycast (pasted website session) -------------------------------------------------

func planRaycast(in PlanInput) ([]Request, error) {
	c, err := pastedCookie(in, "__raycast_session")
	if err != nil {
		return nil, err
	}
	// Only the website session and its CSRF cookie travel; sibling-host
	// cookies in a pasted header are dropped.
	c = keepCookies(c, "__raycast_session", "csrf_token")
	if err := requireCookies(c, "__raycast_session"); err != nil {
		return nil, err
	}
	return []Request{{
		Key: "main", Kind: ReqHTTP, Method: "GET", URL: "https://www.raycast.com/frontend_api/current_user/ai_credits",
		Header:        webHeaders("https://www.raycast.com", "https://www.raycast.com/settings"),
		SecretHeaders: map[string]string{"Cookie": c},
	}}, nil
}

// raycastTiers names the funding tiers Raycast reports.
var raycastTiers = map[string]string{"pro": "Pro", "pro_plus": "Pro+", "max": "Max"}

// ParseRaycastCredits maps the website AI credits body: credits left of the
// monthly allowance, renewing at next_credits_at. Rollover can leave more
// than the grant, which reads as nothing used.
func ParseRaycastCredits(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	rem := j.At("remaining_balance_credits").NumP()
	tot := j.At("total_balance_credits").NumP()
	if (rem == nil && tot == nil) || (rem != nil && *rem < 0) || (tot != nil && *tot < 0) {
		return Snapshot{}, shapeErr("raycast: credit amounts", nil)
	}
	s := newSnap("raycast", SourceRaycastSession, KindBrowser, ConfExact, now)
	if tier, ok := j.At("funding_subscription.tier").Str(); ok && tier != "" {
		s.PlanCode = SanitizeLabel(tier)
		s.PlanLabel = raycastTiers[tier]
		if s.PlanLabel == "" {
			s.PlanLabel = SanitizeLabel(tier)
		}
	}
	renew := j.At("next_credits_at").Time()
	switch {
	case rem != nil && tot != nil && *tot > 0:
		used := max(*tot-*rem, 0)
		w, _ := AmountWindow("monthly", UnitCredits, &used, tot, rem, renew, 0)
		s.Windows = []Window{w}
		if *rem <= 0 {
			s.Status = StatusThrottled
		}
	case rem != nil:
		s.Balances = []Balance{{Kind: "credits", Unit: UnitCredits, Amount: roundCount(*rem)}}
	default:
		s.Status = StatusPlanOnly // only a total, nothing left reported
	}
	return s, nil
}

func parseRaycast(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseRaycastCredits(body, in.Now)
}

// --- LithosAI (pasted console session) --------------------------------------------------

func planLithosAI(in PlanInput) ([]Request, error) {
	c, err := pastedCookie(in, "")
	if err != nil {
		return nil, err
	}
	if err := requireCookies(c, "__Host-console_session", "__Host-console_csrf"); err != nil {
		return nil, err
	}
	org, err := pathID(in.Params["org_id"], "LithosAI organization id")
	if err != nil {
		return nil, err
	}
	sec := map[string]string{"Cookie": c, "X-Console-Csrf": cookieValue(c, "__Host-console_csrf")}
	h := func() map[string]string {
		m := webHeaders("", "")
		m["X-Organization-Id"] = org
		return m
	}
	end := in.Now.UTC().Format("2006-01-02")
	q := url.Values{"start": {end[:8] + "01"}, "end": {end}}
	const base = "https://console.lithosai.cloud/api/billing"
	return []Request{
		{Key: "billing", Kind: ReqHTTP, Method: "GET", URL: base, Header: h(), SecretHeaders: sec},
		{Key: "spend", Kind: ReqHTTP, Method: "GET", URL: base + "/spend?" + q.Encode(), Header: h(), SecretHeaders: sec, Optional: true},
	}, nil
}

// nanosToMicros converts LithosAI's integer nanos (1 USD = 1e9) to micros.
func nanosToMicros(n float64) int64 { return int64(math.Round(n / 1000)) }

// ParseLithosAIBilling maps /api/billing (balanceNanos, onHold) and the
// optional month-to-date spend report (nil when absent or malformed: the
// balance stays).
func ParseLithosAIBilling(billing []byte, spend *J, now time.Time) (Snapshot, error) {
	j, err := ParseJ(billing)
	if err != nil {
		return Snapshot{}, err
	}
	bal, ok := j.At("balanceNanos").Num()
	if !ok || bal != math.Trunc(bal) {
		return Snapshot{}, shapeErr("lithosai: balanceNanos", nil)
	}
	s := newSnap("lithosai", SourceLithosAISession, KindBrowser, ConfExact, now)
	s.PlanCode = "prepaid"
	s.Balances = []Balance{{Kind: "prepaid", Unit: UnitUSDMicros, Amount: nanosToMicros(bal)}}
	if hold, _ := j.At("onHold").Bool(); hold {
		s.Status = StatusThrottled
	}
	if spend != nil {
		days := spend.At("days").Arr()
		today := now.UTC().Format("2006-01-02")
		var month, day float64
		good := days != nil
		for _, d := range days {
			n, okN := d.At("nanos").Num()
			ds, okD := d.At("day").Str()
			if !okN || !okD || n < 0 {
				good = false
				break
			}
			month += n
			if ds == today {
				day += n
			}
		}
		if good {
			s.Spend = []Spend{
				{Period: "month", Unit: UnitUSDMicros, Amount: nanosToMicros(month), Scope: "account"},
				{Period: "day", Unit: UnitUSDMicros, Amount: nanosToMicros(day), Scope: "account"},
			}
		}
	}
	return s, nil
}

func parseLithosAI(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "billing")
	if err != nil {
		return Snapshot{}, err
	}
	var spend *J
	if sp, ok := optionalJ(in, "spend"); ok {
		spend = &sp
	}
	return ParseLithosAIBilling(body, spend, in.Now)
}

// --- WorkBuddy (pasted website session + its browser's user agent) ------------------------

// maxUserAgent caps the pasted user agent.
const maxUserAgent = 512

// WorkBuddyUserAgent cleans the pasted browser user agent. WorkBuddy binds a
// session to the browser that signed in, so the cookies only work with that
// browser's exact user agent. ok=false when it does not look like one.
func WorkBuddyUserAgent(v string) (string, bool) {
	v = cleanPaste(v)
	if i := strings.Index(strings.ToLower(v), "user-agent:"); i >= 0 {
		v = strings.TrimSpace(v[i+len("user-agent:"):])
	}
	if !strings.HasPrefix(v, "Mozilla/") || len(v) > maxUserAgent {
		return "", false
	}
	return v, true
}

func planWorkBuddy(in PlanInput) ([]Request, error) {
	c, err := pastedCookie(in, "")
	if err != nil {
		return nil, err
	}
	ua, ok := WorkBuddyUserAgent(in.Params["user_agent"])
	if !ok {
		return nil, errors.New("planlimits: WorkBuddy needs the browser's user agent")
	}
	h := jsonPost(webHeaders("https://www.workbuddy.cn", "https://www.workbuddy.cn/profile/plans-usage"))
	h["User-Agent"] = ua
	return []Request{{
		Key: "main", Kind: ReqHTTP, Method: "POST", URL: "https://www.workbuddy.cn/billing/meter/get-user-resource-summary",
		Header: h, Body: []byte("{}"), SecretHeaders: map[string]string{"Cookie": c},
	}}, nil
}

// ParseWorkBuddySummary maps get-user-resource-summary: the credits
// packages of this cycle, summed (other capacity units are skipped).
func ParseWorkBuddySummary(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if code, ok := j.At("code").Num(); !ok || code != 0 {
		return Snapshot{}, shapeErr("workbuddy: code", nil)
	}
	pkgs := j.At("data.Packages").Arr()
	if pkgs == nil {
		return Snapshot{}, shapeErr("workbuddy: Packages", nil)
	}
	var total, left float64
	for _, p := range pkgs {
		if u, _ := p.At("CapacityUnit").Str(); u != "credits" {
			continue
		}
		t, okT := p.At("CycleTotalCapacity").Num()
		r, okR := p.At("CycleRemainCapacity").Num()
		if !okT || !okR || t < 0 || r < 0 {
			return Snapshot{}, shapeErr("workbuddy: package capacity", nil)
		}
		total, left = total+t, left+r
	}
	s := newSnap("workbuddy", SourceWorkBuddySession, KindBrowser, ConfExact, now)
	if name, ok := j.At("data.SubscriptionPackageName").Str(); ok {
		s.PlanLabel = SanitizeLabel(name)
	}
	if total > 0 {
		used := max(total-left, 0)
		w, _ := AmountWindow("cycle", UnitCredits, &used, F(total), F(left), nil, 0)
		s.Windows = []Window{w}
		if left <= 0 {
			s.Status = StatusThrottled
		}
		return s, nil
	}
	s.Balances = []Balance{{Kind: "credits", Unit: UnitCredits, Amount: roundCount(left)}}
	return s, nil
}

func parseWorkBuddy(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseWorkBuddySummary(body, in.Now)
}

// --- TinyApi (pasted session) -------------------------------------------------------------

func planTinyAPI(in PlanInput) ([]Request, error) {
	c, err := pastedCookie(in, "")
	if err != nil {
		return nil, err
	}
	return []Request{{
		Key: "main", Kind: ReqHTTP, Method: "GET", URL: "https://tinyapi.rest/api/user/credits",
		Header: webHeaders("", ""), SecretHeaders: map[string]string{"Cookie": c},
	}}, nil
}

// ParseTinyAPICredits maps /api/user/credits: one aggregate credit balance.
// No allowance, split or reset is inferred.
func ParseTinyAPICredits(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	okFlag, _ := j.At("success").Bool()
	bal, ok := j.At("data.totalAvailable").Num()
	if !okFlag || !ok || bal < 0 {
		return Snapshot{}, shapeErr("tinyapi: totalAvailable", nil)
	}
	s := newSnap("tinyapi", SourceTinyAPISession, KindBrowser, ConfExact, now)
	s.Balances = []Balance{{Kind: "credits", Unit: UnitCredits, Amount: roundCount(bal)}}
	if bal <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

func parseTinyAPI(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseTinyAPICredits(body, in.Now)
}

// --- Parallel (pasted platform session) ------------------------------------------------------

func planParallel(in PlanInput) ([]Request, error) {
	c, err := pastedCookie(in, "")
	if err != nil {
		return nil, err
	}
	return []Request{{
		Key: "main", Kind: ReqHTTP, Method: "POST", URL: "https://platform.parallel.ai/api/rpc/billing/payments/refresh-balance",
		Header: jsonPost(webHeaders("https://platform.parallel.ai", "")), Body: []byte("{}"),
		SecretHeaders: map[string]string{"Cookie": c},
	}}, nil
}

// ParseParallelBalance maps the dashboard balance RPC: {"kind":"ok",
// "data":{"balance": cents}}. Anything else is a shape change, never zero.
func ParseParallelBalance(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	kind, _ := j.At("kind").Str()
	cents, ok := j.At("data.balance").Micros(2)
	if kind != "ok" || !ok {
		return Snapshot{}, shapeErr("parallel: balance", nil)
	}
	s := newSnap("parallel", SourceParallelSession, KindBrowser, ConfExact, now)
	s.PlanCode = "prepaid"
	s.Balances = []Balance{{Kind: "prepaid", Unit: UnitUSDMicros, Amount: cents}}
	if cents <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

func parseParallel(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseParallelBalance(body, in.Now)
}

// --- Claude Platform (pasted Console session) ------------------------------------------------

var claudeOrgID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func planClaudePlatform(in PlanInput) ([]Request, error) {
	c, err := pastedCookie(in, "sessionKey")
	if err != nil {
		return nil, err
	}
	if err := requireCookies(c, "sessionKey"); err != nil {
		return nil, err
	}
	org := strings.TrimSpace(in.Params["org_id"])
	if !claudeOrgID.MatchString(org) {
		return nil, errors.New("planlimits: invalid Claude Console organization id")
	}
	base := "https://platform.claude.com/api/organizations/" + org
	h := webHeaders("", "")
	sec := map[string]string{"Cookie": c}
	return []Request{
		{Key: "credits", Kind: ReqHTTP, Method: "GET", URL: base + "/prepaid/credits", Header: h, SecretHeaders: sec},
		{Key: "spend", Kind: ReqHTTP, Method: "GET", URL: base + "/current_spend", Header: h, SecretHeaders: sec, Optional: true},
	}, nil
}

// claudeGrant is one Console credit grant.
type claudeGrant struct {
	program            string
	purchased          bool
	granted, remaining int64
	expires            *time.Time
}

// claudeGrants reads the unexpired grants with a positive amount: promo
// tranches (subscription or promotional credit) and purchased tranches.
func claudeGrants(j J, minor func(J) (int64, bool), now time.Time) ([]claudeGrant, error) {
	var grants []claudeGrant
	for _, f := range []struct {
		field     string
		purchased bool
	}{{"promo_tranches", false}, {"tranches", true}} {
		for _, t := range j.At(f.field).Arr() {
			g, okG := minor(t.At("granted_amount_minor_units"))
			r, okR := minor(t.At("remaining_amount_minor_units"))
			if !okG || !okR {
				return nil, shapeErr("claude platform: credit grant", nil)
			}
			ex := t.At("expires_at").Time()
			if g <= 0 || (ex != nil && !ex.After(now)) {
				continue
			}
			prog, _ := t.At("program_id").Str()
			grants = append(grants, claudeGrant{program: prog, purchased: f.purchased, granted: g, remaining: max(r, 0), expires: ex})
		}
	}
	return grants, nil
}

// claudeGrantLanes picks the grants worth a window: the soonest-expiring
// subscription credit and the soonest-expiring purchased credit that still
// have credit left (the ones about to be lost).
var claudeGrantLanes = []struct {
	key   string
	match func(claudeGrant) bool
}{
	{"grant:subscription", func(g claudeGrant) bool { return g.program == "subscription_api_credit" && g.remaining > 0 }},
	{"grant:purchased", func(g claudeGrant) bool { return g.purchased && g.remaining > 0 }},
}

// claudeGrantWindows builds one money window per grant lane.
func claudeGrantWindows(grants []claudeGrant, unit Unit) []Window {
	var out []Window
	for _, l := range claudeGrantLanes {
		var best *claudeGrant
		for i := range grants {
			g := grants[i]
			if l.match(g) && (best == nil || (g.expires != nil && (best.expires == nil || g.expires.Before(*best.expires)))) {
				best = &grants[i]
			}
		}
		if best == nil {
			continue
		}
		used := float64(best.granted - min(best.remaining, best.granted))
		w, _ := AmountWindow(l.key, unit, &used, F(float64(best.granted)), F(float64(best.remaining)), nil, 0)
		out = append(out, w)
	}
	return out
}

// ParseClaudePlatformCredits maps /prepaid/credits and the optional
// /current_spend body (nil when absent). The prepaid balance left leads;
// month-to-date spend is the used figure. Amounts are minor units divided by
// 10^exponent (default 2). Credit grants expire rather than reset, so their
// windows carry no reset time.
func ParseClaudePlatformCredits(credits []byte, spend *J, now time.Time) (Snapshot, error) {
	j, err := ParseJ(credits)
	if err != nil {
		return Snapshot{}, err
	}
	cur := "USD"
	if c, ok := j.At("currency").Str(); ok {
		cur = c
	}
	unit := CurrencyUnit(cur)
	if unit == "" {
		return Snapshot{}, shapeErr("claude platform: currency "+cur, nil)
	}
	exp := 2
	if e := j.At("balance.credits.exponent"); e.Exists() {
		f, ok := e.Num()
		if !ok || f != math.Trunc(f) || f < 0 || f > 4 {
			return Snapshot{}, shapeErr("claude platform: exponent", nil)
		}
		exp = int(f)
	}
	minor := func(v J) (int64, bool) {
		f, ok := v.Num()
		if !ok || f != math.Trunc(f) {
			return 0, false
		}
		return v.Micros(exp)
	}
	amount, ok := minor(j.At("amount"))
	if !ok {
		return Snapshot{}, shapeErr("claude platform: amount", nil)
	}
	s := newSnap("claude_platform", SourceClaudePlatformSession, KindBrowser, ConfExact, now)
	s.PlanCode = "prepaid"
	s.Balances = []Balance{{Kind: "prepaid", Unit: unit, Amount: amount}}
	grants, err := claudeGrants(j, minor, now)
	if err != nil {
		return Snapshot{}, err
	}
	s.Windows = claudeGrantWindows(grants, unit)
	if spend != nil {
		if a, ok := minor(spend.At("amount")); ok && a >= 0 {
			s.Spend = []Spend{{Period: "month", Unit: unit, Amount: a, Scope: "account"}}
		}
	}
	if amount <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

func parseClaudePlatform(in ParseInput) (Snapshot, error) {
	body, err := sessionBody(in, "credits")
	if err != nil {
		return Snapshot{}, err
	}
	var spend *J
	if sp, ok := optionalJ(in, "spend"); ok {
		spend = &sp
	}
	return ParseClaudePlatformCredits(body, spend, in.Now)
}
