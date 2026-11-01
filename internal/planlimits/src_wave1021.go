package planlimits

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// src_wave1021.go holds the sources for the 2026-10-21 capture wave
// (docs/adapter-parity.md AP-134): Autohand, Kimchi and Stakpak, plus the
// Cortex Code catalogue row. None of these vendors documents its plan or
// credit endpoint, so every live source here is rung 2 (experimental,
// per-provider opt-in). Endpoints, headers and field names were grounded on
// 2026-10-23 from each vendor's own installed client:
//
//   - Autohand: autohand-cli 0.9.8 dist (AuthClient.fetchEntitlement,
//     parseAccountQuota, src/billing/planSummary.ts). GET
//     https://api.autohand.ai/v1/auth/me with the CLI's own session token as
//     "Authorization: Bearer" AND "Cookie: auth_session=" (the CLI sends
//     both). The token lives in ~/.autohand/config.json auth.token with an
//     auth.expiresAt; an "ahc_" token is durable (never expires locally).
//   - Kimchi: kimchi 1.17.0 binary (src/extensions/billing/status.ts:
//     refreshBillingStatus / refreshBudgetStatus / parseCreditsPayload /
//     parseBudgetPayload). GET <llm host>/v1/credits and /v1/budget with
//     "Authorization: Bearer <apiKey>"; a 404 on /v1/budget means no budget.
//     The key lives in ~/.config/kimchi/config.json apiKey (or api_key) on
//     every OS, with region us|eu.
//   - Stakpak: stakpak 0.3.88 binary strings (StakpakApiClient::get_billing,
//     stakpak_shared::models::billing::{BillingResponse, Feature, Product,
//     CreditSchema}) cross-read against the vendor's public source
//     (libs/api/src/stakpak/client.rs: format!("{}/v2/{}/billing",
//     base_url, username); tui side_panel reads features["credits"].balance
//     as dollars and the plan from the first active product). Base URL
//     https://apiv2.stakpak.dev, "Authorization: Bearer <api key>".
//
// Cortex Code (cortex 1.2.18) has no source: its subscription quota
// (usage.subscription_quota_used_percent and usage.limits[] on the
// inference stream) is kept only in process memory, its stats/usage.json
// holds tokens only ("Tokens, not billed credits"), and the per-user daily
// credit limit is a Snowflake account parameter readable only with Snowflake
// credentials (gap cloud_creds_only).
//
// The borrowed sources follow the nous_portal.hermes precedent exactly: the
// vendor file is read read-only by internal/planlimitslocal, only the token
// field is projected, any stored base URL is ignored (the host is fixed),
// an expired token is ErrAuth and never refreshed, and the token only ever
// rides in Request.SecretHeaders to that vendor's own host.

// Wave provider ids.
const (
	ProviderAutohand   = "autohand"
	ProviderKimchi     = "kimchi"
	ProviderStakpak    = "stakpak"
	ProviderCortexCode = "cortex_code"
)

// Wave source ids.
const (
	SourceAutohandAccount = "autohand.account" // Autohand CLI's own sign-in, read-only
	SourceAutohandAPI     = "autohand.api"     // a pasted Autohand token
	SourceKimchiConfig    = "kimchi.config"    // Kimchi's own saved key, read-only
	SourceKimchiAPI       = "kimchi.api"       // a pasted Kimchi key
	SourceStakpakAPI      = "stakpak.api"      // a pasted Stakpak key and the account username
)

// Vendor hosts and paths, grounded from the clients named above.
const (
	autohandMeURL     = "https://api.autohand.ai/v1/auth/me"
	autohandHost      = "api.autohand.ai"
	stakpakHost       = "apiv2.stakpak.dev"
	kimchiCreditsPath = "/v1/credits"
	kimchiBudgetPath  = "/v1/budget"
)

// kimchiRegionHosts maps a Kimchi region (its config "region" value) to its
// LLM gateway host. "self-hosted" has no fixed host and is not served.
var kimchiRegionHosts = map[string]string{"us": "llm.kimchi.dev", "eu": "llm.eu.kimchi.dev"}

// kimchiRegion is the region picker for a pasted Kimchi key.
var kimchiRegion = ParamSpec{Key: "region", Choices: []string{"us", "eu"}}

func init() {
	addSources(
		SourceDef{
			ID: SourceAutohandAccount, Provider: ProviderAutohand, Kind: KindBorrowedToken, Order: 50,
			Hosts: []string{autohandHost}, MinInterval: 10 * time.Minute,
			Local: []LocalSpec{{Key: "config", Kind: LocalFile, Base: BaseHome, Rel: ".autohand/config.json"}},
		},
		SourceDef{
			ID: SourceAutohandAPI, Provider: ProviderAutohand, Kind: KindUndocumented, Order: 55,
			Secrets: []SecretSpec{{Key: SecretKey, Required: true}},
			Hosts:   []string{autohandHost}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceKimchiConfig, Provider: ProviderKimchi, Kind: KindBorrowedToken, Order: 50,
			Hosts: []string{"llm.kimchi.dev", "llm.eu.kimchi.dev"}, MinInterval: 10 * time.Minute,
			Local: []LocalSpec{{Key: "config", Kind: LocalFile, Base: BaseHome, Rel: ".config/kimchi/config.json"}},
		},
		SourceDef{
			ID: SourceKimchiAPI, Provider: ProviderKimchi, Kind: KindUndocumented, Order: 55,
			Secrets: []SecretSpec{{Key: SecretKey, Required: true}}, Params: []ParamSpec{kimchiRegion},
			Hosts: []string{"llm.kimchi.dev", "llm.eu.kimchi.dev"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceStakpakAPI, Provider: ProviderStakpak, Kind: KindUndocumented, Order: 50,
			Secrets: []SecretSpec{{Key: SecretKey, Required: true}},
			Params:  []ParamSpec{{Key: "account_username", Required: true}},
			Hosts:   []string{stakpakHost}, MinInterval: 15 * time.Minute,
		},
	)
	register(SourceAutohandAccount, Driver{Plan: planAutohandAccount, Parse: parseAutohand(SourceAutohandAccount, KindBorrowedToken)})
	register(SourceAutohandAPI, Driver{Plan: planAutohandAPI, Parse: parseAutohand(SourceAutohandAPI, KindUndocumented)})
	register(SourceKimchiConfig, Driver{Plan: planKimchiConfig, Parse: parseKimchi(SourceKimchiConfig, KindBorrowedToken)})
	register(SourceKimchiAPI, Driver{Plan: planKimchiAPI, Parse: parseKimchi(SourceKimchiAPI, KindUndocumented)})
	register(SourceStakpakAPI, Driver{Plan: planStakpak, Parse: parseStakpak})
}

// vendorTokenRe matches a token or key that may ride in a header: printable,
// no whitespace, no separator that could start a second header or cookie.
var vendorTokenRe = regexp.MustCompile(`^[A-Za-z0-9._~+/=:-]{8,}$`)

// maxVendorToken caps a token or key read from a vendor file or a paste.
const maxVendorToken = 4096

// validVendorToken reports whether s may ride in a credential header.
func validVendorToken(s string) bool { return len(s) <= maxVendorToken && vendorTokenRe.MatchString(s) }

// --- Autohand -------------------------------------------------------------------

// autohandDurablePrefix marks a durable Autohand credential: the CLI never
// expires it locally (src/auth/credentialType.ts isDurableAuthCredential).
const autohandDurablePrefix = "ahc_"

// autohandAuth is the projection of ~/.autohand/config.json the call needs.
type autohandAuth struct {
	token     string
	expiresAt *time.Time
}

// parseAutohandConfig reads auth.token and auth.expiresAt only. Every other
// field of the file (providers, hooks, keys) is never read.
func parseAutohandConfig(body []byte) (autohandAuth, error) {
	j, err := ParseJ(body)
	if err != nil {
		return autohandAuth{}, fmt.Errorf("%w: Autohand config not usable", ErrAuth)
	}
	tok, _ := j.At("auth.token").Str()
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return autohandAuth{}, fmt.Errorf("%w: Autohand is not signed in", ErrAuth)
	}
	return autohandAuth{token: tok, expiresAt: j.At("auth.expiresAt").Time()}, nil
}

// autohandRequest is the one /me call, carrying the token the way the CLI
// does (bearer and the auth_session cookie).
func autohandRequest(tok string) ([]Request, error) {
	if !validVendorToken(tok) {
		return nil, fmt.Errorf("%w: Autohand token not usable", ErrAuth)
	}
	return []Request{{
		Key: "me", Kind: ReqHTTP, Method: "GET", URL: autohandMeURL,
		Header:        map[string]string{"Accept": "application/json"},
		SecretHeaders: map[string]string{"Authorization": "Bearer " + tok, "Cookie": "auth_session=" + tok},
	}}, nil
}

func planAutohandAccount(in PlanInput) ([]Request, error) {
	b, err := localBytes(in.Local, "config")
	if err != nil {
		return nil, err
	}
	a, err := parseAutohandConfig(b)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(a.token, autohandDurablePrefix) && a.expiresAt != nil && !in.Now.Add(60*time.Second).Before(*a.expiresAt) {
		return nil, fmt.Errorf("%w: token expired; run autohand login", ErrAuth)
	}
	return autohandRequest(a.token)
}

func planAutohandAPI(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	return autohandRequest(SessionBearer(k))
}

// autohandWindows maps the entitlement quota windows onto window keys,
// classified by the window's documented name, never by position.
var autohandWindows = []struct {
	field, key string
	length     time.Duration
}{
	{"window5h", "5h", 5 * time.Hour},
	{"window24h", "daily", 24 * time.Hour},
	{"week", "weekly", 7 * 24 * time.Hour},
	{"month", "monthly", 30 * 24 * time.Hour},
}

// ParseAutohandMe maps GET /v1/auth/me. The plan is entitlement.tier; the
// quota windows count messages (used, remaining, limit, resetAt); a free
// account may carry freeRemaining, the free grant left. A null window is
// absent, never zero.
func ParseAutohandMe(body []byte, source string, kind SourceKind, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	ent := j.At("entitlement")
	tier, ok := ent.At("tier").Str()
	if !ok || strings.TrimSpace(tier) == "" {
		return Snapshot{}, shapeErr("autohand me: no entitlement tier", nil)
	}
	s := newSnap(ProviderAutohand, source, kind, ConfExact, now)
	s.PlanCode = SanitizeLabel(strings.ToLower(tier))
	if l, ok := ent.At("limits.displayName").Str(); ok {
		s.PlanLabel = SanitizeLabel(l)
	}
	q := ent.At("quota")
	for _, w := range autohandWindows {
		v := q.At(w.field)
		if !v.Exists() {
			continue
		}
		used := v.At("used").NumP()
		if used == nil {
			return Snapshot{}, shapeErr("autohand me: quota window without used", nil)
		}
		if nw, ok := AmountWindow(w.key, UnitRequests, used, v.At("limit").NumP(), v.At("remaining").NumP(), v.At("resetAt").Time(), w.length); ok {
			nw.Rolling = w.key == "5h" || w.key == "daily"
			s.Windows = append(s.Windows, nw)
		}
	}
	if f, ok := ent.At("freeRemaining").Num(); ok {
		s.Balances = append(s.Balances, Balance{Kind: "available", Unit: UnitRequests, Amount: roundCount(f)})
	}
	if avail, ok := q.At("available").Bool(); ok && !avail && len(s.Windows)+len(s.Balances) == 0 {
		s.Status = StatusPlanOnly
		return s, nil
	}
	for _, w := range s.Windows {
		if w.Remaining != nil && *w.Remaining <= 0 && w.Limit != nil && *w.Limit > 0 {
			s.Status = StatusThrottled
		}
	}
	if len(s.Windows)+len(s.Balances) == 0 {
		s.Status = StatusPlanOnly // the tier is known; the account reports no meter
	}
	return s, nil
}

func parseAutohand(source string, kind SourceKind) func(ParseInput) (Snapshot, error) {
	return func(in ParseInput) (Snapshot, error) {
		body, err := need(in, "me")
		if err != nil {
			return Snapshot{}, err
		}
		return ParseAutohandMe(body, source, kind, in.Now)
	}
}

// --- Kimchi -----------------------------------------------------------------------

// kimchiConf is the projection of ~/.config/kimchi/config.json the call
// needs. A stored llmEndpoint or selfHostedUrl is never read: the host comes
// from the region table only.
type kimchiConf struct {
	key, region string
}

func parseKimchiConfig(body []byte) (kimchiConf, error) {
	j, err := ParseJ(body)
	if err != nil {
		return kimchiConf{}, fmt.Errorf("%w: Kimchi config not usable", ErrAuth)
	}
	k, _ := j.First("apiKey", "api_key").Str()
	k = strings.TrimSpace(k)
	if k == "" {
		return kimchiConf{}, fmt.Errorf("%w: Kimchi has no saved key; run kimchi setup", ErrAuth)
	}
	r, _ := j.At("region").Str()
	return kimchiConf{key: k, region: strings.ToLower(strings.TrimSpace(r))}, nil
}

// kimchiRequests plans the credits call and the optional budget call.
func kimchiRequests(key, region string) ([]Request, error) {
	if region == "" {
		region = "us" // the client's DEFAULT_REGION
	}
	host, ok := kimchiRegionHosts[region]
	if !ok {
		return nil, fmt.Errorf("%w: Kimchi region %q has no fixed host", ErrNotApplicable, SanitizeLabel(region))
	}
	if !validVendorToken(key) {
		return nil, fmt.Errorf("%w: Kimchi key not usable", ErrAuth)
	}
	h := map[string]string{"Accept": "application/json"}
	return []Request{
		{Key: "credits", Kind: ReqHTTP, Method: "GET", URL: "https://" + host + kimchiCreditsPath, Header: h, SecretHeaders: bearer(key)},
		{Key: "budget", Kind: ReqHTTP, Method: "GET", URL: "https://" + host + kimchiBudgetPath, Header: h, SecretHeaders: bearer(key), Optional: true},
	}, nil
}

func planKimchiConfig(in PlanInput) ([]Request, error) {
	b, err := localBytes(in.Local, "config")
	if err != nil {
		return nil, err
	}
	c, err := parseKimchiConfig(b)
	if err != nil {
		return nil, err
	}
	return kimchiRequests(c.key, c.region)
}

func planKimchiAPI(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	return kimchiRequests(SessionBearer(k), strings.ToLower(strings.TrimSpace(in.Params["region"])))
}

// kimchiPlanTable normalises a Kimchi tier the way its client does
// (parsePlan), first match wins: exact names, then prefixes.
var kimchiPlanTable = []struct {
	exact  []string
	prefix string
	code   string
}{
	{[]string{"community", "free", "free-tier", "free-slow"}, "", "community"},
	{[]string{"starter", "coder", "individual"}, "coder-", "coder"},
	{[]string{"team", "teams"}, "teams-", "teams"},
	{[]string{"enterprise"}, "enterprise-", "enterprise"},
}

// kimchiKey normalises a vendor key the way the client does.
func kimchiKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("_", "-", " ", "-", "\t", "-").Replace(s)
}

// KimchiPlanCode maps a Kimchi tier string to a plan code; "" when unknown.
func KimchiPlanCode(tier string) string {
	t := kimchiKey(tier)
	for _, r := range kimchiPlanTable {
		for _, e := range r.exact {
			if t == e {
				return r.code
			}
		}
		if r.prefix != "" && strings.HasPrefix(t, r.prefix) {
			return r.code
		}
	}
	return ""
}

// kimchiExhausted lists the billing_status values the client reads as out
// of credits (parseCreditStatus).
var kimchiExhausted = map[string]bool{"exhausted": true, "depleted": true, "empty": true, "out": true, "out-of-credits": true, "no-credits": true}

// kimchiCreditFields are the keys whose presence marks a credits snapshot
// (the client's TIER/IS_PAID_TIER/BILLING_STATUS/HAS_CREDITS field lists).
var kimchiCreditFields = []string{
	"serverless", "tier", "tier_name", "tierName", "is_paid_tier", "isPaidTier",
	"billing_status", "billingStatus", "has_credits", "hasCredits", "remaining",
}

// kimchiAmount reads the credits amount: a number, or a dollar string such
// as "$12.34", "12.34 USD" or "12,34".
func kimchiAmount(v J) (int64, bool) {
	if f, ok := v.Num(); ok {
		if f < 0 {
			return 0, false
		}
		return microsFromFloat(f), true
	}
	s, ok := v.Str()
	if !ok {
		return 0, false
	}
	s = strings.Join(strings.Fields(strings.ToLower(s)), "")
	s = strings.NewReplacer("$", "", "usd", "").Replace(s)
	s = strings.Replace(s, ",", ".", 1)
	m, err := MicrosFromDecimal(s, 0)
	if err != nil || m < 0 {
		return 0, false
	}
	return m, true
}

// kimchiCredits is what the credits body says.
type kimchiCredits struct {
	notServerless bool
	planCode      string
	planLabel     string
	remaining     *int64
	exhausted     bool
}

// parseKimchiCreditsBody maps GET /v1/credits. A body with none of the
// client's credit fields is a shape error.
func parseKimchiCreditsBody(body []byte) (kimchiCredits, error) {
	j, err := ParseJ(body)
	if err != nil {
		return kimchiCredits{}, err
	}
	known := false
	for _, f := range kimchiCreditFields {
		if j.At(f).Exists() {
			known = true
			break
		}
	}
	if !known {
		return kimchiCredits{}, shapeErr("kimchi credits: no credit fields", nil)
	}
	var c kimchiCredits
	if sv, ok := j.At("serverless").Bool(); ok && !sv {
		c.notServerless = true
		return c, nil
	}
	if t, ok := j.First("tier", "tier_name", "tierName").Str(); ok {
		c.planLabel = SanitizeLabel(t)
		c.planCode = KimchiPlanCode(t)
	}
	if m, ok := kimchiAmount(j.At("remaining")); ok {
		c.remaining = &m
	}
	if st, ok := j.First("billing_status", "billingStatus").Str(); ok {
		c.exhausted = kimchiExhausted[strings.TrimPrefix(kimchiKey(st), "billing-status-")]
	}
	if hc, ok := j.First("has_credits", "hasCredits").Bool(); ok && !hc {
		c.exhausted = true // the client's restricted (rate-limited) mode
	}
	return c, nil
}

// kimchiSoftScopes are the budget scopes the client never treats as
// exhausted at 100% (a soft organization budget only warns).
var kimchiSoftScopes = map[string]bool{"ORGANIZATION_SOFT": true}

// kimchiBudgetScopes are the scopes the client accepts (isBudgetScope).
var kimchiBudgetScopes = map[string]bool{
	"API_KEY": true, "USER": true, "TEAM_PER_USER": true, "TEAM_POOLED": true, "ORGANIZATION_SOFT": true, "ORGANIZATION_HARD": true,
}

// kimchiBudgetWindows maps GET /v1/budget onto one dollar window per capped
// budget. An uncapped budget (limit "" or 0) has no window. throttled
// reports a hard budget at or over its limit.
func kimchiBudgetWindows(body []byte) (ws []Window, throttled bool, err error) {
	j, err := ParseJ(body)
	if err != nil {
		return nil, false, err
	}
	start, okS := j.At("period.startTime").Str()
	end, okE := j.At("period.endTime").Str()
	if !okS || !okE {
		return nil, false, shapeErr("kimchi budget: no period", nil)
	}
	st, en := parseISO(start), parseISO(end)
	seen := map[string]bool{}
	for _, b := range j.At("budgets").Arr() {
		scope, _ := b.At("scope").Str()
		if !kimchiBudgetScopes[scope] {
			return nil, false, shapeErr("kimchi budget: unknown scope", nil)
		}
		lim, okL := b.At("budgetLimitUsd").Micros(0)
		spent, okU := b.At("totalSpendUsd").Micros(0)
		if !okU || spent < 0 {
			return nil, false, shapeErr("kimchi budget: no spend", nil)
		}
		if !okL || lim <= 0 {
			continue
		}
		key := "budget:" + slug(scope)
		if seen[key] {
			id, _ := b.At("scopeId").Str()
			if id = slug(id); len(id) > 8 {
				id = id[:8]
			}
			key += ":" + id
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		w := Window{
			Key: key, Unit: UnitUSDMicros, Used: F(float64(spent)), Limit: F(float64(lim)),
			Remaining: F(float64(max(lim-spent, 0))), UsedFrac: F(min(float64(spent)/float64(lim), 2)), ResetsAt: en,
		}
		if st != nil && en != nil && en.After(*st) {
			w.Length = dur(en.Sub(*st))
		}
		ws = append(ws, w)
		if spent >= lim && !kimchiSoftScopes[scope] {
			throttled = true
		}
	}
	return ws, throttled, nil
}

// ParseKimchi maps the credits body and, when present, the budget body.
// Credits are US dollars (the client prints them as "$x.xx" and warns below
// $5). budget may be nil (404: the account has no budget).
func ParseKimchi(credits, budget []byte, source string, kind SourceKind, now time.Time) (Snapshot, error) {
	c, err := parseKimchiCreditsBody(credits)
	if err != nil {
		return Snapshot{}, err
	}
	s := newSnap(ProviderKimchi, source, kind, ConfExact, now)
	s.PlanCode, s.PlanLabel = c.planCode, c.planLabel
	if c.remaining != nil {
		s.Balances = append(s.Balances, Balance{Kind: "credits", Unit: UnitUSDMicros, Amount: *c.remaining})
	}
	if c.exhausted {
		s.Status = StatusThrottled
	}
	if budget != nil {
		ws, throttled, err := kimchiBudgetWindows(budget)
		if err != nil {
			return Snapshot{}, err
		}
		s.Windows = append(s.Windows, ws...)
		if throttled {
			s.Status = StatusThrottled
		}
	}
	if c.notServerless && len(s.Windows) == 0 {
		return Snapshot{}, fmt.Errorf("%w: Kimchi is not using Kimchi inference on this key", ErrNotApplicable)
	}
	if len(s.Windows)+len(s.Balances) == 0 && s.Status == StatusOK {
		if s.PlanCode != "" || s.PlanLabel != "" {
			s.Status = StatusPlanOnly
			return s, nil
		}
		return Snapshot{}, shapeErr("kimchi credits: no readings", nil)
	}
	return s, nil
}

func parseKimchi(source string, kind SourceKind) func(ParseInput) (Snapshot, error) {
	return func(in ParseInput) (Snapshot, error) {
		credits, err := need(in, "credits")
		if err != nil {
			return Snapshot{}, err
		}
		var budget []byte
		if r, ok := in.Responses["budget"]; ok && httpErr(r, true) == nil {
			budget = r.Body
		}
		return ParseKimchi(credits, budget, source, kind, in.Now)
	}
}

// --- Stakpak ----------------------------------------------------------------------

// stakpakUsername matches a Stakpak account username before it reaches the
// URL path.
var stakpakUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func planStakpak(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	k = SessionBearer(k)
	if !validVendorToken(k) {
		return nil, fmt.Errorf("%w: Stakpak key not usable", ErrAuth)
	}
	u := strings.TrimPrefix(strings.TrimSpace(in.Params["account_username"]), "@")
	if !stakpakUsername.MatchString(u) || strings.Contains(u, "..") {
		return nil, errors.New("planlimits: invalid Stakpak username")
	}
	return []Request{{
		Key: "billing", Kind: ReqHTTP, Method: "GET", URL: "https://" + stakpakHost + "/v2/" + url.PathEscape(u) + "/billing",
		Header: map[string]string{"Accept": "application/json"}, SecretHeaders: bearer(k),
	}}, nil
}

// stakpakIntervalKeys maps a feature's reset interval to a window key.
var stakpakIntervalKeys = map[string]string{"day": "daily", "week": "weekly", "month": "monthly"}

// ParseStakpakBilling maps GET /v2/{username}/billing. The plan is the first
// active non-add-on product; the reading is features["credits"]: balance is
// the dollars left (the TUI prints "$x.xx"), and an included grant with its
// usage is a window that resets at next_reset_at.
func ParseStakpakBilling(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if j.At("features").Keys() == nil && j.At("products").Arr() == nil {
		return Snapshot{}, shapeErr("stakpak billing: no features or products", nil)
	}
	s := newSnap(ProviderStakpak, SourceStakpakAPI, KindUndocumented, ConfExact, now)
	for _, p := range j.At("products").Arr() {
		st, _ := p.At("status").Str()
		addOn, _ := p.At("is_add_on").Bool()
		if st != "active" || addOn {
			continue
		}
		if n, ok := p.At("name").Str(); ok {
			s.PlanLabel = SanitizeLabel(n)
		}
		if id, ok := p.At("id").Str(); ok {
			s.PlanCode = SanitizeLabel(strings.ToLower(id))
		}
		break
	}
	f := j.At("features.credits")
	if f.Exists() {
		if m, ok := f.At("balance").Micros(0); ok {
			s.Balances = append(s.Balances, Balance{Kind: "credits", Unit: UnitUSDMicros, Amount: m})
		}
		inc, okI := f.At("included_usage").Micros(0)
		used, okU := f.At("usage").Micros(0)
		if okI && okU && inc > 0 {
			iv, _ := f.At("interval").Str()
			key, ok := stakpakIntervalKeys[strings.ToLower(iv)]
			if !ok {
				key = "cycle"
			}
			s.Windows = append(s.Windows, Window{
				Key: key, Unit: UnitUSDMicros, Used: F(float64(used)), Limit: F(float64(inc)),
				Remaining: F(float64(max(inc-used, 0))), UsedFrac: F(min(max(float64(used)/float64(inc), 0), 2)),
				ResetsAt: f.At("next_reset_at").Time(),
			})
		}
		if unl, ok := f.At("unlimited").Bool(); ok && unl && len(s.Windows)+len(s.Balances) == 0 {
			s.Status = StatusUnmetered
			return s, nil
		}
	}
	if len(s.Windows)+len(s.Balances) == 0 {
		if s.PlanLabel != "" {
			s.Status = StatusPlanOnly
			return s, nil
		}
		return Snapshot{}, shapeErr("stakpak billing: no credits feature", nil)
	}
	return s, nil
}

func parseStakpak(in ParseInput) (Snapshot, error) {
	body, err := need(in, "billing")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseStakpakBilling(body, in.Now)
}
