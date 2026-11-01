package planlimits

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// drv_api.go holds the official-API drivers that use the user's own key
// (rung 1) and the one undocumented own-key endpoint (Kimi Code, rung 2).
// Shapes are from the vendor docs (each SourceDef carries the DocURL), with
// the Phase 0 spike fixtures as the tests.

func init() {
	register(SourceOpenRouter, Driver{Plan: planOpenRouter, Parse: parseOpenRouter})
	register(SourceDeepSeek, Driver{Plan: planSimpleGET("https://api.deepseek.com/user/balance"), Parse: parseDeepSeek})
	register(SourceMoonshot, Driver{Plan: planMoonshot, Parse: parseMoonshot})
	register(SourceKimiCode, Driver{Plan: planSimpleGET("https://api.kimi.com/coding/v1/usages"), Parse: parseKimiCode})
	register(SourceXAI, Driver{Plan: planXAI, Parse: parseXAI})
	register(SourceCopilotBilling, Driver{Plan: planCopilotBilling, Parse: parseCopilotBilling})
}

// secret returns a required secret or ErrAuth.
func secret(in PlanInput, key string) (string, error) {
	v := strings.TrimSpace(in.Secrets[key])
	if v == "" {
		return "", fmt.Errorf("%w: %s missing", ErrAuth, key)
	}
	return v, nil
}

// planSimpleGET is one bearer GET with the "key" secret.
func planSimpleGET(u string) func(PlanInput) ([]Request, error) {
	return func(in PlanInput) ([]Request, error) {
		k, err := secret(in, "key")
		if err != nil {
			return nil, err
		}
		return []Request{{
			Key: "main", Kind: ReqHTTP, Method: "GET", URL: u,
			Header: map[string]string{"Accept": "application/json"}, SecretHeaders: bearer(k),
		}}, nil
	}
}

// --- OpenRouter --------------------------------------------------------------

func planOpenRouter(in PlanInput) ([]Request, error) {
	k, err := secret(in, "key")
	if err != nil {
		return nil, err
	}
	h := map[string]string{"Accept": "application/json"}
	// The account balance (credits) is asked with the key itself first:
	// OpenRouter answers it for a regular key, and the balance left is the
	// number a person cares about (D-681). A management key, when given, is
	// the fallback for a key OpenRouter does not answer credits for.
	reqs := []Request{
		{Key: "key", Kind: ReqHTTP, Method: "GET", URL: "https://openrouter.ai/api/v1/key", Header: h, SecretHeaders: bearer(k)},
		{Key: "credits", Kind: ReqHTTP, Method: "GET", URL: "https://openrouter.ai/api/v1/credits", Header: h, SecretHeaders: bearer(k), Optional: true},
	}
	if m := strings.TrimSpace(in.Secrets["mgmt"]); m != "" {
		reqs = append(reqs, Request{
			Key: "credits_mgmt", Kind: ReqHTTP, Method: "GET", URL: "https://openrouter.ai/api/v1/credits",
			Header: h, SecretHeaders: bearer(m), Optional: true,
		})
	}
	return reqs, nil
}

type orKeyResp struct {
	Data *struct {
		Limit          *float64 `json:"limit"`
		LimitReset     *string  `json:"limit_reset"`
		LimitRemaining *float64 `json:"limit_remaining"`
		Usage          *float64 `json:"usage"`
		UsageDaily     *float64 `json:"usage_daily"`
		UsageWeekly    *float64 `json:"usage_weekly"`
		UsageMonthly   *float64 `json:"usage_monthly"`
		IsFreeTier     *bool    `json:"is_free_tier"`
		FreeDaily      *struct {
			Used      *float64 `json:"used"`
			Limit     *float64 `json:"limit"`
			Remaining *float64 `json:"remaining"`
		} `json:"free_model_daily_requests"`
	} `json:"data"`
}

var resetLength = map[string]time.Duration{"daily": 24 * time.Hour, "weekly": 7 * 24 * time.Hour, "monthly": 30 * 24 * time.Hour}

// ParseOpenRouterKey maps GET /api/v1/key. OpenRouter prices credits 1:1 in
// USD, so amounts are stored as usd_micros.
func ParseOpenRouterKey(body []byte, now time.Time) (Snapshot, error) {
	var r orKeyResp
	if err := json.Unmarshal(body, &r); err != nil || r.Data == nil {
		return Snapshot{}, shapeErr("openrouter key", err)
	}
	d := r.Data
	s := newSnap(ProviderOpenRouter, SourceOpenRouter, KindOfficialAPI, ConfExact, now)
	s.PlanCode = "payg"
	if d.IsFreeTier != nil && *d.IsFreeTier {
		s.PlanCode = "free"
	}
	if d.Limit != nil && *d.Limit > 0 {
		lim := *d.Limit
		w := Window{Key: "key_cap", Unit: UnitUSDMicros, Limit: F(float64(microsFromFloat(lim)))}
		var used float64
		reset := ""
		if d.LimitReset != nil {
			reset = *d.LimitReset
		}
		switch {
		case d.LimitRemaining != nil:
			rem := min(max(*d.LimitRemaining, 0), lim)
			used = lim - rem
			w.Remaining = F(float64(microsFromFloat(rem)))
		case reset == "daily" && d.UsageDaily != nil:
			used = *d.UsageDaily
		case reset == "weekly" && d.UsageWeekly != nil:
			used = *d.UsageWeekly
		case reset == "monthly" && d.UsageMonthly != nil:
			used = *d.UsageMonthly
		case d.Usage != nil:
			used = *d.Usage
		}
		w.Used = F(float64(microsFromFloat(used)))
		w.UsedFrac = F(used / lim)
		if l, ok := resetLength[reset]; ok {
			w.Length = dur(l)
		}
		s.Windows = append(s.Windows, w)
	}
	if fd := d.FreeDaily; fd != nil && fd.Limit != nil && *fd.Limit > 0 && fd.Used != nil {
		s.Windows = append(s.Windows, Window{
			Key: "free_daily_requests", Unit: UnitRequests,
			Used: fd.Used, Limit: fd.Limit, Remaining: fd.Remaining, UsedFrac: F(*fd.Used / *fd.Limit), Length: dur(24 * time.Hour),
		})
	}
	for _, sp := range []struct {
		p string
		v *float64
	}{{"day", d.UsageDaily}, {"week", d.UsageWeekly}, {"month", d.UsageMonthly}, {"all_time", d.Usage}} {
		if sp.v != nil {
			s.Spend = append(s.Spend, Spend{Period: sp.p, Unit: UnitUSDMicros, Amount: microsFromFloat(*sp.v), Scope: "key"})
		}
	}
	return s, nil
}

// ParseOpenRouterCredits maps GET /api/v1/credits. The balance left is
// total_credits - total_usage; both must be present or the read fails.
// "prepaid" is what is left, "purchased" what was bought in total.
func ParseOpenRouterCredits(body []byte) ([]Balance, error) {
	var r struct {
		Data *struct {
			TotalCredits *float64 `json:"total_credits"`
			TotalUsage   *float64 `json:"total_usage"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Data == nil || r.Data.TotalCredits == nil || r.Data.TotalUsage == nil {
		return nil, shapeErr("openrouter credits", err)
	}
	bought := microsFromFloat(*r.Data.TotalCredits)
	used := microsFromFloat(*r.Data.TotalUsage)
	return []Balance{
		{Kind: "prepaid", Unit: UnitUSDMicros, Amount: bought - used},
		{Kind: "purchased", Unit: UnitUSDMicros, Amount: bought},
	}, nil
}

func parseOpenRouter(in ParseInput) (Snapshot, error) {
	body, err := need(in, "key")
	if err != nil {
		return Snapshot{}, err
	}
	s, err := ParseOpenRouterKey(body, in.Now)
	if err != nil {
		return s, err
	}
	for _, k := range []string{"credits", "credits_mgmt"} {
		if r, ok := in.Responses[k]; ok && httpErr(r, true) == nil {
			if b, err := ParseOpenRouterCredits(r.Body); err == nil {
				s.Balances = append(s.Balances, b...)
				break
			}
		}
	}
	return s, nil
}

// --- DeepSeek ----------------------------------------------------------------

// ParseDeepSeekBalance maps GET /user/balance. Each currency entry yields its
// own balances; currencies are never summed.
func ParseDeepSeekBalance(body []byte, now time.Time) (Snapshot, error) {
	var r struct {
		IsAvailable  *bool `json:"is_available"`
		BalanceInfos []struct {
			Currency        string `json:"currency"`
			TotalBalance    string `json:"total_balance"`
			GrantedBalance  string `json:"granted_balance"`
			ToppedUpBalance string `json:"topped_up_balance"`
		} `json:"balance_infos"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.IsAvailable == nil {
		return Snapshot{}, shapeErr("deepseek balance", err)
	}
	s := newSnap(ProviderDeepSeek, SourceDeepSeek, KindOfficialAPI, ConfExact, now)
	s.PlanCode = "payg"
	for _, b := range r.BalanceInfos {
		unit := CurrencyUnit(b.Currency)
		if unit == "" {
			return Snapshot{}, shapeErr("deepseek currency "+b.Currency, nil)
		}
		for _, f := range []struct{ kind, v string }{{"total", b.TotalBalance}, {"granted", b.GrantedBalance}, {"topup", b.ToppedUpBalance}} {
			m, err := MicrosFromDecimal(f.v, 0)
			if err != nil {
				return Snapshot{}, shapeErr("deepseek "+f.kind, err)
			}
			s.Balances = append(s.Balances, Balance{Kind: f.kind, Unit: unit, Amount: m})
		}
	}
	if len(s.Balances) == 0 {
		return Snapshot{}, shapeErr("deepseek: no balances", nil)
	}
	if !*r.IsAvailable {
		s.Status = StatusThrottled // the balance is too low to call the API
	}
	return s, nil
}

func parseDeepSeek(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseDeepSeekBalance(body, in.Now)
}

// --- Moonshot ----------------------------------------------------------------

// moonshotHosts binds the region parameter to a host, and the host decides
// the currency.
var moonshotHosts = map[string]struct {
	host string
	unit Unit
}{
	"":       {"api.moonshot.ai", UnitUSDMicros},
	"global": {"api.moonshot.ai", UnitUSDMicros},
	"china":  {"api.moonshot.cn", UnitCNYMicros},
}

func planMoonshot(in PlanInput) ([]Request, error) {
	h, ok := moonshotHosts[in.Params["region"]]
	if !ok {
		return nil, fmt.Errorf("planlimits: moonshot region %q", in.Params["region"])
	}
	return planSimpleGET("https://" + h.host + "/v1/users/me/balance")(in)
}

// ParseMoonshotBalance maps the documented balance body for a region.
func ParseMoonshotBalance(region string, body []byte, now time.Time) (Snapshot, error) {
	h, ok := moonshotHosts[region]
	if !ok {
		return Snapshot{}, fmt.Errorf("planlimits: moonshot region %q", region)
	}
	var r struct {
		Code   *int  `json:"code"`
		Status *bool `json:"status"`
		Data   *struct {
			Available *float64 `json:"available_balance"`
			Voucher   *float64 `json:"voucher_balance"`
			Cash      *float64 `json:"cash_balance"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Code == nil || *r.Code != 0 || r.Status == nil || !*r.Status ||
		r.Data == nil || r.Data.Available == nil || r.Data.Voucher == nil || r.Data.Cash == nil {
		return Snapshot{}, shapeErr("moonshot balance", err)
	}
	s := newSnap(ProviderMoonshot, SourceMoonshot, KindOfficialAPI, ConfExact, now)
	s.PlanCode = "payg"
	s.Balances = []Balance{
		{Kind: "total", Unit: h.unit, Amount: microsFromFloat(*r.Data.Available)},
		{Kind: "voucher", Unit: h.unit, Amount: microsFromFloat(*r.Data.Voucher)},
		{Kind: "cash", Unit: h.unit, Amount: microsFromFloat(*r.Data.Cash)},
	}
	if *r.Data.Available <= 0 {
		s.Status = StatusThrottled // documented: <= 0 cannot call inference
	}
	return s, nil
}

func parseMoonshot(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseMoonshotBalance(in.Params["region"], body, in.Now)
}

// --- Kimi Code (rung 2: own key, undocumented endpoint) ------------------------

// flexNum accepts a JSON number or a numeric string.
type flexNum struct{ v *float64 }

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexNum) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	f.v = &v
	return nil
}

type kimiCount struct {
	Limit      flexNum `json:"limit"`
	Used       flexNum `json:"used"`
	Remaining  flexNum `json:"remaining"`
	ResetTime  string  `json:"resetTime"`
	ResetAt    string  `json:"resetAt"`
	ResetTime2 string  `json:"reset_time"`
	ResetAt2   string  `json:"reset_at"`
}

func (c kimiCount) reset() *time.Time {
	for _, s := range []string{c.ResetTime, c.ResetAt, c.ResetTime2, c.ResetAt2} {
		if t := parseISO(s); t != nil {
			return t
		}
	}
	return nil
}

// parseISO parses an RFC 3339 time; nil when absent or malformed.
func parseISO(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		t = t.UTC()
		return &t
	}
	return nil
}

var kimiUnitMinutes = map[string]int64{"TIME_UNIT_MINUTE": 1, "TIME_UNIT_HOUR": 60, "TIME_UNIT_DAY": 1440}

// kimiRatioKeys maps the ratio form's keys to window keys, in order.
var kimiRatioKeys = []struct{ in, key string }{{"limit_5h", "5h"}, {"limit_7d", "weekly"}, {"limit_month_total", "monthly"}}

// ParseKimiCodeUsages maps the undocumented Kimi Code usages body (the counts
// form and the ratio form).
func ParseKimiCodeUsages(body []byte, now time.Time) (Snapshot, error) {
	var r struct {
		Usage  *kimiCount `json:"usage"`
		Limits []struct {
			Window struct {
				Duration int64  `json:"duration"`
				TimeUnit string `json:"timeUnit"`
			} `json:"window"`
			Detail kimiCount `json:"detail"`
		} `json:"limits"`
		Usages map[string]struct {
			UsedRatio *float64 `json:"used_ratio"`
			ResetTime string   `json:"reset_time"`
		} `json:"usages"`
		User *struct {
			Membership struct {
				Level string `json:"level"`
			} `json:"membership"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return Snapshot{}, shapeErr("kimi code usages", err)
	}
	s := newSnap(ProviderKimiCode, SourceKimiCode, KindUndocumented, ConfExact, now)
	if r.User != nil {
		s.PlanCode = SanitizeLabel(r.User.Membership.Level)
	}
	for _, k := range kimiRatioKeys {
		if v, ok := r.Usages[k.in]; ok && v.UsedRatio != nil {
			s.Windows = append(s.Windows, Window{
				Key: k.key, Unit: UnitPercent, UsedFrac: v.UsedRatio,
				ResetsAt: parseISO(v.ResetTime), Rolling: k.key != "monthly",
			})
		}
	}
	count := func(key string, d kimiCount, length time.Duration) {
		if _, dup := FindWindow(s, key); dup || d.Limit.v == nil || *d.Limit.v <= 0 {
			return
		}
		used := d.Used.v
		if used == nil && d.Remaining.v != nil {
			used = F(*d.Limit.v - *d.Remaining.v)
		}
		if used == nil {
			return
		}
		w := Window{
			Key: key, Unit: UnitRequests, Used: used, Limit: d.Limit.v, Remaining: d.Remaining.v,
			UsedFrac: F(*used / *d.Limit.v), ResetsAt: d.reset(), Rolling: true,
		}
		if length > 0 {
			w.Length = dur(length)
		}
		s.Windows = append(s.Windows, w)
	}
	for _, l := range r.Limits {
		mins := l.Window.Duration * kimiUnitMinutes[l.Window.TimeUnit]
		count(windowKeyForMinutes(mins), l.Detail, time.Duration(mins)*time.Minute)
	}
	if r.Usage != nil {
		count("weekly", *r.Usage, 7*24*time.Hour)
	}
	if len(s.Windows) == 0 {
		return Snapshot{}, shapeErr("kimi code: no windows", nil)
	}
	return s, nil
}

func parseKimiCode(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseKimiCodeUsages(body, in.Now)
}

// --- xAI Management API ------------------------------------------------------

// XAITeamURL builds a team-scoped URL, refusing ids that could escape the path.
func XAITeamURL(teamID, suffix string) (string, error) {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" || teamID == "." || teamID == ".." || strings.ContainsAny(teamID, "/\\?#%") {
		return "", errors.New("planlimits: invalid xAI team id")
	}
	return "https://management-api.x.ai/v1/billing/teams/" + url.PathEscape(teamID) + suffix, nil
}

func planXAI(in PlanInput) ([]Request, error) {
	m, err := secret(in, "mgmt")
	if err != nil {
		return nil, err
	}
	bal, err := XAITeamURL(in.Params["team_id"], "/prepaid/balance")
	if err != nil {
		return nil, err
	}
	inv, _ := XAITeamURL(in.Params["team_id"], "/postpaid/invoice/preview")
	h := map[string]string{"Accept": "application/json"}
	return []Request{
		{Key: "balance", Kind: ReqHTTP, Method: "GET", URL: bal, Header: h, SecretHeaders: bearer(m)},
		{Key: "invoice", Kind: ReqHTTP, Method: "GET", URL: inv, Header: h, SecretHeaders: bearer(m), Optional: true},
	}, nil
}

type xaiCents struct {
	Val *string `json:"val"`
}

// ParseXAIBalance maps prepaid/balance and returns the money the team HAS in
// USD micros (the ledger is inverted: a purchase is negative).
func ParseXAIBalance(body []byte) (int64, error) {
	var r struct {
		Total *xaiCents `json:"total"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Total == nil || r.Total.Val == nil {
		return 0, shapeErr("xai balance", err)
	}
	m, err := MicrosFromDecimal(*r.Total.Val, 2)
	if err != nil {
		return 0, shapeErr("xai balance", err)
	}
	return -m, nil
}

// XAIInvoice is the subset of the invoice preview the card needs. A missing
// or malformed amount is nil, never zero.
type XAIInvoice struct {
	AmountAfterVatMicros *int64
	SpendingLimitMicros  *int64
	Year, Month          int
}

// ParseXAIInvoicePreview maps postpaid/invoice/preview.
func ParseXAIInvoicePreview(body []byte) (XAIInvoice, error) {
	var r struct {
		CoreInvoice *struct {
			AmountAfterVat *string `json:"amountAfterVat"`
		} `json:"coreInvoice"`
		EffectiveSpendingLimit *string `json:"effectiveSpendingLimit"`
		BillingCycle           *struct {
			Year  int `json:"year"`
			Month int `json:"month"`
		} `json:"billingCycle"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return XAIInvoice{}, shapeErr("xai invoice", err)
	}
	var out XAIInvoice
	if r.CoreInvoice != nil && r.CoreInvoice.AmountAfterVat != nil {
		if m, err := MicrosFromDecimal(*r.CoreInvoice.AmountAfterVat, 2); err == nil {
			out.AmountAfterVatMicros = &m
		}
	}
	if r.EffectiveSpendingLimit != nil {
		if m, err := MicrosFromDecimal(*r.EffectiveSpendingLimit, 2); err == nil {
			out.SpendingLimitMicros = &m
		}
	}
	if r.BillingCycle != nil {
		out.Year, out.Month = r.BillingCycle.Year, r.BillingCycle.Month
	}
	return out, nil
}

// XAISnapshot combines the posted balance and an optional invoice preview.
// With a preview the live remaining is derived, so the snapshot is estimated.
func XAISnapshot(postedMicros int64, inv *XAIInvoice, now time.Time) Snapshot {
	conf := ConfExact
	if inv != nil && inv.AmountAfterVatMicros != nil {
		conf = ConfEstimated
	}
	s := newSnap(ProviderXAI, SourceXAI, KindAdminAPI, conf, now)
	s.PlanCode = "prepaid"
	s.Balances = []Balance{{Kind: "posted", Unit: UnitUSDMicros, Amount: postedMicros}}
	if inv == nil || inv.AmountAfterVatMicros == nil {
		return s
	}
	spent := *inv.AmountAfterVatMicros
	s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: postedMicros - spent})
	s.Spend = append(s.Spend, Spend{Period: "cycle", Unit: UnitUSDMicros, Amount: spent, Scope: "team"})
	if inv.SpendingLimitMicros != nil && *inv.SpendingLimitMicros > 0 {
		used, lim := float64(spent), float64(*inv.SpendingLimitMicros)
		w := Window{Key: "spend_limit", Unit: UnitUSDMicros, Used: &used, Limit: &lim, UsedFrac: F(used / lim)}
		if inv.Year > 0 && inv.Month > 0 {
			reset := time.Date(inv.Year, time.Month(inv.Month)+1, 1, 0, 0, 0, 0, time.UTC)
			w.ResetsAt = &reset
		}
		s.Windows = append(s.Windows, w)
	}
	return s
}

func parseXAI(in ParseInput) (Snapshot, error) {
	body, err := need(in, "balance")
	if err != nil {
		return Snapshot{}, err
	}
	posted, err := ParseXAIBalance(body)
	if err != nil {
		return Snapshot{}, err
	}
	var inv *XAIInvoice
	if r, ok := in.Responses["invoice"]; ok && httpErr(r, true) == nil {
		if v, err := ParseXAIInvoicePreview(r.Body); err == nil {
			inv = &v
		}
	}
	return XAISnapshot(posted, inv, in.Now), nil
}

// --- GitHub Copilot billing usage ---------------------------------------------

// githubUserRe-free validation: GitHub logins are alphanumeric with single
// hyphens; anything else is refused before it reaches a URL path.
func validGitHubLogin(u string) bool {
	if u == "" || len(u) > 39 || strings.HasPrefix(u, "-") || strings.HasSuffix(u, "-") {
		return false
	}
	for _, r := range u {
		if !(r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func planCopilotBilling(in PlanInput) ([]Request, error) {
	pat, err := secret(in, "pat")
	if err != nil {
		return nil, err
	}
	u := strings.TrimSpace(in.Params["username"])
	if !validGitHubLogin(u) {
		return nil, errors.New("planlimits: invalid GitHub username")
	}
	q := fmt.Sprintf("?year=%d&month=%d", in.Now.UTC().Year(), int(in.Now.UTC().Month()))
	h := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"}
	base := "https://api.github.com/users/" + u + "/settings/billing/"
	return []Request{
		{Key: "premium", Kind: ReqHTTP, Method: "GET", URL: base + "premium_request/usage" + q, Header: h, SecretHeaders: bearer(pat)},
		{Key: "ai_credit", Kind: ReqHTTP, Method: "GET", URL: base + "ai_credit/usage" + q, Header: h, SecretHeaders: bearer(pat), Optional: true},
	}, nil
}

// copilotUsage is the documented billing usage body.
type copilotUsage struct {
	TimePeriod *struct {
		Year  int `json:"year"`
		Month int `json:"month"`
	} `json:"timePeriod"`
	UsageItems []struct {
		GrossQuantity    float64  `json:"grossQuantity"`
		DiscountQuantity float64  `json:"discountQuantity"`
		NetAmount        *float64 `json:"netAmount"`
	} `json:"usageItems"`
}

// CopilotBillingWindow maps one billing usage body (premium_request or
// ai_credit) onto a monthly window, the covered quantity and the net spend.
// Empty items mean the seat is billed elsewhere (documented), never zero.
func CopilotBillingWindow(body []byte, key string, unit Unit) (Window, Balance, Spend, error) {
	var r copilotUsage
	if err := json.Unmarshal(body, &r); err != nil || r.TimePeriod == nil {
		return Window{}, Balance{}, Spend{}, shapeErr("copilot billing", err)
	}
	if len(r.UsageItems) == 0 {
		return Window{}, Balance{}, Spend{}, fmt.Errorf("%w: no user-billed usage", ErrNotApplicable)
	}
	var gross, covered, net float64
	for _, it := range r.UsageItems {
		gross += it.GrossQuantity
		covered += it.DiscountQuantity
		if it.NetAmount != nil {
			net += *it.NetAmount
		}
	}
	reset := time.Date(r.TimePeriod.Year, time.Month(r.TimePeriod.Month)+1, 1, 0, 0, 0, 0, time.UTC)
	w := Window{Key: key, Unit: unit, Used: F(gross), ResetsAt: &reset}
	return w, Balance{Kind: "included_used", Unit: unit, Amount: int64(covered)},
		Spend{Period: "month", Unit: UnitUSDMicros, Amount: microsFromFloat(net), Scope: "account"}, nil
}

func parseCopilotBilling(in ParseInput) (Snapshot, error) {
	s := newSnap(ProviderCopilot, SourceCopilotBilling, KindOfficialAPI, ConfExact, in.Now)
	var firstErr error
	var spend int64
	parsed := false
	for _, k := range []struct {
		resp, key string
		unit      Unit
	}{{"premium", "monthly:premium_requests", UnitRequests}, {"ai_credit", "monthly:ai_credits", UnitAICredits}} {
		body, err := need(in, k.resp)
		if err != nil {
			if firstErr == nil && k.resp == "premium" {
				firstErr = err
			}
			continue
		}
		w, b, sp, err := CopilotBillingWindow(body, k.key, k.unit)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		parsed = true
		s.Windows = append(s.Windows, w)
		s.Balances = append(s.Balances, b)
		spend += sp.Amount
	}
	if !parsed {
		if firstErr == nil {
			firstErr = shapeErr("copilot billing: nothing parsed", nil)
		}
		if errors.Is(firstErr, ErrNotApplicable) {
			s.Status = StatusBilledElse
			return s, nil
		}
		return Snapshot{}, firstErr
	}
	s.Spend = []Spend{{Period: "month", Unit: UnitUSDMicros, Amount: spend, Scope: "account"}}
	// A typed allowance turns "used" into "used of N": the limit is the
	// user's statement, so the window becomes estimated.
	if a, ok := parseAllowance(in.Params["allowance"]); ok {
		for i := range s.Windows {
			if s.Windows[i].Key == "monthly:premium_requests" && s.Windows[i].Used != nil {
				s.Windows[i].Limit = F(a)
				s.Windows[i].UsedFrac = F(min(*s.Windows[i].Used/a, 2))
				s.Confidence = ConfEstimated
			}
		}
	}
	sort.SliceStable(s.Windows, func(i, j int) bool { return s.Windows[i].Key > s.Windows[j].Key })
	return s, nil
}

// parseAllowance parses a positive number typed by the user.
func parseAllowance(v string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || f <= 0 {
		return 0, false
	}
	return f, true
}
