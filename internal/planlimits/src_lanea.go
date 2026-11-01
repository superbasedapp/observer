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

// src_lanea.go holds the lane A sources: vendors read with an API key the
// user pastes. Endpoints, field names and units were taken as facts from
// CodexBar (MIT, discovery only) and the vendor doc links it cites; the Go is
// ours. A source is KindOfficialAPI only when a vendor document for the
// endpoint is cited (DocURL); every other key source is KindUndocumented and
// sits behind the provider's experimental opt-in.
//
// Shared rules: unknown is never zero (a missing number is omitted or a shape
// error), money is integer micros of one currency, credits stay credits, and
// a window key comes from the length the vendor declares (by a duration field
// or by the documented name of the window), never from its position.

// Lane A source ids.
const (
	SourceClinePass   = "clinepass.api"
	SourceOpenCodeGo  = "opencode_go.api"
	SourceFactory     = "factory.api"
	SourceFireworks   = "fireworks.api"
	SourceZai         = "zai.api"
	SourceMiniMax     = "minimax.api"
	SourceKilo        = "kilo.api"
	SourceSynthetic   = "synthetic.api"
	SourceElevenLabs  = "elevenlabs.api"
	SourceWarp        = "warp.api"
	SourceDeepInfra   = "deepinfra.api"
	SourceCodebuff    = "codebuff.api"
	SourceVenice      = "venice.api"
	SourceCommandCode = "command_code.api"
	SourcePoe         = "poe.api"
	SourceChutes      = "chutes.api"
	SourceNeuralwatt  = "neuralwatt.api"
	SourceZenMux      = "zenmux.management"
	SourceAiAnd       = "aiand.api"
	SourceIBMBob      = "ibm_bob.api"
	SourceHuggingFace = "hugging_face.api"
	SourceV0          = "v0.api"
)

// laRow builds a source row that needs one pasted secret. Official rows sit
// at order 20, experimental ones at 50, like the first lane's rows.
func laRow(id, provider string, kind SourceKind, secretKey string, hosts []string, every time.Duration, doc string, params ...ParamSpec) SourceDef {
	order := 50
	if RungOf(kind) == RungOfficial {
		order = 20
	}
	return SourceDef{
		ID: id, Provider: provider, Kind: kind, Order: order,
		Secrets: []SecretSpec{{Key: secretKey, Required: true}},
		Params:  params, Hosts: hosts, MinInterval: every, DocURL: doc,
	}
}

// laRegion is the region picker shared by the vendors with a global and a
// China mainland host.
var laRegion = ParamSpec{Key: "region", Choices: []string{"global", "china"}}

func init() {
	addSources(
		laRow(SourceClinePass, "clinepass", KindUndocumented, SecretKey, []string{"api.cline.bot"}, 10*time.Minute, ""),
		laRow(SourceOpenCodeGo, "opencode_go", KindUndocumented, SecretKey, []string{"opencode.ai"}, 10*time.Minute, ""),
		laRow(SourceFactory, "factory", KindUndocumented, SecretKey, []string{"api.factory.ai"}, 10*time.Minute, ""),
		laRow(SourceFireworks, "fireworks", KindUndocumented, SecretKey, []string{"api.fireworks.ai"}, 30*time.Minute, "",
			ParamSpec{Key: "account_id", Required: true}),
		laRow(SourceZai, "zai", KindUndocumented, SecretKey, []string{"api.z.ai", "open.bigmodel.cn"}, 10*time.Minute, "", laRegion),
		laRow(SourceMiniMax, "minimax", KindUndocumented, SecretKey, []string{"api.minimax.io", "api.minimaxi.com"}, 10*time.Minute, "", laRegion),
		laRow(SourceKilo, "kilo", KindUndocumented, SecretKey, []string{"app.kilo.ai"}, 10*time.Minute, "",
			ParamSpec{Key: "org_id"}),
		laRow(SourceSynthetic, "synthetic", KindOfficialAPI, SecretKey, []string{"api.synthetic.new"}, 5*time.Minute,
			"https://dev.synthetic.new/docs/synthetic/quotas"),
		laRow(SourceElevenLabs, "elevenlabs", KindUndocumented, SecretKey, []string{"api.elevenlabs.io"}, 15*time.Minute, ""),
		laRow(SourceWarp, "warp", KindUndocumented, SecretKey, []string{"app.warp.dev"}, 15*time.Minute, ""),
		laRow(SourceDeepInfra, "deepinfra", KindUndocumented, SecretKey, []string{"api.deepinfra.com"}, 15*time.Minute, ""),
		laRow(SourceCodebuff, "codebuff", KindUndocumented, SecretKey, []string{"www.codebuff.com"}, 10*time.Minute, ""),
		laRow(SourceVenice, "venice", KindUndocumented, SecretKey, []string{"api.venice.ai"}, 10*time.Minute, ""),
		laRow(SourceCommandCode, "command_code", KindUndocumented, SecretKey, []string{"api.commandcode.ai"}, 10*time.Minute, ""),
		laRow(SourcePoe, "poe", KindUndocumented, SecretKey, []string{"api.poe.com"}, 15*time.Minute, ""),
		laRow(SourceChutes, "chutes", KindUndocumented, SecretKey, []string{"api.chutes.ai"}, 15*time.Minute, ""),
		laRow(SourceNeuralwatt, "neuralwatt", KindUndocumented, SecretKey, []string{"api.neuralwatt.com"}, 10*time.Minute, ""),
		laRow(SourceZenMux, "zenmux", KindAdminAPI, SecretMgmt, []string{"zenmux.ai"}, 5*time.Minute,
			"https://docs.zenmux.ai/api/platform/subscription-detail"),
		laRow(SourceAiAnd, "aiand", KindOfficialAPI, SecretKey, []string{"api.aiand.com"}, 30*time.Minute,
			"https://docs.aiand.com/analytics/logs/"),
		laRow(SourceIBMBob, "ibm_bob", KindUndocumented, SecretKey, []string{"api.us-east.bob.ibm.com"}, 30*time.Minute, ""),
		laRow(SourceHuggingFace, "hugging_face", KindUndocumented, SecretKey, []string{"huggingface.co"}, 30*time.Minute, ""),
		laRow(SourceV0, "v0", KindOfficialAPI, SecretKey, []string{"api.v0.dev"}, 10*time.Minute,
			"https://v0.app/docs/api/v1/reference/user/get-billing", ParamSpec{Key: "project_id"}),
	)
	for id, d := range map[string]Driver{
		SourceClinePass:   {Plan: keyedGET("https://api.cline.bot/api/v1/users/me/plan/usage-limits", SecretKey, AuthBearer, "", nil), Parse: laOne(ParseClinePass)},
		SourceOpenCodeGo:  {Plan: keyedGET("https://opencode.ai/zen/go/v1/usage", SecretKey, AuthBearer, "", nil), Parse: laOne(ParseOpenCodeGo)},
		SourceFactory:     {Plan: planFactory, Parse: parseFactory},
		SourceFireworks:   {Plan: planFireworks, Parse: laOne(ParseFireworks)},
		SourceZai:         {Plan: planZai, Parse: laOne(ParseZai)},
		SourceMiniMax:     {Plan: planMiniMax, Parse: parseMiniMax},
		SourceKilo:        {Plan: planKilo, Parse: laOne(ParseKilo)},
		SourceSynthetic:   {Plan: keyedGET("https://api.synthetic.new/v2/quotas", SecretKey, AuthBearer, "", nil), Parse: laOne(ParseSynthetic)},
		SourceElevenLabs:  {Plan: keyedGET("https://api.elevenlabs.io/v1/user/subscription", SecretKey, AuthHeader, "xi-api-key", nil), Parse: laOne(ParseElevenLabs)},
		SourceWarp:        {Plan: planWarp, Parse: laOne(ParseWarp)},
		SourceDeepInfra:   {Plan: planDeepInfra, Parse: parseDeepInfra},
		SourceCodebuff:    {Plan: planCodebuff, Parse: parseCodebuff},
		SourceVenice:      {Plan: keyedGET("https://api.venice.ai/api/v1/billing/balance", SecretKey, AuthBearer, "", nil), Parse: laOne(ParseVenice)},
		SourceCommandCode: {Plan: planCommandCode, Parse: parseCommandCode},
		SourcePoe:         {Plan: keyedGET("https://api.poe.com/usage/current_balance", SecretKey, AuthBearer, "", nil), Parse: laOne(ParsePoe)},
		SourceChutes:      {Plan: keyedGET("https://api.chutes.ai/users/me/subscription_usage", SecretKey, AuthBearer, "", nil), Parse: laOne(ParseChutes)},
		SourceNeuralwatt:  {Plan: keyedGET("https://api.neuralwatt.com/v1/quota", SecretKey, AuthBearer, "", nil), Parse: laOne(ParseNeuralwatt)},
		SourceZenMux:      {Plan: planZenMux, Parse: parseZenMux},
		SourceAiAnd:       {Plan: keyedGET("https://api.aiand.com/logs?range=30days&limit=100", SecretKey, AuthBearer, "", nil), Parse: laOne(ParseAiAnd)},
		SourceIBMBob:      {Plan: planIBMBob, Parse: laOne(ParseIBMBob)},
		SourceHuggingFace: {Plan: planHuggingFace, Parse: parseHuggingFace},
		SourceV0:          {Plan: planV0, Parse: parseV0},
	} {
		register(id, d)
	}
}

// --- shared helpers ------------------------------------------------------------

// laOne adapts a single-body parser to a Driver.Parse reading response "main".
func laOne(p func([]byte, time.Time) (Snapshot, error)) func(ParseInput) (Snapshot, error) {
	return func(in ParseInput) (Snapshot, error) {
		body, err := need(in, "main")
		if err != nil {
			return Snapshot{}, err
		}
		return p(body, in.Now)
	}
}

// laReq is one request of a multi-request plan.
type laReq struct {
	key, method, url string
	body             []byte
	optional         bool
	header           map[string]string
}

// laPlan builds requests that all carry the secret secretKey in one style.
func laPlan(in PlanInput, secretKey string, style AuthStyle, headerName string, reqs ...laReq) ([]Request, error) {
	k, err := secret(in, secretKey)
	if err != nil {
		return nil, err
	}
	out := make([]Request, 0, len(reqs))
	for _, r := range reqs {
		h := map[string]string{"Accept": "application/json"}
		if r.body != nil {
			h["Content-Type"] = "application/json"
		}
		for n, v := range r.header {
			h[n] = v
		}
		m := r.method
		if m == "" {
			m = "GET"
		}
		out = append(out, Request{
			Key: r.key, Kind: ReqHTTP, Method: m, URL: r.url, Header: h,
			SecretHeaders: authHeaders(style, headerName, k), Body: r.body, Optional: r.optional,
		})
	}
	return out, nil
}

// laOpt returns an optional response's decoded body; ok=false when it is
// absent, not 2xx or not JSON.
func laOpt(in ParseInput, key string) (J, bool) {
	r, ok := in.Responses[key]
	if !ok || httpErr(r, true) != nil {
		return J{}, false
	}
	j, err := ParseJ(r.Body)
	return j, err == nil
}

// laDone returns the snapshot, or a shape error when it carries no reading.
func laDone(s Snapshot, what string) (Snapshot, error) {
	if err := requireAny(s, what); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// laNum reads the first of several keys that holds a number.
func laNum(j J, keys ...string) (float64, bool) {
	for _, k := range keys {
		if v, ok := j.At(k).Num(); ok {
			return v, true
		}
	}
	return 0, false
}

// laNumP is laNum as a pointer; nil when unknown.
func laNumP(j J, keys ...string) *float64 {
	if v, ok := laNum(j, keys...); ok {
		return &v
	}
	return nil
}

// laStr reads the first non-empty string among keys.
func laStr(j J, keys ...string) string {
	for _, k := range keys {
		if v, ok := j.At(k).Str(); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// laTime reads the first key that holds a time.
func laTime(j J, keys ...string) *time.Time {
	for _, k := range keys {
		if t := j.At(k).Time(); t != nil {
			return t
		}
	}
	return nil
}

// laMinuteKeys names the window lengths a vendor declares in minutes.
var laMinuteKeys = map[int64]string{60: "hourly", 240: "4h", 300: "5h", 1440: "daily", 10080: "weekly", 43200: "monthly"}

// laKeyForMinutes is the window key for a declared length; an unnamed length
// keeps its minutes ("90m"). "" for no length.
func laKeyForMinutes(m int64) string {
	if k, ok := laMinuteKeys[m]; ok {
		return k
	}
	if m <= 0 {
		return ""
	}
	return fmt.Sprintf("%dm", m)
}

// laPct is a percent window from a 0..100 used percentage, clamped.
func laPct(key string, usedPct float64, reset *time.Time, length time.Duration) Window {
	return PercentWindow(key, min(max(usedPct, 0), 200), reset, length)
}

// laMoney converts dollars to a micros pointer.
func laMoney(v *float64) *float64 {
	if v == nil {
		return nil
	}
	return F(float64(microsFromFloat(*v)))
}

// laInt rounds a count (credits, points) to a whole number for a Balance.
func laInt(v float64) int64 { return int64(math.Round(v)) }

// laTitle turns a vendor code ("growing_business") into a label.
func laTitle(s string) string {
	words := strings.Fields(strings.ReplaceAll(strings.TrimSpace(s), "_", " "))
	for i, w := range words {
		r := []rune(w)
		words[i] = strings.ToUpper(string(r[:1])) + string(r[1:])
	}
	return SanitizeLabel(strings.Join(words, " "))
}

// laAdd appends w unless its key is taken.
func laAdd(s *Snapshot, w Window) {
	if _, dup := FindWindow(*s, w.Key); !dup {
		s.Windows = append(s.Windows, w)
	}
}

// laSlugKey keeps a vendor name usable inside a window key.
func laSlugKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '_', r == '.':
			b.WriteRune('_')
		}
		if b.Len() >= 32 {
			break
		}
	}
	return b.String()
}

// --- ClinePass ---------------------------------------------------------------

// laClineWindows binds Cline's documented window names to keys and lengths.
var laClineWindows = map[string]struct {
	key    string
	length time.Duration
}{
	"five_hour": {"5h", 5 * time.Hour},
	"weekly":    {"weekly", 7 * 24 * time.Hour},
	"monthly":   {"monthly", 0},
}

// ParseClinePass maps the Cline plan usage-limits body: percentUsed is 0..100
// used per named window.
func ParseClinePass(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if ok, _ := j.At("success").Bool(); !ok {
		return Snapshot{}, shapeErr("clinepass: success not true", nil)
	}
	lims := j.At("data.limits").Arr()
	if lims == nil {
		return Snapshot{}, shapeErr("clinepass: no limits", nil)
	}
	s := newSnap("clinepass", SourceClinePass, KindUndocumented, ConfExact, now)
	for _, l := range lims {
		t, _ := l.At("type").Str()
		spec, ok := laClineWindows[t]
		if !ok {
			continue
		}
		p, ok := l.At("percentUsed").Num()
		if !ok {
			return Snapshot{}, shapeErr("clinepass: percentUsed", nil)
		}
		laAdd(&s, laPct(spec.key, p, l.At("resetsAt").Time(), spec.length))
	}
	return laDone(s, "clinepass")
}

// --- OpenCode Go -----------------------------------------------------------------

var laOpenCodeWindows = []struct {
	in, key string
	length  time.Duration
}{{"rolling", "5h", 5 * time.Hour}, {"weekly", "weekly", 7 * 24 * time.Hour}, {"monthly", "monthly", 0}}

// ParseOpenCodeGo maps the OpenCode Go usage body. Percent is 0..100 used;
// a reset is either seconds from now or a time.
func ParseOpenCodeGo(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if !j.At("usage.rolling").Exists() {
		return Snapshot{}, shapeErr("opencode go: usage.rolling missing", nil)
	}
	s := newSnap("opencode_go", SourceOpenCodeGo, KindUndocumented, ConfExact, now)
	for _, w := range laOpenCodeWindows {
		o := j.At("usage." + w.in)
		if !o.Exists() {
			continue
		}
		p, ok := laNum(o, "usagePercent", "usedPercent", "percentUsed", "percent", "usage_percent", "used_percent", "utilization")
		if !ok {
			used, uok := laNum(o, "used", "consumed", "count")
			lim, lok := laNum(o, "limit", "total", "quota", "max", "cap")
			if !uok || !lok || lim <= 0 {
				continue
			}
			p = used / lim * 100
		}
		var reset *time.Time
		if sec, ok := laNum(o, "resetInSec", "resetInSeconds", "resetSeconds", "resetIn"); ok && sec >= 0 {
			t := now.Add(time.Duration(sec) * time.Second).UTC()
			reset = &t
		} else {
			reset = laTime(o, "resetAt", "resetsAt", "reset_at", "resets_at")
		}
		laAdd(&s, laPct(w.key, p, reset, w.length))
	}
	return laDone(s, "opencode go")
}

// --- Factory -------------------------------------------------------------------

func planFactory(in PlanInput) ([]Request, error) {
	// No client-identity header: Observer never poses as Factory's own web
	// app (the Phase 0 honesty guardrail).
	var h map[string]string
	return laPlan(in, SecretKey, AuthBearer, "",
		laReq{key: "me", url: "https://api.factory.ai/api/app/auth/me", header: h},
		laReq{key: "limits", url: "https://api.factory.ai/api/billing/limits", header: h, optional: true},
		laReq{key: "usage", url: "https://api.factory.ai/api/organization/subscription/usage?useCache=true", header: h, optional: true},
	)
}

var laFactoryWindows = []struct {
	in, key string
	length  time.Duration
}{{"fiveHour", "5h", 5 * time.Hour}, {"weekly", "weekly", 7 * 24 * time.Hour}, {"monthly", "monthly", 0}}

// FactoryLimits maps the token-rate billing body (usedPercent 0..100 per
// window, standard and core tiers) onto s. ok=false when the account is not
// on token-rate billing.
func FactoryLimits(j J, s *Snapshot, now time.Time) bool {
	if on, _ := j.At("usesTokenRateLimitsBilling").Bool(); !on || !j.At("limits").Exists() {
		return false
	}
	for _, tier := range []string{"standard", "core"} {
		var ws []Window
		active := false
		for _, w := range laFactoryWindows {
			o := j.At("limits." + tier + "." + w.in)
			p, ok := o.At("usedPercent").Num()
			if !ok {
				continue
			}
			var reset *time.Time
			end := o.At("windowEnd").Time()
			if sec, ok := o.At("secondsRemaining").Num(); ok && sec > 0 {
				t := now.Add(time.Duration(sec) * time.Second).UTC()
				reset = &t
			} else if end != nil && end.After(now) {
				reset = end
			} else if end != nil {
				p = 0 // the window ended and nothing new was counted
			}
			if p > 0 || reset != nil {
				active = true
			}
			key := w.key
			if tier != "standard" {
				key = tier + ":" + w.key
			}
			ws = append(ws, laPct(key, p, reset, w.length))
		}
		if tier == "standard" || active {
			for _, w := range ws {
				laAdd(s, w)
			}
		}
	}
	if m, ok := j.At("extraUsageBalanceCents").Micros(2); ok {
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: m})
	}
	return true
}

// FactoryUsage maps the older token allowance body (tokens per billing
// period, standard and premium).
func FactoryUsage(j J, s *Snapshot) {
	start, end := j.At("usage.startDate").Time(), j.At("usage.endDate").Time()
	var length time.Duration
	if start != nil && end != nil && end.After(*start) {
		length = end.Sub(*start)
	}
	for _, tier := range []string{"standard", "premium"} {
		o := j.At("usage." + tier)
		used := o.At("userTokens").NumP()
		lim := o.At("totalAllowance").NumP()
		if lim != nil && *lim > 0 && *lim <= 1e12 && used != nil {
			if w, ok := AmountWindow("cycle:"+tier, UnitTokens, used, lim, nil, end, length); ok {
				laAdd(s, w)
			}
			continue
		}
		if r, ok := o.At("usedRatio").Num(); ok && r >= 0 && r <= 1 {
			laAdd(s, laPct("cycle:"+tier, r*100, end, length))
		}
	}
}

func parseFactory(in ParseInput) (Snapshot, error) {
	body, err := need(in, "me")
	if err != nil {
		return Snapshot{}, err
	}
	me, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	s := newSnap("factory", SourceFactory, KindUndocumented, ConfExact, in.Now)
	s.PlanCode = SanitizeLabel(strings.ToLower(laStr(me, "organization.subscription.factoryTier")))
	s.PlanLabel = SanitizeLabel(laStr(me, "organization.subscription.orbSubscription.plan.name"))
	if s.PlanLabel == "" && s.PlanCode != "" {
		s.PlanLabel = laTitle(s.PlanCode)
	}
	read := false
	if j, ok := laOpt(in, "limits"); ok {
		read = FactoryLimits(j, &s, in.Now)
	}
	if !read {
		if j, ok := laOpt(in, "usage"); ok {
			FactoryUsage(j, &s)
		}
	}
	return laDone(s, "factory")
}

// --- Fireworks -------------------------------------------------------------------

// validSlug accepts a vendor account slug that cannot escape a URL path.
func validSlug(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func planFireworks(in PlanInput) ([]Request, error) {
	slug := strings.TrimSpace(in.Params["account_id"])
	slug = slug[strings.LastIndex(slug, "/")+1:]
	if !validSlug(slug) {
		return nil, errors.New("planlimits: invalid Fireworks account id")
	}
	const layout = "2006-01-02T15:04:05Z"
	now := in.Now.UTC().Truncate(time.Second)
	q := url.Values{"startTime": {now.Add(-30 * 24 * time.Hour).Format(layout)}, "endTime": {now.Format(layout)}}
	return laPlan(in, SecretKey, AuthBearer, "",
		laReq{key: "main", url: "https://api.fireworks.ai/v1/accounts/" + slug + "/billing/summary?" + q.Encode()})
}

// laMoneyItems sums Google-Money-style amounts ({currencyCode, units string,
// nanos}) in the first item's currency; other currencies are skipped, never
// converted. ok=false when no item is priced.
func laMoneyItems(items []J, path string) (Unit, int64, bool) {
	var unit Unit
	var sum int64
	for _, it := range items {
		m := it.At(path)
		code, cok := m.At("currencyCode").Str()
		units, uok := m.At("units").Str()
		nanos, nok := m.At("nanos").Num()
		u := CurrencyUnit(code)
		if !cok || !uok || !nok || u == "" {
			continue
		}
		if unit == "" {
			unit = u
		}
		if u != unit {
			continue
		}
		whole, err := MicrosFromDecimal(units, 0)
		if err != nil {
			continue
		}
		sum += whole + int64(nanos/1000)
	}
	return unit, sum, unit != ""
}

// ParseFireworks maps the 30-day billing summary onto spend. No priced line
// means nothing was billed: the plan is reported without a meter.
func ParseFireworks(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	items := j.At("lineItems")
	s := newSnap("fireworks", SourceFireworks, KindUndocumented, ConfExact, now)
	unit, sum, ok := laMoneyItems(items.Arr(), "totalCost")
	switch {
	case ok:
		s.Spend = []Spend{{Period: "30d", Unit: unit, Amount: sum, Scope: "account"}}
	case items.Exists() || len(j.Keys()) == 0:
		s.Status = StatusUnmetered // nothing billed in the last 30 days
	default:
		return Snapshot{}, shapeErr("fireworks: no lineItems", nil)
	}
	return s, nil
}

// --- z.ai / BigModel ---------------------------------------------------------------

// zaiHosts binds the region parameter to the vendor's host.
var zaiHosts = map[string]string{"": "api.z.ai", "global": "api.z.ai", "china": "open.bigmodel.cn"}

func planZai(in PlanInput) ([]Request, error) {
	h, ok := zaiHosts[in.Params["region"]]
	if !ok {
		return nil, fmt.Errorf("planlimits: z.ai region %q", in.Params["region"])
	}
	return laPlan(in, SecretKey, AuthBearer, "", laReq{key: "main", url: "https://" + h + "/api/monitor/usage/quota/limit"})
}

// zaiUnitMinutes is the length of one z.ai quota "unit".
var zaiUnitMinutes = map[int64]int64{1: 1440, 3: 60, 5: 1, 6: 10080}

// zaiCountUnit is what a z.ai limit type counts.
var zaiCountUnit = map[string]Unit{"TOKENS_LIMIT": UnitTokens, "CREDIT_LIMIT": UnitCredits, "TIME_LIMIT": UnitRequests}

// ParseZai maps the coding plan quota body. Each limit declares its length as
// number x unit; percentage is 0..100 used; counts (usage = the limit,
// currentValue = used, remaining) win over the percentage when present.
func ParseZai(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if code, _ := j.At("code").Num(); code == 401 {
		return Snapshot{}, fmt.Errorf("%w: z.ai code 401", ErrAuth)
	}
	if ok, _ := j.At("success").Bool(); !ok {
		return Snapshot{}, shapeErr("z.ai: success not true", nil)
	}
	s := newSnap("zai", SourceZai, KindUndocumented, ConfExact, now)
	s.PlanLabel = SanitizeLabel(laTitle(laStr(j, "data.planName", "data.plan", "data.plan_type", "data.packageName", "data.level")))
	for _, l := range j.At("data.limits").Arr() {
		typ, _ := l.At("type").Str()
		cu, known := zaiCountUnit[typ]
		unit, uok := l.At("unit").Num()
		num, nok := l.At("number").Num()
		mult, mok := zaiUnitMinutes[int64(unit)]
		if !known || !uok || !nok || !mok {
			continue
		}
		mins := int64(num) * mult
		key := laKeyForMinutes(mins)
		length := time.Duration(mins) * time.Minute
		if typ == "TIME_LIMIT" {
			if mins == 1 { // a monthly tool-call allowance, marked by a one-minute unit
				key, length = "monthly", 0
			}
			key = "mcp:" + key
		}
		reset := l.At("nextResetTime").Time()
		if key == "5h" && reset != nil && reset.After(now.Add(5*time.Hour+time.Minute)) {
			reset = nil
		}
		lim := l.At("usage").NumP()
		used := l.At("currentValue").NumP()
		rem := l.At("remaining").NumP()
		if lim != nil && *lim > 0 && (used != nil || rem != nil) {
			if rem != nil && (used == nil || *lim-*rem > *used) {
				used = F(*lim - *rem)
			}
			if w, ok := AmountWindow(key, cu, used, lim, rem, reset, length); ok {
				laAdd(&s, w)
			}
			continue
		}
		if p, ok := l.At("percentage").Num(); ok {
			laAdd(&s, laPct(key, p, reset, length))
		}
	}
	return laDone(s, "z.ai")
}

// --- MiniMax ---------------------------------------------------------------------

// minimaxHosts binds the region parameter to the API host.
var minimaxHosts = map[string]string{"": "api.minimax.io", "global": "api.minimax.io", "china": "api.minimaxi.com"}

func planMiniMax(in PlanInput) ([]Request, error) {
	h, ok := minimaxHosts[in.Params["region"]]
	if !ok {
		return nil, fmt.Errorf("planlimits: minimax region %q", in.Params["region"])
	}
	return laPlan(in, SecretKey, AuthBearer, "",
		laReq{key: "token", url: "https://" + h + "/v1/token_plan/remains", optional: true},
		laReq{key: "coding", url: "https://" + h + "/v1/api/openplatform/coding_plan/remains", optional: true},
	)
}

// minimaxInPlan reports whether one interval of one model lane carries a
// reading. Status 3 with nothing counted and 100% left marks a lane that is
// not part of the plan (or, for text, unlimited): no window.
func minimaxInPlan(m J, prefix string) bool {
	total, _ := m.At(prefix + "total_count").Num()
	rem := m.At(prefix + "usage_count").NumP()
	pct := m.At(prefix + "remaining_percent").NumP()
	status, _ := m.At(prefix + "status").Num()
	if status == 3 && total == 0 && (rem == nil || *rem == 0) && (pct == nil || *pct >= 100) {
		return false
	}
	return total > 0 || pct != nil
}

// ParseMiniMaxRemains maps a plan remains body (token plan or the older
// coding plan; both share the shape).
func ParseMiniMaxRemains(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if code, ok := j.At("base_resp.status_code").Num(); ok && code != 0 {
		if code == 1004 {
			return Snapshot{}, fmt.Errorf("%w: minimax status 1004", ErrAuth)
		}
		return Snapshot{}, shapeErr(fmt.Sprintf("minimax status %v", code), nil)
	}
	root := j
	if j.At("data.model_remains").Exists() {
		root = j.At("data")
	}
	lanes := root.At("model_remains").Arr()
	if lanes == nil {
		return Snapshot{}, shapeErr("minimax: no model_remains", nil)
	}
	s := newSnap("minimax", SourceMiniMax, KindUndocumented, ConfExact, now)
	s.PlanLabel = SanitizeLabel(laStr(root, "current_subscribe_title", "plan_name", "combo_title", "current_plan_title", "current_combo_card.title"))
	for _, m := range lanes {
		name := laSlugKey(laStr(m, "model_name"))
		if name == "" {
			continue
		}
		for _, lane := range []struct{ field, timePrefix string }{{"current_interval_", ""}, {"current_weekly_", "weekly_"}} {
			// MiniMax's "usage_count" is what is REMAINING; remaining_percent
			// is 0..100 left.
			if !minimaxInPlan(m, lane.field) {
				continue
			}
			start, end := m.At(lane.timePrefix+"start_time").Time(), m.At(lane.timePrefix+"end_time").Time()
			var length time.Duration
			if start != nil && end != nil && end.After(*start) {
				length = end.Sub(*start)
			}
			key := laKeyForMinutes(int64(length / time.Minute))
			if lane.timePrefix == "weekly_" {
				key = "weekly"
			}
			if key == "" {
				continue
			}
			key += ":" + name
			reset := end
			if reset == nil || !reset.After(now) {
				reset = nil
				remainsField := "remains_time"
				if lane.timePrefix != "" {
					remainsField = lane.timePrefix + "remains_time"
				}
				if r, ok := m.At(remainsField).Num(); ok && r > 0 {
					d := time.Duration(r) * time.Second
					if r > 1_000_000 {
						d = time.Duration(r) * time.Millisecond
					}
					t := now.Add(d).UTC()
					reset = &t
				}
			}
			total := m.At(lane.field + "total_count").NumP()
			rem := m.At(lane.field + "usage_count").NumP()
			if total != nil && *total > 0 && rem != nil {
				if w, ok := AmountWindow(key, UnitRequests, nil, total, rem, reset, length); ok {
					laAdd(&s, w)
				}
				continue
			}
			if p, ok := m.At(lane.field + "remaining_percent").Num(); ok {
				laAdd(&s, laPct(key, 100-p, reset, length))
			}
		}
	}
	if b, ok := laNum(root, "points_balance", "point_balance", "credits_balance", "credit_balance"); ok {
		s.Balances = append(s.Balances, Balance{Kind: "points", Unit: UnitPoints, Amount: laInt(b)})
	}
	sort.SliceStable(s.Windows, func(a, b int) bool { return s.Windows[a].Key < s.Windows[b].Key })
	return laDone(s, "minimax")
}

func parseMiniMax(in ParseInput) (Snapshot, error) {
	var firstErr error
	for _, k := range []string{"token", "coding"} {
		body, err := need(in, k)
		if err == nil {
			var s Snapshot
			if s, err = ParseMiniMaxRemains(body, in.Now); err == nil {
				return s, nil
			}
		}
		if firstErr == nil || errors.Is(err, ErrAuth) {
			firstErr = err
		}
	}
	return Snapshot{}, firstErr
}

// --- Kilo --------------------------------------------------------------------------

// kiloUsageURL is the one batched read of the credit blocks and the Kilo Pass.
var kiloUsageURL = "https://app.kilo.ai/api/trpc/user.getCreditBlocks,kiloPass.getState?batch=1&input=" +
	url.QueryEscape(`{"0":{"json":null},"1":{"json":null}}`)

func planKilo(in PlanInput) ([]Request, error) {
	var h map[string]string
	if org := strings.TrimSpace(in.Params["org_id"]); org != "" {
		if !validSlug(org) {
			return nil, errors.New("planlimits: invalid Kilo organization id")
		}
		h = map[string]string{"X-KILOCODE-ORGANIZATIONID": org}
	}
	return laPlan(in, SecretKey, AuthBearer, "", laReq{key: "main", url: kiloUsageURL, header: h})
}

// kiloPlanNames names the Kilo Pass tiers.
var kiloPlanNames = map[string]string{"tier_19": "Starter", "tier_49": "Pro", "tier_199": "Expert"}

// kiloEntry returns one batch entry's payload, or the error it carries.
func kiloEntry(j J, i int) (J, error) {
	e := j.At(strconv.Itoa(i))
	if e.Exists() && e.At("error").Exists() {
		msg := strings.ToLower(laStr(e.At("error"), "json.data.code", "data.code", "code", "json.message", "message"))
		if strings.Contains(msg, "unauthorized") || strings.Contains(msg, "forbidden") {
			return J{}, fmt.Errorf("%w: kilo %s", ErrAuth, msg)
		}
		return J{}, shapeErr("kilo entry error "+msg, nil)
	}
	return e.First("result.data.json", "result.data", "result.json"), nil
}

// ParseKilo maps the batched credit blocks (amounts in micro dollars, the
// "_mUsd" suffix notwithstanding) and the Kilo Pass state (plain dollars).
func ParseKilo(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if j.Arr() == nil && !j.At("0").Exists() {
		return Snapshot{}, shapeErr("kilo: not a batch", nil)
	}
	s := newSnap("kilo", SourceKilo, KindUndocumented, ConfExact, now)
	credits, err := kiloEntry(j, 0)
	if err != nil {
		return Snapshot{}, err
	}
	if blocks := credits.At("creditBlocks").Arr(); len(blocks) > 0 {
		var left, bought int64
		for _, b := range blocks {
			bal, bok := b.At("balance_mUsd").Num()
			amt, aok := b.At("amount_mUsd").Num()
			if !bok || !aok {
				return Snapshot{}, shapeErr("kilo credit block", nil)
			}
			left += laInt(bal)
			bought += laInt(amt)
		}
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: left}, Balance{Kind: "purchased", Unit: UnitUSDMicros, Amount: bought})
	} else if v, ok := credits.At("totalBalance_mUsd").Num(); ok {
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: laInt(v)})
	}
	pass, err := kiloEntry(j, 1)
	if err != nil {
		return Snapshot{}, err
	}
	sub := pass.At("subscription")
	if !sub.Exists() && (pass.At("tier").Exists() || pass.At("currentPeriodUsageUsd").Exists()) {
		sub = pass
	}
	if sub.Exists() {
		tier := laStr(sub, "tier")
		s.PlanCode = SanitizeLabel(tier)
		s.PlanLabel = kiloPlanNames[tier]
		if s.PlanLabel == "" {
			s.PlanLabel = SanitizeLabel(tier)
		}
		base, bok := sub.At("currentPeriodBaseCreditsUsd").Num()
		bonus, _ := sub.At("currentPeriodBonusCreditsUsd").Num()
		used := sub.At("currentPeriodUsageUsd").NumP()
		if bok && base+bonus > 0 && used != nil {
			if w, ok := AmountWindow("cycle", UnitUSDMicros, laMoney(used), laMoney(F(base+bonus)), nil,
				laTime(sub, "nextBillingAt", "nextRenewalAt", "renewsAt", "renewAt"), 0); ok {
				s.Windows = append(s.Windows, w)
			}
		}
	}
	return laDone(s, "kilo")
}

// --- Synthetic -----------------------------------------------------------------------

// synthSlots are the documented quota slots and their declared lengths.
var synthSlots = []struct {
	path, key string
	length    time.Duration
	unit      Unit
	rolling   bool
}{
	{"rollingFiveHourLimit", "5h", 5 * time.Hour, UnitRequests, true},
	{"weeklyTokenLimit", "weekly", 7 * 24 * time.Hour, UnitTokens, true},
	{"search.hourly", "search_hourly", time.Hour, UnitRequests, false},
}

// laDollars reads a dollar amount that may be a "$1,234.50" string.
func laDollars(j J) *float64 {
	if s, ok := j.Str(); ok {
		s = strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(s), "$"), ",", "")
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			return F(float64(microsFromFloat(v)))
		}
		return nil
	}
	if v, ok := j.Num(); ok {
		return F(float64(microsFromFloat(v)))
	}
	return nil
}

// synthQuota maps one Synthetic quota object. A dollar quota (maxCredits)
// is money; otherwise a percentage (used or remaining; a value up to 1 is a
// fraction) or counts in countUnit.
func synthQuota(key string, q J, length time.Duration, countUnit Unit) (Window, bool) {
	reset := laTime(q, "resetAt", "reset_at", "resetsAt", "resets_at", "renewsAt", "renews_at", "nextRegenAt", "next_regen_at", "periodEnd", "period_end")
	if lim := laDollars(q.At("maxCredits")); lim != nil && *lim > 0 {
		return AmountWindow(key, UnitUSDMicros, laDollars(q.At("usedCredits")), lim, laDollars(q.At("remainingCredits")), reset, length)
	}
	pct := func(v float64) float64 {
		if v <= 1 {
			return v * 100
		}
		return v
	}
	if v, ok := laNum(q, "percentUsed", "usedPercent", "usagePercent", "usage_percent", "used_percent", "percent_used"); ok {
		return laPct(key, pct(v), reset, length), true
	}
	if v, ok := laNum(q, "percentRemaining", "remainingPercent", "remaining_percent", "percent_remaining"); ok {
		return laPct(key, 100-pct(v), reset, length), true
	}
	lim := laNumP(q, "limit", "messageLimit", "maxRequests", "requestLimit", "quota", "max", "total", "allowance")
	used := laNumP(q, "used", "usage", "messagesUsed", "requests", "requestCount", "consumed")
	rem := laNumP(q, "remaining", "left", "available")
	if lim == nil && used != nil && rem != nil {
		lim = F(*used + *rem)
	}
	return AmountWindow(key, countUnit, used, lim, rem, reset, length)
}

// ParseSynthetic maps the documented quotas body: the named slots first,
// then any generic quota list keyed by its declared length.
func ParseSynthetic(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	root := j
	if d := j.At("data"); d.Keys() != nil {
		root = d
	}
	s := newSnap("synthetic", SourceSynthetic, KindOfficialAPI, ConfExact, now)
	s.PlanLabel = SanitizeLabel(laStr(root, "plan", "planName", "plan_name", "tier"))
	for _, sl := range synthSlots {
		if q := root.At(sl.path); q.Keys() != nil {
			if w, ok := synthQuota(sl.key, q, sl.length, sl.unit); ok {
				w.Rolling = sl.rolling
				laAdd(&s, w)
			}
		}
	}
	list := root.At("quotas").Arr()
	if list == nil {
		list = j.Arr()
	}
	for _, q := range list {
		mins, _ := laNum(q, "windowMinutes", "window_minutes", "periodMinutes")
		if h, ok := laNum(q, "windowHours", "window_hours"); ok {
			mins = h * 60
		}
		if d, ok := laNum(q, "windowDays", "window_days"); ok {
			mins = d * 1440
		}
		key := laKeyForMinutes(int64(mins))
		if key == "" {
			key = "quota:" + laSlugKey(laStr(q, "name", "label", "type", "id"))
		}
		if w, ok := synthQuota(key, q, time.Duration(mins)*time.Minute, UnitRequests); ok {
			laAdd(&s, w)
		}
	}
	return laDone(s, "synthetic")
}

// --- ElevenLabs ------------------------------------------------------------------------

// ParseElevenLabs maps the subscription body: characters used of the
// monthly character limit.
func ParseElevenLabs(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	used, uok := j.At("character_count").Num()
	lim, lok := j.At("character_limit").Num()
	if !uok || !lok {
		return Snapshot{}, shapeErr("elevenlabs: character counts", nil)
	}
	s := newSnap("elevenlabs", SourceElevenLabs, KindUndocumented, ConfExact, now)
	if tier := laStr(j, "tier"); tier != "" {
		s.PlanCode = SanitizeLabel(strings.ToLower(tier))
		s.PlanLabel = laTitle(tier)
	}
	w := Window{Key: "monthly", Unit: UnitCharacters, Used: F(used), Limit: F(lim), ResetsAt: j.At("next_character_count_reset_unix").Time()}
	if lim > 0 {
		w.Remaining = F(max(lim-used, 0))
		w.UsedFrac = F(min(used/lim, 2))
		if used >= lim {
			s.Status = StatusThrottled
		}
	}
	s.Windows = []Window{w}
	return s, nil
}

// --- Warp ---------------------------------------------------------------------------

// warpQuery is the read-only request limit query Warp's own app sends.
const warpQuery = `query GetRequestLimitInfo($requestContext: RequestContext!) { user(requestContext: $requestContext) { __typename ... on UserOutput { user { requestLimitInfo { isUnlimited nextRefreshTime requestLimit requestsUsedSinceLastRefresh } bonusGrants { requestCreditsGranted requestCreditsRemaining expiration } workspaces { bonusGrantsInfo { grants { requestCreditsGranted requestCreditsRemaining expiration } } } } } } }`

func planWarp(in PlanInput) ([]Request, error) {
	body, err := json.Marshal(map[string]any{
		"query":         warpQuery,
		"variables":     map[string]any{"requestContext": map[string]any{"clientContext": map[string]any{}, "osContext": map[string]any{}}},
		"operationName": "GetRequestLimitInfo",
	})
	if err != nil {
		return nil, fmt.Errorf("planlimits.planWarp: %w", err)
	}
	return laPlan(in, SecretKey, AuthBearer, "", laReq{
		key: "main", method: "POST", url: "https://app.warp.dev/graphql/v2?op=GetRequestLimitInfo", body: body,
		// No x-warp-client-id or Warp user agent: Observer identifies as
		// itself, never as Warp's app. Warp may rate limit that (a 429 maps
		// to backoff), which is the honest outcome.
	})
}

// ParseWarp maps the request limit info: credits used of the cycle's limit
// (the fields say "request", Warp bills them as credits) plus bonus grants.
func ParseWarp(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if errs := j.At("errors").Arr(); len(errs) > 0 {
		msg := strings.ToLower(laStr(errs[0], "message"))
		if msg == "" {
			msg, _ = errs[0].Str()
			msg = strings.ToLower(msg)
		}
		if strings.Contains(msg, "unauthor") || strings.Contains(msg, "unauthent") {
			return Snapshot{}, fmt.Errorf("%w: warp %s", ErrAuth, msg)
		}
		return Snapshot{}, shapeErr("warp error "+msg, nil)
	}
	u := j.At("data.user.user")
	info := u.At("requestLimitInfo")
	if !info.Exists() {
		if tn := laStr(j, "data.user.__typename"); tn != "" && tn != "UserOutput" {
			return Snapshot{}, fmt.Errorf("%w: warp %s", ErrAuth, tn)
		}
		return Snapshot{}, shapeErr("warp: requestLimitInfo missing", nil)
	}
	s := newSnap("warp", SourceWarp, KindUndocumented, ConfExact, now)
	if unl, _ := info.At("isUnlimited").Bool(); unl {
		s.Status = StatusUnmetered
	} else if w, ok := AmountWindow("cycle", UnitCredits, info.At("requestsUsedSinceLastRefresh").NumP(),
		info.At("requestLimit").NumP(), nil, info.At("nextRefreshTime").Time(), 0); ok {
		s.Windows = append(s.Windows, w)
	}
	grants := u.At("bonusGrants").Arr()
	for _, ws := range u.At("workspaces").Arr() {
		grants = append(grants, ws.At("bonusGrantsInfo.grants").Arr()...)
	}
	var granted, left float64
	for _, g := range grants {
		a, aok := g.At("requestCreditsGranted").Num()
		r, rok := g.At("requestCreditsRemaining").Num()
		if aok && rok {
			granted += a
			left += r
		}
	}
	if granted > 0 {
		s.Balances = append(s.Balances, Balance{Kind: "credits", Unit: UnitCredits, Amount: laInt(left)},
			Balance{Kind: "granted_total", Unit: UnitCredits, Amount: laInt(granted)})
	}
	if s.Status == StatusOK {
		return laDone(s, "warp")
	}
	return s, nil
}

// --- DeepInfra -------------------------------------------------------------------

func planDeepInfra(in PlanInput) ([]Request, error) {
	return laPlan(in, SecretKey, AuthBearer, "",
		laReq{key: "checklist", url: "https://api.deepinfra.com/payment/checklist?compute_owed=true"},
		laReq{key: "usage", url: "https://api.deepinfra.com/payment/usage?from=current", optional: true},
	)
}

// DeepInfraChecklist maps the payment checklist (USD dollars). stripe_balance
// is the account ledger (negative = prepaid funds) and recent the cycle's
// spend not yet posted, so what is left is -(stripe_balance + recent).
func DeepInfraChecklist(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	ledger, lok := j.At("stripe_balance").Num()
	recent, rok := j.At("recent").Num()
	if !lok || !rok {
		return Snapshot{}, shapeErr("deepinfra checklist", nil)
	}
	s := newSnap("deepinfra", SourceDeepInfra, KindUndocumented, ConfExact, now)
	left := -(ledger + max(recent, 0))
	s.Balances = []Balance{{Kind: "available", Unit: UnitUSDMicros, Amount: microsFromFloat(left)}}
	s.Spend = []Spend{{Period: "cycle", Unit: UnitUSDMicros, Amount: microsFromFloat(recent), Scope: "account"}}
	if lim, ok := j.At("limit").Num(); ok && lim > 0 {
		if w, ok := AmountWindow("spend_limit", UnitUSDMicros, laMoney(&recent), laMoney(&lim), nil, nil, 0); ok {
			s.Windows = append(s.Windows, w)
		}
	}
	// A negative "available" is an amount owed, normal for a card-billed
	// account; only a suspension stops calls.
	if sus, _ := j.At("suspended").Bool(); sus {
		s.Status = StatusThrottled
	}
	return s, nil
}

func parseDeepInfra(in ParseInput) (Snapshot, error) {
	body, err := need(in, "checklist")
	if err != nil {
		return Snapshot{}, err
	}
	s, err := DeepInfraChecklist(body, in.Now)
	if err != nil {
		return s, err
	}
	if j, ok := laOpt(in, "usage"); ok {
		if months := j.At("months").Arr(); len(months) > 0 {
			if c, ok := months[len(months)-1].At("total_cost").Micros(2); ok {
				s.Spend = append(s.Spend, Spend{Period: "month", Unit: UnitUSDMicros, Amount: c, Scope: "account"})
			}
		}
	}
	return s, nil
}

// --- Codebuff -----------------------------------------------------------------------

func planCodebuff(in PlanInput) ([]Request, error) {
	return laPlan(in, SecretKey, AuthBearer, "",
		laReq{key: "main", method: "POST", url: "https://www.codebuff.com/api/v1/usage", body: []byte(`{"fingerprintId":"superbased-observer-usage"}`)},
		laReq{key: "subscription", url: "https://www.codebuff.com/api/user/subscription", optional: true},
	)
}

// ParseCodebuffUsage maps the credit usage body (credits, never money).
func ParseCodebuffUsage(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	s := newSnap("codebuff", SourceCodebuff, KindUndocumented, ConfExact, now)
	used := laNumP(j, "usage", "used")
	lim := laNumP(j, "quota", "limit")
	rem := laNumP(j, "remainingBalance", "remaining")
	if lim != nil && *lim <= 0 {
		lim = nil
	}
	if w, ok := AmountWindow("cycle", UnitCredits, used, lim, rem, j.At("next_quota_reset").Time(), 0); ok {
		s.Windows = append(s.Windows, w)
	}
	if rem != nil {
		s.Balances = append(s.Balances, Balance{Kind: "credits", Unit: UnitCredits, Amount: laInt(*rem)})
		if *rem <= 0 {
			s.Status = StatusThrottled
		}
	}
	return laDone(s, "codebuff")
}

func parseCodebuff(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	s, err := ParseCodebuffUsage(body, in.Now)
	if err != nil {
		return s, err
	}
	if j, ok := laOpt(in, "subscription"); ok {
		s.PlanLabel = SanitizeLabel(laStr(j, "subscription.displayName", "displayName", "subscription.tier", "tier"))
		if w, ok := AmountWindow("weekly", UnitCredits, laNumP(j, "rateLimit.weeklyUsed", "rateLimit.used"),
			laNumP(j, "rateLimit.weeklyLimit", "rateLimit.limit"), nil, j.At("rateLimit.weeklyResetsAt").Time(), 7*24*time.Hour); ok && w.Limit != nil && *w.Limit > 0 {
			laAdd(&s, w)
		}
	}
	return s, nil
}

// --- Venice -------------------------------------------------------------------------

// ParseVenice maps the API balance: USD and DIEM balances (DIEM is Venice's
// own unit, kept as credits) and the DIEM allocation per epoch.
func ParseVenice(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	can, ok := j.At("canConsume").Bool()
	if !ok || j.At("balances").Keys() == nil {
		return Snapshot{}, shapeErr("venice balance", nil)
	}
	s := newSnap("venice", SourceVenice, KindUndocumented, ConfExact, now)
	if m, ok := j.At("balances.usd").Micros(0); ok {
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: m})
	}
	if d, ok := j.At("balances.diem").Num(); ok {
		s.Balances = append(s.Balances, Balance{Kind: "credits", Unit: UnitCredits, Amount: laInt(d)})
		if alloc, ok := j.At("diemEpochAllocation").Num(); ok && alloc > 0 {
			if w, ok := AmountWindow("diem_epoch", UnitCredits, nil, F(alloc), F(d), nil, 0); ok {
				s.Windows = append(s.Windows, w)
			}
		}
	}
	if !can {
		s.Status = StatusThrottled
		return s, nil
	}
	return laDone(s, "venice")
}

// --- Command Code ---------------------------------------------------------------------

func planCommandCode(in PlanInput) ([]Request, error) {
	return laPlan(in, SecretKey, AuthBearer, "",
		laReq{key: "main", url: "https://api.commandcode.ai/alpha/billing/credits"},
		laReq{key: "subscription", url: "https://api.commandcode.ai/alpha/billing/subscriptions", optional: true},
	)
}

// commandCodePlans names the plan ids Command Code publishes on its pricing page.
var commandCodePlans = map[string]string{
	"individual-go": "Go", "individual-go-v1": "Go", "individual-goat": "GOAT", "individual-pro": "Pro",
	"individual-pro-v1": "Pro", "individual-max": "Max", "individual-ultra": "Ultra",
}

// ParseCommandCodeCredits maps the credits body: the monthly grant LEFT and
// top-ups in dollars, plus the rolling five-hour and weekly caps (their unit
// is not stated, so they stay credits).
func ParseCommandCodeCredits(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	monthly, ok := j.At("credits.monthlyCredits").Num()
	if !ok {
		return Snapshot{}, shapeErr("command code: monthlyCredits", nil)
	}
	s := newSnap("command_code", SourceCommandCode, KindUndocumented, ConfExact, now)
	granted := j.At("credits.monthlyCreditsGranted").NumP()
	if w, ok := AmountWindow("monthly", UnitUSDMicros, nil, laMoney(granted), laMoney(F(max(monthly, 0))), nil, 0); ok {
		s.Windows = append(s.Windows, w)
	}
	purchased := j.At("credits.purchasedCredits").NumP()
	if purchased != nil {
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: microsFromFloat(*purchased)})
	}
	wl := j.First("windowLimits", "credits.windowLimits")
	for _, w := range []struct {
		in, key string
		length  time.Duration
	}{{"fiveHour", "5h", 5 * time.Hour}, {"weekly", "weekly", 7 * 24 * time.Hour}} {
		o := wl.At(w.in)
		lim, used := o.At("cap").NumP(), o.At("used").NumP()
		if lim == nil || *lim <= 0 {
			continue
		}
		if win, ok := AmountWindow(w.key, UnitCredits, used, lim, nil, o.At("resetAt").Time(), w.length); ok {
			win.Rolling = true
			laAdd(&s, win)
		}
	}
	if monthly <= 0 && (purchased == nil || *purchased <= 0) {
		s.Status = StatusThrottled
	}
	return laDone(s, "command code")
}

func parseCommandCode(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	s, err := ParseCommandCodeCredits(body, in.Now)
	if err != nil {
		return s, err
	}
	if j, ok := laOpt(in, "subscription"); ok {
		if okv, _ := j.At("success").Bool(); okv {
			if id := laStr(j, "data.planId"); id != "" {
				s.PlanCode = SanitizeLabel(id)
				s.PlanLabel = commandCodePlans[id]
			} else if !j.At("data").Exists() {
				s.PlanCode = "free"
			}
		}
	}
	return s, nil
}

// --- Poe --------------------------------------------------------------------------------

// ParsePoe maps the current point balance (Poe points, never money).
func ParsePoe(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	p, ok := j.At("current_point_balance").Num()
	if !ok {
		return Snapshot{}, shapeErr("poe: current_point_balance", nil)
	}
	s := newSnap("poe", SourcePoe, KindUndocumented, ConfExact, now)
	s.Balances = []Balance{{Kind: "points", Unit: UnitPoints, Amount: laInt(p)}}
	if p <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- Chutes ----------------------------------------------------------------------------

// chutesNamed binds the window names Chutes uses to keys, for a window that
// does not declare its length.
var chutesNamed = map[string]string{
	"monthly": "monthly", "subscription_usage": "monthly", "billing_period": "monthly",
	"rolling": "4h", "rolling_window": "4h", "rolling_4h": "4h", "four_hour": "4h", "window_4h": "4h",
}

// chutesUnits maps the unit a Chutes window names.
var chutesUnits = map[string]Unit{"credits": UnitCredits, "requests": UnitRequests, "tokens": UnitTokens}

// ParseChutes maps the subscription usage body: every object carrying a
// limit and a use, keyed by its declared length or its documented name.
func ParseChutes(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	root := j
	if d := j.At("data"); d.Keys() != nil {
		root = d
	}
	s := newSnap("chutes", SourceChutes, KindUndocumented, ConfExact, now)
	sub := root.At("subscription")
	s.PlanLabel = SanitizeLabel(laStr(sub, "plan_name", "plan", "tier"))
	if active, ok := sub.At("active").Bool(); ok && !active {
		return Snapshot{}, fmt.Errorf("%w: no active Chutes subscription", ErrNotApplicable)
	}
	for _, name := range root.Keys() {
		o := root.At(name)
		if name == "subscription" || o.Keys() == nil {
			continue
		}
		lim := laNumP(o, "limit", "cap", "max", "quota", "total")
		used := laNumP(o, "used", "usage", "requests", "tokens")
		rem := laNumP(o, "remaining", "available")
		mins, _ := laNum(o, "window_minutes", "windowMinutes")
		if h, ok := laNum(o, "window_hours", "windowHours"); ok {
			mins = h * 60
		}
		if d, ok := laNum(o, "window_days", "windowDays"); ok {
			mins = d * 1440
		}
		key := laKeyForMinutes(int64(mins))
		if key == "" {
			key = chutesNamed[name]
		}
		if key == "" {
			key = "quota:" + laSlugKey(name)
		}
		unit := chutesUnits[strings.ToLower(laStr(o, "unit"))]
		if unit == "" {
			unit = UnitCredits
		}
		reset := laTime(o, "reset_at", "resets_at", "current_period_end")
		if w, ok := AmountWindow(key, unit, used, lim, rem, reset, time.Duration(mins)*time.Minute); ok && w.Limit != nil {
			w.Rolling = mins > 0 && mins < 1440
			laAdd(&s, w)
		} else if p, ok := laNum(o, "percent_used", "used_percent", "utilization"); ok {
			if p < 1 {
				p *= 100
			}
			laAdd(&s, laPct(key, p, reset, time.Duration(mins)*time.Minute))
		}
	}
	return laDone(s, "chutes")
}

// --- Neuralwatt -----------------------------------------------------------------------

// ParseNeuralwatt maps the quota body: the prepaid balance in dollars, the
// subscription's included energy (kWh) per billing period, a per-key dollar
// allowance and this month's spend.
func ParseNeuralwatt(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	bal := j.At("balance")
	if bal.Keys() == nil {
		return Snapshot{}, shapeErr("neuralwatt: balance missing", nil)
	}
	s := newSnap("neuralwatt", SourceNeuralwatt, KindUndocumented, ConfExact, now)
	if m, ok := bal.At("credits_remaining_usd").Micros(0); ok {
		s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: UnitUSDMicros, Amount: m})
	}
	if m, ok := bal.At("total_credits_usd").Micros(0); ok && m > 0 {
		s.Balances = append(s.Balances, Balance{Kind: "purchased", Unit: UnitUSDMicros, Amount: m})
	}
	if sub := j.At("subscription"); sub.Keys() != nil {
		plan := laStr(sub, "plan")
		s.PlanCode = SanitizeLabel(strings.ToLower(plan))
		s.PlanLabel = laTitle(plan)
		start, end := sub.At("current_period_start").Time(), sub.At("current_period_end").Time()
		var length time.Duration
		if start != nil && end != nil && end.After(*start) {
			length = end.Sub(*start)
		}
		inc := sub.At("kwh_included").NumP()
		if inc != nil && *inc > 0 {
			if w, ok := AmountWindow("cycle", UnitKWh, sub.At("kwh_used").NumP(), inc, sub.At("kwh_remaining").NumP(), end, length); ok {
				s.Windows = append(s.Windows, w)
			}
		}
	}
	allow := j.At("key.allowance")
	if lim := allow.At("limit_usd").NumP(); lim != nil && *lim > 0 {
		if w, ok := AmountWindow("key_cap", UnitUSDMicros, laMoney(allow.At("spent_usd").NumP()), laMoney(lim),
			laMoney(allow.At("remaining_usd").NumP()), nil, 0); ok {
			s.Windows = append(s.Windows, w)
		}
	}
	if blocked, _ := allow.At("blocked").Bool(); blocked {
		s.Status = StatusThrottled
	}
	if m, ok := j.At("usage.current_month.cost_usd").Micros(0); ok {
		s.Spend = append(s.Spend, Spend{Period: "month", Unit: UnitUSDMicros, Amount: m, Scope: "account"})
	}
	if s.Status == StatusOK {
		return laDone(s, "neuralwatt")
	}
	return s, nil
}

// --- ZenMux --------------------------------------------------------------------------

func planZenMux(in PlanInput) ([]Request, error) {
	return laPlan(in, SecretMgmt, AuthBearer, "",
		laReq{key: "main", url: "https://zenmux.ai/api/v1/management/subscription/detail"},
		laReq{key: "payg", url: "https://zenmux.ai/api/v1/management/payg/balance", optional: true},
	)
}

// zenmuxQuotas are the documented quota objects and their lengths.
var zenmuxQuotas = []struct {
	in, key string
	length  time.Duration
}{{"quota_5_hour", "5h", 5 * time.Hour}, {"quota_7_day", "weekly", 7 * 24 * time.Hour}}

// ParseZenMuxSubscription maps the documented subscription detail:
// usage_percentage is a 0..1 used fraction per window.
func ParseZenMuxSubscription(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if ok, _ := j.At("success").Bool(); !ok || !j.At("data").Exists() {
		return Snapshot{}, shapeErr("zenmux subscription", nil)
	}
	d := j.At("data")
	s := newSnap("zenmux", SourceZenMux, KindAdminAPI, ConfExact, now)
	if tier := laStr(d, "plan.tier"); tier != "" {
		s.PlanCode = SanitizeLabel(strings.ToLower(tier))
		s.PlanLabel = laTitle(tier)
	}
	for _, q := range zenmuxQuotas {
		o := d.At(q.in)
		f, ok := o.At("usage_percentage").Num()
		if !ok {
			return Snapshot{}, shapeErr("zenmux "+q.in, nil)
		}
		laAdd(&s, laPct(q.key, f*100, o.At("resets_at").Time(), q.length))
	}
	return s, nil
}

func parseZenMux(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	s, err := ParseZenMuxSubscription(body, in.Now)
	if err != nil {
		return s, err
	}
	if r, ok := in.Responses["payg"]; ok && (r.Status == 401 || r.Status == 403) {
		return Snapshot{}, fmt.Errorf("%w: zenmux http %d", ErrAuth, r.Status)
	}
	if j, ok := laOpt(in, "payg"); ok {
		if okv, _ := j.At("success").Bool(); okv {
			if u := CurrencyUnit(laStr(j, "data.currency")); u != "" {
				if m, ok := j.At("data.total_credits").Micros(0); ok {
					s.Balances = append(s.Balances, Balance{Kind: "prepaid", Unit: u, Amount: m})
				}
			}
		}
	}
	return s, nil
}

// --- ai& -------------------------------------------------------------------------------

// ParseAiAnd maps one page of the documented request logs (last 30 days,
// newest first) onto spend in the first row's currency. When the vendor says
// more rows exist the sum covers only this page and is marked estimated.
func ParseAiAnd(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	rows := j.At("data")
	if rows.Arr() == nil && !rows.Exists() {
		return Snapshot{}, shapeErr("aiand: data missing", nil)
	}
	s := newSnap("aiand", SourceAiAnd, KindOfficialAPI, ConfExact, now)
	if more, _ := j.At("has_more").Bool(); more {
		s.Confidence = ConfEstimated
	}
	var unit Unit
	var sum int64
	for _, r := range rows.Arr() {
		u := CurrencyUnit(laStr(r, "currency"))
		m, ok := r.At("cost").Micros(0)
		if u == "" || !ok {
			continue
		}
		if unit == "" {
			unit = u
		}
		if u == unit {
			sum += m
		}
	}
	if unit == "" {
		s.Status = StatusUnmetered // no priced request in the last 30 days
		return s, nil
	}
	s.Spend = []Spend{{Period: "30d", Unit: unit, Amount: sum, Scope: "account"}}
	return s, nil
}

// --- IBM Bob -----------------------------------------------------------------------------

// ibmBobAuth picks Bob's own scheme: a JWT rides as Bearer, an API key as
// "Apikey <key>".
func ibmBobAuth(k string) map[string]string {
	if _, _, ok := jwtClaims(k); ok {
		return bearer(k)
	}
	return map[string]string{"Authorization": "Apikey " + k}
}

func planIBMBob(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretKey)
	if err != nil {
		return nil, err
	}
	return []Request{{
		Key: "main", Kind: ReqHTTP, Method: "GET", URL: "https://api.us-east.bob.ibm.com/admin/v1/profile",
		Header: map[string]string{"Accept": "application/json"}, SecretHeaders: ibmBobAuth(k),
	}}, nil
}

// ParseIBMBob maps the profile: Bobcoins used of each team's monthly budget,
// summed across teams (a negative budget is unlimited, so then no limit).
func ParseIBMBob(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	inst := j.At("instances").Arr()
	if inst == nil {
		return Snapshot{}, shapeErr("ibm bob: instances missing", nil)
	}
	s := newSnap("ibm_bob", SourceIBMBob, KindUndocumented, ConfExact, now)
	var used, limit float64
	limited, teams := true, 0
	var reset *time.Time
	plans := map[string]bool{}
	for _, in := range inst {
		if p := laStr(in, "plan_name"); p != "" {
			plans[p] = true
		}
		if t := in.At("refresh_at").Time(); t != nil && (reset == nil || t.Before(*reset)) {
			reset = t
		}
		for _, t := range in.At("teams").Arr() {
			u, ok := t.At("usage").Num()
			if !ok {
				continue
			}
			teams++
			used += max(u, 0)
			if l, ok := t.At("budget_limit").Num(); ok && l >= 0 {
				limit += l
			} else {
				limited = false
			}
		}
	}
	if teams == 0 {
		return Snapshot{}, fmt.Errorf("%w: no IBM Bob team", ErrNotApplicable)
	}
	names := make([]string, 0, len(plans))
	for p := range plans {
		names = append(names, p)
	}
	sort.Strings(names)
	s.PlanLabel = SanitizeLabel(strings.Join(names, ", "))
	var lim *float64
	if limited && limit > 0 {
		lim = &limit
	}
	w, _ := AmountWindow("monthly", UnitCredits, &used, lim, nil, reset, 0)
	s.Windows = []Window{w}
	if lim != nil && used >= limit {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- Hugging Face ----------------------------------------------------------------------

func planHuggingFace(in PlanInput) ([]Request, error) {
	now := in.Now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	q := fmt.Sprintf("?startDate=%d&endDate=%d", start.Unix(), now.Unix())
	return laPlan(in, SecretKey, AuthBearer, "",
		laReq{key: "main", url: "https://huggingface.co/api/settings/billing/usage-v2" + q},
		laReq{key: "zerogpu", url: "https://huggingface.co/api/spaces/zero-gpu/quota", optional: true},
	)
}

// ParseHuggingFaceBilling maps this month's inference usage (nano dollars):
// the included credit used and left, and the billable amount beyond it.
func ParseHuggingFaceBilling(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	ip := j.At("usage.inferenceProviders")
	used, uok := ip.At("usedNanoUsd").Num()
	inc, iok := ip.At("includedNanoUsd").Num()
	if !uok || !iok || used < 0 || inc < 0 {
		return Snapshot{}, shapeErr("hugging face billing", nil)
	}
	nano := func(v float64) int64 { return int64(v / 1000) }
	s := newSnap("hugging_face", SourceHuggingFace, KindUndocumented, ConfExact, now)
	billable := max(used-inc, 0)
	s.Spend = []Spend{{Period: "month", Unit: UnitUSDMicros, Amount: nano(billable), Scope: "account"}}
	if inc > 0 {
		w, _ := AmountWindow("monthly:included", UnitUSDMicros, F(float64(nano(min(used, inc)))), F(float64(nano(inc))), nil, nil, 0)
		s.Windows = append(s.Windows, w)
	}
	if lim, ok := ip.At("limitNanoUsd").Num(); ok && lim > 0 {
		w, _ := AmountWindow("spend_limit", UnitUSDMicros, F(float64(nano(billable))), F(float64(nano(lim))), nil, nil, 0)
		s.Windows = append(s.Windows, w)
	}
	return s, nil
}

func parseHuggingFace(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	s, err := ParseHuggingFaceBilling(body, in.Now)
	if err != nil {
		return s, err
	}
	if j, ok := laOpt(in, "zerogpu"); ok {
		base, bok := j.At("base").Num()
		cur, cok := j.At("current").Num()
		if bok && cok && base > 0 {
			if w, ok := AmountWindow("zero_gpu", UnitHours, nil, F(base/3600), F(cur/3600), j.At("resetsAt").Time(), 0); ok {
				laAdd(&s, w)
			}
		}
	}
	return s, nil
}

// --- v0 ----------------------------------------------------------------------------------

func planV0(in PlanInput) ([]Request, error) {
	q := ""
	if p := strings.TrimSpace(in.Params["project_id"]); p != "" {
		q = "?scope=" + url.QueryEscape(p)
	}
	return laPlan(in, SecretKey, AuthBearer, "",
		laReq{key: "main", url: "https://api.v0.dev/v1/user/billing" + q},
		laReq{key: "rate", url: "https://api.v0.dev/v1/rate-limits" + q, optional: true},
	)
}

// v0Window maps a {limit, remaining, reset} block.
func v0Window(key string, unit Unit, o J) (Window, bool) {
	lim := o.At("limit").NumP()
	if lim == nil || *lim < 0 {
		return Window{}, false
	}
	return AmountWindow(key, unit, nil, lim, o.At("remaining").NumP(), o.At("reset").Time(), 0)
}

// ParseV0Billing maps the documented billing body: the cycle's credit
// balance (token billing) or the legacy limit block, plus the on-demand
// balance, which is never added to the allowance.
func ParseV0Billing(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	s := newSnap("v0", SourceV0, KindOfficialAPI, ConfExact, now)
	d := j.At("data")
	switch laStr(j, "billingType") {
	case "token":
		tot, tok := d.At("balance.total").Num()
		rem, rok := d.At("balance.remaining").Num()
		if !tok || !rok || tot < 0 {
			return Snapshot{}, shapeErr("v0 token balance", nil)
		}
		if w, ok := AmountWindow("cycle", UnitCredits, nil, F(tot), F(rem), d.At("billingCycle.end").Time(), 0); ok {
			s.Windows = append(s.Windows, w)
		}
		if od, ok := d.At("onDemand.balance").Num(); ok {
			s.Balances = append(s.Balances, Balance{Kind: "on_demand", Unit: UnitCredits, Amount: laInt(od)})
		}
	case "legacy":
		w, ok := v0Window("cycle", UnitCredits, d)
		if !ok {
			return Snapshot{}, shapeErr("v0 legacy billing", nil)
		}
		s.Windows = append(s.Windows, w)
	default:
		return Snapshot{}, shapeErr("v0 billingType", nil)
	}
	return laDone(s, "v0")
}

func parseV0(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	s, err := ParseV0Billing(body, in.Now)
	if err != nil {
		return s, err
	}
	if j, ok := laOpt(in, "rate"); ok {
		if w, ok := v0Window("rate_limit", UnitRequests, j); ok {
			laAdd(&s, w)
		}
	}
	return s, nil
}
