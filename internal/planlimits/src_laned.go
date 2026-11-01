package planlimits

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// src_laned.go holds lane D of the provider catalogue: vendor-local apps,
// vendor CLIs, organisation admin APIs and cloud billing. Endpoint names,
// field names and units were taken as facts from CodexBar (MIT, discovery
// only) and from the vendors' own documentation named in each DocURL; the Go
// here is ours.
//
// Providers in this lane with no source carry a Gap in catalog.go instead:
// azure_openai (only a paid deployment probe exists), gemini (Google ended
// the CLI sign-in for individual plans), antigravity (needs the running
// language server or a CLI print mode that may open a browser), vertex_ai
// (needs gcloud to mint an access token) and pi (no plan exists; Observer
// already captures Pi sessions).

// Lane D provider ids (rows in catalog.go).
const (
	ProviderOpenAIAPI    = "openai_api"
	ProviderAnthropicAPI = "anthropic_api"
	ProviderAWSBedrock   = "aws_bedrock"
	ProviderGrok         = "grok"
	ProviderJetBrainsAI  = "jetbrains_ai"
	ProviderNousPortal   = "nous_portal"
	ProviderMuseCode     = "muse_code"
	ProviderCodeRabbit   = "coderabbit"
	ProviderDoubao       = "doubao"
)

// Lane D source ids.
const (
	SourceOpenAIAdmin    = "openai_api.admin"
	SourceOpenAIGrants   = "openai_api.credit_grants"
	SourceAnthropicAdmin = "anthropic_api.admin"
	SourceBedrockBudget  = "aws_bedrock.budget"
	SourceGrokAgent      = "grok.agent"
	SourceJetBrainsQuota = "jetbrains_ai.quota_file"
	SourceNousHermes     = "nous_portal.hermes"
	SourceMuseWeb        = "muse_code.web"
	SourceCodeRabbitCLI  = "coderabbit.cli"
	SourceDoubaoArkcli   = "doubao.arkcli"
)

// jetBrainsQuotaRelPath is the IDE quota file under the per-OS config
// directory. The product and version directory ("IntelliJIdea2026.2")
// differs per install, so the "*" segment needs planlimitslocal to pick the
// most recently modified match (requested from the lead lane; until then the
// read reports the file as not found).
const jetBrainsQuotaRelPath = "JetBrains/*/options/AIAssistantQuotaManager2.xml"

func init() {
	addSources(
		SourceDef{
			ID: SourceOpenAIAdmin, Provider: ProviderOpenAIAPI, Kind: KindAdminAPI, Order: 20,
			Secrets: []SecretSpec{{Key: SecretMgmt, Required: true}},
			Params:  []ParamSpec{{Key: "project_id"}},
			Hosts:   []string{"api.openai.com"}, MinInterval: 30 * time.Minute,
			DocURL: "https://platform.openai.com/docs/api-reference/usage/costs",
		},
		SourceDef{
			ID: SourceOpenAIGrants, Provider: ProviderOpenAIAPI, Kind: KindUndocumented, Order: 50,
			Secrets: []SecretSpec{{Key: SecretKey, Required: true}},
			Hosts:   []string{"api.openai.com"}, MinInterval: 30 * time.Minute,
		},
		SourceDef{
			ID: SourceAnthropicAdmin, Provider: ProviderAnthropicAPI, Kind: KindAdminAPI, Order: 20,
			Secrets: []SecretSpec{{Key: SecretMgmt, Required: true}},
			Hosts:   []string{"api.anthropic.com"}, MinInterval: 30 * time.Minute,
			DocURL: "https://docs.claude.com/en/api/admin-api/usage-cost/get-cost-report",
		},
		SourceDef{
			ID: SourceBedrockBudget, Provider: ProviderAWSBedrock, Kind: KindAdminAPI, Order: 20,
			Secrets: []SecretSpec{{Key: SecretAWS, Required: true}},
			Params: []ParamSpec{
				{Key: "access_key_id", Required: true},
				{Key: "account_id", Required: true},
				{Key: "budget_name", Required: true},
			},
			Hosts: []string{"budgets.amazonaws.com"}, MinInterval: time.Hour,
			DocURL: "https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_budgets_DescribeBudget.html",
		},
		SourceDef{
			ID: SourceGrokAgent, Provider: ProviderGrok, Kind: KindVendorRPC, Command: "grok", Order: 20,
			MinInterval: 10 * time.Minute,
			DocURL:      "https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-shell/src/extensions/billing.rs",
		},
		SourceDef{
			ID: SourceJetBrainsQuota, Provider: ProviderJetBrainsAI, Kind: KindLocalState, Order: 50,
			MinInterval: 5 * time.Minute,
			Local:       []LocalSpec{{Key: "quota", Kind: LocalFile, Base: BaseConfig, Rel: jetBrainsQuotaRelPath}},
		},
		SourceDef{
			ID: SourceNousHermes, Provider: ProviderNousPortal, Kind: KindBorrowedToken, Order: 50,
			Hosts: []string{"portal.nousresearch.com"}, MinInterval: 10 * time.Minute,
			Local: []LocalSpec{{Key: "auth", Kind: LocalFile, Base: BaseHome, Rel: ".hermes/auth.json"}},
		},
		SourceDef{
			ID: SourceMuseWeb, Provider: ProviderMuseCode, Kind: KindBrowser, Order: 70,
			Secrets: []SecretSpec{{Key: SecretSession, Required: true}},
			Params:  []ParamSpec{{Key: "team_id", Required: true}},
			Hosts:   []string{"dev.meta.ai"}, MinInterval: 10 * time.Minute,
		},
		SourceDef{
			ID: SourceCodeRabbitCLI, Provider: ProviderCodeRabbit, Kind: KindVendorCLI, Command: "coderabbit", Order: 20,
			MinInterval: 30 * time.Minute, DocURL: "https://docs.coderabbit.ai/cli/reference#usage-command",
		},
		SourceDef{
			ID: SourceDoubaoArkcli, Provider: ProviderDoubao, Kind: KindVendorCLI, Command: "arkcli", Order: 20,
			MinInterval: 10 * time.Minute,
		},
	)
	register(SourceOpenAIAdmin, Driver{Plan: planOpenAIAdmin, Parse: parseOpenAIAdmin})
	register(SourceOpenAIGrants, Driver{
		Plan:  keyedGET("https://api.openai.com/v1/dashboard/billing/credit_grants", SecretKey, AuthBearer, "", nil),
		Parse: parseOpenAIGrants,
	})
	register(SourceAnthropicAdmin, Driver{Plan: planAnthropicAdmin, Parse: parseAnthropicAdmin})
	register(SourceBedrockBudget, Driver{Plan: planBedrockBudget, Parse: parseBedrockBudget})
	register(SourceGrokAgent, Driver{Converse: converseGrok, Argv: GrokAgentArgv})
	register(SourceJetBrainsQuota, Driver{Plan: func(PlanInput) ([]Request, error) { return nil, nil }, Parse: parseJetBrains})
	register(SourceNousHermes, Driver{Plan: planNous, Parse: parseNous})
	register(SourceMuseWeb, Driver{Plan: planMuseWeb, Parse: parseMuseWeb})
	register(SourceCodeRabbitCLI, cliDriver([]string{"coderabbit", "usage"}, 15*time.Second, []string{"NO_COLOR=1"}, ParseCodeRabbitUsage))
	register(SourceDoubaoArkcli, cliDriver([]string{"arkcli", "usage", "plan", "--format", "json"}, 15*time.Second, []string{"NO_COLOR=1"}, ParseArkcliUsage))
}

// --- shared lane D helpers -------------------------------------------------------

// ldPeriodRule classifies a declared window length into a window key.
type ldPeriodRule struct {
	maxMinutes int64
	key        string
}

// ldPeriodTable is walked top-down: the first rule whose bound holds wins.
var ldPeriodTable = []ldPeriodRule{
	{6 * 60, "5h"},
	{26 * 60, "daily"},
	{8 * 24 * 60, "weekly"},
	{35 * 24 * 60, "monthly"},
}

// ldPeriodKey returns the window key for a declared length in minutes;
// "cycle" when the length is unknown or longer than a month.
func ldPeriodKey(minutes int64) string {
	if minutes <= 0 {
		return "cycle"
	}
	for _, r := range ldPeriodTable {
		if minutes <= r.maxMinutes {
			return r.key
		}
	}
	return "cycle"
}

// ldMonthStart is the first instant of now's UTC month.
func ldMonthStart(now time.Time) time.Time {
	n := now.UTC()
	return time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// ldCostItem is one amount in one currency inside a cost bucket.
type ldCostItem struct {
	unit   Unit
	micros int64
}

// ldCostBucket is one daily cost bucket of an admin cost report.
type ldCostBucket struct {
	start, end *time.Time
	items      []ldCostItem
}

// ldSpendFromBuckets sums month-to-date and today's spend per currency. A
// report with buckets but no line items is a known zero in US dollars.
func ldSpendFromBuckets(buckets []ldCostBucket, now time.Time, scope string) []Spend {
	month, day := map[Unit]int64{}, map[Unit]int64{}
	for _, b := range buckets {
		today := b.start != nil && b.end != nil && !now.Before(*b.start) && now.Before(*b.end)
		for _, it := range b.items {
			month[it.unit] += it.micros
			if today {
				day[it.unit] += it.micros
			}
		}
	}
	if len(month) == 0 {
		month[UnitUSDMicros] = 0
	}
	units := make([]string, 0, len(month))
	for u := range month {
		units = append(units, string(u))
	}
	sort.Strings(units)
	var out []Spend
	for _, u := range units {
		out = append(out, Spend{Period: "month", Unit: Unit(u), Amount: month[Unit(u)], Scope: scope})
		if v, ok := day[Unit(u)]; ok {
			out = append(out, Spend{Period: "day", Unit: Unit(u), Amount: v, Scope: scope})
		}
	}
	return out
}

// --- OpenAI API: organisation costs (Admin API) -----------------------------------

var openAIProjectRe = regexp.MustCompile(`^proj_[A-Za-z0-9]{1,64}$`)

func planOpenAIAdmin(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretMgmt)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("start_time", strconv.FormatInt(ldMonthStart(in.Now).Unix(), 10))
	q.Set("bucket_width", "1d")
	q.Set("limit", "31")
	if p := strings.TrimSpace(in.Params["project_id"]); p != "" {
		if !openAIProjectRe.MatchString(p) {
			return nil, errors.New("planlimits: invalid OpenAI project id")
		}
		q.Set("project_ids", p)
	}
	return []Request{{
		Key: "costs", Kind: ReqHTTP, Method: "GET", URL: "https://api.openai.com/v1/organization/costs?" + q.Encode(),
		Header: map[string]string{"Accept": "application/json"}, SecretHeaders: bearer(k),
	}}, nil
}

// ParseOpenAICosts maps GET /v1/organization/costs (daily buckets from the
// start of the month). amount.value is in whole currency units. OpenAI
// reports spend only, so the card is used-only.
func ParseOpenAICosts(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	data := j.At("data")
	if !data.Exists() || data.Arr() == nil {
		return Snapshot{}, shapeErr("openai costs: no data", nil)
	}
	if more, _ := j.At("has_more").Bool(); more {
		return Snapshot{}, shapeErr("openai costs: more pages than one month", nil)
	}
	var buckets []ldCostBucket
	for _, b := range data.Arr() {
		cb := ldCostBucket{start: b.At("start_time").Time(), end: b.At("end_time").Time()}
		for _, r := range b.At("results").Arr() {
			cur, _ := r.At("amount.currency").Str()
			unit := CurrencyUnit(cur)
			m, ok := r.At("amount.value").Micros(0)
			if unit == "" || !ok {
				return Snapshot{}, shapeErr("openai costs: amount", nil)
			}
			cb.items = append(cb.items, ldCostItem{unit, m})
		}
		buckets = append(buckets, cb)
	}
	if len(buckets) == 0 {
		return Snapshot{}, shapeErr("openai costs: no buckets", nil)
	}
	s := newSnap(ProviderOpenAIAPI, SourceOpenAIAdmin, KindAdminAPI, ConfExact, now)
	s.PlanCode = "payg"
	s.Spend = ldSpendFromBuckets(buckets, now, "account")
	return s, nil
}

func parseOpenAIAdmin(in ParseInput) (Snapshot, error) {
	body, err := need(in, "costs")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseOpenAICosts(body, in.Now)
}

// ParseOpenAICreditGrants maps the legacy, undocumented credit_grants body.
// total_available is what is left; total_granted what was granted in all.
func ParseOpenAICreditGrants(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	avail, ok := j.At("total_available").Micros(0)
	if !ok {
		return Snapshot{}, shapeErr("openai credit grants: total_available", nil)
	}
	s := newSnap(ProviderOpenAIAPI, SourceOpenAIGrants, KindUndocumented, ConfExact, now)
	s.PlanCode = "prepaid"
	s.Balances = []Balance{{Kind: "available", Unit: UnitUSDMicros, Amount: avail}}
	if g, ok := j.At("total_granted").Micros(0); ok && g > 0 {
		s.Balances = append(s.Balances, Balance{Kind: "granted_total", Unit: UnitUSDMicros, Amount: g})
	}
	if avail <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

func parseOpenAIGrants(in ParseInput) (Snapshot, error) {
	body, err := need(in, "main")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseOpenAICreditGrants(body, in.Now)
}

// --- Anthropic API: organisation cost report (Admin API) ---------------------------

// AnthropicAdminVersion is the documented anthropic-version header value.
const AnthropicAdminVersion = "2023-06-01"

func planAnthropicAdmin(in PlanInput) ([]Request, error) {
	k, err := secret(in, SecretMgmt)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("starting_at", ldMonthStart(in.Now).Format(time.RFC3339))
	q.Set("bucket_width", "1d")
	q.Set("limit", "31")
	return []Request{{
		Key: "costs", Kind: ReqHTTP, Method: "GET", URL: "https://api.anthropic.com/v1/organizations/cost_report?" + q.Encode(),
		Header:        map[string]string{"Accept": "application/json", "anthropic-version": AnthropicAdminVersion},
		SecretHeaders: authHeaders(AuthHeader, "x-api-key", k),
	}}, nil
}

// ParseAnthropicCostReport maps GET /v1/organizations/cost_report. amount is
// a decimal string in the currency's lowest unit (cents for USD).
func ParseAnthropicCostReport(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	data := j.At("data")
	if !data.Exists() || data.Arr() == nil || len(data.Arr()) == 0 {
		return Snapshot{}, shapeErr("anthropic cost report: no buckets", nil)
	}
	if more, _ := j.At("has_more").Bool(); more {
		return Snapshot{}, shapeErr("anthropic cost report: more pages than one month", nil)
	}
	var buckets []ldCostBucket
	for _, b := range data.Arr() {
		cb := ldCostBucket{start: b.At("starting_at").Time(), end: b.At("ending_at").Time()}
		for _, r := range b.At("results").Arr() {
			cur, ok := r.At("currency").Str()
			if !ok {
				cur = "USD"
			}
			unit := CurrencyUnit(cur)
			m, ok := r.At("amount").Micros(2)
			if unit == "" || !ok {
				return Snapshot{}, shapeErr("anthropic cost report: amount", nil)
			}
			cb.items = append(cb.items, ldCostItem{unit, m})
		}
		buckets = append(buckets, cb)
	}
	s := newSnap(ProviderAnthropicAPI, SourceAnthropicAdmin, KindAdminAPI, ConfExact, now)
	s.PlanCode = "payg"
	s.Spend = ldSpendFromBuckets(buckets, now, "account")
	return s, nil
}

func parseAnthropicAdmin(in ParseInput) (Snapshot, error) {
	body, err := need(in, "costs")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseAnthropicCostReport(body, in.Now)
}

// --- AWS Bedrock: one AWS Budgets budget, SigV4 signed ----------------------------
//
// AWS Cost Explorer is billed per request, so Observer never calls it. The
// Budgets DescribeBudget call is free to read; the user names the budget
// they set up for Bedrock. The request is signed here with AWS Signature
// Version 4, purely: the signature depends only on the request, the key and
// the time, so it is computed in Plan and only the Authorization header is
// secret.

const (
	bedrockBudgetsHost   = "budgets.amazonaws.com"
	bedrockBudgetsRegion = "us-east-1" // the Budgets endpoint is global, signed for us-east-1
	bedrockBudgetsTarget = "AWSBudgetServiceGateway.DescribeBudget"
	awsJSONContentType   = "application/x-amz-json-1.1"
)

var (
	awsAccessKeyIDRe = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	awsAccountIDRe   = regexp.MustCompile(`^[0-9]{12}$`)
	awsBudgetNameRe  = regexp.MustCompile(`^[^:\\\x00-\x1f\x7f]{1,100}$`)
)

// SigV4Input is one request to sign with AWS Signature Version 4.
type SigV4Input struct {
	Method, Host, Path, Query string // Query is already canonical (sorted, encoded)
	Headers                   map[string]string
	Body                      []byte
	Region, Service           string
	AccessKeyID, Secret       string
	Time                      time.Time
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// SigV4Sign returns the Authorization header value and the X-Amz-Date value
// for a request. Headers are signed together with host and x-amz-date.
func SigV4Sign(in SigV4Input) (authorization, amzDate string) {
	t := in.Time.UTC()
	amzDate = t.Format("20060102T150405Z")
	day := t.Format("20060102")
	hdr := map[string]string{"host": in.Host, "x-amz-date": amzDate}
	for k, v := range in.Headers {
		hdr[strings.ToLower(strings.TrimSpace(k))] = strings.Join(strings.Fields(v), " ")
	}
	names := make([]string, 0, len(hdr))
	for k := range hdr {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHdr strings.Builder
	for _, k := range names {
		canonHdr.WriteString(k + ":" + hdr[k] + "\n")
	}
	signed := strings.Join(names, ";")
	path := in.Path
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{in.Method, path, in.Query, canonHdr.String(), signed, sha256Hex(in.Body)}, "\n")
	scope := day + "/" + in.Region + "/" + in.Service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	k := hmacSHA256([]byte("AWS4"+in.Secret), day)
	k = hmacSHA256(k, in.Region)
	k = hmacSHA256(k, in.Service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	return "AWS4-HMAC-SHA256 Credential=" + in.AccessKeyID + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + sig, amzDate
}

func planBedrockBudget(in PlanInput) ([]Request, error) {
	sec, err := secret(in, SecretAWS)
	if err != nil {
		return nil, err
	}
	akid := strings.TrimSpace(in.Params["access_key_id"])
	acct := strings.TrimSpace(in.Params["account_id"])
	name := strings.TrimSpace(in.Params["budget_name"])
	switch {
	case !awsAccessKeyIDRe.MatchString(akid):
		return nil, errors.New("planlimits: invalid AWS access key id")
	case !awsAccountIDRe.MatchString(acct):
		return nil, errors.New("planlimits: invalid AWS account id")
	case !awsBudgetNameRe.MatchString(name):
		return nil, errors.New("planlimits: invalid AWS budget name")
	}
	body, err := json.Marshal(map[string]string{"AccountId": acct, "BudgetName": name})
	if err != nil {
		return nil, fmt.Errorf("planlimits.planBedrockBudget: %w", err)
	}
	signedHdr := map[string]string{"Content-Type": awsJSONContentType, "X-Amz-Target": bedrockBudgetsTarget}
	auth, amzDate := SigV4Sign(SigV4Input{
		Method: "POST", Host: bedrockBudgetsHost, Path: "/", Headers: signedHdr, Body: body,
		Region: bedrockBudgetsRegion, Service: "budgets", AccessKeyID: akid, Secret: sec, Time: in.Now,
	})
	h := map[string]string{"Accept": "application/json", "X-Amz-Date": amzDate}
	for k, v := range signedHdr {
		h[k] = v
	}
	return []Request{{
		Key: "budget", Kind: ReqHTTP, Method: "POST", URL: "https://" + bedrockBudgetsHost + "/",
		Header: h, SecretHeaders: map[string]string{"Authorization": auth}, Body: body,
	}}, nil
}

// awsBudgetPeriod binds a budget TimeUnit to a window key, a spend period
// and the next reset after now (UTC, as AWS Budgets keeps its periods).
var awsBudgetPeriod = map[string]struct {
	key, period string
	next        func(time.Time) time.Time
}{
	"DAILY": {"daily", "day", func(n time.Time) time.Time {
		return time.Date(n.Year(), n.Month(), n.Day()+1, 0, 0, 0, 0, time.UTC)
	}},
	"MONTHLY": {"monthly", "month", func(n time.Time) time.Time {
		return time.Date(n.Year(), n.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	}},
	"QUARTERLY": {"cycle", "cycle", func(n time.Time) time.Time {
		q := (int(n.Month())-1)/3*3 + 4
		return time.Date(n.Year(), time.Month(q), 1, 0, 0, 0, 0, time.UTC)
	}},
	"ANNUALLY": {"cycle", "cycle", func(n time.Time) time.Time {
		return time.Date(n.Year()+1, 1, 1, 0, 0, 0, 0, time.UTC)
	}},
}

// ParseAWSBudget maps a DescribeBudget body. Only a cost budget in a
// supported currency is a reading; spend is the budget's actual spend.
func ParseAWSBudget(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	b := j.At("Budget")
	if !b.Exists() {
		return Snapshot{}, shapeErr("aws budget: no Budget", nil)
	}
	if t, _ := b.At("BudgetType").Str(); t != "COST" {
		return Snapshot{}, fmt.Errorf("%w: the named budget is not a cost budget", ErrNotApplicable)
	}
	tu, _ := b.At("TimeUnit").Str()
	per, ok := awsBudgetPeriod[tu]
	if !ok {
		return Snapshot{}, shapeErr("aws budget: time unit "+tu, nil)
	}
	limCur, _ := b.At("BudgetLimit.Unit").Str()
	actCur, _ := b.At("CalculatedSpend.ActualSpend.Unit").Str()
	unit := CurrencyUnit(actCur)
	actual, okA := b.At("CalculatedSpend.ActualSpend.Amount").Micros(0)
	if unit == "" || !okA {
		return Snapshot{}, shapeErr("aws budget: actual spend", nil)
	}
	s := newSnap(ProviderAWSBedrock, SourceBedrockBudget, KindAdminAPI, ConfExact, now)
	s.PlanCode = "payg"
	s.Spend = []Spend{{Period: per.period, Unit: unit, Amount: actual, Scope: "account"}}
	reset := per.next(now.UTC())
	w := Window{Key: per.key, Unit: unit, Used: F(float64(actual)), ResetsAt: &reset}
	if lim, ok := b.At("BudgetLimit.Amount").Micros(0); ok && CurrencyUnit(limCur) == unit && lim > 0 {
		w.Limit = F(float64(lim))
		w.Remaining = F(float64(max(lim-actual, 0)))
		w.UsedFrac = F(min(float64(actual)/float64(lim), 2))
	}
	s.Windows = []Window{w}
	return s, nil
}

func parseBedrockBudget(in ParseInput) (Snapshot, error) {
	r, ok := in.Responses["budget"]
	if ok && r.Err == nil && r.Status == 400 {
		// AWS JSON APIs answer 400 with a typed error for a missing budget
		// or a refused permission.
		t := ""
		if j, err := ParseJ(r.Body); err == nil {
			t, _ = j.At("__type").Str()
		}
		switch {
		case strings.Contains(t, "NotFound"):
			return Snapshot{}, fmt.Errorf("%w: no budget with that name", ErrNotApplicable)
		case strings.Contains(t, "AccessDenied"), strings.Contains(t, "UnrecognizedClient"), strings.Contains(t, "Signature"):
			return Snapshot{}, fmt.Errorf("%w: AWS refused the key", ErrAuth)
		}
	}
	body, err := need(in, "budget")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseAWSBudget(body, in.Now)
}

// --- Grok: `grok agent stdio` x.ai/billing over ACP JSON-RPC -----------------------

// GrokAgentArgv is the fixed launch vector. Observer only initializes and
// asks for billing; it never opens a session, so the agent runs no tool.
var GrokAgentArgv = []string{"grok", "agent", "stdio"}

// GrokClientName is the clientInfo.name sent at initialize; honest, like the
// codex app-server client name.
const GrokClientName = "superbased_observer_plans"

// acpMsg is one JSON-RPC 2.0 message on the ACP stdio transport.
type acpMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  any             `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// acpCall sends one request and waits for its response, skipping
// notifications and any request the agent sends (those carry a method).
func acpCall(s *rpcSession, method string, params any) (json.RawMessage, error) {
	id := s.nextID
	s.nextID++
	b, err := json.Marshal(acpMsg{JSONRPC: "2.0", ID: &id, Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("planlimits.acpCall: %w", err)
	}
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		return nil, fmt.Errorf("%w: grok %s: %s", ErrTransient, method, err.Error())
	}
	for s.r.Scan() {
		var m acpMsg
		if json.Unmarshal(s.r.Bytes(), &m) != nil || m.Method != "" || m.ID == nil || *m.ID != id {
			continue
		}
		if m.Error != nil {
			return nil, grokRPCError(method, m.Error.Code, m.Error.Message)
		}
		return m.Result, nil
	}
	return nil, fmt.Errorf("%w: grok %s: closed", ErrTransient, method)
}

// grokRPCError classifies a JSON-RPC error: method-not-found by its code
// (this grok version does not serve billing on the agent protocol), sign-in
// by its words, anything else as a shape change.
func grokRPCError(method string, code int, msg string) error {
	low := strings.ToLower(msg)
	switch {
	case code == -32601:
		return fmt.Errorf("%w: this grok version does not report billing to other apps", ErrNotApplicable)
	case strings.Contains(low, "authentication required") || strings.Contains(low, "grok login"):
		return fmt.Errorf("%w: grok is not signed in", ErrAuth)
	}
	return fmt.Errorf("%w: grok %s: %s", ErrShape, method, SanitizeLabel(msg))
}

func converseGrok(w io.Writer, r io.Reader, in PlanInput) (Snapshot, error) {
	s := newRPCSession(w, r)
	if _, err := acpCall(s, "initialize", map[string]any{
		"protocolVersion": 1,
		"clientCapabilities": map[string]any{
			"fs":       map[string]bool{"readTextFile": false, "writeTextFile": false},
			"terminal": false,
		},
		"clientInfo": map[string]string{
			"name": GrokClientName, "title": "SuperBased Observer Plans & limits", "version": in.Params["observer_version"],
		},
	}); err != nil {
		return Snapshot{}, err
	}
	raw, err := acpCall(s, "x.ai/billing", map[string]any{})
	if err != nil {
		return Snapshot{}, err
	}
	return ParseGrokBilling(raw, in.Now)
}

// grokCents reads a {val: cents} amount into USD micros. An object without
// val is a confirmed zero (the vendor's proto3 default); a missing object is
// unknown.
func grokCents(j J) (int64, bool) {
	if _, isObj := j.v.(map[string]any); !isObj {
		return 0, false
	}
	if !j.At("val").Exists() {
		return 0, true
	}
	return j.At("val").Micros(2)
}

// ParseGrokBilling maps the x.ai/billing result. Amounts are USD cents.
// The credit window is classified by the billing period's declared length.
func ParseGrokBilling(raw []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(raw)
	if err != nil {
		return Snapshot{}, err
	}
	s := newSnap(ProviderGrok, SourceGrokAgent, KindVendorRPC, ConfExact, now)
	start, end := j.At("billingCycle.billingPeriodStart").Time(), j.At("billingCycle.billingPeriodEnd").Time()
	key := "cycle"
	var length time.Duration
	if start != nil && end != nil && end.After(*start) {
		length = end.Sub(*start)
		key = ldPeriodKey(int64(length / time.Minute))
	}
	used, okU := grokCents(j.At("usage.totalUsed"))
	limit, okL := grokCents(j.At("monthlyLimit"))
	onDemand, _ := j.At("on_demand_enabled").Bool()
	odUsed, okOU := grokCents(j.At("usage.onDemandUsed"))
	odCap, okOC := grokCents(j.At("onDemandCap"))
	if okU && okL && limit > 0 {
		w := Window{
			Key: key, Unit: UnitUSDMicros, Used: F(float64(used)), Limit: F(float64(limit)),
			Remaining: F(float64(max(limit-used, 0))), UsedFrac: F(min(float64(used)/float64(limit), 2)), ResetsAt: end,
		}
		if length > 0 {
			w.Length = dur(length)
		}
		s.Windows = append(s.Windows, w)
	}
	odLeft := false
	if onDemand && okOU && okOC && odCap > 0 {
		s.Windows = append(s.Windows, Window{
			Key: "on_demand", Unit: UnitUSDMicros, Used: F(float64(odUsed)), Limit: F(float64(odCap)),
			Remaining: F(float64(max(odCap-odUsed, 0))), UsedFrac: F(min(float64(odUsed)/float64(odCap), 2)), ResetsAt: end,
		})
		odLeft = odUsed < odCap
	}
	if okU {
		s.Spend = []Spend{{Period: "cycle", Unit: UnitUSDMicros, Amount: used, Scope: "account"}}
	}
	if len(s.Windows)+len(s.Spend) == 0 {
		return Snapshot{}, shapeErr("grok billing: no amounts", nil)
	}
	if okU && okL && limit > 0 && used >= limit && !odLeft {
		s.Status = StatusThrottled
	}
	return s, nil
}

// --- JetBrains AI: the IDE's AIAssistantQuotaManager2.xml --------------------------

// jetBrainsUnitsPerCredit converts quota units to AI credits.
const jetBrainsUnitsPerCredit = 100_000

type jbOption struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type jbApplication struct {
	Components []struct {
		Name    string     `xml:"name,attr"`
		Options []jbOption `xml:"option"`
	} `xml:"component"`
}

var isoHoursRe = regexp.MustCompile(`^PT(\d+)H$`)

// jbOptions returns the quotaInfo and nextRefill option values of the
// AIAssistantQuotaManager2 component (entities already decoded).
func jbOptions(data []byte) (quota, refill string, err error) {
	var app jbApplication
	if err := xml.Unmarshal(data, &app); err != nil {
		return "", "", shapeErr("jetbrains quota xml", err)
	}
	for _, c := range app.Components {
		if c.Name != "AIAssistantQuotaManager2" {
			continue
		}
		for _, o := range c.Options {
			switch o.Name {
			case "quotaInfo":
				quota = o.Value
			case "nextRefill":
				refill = o.Value
			}
		}
	}
	if quota == "" {
		return "", "", shapeErr("jetbrains quota: no quotaInfo", nil)
	}
	return quota, refill, nil
}

// jbCredits reads a quota amount in units and returns AI credits; negative
// or non-finite amounts are unknown.
func jbCredits(j J) (float64, bool) {
	v, ok := j.Num()
	if !ok || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, false
	}
	return v / jetBrainsUnitsPerCredit, true
}

// jbRefill reads the next refill: the reset time and, from the declared
// tariff duration ("PT720H"), the window key and length. Without a declared
// duration the window is the monthly credit quota JetBrains names.
func jbRefill(raw string) (key string, reset *time.Time, length time.Duration) {
	key = "monthly"
	if raw == "" {
		return key, nil, 0
	}
	r, err := ParseJ([]byte(raw))
	if err != nil {
		return key, nil, 0
	}
	reset = r.At("next").Time()
	if d, ok := r.At("tariff.duration").Str(); ok {
		if m := isoHoursRe.FindStringSubmatch(d); m != nil {
			h, _ := strconv.ParseInt(m[1], 10, 64)
			length = time.Duration(h) * time.Hour
			key = ldPeriodKey(h * 60)
		}
	}
	return key, reset, length
}

// ParseJetBrainsQuota maps the IDE's quota file. The IDE persists it rarely,
// so the reading is estimated. Quota units are 100,000 per AI credit; the
// monthly window uses tariffQuota (never mixed with the total), top-up
// credits are a balance.
func ParseJetBrainsQuota(data []byte, now time.Time) (Snapshot, error) {
	quotaRaw, refillRaw, err := jbOptions(data)
	if err != nil {
		return Snapshot{}, err
	}
	q, err := ParseJ([]byte(quotaRaw))
	if err != nil {
		return Snapshot{}, err
	}
	credits := jbCredits
	s := newSnap(ProviderJetBrainsAI, SourceJetBrainsQuota, KindLocalState, ConfEstimated, now)
	key, reset, length := jbRefill(refillRaw)
	used, okU := credits(q.At("tariffQuota.current"))
	limit, okL := credits(q.At("tariffQuota.maximum"))
	var remaining *float64
	if okU && okL {
		if a, ok := credits(q.At("tariffQuota.available")); ok {
			remaining = F(a)
		}
	} else {
		used, okU = credits(q.At("current"))
		limit, okL = credits(q.At("maximum"))
	}
	if okU && okL && limit > 0 {
		if w, ok := AmountWindow(key, UnitAICredits, F(used), F(limit), remaining, reset, length); ok {
			s.Windows = append(s.Windows, w)
		}
	}
	topUp := 0.0
	if a, ok := credits(q.At("topUpQuota.available")); ok && a > 0 {
		topUp = a
		// Balance amounts are whole numbers; round down so a balance is
		// never overstated.
		s.Balances = append(s.Balances, Balance{Kind: "credits", Unit: UnitAICredits, Amount: int64(math.Floor(a))})
	}
	if err := requireAny(s, "jetbrains quota"); err != nil {
		return Snapshot{}, err
	}
	if len(s.Windows) == 1 && s.Windows[0].Remaining != nil && *s.Windows[0].Remaining <= 0 && topUp <= 0 {
		s.Status = StatusThrottled
	}
	return s, nil
}

func parseJetBrains(in ParseInput) (Snapshot, error) {
	b, err := localBytes(in.Local, "quota")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseJetBrainsQuota(b, in.Now)
}

// --- Nous Portal: Hermes Agent's own sign-in, read-only -------------------------

// nousToken is the projection of Hermes' auth.json the call needs.
type nousToken struct {
	token string
	exp   *time.Time
}

// parseNousAuth accepts the three shapes Hermes writes: providers.nous,
// credential_pool.nous[] (newest agent key, then newest access expiry, then
// lowest priority) or a bare state object. The stored portal_base_url is
// never read: the token only ever goes to portal.nousresearch.com.
func parseNousAuth(body []byte) (nousToken, error) {
	j, err := ParseJ(body)
	if err != nil {
		return nousToken{}, fmt.Errorf("%w: Hermes sign-in not usable", ErrAuth)
	}
	from := func(e J) (nousToken, bool) {
		tok, ok := e.At("access_token").Str()
		tok = strings.TrimSpace(tok)
		if !ok || tok == "" {
			return nousToken{}, false
		}
		t := nousToken{token: tok, exp: e.At("expires_at").Time()}
		if t.exp == nil {
			if _, exp, ok := jwtClaims(tok); ok && exp > 0 {
				t.exp = unixPtr(exp)
			}
		}
		return t, true
	}
	if t, ok := from(j.At("providers.nous")); ok {
		return t, nil
	}
	var best nousToken
	var bestKey [3]float64
	found := false
	for _, e := range j.At("credential_pool.nous").Arr() {
		t, ok := from(e)
		if !ok {
			continue
		}
		var k [3]float64
		if a := e.At("agent_key_expires_at").Time(); a != nil {
			k[0] = float64(a.Unix())
		}
		if t.exp != nil {
			k[1] = float64(t.exp.Unix())
		}
		if p, ok := e.At("priority").Num(); ok {
			k[2] = -p
		}
		if !found || k[0] > bestKey[0] || (k[0] == bestKey[0] && (k[1] > bestKey[1] || (k[1] == bestKey[1] && k[2] > bestKey[2]))) {
			best, bestKey, found = t, k, true
		}
	}
	if found {
		return best, nil
	}
	if t, ok := from(j); ok {
		return t, nil
	}
	return nousToken{}, fmt.Errorf("%w: Hermes is not signed in to Nous Portal", ErrAuth)
}

func planNous(in PlanInput) ([]Request, error) {
	b, err := localBytes(in.Local, "auth")
	if err != nil {
		return nil, err
	}
	t, err := parseNousAuth(b)
	if err != nil {
		return nil, err
	}
	if t.exp != nil && !in.Now.Add(60*time.Second).Before(*t.exp) {
		return nil, fmt.Errorf("%w: token expired; run hermes to sign in again", ErrAuth)
	}
	return []Request{{
		Key: "account", Kind: ReqHTTP, Method: "GET", URL: "https://portal.nousresearch.com/api/oauth/account",
		Header: map[string]string{"Accept": "application/json"}, SecretHeaders: bearer(t.token),
	}}, nil
}

// ParseNousAccount maps GET /api/oauth/account. Credits are US dollars. The
// monthly grant is a window; total usable credits lead as the balance left.
func ParseNousAccount(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	if j.At("error").Exists() {
		return Snapshot{}, shapeErr("nous account: error", nil)
	}
	money := func(paths ...string) (int64, bool) {
		v := j.First(paths...)
		if !v.Exists() {
			return 0, false
		}
		return v.Micros(0)
	}
	monthly, okM := money("subscription.monthly_credits")
	remaining, okR := money("subscription.credits_remaining", "paid_service_access.subscription_credits_remaining")
	purchased, okP := money("purchased_credits_remaining", "paid_service_access.purchased_credits_remaining")
	total, okT := money("paid_service_access.total_usable_credits")
	s := newSnap(ProviderNousPortal, SourceNousHermes, KindBorrowedToken, ConfExact, now)
	if p, ok := j.At("subscription.plan").Str(); ok {
		s.PlanLabel = SanitizeLabel(p)
	}
	if okM && okR && monthly > 0 {
		rem := max(remaining, 0)
		used := max(monthly-rem, 0)
		s.Windows = append(s.Windows, Window{
			Key: "monthly", Unit: UnitUSDMicros, Used: F(float64(used)), Limit: F(float64(monthly)),
			Remaining: F(float64(rem)), UsedFrac: F(float64(used) / float64(monthly)),
			ResetsAt: j.At("subscription.current_period_end").Time(),
		})
	}
	if okT {
		s.Balances = append(s.Balances, Balance{Kind: "total", Unit: UnitUSDMicros, Amount: total})
	}
	if okP {
		kind := "prepaid" // the only amount left when no total is reported
		if okT {
			kind = "topup"
		}
		s.Balances = append(s.Balances, Balance{Kind: kind, Unit: UnitUSDMicros, Amount: purchased})
	}
	if len(s.Windows)+len(s.Balances) == 0 {
		return Snapshot{}, shapeErr("nous account: no credit amounts", nil)
	}
	return s, nil
}

func parseNous(in ParseInput) (Snapshot, error) {
	body, err := need(in, "account")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseNousAccount(body, in.Now)
}

// --- Muse Code: a pasted dev.meta.ai session, one team's subscription quota ------
//
// The CLI route mints an inference key on every read and keeps its token in
// the macOS keychain, so Observer never takes it. The person pastes their
// dev.meta.ai session and names the team whose quota they want.

var museTeamIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func planMuseWeb(in PlanInput) ([]Request, error) {
	sess, err := secret(in, SecretSession)
	if err != nil {
		return nil, err
	}
	team := strings.TrimSpace(in.Params["team_id"])
	if !museTeamIDRe.MatchString(team) {
		return nil, errors.New("planlimits: invalid Muse team id")
	}
	return []Request{{
		Key: "quota", Kind: ReqHTTP, Method: "GET", URL: "https://dev.meta.ai/api/portal/teams/" + team + "/subscription-quota",
		Header: map[string]string{"Accept": "application/json"}, SecretHeaders: authHeaders(AuthCookie, "", sess),
	}}, nil
}

// ParseMuseTeamQuota maps the team subscription-quota body. Amounts are
// weighted token counts (decimal strings), so windows are percent only. An
// idle short window (no reset, or a reset already past) is 0%; a weekly
// window without a future reset is stale and dropped.
func ParseMuseTeamQuota(body []byte, now time.Time) (Snapshot, error) {
	j, err := ParseJ(body)
	if err != nil {
		return Snapshot{}, err
	}
	q := j.At("subscription_quota")
	if !q.Exists() {
		return Snapshot{}, fmt.Errorf("%w: no subscription quota for this team", ErrNotApplicable)
	}
	frac := func(u, l string) (float64, bool) {
		used, okU := q.At(u).Num()
		lim, okL := q.At(l).Num()
		if !okU || !okL || lim <= 0 || used < 0 {
			return 0, false
		}
		return min(used/lim, 1), true
	}
	s := newSnap(ProviderMuseCode, SourceMuseWeb, KindBrowser, ConfPercentOnly, now)
	if tier, ok := q.At("tier").Str(); ok {
		s.PlanLabel = SanitizeLabel(tier)
	}
	if f, ok := frac("window_weighted_used", "window_weighted_limit"); ok {
		secs, okS := q.At("window_duration_secs").Num()
		if okS && secs >= 60 {
			length := time.Duration(secs) * time.Second
			reset := q.At("window_resets_at").Time()
			if reset == nil || !reset.After(now) {
				f, reset = 0, nil
			}
			s.Windows = append(s.Windows, Window{
				Key: ldPeriodKey(int64(secs) / 60), Unit: UnitPercent, UsedFrac: F(f), ResetsAt: reset, Length: dur(length), Rolling: true,
			})
		}
	}
	if f, ok := frac("weekly_weighted_used", "weekly_weighted_limit"); ok {
		if reset := q.At("weekly_resets_at").Time(); reset != nil && reset.After(now) {
			if _, dup := FindWindow(s, "weekly"); !dup {
				s.Windows = append(s.Windows, Window{Key: "weekly", Unit: UnitPercent, UsedFrac: F(f), ResetsAt: reset, Length: dur(7 * 24 * time.Hour)})
			}
		}
	}
	if len(s.Windows) == 0 {
		return Snapshot{}, shapeErr("muse team quota: no current windows", nil)
	}
	for _, w := range s.Windows {
		if *w.UsedFrac >= 1 {
			s.Status = StatusThrottled
		}
	}
	return s, nil
}

func parseMuseWeb(in ParseInput) (Snapshot, error) {
	body, err := need(in, "quota")
	if err != nil {
		return Snapshot{}, err
	}
	return ParseMuseTeamQuota(body, in.Now)
}

// --- CodeRabbit: `coderabbit usage` ----------------------------------------------

var codeRabbitSignedOut = []string{"not authenticated", "please log in", "auth login", "authentication required", "unauthorized", "no session found"}

// ParseCodeRabbitUsage parses `coderabbit usage` ("Label : value" lines).
// CodeRabbit reports a review count with no quota, so the card is used-only.
// The organization and user lines are never stored.
func ParseCodeRabbitUsage(out string, now time.Time) (Snapshot, error) {
	t := StripANSI(out)
	fields := map[string]string{}
	for _, line := range strings.Split(t, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if _, seen := fields[k]; !seen && v != "" {
			fields[k] = v
		}
	}
	reviews, errR := strconv.Atoi(fields["your reviews"])
	if (errR != nil || reviews < 0) && fields["usage billing"] == "" && fields["period resets"] == "" {
		low := strings.ToLower(t)
		for _, k := range codeRabbitSignedOut {
			if strings.Contains(low, k) {
				return Snapshot{}, errNotSignedIn("coderabbit")
			}
		}
		return Snapshot{}, errNoMatch("coderabbit")
	}
	s := newSnap(ProviderCodeRabbit, SourceCodeRabbitCLI, KindVendorCLI, ConfExact, now)
	s.PlanLabel = SanitizeLabel(fields["plan"])
	var reset *time.Time
	if r, err := time.Parse("2006-01-02", fields["period resets"]); err == nil {
		reset = &r
	}
	if errR == nil && reviews >= 0 {
		s.Windows = []Window{{Key: "cycle:reviews", Unit: UnitRequests, Used: F(float64(reviews)), ResetsAt: reset}}
		return s, nil
	}
	s.Status = StatusPlanOnly
	return s, nil
}

// --- Doubao: `arkcli usage plan --format json` -----------------------------------

// arkcliProducts binds an arkcli product to its window-key prefix.
var arkcliProducts = map[string]string{
	"coding-plan":      "",
	"agent-plan":       "agent:",
	"coding-plan-team": "coding_team:",
	"agent-plan-team":  "agent_team:",
}

// arkcliLabels binds an arkcli period label to a window key and length.
var arkcliLabels = map[string]struct {
	key    string
	length time.Duration
}{
	"session": {"5h", 5 * time.Hour},
	"5h":      {"5h", 5 * time.Hour},
	"daily":   {"daily", 24 * time.Hour},
	"weekly":  {"weekly", 7 * 24 * time.Hour},
	"monthly": {"monthly", 0},
}

var arkcliSignedOut = []string{"not logged in", "not authenticated", "authentication required", "login required", "please login", "please log in"}

// ParseArkcliUsage parses `arkcli usage plan --format json`. Percent is
// used percent 0..100; reset_at is ISO or epoch seconds or milliseconds,
// and a non-positive value means no reset.
func ParseArkcliUsage(out string, now time.Time) (Snapshot, error) {
	i := strings.Index(out, "{")
	if i < 0 {
		low := strings.ToLower(out)
		for _, k := range arkcliSignedOut {
			if strings.Contains(low, k) {
				return Snapshot{}, errNotSignedIn("arkcli")
			}
		}
		return Snapshot{}, errNoMatch("arkcli")
	}
	j, err := ParseJ([]byte(out[i:]))
	if err != nil {
		return Snapshot{}, err
	}
	if m, _ := j.At("viewer.auth_method").Str(); strings.EqualFold(strings.TrimSpace(m), "none") {
		return Snapshot{}, errNotSignedIn("arkcli")
	}
	s := newSnap(ProviderDoubao, SourceDoubaoArkcli, KindVendorCLI, ConfPercentOnly, now)
	for _, it := range j.At("items").Arr() {
		p, _ := it.At("product").Str()
		prefix, ok := arkcliProducts[strings.ToLower(p)]
		if !ok {
			continue
		}
		if sub, okS := it.At("subscribed").Bool(); okS && !sub {
			continue
		}
		for _, per := range it.At("periods").Arr() {
			label, _ := per.At("label").Str()
			lab, ok := arkcliLabels[strings.ToLower(label)]
			pct, okP := per.At("percent").Num()
			if !ok || !okP {
				continue
			}
			key := prefix + lab.key
			if _, dup := FindWindow(s, key); dup {
				continue
			}
			s.Windows = append(s.Windows, PercentWindow(key, min(max(pct, 0), 100), per.At("reset_at").Time(), lab.length))
		}
	}
	if len(s.Windows) == 0 {
		return Snapshot{}, errNoMatch("arkcli")
	}
	for _, w := range s.Windows {
		if *w.UsedFrac >= 1 {
			s.Status = StatusThrottled
		}
	}
	return s, nil
}
