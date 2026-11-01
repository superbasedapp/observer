package planlimits

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// laSources lists every lane A source, so a new row cannot skip the tests.
var laSources = []string{
	SourceClinePass, SourceOpenCodeGo, SourceFactory, SourceFireworks, SourceZai, SourceMiniMax, SourceKilo,
	SourceSynthetic, SourceElevenLabs, SourceWarp, SourceDeepInfra, SourceCodebuff, SourceVenice, SourceCommandCode,
	SourcePoe, SourceChutes, SourceNeuralwatt, SourceZenMux, SourceAiAnd, SourceIBMBob, SourceHuggingFace, SourceV0,
}

const laSecret = "SECRET-K"

var laParams = map[string]string{"region": "global", "account_id": "acct-1", "project_id": "proj-1", "org_id": "org_1"}

func laSecrets() map[string]string {
	return map[string]string{SecretKey: laSecret, SecretMgmt: laSecret}
}

// TestLaneAPlans pins, for every lane A source: each request goes over HTTPS
// to a host the row allows, the secret rides only in SecretHeaders, and a
// missing secret is ErrAuth before anything is planned.
func TestLaneAPlans(t *testing.T) {
	for _, id := range laSources {
		def, ok := SourceByID(id)
		if !ok {
			t.Fatalf("%s: no source row", id)
		}
		d, ok := Drivers[id]
		if !ok {
			t.Fatalf("%s: no driver", id)
		}
		if _, ok := ProviderByID(def.Provider); !ok {
			t.Errorf("%s: provider %q has no catalogue row", id, def.Provider)
		}
		if (def.DocURL != "") != (RungOf(def.Kind) == RungOfficial) {
			t.Errorf("%s: an official source carries a vendor doc and only an official one: kind %s doc %q", id, def.Kind, def.DocURL)
		}
		reqs, err := d.Plan(PlanInput{Params: laParams, Secrets: laSecrets(), Now: t0})
		if err != nil || len(reqs) == 0 {
			t.Fatalf("%s: plan %v %v", id, reqs, err)
		}
		for _, r := range reqs {
			u, err := url.Parse(r.URL)
			if err != nil || u.Scheme != "https" || !slices.Contains(def.Hosts, u.Host) {
				t.Errorf("%s: request %q leaves the allowed hosts %v", id, r.URL, def.Hosts)
			}
			if strings.Contains(r.URL, laSecret) || strings.Contains(string(r.Body), laSecret) {
				t.Errorf("%s: secret in URL or body", id)
			}
			for n, v := range r.Header {
				if strings.Contains(v, laSecret) {
					t.Errorf("%s: secret in plain header %s", id, n)
				}
			}
			found := false
			for _, v := range r.SecretHeaders {
				found = found || strings.Contains(v, laSecret)
			}
			if !found {
				t.Errorf("%s: request %s carries no secret", id, r.Key)
			}
		}
		if _, err := d.Plan(PlanInput{Params: laParams, Now: t0}); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: missing secret = %v, want ErrAuth", id, err)
		}
	}
}

// TestLaneAAuthHeaders pins how each auth method sends the secret.
func TestLaneAAuthHeaders(t *testing.T) {
	jwt := fakeJWT(`{"sub":"u","exp":4102444800}`)
	cases := []struct {
		name, src, secretKey, secret, header, want string
	}{
		{"pasted key, documented, bearer", SourceSynthetic, SecretKey, "K", "Authorization", "Bearer K"},
		{"management key, documented, bearer", SourceZenMux, SecretMgmt, "M", "Authorization", "Bearer M"},
		{"undocumented key, bearer", SourceClinePass, SecretKey, "K", "Authorization", "Bearer K"},
		{"undocumented key, custom header", SourceElevenLabs, SecretKey, "K", "xi-api-key", "K"},
		{"undocumented key, vendor scheme", SourceIBMBob, SecretKey, "K", "Authorization", "Apikey K"},
		{"undocumented token, bearer when a JWT", SourceIBMBob, SecretKey, jwt, "Authorization", "Bearer " + jwt},
	}
	for _, c := range cases {
		reqs, err := Drivers[c.src].Plan(PlanInput{Params: laParams, Secrets: map[string]string{c.secretKey: c.secret}, Now: t0})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, r := range reqs {
			if got := r.SecretHeaders[c.header]; got != c.want || len(r.SecretHeaders) != 1 {
				t.Errorf("%s: secret headers %v, want %s: %s", c.name, r.SecretHeaders, c.header, c.want)
			}
		}
	}
	// ZenMux takes a management key, never the plain key slot.
	if _, err := Drivers[SourceZenMux].Plan(PlanInput{Secrets: map[string]string{SecretKey: "K"}, Now: t0}); !errors.Is(err, ErrAuth) {
		t.Errorf("zenmux with an inference key: %v", err)
	}
}

// TestLaneARegionsAndParams pins the region host tables and the parameters
// that reach a URL.
func TestLaneARegionsAndParams(t *testing.T) {
	cases := []struct {
		src    string
		params map[string]string
		want   []string // URL prefixes, in request order
	}{
		{SourceZai, map[string]string{"region": "global"}, []string{"https://api.z.ai/api/monitor/usage/quota/limit"}},
		{SourceZai, map[string]string{"region": "china"}, []string{"https://open.bigmodel.cn/api/monitor/usage/quota/limit"}},
		{SourceZai, nil, []string{"https://api.z.ai/"}},
		{SourceMiniMax, map[string]string{"region": "china"}, []string{"https://api.minimaxi.com/v1/token_plan/remains", "https://api.minimaxi.com/v1/api/openplatform/coding_plan/remains"}},
		{SourceMiniMax, map[string]string{"region": "global"}, []string{"https://api.minimax.io/v1/token_plan/remains", "https://api.minimax.io/"}},
		{SourceFireworks, map[string]string{"account_id": "accounts/my-acct"}, []string{"https://api.fireworks.ai/v1/accounts/my-acct/billing/summary?endTime=2025-10-09T08%3A53%3A20Z&startTime=2025-09-09T08%3A53%3A20Z"}},
		{SourceV0, map[string]string{"project_id": "my project"}, []string{"https://api.v0.dev/v1/user/billing?scope=my+project", "https://api.v0.dev/v1/rate-limits?scope=my+project"}},
		{SourceV0, nil, []string{"https://api.v0.dev/v1/user/billing", "https://api.v0.dev/v1/rate-limits"}},
		{SourceHuggingFace, nil, []string{"https://huggingface.co/api/settings/billing/usage-v2?startDate=1759276800&endDate=1760000000", "https://huggingface.co/api/spaces/zero-gpu/quota"}},
	}
	for _, c := range cases {
		reqs, err := Drivers[c.src].Plan(PlanInput{Params: c.params, Secrets: laSecrets(), Now: t0})
		if err != nil || len(reqs) != len(c.want) {
			t.Fatalf("%s %v: %v %v", c.src, c.params, reqs, err)
		}
		for i, r := range reqs {
			if !strings.HasPrefix(r.URL, c.want[i]) {
				t.Errorf("%s %v: url %q, want prefix %q", c.src, c.params, r.URL, c.want[i])
			}
		}
	}
	bad := []struct {
		src    string
		params map[string]string
	}{
		{SourceZai, map[string]string{"region": "mars"}},
		{SourceMiniMax, map[string]string{"region": "mars"}},
		{SourceFireworks, map[string]string{"account_id": ".."}},
		{SourceFireworks, map[string]string{"account_id": "a?b"}},
		{SourceFireworks, nil},
		{SourceKilo, map[string]string{"org_id": "x/../y"}},
	}
	for _, b := range bad {
		if _, err := Drivers[b.src].Plan(PlanInput{Params: b.params, Secrets: laSecrets(), Now: t0}); err == nil {
			t.Errorf("%s %v must be refused", b.src, b.params)
		}
	}
	reqs, _ := Drivers[SourceKilo].Plan(PlanInput{Params: map[string]string{"org_id": "org_1"}, Secrets: laSecrets(), Now: t0})
	if reqs[0].Header["X-KILOCODE-ORGANIZATIONID"] != "org_1" {
		t.Errorf("kilo org header %v", reqs[0].Header)
	}
	reqs, _ = Drivers[SourceWarp].Plan(PlanInput{Secrets: laSecrets(), Now: t0})
	if reqs[0].Method != "POST" || !strings.Contains(string(reqs[0].Body), "GetRequestLimitInfo") || reqs[0].Header["Content-Type"] != "application/json" {
		t.Errorf("warp request %+v", reqs[0])
	}
	reqs, _ = Drivers[SourceCodebuff].Plan(PlanInput{Secrets: laSecrets(), Now: t0})
	if reqs[0].Method != "POST" || reqs[1].Method != "GET" || !reqs[1].Optional {
		t.Errorf("codebuff requests %+v", reqs)
	}
}

// laCase is one parse case: the response bodies (fixture files under
// testdata/lanea, keyed by request key) and what the snapshot must say.
type laCase struct {
	name   string
	src    string
	params map[string]string
	bodies map[string]string
	check  func(t *testing.T, s Snapshot)
}

func laRun(t *testing.T, c laCase) (Snapshot, error) {
	t.Helper()
	resp := map[string]Response{}
	for k, f := range c.bodies {
		resp[k] = Response{Key: k, Status: 200, Body: fixture(t, "lanea/"+f)}
	}
	return Drivers[c.src].Parse(ParseInput{Params: c.params, Responses: resp, Now: t0})
}

// laWin returns window k or fails.
func laWin(t *testing.T, s Snapshot, k string) Window {
	t.Helper()
	w, ok := FindWindow(s, k)
	if !ok {
		t.Fatalf("window %q missing in %+v", k, s.Windows)
	}
	return w
}

// laFrac pins a window's used fraction.
func laFrac(t *testing.T, s Snapshot, k string, want float64) {
	t.Helper()
	w := laWin(t, s, k)
	if f, ok := usedFrac(w); !ok || !approx(f, want) {
		t.Errorf("window %s used %v, want %v", k, f, want)
	}
}

// laBal pins a balance.
func laBal(t *testing.T, s Snapshot, kind string, unit Unit, want int64) {
	t.Helper()
	b, ok := FindBalance(s, kind)
	if !ok || b.Unit != unit || b.Amount != want {
		t.Errorf("balance %s = %+v (%v), want %d %s", kind, b, ok, want, unit)
	}
}

// wantPercentLeft pins a percent-left headline on window basis.
func wantPercentLeft(t *testing.T, h Headline, basis string, left float64) {
	t.Helper()
	if h.Kind != HeadlinePercentLeft || h.Basis != "window:"+basis || h.Value == nil || !approx(*h.Value, left) {
		t.Errorf("headline %+v, want %v left of window %s", h, left, basis)
	}
}

// wantUsedOnly pins the honest used-only headline.
func wantUsedOnly(t *testing.T, h Headline, unit Unit, used float64) {
	t.Helper()
	if h.Kind != HeadlineUsedOnly || h.Unit != unit || h.Value == nil || !approx(*h.Value, used) {
		t.Errorf("headline %+v, want used only %v %s", h, used, unit)
	}
}

func TestLaneAParse(t *testing.T) {
	cases := []laCase{
		{"clinepass", SourceClinePass, nil, map[string]string{"main": "clinepass.json"}, func(t *testing.T, s Snapshot) {
			if len(s.Windows) != 3 {
				t.Errorf("windows %+v", s.Windows)
			}
			laFrac(t, s, "5h", 0.125)
			if w := laWin(t, s, "5h"); w.Length == nil || *w.Length != 5*time.Hour || w.ResetsAt == nil {
				t.Errorf("5h %+v", w)
			}
			wantPercentLeft(t, headlineOf(t, s), "monthly", 0.39)
		}},
		{"opencode go", SourceOpenCodeGo, nil, map[string]string{"main": "opencode_go.json"}, func(t *testing.T, s Snapshot) {
			laFrac(t, s, "5h", 0.03)
			if w := laWin(t, s, "5h"); w.ResetsAt == nil || !w.ResetsAt.Equal(t0.Add(5*time.Hour)) {
				t.Errorf("reset in seconds from now: %+v", w.ResetsAt)
			}
			wantPercentLeft(t, headlineOf(t, s), "weekly", 0.775)
		}},
		{"factory token billing", SourceFactory, nil, map[string]string{"me": "factory_me.json", "limits": "factory_limits.json", "usage": "factory_usage.json"}, func(t *testing.T, s Snapshot) {
			if s.PlanCode != "team" || s.PlanLabel != "Team Monthly" {
				t.Errorf("plan %q %q", s.PlanCode, s.PlanLabel)
			}
			if len(s.Windows) != 3 {
				t.Errorf("an idle core tier stays hidden; legacy usage is not read: %+v", s.Windows)
			}
			laFrac(t, s, "weekly", 0.34)
			laBal(t, s, "prepaid", UnitUSDMicros, 25_000_000)
			wantPercentLeft(t, headlineOf(t, s), "monthly", 0.44)
		}},
		{"factory legacy allowance", SourceFactory, nil, map[string]string{"me": "factory_me.json", "limits": "factory_limits_off.json", "usage": "factory_usage.json"}, func(t *testing.T, s Snapshot) {
			w := laWin(t, s, "cycle:standard")
			if w.Unit != UnitTokens || *w.Used != 250_000 || *w.Limit != 1_000_000 || w.Length == nil {
				t.Errorf("standard %+v", w)
			}
			laFrac(t, s, "cycle:premium", 0.5)
			wantPercentLeft(t, headlineOf(t, s), "cycle:premium", 0.5)
		}},
		{"fireworks", SourceFireworks, laParams, map[string]string{"main": "fireworks.json"}, func(t *testing.T, s Snapshot) {
			if len(s.Spend) != 1 || s.Spend[0].Amount != 12_345_000 || s.Spend[0].Unit != UnitUSDMicros || s.Spend[0].Period != "30d" {
				t.Errorf("spend %+v (other currencies are skipped, never summed)", s.Spend)
			}
			wantUsedOnly(t, headlineOf(t, s), UnitUSDMicros, 12_345_000)
		}},
		{"zai", SourceZai, laParams, map[string]string{"main": "zai.json"}, func(t *testing.T, s Snapshot) {
			if s.PlanLabel != "Pro" || len(s.Windows) != 3 {
				t.Errorf("plan %q windows %+v", s.PlanLabel, s.Windows)
			}
			laFrac(t, s, "5h", 0.25)
			laFrac(t, s, "weekly", 0.09)
			if w := laWin(t, s, "mcp:monthly"); w.Unit != UnitRequests || *w.Used != 224 || *w.Remaining != 776 {
				t.Errorf("tool calls %+v", w)
			}
			wantPercentLeft(t, headlineOf(t, s), "5h", 0.75)
		}},
		{"minimax", SourceMiniMax, laParams, map[string]string{"token": "minimax.json"}, func(t *testing.T, s Snapshot) {
			if s.PlanLabel != "Plus" || len(s.Windows) != 2 {
				t.Errorf("a lane outside the plan has no window: %q %+v", s.PlanLabel, s.Windows)
			}
			w := laWin(t, s, "5h:general")
			if *w.Limit != 1500 || *w.Remaining != 1200 || *w.Used != 300 {
				t.Errorf("usage_count is what is left: %+v", w)
			}
			laFrac(t, s, "weekly:general", 0.3)
			wantPercentLeft(t, headlineOf(t, s), "weekly:general", 0.7)
		}},
		{"minimax older coding plan", SourceMiniMax, laParams, map[string]string{"coding": "minimax.json"}, func(t *testing.T, s Snapshot) {
			laFrac(t, s, "5h:general", 0.2)
		}},
		{"kilo", SourceKilo, nil, map[string]string{"main": "kilo.json"}, func(t *testing.T, s Snapshot) {
			laBal(t, s, "prepaid", UnitUSDMicros, 17_500_000)
			laBal(t, s, "purchased", UnitUSDMicros, 24_000_000)
			if s.PlanLabel != "Starter" || s.PlanCode != "tier_19" {
				t.Errorf("plan %q %q", s.PlanLabel, s.PlanCode)
			}
			if w := laWin(t, s, "cycle"); *w.Used != 4_250_000 || *w.Limit != 28_500_000 {
				t.Errorf("pass %+v", w)
			}
			h := headlineOf(t, s)
			wantLeft(t, "kilo", h, UnitUSDMicros, 17_500_000, F(6_500_000))
			if h.Of == nil || *h.Of != 24_000_000 {
				t.Errorf("kilo of %+v", h)
			}
		}},
		{"synthetic", SourceSynthetic, nil, map[string]string{"main": "synthetic.json"}, func(t *testing.T, s Snapshot) {
			if w := laWin(t, s, "weekly"); w.Unit != UnitUSDMicros || *w.Limit != 36_000_000 || *w.Remaining != 35_300_000 || !w.Rolling {
				t.Errorf("weekly dollars %+v", w)
			}
			laFrac(t, s, "search_hourly", 2.0/250)
			wantLeft(t, "synthetic", headlineOf(t, s), UnitRequests, 108, F(27))
		}},
		{"synthetic generic list", SourceSynthetic, nil, map[string]string{"main": "synthetic_generic.json"}, func(t *testing.T, s Snapshot) {
			laFrac(t, s, "quota:monthly", 0.25)
			if w := laWin(t, s, "daily"); *w.Used != 150 || w.Length == nil || *w.Length != 24*time.Hour {
				t.Errorf("daily %+v", w)
			}
			if s.PlanLabel != "Starter" {
				t.Errorf("plan %q", s.PlanLabel)
			}
		}},
		{"elevenlabs", SourceElevenLabs, nil, map[string]string{"main": "elevenlabs.json"}, func(t *testing.T, s Snapshot) {
			if s.PlanLabel != "Growing Business" || s.PlanCode != "growing_business" {
				t.Errorf("plan %q %q", s.PlanLabel, s.PlanCode)
			}
			if w := laWin(t, s, "monthly"); w.ResetsAt == nil || w.ResetsAt.Unix() != 1761955200 {
				t.Errorf("reset epoch seconds %+v", w)
			}
			wantLeft(t, "elevenlabs", headlineOf(t, s), UnitCharacters, 75_000, F(25_000))
		}},
		{"warp", SourceWarp, nil, map[string]string{"main": "warp.json"}, func(t *testing.T, s Snapshot) {
			laBal(t, s, "credits", UnitCredits, 15)
			laBal(t, s, "granted_total", UnitCredits, 35)
			wantLeft(t, "warp", headlineOf(t, s), UnitCredits, 1200, F(300))
		}},
		{"deepinfra", SourceDeepInfra, nil, map[string]string{"checklist": "deepinfra_checklist.json", "usage": "deepinfra_usage.json"}, func(t *testing.T, s Snapshot) {
			laBal(t, s, "available", UnitUSDMicros, 95_810_000)
			if len(s.Spend) != 2 || s.Spend[1].Period != "month" || s.Spend[1].Amount != 3_940_000 {
				t.Errorf("month spend from cents %+v", s.Spend)
			}
			laFrac(t, s, "spend_limit", 3.94/20)
			wantLeft(t, "deepinfra", headlineOf(t, s), UnitUSDMicros, 95_810_000, F(3_940_000))
		}},
		{"codebuff", SourceCodebuff, nil, map[string]string{"main": "codebuff_usage.json", "subscription": "codebuff_subscription.json"}, func(t *testing.T, s Snapshot) {
			laFrac(t, s, "cycle", 0.25)
			laBal(t, s, "credits", UnitCredits, 3750)
			if s.PlanLabel != "pro" {
				t.Errorf("plan %q", s.PlanLabel)
			}
			wantLeft(t, "codebuff", headlineOf(t, s), UnitCredits, 4900, F(2100))
		}},
		{"codebuff key without a subscription answer", SourceCodebuff, nil, map[string]string{"main": "codebuff_usage.json"}, func(t *testing.T, s Snapshot) {
			wantLeft(t, "codebuff", headlineOf(t, s), UnitCredits, 3750, F(1250))
		}},
		{"venice", SourceVenice, nil, map[string]string{"main": "venice.json"}, func(t *testing.T, s Snapshot) {
			laBal(t, s, "credits", UnitCredits, 91) // 90.5 DIEM, rounded, never converted to money
			laFrac(t, s, "diem_epoch", 0.095)
			wantLeft(t, "venice", headlineOf(t, s), UnitUSDMicros, 12_400_000, nil)
		}},
		{"venice blocked", SourceVenice, nil, map[string]string{"main": "venice_blocked.json"}, func(t *testing.T, s Snapshot) {
			if s.Status != StatusThrottled {
				t.Errorf("status %q", s.Status)
			}
		}},
		{"command code", SourceCommandCode, nil, map[string]string{"main": "commandcode_credits.json", "subscription": "commandcode_subscription.json"}, func(t *testing.T, s Snapshot) {
			if s.PlanLabel != "Pro" || s.PlanCode != "individual-pro" {
				t.Errorf("plan %q %q", s.PlanLabel, s.PlanCode)
			}
			laBal(t, s, "prepaid", UnitUSDMicros, 4_250_000)
			laFrac(t, s, "5h", 0.25)
			wantLeft(t, "command code", headlineOf(t, s), UnitUSDMicros, 8_500_000, F(21_500_000))
		}},
		{"poe", SourcePoe, nil, map[string]string{"main": "poe.json"}, func(t *testing.T, s Snapshot) {
			wantLeft(t, "poe", headlineOf(t, s), UnitPoints, 2500, nil)
		}},
		{"chutes", SourceChutes, nil, map[string]string{"main": "chutes.json"}, func(t *testing.T, s Snapshot) {
			if s.PlanLabel != "Pro" {
				t.Errorf("plan %q", s.PlanLabel)
			}
			laFrac(t, s, "monthly", 0.25)
			if w := laWin(t, s, "4h"); w.Unit != UnitRequests || !w.Rolling || *w.Length != 4*time.Hour {
				t.Errorf("rolling %+v", w)
			}
			wantLeft(t, "chutes", headlineOf(t, s), UnitRequests, 60, F(40))
		}},
		{"neuralwatt", SourceNeuralwatt, nil, map[string]string{"main": "neuralwatt.json"}, func(t *testing.T, s Snapshot) {
			laBal(t, s, "prepaid", UnitUSDMicros, 51_000_000)
			laBal(t, s, "purchased", UnitUSDMicros, 77_040_000)
			laFrac(t, s, "key_cap", 0.2)
			if w := laWin(t, s, "cycle"); w.Unit != UnitKWh || w.Length == nil || *w.Length != 31*24*time.Hour {
				t.Errorf("energy %+v", w)
			}
			wantLeft(t, "neuralwatt", headlineOf(t, s), UnitKWh, 7.5, F(2.5))
		}},
		{"zenmux", SourceZenMux, nil, map[string]string{"main": "zenmux_subscription.json", "payg": "zenmux_payg.json"}, func(t *testing.T, s Snapshot) {
			if s.PlanLabel != "Ultra" {
				t.Errorf("plan %q", s.PlanLabel)
			}
			laFrac(t, s, "5h", 0.0715)
			laBal(t, s, "prepaid", UnitUSDMicros, 482_740_000)
			wantPercentLeft(t, headlineOf(t, s), "5h", 0.9285)
		}},
		{"aiand", SourceAiAnd, nil, map[string]string{"main": "aiand.json"}, func(t *testing.T, s Snapshot) {
			if len(s.Spend) != 1 || s.Spend[0].Amount != 7_523_440 || s.Spend[0].Unit != UnitUSDMicros || s.Confidence != ConfExact {
				t.Errorf("spend %+v %s", s.Spend, s.Confidence)
			}
			wantUsedOnly(t, headlineOf(t, s), UnitUSDMicros, 7_523_440)
		}},
		{"aiand partial page", SourceAiAnd, nil, map[string]string{"main": "aiand_more.json"}, func(t *testing.T, s Snapshot) {
			if s.Confidence != ConfEstimated {
				t.Errorf("a partial sum is an estimate: %s", s.Confidence)
			}
		}},
		{"aiand nothing billed", SourceAiAnd, nil, map[string]string{"main": "aiand_empty.json"}, func(t *testing.T, s Snapshot) {
			if s.Status != StatusUnmetered || len(s.Spend) != 0 {
				t.Errorf("no zero spend in an unknown currency: %+v", s)
			}
		}},
		{"ibm bob", SourceIBMBob, nil, map[string]string{"main": "ibm_bob.json"}, func(t *testing.T, s Snapshot) {
			if s.PlanLabel != "Pro+" {
				t.Errorf("plan %q", s.PlanLabel)
			}
			if w := laWin(t, s, "monthly"); w.ResetsAt == nil || w.ResetsAt.Unix() != 1761955200 {
				t.Errorf("reset %+v", w)
			}
			wantLeft(t, "ibm bob", headlineOf(t, s), UnitCredits, 57.5, F(22.5))
		}},
		{"ibm bob unlimited", SourceIBMBob, nil, map[string]string{"main": "ibm_bob_unlimited.json"}, func(t *testing.T, s Snapshot) {
			if w := laWin(t, s, "monthly"); w.Limit != nil {
				t.Errorf("an unlimited budget has no limit: %+v", w)
			}
			wantUsedOnly(t, headlineOf(t, s), UnitCredits, 7)
		}},
		{"hugging face", SourceHuggingFace, nil, map[string]string{"main": "hugging_face_usage.json", "zerogpu": "hugging_face_zerogpu.json"}, func(t *testing.T, s Snapshot) {
			if len(s.Spend) != 1 || s.Spend[0].Amount != 450_000 {
				t.Errorf("billable beyond the included credit %+v", s.Spend)
			}
			laFrac(t, s, "monthly:included", 1)
			laFrac(t, s, "spend_limit", 0.045)
			laFrac(t, s, "zero_gpu", 0.4)
			h := headlineOf(t, s)
			wantLeft(t, "hugging face", h, UnitUSDMicros, 0, F(2_000_000))
		}},
		{"v0 token billing", SourceV0, nil, map[string]string{"main": "v0_billing.json", "rate": "v0_rate.json"}, func(t *testing.T, s Snapshot) {
			laBal(t, s, "on_demand", UnitCredits, 120)
			laFrac(t, s, "rate_limit", 0.2)
			wantLeft(t, "v0", headlineOf(t, s), UnitCredits, 750, F(250))
		}},
		{"v0 legacy billing", SourceV0, nil, map[string]string{"main": "v0_legacy.json"}, func(t *testing.T, s Snapshot) {
			if w := laWin(t, s, "cycle"); w.ResetsAt == nil || w.ResetsAt.Unix() != 1761955200 {
				t.Errorf("epoch ms reset %+v", w)
			}
			wantLeft(t, "v0 legacy", headlineOf(t, s), UnitCredits, 400, F(600))
		}},
	}
	covered := map[string]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := laRun(t, c)
			if err != nil {
				t.Fatal(err)
			}
			mustValid(t, s)
			def, _ := SourceByID(c.src)
			if s.Provider != def.Provider || s.Source != c.src || s.Kind != def.Kind {
				t.Errorf("identity %s %s %s", s.Provider, s.Source, s.Kind)
			}
			c.check(t, s)
		})
		covered[c.src] = true
	}
	for _, id := range laSources {
		if !covered[id] {
			t.Errorf("%s has no parse case", id)
		}
	}
}

// TestLaneAErrors pins the shape canary for every source (an unexpected 2xx
// body is ErrShape, never a zero) and the vendor-specific sign-in and
// not-applicable answers.
func TestLaneAErrors(t *testing.T) {
	for _, id := range laSources {
		reqs, err := Drivers[id].Plan(PlanInput{Params: laParams, Secrets: laSecrets(), Now: t0})
		if err != nil {
			t.Fatal(err)
		}
		resp := map[string]Response{}
		for _, r := range reqs {
			resp[r.Key] = Response{Key: r.Key, Status: 200, Body: []byte(`{"unexpected":true}`)}
		}
		if _, err := Drivers[id].Parse(ParseInput{Params: laParams, Responses: resp, Now: t0}); !errors.Is(err, ErrShape) {
			t.Errorf("%s: unexpected body = %v, want ErrShape", id, err)
		}
		first := reqs[0].Key
		resp[first] = Response{Key: first, Status: 401}
		if _, err := Drivers[id].Parse(ParseInput{Params: laParams, Responses: resp, Now: t0}); id != SourceMiniMax && !errors.Is(err, ErrAuth) {
			t.Errorf("%s: 401 = %v, want ErrAuth", id, err)
		}
	}
	cases := []struct {
		name string
		c    laCase
		want error
	}{
		{"minimax sign-in code", laCase{src: SourceMiniMax, params: laParams, bodies: map[string]string{"token": "minimax_auth.json"}}, ErrAuth},
		{"kilo trpc unauthorized", laCase{src: SourceKilo, bodies: map[string]string{"main": "kilo_auth.json"}}, ErrAuth},
		{"warp auth error type", laCase{src: SourceWarp, bodies: map[string]string{"main": "warp_autherr.json"}}, ErrAuth},
		{"chutes without a subscription", laCase{src: SourceChutes, bodies: map[string]string{"main": "chutes_inactive.json"}}, ErrNotApplicable},
	}
	for _, c := range cases {
		if _, err := laRun(t, c.c); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// MiniMax answers 401 on the token plan and the old route both: sign in.
	resp := map[string]Response{"token": {Status: 401}, "coding": {Status: 401}}
	if _, err := Drivers[SourceMiniMax].Parse(ParseInput{Responses: resp, Now: t0}); !errors.Is(err, ErrAuth) {
		t.Errorf("minimax 401: %v", err)
	}
	// A refused ZenMux management key fails the refresh even on the balance call.
	resp = map[string]Response{"main": {Status: 200, Body: fixture(t, "lanea/zenmux_subscription.json")}, "payg": {Status: 403}}
	if _, err := Drivers[SourceZenMux].Parse(ParseInput{Responses: resp, Now: t0}); !errors.Is(err, ErrAuth) {
		t.Errorf("zenmux payg 403: %v", err)
	}
}
