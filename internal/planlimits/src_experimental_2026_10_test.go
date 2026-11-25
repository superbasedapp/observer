package planlimits

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// waveSources lists every source of the 2026-10-21 wave, so a new row
// cannot skip the tests.
var waveSources = []string{SourceAutohandAccount, SourceAutohandAPI, SourceKimchiConfig, SourceKimchiAPI, SourceStakpakAPI}

func fixtureW(t *testing.T, name string) []byte {
	t.Helper()
	return fixture(t, "wave1021/"+name)
}

// waveInputs are complete plan inputs for every wave source.
func waveInputs(t *testing.T) map[string]PlanInput {
	return map[string]PlanInput{
		SourceAutohandAccount: {Now: t0, Local: map[string][]byte{"config": fixtureW(t, "autohand_config.json")}},
		SourceAutohandAPI:     {Now: t0, Secrets: map[string]string{SecretKey: "Bearer fixture-autohand-pasted"}},
		SourceKimchiConfig:    {Now: t0, Local: map[string][]byte{"config": fixtureW(t, "kimchi_config.json")}},
		SourceKimchiAPI:       {Now: t0, Secrets: map[string]string{SecretKey: "fixture-kimchi-pasted"}, Params: map[string]string{"region": "us"}},
		SourceStakpakAPI:      {Now: t0, Secrets: map[string]string{SecretKey: "fixture-stakpak-key"}, Params: map[string]string{"account_username": "fixture-user"}},
	}
}

var waveSecretValues = []string{"fixture-autohand-session-token", "fixture-autohand-pasted", "fixture-kimchi-key-0000", "fixture-kimchi-pasted", "fixture-stakpak-key"}

// TestWavePlansStayInsideTheirHosts pins, for every wave source: it is
// experimental, has a catalogue row, plans HTTPS requests only to its own
// hosts, and every credential rides only in SecretHeaders.
func TestWavePlansStayInsideTheirHosts(t *testing.T) {
	inputs := waveInputs(t)
	for _, id := range waveSources {
		def, ok := SourceByID(id)
		if !ok {
			t.Fatalf("%s: no source row", id)
		}
		if !def.Experimental() || def.DocURL != "" {
			t.Errorf("%s: an undocumented vendor endpoint must be experimental with no doc URL", id)
		}
		if _, ok := ProviderByID(def.Provider); !ok {
			t.Errorf("%s: provider %q has no catalogue row", id, def.Provider)
		}
		reqs, err := Drivers[id].Plan(inputs[id])
		if err != nil || len(reqs) == 0 {
			t.Fatalf("%s: plan %v %v", id, reqs, err)
		}
		for _, r := range reqs {
			u, err := url.Parse(r.URL)
			if err != nil || u.Scheme != "https" || !slices.Contains(def.Hosts, u.Host) || r.Base != "" {
				t.Errorf("%s: request %q leaves the allowed hosts %v", id, r.URL, def.Hosts)
			}
			for _, sv := range waveSecretValues {
				if strings.Contains(r.URL, sv) || strings.Contains(string(r.Body), sv) {
					t.Errorf("%s: secret in URL or body", id)
				}
				for n, v := range r.Header {
					if strings.Contains(v, sv) {
						t.Errorf("%s: secret in plain header %s", id, n)
					}
				}
			}
			if len(r.SecretHeaders) == 0 {
				t.Errorf("%s: no credential header", id)
			}
		}
	}
}

func TestWavePlanURLsAndHeaders(t *testing.T) {
	in := waveInputs(t)
	plan := func(id string, pi PlanInput) []Request {
		t.Helper()
		reqs, err := Drivers[id].Plan(pi)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		return reqs
	}
	// Autohand: the CLI's own token, as bearer AND auth_session cookie; the
	// stored api.baseUrl is never read.
	r := plan(SourceAutohandAccount, in[SourceAutohandAccount])[0]
	if r.URL != "https://api.autohand.ai/v1/auth/me" ||
		r.SecretHeaders["Authorization"] != "Bearer fixture-autohand-session-token" ||
		r.SecretHeaders["Cookie"] != "auth_session=fixture-autohand-session-token" {
		t.Errorf("autohand account request %+v", r)
	}
	// A pasted "Bearer x" is normalised.
	r = plan(SourceAutohandAPI, in[SourceAutohandAPI])[0]
	if r.SecretHeaders["Authorization"] != "Bearer fixture-autohand-pasted" {
		t.Errorf("autohand pasted %+v", r.SecretHeaders)
	}
	// Kimchi: the region decides the host; the stored llmEndpoint and
	// selfHostedUrl are never read.
	reqs := plan(SourceKimchiConfig, in[SourceKimchiConfig])
	if len(reqs) != 2 || reqs[0].URL != "https://llm.eu.kimchi.dev/v1/credits" || reqs[1].URL != "https://llm.eu.kimchi.dev/v1/budget" ||
		reqs[0].Optional || !reqs[1].Optional || reqs[0].SecretHeaders["Authorization"] != "Bearer fixture-kimchi-key-0000" {
		t.Errorf("kimchi config requests %+v", reqs)
	}
	reqs = plan(SourceKimchiAPI, in[SourceKimchiAPI])
	if reqs[0].URL != "https://llm.kimchi.dev/v1/credits" {
		t.Errorf("kimchi us %s", reqs[0].URL)
	}
	reqs = plan(SourceKimchiAPI, PlanInput{Now: t0, Secrets: map[string]string{SecretKey: "fixture-kimchi-pasted"}})
	if reqs[0].URL != "https://llm.kimchi.dev/v1/credits" {
		t.Errorf("kimchi default region %s", reqs[0].URL)
	}
	// Kimchi's api_key spelling is read too.
	reqs = plan(SourceKimchiConfig, PlanInput{Now: t0, Local: map[string][]byte{"config": []byte(`{"api_key":"fixture-kimchi-key-0000"}`)}})
	if reqs[0].URL != "https://llm.kimchi.dev/v1/credits" {
		t.Errorf("kimchi api_key %s", reqs[0].URL)
	}
	// Stakpak: the username is path-escaped into /v2/<username>/billing.
	r = plan(SourceStakpakAPI, in[SourceStakpakAPI])[0]
	if r.URL != "https://apiv2.stakpak.dev/v2/fixture-user/billing" || r.SecretHeaders["Authorization"] != "Bearer fixture-stakpak-key" {
		t.Errorf("stakpak request %+v", r)
	}
}

// TestWaveRefusals: a missing, expired, malformed or foreign credential and
// a bad typed id never produce a request.
func TestWaveRefusals(t *testing.T) {
	cfg := func(s string) map[string][]byte { return map[string][]byte{"config": []byte(s)} }
	for _, c := range []struct {
		name string
		id   string
		in   PlanInput
		want error
	}{
		{"autohand not installed", SourceAutohandAccount, PlanInput{Now: t0}, ErrUnavailable},
		{"autohand signed out", SourceAutohandAccount, PlanInput{Now: t0, Local: cfg(`{"provider":"openrouter"}`)}, ErrAuth},
		{"autohand expired session", SourceAutohandAccount, PlanInput{Now: t0.Add(30 * 24 * time.Hour), Local: cfg(`{"auth":{"token":"fixture-autohand-session-token","expiresAt":"2025-10-20T00:00:00Z"}}`)}, ErrAuth},
		{"autohand header injection", SourceAutohandAccount, PlanInput{Now: t0, Local: cfg(`{"auth":{"token":"abcdefgh; other=1"}}`)}, ErrAuth},
		{"autohand not json", SourceAutohandAccount, PlanInput{Now: t0, Local: cfg(`auth:\n  token: x`)}, ErrAuth},
		{"autohand pasted missing", SourceAutohandAPI, PlanInput{Now: t0}, ErrAuth},
		{"kimchi no key", SourceKimchiConfig, PlanInput{Now: t0, Local: cfg(`{"region":"us"}`)}, ErrAuth},
		{"kimchi self-hosted", SourceKimchiConfig, PlanInput{Now: t0, Local: cfg(`{"apiKey":"fixture-kimchi-key-0000","region":"self-hosted"}`)}, ErrNotApplicable},
		{"kimchi unknown region", SourceKimchiAPI, PlanInput{Now: t0, Secrets: map[string]string{SecretKey: "fixture-kimchi-pasted"}, Params: map[string]string{"region": "attacker.example.com"}}, ErrNotApplicable},
		{"stakpak missing key", SourceStakpakAPI, PlanInput{Now: t0, Params: map[string]string{"account_username": "u"}}, ErrAuth},
	} {
		_, err := Drivers[c.id].Plan(c.in)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// A durable ahc_ credential is used regardless of a past expiresAt.
	reqs, err := Drivers[SourceAutohandAccount].Plan(PlanInput{Now: t0.Add(30 * 24 * time.Hour), Local: cfg(`{"auth":{"token":"ahc_fixturedurable","expiresAt":"2025-10-20T00:00:00Z"}}`)})
	if err != nil || len(reqs) != 1 {
		t.Errorf("durable credential: %v %v", reqs, err)
	}
	// A Stakpak username can never steer the path.
	for _, u := range []string{"", "../admin", "a/b", "a?b=1", "..", "a b"} {
		_, err := Drivers[SourceStakpakAPI].Plan(PlanInput{Now: t0, Secrets: map[string]string{SecretKey: "fixture-stakpak-key"}, Params: map[string]string{"account_username": u}})
		if err == nil {
			t.Errorf("stakpak username %q accepted", u)
		}
	}
}

func TestAutohandMe(t *testing.T) {
	s, err := ParseAutohandMe(fixtureW(t, "autohand_me_pro.json"), SourceAutohandAccount, KindBorrowedToken, t0)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if s.PlanCode != "pro" || s.PlanLabel != "Pro" || s.Rung != RungExperimental || s.Status != StatusOK {
		t.Errorf("plan %+v", s)
	}
	w5, ok := FindWindow(s, "5h")
	if !ok || w5.Unit != UnitRequests || *w5.Used != 42 || *w5.Limit != 200 || *w5.Remaining != 158 || w5.ResetsAt == nil || !w5.Rolling {
		t.Errorf("5h %+v", w5)
	}
	wk, ok := FindWindow(s, "weekly")
	if !ok || !approx(*wk.UsedFrac, 0.8) {
		t.Errorf("weekly %+v", wk)
	}
	if _, ok := FindWindow(s, "daily"); ok {
		t.Error("a null window must be absent, never zero")
	}
	// A plan card leads with the tightest window: 300 of 1500 messages left.
	h := headlineOf(t, s)
	if h.Basis != "window:weekly" {
		t.Errorf("autohand headline %+v", h)
	}

	free, err := ParseAutohandMe(fixtureW(t, "autohand_me_free.json"), SourceAutohandAPI, KindUndocumented, t0)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, free)
	if b, ok := FindBalance(free, "available"); !ok || b.Amount != 7 || b.Unit != UnitRequests || free.PlanCode != "free" {
		t.Errorf("free grant %+v", free)
	}
	wantLeft(t, "autohand free", headlineOf(t, free), UnitRequests, 7, nil)

	// A spent window is throttled; a tier with no meter is plan-only.
	s, err = ParseAutohandMe([]byte(`{"entitlement":{"tier":"pro","quota":{"available":true,"window5h":{"used":200,"remaining":0,"limit":200,"resetAt":null},"week":{"used":250,"remaining":1250,"limit":1500,"resetAt":null}}}}`), SourceAutohandAPI, KindUndocumented, t0)
	if err != nil || s.Status != StatusThrottled {
		t.Errorf("spent 5h: %v %+v", err, s)
	}
	s, err = ParseAutohandMe([]byte(`{"entitlement":{"tier":"enterprise"}}`), SourceAutohandAPI, KindUndocumented, t0)
	if err != nil || s.Status != StatusPlanOnly || s.PlanCode != "enterprise" {
		t.Errorf("plan only: %v %+v", err, s)
	}
	// Shape canary.
	for _, body := range []string{`{"user":{"id":"x"}}`, `<html>`, `{"entitlement":{"tier":"pro","quota":{"available":true,"window5h":{"remaining":3}}}}`} {
		if _, err := ParseAutohandMe([]byte(body), SourceAutohandAPI, KindUndocumented, t0); !errors.Is(err, ErrShape) {
			t.Errorf("%s: %v, want shape error", body, err)
		}
	}
	// A 401 is a sign-in error, never a reading.
	if _, err := Drivers[SourceAutohandAccount].Parse(ParseInput{Now: t0, Responses: map[string]Response{"me": {Status: 401}}}); !errors.Is(err, ErrAuth) {
		t.Errorf("401: %v", err)
	}
}

func TestKimchiCreditsAndBudget(t *testing.T) {
	parse := Drivers[SourceKimchiConfig].Parse
	s, err := parse(ParseInput{Now: t0, Responses: map[string]Response{
		"credits": {Status: 200, Body: fixtureW(t, "kimchi_credits.json")},
		"budget":  {Status: 200, Body: fixtureW(t, "kimchi_budget.json")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if s.PlanCode != "coder" || s.Kind != KindBorrowedToken || s.Rung != RungExperimental {
		t.Errorf("plan %+v", s)
	}
	if b, ok := FindBalance(s, "credits"); !ok || b.Unit != UnitUSDMicros || b.Amount != 18_420_000 {
		t.Errorf("credits %+v", s.Balances)
	}
	u, ok := FindWindow(s, "budget:user")
	if !ok || *u.Used != 12_500_000 || *u.Limit != 50_000_000 || u.ResetsAt == nil || u.Length == nil || *u.Length != 31*24*time.Hour {
		t.Errorf("user budget %+v", u)
	}
	if _, ok := FindWindow(s, "budget:team_pooled"); !ok {
		t.Error("team budget missing")
	}
	if _, ok := FindWindow(s, "budget:organization_soft"); ok {
		t.Error("an uncapped budget must have no window")
	}
	// The pooled team budget is over its hard cap.
	if s.Status != StatusThrottled {
		t.Errorf("status %q", s.Status)
	}
	// A balance card leads with the credits left.
	wantLeft(t, "kimchi", headlineOf(t, s), UnitUSDMicros, 18_420_000, nil)

	// No budget (404) is not a failure; a dollar string is read like the client.
	s, err = parse(ParseInput{Now: t0, Responses: map[string]Response{
		"credits": {Status: 200, Body: []byte(`{"tierName":"Coder-Monthly","remaining":"$3.10","billingStatus":"low"}`)},
		"budget":  {Status: 404},
	}})
	if err != nil || s.PlanCode != "coder" || s.Status != StatusOK {
		t.Fatalf("string credits: %v %+v", err, s)
	}
	if b, _ := FindBalance(s, "credits"); b.Amount != 3_100_000 {
		t.Errorf("string credits amount %d", b.Amount)
	}
	// Restricted mode and an exhausted status are throttled.
	for _, body := range []string{`{"has_credits":false,"remaining":0}`, `{"billing_status":"BILLING_STATUS_EXHAUSTED","remaining":"0"}`} {
		s, err = parse(ParseInput{Now: t0, Responses: ok200("credits", body)})
		if err != nil || s.Status != StatusThrottled {
			t.Errorf("%s: %v %+v", body, err, s)
		}
	}
	// Bring-your-own inference has no Kimchi credits.
	if _, err := parse(ParseInput{Now: t0, Responses: ok200("credits", `{"serverless":false}`)}); !errors.Is(err, ErrNotApplicable) {
		t.Errorf("serverless false: %v", err)
	}
	// Shape canary, and a broken budget body is never half-read.
	if _, err := parse(ParseInput{Now: t0, Responses: ok200("credits", `{"balance":5}`)}); !errors.Is(err, ErrShape) {
		t.Errorf("unknown credits shape: %v", err)
	}
	_, err = parse(ParseInput{Now: t0, Responses: map[string]Response{
		"credits": {Status: 200, Body: fixtureW(t, "kimchi_credits.json")},
		"budget":  {Status: 200, Body: []byte(`{"period":{"startTime":"2025-10-01T00:00:00Z","endTime":"2025-11-01T00:00:00Z"},"budgets":[{"scope":"WHATEVER","budgetLimitUsd":"1","totalSpendUsd":"0"}]}`)},
	}})
	if !errors.Is(err, ErrShape) {
		t.Errorf("unknown budget scope: %v", err)
	}
	if _, err := parse(ParseInput{Now: t0, Responses: map[string]Response{"credits": {Status: 401}}}); !errors.Is(err, ErrAuth) {
		t.Errorf("401: %v", err)
	}
}

func TestKimchiPlanCode(t *testing.T) {
	for in, want := range map[string]string{
		"community": "community", "Free_Slow": "community", "Coder": "coder", "coder-annual": "coder",
		"Teams Monthly": "teams", "enterprise-x": "enterprise", "gold": "",
	} {
		if got := KimchiPlanCode(in); got != want {
			t.Errorf("KimchiPlanCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStakpakBilling(t *testing.T) {
	s, err := ParseStakpakBilling(fixtureW(t, "stakpak_billing.json"), t0)
	if err != nil {
		t.Fatal(err)
	}
	mustValid(t, s)
	if s.PlanLabel != "Pro" || s.PlanCode != "pro" {
		t.Errorf("an add-on is never the plan: %+v", s)
	}
	if b, ok := FindBalance(s, "credits"); !ok || b.Amount != 7_250_000 || b.Unit != UnitUSDMicros {
		t.Errorf("credits %+v", s.Balances)
	}
	m, ok := FindWindow(s, "monthly")
	if !ok || *m.Used != 12_750_000 || *m.Limit != 20_000_000 || m.ResetsAt == nil || m.ResetsAt.Year() != 2025 || m.ResetsAt.Month() != time.November {
		t.Errorf("monthly %+v", m)
	}
	wantLeft(t, "stakpak", headlineOf(t, s), UnitUSDMicros, 7_250_000, nil)

	s, err = ParseStakpakBilling([]byte(`{"features":{"credits":{"id":"credits","unlimited":true}},"products":[]}`), t0)
	if err != nil || s.Status != StatusUnmetered {
		t.Errorf("unlimited: %v %+v", err, s)
	}
	s, err = ParseStakpakBilling([]byte(`{"features":{},"products":[{"id":"free","name":"Free","status":"active","is_add_on":false}]}`), t0)
	if err != nil || s.Status != StatusPlanOnly || s.PlanLabel != "Free" {
		t.Errorf("plan only: %v %+v", err, s)
	}
	for _, body := range []string{`{"id":"x"}`, `{"features":{},"products":[]}`, `[]`} {
		if _, err := ParseStakpakBilling([]byte(body), t0); !errors.Is(err, ErrShape) {
			t.Errorf("%s: %v, want shape error", body, err)
		}
	}
	if _, err := Drivers[SourceStakpakAPI].Parse(ParseInput{Now: t0, Responses: map[string]Response{"billing": {Status: 404}}}); !errors.Is(err, ErrGone) {
		t.Errorf("404: %v", err)
	}
}

func TestCortexCodeIsAnHonestGap(t *testing.T) {
	p, ok := ProviderByID(ProviderCortexCode)
	if !ok || p.Gap != GapCloudCredsOnly || CoverageOf(ProviderCortexCode) != CoverageManual {
		t.Errorf("cortex code row %+v coverage %s", p, CoverageOf(ProviderCortexCode))
	}
	for _, id := range []string{ProviderAutohand, ProviderKimchi, ProviderStakpak} {
		if CoverageOf(id) != CoverageExperimental {
			t.Errorf("%s coverage %s", id, CoverageOf(id))
		}
	}
}
