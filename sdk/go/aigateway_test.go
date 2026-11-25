package superbased

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// The shared AI gateway cases (sdk/contract/ai-gateway-cases.json) through
// the pure resolver and ParseGatewayRefusal, and the helpers around them.

type gatewayURLCase struct {
	Name        string  `json:"name"`
	Provider    string  `json:"provider"`
	Upstream    *string `json:"upstream"`
	URL         *string `json:"url"`
	Env         *string `json:"env"`
	Destination string  `json:"destination"`
	OrgURL      string  `json:"org_url"`
	Local       any     `json:"local"`
	Want        struct {
		URL            string `json:"url"`
		Source         string `json:"source"`
		UpstreamHeader string `json:"upstream_header"`
		Problem        string `json:"problem"`
	} `json:"want"`
}

type gatewayRefusalCase struct {
	Name    string            `json:"name"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
	Want    *struct {
		Kind       string  `json:"kind"`
		Code       string  `json:"code"`
		Status     int     `json:"status"`
		Message    *string `json:"message"`
		RequestID  string  `json:"request_id"`
		RetryAfter *int64  `json:"retry_after_seconds"`
		Budget     *struct {
			Level     *string  `json:"level"`
			ScopeID   *string  `json:"scope_id"`
			Unit      *string  `json:"unit"`
			Remaining *float64 `json:"remaining"`
			Cap       *float64 `json:"cap"`
			Estimated bool     `json:"estimated"`
		} `json:"budget"`
		PlanRefusal *struct {
			Kind       string `json:"kind"`
			Code       string `json:"code"`
			UpgradeURL string `json:"upgrade_url"`
			Capability string `json:"capability"`
		} `json:"plan_refusal"`
	} `json:"want"`
}

type gatewayKeyCase struct {
	Name       string  `json:"name"`
	Source     string  `json:"source"`
	BaseURL    string  `json:"base_url"`
	GatewayKey *string `json:"gateway_key"`
	Want       struct {
		Key     *string `json:"key"`
		Problem string  `json:"problem"`
	} `json:"want"`
}

type gatewayCases struct {
	BaseURL []gatewayURLCase     `json:"base_url"`
	Refusal []gatewayRefusalCase `json:"refusal"`
	APIKey  []gatewayKeyCase     `json:"api_key"`
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func floatEq(got, want *float64) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return math.Abs(*got-*want) < 1e-12
}

func TestAIGatewayBaseURLContractCases(t *testing.T) {
	var f gatewayCases
	readContract(t, "ai-gateway-cases.json", &f)
	if len(f.BaseURL) < 20 {
		t.Fatalf("only %d base_url cases", len(f.BaseURL))
	}
	for _, c := range f.BaseURL {
		asked := false
		local := c.Local
		in := gatewayInputs{
			provider: c.Provider, upstream: str(c.Upstream), url: str(c.URL), env: str(c.Env),
			destination: c.Destination, orgURL: c.OrgURL,
			local: func() any { asked = true; return local },
		}
		ep, problem, msg := resolveGatewayEndpoint(in)
		if c.Want.Problem != "" {
			if problem != c.Want.Problem || msg == "" || ep.BaseURL != "" {
				t.Errorf("%s: want problem %s, got %q %q %+v", c.Name, c.Want.Problem, problem, msg, ep)
			}
			continue
		}
		if problem != "" || ep.BaseURL != c.Want.URL || ep.Source != c.Want.Source || ep.UpstreamHeader != c.Want.UpstreamHeader {
			t.Errorf("%s: got %+v (%s %s), want %+v", c.Name, ep, problem, msg, c.Want)
		}
		if asked && c.Want.Source != GatewaySourceMachine && c.Destination == DestinationOnline {
			t.Errorf("%s: asked the machine under destination online", c.Name)
		}
	}
}

func TestAIGatewayRefusalContractCases(t *testing.T) {
	var f gatewayCases
	readContract(t, "ai-gateway-cases.json", &f)
	if len(f.Refusal) < 15 {
		t.Fatalf("only %d refusal cases", len(f.Refusal))
	}
	sentinels := map[string]error{
		GatewayRefusalBudgetExceeded:  ErrBudgetExceeded,
		GatewayRefusalModelNotAllowed: ErrModelNotAllowed,
		GatewayRefusalAdmissionDenied: ErrAdmissionDenied,
		GatewayRefusalQuotaExceeded:   ErrGatewayQuotaExceeded,
	}
	for _, c := range f.Refusal {
		h := http.Header{}
		for k, v := range c.Headers {
			h.Set(k, v)
		}
		got := ParseGatewayRefusal(c.Status, planCase{Body: c.Body}.rawBody(t), h)
		w := c.Want
		if w == nil {
			if got != nil {
				t.Errorf("%s: want no refusal, got %+v", c.Name, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("%s: want a refusal, got none", c.Name)
			continue
		}
		if got.Kind != w.Kind || got.Code != w.Code || got.Status != w.Status || got.RequestID != w.RequestID {
			t.Errorf("%s: %+v", c.Name, got)
		}
		if got.Message == "" || (w.Message != nil && got.Message != *w.Message) {
			t.Errorf("%s: message %q", c.Name, got.Message)
		}
		if s, ok := sentinels[w.Kind]; ok && !errors.Is(got, s) {
			t.Errorf("%s: errors.Is(%v) false", c.Name, s)
		}
		if (w.RetryAfter == nil && got.RetryAfter != 0) || (w.RetryAfter != nil && got.RetryAfter != time.Duration(*w.RetryAfter)*time.Second) {
			t.Errorf("%s: retry after %v", c.Name, got.RetryAfter)
		}
		switch {
		case (w.Budget == nil) != (got.Budget == nil):
			t.Errorf("%s: budget %+v", c.Name, got.Budget)
		case w.Budget != nil:
			b := got.Budget
			if b.Level != str(w.Budget.Level) || b.ScopeID != str(w.Budget.ScopeID) || b.Unit != str(w.Budget.Unit) ||
				!floatEq(b.Remaining, w.Budget.Remaining) || !floatEq(b.Cap, w.Budget.Cap) || b.Estimated != w.Budget.Estimated {
				t.Errorf("%s: budget %+v", c.Name, b)
			}
		}
		switch {
		case (w.PlanRefusal == nil) != (got.PlanRefusal == nil):
			t.Errorf("%s: plan refusal %+v", c.Name, got.PlanRefusal)
		case w.PlanRefusal != nil:
			p := got.PlanRefusal
			if p.Kind != w.PlanRefusal.Kind || p.Code != w.PlanRefusal.Code || p.UpgradeURL != w.PlanRefusal.UpgradeURL || p.Capability != w.PlanRefusal.Capability {
				t.Errorf("%s: plan refusal %+v", c.Name, p)
			}
			var pr *PlanRefusalError
			if !errors.As(got, &pr) || pr != p {
				t.Errorf("%s: errors.As does not find the plan refusal", c.Name)
			}
			sentinel := ErrPlanRequired
			if p.Kind == PlanRefusalAllowanceExceeded {
				sentinel = ErrAllowanceExceeded
			}
			if !errors.Is(got, sentinel) {
				t.Errorf("%s: errors.Is(%v) false", c.Name, sentinel)
			}
		}
	}
}

func TestParseGatewayRefusalNeverPanics(t *testing.T) {
	for _, b := range [][]byte{nil, {}, []byte("null"), []byte("\xff\xfe"), []byte(`{"reason":7}`), []byte(`{"reason":"budget_exceeded","unit":"usd","cap_usd":true}`)} {
		r := ParseGatewayRefusal(402, b, nil)
		if r != nil && r.Budget != nil && r.Budget.Cap != nil {
			t.Fatalf("%q: %+v", b, r.Budget)
		}
	}
}

func TestResolveGatewayFollowsTheDestination(t *testing.T) {
	setup(t)
	t.Setenv("SUPERBASED_DESTINATION", "online")
	t.Setenv("SUPERBASED_ORG_URL", "https://acme.superbased.app")
	t.Setenv("SUPERBASED_API_KEY", "ik_1.secret")
	got, err := GatewayBaseURL(GatewayProviderOpenAI, "")
	if err != nil || got != "https://acme.superbased.app/ai/openai/v1" {
		t.Fatalf("online: %q %v", got, err)
	}
	ep, err := ResolveGateway(GatewayProviderAnthropic, GatewayOptions{Upstream: "claude"})
	if err != nil || ep.BaseURL != "https://acme.superbased.app/ai/claude" || ep.Source != GatewaySourceOrg || ep.UpstreamHeader != "" {
		t.Fatalf("online anthropic: %+v %v", ep, err)
	}
	t.Setenv(EnvAIGatewayURL, "https://ai.example.com")
	ep, err = ResolveGateway(GatewayProviderOpenAI, GatewayOptions{Upstream: "openai-eu"})
	if err != nil || ep.BaseURL != "https://ai.example.com/v1" || ep.Source != GatewaySourceEnv || ep.UpstreamHeader != "openai-eu" {
		t.Fatalf("env: %+v %v", ep, err)
	}
	ep, err = ResolveGateway(GatewayProviderOpenAI, GatewayOptions{URL: "https://arg.example.com"})
	if err != nil || ep.BaseURL != "https://arg.example.com/v1" || ep.Source != GatewaySourceArgument {
		t.Fatalf("argument: %+v %v", ep, err)
	}
}

func TestResolveGatewayMachineLane(t *testing.T) {
	setup(t)
	t.Setenv("SUPERBASED_DESTINATION", "local")
	t.Setenv("SUPERBASED_DISCOVER", "1")
	asked := 0
	orig := discover
	discover = func(nodeURL string) (map[string]any, string) {
		asked++
		return map[string]any{"api_version": 1, "destination": "local", "local": map[string]any{
			"app_lanes": []any{map[string]any{"id": "openai", "base_url": "http://127.0.0.1:8820/up/openai"}},
		}}, ""
	}
	t.Cleanup(func() { discover = orig })
	got, err := GatewayBaseURL(GatewayProviderOpenAI, "")
	if err != nil || got != "http://127.0.0.1:8820/up/openai/v1" {
		t.Fatalf("lane: %q %v", got, err)
	}
	_, err = GatewayBaseURL(GatewayProviderAnthropic, "")
	var ae *GatewayAddressError
	if !errors.Is(err, ErrGatewayNotConfigured) || !errors.As(err, &ae) || ae.Problem != GatewayProblemNotConfigured || !strings.Contains(err.Error(), "observer apps lane add") {
		t.Fatalf("no lane: %v", err)
	}
	t.Setenv("SUPERBASED_DISCOVER", "0")
	resetForTests()
	before := asked
	if _, err := GatewayBaseURL(GatewayProviderOpenAI, ""); !errors.Is(err, ErrGatewayNotConfigured) || asked != before {
		t.Fatalf("discovery off still asked the machine: %v", err)
	}
}

func TestGatewayEndpointHTTPClient(t *testing.T) {
	setup(t)
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://elsewhere.example.com/", http.StatusFound)
			return
		}
		w.Header().Set(HeaderRequestID, "gw-1")
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = io.WriteString(w, `{"error":"denied","reason":"budget_exceeded","unit":"usd","cap_usd":1,"remaining_usd":-0.5,"estimated":true}`)
	}))
	defer srv.Close()

	ep := GatewayEndpoint{BaseURL: srv.URL, UpstreamHeader: "openai-eu"}
	client := ep.HTTPClient(nil)
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
	}))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader("{}"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if seen.Get(HeaderUpstream) != "openai-eu" || !strings.HasPrefix(seen.Get(HeaderRequestID), "sdk-") {
		t.Fatalf("headers %v", seen)
	}
	if want := "00-01000000000000000000000000000000-0200000000000000-01"; seen.Get(HeaderTraceparent) != want {
		t.Fatalf("traceparent %q", seen.Get(HeaderTraceparent))
	}
	r := GatewayRefusalFromResponse(resp)
	if r == nil || !errors.Is(r, ErrBudgetExceeded) || r.RequestID != "gw-1" || r.Budget == nil || *r.Budget.Remaining != -0.5 {
		t.Fatalf("refusal %+v", r)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "budget_exceeded") {
		t.Fatalf("the body was not put back: %q", body)
	}
	_ = resp.Body.Close()

	// A traceparent the request already carries is kept.
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/messages", nil)
	req.Header.Set(HeaderTraceparent, "00-0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0bbbbbbbbbbbbbbb-01")
	req.Header.Set(HeaderUpstream, "mine")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if seen.Get(HeaderTraceparent) != "00-0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0bbbbbbbbbbbbbbb-01" || seen.Get(HeaderUpstream) != "mine" {
		t.Fatalf("overwrote the request's headers: %v", seen)
	}

	// No redirect is followed (the key travels with every call).
	resp, err = client.Post(srv.URL+"/redirect", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("followed a redirect: %d", resp.StatusCode)
	}

	// Without an upstream header the client sends none.
	resp, err = GatewayEndpoint{BaseURL: srv.URL}.HTTPClient(nil).Post(srv.URL+"/v1/messages", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if seen.Get(HeaderUpstream) != "" {
		t.Fatalf("sent an upstream header: %v", seen)
	}
}

// TestAIGatewayAPIKeyContractCases runs the shared api_key cases through
// GatewayEndpoint.APIKey (hosted AI gateway review L7): the key rule every
// SDK shares, so a provider's own key never reaches a remote gateway.
func TestAIGatewayAPIKeyContractCases(t *testing.T) {
	var f gatewayCases
	readContract(t, "ai-gateway-cases.json", &f)
	if len(f.APIKey) < 10 {
		t.Fatalf("only %d api_key cases", len(f.APIKey))
	}
	prev := osEnv
	t.Cleanup(func() { osEnv = prev })
	for _, c := range f.APIKey {
		env := map[string]string{}
		if c.GatewayKey != nil {
			env[EnvAIGatewayKey] = *c.GatewayKey
		}
		osEnv = mapEnv(env)
		key, err := GatewayEndpoint{BaseURL: c.BaseURL, Source: c.Source}.APIKey()
		if c.Want.Problem != "" {
			var ae *GatewayAddressError
			if !errors.As(err, &ae) || ae.Problem != c.Want.Problem || !errors.Is(err, ErrGatewayNotConfigured) || key != "" {
				t.Errorf("%s: got %q %v, want problem %s", c.Name, key, err, c.Want.Problem)
			}
			continue
		}
		if err != nil || key != str(c.Want.Key) {
			t.Errorf("%s: got %q %v, want %q", c.Name, key, err, str(c.Want.Key))
		}
	}
}

func TestGatewayKey(t *testing.T) {
	setup(t)
	if GatewayKey() != "" {
		t.Fatal("key without the variable")
	}
	t.Setenv(EnvAIGatewayKey, "sbo-vk-test")
	if GatewayKey() != "sbo-vk-test" {
		t.Fatal(GatewayKey())
	}
}

func TestGatewayRefusalFromResponseIgnoresSuccess(t *testing.T) {
	if GatewayRefusalFromResponse(nil) != nil || GatewayRefusalFromResponse(&http.Response{StatusCode: 200}) != nil {
		t.Fatal("a success is not a refusal")
	}
	if r := GatewayRefusalFromResponse(&http.Response{StatusCode: 403, Header: http.Header{}}); r != nil {
		t.Fatal("a body-less 403 is not a gateway refusal")
	}
}
