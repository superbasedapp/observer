package superbased

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// The shared plan refusal cases (sdk/contract/plan-refusal-cases.json)
// through ParsePlanRefusal, and how each call surfaces a refusal.

type planCase struct {
	Name    string            `json:"name"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
	Want    *struct {
		Kind             string           `json:"kind"`
		Code             string           `json:"code"`
		Status           int              `json:"status"`
		Message          *string          `json:"message"`
		UpgradeURL       string           `json:"upgrade_url"`
		Capability       string           `json:"capability"`
		PlanName         *string          `json:"plan_name"`
		PlanVersion      *int             `json:"plan_version"`
		PlanLabel        *string          `json:"plan_label"`
		Allowance        map[string]int64 `json:"allowance"`
		Plans            []string         `json:"plans"`
		OfferedAllowance map[string]int64 `json:"offered_allowance"`
		Quota            *PlanQuota       `json:"quota"`
		RetryAfter       *int64           `json:"retry_after_seconds"`
	} `json:"want"`
}

// rawBody is the case body as bytes on the wire: a string is the raw text.
func (c planCase) rawBody(t *testing.T) []byte {
	var s string
	if json.Unmarshal(c.Body, &s) == nil {
		return []byte(s)
	}
	return c.Body
}

func axisEq(got *int64, want map[string]int64, key string) bool {
	w, ok := want[key]
	if !ok {
		return got == nil
	}
	return got != nil && *got == w
}

// allowanceEq compares every allowance axis; an axis absent from want reads
// as no cap.
func allowanceEq(got *PlanAllowance, want map[string]int64) bool {
	return axisEq(got.EventsMonthly, want, "events_monthly") && axisEq(got.GBMonthly, want, "gb_monthly") &&
		axisEq(got.RequestsMonthly, want, "requests_monthly") && axisEq(got.Concurrency, want, "concurrency")
}

func TestPlanRefusalContractCases(t *testing.T) {
	var f struct {
		Cases []planCase `json:"cases"`
	}
	readContract(t, "plan-refusal-cases.json", &f)
	if len(f.Cases) < 10 {
		t.Fatalf("only %d cases", len(f.Cases))
	}
	for _, c := range f.Cases {
		h := http.Header{}
		for k, v := range c.Headers {
			h.Set(k, v)
		}
		got := ParsePlanRefusal(c.Status, c.rawBody(t), h)
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
		sentinel := ErrPlanRequired
		if w.Kind == PlanRefusalAllowanceExceeded {
			sentinel = ErrAllowanceExceeded
		}
		switch {
		case got.Kind != w.Kind || !errors.Is(got, sentinel):
			t.Errorf("%s: kind %q", c.Name, got.Kind)
		case got.Code != w.Code || got.Status != w.Status || got.UpgradeURL != w.UpgradeURL || got.Capability != w.Capability:
			t.Errorf("%s: %+v", c.Name, got)
		case got.Message == "" || (w.Message != nil && (got.Message != *w.Message || got.Error() != *w.Message)):
			t.Errorf("%s: message %q", c.Name, got.Message)
		case (w.PlanName == nil) != (got.Plan == nil) || (w.PlanName != nil && got.Plan.Name != *w.PlanName):
			t.Errorf("%s: plan %+v", c.Name, got.Plan)
		case w.PlanVersion != nil && (got.Plan.Version != *w.PlanVersion || got.Plan.Label != *w.PlanLabel):
			t.Errorf("%s: plan %+v", c.Name, got.Plan)
		case (w.Allowance == nil) != (got.Allowance == nil):
			t.Errorf("%s: allowance %+v", c.Name, got.Allowance)
		case w.Allowance != nil && !allowanceEq(got.Allowance, w.Allowance):
			t.Errorf("%s: allowance %+v", c.Name, got.Allowance)
		case (w.Quota == nil) != (got.Quota == nil) || (w.Quota != nil && *got.Quota != *w.Quota):
			t.Errorf("%s: quota %+v", c.Name, got.Quota)
		case w.RetryAfter == nil && got.RetryAfter != 0, w.RetryAfter != nil && got.RetryAfter != time.Duration(*w.RetryAfter)*time.Second:
			t.Errorf("%s: retry after %v", c.Name, got.RetryAfter)
		}
		names := []string{}
		for _, p := range got.Plans {
			names = append(names, p.Name)
		}
		if fmt.Sprint(names) != fmt.Sprint(w.Plans) {
			t.Errorf("%s: plans %v, want %v", c.Name, names, w.Plans)
		}
		if w.OfferedAllowance != nil {
			a := got.Plans[0].Allowance
			if a == nil || !allowanceEq(a, w.OfferedAllowance) {
				t.Errorf("%s: offered allowance %+v", c.Name, a)
			}
		}
	}
}

func TestParsePlanRefusalNeverPanics(t *testing.T) {
	for _, b := range [][]byte{nil, {}, []byte("null"), []byte("\xff\xfe"), []byte(`{"error":null}`), []byte(`{"error":"plan_required","upgrade_url":7}`)} {
		if r := ParsePlanRefusal(403, b, nil); r != nil {
			t.Fatalf("%q: %+v", b, r)
		}
	}
}

const planRequiredBody = `{"error":"plan_required","message":"AI Apps ingest is not part of this organization's plan (Team).","capability":"org.planea.gateway","plan":{"name":"team","version":1,"label":"Team"},"upgrade_url":"https://cloud.superbased.app/portal/orgs/org_1"}`

const eventsOverBody = `{"error":"planea_events_quota_exceeded","message":"This organization has used this month's AI Apps allowance of its plan (Team).","quota":{"quota":"events_monthly","unit":"events","used":10,"limit":10,"resets_at":"2026-12-01T00:00:00Z"},"capability":"org.planea.gateway","upgrade_url":"https://cloud.superbased.app/portal/orgs/org_1"}`

func TestPlanRefusalInExportError(t *testing.T) {
	// The texts otlptracehttp v1.45 returns: a non-retried status, and a
	// retried one given up on (the status is not in the text).
	direct := fmt.Errorf("failed to send to http://127.0.0.1:4318/v1/traces: 403 Forbidden (%w)", errors.New("body: "+planRequiredBody))
	if r := planRefusalInExportError(direct); r == nil || r.Kind != PlanRefusalPlanRequired || r.Status != 403 {
		t.Fatalf("403: %+v", r)
	}
	retried := fmt.Errorf("max retry time elapsed: %w", errors.New("retry-able request failure: body: "+eventsOverBody))
	if r := planRefusalInExportError(retried); r == nil || r.Kind != PlanRefusalAllowanceExceeded || r.Status != 429 || r.Quota.Quota != "events_monthly" {
		t.Fatalf("429: %+v", r)
	}
	for _, err := range []error{
		nil,
		errors.New("connection refused"),
		errors.New("failed to send to http://x/v1/traces: 401 Unauthorized (body: " + planRequiredBody + ")"),
		errors.New("failed to send to http://x/v1/traces: 403 Forbidden (body: {\"error\":\"insufficient_scope\"})"),
		errors.New("retry-able request failure: body: (empty)"),
	} {
		if r := planRefusalInExportError(err); r != nil {
			t.Fatalf("%v: %+v", err, r)
		}
	}
}

func onlineStub(t *testing.T) *stub {
	t.Helper()
	st := newStub(t)
	memInit(t, Options{Destination: DestinationOnline, OrgURL: st.URL, APIKey: "ik_1.s"})
	return st
}

func TestGetPromptReturnsThePlanRefusal(t *testing.T) {
	setup(t)
	st := onlineStub(t)
	st.route("GET", "/v1/sdk/prompts/greet", func(stubReq) (int, any, map[string]string) {
		return 403, []byte(planRequiredBody), nil
	})
	_, err := GetPrompt(context.Background(), "greet", PromptOptions{})
	var pr *PlanRefusalError
	if !errors.Is(err, ErrPromptFetch) || !errors.Is(err, ErrPlanRequired) || !errors.As(err, &pr) {
		t.Fatalf("err %v", err)
	}
	if pr.UpgradeURL != "https://cloud.superbased.app/portal/orgs/org_1" || !strings.Contains(err.Error(), "plan_required") {
		t.Fatalf("refusal %+v, err %v", pr, err)
	}
	if d := GetDiagnostics(); d.PlanRefusal == nil || d.PlanRefusal.Code != CodePlanRequired || d.PlanRefusalAt.IsZero() {
		t.Fatalf("diagnostics %+v", d.PlanRefusal)
	}
}

func TestGetDatasetReturnsThePlanRefusal(t *testing.T) {
	setup(t)
	st := onlineStub(t)
	st.route("GET", "/v1/sdk/datasets", func(stubReq) (int, any, map[string]string) {
		return 429, []byte(eventsOverBody), map[string]string{"Retry-After": "120"}
	})
	_, err := GetDataset(context.Background(), "golden")
	var ee *ExperimentError
	var pr *PlanRefusalError
	if !errors.As(err, &ee) || !errors.As(err, &pr) || !errors.Is(err, ErrAllowanceExceeded) {
		t.Fatalf("err %v", err)
	}
	if pr.RetryAfter != 120*time.Second || pr.Quota == nil || pr.Quota.Unit != "events" {
		t.Fatalf("refusal %+v", pr)
	}
}

func TestScoreCarriesThePlanRefusalAndDoesNotRetry(t *testing.T) {
	setup(t)
	st := onlineStub(t)
	st.route("POST", "/v1/sdk/scores", func(stubReq) (int, any, map[string]string) {
		return 429, []byte(eventsOverBody), map[string]string{"Retry-After": "120"}
	})
	var res ScoreResult
	_ = WithSpan(context.Background(), "req", SpanOptions{}, func(ctx context.Context, _ trace.Span) error {
		res = Score(ctx, "accuracy", 1.0, ScoreOptions{})
		return nil
	})
	if res.OK || res.PlanRefusal == nil || !errors.Is(res.PlanRefusal, ErrAllowanceExceeded) {
		t.Fatalf("result %+v", res)
	}
	if n := len(st.seen("/v1/sdk/scores")); n != 1 {
		t.Fatalf("%d score posts, want 1 (no retry over the allowance)", n)
	}
}

func TestAdmitCarriesThePlanRefusal(t *testing.T) {
	lc := setup(t)
	st := newStub(t)
	st.reply([]byte(planRequiredBody), 403, nil)
	v := Admit(context.Background(), "hi", AdmitOptions{OrgURL: st.URL, APIKey: "ik_1.s"})
	if !v.Allowed || v.Degraded != DegradedUnavailable || v.HTTPStatus != 403 || v.PlanRefusal == nil || v.PlanRefusal.Kind != PlanRefusalPlanRequired {
		t.Fatalf("verdict %+v", v)
	}
	if w := lc.warnings("upgrade: https://cloud.superbased.app/portal/orgs/org_1"); len(w) != 1 {
		t.Fatalf("warnings %v", lc.warns)
	}
	st.reply(map[string]any{"error": "insufficient_scope"}, 403, nil)
	if v := Admit(context.Background(), "hi", AdmitOptions{OrgURL: st.URL, APIKey: "ik_1.s"}); v.PlanRefusal != nil {
		t.Fatalf("no plan refusal: %+v", v.PlanRefusal)
	}
}

func TestExportPlanRefusalInDiagnosticsAndLoggedOnce(t *testing.T) {
	lc := setup(t)
	st := newStub(t)
	st.route("POST", "/v1/traces", func(stubReq) (int, any, map[string]string) {
		return 403, []byte(planRequiredBody), map[string]string{"Content-Type": "application/json"}
	})
	if GetDiagnostics().PlanRefusal != nil {
		t.Fatal("a refusal before any call")
	}
	if _, err := Init(context.Background(), Options{Destination: DestinationOnline, OrgURL: st.URL, APIKey: "ik_1.s"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_ = WithSpan(context.Background(), "refused", SpanOptions{}, func(context.Context, trace.Span) error { return nil })
		if Flush(context.Background()) {
			t.Fatal("a refused export flushed clean")
		}
	}
	d := GetDiagnostics()
	if d.FailedExports < 2 || d.PlanRefusal == nil || d.PlanRefusal.Kind != PlanRefusalPlanRequired || d.PlanRefusal.Plan == nil || d.PlanRefusal.Plan.Name != "team" {
		t.Fatalf("diagnostics %+v / %+v", d, d.PlanRefusal)
	}
	w := lc.warnings("refused by the organization's plan")
	if len(w) != 1 || !strings.Contains(w[0], "upgrade: https://cloud.superbased.app/portal/orgs/org_1") || strings.Contains(w[0], "\n") {
		t.Fatalf("warnings %q", w)
	}
}
