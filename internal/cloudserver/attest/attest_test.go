package attest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func boundBinding() Binding {
	return Binding{
		TenantID:         "t-1",
		SubscriptionID:   "s-1",
		ARMResourceID:    "/subscriptions/s-1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/luna",
		EndpointAudience: "https://management.azure.com",
		RouteGeneration:  3,
	}
}

func armServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("missing bearer, got %q", got)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestARMAttestorHealthyWhenContentLoggingFalse(t *testing.T) {
	srv := armServer(t, 200, `{"properties":{"contentLogging":false}}`)
	a := &ARMAttestor{Tokens: StaticTokenSource{Value: "tok"}, BaseURL: srv.URL}
	att, err := a.Attest(context.Background(), boundBinding(), time.Now())
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if !att.Healthy || att.ContentLoggingValue != "false" {
		t.Fatalf("want healthy false, got %+v", att)
	}
}

func TestARMAttestorUnhealthyMatrix(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"content_logging_enabled", 200, `{"properties":{"contentLogging":true}}`},
		{"capability_absent", 200, `{"properties":{"other":false}}`},
		{"capability_non_boolean", 200, `{"properties":{"contentLogging":"false"}}`},
		{"capability_null", 200, `{"properties":{"contentLogging":null}}`},
		{"arm_outage_500", 500, `{"error":"boom"}`},
		{"arm_forbidden_403", 403, `{"error":"nope"}`},
		{"unparseable", 200, `not json`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := armServer(t, c.status, c.body)
			a := &ARMAttestor{Tokens: StaticTokenSource{Value: "tok"}, BaseURL: srv.URL}
			att, err := a.Attest(context.Background(), boundBinding(), time.Now())
			if err != nil {
				t.Fatalf("Attest returned hard error (want fail-closed unhealthy): %v", err)
			}
			if att.Healthy {
				t.Fatalf("want unhealthy, got healthy: %+v", att)
			}
			if att.Reason == "" {
				t.Fatal("unhealthy attestation must carry a reason")
			}
		})
	}
}

func TestARMAttestorUnboundFailsClosedNoHTTP(t *testing.T) {
	// A server that would PASS if reached — proves the unbound check short-
	// circuits before any HTTP call.
	srv := armServer(t, 200, `{"properties":{"contentLogging":false}}`)
	a := &ARMAttestor{Tokens: StaticTokenSource{Value: "tok"}, BaseURL: srv.URL}
	att, err := a.Attest(context.Background(), Binding{}, time.Now())
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if att.Healthy || !strings.Contains(att.Reason, "not bound") {
		t.Fatalf("unbound binding not failed closed: %+v", att)
	}
}

func TestARMAttestorNilTokenSourceErrors(t *testing.T) {
	a := &ARMAttestor{}
	if _, err := a.Attest(context.Background(), boundBinding(), time.Now()); err == nil {
		t.Fatal("nil TokenSource should error")
	}
}

type errTokens struct{}

func (errTokens) Token(context.Context, string) (string, error) {
	return "", errors.New("imds unavailable")
}

func TestARMAttestorTokenErrorFailsClosed(t *testing.T) {
	a := &ARMAttestor{Tokens: errTokens{}, BaseURL: "http://127.0.0.1:1"}
	att, err := a.Attest(context.Background(), boundBinding(), time.Now())
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if att.Healthy || !strings.Contains(att.Reason, "token") {
		t.Fatalf("token error not failed closed: %+v", att)
	}
}

func TestOperatorAttestorHealthyForAttestedResource(t *testing.T) {
	b := boundBinding()
	o := OperatorAttestor{AttestedResourceID: b.ARMResourceID, AttestedBy: "santosh"}
	att, err := o.Attest(context.Background(), b, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !att.Healthy {
		t.Fatalf("want healthy for the attested resource, got %+v", att)
	}
	if !strings.Contains(att.Reason, "operator-attested") || !strings.Contains(att.Reason, "santosh") {
		t.Errorf("reason must name operator-attestation + identity, got %q", att.Reason)
	}
	if att.ContentLoggingValue != "false (operator-attested)" {
		t.Errorf("content logging value = %q", att.ContentLoggingValue)
	}
}

func TestOperatorAttestorFailsClosed(t *testing.T) {
	full := boundBinding()
	cases := []struct {
		name string
		att  OperatorAttestor
		b    Binding
	}{
		{"different resource", OperatorAttestor{AttestedResourceID: full.ARMResourceID + "-other"}, full},
		{"empty attested id", OperatorAttestor{AttestedResourceID: ""}, full},
		{"incomplete binding", OperatorAttestor{AttestedResourceID: full.ARMResourceID}, Binding{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			att, err := tc.att.Attest(context.Background(), tc.b, time.Now())
			if err != nil {
				t.Fatalf("fail-closed must be a nil error, got %v", err)
			}
			if att.Healthy {
				t.Fatalf("want fail-closed (unhealthy), got %+v", att)
			}
			if att.Reason == "" {
				t.Error("fail-closed must carry a reason")
			}
		})
	}
}
