package inference

import (
	"context"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestDialectTable(t *testing.T) {
	cases := []struct {
		dialect      string
		known        bool
		family       Family
		verification bool
		modelID      bool
		attestation  Attestation
	}{
		{"chat_completions", true, FamilyFoundry, false, false, AttestationContentLogging},
		{"responses_store_false", true, FamilyFoundry, true, false, AttestationContentLogging},
		{"anthropic_messages", true, FamilyAnthropic, false, true, AttestationDisclosedOnly},
		{"", false, "", false, false, ""},
		{"Anthropic_Messages", false, "", false, false, ""},
		{"openai_responses", false, "", false, false, ""},
	}
	for _, c := range cases {
		spec, ok := SpecFor(c.dialect)
		if ok != c.known {
			t.Fatalf("SpecFor(%q) known = %v, want %v", c.dialect, ok, c.known)
		}
		if !ok {
			continue
		}
		if spec.Family != c.family || spec.RequiresVerificationRecord != c.verification ||
			spec.DeploymentIsModelID != c.modelID || spec.Attestation != c.attestation {
			t.Errorf("SpecFor(%q) = %+v", c.dialect, spec)
		}
	}
}

func TestParseFamilyAndAttestation(t *testing.T) {
	cases := []struct {
		in   string
		want Family
		ok   bool
		att  Attestation
	}{
		{"anthropic", FamilyAnthropic, true, AttestationDisclosedOnly},
		{" Anthropic ", FamilyAnthropic, true, AttestationDisclosedOnly},
		{"foundry", FamilyFoundry, true, AttestationContentLogging},
		{"azure", "", false, ""},
		{"", "", false, ""},
	}
	for _, c := range cases {
		got, ok := ParseFamily(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseFamily(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
		if ok && got.Attestation() != c.att {
			t.Errorf("%q.Attestation() = %q, want %q", got, got.Attestation(), c.att)
		}
	}
	if d := DialectsOf(FamilyAnthropic); len(d) != 1 || d[0] != DialectAnthropicMessages {
		t.Errorf("DialectsOf(anthropic) = %v", d)
	}
	if d := DialectsOf(FamilyFoundry); len(d) != 2 {
		t.Errorf("DialectsOf(foundry) = %v", d)
	}
}

func TestRouterDispatchesByDialectOnly(t *testing.T) {
	anth := &FakeProvider{Response: Response{Content: "a"}}
	fdry := &FakeProvider{Response: Response{Content: "f"}}
	r := NewRouter(map[Dialect]Provider{
		DialectAnthropicMessages:   anth,
		DialectChatCompletions:     fdry,
		Dialect("bogus"):           &FakeProvider{},
		DialectResponsesStoreFalse: nil,
	})
	ctx := context.Background()

	res, err := r.Complete(ctx, Request{Dialect: DialectAnthropicMessages})
	if err != nil || res.Content != "a" {
		t.Fatalf("anthropic dispatch = %+v, %v", res, err)
	}
	res, err = r.Complete(ctx, Request{Dialect: DialectChatCompletions})
	if err != nil || res.Content != "f" {
		t.Fatalf("chat dispatch = %+v, %v", res, err)
	}
	for _, d := range []Dialect{DialectResponsesStoreFalse, "bogus", ""} {
		if _, err := r.Complete(ctx, Request{Dialect: d}); !errors.Is(err, ErrUnsupportedDialect) {
			t.Errorf("dialect %q: err = %v, want ErrUnsupportedDialect", d, err)
		}
		if r.Supports(d) {
			t.Errorf("Supports(%q) = true", d)
		}
	}
	if len(anth.Requests) != 1 || len(fdry.Requests) != 1 {
		t.Errorf("calls anth=%d fdry=%d, want 1/1", len(anth.Requests), len(fdry.Requests))
	}
	var nilRouter *Router
	if _, err := nilRouter.Complete(ctx, Request{Dialect: DialectAnthropicMessages}); !errors.Is(err, ErrUnsupportedDialect) {
		t.Errorf("nil router err = %v", err)
	}
}

func TestResponseFinishHelpers(t *testing.T) {
	cases := []struct {
		finish    string
		truncated bool
		refused   bool
	}{
		{FinishLength, true, false},
		{FinishRefusal, false, true},
		{FinishRefusal + ":cyber", false, true},
		{"refusals", false, false},
		{"end_turn", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		r := Response{FinishReason: c.finish}
		if r.Truncated() != c.truncated || r.Refused() != c.refused {
			t.Errorf("%q: truncated=%v refused=%v", c.finish, r.Truncated(), r.Refused())
		}
	}
	if (Usage{Input: 3, CacheRead: 5, CacheWrite: 7, Output: 11}).PromptTokens() != 15 {
		t.Error("PromptTokens must sum input + cache read + cache write")
	}
}

// TestBoundaryImports pins the seam pure: no HTTP, no SQL.
func TestBoundaryImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"net/http", "database/sql", "github.com/jackc/pgx/v5"},
		ForbiddenTrees: []string{
			"github.com/anthropics/anthropic-sdk-go",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
		},
		Reason: "inference is the pure provider seam; clients and SQL live elsewhere",
	})
}
