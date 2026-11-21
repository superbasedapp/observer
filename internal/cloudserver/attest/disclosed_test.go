package attest

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDisclosedAttestorHealthyForAttestedResourceAndPolicy(t *testing.T) {
	b := boundBinding()
	d := DisclosedAttestor{AttestedResourceID: b.ARMResourceID, PolicyVersion: "1", AttestedBy: "santosh"}
	att, err := d.Attest(context.Background(), b, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !att.Healthy {
		t.Fatalf("want healthy for the disclosed resource, got %+v", att)
	}
	for _, want := range []string{ModeProviderRetentionDisclosed, "policy v1", b.ARMResourceID, "santosh", "NOT verified"} {
		if !strings.Contains(att.Reason, want) {
			t.Errorf("reason must carry %q, got %q", want, att.Reason)
		}
	}
	// The persisted value must never read as a disabled-logging claim.
	if strings.HasPrefix(att.ContentLoggingValue, "false") {
		t.Fatalf("disclosed mode must never claim ContentLogging=false, got %q", att.ContentLoggingValue)
	}
	if !strings.Contains(att.ContentLoggingValue, "not-disabled") || !strings.Contains(att.ContentLoggingValue, ModeProviderRetentionDisclosed) {
		t.Errorf("content logging value must name the disclosed posture, got %q", att.ContentLoggingValue)
	}
}

// TestDisclosedAttestorListCoversEachNamedResourceOnly pins the ruling R-AI1
// shape: one disclosure lists the free and paid tier models (two resource
// identities), each is covered exactly, and nothing else is - not a prefix,
// not an empty entry, not a resource the list does not name.
func TestDisclosedAttestorListCoversEachNamedResourceOnly(t *testing.T) {
	d := DisclosedAttestor{
		AttestedResourceID: " openai_compatible:chat:gpt-oss-20b , openai_compatible:chat:gpt-oss-120b,,",
		PolicyVersion:      "3", AttestedBy: "operator",
	}
	bind := func(res string) Binding {
		return Binding{
			TenantID: "openai_compatible", SubscriptionID: "default", ARMResourceID: res,
			EndpointAudience: "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1", RouteGeneration: 2,
		}
	}
	for res, want := range map[string]bool{
		"openai_compatible:chat:gpt-oss-20b":  true,
		"openai_compatible:chat:gpt-oss-120b": true,
		"openai_compatible:chat:gpt-oss":      false,
		"openai_compatible:chat:qwen3":        false,
	} {
		att, err := d.Attest(context.Background(), bind(res), time.Now())
		if err != nil || att.Healthy != want {
			t.Errorf("%s: healthy=%v err=%v, want %v", res, att.Healthy, err, want)
		}
		if want && !strings.Contains(att.Reason, res) {
			t.Errorf("%s: the verdict must name the covered resource, got %q", res, att.Reason)
		}
	}
}

// TestDisclosedAttestorAnthropicResource pins the Anthropic shape: a route
// bound to the provider-neutral "anthropic:messages:<model>" identity attests
// under the disclosed mode, and the verdict says retention is not verified.
func TestDisclosedAttestorAnthropicResource(t *testing.T) {
	b := Binding{
		TenantID: "anthropic", SubscriptionID: "default",
		ARMResourceID:    "anthropic:messages:claude-haiku-5-5",
		EndpointAudience: "https://api.anthropic.com", RouteGeneration: 3,
	}
	d := DisclosedAttestor{AttestedResourceID: "anthropic:messages:claude-haiku-5-5", PolicyVersion: "2", AttestedBy: "operator"}
	att, err := d.Attest(context.Background(), b, time.Now())
	if err != nil || !att.Healthy {
		t.Fatalf("want healthy, got %+v, %v", att, err)
	}
	if att.Reason != DisclosedReason("2", "anthropic:messages:claude-haiku-5-5", "operator") {
		t.Errorf("reason = %q", att.Reason)
	}
	if strings.Contains(att.Reason, "ContentLogging disabled") || !strings.Contains(att.Reason, "NOT verified") {
		t.Errorf("reason must never read as a verified/disabled-logging claim: %q", att.Reason)
	}
	// A different model is a different resource: not covered.
	other := b
	other.ARMResourceID = "anthropic:messages:claude-opus-5-5"
	if att, _ := d.Attest(context.Background(), other, time.Now()); att.Healthy {
		t.Fatalf("disclosure for one model must not cover another, got %+v", att)
	}
}

func TestDisclosedAttestorFailsClosed(t *testing.T) {
	full := boundBinding()
	cases := []struct {
		name string
		att  DisclosedAttestor
		b    Binding
		want string
	}{
		{"different resource", DisclosedAttestor{AttestedResourceID: full.ARMResourceID + "-other", PolicyVersion: "1"}, full, "not covered"},
		{"empty attested id", DisclosedAttestor{AttestedResourceID: "", PolicyVersion: "1"}, full, "not covered"},
		{"empty policy version", DisclosedAttestor{AttestedResourceID: full.ARMResourceID, PolicyVersion: "  "}, full, "no policy version"},
		{"incomplete binding", DisclosedAttestor{AttestedResourceID: full.ARMResourceID, PolicyVersion: "1"}, Binding{}, "not bound"},
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
			if !strings.Contains(att.Reason, tc.want) || !strings.Contains(att.Reason, ModeProviderRetentionDisclosed) {
				t.Errorf("reason = %q, want it to name the mode and %q", att.Reason, tc.want)
			}
		})
	}
}

func TestRefusingAttestorAlwaysFailsClosed(t *testing.T) {
	for _, b := range []Binding{boundBinding(), {}} {
		att, err := RefusingAttestor{Reason: "conflicting attestation modes"}.Attest(context.Background(), b, time.Now())
		if err != nil {
			t.Fatalf("nil error expected, got %v", err)
		}
		if att.Healthy || att.Reason != "conflicting attestation modes" {
			t.Fatalf("want unhealthy with the configured reason, got %+v", att)
		}
	}
	att, _ := RefusingAttestor{}.Attest(context.Background(), boundBinding(), time.Now())
	if att.Healthy || att.Reason == "" {
		t.Fatalf("empty reason must still fail closed with a reason, got %+v", att)
	}
}
